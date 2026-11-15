"""A full node: TCP server/client, handshake, discovery, inventory relay, mempool, mining,
per-peer rate limiting, timeouts, malformed-message handling, peer scoring, structured logs."""

from __future__ import annotations

import asyncio
import itertools
import json
import random
import time
from dataclasses import dataclass, field

from chain.block import Block
from chain.chain import ChainManager, ChainParams
from chain.miner import build_block
from chain.tx import Transaction

from .mempool import Mempool
from .protocol import MAX_INV_ITEMS, ProtocolError, decode, encode, read_frame


@dataclass
class NodeConfig:
    host: str = "127.0.0.1"
    port: int = 0
    max_peers: int = 8
    latency: float = 0.0              # artificial one-way delay added to every message we send
    jitter: float = 0.0
    handshake_timeout: float = 3.0
    idle_timeout: float = 10.0        # no message at all for this long -> disconnect
    ping_interval: float = 2.0
    rate: float = 200.0               # token bucket: messages per second ...
    burst: float = 400.0              # ... and bucket size
    ban_score: int = 100
    ban_seconds: float = 60.0
    connect_interval: float = 0.3
    mempool_ttl: float = 600.0
    block_target: int | None = None   # target used when this node mines


# misbehaviour penalties (basic peer scoring)
PENALTY = {"bad-json": 10, "bad-message": 10, "unknown-type": 5, "bad-version": 10,
           "rate-limited": 2, "invalid-tx": 10, "invalid-block": 50, "unsolicited": 1}


@dataclass
class Peer:
    pid: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    outbound: bool
    node_id: str | None = None
    listen_port: int | None = None
    score: int = 0
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.monotonic)
    last_recv: float = field(default_factory=time.monotonic)
    ping_nonce: int | None = None
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    sender: asyncio.Task | None = None
    closed: bool = False

    @property
    def label(self) -> str:
        return self.node_id or f"conn{self.pid}"


class Node:
    _pids = itertools.count(1)

    def __init__(self, node_id: str, params: ChainParams, genesis: Block, cfg: NodeConfig | None = None,
                 log_path: str | None = None, miner_pkh: bytes | None = None):
        self.id = node_id
        self.cfg = cfg or NodeConfig()
        self.chain = ChainManager(params, genesis, node_id)
        self.mempool = Mempool(ttl=self.cfg.mempool_ttl)
        self.peers: dict[int, Peer] = {}
        self.known_addrs: dict[str, tuple[str, int]] = {}
        self.blocked: set[str] = set()                 # partition simulation
        self.banned: dict[str, float] = {}
        self.seen: set[tuple[str, str]] = set()        # inventory we have processed (dup suppression)
        self.in_flight: dict[tuple[str, str], float] = {}
        self.rejected_blocks: set[bytes] = set()
        self.events: list[dict] = []
        self.miner_pkh = miner_pkh
        self._log_file = open(log_path, "a") if log_path else None
        self._server: asyncio.base_events.Server | None = None
        self._tasks: list[asyncio.Task] = []
        self.stopped = False

    # ------------------------------------------------------------------ logging
    def log(self, event: str, peer: Peer | str | None = None, obj: str | None = None, **extra) -> None:
        rec = {"ts": round(time.time(), 6), "node": self.id,
               "peer": peer.label if isinstance(peer, Peer) else peer, "object": obj, "event": event}
        rec.update(extra)
        self.events.append(rec)
        if self._log_file:
            self._log_file.write(json.dumps(rec) + "\n")

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        self._server = await asyncio.start_server(self._on_inbound, self.cfg.host, self.cfg.port)
        self.cfg.port = self._server.sockets[0].getsockname()[1]
        self._tasks = [asyncio.create_task(self._connector()), asyncio.create_task(self._maintenance())]
        self.log("started", port=self.cfg.port)

    async def stop(self) -> None:
        self.stopped = True
        for t in self._tasks:
            t.cancel()
        for p in list(self.peers.values()):
            await self._close(p, "shutdown")
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self._log_file:
            self._log_file.close()

    @property
    def addr(self) -> tuple[str, int]:
        return self.cfg.host, self.cfg.port

    def connected_ids(self) -> set[str]:
        return {p.node_id for p in self.peers.values() if p.node_id}

    def add_known(self, node_id: str, host: str, port: int) -> None:
        if node_id != self.id:
            self.known_addrs[node_id] = (host, port)

    # ------------------------------------------------------------------ connections
    async def connect(self, host: str, port: int) -> None:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 2.0)
        except (OSError, asyncio.TimeoutError):
            return
        await self._run_peer(reader, writer, outbound=True)

    async def _on_inbound(self, reader, writer) -> None:
        await self._run_peer(reader, writer, outbound=False)

    async def _run_peer(self, reader, writer, outbound: bool) -> None:
        p = Peer(next(self._pids), reader, writer, outbound, tokens=self.cfg.burst)
        self.peers[p.pid] = p
        p.sender = asyncio.create_task(self._sender(p))
        self.log("connected", p, direction="out" if outbound else "in")
        if outbound:
            self._send_hello(p)
        try:
            await self._read_loop(p)
        finally:
            await self._close(p, "read loop ended")

    async def _close(self, p: Peer, why: str) -> None:
        if p.closed:
            return
        p.closed = True
        self.peers.pop(p.pid, None)
        if p.sender:
            p.sender.cancel()
        try:
            p.writer.close()
        except Exception:  # noqa: BLE001
            pass
        self.log("disconnected", p, reason=why)

    async def _sender(self, p: Peer) -> None:
        """Delivers queued frames in order, each no earlier than its scheduled time (latency)."""
        try:
            while True:
                due, frame = await p.queue.get()
                delay = due - time.monotonic()
                if delay > 0:
                    await asyncio.sleep(delay)
                p.writer.write(frame)
                await p.writer.drain()
        except (asyncio.CancelledError, ConnectionError, OSError):
            pass

    def send(self, p: Peer, msg: dict) -> None:
        if p.closed:
            return
        delay = self.cfg.latency + (random.uniform(0, self.cfg.jitter) if self.cfg.jitter else 0)
        p.queue.put_nowait((time.monotonic() + delay, encode(msg)))

    def _send_hello(self, p: Peer) -> None:
        self.send(p, {"type": "hello", "node_id": self.id, "listen_port": self.cfg.port,
                      "height": self.chain.height, "tip": self.chain.tip.block.hash.hex(),
                      "user_agent": "toynode/1.0"})

    # ------------------------------------------------------------------ reading
    def _rate_ok(self, p: Peer) -> bool:
        now = time.monotonic()
        p.tokens = min(self.cfg.burst, p.tokens + (now - p.last_refill) * self.cfg.rate)
        p.last_refill = now
        if p.tokens >= 1:
            p.tokens -= 1
            return True
        return False

    async def _penalise(self, p: Peer, reason: str, detail: str = "") -> bool:
        """Add misbehaviour score; returns True if the peer was banned and disconnected."""
        p.score += PENALTY.get(reason, 10)
        self.log("misbehaviour", p, reason=reason, detail=detail[:120], score=p.score)
        if p.score >= self.cfg.ban_score:
            if p.node_id:
                self.banned[p.node_id] = time.monotonic() + self.cfg.ban_seconds
            self.log("banned", p, score=p.score)
            await self._close(p, "banned")
            return True
        return False

    async def _read_loop(self, p: Peer) -> None:
        while not p.closed:
            timeout = self.cfg.handshake_timeout if p.node_id is None else self.cfg.idle_timeout
            try:
                payload = await read_frame(p.reader, timeout)
            except asyncio.TimeoutError:
                self.log("timeout", p, phase="handshake" if p.node_id is None else "idle")
                return
            except ProtocolError as e:                           # fatal framing errors
                self.log("malformed", p, code=e.code, detail=e.detail, fatal=True)
                p.score += 50
                return
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                return
            p.last_recv = time.monotonic()
            if not self._rate_ok(p):
                if await self._penalise(p, "rate-limited"):
                    return
                continue                                         # drop the message
            try:
                msg = decode(payload)
            except ProtocolError as e:                           # non-fatal: answer and continue
                self.send(p, {"type": "error", "code": e.code, "detail": e.detail})
                if await self._penalise(p, e.code, e.detail):
                    return
                continue
            if p.node_id is None and msg["type"] != "hello":
                self.log("protocol-violation", p, detail="message before hello")
                return
            try:
                await self._dispatch(p, msg)
            except Exception as e:  # noqa: BLE001 - a bad message must never kill the node
                self.send(p, {"type": "error", "code": "bad-message", "detail": str(e)[:100]})
                if await self._penalise(p, "bad-message", repr(e)):
                    return

    # ------------------------------------------------------------------ handlers
    async def _dispatch(self, p: Peer, msg: dict) -> None:
        t = msg["type"]
        if t != "ping" and t != "pong":
            self.log(f"recv-{t}", p, obj=_obj_label(msg))
        await getattr(self, f"_on_{t}")(p, msg)

    async def _on_hello(self, p: Peer, msg: dict) -> None:
        nid = msg["node_id"]
        if p.node_id is not None:
            return
        if nid == self.id:
            await self._close(p, "connected to self")
            return
        if nid in self.blocked or self.banned.get(nid, 0) > time.monotonic():
            await self._close(p, "peer blocked/banned")
            return
        # duplicate connection: keep the one opened by the lower node id
        for q in list(self.peers.values()):
            if q.node_id == nid and q is not p:
                keep_q = (q.outbound and self.id < nid) or (not q.outbound and nid < self.id)
                await self._close(p if keep_q else q, "duplicate connection")
                if keep_q:
                    return
        if len(self.connected_ids()) >= self.cfg.max_peers:
            await self._close(p, "too many peers")
            return
        p.node_id, p.listen_port = nid, msg["listen_port"]
        host = p.writer.get_extra_info("peername")[0]
        self.add_known(nid, host, p.listen_port)
        if not p.outbound:
            self._send_hello(p)
        self.log("handshake-complete", p, their_height=msg["height"], their_tip=msg["tip"][:12])
        self.send(p, {"type": "getaddr"})
        self.send(p, {"type": "inv", "items": [{"kind": "block", "id": self.chain.tip.block.hash.hex()}]})
        if self.mempool.entries:
            self.send(p, {"type": "inv", "items": [{"kind": "tx", "id": t.hex()}
                                                   for t in list(self.mempool.entries)[:MAX_INV_ITEMS]]})

    async def _on_getaddr(self, p: Peer, msg: dict) -> None:
        addrs = [{"node_id": self.id, "host": self.cfg.host, "port": self.cfg.port}]
        addrs += [{"node_id": n, "host": h, "port": port} for n, (h, port) in self.known_addrs.items()]
        self.send(p, {"type": "addr", "addrs": addrs[:100]})

    async def _on_addr(self, p: Peer, msg: dict) -> None:
        for a in msg["addrs"]:
            if a["node_id"] not in self.known_addrs and a["node_id"] != self.id:
                self.add_known(a["node_id"], a["host"], a["port"])
                self.log("peer-discovered", p, obj=a["node_id"])

    def _have(self, kind: str, oid: bytes) -> bool:
        if kind == "tx":
            return oid in self.mempool or (kind, oid.hex()) in self.seen
        return oid in self.chain.index or oid in self.rejected_blocks

    async def _on_inv(self, p: Peer, msg: dict) -> None:
        want = []
        now = time.monotonic()
        for it in msg["items"]:
            key = (it["kind"], it["id"])
            if self._have(it["kind"], bytes.fromhex(it["id"])):
                continue
            if self.in_flight.get(key, 0) > now - 2.0:            # already requested recently
                continue
            self.in_flight[key] = now
            want.append(it)
        if want:
            self.send(p, {"type": "getdata", "items": want})

    async def _on_getdata(self, p: Peer, msg: dict) -> None:
        missing = []
        for it in msg["items"]:
            oid = bytes.fromhex(it["id"])
            if it["kind"] == "tx" and oid in self.mempool:
                self.send(p, {"type": "tx", "tx": self.mempool.get(oid).to_obj()})
            elif it["kind"] == "block" and oid in self.chain.index:
                self.send(p, {"type": "block", "block": self.chain.index[oid].block.to_obj()})
            else:
                missing.append(it)
        if missing:
            self.send(p, {"type": "notfound", "items": missing})

    async def _on_notfound(self, p: Peer, msg: dict) -> None:
        for it in msg["items"]:
            self.in_flight.pop((it["kind"], it["id"]), None)

    async def _on_tx(self, p: Peer, msg: dict) -> None:
        tx = Transaction.from_obj(msg["tx"])
        await self.accept_tx(tx, source=p)

    async def _on_block(self, p: Peer, msg: dict) -> None:
        blk = Block.from_obj(msg["block"])
        await self.accept_block(blk, source=p)

    async def _on_ping(self, p: Peer, msg: dict) -> None:
        self.send(p, {"type": "pong", "nonce": msg["nonce"]})

    async def _on_pong(self, p: Peer, msg: dict) -> None:
        if msg["nonce"] == p.ping_nonce:
            p.ping_nonce = None

    async def _on_error(self, p: Peer, msg: dict) -> None:
        pass  # already logged by _dispatch

    # ------------------------------------------------------------------ objects
    def announce(self, kind: str, oid: bytes, exclude: Peer | None = None) -> None:
        for q in list(self.peers.values()):
            if q is not exclude and q.node_id:
                self.send(q, {"type": "inv", "items": [{"kind": kind, "id": oid.hex()}]})
        self.log("announce", None, obj=f"{kind}:{oid.hex()[:12]}")

    async def accept_tx(self, tx: Transaction, source: Peer | None = None) -> tuple[bool, str]:
        txid = tx.txid()
        key = ("tx", txid.hex())
        self.in_flight.pop(key, None)
        if key in self.seen and txid not in self.mempool:
            return False, "already-seen"
        self.seen.add(key)
        ok, reason = self.mempool.add(tx, self.chain.utxo, time.time())
        self.log("tx-accepted" if ok else "tx-rejected", source, obj=f"tx:{txid.hex()[:12]}", reason=reason)
        if ok:
            self.announce("tx", txid, exclude=source)
        elif source is not None and reason not in ("already-in-mempool", "mempool-conflict",
                                                    "missing-or-spent-input", "mempool-full"):
            await self._penalise(source, "invalid-tx", reason)
        return ok, reason

    async def accept_block(self, blk: Block, source: Peer | None = None) -> str:
        bh = blk.hash
        self.in_flight.pop(("block", bh.hex()), None)
        r = self.chain.submit_block(blk, now=int(time.time()))
        self.log(f"block-{r.status}", source, obj=f"block:{bh.hex()[:12]}", height=self.chain.height,
                 reason=r.reason[:120])
        if r.status in ("connected", "reorg"):
            for h in r.connected:
                self.mempool.block_connected(self.chain.index[h].block)
            if r.status == "reorg":
                self.log("reorg", source, obj=f"block:{bh.hex()[:12]}",
                         disconnected=[h.hex()[:12] for h in r.disconnected],
                         connected=[h.hex()[:12] for h in r.connected])
                dropped = self.mempool.revalidate(self.chain.utxo)
                for txid, ok, why in self.mempool.reconsider(r.returned_txs, self.chain.utxo, time.time()):
                    self.log("tx-reconsidered", None, obj=f"tx:{txid.hex()[:12]}",
                             result="re-added" if ok else "dropped", reason=why)
                    if ok:
                        self.announce("tx", txid)
                for txid in dropped:
                    self.log("tx-dropped", None, obj=f"tx:{txid.hex()[:12]}", reason="invalid after reorg")
            for h in r.connected:
                self.announce("block", h, exclude=source)
        elif r.status == "orphan" and source is not None:
            parent = blk.header.prev_hash.hex()
            self.log("request-parent", source, obj=f"block:{parent[:12]}")
            self.in_flight[("block", parent)] = time.monotonic()
            self.send(source, {"type": "getdata", "items": [{"kind": "block", "id": parent}]})
        elif r.status == "rejected":
            self.rejected_blocks.add(bh)
            if source is not None:
                await self._penalise(source, "invalid-block", r.reason)
        return r.status

    async def mine(self, miner_pkh: bytes | None = None, max_txs: int = 100) -> Block:
        txs = self.mempool.select(self.chain.utxo, max_txs)
        blk, attempts = build_block(self.chain, miner_pkh or self.miner_pkh, txs,
                                    target=self.cfg.block_target)
        self.log("mined", None, obj=f"block:{blk.short()}", attempts=attempts, txs=len(txs))
        await self.accept_block(blk)
        return blk

    async def submit_local_tx(self, tx: Transaction) -> tuple[bool, str]:
        return await self.accept_tx(tx, source=None)

    # ------------------------------------------------------------------ background tasks
    async def _connector(self) -> None:
        while True:
            await asyncio.sleep(self.cfg.connect_interval)
            have = self.connected_ids()
            for nid, (h, port) in list(self.known_addrs.items()):
                if len(have) >= self.cfg.max_peers:
                    break
                if nid in have or nid in self.blocked or self.banned.get(nid, 0) > time.monotonic():
                    continue
                asyncio.create_task(self.connect(h, port))
                have.add(nid)

    async def _maintenance(self) -> None:
        while True:
            await asyncio.sleep(self.cfg.ping_interval)
            now = time.monotonic()
            for p in list(self.peers.values()):
                if p.node_id is None:
                    continue
                if p.ping_nonce is not None:                       # previous ping unanswered
                    self.log("timeout", p, phase="pong")
                    await self._close(p, "ping timeout")
                    continue
                p.ping_nonce = random.getrandbits(32)
                self.send(p, {"type": "ping", "nonce": p.ping_nonce})
            for txid in self.mempool.expire(time.time()):
                self.log("tx-expired", None, obj=f"tx:{txid.hex()[:12]}")
            self.in_flight = {k: v for k, v in self.in_flight.items() if v > now - 10}

    # ------------------------------------------------------------------ partition simulation
    async def block_peers(self, node_ids: set[str]) -> None:
        self.blocked = set(node_ids)
        for p in list(self.peers.values()):
            if p.node_id in self.blocked:
                await self._close(p, "partitioned")

    def unblock_all(self) -> None:
        self.blocked = set()


def _obj_label(msg: dict) -> str | None:
    t = msg["type"]
    if t in ("inv", "getdata", "notfound"):
        items = msg["items"]
        s = ",".join(f"{i['kind']}:{i['id'][:12]}" for i in items[:3])
        return s + (f",+{len(items) - 3}" if len(items) > 3 else "")
    if t == "tx":
        try:
            return f"tx:{Transaction.from_obj(msg['tx']).txid().hex()[:12]}"
        except Exception:  # noqa: BLE001
            return "tx:?"
    if t == "block":
        return f"block:{msg['block'].get('hash', '?')[:12]}"
    if t == "hello":
        return msg["node_id"]
    return None
