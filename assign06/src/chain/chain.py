"""Node-local chain manager: block validation, most-work selection, reorganisation.

Rules
-----
Context-free (checked before a block is stored):
  * header hash <= header target (Proof of Work) and 0 < target <= pow_limit
  * at least one tx; the first tx is a coinbase; no other tx is a coinbase
  * no duplicate txids; Merkle root in the header equals the root of the txids
  * every tx has well-formed outputs (positive, <= MAX_MONEY, no overflow)
Contextual (needs the parent):
  * parent known and not invalid (otherwise the block waits as an orphan)
  * timestamp > median of the previous 11 timestamps (median-time-past) and,
    if a clock is supplied, timestamp <= now + max_future_drift
  * coinbase prev_index == block height
State transition (when the block is connected to the active chain):
  * every non-coinbase tx passes the Assignment 4 rules against the UTXO set
    produced by all earlier txs (earlier txs of the same block included)
  * coinbase value <= subsidy + sum(fees)

Chain selection: the valid chain with the greatest CUMULATIVE WORK
(sum of 2^256/(target+1)), not the most blocks. Ties keep the first-seen tip.
Simplification: there is no difficulty retargeting; any target <= pow_limit is
accepted and credited with exactly the work it represents.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from .block import Block, BlockHeader, merkle_root, work_for_target
from .tx import Transaction, TxOut
from .utxoset import TxInvalid, TxUndo, UtxoSet


@dataclass(frozen=True)
class ChainParams:
    pow_limit: int                    # largest (easiest) allowed target
    subsidy: int = 50
    max_future_drift: int = 2 * 60 * 60
    mtp_window: int = 11


class BlockInvalid(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass
class IndexEntry:
    block: Block
    height: int
    cum_work: int
    invalid: bool = False


@dataclass
class SubmitResult:
    status: str               # connected | reorg | side-branch | orphan | duplicate | rejected
    reason: str = ""
    disconnected: list[bytes] = field(default_factory=list)
    connected: list[bytes] = field(default_factory=list)
    returned_txs: list[Transaction] = field(default_factory=list)   # from disconnected blocks


def make_genesis(params: ChainParams, pkh: bytes, timestamp: int = 1_700_000_000,
                 target: int | None = None) -> Block:
    from .miner import mine_header
    cb = Transaction.coinbase(0, [TxOut(params.subsidy, pkh)])
    hdr = BlockHeader(1, b"\x00" * 32, merkle_root([cb.txid()]), timestamp,
                      target or params.pow_limit, 0)
    hdr, _ = mine_header(hdr)
    return Block(hdr, (cb,))


class ChainManager:
    def __init__(self, params: ChainParams, genesis: Block, name: str = "node"):
        self.params = params
        self.name = name
        self.index: dict[bytes, IndexEntry] = {}
        self.orphans: dict[bytes, list[Block]] = {}      # parent hash -> waiting children
        self.utxo = UtxoSet()
        self.undo: dict[bytes, list[TxUndo]] = {}
        self.active: list[bytes] = []
        self.log: list[str] = []
        self.check_context_free(genesis)
        g = genesis.hash
        self.index[g] = IndexEntry(genesis, 0, work_for_target(genesis.header.target))
        self._connect(genesis, 0)
        self.active.append(g)

    # ------------------------------------------------------------------ queries
    @property
    def tip(self) -> IndexEntry:
        return self.index[self.active[-1]]

    @property
    def height(self) -> int:
        return len(self.active) - 1

    def block_at(self, h: int) -> Block:
        return self.index[self.active[h]].block

    def median_time_past(self, block_hash: bytes) -> int:
        ts, h = [], block_hash
        while h in self.index and len(ts) < self.params.mtp_window:
            e = self.index[h]
            ts.append(e.block.header.timestamp)
            h = e.block.header.prev_hash
        return int(statistics.median_low(ts))

    # ------------------------------------------------------------------ validation
    def check_context_free(self, b: Block) -> None:
        h = b.header
        if not 0 < h.target <= self.params.pow_limit:
            raise BlockInvalid("bad-target", f"target must be in (0, pow_limit]")
        if not h.pow_ok():
            raise BlockInvalid("bad-pow", f"hash {b.hash.hex()[:16]}… > target")
        if not b.txs:
            raise BlockInvalid("no-transactions", "block has no transactions")
        if not b.txs[0].is_coinbase:
            raise BlockInvalid("first-tx-not-coinbase", "first transaction must be a coinbase")
        if any(t.is_coinbase for t in b.txs[1:]):
            raise BlockInvalid("multiple-coinbase", "only the first transaction may be a coinbase")
        try:
            txids = [t.txid() for t in b.txs]
        except Exception as e:  # noqa: BLE001 - unencodable tx
            raise BlockInvalid("malformed-tx", str(e)) from None
        if len(set(txids)) != len(txids):
            raise BlockInvalid("duplicate-tx", "block contains the same transaction twice")
        if merkle_root(txids) != h.merkle_root:
            raise BlockInvalid("bad-merkle-root", "header merkle_root does not match transactions")
        for t in b.txs:
            try:
                UtxoSet().check_outputs(t)
            except TxInvalid as e:
                raise BlockInvalid("bad-tx", f"tx {t.txid().hex()[:10]}: {e}") from None

    def _check_contextual(self, b: Block, parent: IndexEntry, now: int | None) -> None:
        mtp = self.median_time_past(parent.block.hash)
        if b.header.timestamp <= mtp:
            raise BlockInvalid("time-too-old", f"timestamp {b.header.timestamp} <= median-time-past {mtp}")
        if now is not None and b.header.timestamp > now + self.params.max_future_drift:
            raise BlockInvalid("time-too-new", "timestamp too far in the future")
        if b.txs[0].inputs[0].prevout.index != parent.height + 1:
            raise BlockInvalid("bad-coinbase-height", "coinbase must commit to the block height")

    # ------------------------------------------------------------------ connect / disconnect
    def _connect(self, b: Block, height: int) -> None:
        """Apply a block's transactions to the UTXO set; all-or-nothing."""
        undos: list[TxUndo] = []
        try:
            fees = 0
            for t in b.txs[1:]:
                try:
                    fees += self.utxo.validate(t)
                    undos.append(self.utxo.apply(t))
                except TxInvalid as e:
                    raise BlockInvalid("bad-tx", f"tx {t.txid().hex()[:10]}: {e}") from None
            cb = b.txs[0]
            cb_value = sum(o.value for o in cb.outputs)
            if cb_value > self.params.subsidy + fees:
                raise BlockInvalid("excess-coinbase",
                                   f"coinbase pays {cb_value} > subsidy {self.params.subsidy} + fees {fees}")
            try:
                undos.append(self.utxo.apply(cb))
            except TxInvalid as e:
                raise BlockInvalid("bad-coinbase", str(e)) from None
        except BlockInvalid:
            for u in reversed(undos):
                self.utxo.undo(u)
            raise
        self.undo[b.hash] = undos

    def _disconnect(self, b: Block) -> list[Transaction]:
        for u in reversed(self.undo.pop(b.hash)):
            self.utxo.undo(u)
        return [t for t in b.txs if not t.is_coinbase]

    # ------------------------------------------------------------------ submission
    def submit_block(self, b: Block, now: int | None = None) -> SubmitResult:
        bh = b.hash
        if bh in self.index:
            return SubmitResult("duplicate", "block already known")
        try:
            self.check_context_free(b)
        except BlockInvalid as e:
            self.log.append(f"reject {b.short()} {e}")
            return SubmitResult("rejected", str(e))
        parent = self.index.get(b.header.prev_hash)
        if parent is None:
            self.orphans.setdefault(b.header.prev_hash, []).append(b)
            return SubmitResult("orphan", "parent unknown; stored until it arrives")
        if parent.invalid:
            return SubmitResult("rejected", "invalid-parent: builds on an invalid block")
        try:
            self._check_contextual(b, parent, now)
        except BlockInvalid as e:
            return SubmitResult("rejected", str(e))
        entry = IndexEntry(b, parent.height + 1, parent.cum_work + work_for_target(b.header.target))
        self.index[bh] = entry
        if entry.cum_work > self.tip.cum_work:
            res = self._activate(bh)
        else:
            res = SubmitResult("side-branch", f"stored at height {entry.height}; work "
                                              f"{entry.cum_work} <= tip work {self.tip.cum_work}")
        for child in self.orphans.pop(bh, []):          # adopt waiting orphans
            r2 = self.submit_block(child, now)
            if r2.status in ("connected", "reorg"):
                res.disconnected += r2.disconnected
                res.connected += r2.connected
                res.returned_txs += r2.returned_txs
                res.status = "reorg" if res.disconnected else "connected"
                res.reason = r2.reason
        return res

    def _branch_to(self, tip_hash: bytes) -> tuple[int, list[bytes]]:
        """Return (fork_height, [hashes from just above the fork up to tip_hash])."""
        branch, h = [], tip_hash
        while True:
            e = self.index[h]
            if e.height < len(self.active) and self.active[e.height] == h:
                return e.height, list(reversed(branch))
            branch.append(h)
            h = e.block.header.prev_hash

    def _activate(self, new_tip: bytes) -> SubmitResult:
        fork_h, new_branch = self._branch_to(new_tip)
        old_branch = self.active[fork_h + 1:]
        returned: list[Transaction] = []
        for h in reversed(old_branch):                       # disconnect old blocks, newest first
            returned += self._disconnect(self.index[h].block)
        del self.active[fork_h + 1:]
        connected: list[bytes] = []
        for h in new_branch:                                 # connect the winning branch
            e = self.index[h]
            try:
                self._connect(e.block, e.height)
            except BlockInvalid as err:
                self._mark_invalid(h)
                for c in reversed(connected):                # roll back the partial branch
                    self._disconnect(self.index[c].block)
                del self.active[fork_h + 1:]
                for oh in old_branch:                        # restore the original chain
                    self._connect(self.index[oh].block, self.index[oh].height)
                    self.active.append(oh)
                self.log.append(f"reject {e.block.short()} {err}; active chain unchanged")
                return SubmitResult("rejected", f"{err} (active chain unchanged)")
            self.active.append(h)
            connected.append(h)
        # txs from the losing branch that are not in the winning branch go back to the caller
        now_in_chain = {t.txid() for h in new_branch for t in self.index[h].block.txs}
        returned = [t for t in returned if t.txid() not in now_in_chain]
        status = "reorg" if old_branch else "connected"
        if old_branch:
            self.log.append(f"REORG at height {fork_h}: -{len(old_branch)} +{len(new_branch)} blocks, "
                            f"new tip {new_tip.hex()[:10]}")
        return SubmitResult(status, f"tip height {self.height}", list(old_branch), connected, returned)

    def _mark_invalid(self, h: bytes) -> None:
        self.index[h].invalid = True
        for k, e in self.index.items():                      # descendants are invalid too
            p = e.block.header.prev_hash
            while p in self.index:
                if p == h:
                    e.invalid = True
                    break
                p = self.index[p].block.header.prev_hash
