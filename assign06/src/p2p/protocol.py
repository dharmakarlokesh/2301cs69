"""Wire protocol: length-prefixed, versioned JSON messages over TCP.

Frame  = MAGIC (4 bytes "TOYN") || LENGTH (u32 big-endian) || PAYLOAD (LENGTH bytes, UTF-8 JSON)
Limits = LENGTH <= MAX_MESSAGE_SIZE (1 MiB). A bad magic or oversize length is FATAL for the
         connection (the stream can no longer be trusted to be in sync). A payload that is not
         valid JSON or fails the schema is NON-FATAL: the frame boundary is still known, so the
         node answers with an `error` message, penalises the peer, and keeps reading.

Every payload is an object {"v": 1, "type": <type>, ...fields}:

  hello      node_id, listen_port, height, tip, user_agent      handshake (both directions)
  getaddr    -                                                   peer discovery request
  addr       addrs: [{node_id, host, port}] (<= 100)             peer discovery reply
  inv        items: [{kind: "tx"|"block", id: hex64}] (<= 500)   inventory announcement
  getdata    items: [...]                                        object request
  notfound   items: [...]                                        requested object unknown
  tx         tx: <transaction object>
  block      block: <block object>
  ping/pong  nonce: int
  error      code, detail                                        error response
"""

from __future__ import annotations

import asyncio
import json
import re
import struct

MAGIC = b"TOYN"
PROTOCOL_VERSION = 1
MAX_MESSAGE_SIZE = 1 << 20
MAX_INV_ITEMS = 500
MAX_ADDRS = 100
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

TYPES = {"hello", "getaddr", "addr", "inv", "getdata", "notfound", "tx", "block",
         "ping", "pong", "error"}


class ProtocolError(Exception):
    def __init__(self, code: str, detail: str, fatal: bool):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.fatal = code, detail, fatal


def encode(msg: dict) -> bytes:
    payload = json.dumps({"v": PROTOCOL_VERSION, **msg}, separators=(",", ":")).encode()
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError("message too large")
    return MAGIC + struct.pack(">I", len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader, timeout: float | None) -> bytes:
    hdr = await asyncio.wait_for(reader.readexactly(8), timeout)
    if hdr[:4] != MAGIC:
        raise ProtocolError("bad-magic", f"got {hdr[:4]!r}", fatal=True)
    (n,) = struct.unpack(">I", hdr[4:])
    if n > MAX_MESSAGE_SIZE:
        raise ProtocolError("oversize", f"declared length {n} > {MAX_MESSAGE_SIZE}", fatal=True)
    return await asyncio.wait_for(reader.readexactly(n), timeout)


def _items(msg, key="items", limit=MAX_INV_ITEMS):
    items = msg.get(key)
    if not isinstance(items, list) or len(items) > limit:
        raise ProtocolError("bad-message", f"{key} must be a list of <= {limit}", fatal=False)
    return items


def decode(payload: bytes) -> dict:
    try:
        msg = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ProtocolError("bad-json", str(e)[:80], fatal=False) from None
    if not isinstance(msg, dict):
        raise ProtocolError("bad-message", "payload must be an object", fatal=False)
    if msg.get("v") != PROTOCOL_VERSION:
        raise ProtocolError("bad-version", f"unsupported protocol version {msg.get('v')!r}", fatal=False)
    t = msg.get("type")
    if t not in TYPES:
        raise ProtocolError("unknown-type", f"unknown message type {t!r}", fatal=False)
    # per-type schema
    if t == "hello":
        if not (isinstance(msg.get("node_id"), str) and 0 < len(msg["node_id"]) <= 64
                and type(msg.get("listen_port")) is int and type(msg.get("height")) is int
                and isinstance(msg.get("tip"), str) and _HEX64.match(msg["tip"])):
            raise ProtocolError("bad-message", "malformed hello", fatal=False)
    elif t in ("inv", "getdata", "notfound"):
        for it in _items(msg):
            if not (isinstance(it, dict) and it.get("kind") in ("tx", "block")
                    and isinstance(it.get("id"), str) and _HEX64.match(it["id"])):
                raise ProtocolError("bad-message", "malformed inventory item", fatal=False)
    elif t == "addr":
        for a in _items(msg, "addrs", MAX_ADDRS):
            if not (isinstance(a, dict) and isinstance(a.get("node_id"), str)
                    and isinstance(a.get("host"), str) and type(a.get("port")) is int):
                raise ProtocolError("bad-message", "malformed addr entry", fatal=False)
    elif t in ("ping", "pong"):
        if type(msg.get("nonce")) is not int:
            raise ProtocolError("bad-message", "ping/pong needs integer nonce", fatal=False)
    elif t == "tx" and not isinstance(msg.get("tx"), dict):
        raise ProtocolError("bad-message", "tx must be an object", fatal=False)
    elif t == "block" and not isinstance(msg.get("block"), dict):
        raise ProtocolError("bad-message", "block must be an object", fatal=False)
    elif t == "error" and not isinstance(msg.get("code"), str):
        raise ProtocolError("bad-message", "error needs a code", fatal=False)
    return msg
