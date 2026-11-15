"""Block headers, Merkle roots, toy Proof of Work and work accounting.

Header (116 bytes, big-endian):
  offset size field
  0      4    version        u32
  4      32   prev_hash      hash of the parent header
  36     32   merkle_root    Merkle root of the block's txids (Assignment 2 rules)
  68     8    timestamp      u64 seconds since the Unix epoch
  76     32   target         256-bit unsigned integer; valid iff hash <= target
  108    8    nonce          u64
block hash = SHA-256(header)   interpreted as a 256-bit big-endian unsigned integer
work(block) = floor(2^256 / (target + 1))   expected number of hashes to find it
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from .tx import Transaction

HEADER_LEN = 116
TWO_256 = 1 << 256


# ---------------------------------------------------------------- Merkle (A2 rules)
def merkle_root(txids: list[bytes]) -> bytes:
    """leaf = H(0x00||txid), node = H(0x01||L||R), odd node promoted, empty = H('')."""
    if not txids:
        return hashlib.sha256(b"").digest()
    level = [hashlib.sha256(b"\x00" + t).digest() for t in txids]
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def target_from_bits(zero_bits: int) -> int:
    """Convenience: the target whose valid hashes start with `zero_bits` zero bits."""
    return (1 << (256 - zero_bits)) - 1


def work_for_target(target: int) -> int:
    return TWO_256 // (target + 1)


@dataclass(frozen=True)
class BlockHeader:
    version: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    target: int
    nonce: int

    def serialize(self) -> bytes:
        return (struct.pack(">I", self.version) + self.prev_hash + self.merkle_root
                + struct.pack(">Q", self.timestamp) + self.target.to_bytes(32, "big")
                + struct.pack(">Q", self.nonce))

    def prefix(self) -> bytes:
        """Everything except the nonce (the miner only varies the last 8 bytes)."""
        return self.serialize()[:108]

    def hash(self) -> bytes:
        return hashlib.sha256(self.serialize()).digest()

    def pow_ok(self) -> bool:
        return int.from_bytes(self.hash(), "big") <= self.target

    @classmethod
    def parse(cls, b: bytes) -> "BlockHeader":
        if len(b) != HEADER_LEN:
            raise ValueError("header must be 116 bytes")
        return cls(struct.unpack(">I", b[:4])[0], b[4:36], b[36:68], struct.unpack(">Q", b[68:76])[0],
                   int.from_bytes(b[76:108], "big"), struct.unpack(">Q", b[108:116])[0])

    def hexdump(self) -> str:
        b = self.serialize()
        fields = [("version", 0, 4, f"u32 = {self.version}"),
                  ("prev_hash", 4, 32, "parent block hash"),
                  ("merkle_root", 36, 32, "Merkle root of txids"),
                  ("timestamp", 68, 8, f"u64 = {self.timestamp}"),
                  ("target", 76, 32, f"= 2^{self.target.bit_length()} - 1" if self.target & (self.target + 1) == 0
                   else "256-bit target"),
                  ("nonce", 108, 8, f"u64 = {self.nonce}")]
        rows = [f"{'offset':>6}  {'field':<12} {'bytes (hex)':<64}  meaning"]
        for name, off, ln, meaning in fields:
            rows.append(f"{off:>6}  {name:<12} {b[off:off + ln].hex():<64}  {meaning}")
        rows.append(f"\nraw header ({len(b)} bytes):")
        for i in range(0, len(b), 16):
            chunk = b[i:i + 16]
            rows.append(f"{i:04x}  {' '.join(f'{x:02x}' for x in chunk):<47}")
        rows.append(f"\nSHA-256(header) = {self.hash().hex()}")
        rows.append(f"target          = {self.target:064x}")
        rows.append(f"hash <= target  : {self.pow_ok()}")
        return "\n".join(rows)


@dataclass(frozen=True)
class Block:
    header: BlockHeader
    txs: tuple[Transaction, ...]

    @property
    def hash(self) -> bytes:
        return self.header.hash()

    def short(self) -> str:
        return self.hash.hex()[:10]

    def to_obj(self) -> dict:
        h = self.header
        return {"header": {"version": h.version, "prev_hash": h.prev_hash.hex(),
                           "merkle_root": h.merkle_root.hex(), "timestamp": h.timestamp,
                           "target": f"{h.target:064x}", "nonce": h.nonce},
                "hash": self.hash.hex(),
                "txs": [t.to_obj() for t in self.txs]}

    @classmethod
    def from_obj(cls, o: dict) -> "Block":
        h = o["header"]
        return cls(BlockHeader(h["version"], bytes.fromhex(h["prev_hash"]), bytes.fromhex(h["merkle_root"]),
                               h["timestamp"], int(h["target"], 16), h["nonce"]),
                   tuple(Transaction.from_obj(t) for t in o["txs"]))
