"""Transactions (from Assignment 4) extended with coinbase transactions.

Canonical body (big-endian):
  b"UTXO-TX-V1\\x00" | version u32 | n_in u16 | (prev_txid 32 | prev_index u32)*
                     | n_out u16 | (value u64 | pubkey_hash 20)*
txid    = SHA-256(body)                        (witnesses excluded)
sighash = SHA-256(b"UTXO-SIGHASH-ALL" | body)

Coinbase: exactly one input whose prev_txid is 32 zero bytes and whose
prev_index is the block HEIGHT (this makes every coinbase txid unique), with an
empty witness. It may only appear as the first transaction of a block.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .crypto import sha256

DOMAIN = b"UTXO-TX-V1\x00"
SIGHASH_TAG = b"UTXO-SIGHASH-ALL"
MAX_IO = 1000
U64_MAX = 2**64 - 1
MAX_MONEY = 21_000_000 * 100_000_000
NULL_TXID = b"\x00" * 32


class EncodeError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class OutPoint:
    txid: bytes
    index: int

    def __str__(self) -> str:
        return f"{self.txid.hex()[:10]}…:{self.index}"

    def key(self) -> str:
        return f"{self.txid.hex()}:{self.index}"

    @classmethod
    def from_key(cls, k: str) -> "OutPoint":
        t, i = k.split(":")
        return cls(bytes.fromhex(t), int(i))


@dataclass(frozen=True)
class TxOut:
    value: int
    pubkey_hash: bytes


@dataclass(frozen=True)
class TxIn:
    prevout: OutPoint
    pubkey: bytes = b""
    signature: bytes = b""


@dataclass(frozen=True)
class Transaction:
    inputs: tuple[TxIn, ...]
    outputs: tuple[TxOut, ...]
    version: int = 1
    _cache: dict = field(default_factory=dict, compare=False, repr=False, hash=False)

    @classmethod
    def coinbase(cls, height: int, outputs: list[TxOut]) -> "Transaction":
        return cls((TxIn(OutPoint(NULL_TXID, height)),), tuple(outputs))

    @property
    def is_coinbase(self) -> bool:
        return len(self.inputs) == 1 and self.inputs[0].prevout.txid == NULL_TXID

    def body_bytes(self) -> bytes:
        if "body" in self._cache:
            return self._cache["body"]
        if not (1 <= len(self.inputs) <= MAX_IO and 1 <= len(self.outputs) <= MAX_IO):
            raise EncodeError("input/output count out of range")
        parts = [DOMAIN, struct.pack(">IH", self.version, len(self.inputs))]
        for i in self.inputs:
            if len(i.prevout.txid) != 32 or not 0 <= i.prevout.index <= 0xFFFFFFFF:
                raise EncodeError("malformed outpoint")
            parts.append(i.prevout.txid + struct.pack(">I", i.prevout.index))
        parts.append(struct.pack(">H", len(self.outputs)))
        for o in self.outputs:
            if type(o.value) is not int or not 0 <= o.value <= U64_MAX:
                raise EncodeError(f"output value {o.value!r} is not a u64")
            if len(o.pubkey_hash) != 20:
                raise EncodeError("pubkey_hash must be 20 bytes")
            parts.append(struct.pack(">Q", o.value) + o.pubkey_hash)
        self._cache["body"] = b"".join(parts)
        return self._cache["body"]

    def txid(self) -> bytes:
        if "txid" not in self._cache:
            self._cache["txid"] = sha256(self.body_bytes())
        return self._cache["txid"]

    def sighash(self) -> bytes:
        return sha256(SIGHASH_TAG + self.body_bytes())

    def with_witnesses(self, w: list[tuple[bytes, bytes]]) -> "Transaction":
        return Transaction(tuple(TxIn(i.prevout, p, s) for i, (p, s) in zip(self.inputs, w)),
                           self.outputs, self.version)

    def to_obj(self) -> dict:
        return {"version": self.version,
                "inputs": [{"txid": i.prevout.txid.hex(), "index": i.prevout.index,
                            "pubkey": i.pubkey.hex(), "signature": i.signature.hex()} for i in self.inputs],
                "outputs": [{"value": o.value, "pubkey_hash": o.pubkey_hash.hex()} for o in self.outputs]}

    @classmethod
    def from_obj(cls, o: dict) -> "Transaction":
        return cls(tuple(TxIn(OutPoint(bytes.fromhex(i["txid"]), i["index"]), bytes.fromhex(i["pubkey"]),
                              bytes.fromhex(i["signature"])) for i in o["inputs"]),
                   tuple(TxOut(x["value"], bytes.fromhex(x["pubkey_hash"])) for x in o["outputs"]),
                   o.get("version", 1))


def sign_tx(inputs: list[tuple[OutPoint, "object"]], outputs: list[TxOut]) -> Transaction:
    """Build and sign a transaction; each input is (outpoint, Key)."""
    unsigned = Transaction(tuple(TxIn(op) for op, _ in inputs), tuple(outputs))
    try:
        h = unsigned.sighash()
    except EncodeError:
        h = b"\x00" * 32
    return unsigned.with_witnesses([(k.pub, k.sign(h)) for _, k in inputs])
