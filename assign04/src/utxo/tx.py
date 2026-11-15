"""Transactions, outpoints and their canonical serialization.

Canonical body bytes (all integers big-endian):

    b"UTXO-TX-V1\\x00"                     11-byte domain tag
    version            u32
    input_count        u16                  1..MAX_IO
      per input:  prev_txid (32 bytes) || prev_index (u32)
    output_count       u16                  1..MAX_IO
      per output: value (u64) || pubkey_hash (20 bytes)

txid    = SHA-256(body)                     -> excludes signatures, so a third
                                               party cannot change the txid
                                               (no signature malleability)
sighash = SHA-256(b"UTXO-SIGHASH-ALL" || body)   signed by every input
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .crypto import sha256

DOMAIN = b"UTXO-TX-V1\x00"
SIGHASH_TAG = b"UTXO-SIGHASH-ALL"
MAX_IO = 1000
U64_MAX = 2**64 - 1
MAX_MONEY = 21_000_000 * 100_000_000          # total supply cap in base units


class EncodeError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class OutPoint:
    txid: bytes          # 32 bytes
    index: int           # output index within that transaction

    def __str__(self) -> str:
        return f"{self.txid.hex()[:12]}…:{self.index}"

    def key(self) -> str:
        return f"{self.txid.hex()}:{self.index}"

    @classmethod
    def from_key(cls, k: str) -> "OutPoint":
        t, i = k.split(":")
        return cls(bytes.fromhex(t), int(i))


@dataclass(frozen=True)
class TxOut:
    value: int
    pubkey_hash: bytes   # 20 bytes; locking condition = pay-to-public-key-hash

    def to_obj(self) -> dict:
        return {"value": self.value, "lock": {"type": "p2pkh", "pubkey_hash": self.pubkey_hash.hex()}}

    @classmethod
    def from_obj(cls, o: dict) -> "TxOut":
        if o["lock"]["type"] != "p2pkh":
            raise EncodeError("only p2pkh locking conditions are supported")
        return cls(o["value"], bytes.fromhex(o["lock"]["pubkey_hash"]))


@dataclass(frozen=True)
class TxIn:
    prevout: OutPoint
    pubkey: bytes = b""      # unlocking data (witness): not part of txid
    signature: bytes = b""


@dataclass(frozen=True)
class Transaction:
    inputs: tuple[TxIn, ...]
    outputs: tuple[TxOut, ...]
    version: int = 1
    _cache: dict = field(default_factory=dict, compare=False, repr=False, hash=False)

    # ---- canonical encoding --------------------------------------------------
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
        body = b"".join(parts)
        self._cache["body"] = body
        return body

    def txid(self) -> bytes:
        return sha256(self.body_bytes())

    def sighash(self) -> bytes:
        return sha256(SIGHASH_TAG + self.body_bytes())

    def txid_hex(self) -> str:
        try:
            return self.txid().hex()
        except EncodeError:
            return "<unencodable>"

    # ---- JSON -----------------------------------------------------------------
    def to_obj(self) -> dict:
        return {
            "version": self.version,
            "inputs": [{"txid": i.prevout.txid.hex(), "index": i.prevout.index,
                        "pubkey": i.pubkey.hex(), "signature": i.signature.hex()} for i in self.inputs],
            "outputs": [o.to_obj() for o in self.outputs],
        }

    @classmethod
    def from_obj(cls, o: dict) -> "Transaction":
        ins = tuple(TxIn(OutPoint(bytes.fromhex(i["txid"]), i["index"]), bytes.fromhex(i["pubkey"]),
                         bytes.fromhex(i["signature"])) for i in o["inputs"])
        outs = tuple(TxOut.from_obj(x) for x in o["outputs"])
        return cls(ins, outs, o.get("version", 1))

    def with_witnesses(self, witnesses: list[tuple[bytes, bytes]]) -> "Transaction":
        ins = tuple(TxIn(i.prevout, pub, sig) for i, (pub, sig) in zip(self.inputs, witnesses))
        return Transaction(ins, self.outputs, self.version)
