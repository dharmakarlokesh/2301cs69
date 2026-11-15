"""UTXO set with undo records, so blocks can be connected AND disconnected.

The per-transaction validation rules are those of Assignment 4.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .crypto import pubkey_hash, sha256, verify_sig
from .tx import MAX_IO, MAX_MONEY, EncodeError, OutPoint, Transaction, TxOut


class TxInvalid(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass
class TxUndo:
    txid: bytes
    spent: list[tuple[OutPoint, TxOut]] = field(default_factory=list)   # restored on disconnect
    created: list[OutPoint] = field(default_factory=list)               # removed on disconnect


class UtxoSet:
    def __init__(self):
        self.utxos: dict[OutPoint, TxOut] = {}

    def copy(self) -> "UtxoSet":
        u = UtxoSet()
        u.utxos = dict(self.utxos)
        return u

    def check_outputs(self, tx: Transaction) -> int:
        if not tx.inputs or not tx.outputs:
            raise TxInvalid("empty", "transaction needs inputs and outputs")
        if len(tx.inputs) > MAX_IO or len(tx.outputs) > MAX_IO:
            raise TxInvalid("too-many-io", "too many inputs/outputs")
        total = 0
        for n, o in enumerate(tx.outputs):
            if type(o.value) is not int:
                raise TxInvalid("bad-output-type", f"output {n} is not an integer")
            if o.value <= 0:
                raise TxInvalid("non-positive-output", f"output {n} value {o.value} <= 0")
            if o.value > MAX_MONEY:
                raise TxInvalid("output-out-of-range", f"output {n} value exceeds MAX_MONEY")
            total += o.value
            if total > MAX_MONEY:
                raise TxInvalid("output-sum-overflow", "sum of outputs exceeds MAX_MONEY")
        try:
            tx.body_bytes()
        except EncodeError as e:
            raise TxInvalid("malformed", str(e)) from None
        return total

    def validate(self, tx: Transaction) -> int:
        """Validate a NON-coinbase tx against this set. Returns the fee."""
        if tx.is_coinbase:
            raise TxInvalid("unexpected-coinbase", "coinbase only allowed as first tx of a block")
        total_out = self.check_outputs(tx)
        sighash = tx.sighash()
        seen, total_in = set(), 0
        for n, i in enumerate(tx.inputs):
            if i.prevout in seen:
                raise TxInvalid("duplicate-input", f"input {n} repeats {i.prevout}")
            seen.add(i.prevout)
            prev = self.utxos.get(i.prevout)
            if prev is None:
                raise TxInvalid("missing-or-spent-input", f"input {n} {i.prevout} is not unspent")
            if pubkey_hash(i.pubkey) != prev.pubkey_hash:
                raise TxInvalid("pubkey-mismatch", f"input {n} pubkey does not match lock")
            if not verify_sig(i.pubkey, i.signature, sighash):
                raise TxInvalid("bad-signature", f"input {n} signature invalid")
            total_in += prev.value
        if total_in < total_out:
            raise TxInvalid("outputs-exceed-inputs", f"outputs {total_out} > inputs {total_in}")
        return total_in - total_out

    def _txid_has_unspent(self, txid: bytes, n_out: int) -> bool:
        return any(OutPoint(txid, k) in self.utxos for k in range(n_out))

    def apply(self, tx: Transaction) -> TxUndo:
        """Apply an already-validated tx (or a checked coinbase); return undo data."""
        txid = tx.txid()
        if self._txid_has_unspent(txid, len(tx.outputs)):
            raise TxInvalid("txid-collision", "a tx with this txid still has unspent outputs")
        undo = TxUndo(txid)
        if not tx.is_coinbase:
            for i in tx.inputs:
                undo.spent.append((i.prevout, self.utxos.pop(i.prevout)))
        for n, o in enumerate(tx.outputs):
            op = OutPoint(txid, n)
            self.utxos[op] = o
            undo.created.append(op)
        return undo

    def undo(self, u: TxUndo) -> None:
        for op in u.created:
            del self.utxos[op]
        for op, o in u.spent:
            self.utxos[op] = o

    # --------------------------------------------------------------- inspection
    def listing(self) -> list[dict]:
        return [{"outpoint": op.key(), "value": o.value, "pubkey_hash": o.pubkey_hash.hex()}
                for op, o in sorted(self.utxos.items())]

    def state_hash(self) -> str:
        return sha256(json.dumps(self.listing(), separators=(",", ":")).encode()).hex()

    def balance(self, pkh: bytes) -> int:
        return sum(o.value for o in self.utxos.values() if o.pubkey_hash == pkh)

    def total(self) -> int:
        return sum(o.value for o in self.utxos.values())
