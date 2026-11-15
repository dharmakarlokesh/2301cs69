"""In-memory UTXO ledger with atomic validation and persistence."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass

from .crypto import pubkey_hash, sha256, verify_sig
from .tx import MAX_IO, MAX_MONEY, EncodeError, OutPoint, Transaction, TxOut

SNAPSHOT_FORMAT = "utxo-snapshot-v1"


class TxRejected(Exception):
    """Validation failure with a machine-readable code and a precise reason."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Policy:
    min_fee: int = 0           # base units
    max_fee: int = 10_000      # "absurd fee" guard: catches change that was forgotten or miscomputed


class Ledger:
    def __init__(self, policy: Policy | None = None):
        self.utxos: dict[OutPoint, TxOut] = {}
        self.spent: dict[OutPoint, str] = {}       # outpoint -> txid that spent it
        self.accepted: set[str] = set()            # txids applied to this ledger
        self.policy = policy or Policy()

    # ------------------------------------------------------------------ genesis
    @classmethod
    def from_genesis(cls, allocations: list[tuple[bytes, int]], policy: Policy | None = None) -> "Ledger":
        led = cls(policy)
        gid = sha256(b"UTXO-GENESIS" + b"".join(pkh + v.to_bytes(8, "big") for pkh, v in allocations))
        for i, (pkh, v) in enumerate(allocations):
            if not 0 < v <= MAX_MONEY or len(pkh) != 20:
                raise ValueError("bad genesis allocation")
            led.utxos[OutPoint(gid, i)] = TxOut(v, pkh)
        led.accepted.add(gid.hex())
        return led

    # ------------------------------------------------------------------ queries
    def balance(self, pkh: bytes) -> int:
        return sum(o.value for o in self.utxos.values() if o.pubkey_hash == pkh)

    def utxos_for(self, pkh: bytes) -> dict[OutPoint, TxOut]:
        return {op: o for op, o in self.utxos.items() if o.pubkey_hash == pkh}

    def total_value(self) -> int:
        return sum(o.value for o in self.utxos.values())

    # ------------------------------------------------------------------ validation
    def validate(self, tx: Transaction) -> int:
        """Check everything; return the fee. Never mutates state."""
        # 1. structure
        if not tx.inputs:
            raise TxRejected("no-inputs", "transaction has no inputs")
        if not tx.outputs:
            raise TxRejected("no-outputs", "transaction has no outputs")
        if len(tx.inputs) > MAX_IO or len(tx.outputs) > MAX_IO:
            raise TxRejected("too-many-io", f"more than {MAX_IO} inputs or outputs")

        # 2. output ranges and overflow (u64 / supply cap), before any serialization
        total_out = 0
        for n, o in enumerate(tx.outputs):
            if type(o.value) is not int:
                raise TxRejected("bad-output-type", f"output {n} value is not an integer")
            if o.value < 0:
                raise TxRejected("negative-output", f"output {n} value {o.value} is negative")
            if o.value == 0:
                raise TxRejected("zero-output", f"output {n} has value 0")
            if o.value > MAX_MONEY:
                raise TxRejected("output-out-of-range",
                                 f"output {n} value {o.value} exceeds MAX_MONEY {MAX_MONEY}")
            total_out += o.value
            if total_out > MAX_MONEY:
                raise TxRejected("output-sum-overflow",
                                 f"sum of outputs exceeds MAX_MONEY after output {n}")
            if len(o.pubkey_hash) != 20:
                raise TxRejected("bad-lock", f"output {n} pubkey_hash must be 20 bytes")
        try:
            txid = tx.txid().hex()
            sighash = tx.sighash()
        except EncodeError as e:
            raise TxRejected("malformed", str(e)) from None

        # 3. replay of a whole transaction
        if txid in self.accepted:
            raise TxRejected("duplicate-transaction", f"txid {txid[:16]}… was already applied")

        # 4. inputs: duplicates, existence, double spend
        seen: set[OutPoint] = set()
        total_in = 0
        for n, i in enumerate(tx.inputs):
            op = i.prevout
            if op in seen:
                raise TxRejected("duplicate-input", f"input {n} repeats outpoint {op} within this tx")
            seen.add(op)
            prev = self.utxos.get(op)
            if prev is None:
                if op in self.spent:
                    raise TxRejected("already-spent", f"input {n} outpoint {op} was already spent "
                                                      f"by tx {self.spent[op][:16]}…")
                raise TxRejected("missing-input", f"input {n} outpoint {op} does not exist")
            # 5. authorization: pay-to-public-key-hash
            if pubkey_hash(i.pubkey) != prev.pubkey_hash:
                raise TxRejected("pubkey-mismatch", f"input {n}: public key does not hash to the "
                                                    f"locking pubkey_hash of {op}")
            if not verify_sig(i.pubkey, i.signature, sighash):
                raise TxRejected("bad-signature", f"input {n}: signature invalid or non-canonical")
            total_in += prev.value
            if total_in > MAX_MONEY:
                raise TxRejected("input-sum-overflow", "sum of inputs exceeds MAX_MONEY")

        # 6. value conservation
        if total_in < total_out:
            raise TxRejected("outputs-exceed-inputs",
                             f"outputs {total_out} > inputs {total_in} (would create {total_out - total_in} units)")
        fee = total_in - total_out
        if fee < self.policy.min_fee:
            raise TxRejected("fee-too-low", f"fee {fee} < minimum {self.policy.min_fee}")
        if fee > self.policy.max_fee:
            raise TxRejected("absurd-fee", f"fee {fee} > maximum {self.policy.max_fee}; "
                                           "change output is probably missing or wrong")
        return fee

    def apply(self, tx: Transaction) -> int:
        """Validate, then update the UTXO set atomically. Returns the fee.
        On any failure, raises TxRejected and the state is unchanged."""
        fee = self.validate(tx)
        txid = tx.txid()
        txid_hex = txid.hex()
        # all checks passed - the following cannot fail, so the update is all-or-nothing
        for i in tx.inputs:
            del self.utxos[i.prevout]
            self.spent[i.prevout] = txid_hex
        for n, o in enumerate(tx.outputs):
            self.utxos[OutPoint(txid, n)] = o
        self.accepted.add(txid_hex)
        return fee

    # ------------------------------------------------------------------ persistence
    def utxo_listing(self) -> list[dict]:
        return [{"outpoint": op.key(), "value": o.value, "pubkey_hash": o.pubkey_hash.hex()}
                for op, o in sorted(self.utxos.items())]

    def state_hash(self) -> str:
        """Hash of the canonical, sorted UTXO set (the logical contents)."""
        canon = json.dumps(self.utxo_listing(), sort_keys=True, separators=(",", ":"))
        return sha256(canon.encode()).hex()

    def to_obj(self) -> dict:
        return {
            "format": SNAPSHOT_FORMAT,
            "state_hash": self.state_hash(),
            "total_value": self.total_value(),
            "utxos": self.utxo_listing(),
            "spent": {op.key(): t for op, t in sorted(self.spent.items())},
            "accepted_txids": sorted(self.accepted),
            "policy": {"min_fee": self.policy.min_fee, "max_fee": self.policy.max_fee},
        }

    def save(self, path: str) -> None:
        """Atomic write: temp file in the same directory, fsync, rename."""
        d = os.path.dirname(os.path.abspath(path))
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".snap-", suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.to_obj(), f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    @classmethod
    def load(cls, path: str) -> "Ledger":
        with open(path) as f:
            obj = json.load(f)
        if obj.get("format") != SNAPSHOT_FORMAT:
            raise ValueError("unknown snapshot format")
        led = cls(Policy(**obj["policy"]))
        for u in obj["utxos"]:
            led.utxos[OutPoint.from_key(u["outpoint"])] = TxOut(u["value"], bytes.fromhex(u["pubkey_hash"]))
        led.spent = {OutPoint.from_key(k): v for k, v in obj["spent"].items()}
        led.accepted = set(obj["accepted_txids"])
        if led.state_hash() != obj["state_hash"]:
            raise ValueError("snapshot is corrupt: state_hash mismatch")
        return led

    def logically_equal(self, other: "Ledger") -> bool:
        return (self.utxos == other.utxos and self.spent == other.spent
                and self.accepted == other.accepted and self.policy == other.policy)
