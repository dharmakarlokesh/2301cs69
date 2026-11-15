"""Wallet-side transaction builder with deterministic coin selection.

Strategy: **largest-first**.
  Candidates = this wallet's UTXOs, sorted by (value DESC, txid ASC, index ASC).
  Take candidates in that order until  selected >= amount + fee.
  change = selected - amount - fee; a change output is added only if change > 0.
  Output order: [payment, change].
The tie-break on (txid, index) makes the choice fully deterministic: the same
UTXO set and request always produce the same transaction body and txid.

Why largest-first: few inputs (small tx, low fee) and simple to audit; the
trade-off is that it leaves many small UTXOs behind and leaks which coin is
change. It is not privacy-optimal (branch-and-bound would try to avoid change).
"""

from __future__ import annotations

from .crypto import Key
from .tx import OutPoint, Transaction, TxIn, TxOut


class WalletError(ValueError):
    pass


class InsufficientFunds(WalletError):
    pass


def select_coins(utxos: dict[OutPoint, TxOut], target: int) -> list[tuple[OutPoint, TxOut]]:
    ordered = sorted(utxos.items(), key=lambda kv: (-kv[1].value, kv[0].txid, kv[0].index))
    chosen, total = [], 0
    for op, out in ordered:
        if total >= target:
            break
        chosen.append((op, out))
        total += out.value
    if total < target:
        raise InsufficientFunds(f"need {target}, wallet has {total}")
    return chosen


class Wallet:
    def __init__(self, key: Key, name: str = ""):
        self.key = key
        self.name = name

    @property
    def pkh(self) -> bytes:
        return self.key.pkh

    def build_payment(self, ledger, recipient_pkh: bytes, amount: int, fee: int) -> Transaction:
        if amount <= 0 or fee < 0:
            raise WalletError("amount must be positive and fee non-negative")
        chosen = select_coins(ledger.utxos_for(self.pkh), amount + fee)
        total = sum(o.value for _, o in chosen)
        change = total - amount - fee
        outputs = [TxOut(amount, recipient_pkh)]
        if change > 0:
            outputs.append(TxOut(change, self.pkh))
        unsigned = Transaction(tuple(TxIn(op) for op, _ in chosen), tuple(outputs))
        return self.sign(unsigned)

    def sign(self, tx: Transaction) -> Transaction:
        sig = self.key.sign(tx.sighash())
        return tx.with_witnesses([(self.key.pub, sig)] * len(tx.inputs))


def audit_payment(tx: Transaction, ledger, payer_pkh: bytes, recipient_pkh: bytes,
                  amount: int, fee: int) -> None:
    """Wallet-side sanity check before broadcasting: is the change exactly right?

    Raises WalletError('incorrect change ...') if the outputs don't pay
    `amount` to the recipient and return exactly inputs - amount - fee to the payer."""
    total_in = 0
    for i in tx.inputs:
        prev = ledger.utxos.get(i.prevout)
        if prev is None or prev.pubkey_hash != payer_pkh:
            raise WalletError(f"input {i.prevout} is not an unspent output of the payer")
        total_in += prev.value
    paid = sum(o.value for o in tx.outputs if o.pubkey_hash == recipient_pkh)
    change = sum(o.value for o in tx.outputs if o.pubkey_hash == payer_pkh)
    other = [o for o in tx.outputs if o.pubkey_hash not in (recipient_pkh, payer_pkh)]
    if other:
        raise WalletError("transaction pays an unexpected third party")
    if paid != amount:
        raise WalletError(f"recipient receives {paid}, expected {amount}")
    expected_change = total_in - amount - fee
    if change != expected_change:
        raise WalletError(f"incorrect change: got {change}, expected {expected_change} "
                          f"(inputs {total_in} - amount {amount} - fee {fee})")
