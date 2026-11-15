"""Mempool: validation, duplicate suppression, fee-rate ordering, expiry, conflicts.

Policy
------
* A tx must be valid against the UTXO set of the current tip (Assignment 4 rules).
  Chained unconfirmed spends are not supported (simplification).
* Duplicate txids are ignored ("already-in-mempool").
* fee_rate = fee / size, size = canonical body bytes + witness bytes.
* Conflict (two txs spending the same outpoint): the newcomer replaces the existing
  conflicting tx(s) only if its fee_rate AND absolute fee are strictly higher
  (replace-by-fee); otherwise it is rejected with "mempool-conflict".
* Entries older than `ttl` seconds expire.
* Capacity `max_size` entries; when full, the lowest fee-rate entry is evicted if
  the newcomer pays a higher rate, else the newcomer is rejected ("mempool-full").
* When a block connects: included txs and txs conflicting with it are removed.
  After a reorg, txs from disconnected blocks are re-offered ("reconsidered") and
  every remaining entry is re-validated against the new tip.
"""

from __future__ import annotations

from dataclasses import dataclass

from chain.tx import OutPoint, Transaction
from chain.utxoset import TxInvalid, UtxoSet


def tx_size(tx: Transaction) -> int:
    return len(tx.body_bytes()) + sum(len(i.pubkey) + len(i.signature) for i in tx.inputs)


@dataclass
class Entry:
    tx: Transaction
    fee: int
    size: int
    added: float

    @property
    def fee_rate(self) -> float:
        return self.fee / self.size


class Mempool:
    def __init__(self, ttl: float = 600.0, max_size: int = 5000):
        self.entries: dict[bytes, Entry] = {}
        self.spends: dict[OutPoint, bytes] = {}       # outpoint -> txid spending it
        self.ttl, self.max_size = ttl, max_size

    def __contains__(self, txid: bytes) -> bool:
        return txid in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, txid: bytes) -> Transaction | None:
        e = self.entries.get(txid)
        return e.tx if e else None

    def _remove(self, txid: bytes) -> None:
        e = self.entries.pop(txid, None)
        if e:
            for i in e.tx.inputs:
                if self.spends.get(i.prevout) == txid:
                    del self.spends[i.prevout]

    def add(self, tx: Transaction, utxo: UtxoSet, now: float) -> tuple[bool, str]:
        txid = tx.txid()
        if txid in self.entries:
            return False, "already-in-mempool"
        try:
            fee = utxo.validate(tx)
        except TxInvalid as e:
            return False, e.code
        entry = Entry(tx, fee, tx_size(tx), now)
        conflicts = {self.spends[i.prevout] for i in tx.inputs if i.prevout in self.spends}
        if conflicts:
            olds = [self.entries[c] for c in conflicts]
            if all(entry.fee_rate > o.fee_rate and entry.fee > o.fee for o in olds):
                for c in conflicts:
                    self._remove(c)
                reason = f"replaced {len(conflicts)} conflicting tx (higher fee rate)"
            else:
                return False, "mempool-conflict"
        else:
            reason = "accepted"
        if len(self.entries) >= self.max_size:
            worst = min(self.entries.values(), key=lambda e: (e.fee_rate, e.tx.txid()))
            if worst.fee_rate >= entry.fee_rate:
                return False, "mempool-full"
            self._remove(worst.tx.txid())
        self.entries[txid] = entry
        for i in tx.inputs:
            self.spends[i.prevout] = txid
        return True, reason

    def expire(self, now: float) -> list[bytes]:
        old = [t for t, e in self.entries.items() if now - e.added > self.ttl]
        for t in old:
            self._remove(t)
        return old

    def ordered(self) -> list[Entry]:
        """Highest fee rate first; txid breaks ties deterministically."""
        return sorted(self.entries.values(), key=lambda e: (-e.fee_rate, e.tx.txid()))

    def select(self, utxo: UtxoSet, max_txs: int = 100) -> list[Transaction]:
        chosen, u = [], utxo.copy()
        for e in self.ordered():
            if len(chosen) >= max_txs:
                break
            try:
                u.validate(e.tx)
                u.apply(e.tx)
                chosen.append(e.tx)
            except TxInvalid:
                continue
        return chosen

    def block_connected(self, block) -> None:
        for t in block.txs:
            self._remove(t.txid())
            for i in t.inputs:
                c = self.spends.get(i.prevout)
                if c is not None:
                    self._remove(c)                     # conflicts with the block

    def revalidate(self, utxo: UtxoSet) -> list[bytes]:
        dropped = []
        for txid, e in list(self.entries.items()):
            try:
                utxo.validate(e.tx)
            except TxInvalid:
                self._remove(txid)
                dropped.append(txid)
        return dropped

    def reconsider(self, txs: list[Transaction], utxo: UtxoSet, now: float) -> list[tuple[bytes, bool, str]]:
        return [(t.txid(), *self.add(t, utxo, now)) for t in txs]
