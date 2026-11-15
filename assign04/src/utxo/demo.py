"""Scripted scenario that produces the accepted/rejected trace and ledger snapshots."""

from __future__ import annotations

import os

from .crypto import Key
from .ledger import Ledger, Policy, TxRejected
from .tx import MAX_MONEY, EncodeError, OutPoint, Transaction, TxIn, TxOut
from .wallet import Wallet, WalletError, audit_payment


def signed_tx(inputs: list[tuple[OutPoint, Key]], outputs: list[TxOut]) -> Transaction:
    """Build a tx and sign each input with the given key (for crafting test cases)."""
    unsigned = Transaction(tuple(TxIn(op) for op, _ in inputs), tuple(outputs))
    try:
        h = unsigned.sighash()
    except EncodeError:                 # e.g. negative value: cannot even be serialized,
        h = b"\x00" * 32                # so sign a placeholder; the validator rejects it first
    return unsigned.with_witnesses([(k.pub, k.sign(h)) for _, k in inputs])


class Tracer:
    def __init__(self, ledger: Ledger, names: dict[bytes, str]):
        self.ledger = ledger
        self.names = names
        self.rows: list[str] = []
        self.step = 0

    def name(self, pkh: bytes) -> str:
        return self.names.get(pkh, pkh.hex()[:8])

    def describe(self, tx: Transaction) -> str:
        ins = ", ".join(str(i.prevout) for i in tx.inputs)
        outs = ", ".join(f"{o.value}→{self.name(o.pubkey_hash)}" for o in tx.outputs)
        return f"in[{ins}] out[{outs}]"

    def submit(self, label: str, tx: Transaction, expect: str | None) -> None:
        """expect=None -> must be accepted; otherwise the exact rejection code."""
        self.step += 1
        before = self.ledger.state_hash()
        try:
            fee = self.ledger.apply(tx)
            result, reason = "ACCEPTED", f"fee {fee}"
            code = None
        except TxRejected as e:
            result, reason, code = "REJECTED", f"`{e.code}`: {e.detail}", e.code
        after = self.ledger.state_hash()
        if code is not None:
            assert after == before, "rejected tx changed state!"
        assert code == expect, f"step {self.step} {label}: expected {expect}, got {code}"
        state = "unchanged" if after == before else f"{before[:8]}→{after[:8]}"
        tid = tx.txid_hex()
        tid = f"`{tid[:12]}`" if not tid.startswith("<") else "(unencodable)"
        self.rows.append(f"| {self.step} | {label} | {tid} | {self.describe(tx)} "
                         f"| **{result}** | {reason} | {state} |")

    def note(self, label: str, result: str, reason: str) -> None:
        self.step += 1
        self.rows.append(f"| {self.step} | {label} | – | – | **{result}** | {reason} | unchanged |")


def run(out_dir: str) -> str:
    os.makedirs(os.path.join(out_dir, "snapshots"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "reports"), exist_ok=True)
    alice, bob, carol, mallory = (Key.from_seed(n) for n in ("alice", "bob", "carol", "mallory"))
    names = {alice.pkh: "Alice", bob.pkh: "Bob", carol.pkh: "Carol", mallory.pkh: "Mallory"}
    led = Ledger.from_genesis([(alice.pkh, 40), (alice.pkh, 70), (carol.pkh, 100)],
                              Policy(min_fee=0, max_fee=10))
    led.save(os.path.join(out_dir, "snapshots", "00_genesis.json"))
    tr = Tracer(led, names)
    gen = sorted(led.utxos)                       # [Alice40, Alice70, Carol100] by index
    a40, a70, c100 = gen[0], gen[1], gen[2]

    # 1. the assignment example: Alice (40 + 70) pays Bob 85 with fee 2 -> change 23
    wa, wb = Wallet(alice, "Alice"), Wallet(bob, "Bob")
    pay = wa.build_payment(led, bob.pkh, 85, 2)
    audit_payment(pay, led, alice.pkh, bob.pkh, 85, 2)
    tr.submit("Alice pays Bob 85, fee 2 (largest-first: 70 then 40, change 23)", pay, None)
    led.save(os.path.join(out_dir, "snapshots", "01_after_alice_pays_bob.json"))
    bob85 = OutPoint(pay.txid(), 0)

    # 2. replay: submitting the same signed tx again must not pay Bob twice
    tr.submit("Same signed transaction submitted again", pay, "duplicate-transaction")
    # 3. double spend of an already-consumed output in a NEW transaction
    tr.submit("Alice re-spends her consumed 40-unit output",
              signed_tx([(a40, alice)], [TxOut(39, mallory.pkh)]), "already-spent")
    # 4. nonexistent input
    tr.submit("Input references a nonexistent outpoint",
              signed_tx([(OutPoint(b"\xab" * 32, 0), alice)], [TxOut(1, bob.pkh)]), "missing-input")
    # 5. repeated outpoint within one transaction
    tr.submit("Carol lists her 100-unit outpoint twice",
              signed_tx([(c100, carol), (c100, carol)], [TxOut(199, carol.pkh)]), "duplicate-input")
    # 6. bad authorization
    tr.submit("Mallory spends Bob's output with her own key",
              signed_tx([(bob85, mallory)], [TxOut(85, mallory.pkh)]), "pubkey-mismatch")
    good = signed_tx([(bob85, bob)], [TxOut(80, carol.pkh), TxOut(4, bob.pkh)])
    tampered = Transaction(good.inputs, (TxOut(80, mallory.pkh), TxOut(4, bob.pkh)))
    tr.submit("Bob's signed tx with recipient changed to Mallory", tampered, "bad-signature")
    # 7. negative / overflowing values
    tr.submit("Negative output value",
              signed_tx([(c100, carol)], [TxOut(-5, mallory.pkh), TxOut(104, carol.pkh)]), "negative-output")
    tr.submit("Output value 2^64 (u64 overflow)",
              signed_tx([(c100, carol)], [TxOut(2**64, carol.pkh)]), "output-out-of-range")
    tr.submit("Two outputs whose sum overflows MAX_MONEY",
              signed_tx([(c100, carol)], [TxOut(MAX_MONEY, carol.pkh), TxOut(MAX_MONEY, carol.pkh)]),
              "output-sum-overflow")
    # 8. excessive creation of value
    tr.submit("Bob spends 85 but creates 90",
              signed_tx([(bob85, bob)], [TxOut(90, bob.pkh)]), "outputs-exceed-inputs")
    # 9. incorrect change
    bad_change = signed_tx([(c100, carol)], [TxOut(30, bob.pkh), TxOut(75, carol.pkh)])
    tr.submit("Carol pays Bob 30 with change 75 (100 in, 105 out)", bad_change, "outputs-exceed-inputs")
    forgot = signed_tx([(c100, carol)], [TxOut(30, bob.pkh)])
    try:
        audit_payment(forgot, led, carol.pkh, bob.pkh, 30, 1)
    except WalletError as e:
        tr.note("Wallet audit: Carol pays Bob 30, fee 1 but forgets change", "BLOCKED by wallet", str(e))
    tr.submit("…same tx submitted anyway: implied fee 70 > max_fee 10", forgot, "absurd-fee")
    # 10. valid follow-ups: Bob pays Carol, Carol pays Alice
    tr.submit("Bob pays Carol 50, fee 1 (change 34)", wb.build_payment(led, carol.pkh, 50, 1), None)
    wc = Wallet(carol, "Carol")
    p3 = wc.build_payment(led, alice.pkh, 120, 1)
    audit_payment(p3, led, carol.pkh, alice.pkh, 120, 1)
    tr.submit("Carol pays Alice 120, fee 1 (100 + 50, change 29)", p3, None)

    final = os.path.join(out_dir, "snapshots", "02_final.json")
    led.save(final)
    reloaded = Ledger.load(final)
    assert reloaded.logically_equal(led) and reloaded.state_hash() == led.state_hash()

    bal = {n: led.balance(k.pkh) for k, n in ((alice, "Alice"), (bob, "Bob"), (carol, "Carol"),
                                              (mallory, "Mallory"))}
    fees = 210 - led.total_value()
    lines = [
        "# UTXO ledger trace",
        "",
        "Generated by `python -m utxo demo` (keys are deterministic demo keys, so txids are reproducible; "
        "signatures are not part of the txid).",
        "",
        "Genesis: Alice 40, Alice 70, Carol 100 (total 210). Policy: `min_fee=0`, `max_fee=10`.",
        "",
        "| # | Action | txid | Inputs / outputs | Result | Reason | State hash |",
        "|---:|---|---|---|---|---|---|",
        *tr.rows,
        "",
        "## Final state",
        "",
        "| Owner | Balance |",
        "|---|---:|",
        *[f"| {n} | {v} |" for n, v in bal.items()],
        f"| *fees collected (destroyed in A4; paid to miners in A5)* | {fees} |",
        "",
        f"Final UTXO state hash: `{led.state_hash()}`.",
        "Snapshot `snapshots/02_final.json` was saved, reloaded and compared: logically identical ✔",
        "",
        "Every rejected transaction left the state hash unchanged (asserted for every row).",
    ]
    report = "\n".join(lines) + "\n"
    with open(os.path.join(out_dir, "reports", "trace.md"), "w") as f:
        f.write(report)
    return report
