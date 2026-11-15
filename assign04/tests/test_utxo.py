import copy
import json

import pytest

from utxo.crypto import N, Key, der_encode, strict_der_decode, verify_sig
from utxo.demo import run, signed_tx
from utxo.ledger import Ledger, Policy, TxRejected
from utxo.tx import MAX_MONEY, OutPoint, Transaction, TxIn, TxOut
from utxo.wallet import InsufficientFunds, Wallet, WalletError, audit_payment, select_coins

ALICE, BOB, CAROL, MALLORY = (Key.from_seed(n) for n in ("alice", "bob", "carol", "mallory"))


@pytest.fixture
def led():
    return Ledger.from_genesis([(ALICE.pkh, 40), (ALICE.pkh, 70), (CAROL.pkh, 100)],
                               Policy(min_fee=0, max_fee=10))


def outs(led):
    return sorted(led.utxos)          # [Alice40, Alice70, Carol100]


def rejected(led, tx, code):
    before = (copy.deepcopy(led.utxos), copy.deepcopy(led.spent), set(led.accepted), led.state_hash())
    with pytest.raises(TxRejected) as e:
        led.apply(tx)
    assert e.value.code == code, e.value
    assert (led.utxos, led.spent, led.accepted, led.state_hash()) == before   # state unchanged


def pay_bob(led):
    tx = Wallet(ALICE).build_payment(led, BOB.pkh, 85, 2)
    assert led.apply(tx) == 2
    return tx


# ----------------------------------------------------------- basic structure
def test_outpoint_is_txid_plus_index(led):
    tx = pay_bob(led)
    assert OutPoint(tx.txid(), 0) in led.utxos and OutPoint(tx.txid(), 1) in led.utxos
    assert led.utxos[OutPoint(tx.txid(), 0)] == TxOut(85, BOB.pkh)


def test_txid_is_hash_of_canonical_bytes_and_excludes_signatures(led):
    tx = Wallet(ALICE).build_payment(led, BOB.pkh, 85, 2)
    resigned = Wallet(ALICE).sign(Transaction(tuple(TxIn(i.prevout) for i in tx.inputs), tx.outputs))
    assert tx.inputs[0].signature != resigned.inputs[0].signature   # ECDSA is randomized
    assert tx.txid() == resigned.txid()                               # but txid is stable
    import hashlib
    assert tx.txid() == hashlib.sha256(tx.body_bytes()).digest()


def test_json_roundtrip(led):
    tx = Wallet(ALICE).build_payment(led, BOB.pkh, 85, 2)
    assert Transaction.from_obj(json.loads(json.dumps(tx.to_obj()))).txid() == tx.txid()


# ----------------------------------------------------------- assignment example
def test_example_alice_pays_bob(led):
    tx = Wallet(ALICE).build_payment(led, BOB.pkh, 85, 2)
    assert sorted(led.utxos[i.prevout].value for i in tx.inputs) == [40, 70]
    assert [(o.value, o.pubkey_hash) for o in tx.outputs] == [(85, BOB.pkh), (23, ALICE.pkh)]
    audit_payment(tx, led, ALICE.pkh, BOB.pkh, 85, 2)
    assert led.apply(tx) == 2
    assert led.balance(BOB.pkh) == 85 and led.balance(ALICE.pkh) == 23
    assert led.total_value() == 208


def test_same_signed_tx_twice_does_not_pay_twice(led):
    tx = pay_bob(led)
    rejected(led, tx, "duplicate-transaction")
    assert led.balance(BOB.pkh) == 85


# ----------------------------------------------------------- acceptance-check rejections
def test_reject_nonexistent_input(led):
    rejected(led, signed_tx([(OutPoint(b"\x01" * 32, 0), ALICE)], [TxOut(1, BOB.pkh)]), "missing-input")
    a40 = outs(led)[0]
    rejected(led, signed_tx([(OutPoint(a40.txid, 9), ALICE)], [TxOut(1, BOB.pkh)]), "missing-input")


def test_reject_repeated_outpoint_in_one_tx(led):
    c = outs(led)[2]
    rejected(led, signed_tx([(c, CAROL), (c, CAROL)], [TxOut(150, CAROL.pkh)]), "duplicate-input")


def test_reject_second_spend_of_consumed_output(led):
    pay_bob(led)
    a40 = outs(Ledger.from_genesis([(ALICE.pkh, 40), (ALICE.pkh, 70), (CAROL.pkh, 100)]))[0]
    rejected(led, signed_tx([(a40, ALICE)], [TxOut(40, MALLORY.pkh)]), "already-spent")


def test_reject_wrong_key(led):
    a40 = outs(led)[0]
    rejected(led, signed_tx([(a40, MALLORY)], [TxOut(40, MALLORY.pkh)]), "pubkey-mismatch")


def test_reject_bad_signature_after_tampering(led):
    a40 = outs(led)[0]
    good = signed_tx([(a40, ALICE)], [TxOut(39, BOB.pkh)])
    rejected(led, Transaction(good.inputs, (TxOut(39, MALLORY.pkh),)), "bad-signature")
    rejected(led, Transaction(good.inputs, (TxOut(38, BOB.pkh),)), "bad-signature")


def test_reject_signature_from_other_input_key(led):
    a40, c100 = outs(led)[0], outs(led)[2]
    unsigned = Transaction((TxIn(a40), TxIn(c100)), (TxOut(139, ALICE.pkh),))
    h = unsigned.sighash()
    tx = unsigned.with_witnesses([(ALICE.pub, ALICE.sign(h)), (CAROL.pub, ALICE.sign(h))])
    rejected(led, tx, "bad-signature")


def test_reject_high_s_signature(led):
    a40 = outs(led)[0]
    tx = signed_tx([(a40, ALICE)], [TxOut(39, BOB.pkh)])
    r, s = strict_der_decode(tx.inputs[0].signature)
    assert verify_sig(ALICE.pub, tx.inputs[0].signature, tx.sighash())
    high = der_encode(r, N - s)
    rejected(led, tx.with_witnesses([(ALICE.pub, high)]), "bad-signature")


def test_reject_negative_value(led):
    c = outs(led)[2]
    rejected(led, signed_tx([(c, CAROL)], [TxOut(-1, BOB.pkh), TxOut(100, CAROL.pkh)]), "negative-output")


def test_reject_zero_value(led):
    c = outs(led)[2]
    rejected(led, signed_tx([(c, CAROL)], [TxOut(0, BOB.pkh), TxOut(99, CAROL.pkh)]), "zero-output")


def test_reject_overflowing_value(led):
    c = outs(led)[2]
    rejected(led, signed_tx([(c, CAROL)], [TxOut(2**64, CAROL.pkh)]), "output-out-of-range")
    rejected(led, signed_tx([(c, CAROL)], [TxOut(2**64 - 1, CAROL.pkh)]), "output-out-of-range")
    rejected(led, signed_tx([(c, CAROL)], [TxOut(MAX_MONEY, CAROL.pkh), TxOut(1, CAROL.pkh)]),
             "output-sum-overflow")


def test_reject_non_integer_value(led):
    c = outs(led)[2]
    rejected(led, signed_tx([(c, CAROL)], [TxOut(True, CAROL.pkh)]), "bad-output-type")


def test_reject_excessive_creation_of_value(led):
    c = outs(led)[2]
    rejected(led, signed_tx([(c, CAROL)], [TxOut(101, CAROL.pkh)]), "outputs-exceed-inputs")


def test_reject_incorrect_change(led):
    c = outs(led)[2]
    too_much = signed_tx([(c, CAROL)], [TxOut(30, BOB.pkh), TxOut(75, CAROL.pkh)])
    rejected(led, too_much, "outputs-exceed-inputs")
    too_little = signed_tx([(c, CAROL)], [TxOut(30, BOB.pkh), TxOut(10, CAROL.pkh)])
    with pytest.raises(WalletError, match="incorrect change"):
        audit_payment(too_little, led, CAROL.pkh, BOB.pkh, 30, 1)
    rejected(led, too_little, "absurd-fee")


def test_fee_bounds():
    led = Ledger.from_genesis([(ALICE.pkh, 100)], Policy(min_fee=2, max_fee=10))
    op = outs(led)[0]
    rejected(led, signed_tx([(op, ALICE)], [TxOut(99, BOB.pkh)]), "fee-too-low")
    assert led.apply(signed_tx([(op, ALICE)], [TxOut(98, BOB.pkh)])) == 2


def test_failure_in_last_input_leaves_state_unchanged(led):
    a40, a70, c100 = outs(led)
    unsigned = Transaction((TxIn(a40), TxIn(a70), TxIn(c100)), (TxOut(200, MALLORY.pkh),))
    h = unsigned.sighash()
    tx = unsigned.with_witnesses([(ALICE.pub, ALICE.sign(h))] * 2 + [(MALLORY.pub, MALLORY.sign(h))])
    rejected(led, tx, "pubkey-mismatch")
    assert len(led.utxos) == 3


def test_empty_inputs_or_outputs(led):
    rejected(led, Transaction((), (TxOut(1, BOB.pkh),)), "no-inputs")
    rejected(led, Transaction((TxIn(outs(led)[0]),), ()), "no-outputs")


# ----------------------------------------------------------- fee and value conservation
def test_fee_and_conservation_over_many_payments(led):
    w = {k.pkh: Wallet(k) for k in (ALICE, BOB, CAROL)}
    fees = 0
    for payer, payee, amt, fee in [(ALICE, BOB, 85, 2), (BOB, CAROL, 50, 1), (CAROL, ALICE, 120, 1),
                                   (ALICE, BOB, 100, 3)]:
        fees += led.apply(w[payer.pkh].build_payment(led, payee.pkh, amt, fee))
        assert led.total_value() + fees == 210


# ----------------------------------------------------------- coin selection
def test_coin_selection_largest_first_and_deterministic():
    g = Ledger.from_genesis([(ALICE.pkh, v) for v in (5, 50, 20, 50, 1)])
    chosen = select_coins(g.utxos_for(ALICE.pkh), 60)
    assert [o.value for _, o in chosen] == [50, 50]
    ops = [op for op, _ in chosen]
    assert ops == sorted(ops, key=lambda o: (o.txid, o.index))         # tie broken by outpoint
    tx1 = Wallet(ALICE).build_payment(g, BOB.pkh, 60, 1)
    tx2 = Wallet(ALICE).build_payment(g, BOB.pkh, 60, 1)
    assert tx1.txid() == tx2.txid()


def test_exact_amount_has_no_change_output():
    g = Ledger.from_genesis([(ALICE.pkh, 50)])
    tx = Wallet(ALICE).build_payment(g, BOB.pkh, 49, 1)
    assert len(tx.outputs) == 1
    assert g.apply(tx) == 1


def test_insufficient_funds(led):
    with pytest.raises(InsufficientFunds):
        Wallet(ALICE).build_payment(led, BOB.pkh, 109, 2)


# ----------------------------------------------------------- persistence
def test_persist_and_reload(led, tmp_path):
    pay_bob(led)
    p = tmp_path / "snap.json"
    led.save(str(p))
    again = Ledger.load(str(p))
    assert again.logically_equal(led) and again.state_hash() == led.state_hash()
    # reloaded ledger keeps double-spend and replay knowledge
    tx = Wallet(BOB).build_payment(again, CAROL.pkh, 50, 1)
    assert again.apply(tx) == 1
    rejected(again, tx, "duplicate-transaction")
    # save -> load -> save is byte-identical
    p2 = tmp_path / "snap2.json"
    Ledger.load(str(p)).save(str(p2))
    assert p.read_bytes() == p2.read_bytes()


def test_corrupt_snapshot_detected(led, tmp_path):
    p = tmp_path / "snap.json"
    led.save(str(p))
    obj = json.loads(p.read_text())
    obj["utxos"][0]["value"] += 1000
    p.write_text(json.dumps(obj))
    with pytest.raises(ValueError, match="corrupt"):
        Ledger.load(str(p))


# ----------------------------------------------------------- the full trace
def test_demo_trace_runs(tmp_path):
    report = run(str(tmp_path))
    assert report.count("**ACCEPTED**") == 3
    assert (tmp_path / "snapshots" / "02_final.json").exists()
