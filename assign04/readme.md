# Assignment 4 — A UTXO Ledger and Transaction Validator

 **Stack:** Python 3.11+, `cryptography` (secp256k1 ECDSA) · tests with `pytest`

An in-memory UTXO ledger that enforces value conservation, pay-to-public-key-hash authorisation and
double-spend prevention. It comes with a deterministic wallet-side transaction builder, atomic state
updates, and snapshot persistence. No mining or networking yet; those come in Assignments 5 and 6.

## Layout

```
assign04/
├── readme.md
├── pyproject.toml / requirements.txt
├── src/utxo/
│   ├── crypto.py   ← keys, P2PKH hash, strict-DER low-S ECDSA (via `cryptography`)
│   ├── tx.py       ← OutPoint, TxIn, TxOut, Transaction, canonical bytes, txid, sighash
│   ├── ledger.py   ← validator, atomic apply, snapshots (save/load)
│   ├── wallet.py   ← largest-first coin selection, builder, change audit
│   ├── demo.py     ← scripted scenario → trace + snapshots
│   └── cli.py      ← `utxo demo`, `utxo show <snapshot>`
├── tests/test_utxo.py           ← 28 tests
├── reports/trace.md             ← accepted and rejected transactions with precise reasons
└── snapshots/00_genesis.json, 01_after_alice_pays_bob.json, 02_final.json
```

## How to run

```bash
cd assign04
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

utxo demo                       # runs the scenario, rewrites reports/trace.md and snapshots/
utxo show snapshots/02_final.json
pytest -q
```

Without installing: `PYTHONPATH=src python3 -m utxo demo`.

## Data model

| Concept | Definition |
|---|---|
| Outpoint | `transaction_id (32 B) + output_index (u32)` |
| Output | `value` (integer base units) + locking condition `{"type":"p2pkh","pubkey_hash": 20 B}` |
| P2PKH | `pubkey_hash = SHA-256(compressed pubkey)[0:20]`. To spend, an input supplies `pubkey` and `signature`; the validator checks `hash(pubkey) == lock` and that the ECDSA signature over the sighash is valid (strict DER, low-S) |
| Canonical bytes | `"UTXO-TX-V1\0" ‖ version u32 ‖ n_in u16 ‖ (txid ‖ index u32)* ‖ n_out u16 ‖ (value u64 ‖ pkh)*`, big-endian |
| Transaction ID | `txid = SHA-256(canonical bytes)`. Signatures and pubkeys are **excluded** (like SegWit), so a third party cannot change a txid by re-encoding a signature |
| Sighash | `SHA-256("UTXO-SIGHASH-ALL" ‖ canonical bytes)`, signed by every input, so it commits to all inputs and outputs |
| Supply cap | `MAX_MONEY = 21,000,000 × 10^8`; every value and every running sum must stay ≤ MAX_MONEY, which also rules out u64 overflow |

## Validation rules (in order)

| Code | Rule |
|---|---|
| `no-inputs`, `no-outputs`, `too-many-io` | structure |
| `bad-output-type`, `negative-output`, `zero-output`, `output-out-of-range`, `output-sum-overflow` | output ranges and arithmetic overflow |
| `duplicate-transaction` | txid already applied (replay of the same signed tx) |
| `duplicate-input` | the same outpoint appears twice in one tx |
| `already-spent` | the outpoint existed but was consumed earlier (the error names the spending txid) |
| `missing-input` | the outpoint never existed |
| `pubkey-mismatch` | the supplied pubkey does not hash to the output's lock |
| `bad-signature` | the signature is invalid, made by the wrong key, over tampered data, or non-canonical |
| `input-sum-overflow` | Σinputs > MAX_MONEY |
| `outputs-exceed-inputs` | Σinputs ≥ Σoutputs is violated (creation of value) |
| `fee-too-low` / `absurd-fee` | fee outside the policy `[min_fee, max_fee]`; `absurd-fee` catches a forgotten or wrong change output |

**Fee** = Σinputs − Σoutputs. **Atomicity:** `Ledger.apply` runs `validate` (which never mutates)
first, and only then deletes the inputs, records them as spent, and inserts the outputs. Because every
check happens before the first write, a validation failure leaves the state unchanged. Each test
asserts this by comparing the UTXO set, spent set, txid set, and state hash before and after.

## Wallet: deterministic coin selection

**Strategy: largest-first.** Sort the wallet's UTXOs by `(value desc, txid asc, index asc)` and take
them until `selected ≥ amount + fee`. Change is `selected − amount − fee`, and a change output is
added only when change > 0. Outputs are ordered `[payment, change]`. The tie-break makes the result
fully deterministic (`test_coin_selection_largest_first_and_deterministic`).

*Trade-off:* few inputs mean a small transaction, but small UTXOs accumulate and change is easy to
identify. Branch-and-bound would try to avoid creating change.

`audit_payment` is the wallet-side check before broadcast: it rejects a transaction whose
recipient amount or change doesn't match `inputs − amount − fee` ("incorrect change").

## Example scenario (from the assignment)

Alice controls 40 and 70. She pays Bob 85 with fee 2. Largest-first picks 70, then 40 (110), giving
**85 → Bob** and **23 → Alice** as change. Submitting the same signed transaction again is rejected
with `duplicate-transaction`, so Bob is not paid twice. See [`reports/trace.md`](reports/trace.md)
for the full trace: 16 steps, 3 accepted, 12 rejected by the ledger, and 1 blocked by the wallet,
each with its precise reason and the state hash before and after.

## Persistence

`Ledger.save` writes a sorted JSON snapshot atomically (temp file, `fsync`, `os.replace`), including a
`state_hash` over the canonical UTXO listing. `Ledger.load` recomputes that hash and refuses corrupt
snapshots. Tests check that save → load gives a logically equal ledger, that save → load → save is
byte-identical, and that a reloaded ledger still rejects replays and double spends.

## Acceptance checks → tests

| Requirement | Test |
|---|---|
| Reject nonexistent inputs | `test_reject_nonexistent_input` |
| Reject repeated outpoints in one tx | `test_reject_repeated_outpoint_in_one_tx` |
| Reject a second spend of a consumed output | `test_reject_second_spend_of_consumed_output`, `test_same_signed_tx_twice_does_not_pay_twice` |
| Reject bad signatures | `test_reject_wrong_key`, `test_reject_bad_signature_after_tampering`, `test_reject_signature_from_other_input_key`, `test_reject_high_s_signature` |
| Reject negative or overflowing values | `test_reject_negative_value`, `test_reject_overflowing_value`, `test_reject_zero_value`, `test_reject_non_integer_value` |
| Reject excessive creation of value | `test_reject_excessive_creation_of_value` |
| Reject incorrect change | `test_reject_incorrect_change` |
| Failure leaves state unchanged | every `rejected(...)` call, plus `test_failure_in_last_input_leaves_state_unchanged` |
| Persist and reload | `test_persist_and_reload`, `test_corrupt_snapshot_detected` |

## Video demo

YouTube (unlisted): _to be added_
