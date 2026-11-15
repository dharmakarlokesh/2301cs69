# Assignment 3 — Keys, Addresses, and Signed Transactions

 **Stack:** Python 3.11+, [`cryptography`](https://cryptography.io) (secp256k1 ECDSA via OpenSSL) · tests with `pytest`

`toywallet` is an educational wallet for a toy chain. It generates keys from OS randomness, derives
Base58Check addresses, builds a canonical binary transaction, signs it, and lets anyone verify it
independently. **No elliptic-curve arithmetic or random-number generation is implemented here.**

## Layout

```
assign03/
├── readme.md
├── pyproject.toml / requirements.txt
├── src/toywallet/
│   ├── encoding.py    ← Base58Check addresses, strict DER + low-S parsing
│   ├── tx.py          ← canonical transaction bytes, sign, verify, replay (nonce) store
│   ├── keys.py        ← OS-random keygen, 0600 TEST-ONLY key file
│   └── cli.py         ← keygen | address | check-address | memo-hash | sign | verify
├── tests/test_wallet.py
├── scripts/independent_verify.py   ← verifier written only from the spec (no toywallet import)
├── docs/transaction_format.md      ← byte-level transaction format (specification)
├── docs/threat_model.md            ← key theft, weak randomness, replay, clipboard, phishing, mainnet
└── examples/tx.json, signed_tx.json, alice.public.json, bob.public.json
```

## How to run

```bash
cd assign03
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

# 1. keys (private key goes to a 0600 file and is never printed)
toywallet keygen --keyfile alice.dev-key.json
toywallet keygen --keyfile bob.dev-key.json
toywallet address --keyfile alice.dev-key.json
toywallet check-address mySRZxR8vRoUEkwQrDbr7VA45gxEjWJNqB

# 2. write a transaction (see examples/tx.json), with sender = Alice's address
toywallet sign examples/tx.json --keyfile alice.dev-key.json --memo "rent for November" -o signed.json
#    (to sign the committed example you need the key that owns its sender, so use your own tx)

# 3. verify, using public data only
toywallet verify examples/signed_tx.json                          # VALID ...
toywallet verify examples/signed_tx.json --network course-mainnet # INVALID: wrong network
toywallet verify examples/signed_tx.json --nonce-db nonces.json   # VALID, nonce recorded
toywallet verify examples/signed_tx.json --nonce-db nonces.json   # INVALID: replayed nonce
python3 scripts/independent_verify.py examples/signed_tx.json     # spec-only verifier

pytest -q                                                         # 42 tests
```

## Design summary

- **Keys:** secp256k1. The private scalar is 32 bytes from `secrets.token_bytes` (the OS CSPRNG),
  redrawn until `1 ≤ k < n`, then handed to `cryptography`.
- **Public key export:** by default `keygen` and `address` output only the public key and address. The
  private key lives in a `*.dev-key.json` file created with `O_EXCL` and mode **0600** and a
  conspicuous **TEST-ONLY** warning. The wallet refuses to load it if its permissions are wider,
  and `.gitignore` excludes it.
- **Address:** `Base58Check(version ‖ SHA-256(pubkey)[0:20])`, with checksum
  `SHA-256²(payload)[0:4]`. The version byte is `0x6F` on `course-testnet` (addresses start with
  `m`/`n`) and `0x00` on `course-mainnet` (start with `1`).
- **Canonical transaction:** a fixed 122-byte layout (for `course-testnet`): domain tag, version,
  network ID, sender, recipient, `amount_units` (u64), `nonce` (u64), `memo_hash` (32 B). The
  layout is in [`docs/transaction_format.md`](docs/transaction_format.md), with a worked hex dump.
- **Signature:** ECDSA-SHA256, strict DER, always **low-S**.

## Acceptance checks → tests

| Requirement | Test(s) |
|---|---|
| Instructor verifies using only public data and the spec | `test_independent_verifier_script`, `test_committed_example_verifies` |
| Changing any signed field fails | `test_changing_any_signed_field_fails` (amount, nonce, memo), `test_changed_recipient_fails`, `test_changed_amount_detected_by_txid_too` |
| Different whitespace or key order → same signed bytes | `test_whitespace_and_key_order_give_same_signed_bytes` |
| Reject changed amount | as above |
| Reject wrong network | `test_wrong_network` (verifier network and relabelled tx) |
| Reject wrong signer | `test_wrong_signer` (foreign public key; signature from another key) |
| Reject replayed nonce | `test_replayed_nonce` (exact replay, persisted store, lower nonce) |
| Reject malformed address or invalid checksum | `test_malformed_addresses_rejected`, `test_address_wrong_length_and_wrong_network`, `test_malformed_and_bad_checksum_address_in_signed_tx` |
| Reject non-canonical signature encoding | `test_non_canonical_signature_encodings` (high-S, padded INTEGER, trailing byte, BER long length, wrong tag, raw r‖s, r = 0) |
| Key file permissions and warning | `test_keyfile_permissions_warning_and_no_overwrite`, `test_keyfile_refused_when_world_readable`, `test_cli_keygen_prints_only_public` |

## Deliverables

- Commands `keygen`, `address`, `sign`, `verify` ✔ (plus `check-address`, `memo-hash`)
- Tests ✔ `tests/test_wallet.py`
- Byte-level transaction-format document ✔ [`docs/transaction_format.md`](docs/transaction_format.md)
- Threat-model note ✔ [`docs/threat_model.md`](docs/threat_model.md)

## Video demo

YouTube (unlisted): _to be added_
