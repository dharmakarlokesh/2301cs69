# Assignment 1 — Bytes, Hashes, and Reproducible Data (`hashlab`)

 **Stack:** Python 3.11+ (standard library only) · tests with `pytest`

`hashlab` is a command-line tool that turns text, a hex byte string, or a file into exact bytes and
reports SHA-256 diagnostics. SHA-256 is **not** implemented here: every digest comes from Python's
standard-library `hashlib` (OpenSSL-backed). This assignment is about handling the bytes correctly.

## Layout

```
assign01/
├── readme.md            ← this file
├── pyproject.toml       ← package metadata + `hashlab` console script (no runtime deps)
├── requirements.txt     ← test dependency (pytest)
├── examples/            ← sample inputs used in the demo
├── src/hashlab/         ← source code
│   ├── core.py          ← byte decoding, hashing, avalanche, canonical JSON, demo cases
│   └── cli.py           ← argparse command-line interface
└── tests/test_hashlab.py
```

## How to run

```bash
cd assign01
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[test]"                                  # installs the `hashlab` command + pytest

hashlab text "Alice pays Bob 10"
hashlab hex 0x416c696365
hashlab file examples/tx.json          # any file; '-' reads stdin
hashlab avalanche --text "Alice pays Bob 10" --bit 7
hashlab canonical-json examples/tx.json
hashlab canonical-json --rules         # prints the canonicalization rules
hashlab demo                           # visually similar inputs with different bytes

pytest -q                              # run the full test suite
```

If you don't want to install anything, run it from source: `PYTHONPATH=src python3 -m hashlab text "hi"`.

### Example output

```
$ hashlab text "Alice pays Bob 10"
bytes: 17
sha256: 69ad18dfd1ac4b3d711b02ee62caa00a82f0f67cc11ebacdd0c0ede0d8b6eaed
sha256_base64: aa0Y39GsSz1xGwLuYsqgCoLw9nzBHrrN0MDt4Ni26u0=

$ echo "Alice pays Bob 10" | hashlab file -
bytes: 18
sha256: a559dd30f6cd021ebe7f50aa899b92a360968ff9195877190f1954140d4e1b39

$ hashlab avalanche --text "Alice pays Bob 10" --bit 7
bytes: 17
flipped_bit: 7 (byte 0, mask 0x01)
original_sha256: 69ad18dfd1ac4b3d711b02ee62caa00a82f0f67cc11ebacdd0c0ede0d8b6eaed
flipped_sha256:  effa3a722595f51264a12287702bfeb91e885a703d399a2c74c991a1fd57bcce
changed_bits_in_digest: 119
changed_fraction: 0.465  (ideal ~0.5)
```

> Note: the string `Alice pays Bob 10` is **17** bytes. The assignment's example shows 18, which is
> what you get once a trailing newline is added (for example by `echo`). That is the exact trap
> the "distinguish a trailing newline" acceptance check is about.

## Design decisions (documented rules)

| Topic | Rule |
|---|---|
| Text encoding | UTF-8, **no** Unicode normalization by default (`--normalize NFC` etc. is opt-in) |
| Hex parsing | Optional `0x` prefix; only `[0-9a-fA-F]`; even digit count; whitespace is rejected; `""` = 0 bytes. Malformed input exits with code 2 and `error: malformed hex: …` |
| Output | `bytes`, `sha256` (lowercase hex, 64 chars), `sha256_base64` (standard alphabet, padded) |
| Streaming | `file` reads 64 KiB chunks into `hashlib.sha256().update()`, so memory stays O(chunk) whatever the file size |
| Bit numbering (avalanche) | MSB-first across the message: bit 0 = `0x80` of byte 0, bit 7 = `0x01` of byte 0, bit 8 = `0x80` of byte 1 |
| Hamming distance | popcount of `digestA XOR digestB` over all 256 bits |

### Canonical JSON rules (`hashlab canonical-json --rules`)

1. The top-level value must be a JSON **object**.
2. Duplicate keys at any depth are **rejected**, because the input is ambiguous.
3. Keys are sorted by UTF-16 code units (the same order as RFC 8785 / JCS).
4. No insignificant whitespace; separators are exactly `,` and `:`.
5. Strings are emitted as raw UTF-8, escaping only `"`, `\` and control characters
   (`\b \f \n \r \t`, otherwise `\u00XX`). **No Unicode normalization.**
6. Numbers must be integers within ±(2^53−1). Floats, exponents, NaN, and Infinity are rejected,
   since they have no single spelling.
7. `true`, `false`, and `null` are emitted literally.
8. The canonical text is encoded as UTF-8 and hashed with SHA-256.

So `{"to":"Bob","from":"Alice"}` and `{ "from": "Alice", "to": "Bob" }` hash identically, while
`{"amount":10}` and `{"amount":"10"}` do not.

## Demonstrations (`hashlab demo`)

| Case | A | B | Same digest? |
|---|---|---|---|
| Trailing newline | `Alice pays Bob 10` (17 B) | `…10\n` (18 B) | no |
| Line endings | `line1\nline2` | `line1\r\nline2` | no |
| Unicode normalization | `café` NFC `63 61 66 c3a9` | `café` NFD `63 61 66 65 cc81` | no |
| Integer vs string | `{"amount":10}` | `{"amount":"10"}` | no |
| Key order | `{"from":…,"to":…}` | `{"to":…,"from":…}` | raw: no · canonical: **yes** |

Why this matters for a blockchain: nodes agree on transactions and blocks by **hash**, so two
honest implementations must produce *byte-identical* serializations. Invisible differences
(newline, normalization, number type, key order) would make a signature or transaction ID fail
to verify, or let one logical message carry two IDs (malleability).

## Acceptance checks → tests

| Requirement | Test |
|---|---|
| Matches a trusted independent SHA-256 utility | `test_file_matches_independent_utility` (compares with `sha256sum`/`shasum` on 4 files) and NIST vectors in `test_known_vectors` |
| Rejects malformed hex | `test_hex_malformed_rejected`, `test_hex_cli_rejects_with_nonzero_exit` |
| Distinguishes a trailing newline | `test_trailing_newline_is_distinguished` |
| 100 MB file without ~100 MB memory growth | `test_large_file_is_streamed` writes a 100 MB file and asserts the `tracemalloc` peak stays **< 2 MB** |
| Avalanche | `test_avalanche_example`, `test_avalanche_statistics` (mean over all 136 single-bit flips ≈ 128) |
| Canonical JSON | `test_canonical_*` (order, whitespace, escapes, UTF-16 sort, rejection cases) |

You can also measure the memory bound by hand on Linux:
```bash
head -c 100M /dev/urandom > /tmp/big.bin
/usr/bin/time -v hashlab file /tmp/big.bin 2>&1 | grep -E "sha256|Maximum resident"   # RSS stays ~15–20 MB
```

## Video demo

YouTube (unlisted): _to be added_
