# Byte-level transaction format — `TOYCHAIN-TX-V1`

This document is the **specification**. An instructor can verify any signed transaction from it plus
the public data alone. [`scripts/independent_verify.py`](../scripts/independent_verify.py) is a
verifier written only from this page, and it does not import the wallet code.

## 1. Cryptographic primitives

| Item | Choice |
|---|---|
| Curve | secp256k1 (SEC 2) |
| Signature | ECDSA with SHA-256 over the *signing bytes* below; implementation from `cryptography` (OpenSSL) |
| Public key | 33-byte SEC1 **compressed** point (`02`/`03` ‖ X) |
| Randomness | private scalar = 32 bytes from the OS CSPRNG (`secrets.token_bytes`), redrawn until `1 ≤ k < n` |

## 2. Address

```
pubkey_hash = SHA-256(compressed_pubkey)[0:20]
payload     = version_byte (1 byte) || pubkey_hash (20 bytes)          → 21 bytes
checksum    = SHA-256(SHA-256(payload))[0:4]
address     = Base58( payload || checksum )   alphabet 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
                                                (each leading 0x00 byte → one leading '1')
```

| network_id | version byte | address starts with |
|---|---|---|
| `course-testnet` | `0x6F` | `m` or `n` |
| `course-mainnet` | `0x00` | `1` |

Validation rejects: characters outside the alphabet, bad checksum, a payload that isn't 21 bytes, a
non-canonical spelling (re-encoding must reproduce the string), and a version byte that doesn't
belong to the transaction's network.

## 3. Transaction fields (JSON carrier)

| Field | JSON type | Rule |
|---|---|---|
| `version` | integer | must be `1` |
| `network_id` | string | `[a-z0-9-]{1,32}` |
| `sender`, `recipient` | string | valid addresses **for `network_id`** |
| `amount_units` | integer | smallest unit, `1 … 2^64−1` (no floats, no strings) |
| `nonce` | integer | `0 … 2^64−1`; must exceed the sender's last accepted nonce |
| `memo_hash` | string | 64 lowercase hex = SHA-256 of the UTF-8 memo (the memo itself is never signed directly) |

The JSON must contain **exactly** these 7 keys. Duplicate keys, floats, `NaN`, and booleans-as-integers
are rejected. Whitespace and key order are irrelevant because the JSON is never hashed; it is
re-encoded into the fixed binary layout below.

## 4. Signing bytes (all integers big-endian)

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 16 | domain tag | ASCII `TOYCHAIN-TX-V1` + two `0x00` bytes |
| 16 | 1 | version | u8 |
| 17 | 1 | L = len(network_id) | u8 |
| 18 | L | network_id | ASCII |
| 18+L | 21 | sender | address payload (version byte ‖ 20-byte pubkey hash), checksum dropped |
| 39+L | 21 | recipient | same |
| 60+L | 8 | amount_units | u64 |
| 68+L | 8 | nonce | u64 |
| 76+L | 32 | memo_hash | raw 32 bytes |

Total length = 108 + L bytes (122 for `course-testnet`). `txid = SHA-256(signing bytes)`.
The domain tag ensures these bytes can never be confused with another protocol's signed message.

## 5. Signed transaction (what is published)

```json
{
  "tx": { …7 fields… },
  "txid": "<hex, optional; if present must equal SHA-256(signing bytes)>",
  "public_key": "<66 hex chars, compressed>",
  "signature": "<hex, strict DER ECDSA (r, s)>",
  "scheme": "ECDSA-secp256k1-SHA256, strict DER, low-S"
}
```

**Signature canonicality** (prevents malleability, like BIP-66 and BIP-62):
`30 len 02 len(r) r 02 len(s) s` where the outer length is exact, there is no trailing data,
each integer is positive and minimally encoded (a leading `00` only if the next byte ≥ `0x80`),
`1 ≤ r, s < n`, and **`s ≤ n/2` (low-S)**. The signer always normalises `s → n − s` when needed.

## 6. Verification algorithm

1. Parse the JSON strictly and check every field rule in §3.
2. Reject if `network_id` ≠ the verifier's network.
3. Decode both addresses for that network (§2).
4. Build the signing bytes (§4); if `txid` is present it must match.
5. `SHA-256(public_key)[0:20]` must equal the sender's pubkey hash (**right signer**).
6. Parse the signature with the strict DER and low-S rules (§5).
7. Run ECDSA-verify(public_key, signature, signing bytes).
8. (Stateful) The nonce must be greater than the last nonce accepted from this sender (**replay**).

## 7. Worked example (`examples/signed_tx.json`)

| Offset | Size | Field | Bytes (hex) | Meaning |
|---:|---:|---|---|---|
| 0 | 16 | domain tag | `544f59434841494e2d54582d56310000` | `"TOYCHAIN-TX-V1\0\0"` |
| 16 | 1 | version | `01` | u8 = 1 |
| 17 | 1 | len(network_id) | `0e` | u8 = 14 |
| 18 | 14 | network_id | `636f757273652d746573746e6574` | ASCII `"course-testnet"` |
| 32 | 21 | sender | `6f013f4e07ef77137588d5f4f76ce0e8b4f5123e1d` | `mfdYojwBtZF7vHS3ywUwfM3qJtuS4ipMW6` decoded: version 0x6f + pubkey hash |
| 53 | 21 | recipient | `6fc496f39e5cde684df83d021200af08fa94df1af5` | `mySRZxR8vRoUEkwQrDbr7VA45gxEjWJNqB` decoded |
| 74 | 8 | amount_units | `00000000001312d0` | u64 BE = 1250000 |
| 82 | 8 | nonce | `0000000000000007` | u64 BE = 7 |
| 90 | 32 | memo_hash | `b300e20c1c69562a3648bb22067ab521623feedc9d002b5d669618944dbfd620` | SHA-256("rent for November") |

Total: **122 bytes**. `txid = SHA-256(bytes)` = `5f06637f9eac50403d2318b5fd7d68cc43d119eef4a7753012a920c7ee87e1d5`
