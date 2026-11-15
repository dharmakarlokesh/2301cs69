# Merkle tree performance report

- Machine: `x86_64`, Linux 6.18.44-fc-v470
- Python: 3.13.18 (CPython), SHA-256 from `hashlib` (OpenSSL)
- Leaves: `tx0`, `tx1`, … (UTF-8). Build time = best of 5 runs (2 for ≥1M), includes hashing every leaf and every internal node and storing all levels.
- Proof size measured for the first, middle and last leaf; the maximum is reported.

| Leaves | Build time (ms) | Leaves / s | Proof siblings | Raw proof (bytes) | JSON proof (bytes) | Verify (µs) | Root (prefix) |
|---:|---:|---:|---:|---:|---:|---:|---|
| 8 | 0.01 | 1,196,888 | 3 | 96 | 332 | 7.1 | `807a99ec8905538b…` |
| 1,024 | 0.73 | 1,403,076 | 10 | 320 | 1001 | 9.9 | `67bc1450b057e562…` |
| 100,000 | 82.59 | 1,210,786 | 17 | 544 | 1667 | 24.9 | `1dbbf426fa2dc0bb…` |
| 1,000,000 | 902.60 | 1,107,916 | 20 | 640 | 1953 | 27.4 | `2fb5aaabee856ab2…` |

## Observations

- **Construction is O(n):** a tree with n leaves needs n leaf hashes and n−1 node hashes, so the build time grows linearly (leaves per second stays roughly constant once the fixed Python overhead is amortised).
- **Proofs are O(log n):** the number of siblings is ⌈log₂ n⌉ (fewer when a node is promoted on an odd level). Going from 1,024 to 1,000,000 leaves (~1000× more data) only grows the proof from 10 to 20 hashes, i.e. 320 → 640 raw bytes.
- **Verification is O(log n)** and takes microseconds regardless of tree size; this is why a light client can check one transaction against a block header's Merkle root without downloading the block.
- The JSON encoding is ~2.3× larger than raw bytes (hex doubles each hash, plus keys); a wire protocol would send raw 32-byte hashes and a bitmap of directions.
