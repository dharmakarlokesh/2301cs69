# Assignment 2 — Merkle Trees and Proofs of Inclusion

 **Stack:** Python 3.11+ (standard library `hashlib` only, no Merkle package) · tests with `pytest`

A Merkle-tree library and CLI (`root`, `prove`, `verify`) with an unambiguous specification,
strict proof parsing, test vectors, a performance report, and a proof-path diagram.

## Layout

```
assign02/
├── readme.md
├── pyproject.toml / requirements.txt
├── src/merkle/
│   ├── tree.py        ← library: hashing, MerkleTree, Proof (JSON), verify
│   ├── cli.py         ← `merkle root | prove | verify | bench | diagram`
│   ├── bench.py       ← performance measurement
│   └── diagram.py     ← Mermaid proof-path diagram
├── tests/test_merkle.py, tests/vectors.json   ← tests and test vectors
├── scripts/gen_vectors.py                     ← regenerates tests/vectors.json
├── reports/performance.md                     ← performance report (8 / 1,024 / 100,000 / 1,000,000 leaves)
├── docs/proof_path_5tx.md                     ← diagram of the exact proof path for 5 transactions
└── examples/five_tx.txt, proof_tx2.json, root.txt
```

## How to run

```bash
cd assign02
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

merkle root examples/five_tx.txt
# tree_size: 5
# root: 410e561afb28190ea4a953dc541c5ee3965b9abc09724adfe1467fd55dfc1949

merkle prove examples/five_tx.txt --index 2 -o proof.json
merkle verify --leaf tx2 --proof proof.json \
       --root 410e561afb28190ea4a953dc541c5ee3965b9abc09724adfe1467fd55dfc1949 --tree-size 5
# VALID: leaf is included at index 2           (exit code 0; INVALID → 1; malformed → 2)

merkle bench -o reports/performance.md        # regenerate the performance report
merkle diagram --index 2                      # Mermaid diagram of the proof path
pytest -q                                     # 70 tests
```

Without installing: `PYTHONPATH=src python3 -m merkle root examples/five_tx.txt`.

**Leaves file:** one leaf per line, and the leaf is the line's UTF-8 bytes *without* the `\n`.
CRLF files are rejected so the bytes are never ambiguous. Use `--format hex` for binary leaves
(one hex string per line).

## Specification

| Item | Rule |
|---|---|
| Hash `H` | SHA-256 |
| Leaf hash | `H_leaf = H(0x00 ‖ data)` |
| Internal node | `H_node = H(0x01 ‖ left ‖ right)` |
| 0 leaves | root = `H("")` = `e3b0c442…b855`; no proofs exist |
| 1 leaf | root = `H_leaf(d0)`; the proof has 0 siblings |
| Odd number of nodes on a level | the **last node is promoted unchanged** to the next level, **not duplicated** |
| Proof | `{leaf_index, tree_size, siblings:[{side, hash}]}`, listed from the leaf level up; `side` is where the sibling sits |
| Verification | recompute: `side=="left"` → `h = H_node(sib, h)`, `side=="right"` → `h = H_node(h, sib)`; compare with root |

This shape is exactly the RFC 6962 (Certificate Transparency) tree: the root for every size 0–33
(and 100, 255–257, 1000) is cross-checked against an independent recursive RFC 6962
implementation, and against the published 8-leaf CT test vector `5dc9da79…4328`.

**Why domain separation (`0x00` / `0x01`)?** Without it, a 64-byte leaf equal to `left‖right` would
hash to the same value as an internal node, so an attacker could pass an internal node off as a
leaf (second-preimage attack). **Why promote rather than duplicate?** Bitcoin duplicates the last
hash, which makes `[a,b,c]` and `[a,b,c,c]` share a root (CVE-2012-2459). Promotion keeps every
leaf list's root distinct (`test_odd_tree_promotes_not_duplicates`).

### Strict proof parsing (rejections)

`Proof.from_json` rejects proofs with:
- keys other than exactly `leaf_index`, `tree_size`, `siblings` (or `side`/`hash` per sibling);
- non-integer or boolean index/size, `tree_size < 1`, or `leaf_index ∉ [0, tree_size)`;
- **malformed hashes**: anything that isn't exactly 64 *lowercase* hex characters;
- **invalid directions**: anything other than `"left"` or `"right"`.

`verify` then computes the exact side sequence that `(leaf_index, tree_size)` implies, and rejects:
- **wrong indexes**, because the directions no longer match the claimed position;
- **unnecessarily long** (or short) proofs, because the sibling count must match exactly.

> **Security note:** a Merkle root does not commit to `tree_size`. The leaf's *membership* is always
> proven, but its claimed *index* is only authenticated when the verifier knows the real size
> from a trusted source, such as the transaction count in a block header. Pass `--tree-size`
> (or `verify(..., tree_size=n)`) for that. `test_index_is_authenticated_only_with_trusted_size`
> shows a forged `(index=1, size=2)` claim for `tx4` that is rejected once the size is supplied.

## Performance (from `reports/performance.md`)

| Leaves | Build time | Proof siblings | Raw proof | JSON proof |
|---:|---:|---:|---:|---:|
| 8 | 0.01 ms | 3 | 96 B | 332 B |
| 1,024 | 0.73 ms | 10 | 320 B | 1,001 B |
| 100,000 | 83 ms | 17 | 544 B | 1,667 B |
| 1,000,000 | 0.90 s | 20 | 640 B | 1,953 B |

Build time is O(n) at about 1.1–1.4 M leaves/s; proof size is O(log n). See the full report for
verification times and discussion.

## Diagram

See [`docs/proof_path_5tx.md`](docs/proof_path_5tx.md) for the exact proof path of `tx2` among 5
transactions: `proof = [right: L3, left: N01, right: L4]`.

## Video demo

YouTube (unlisted): _to be added_
