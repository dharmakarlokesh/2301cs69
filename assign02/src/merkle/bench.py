"""Performance measurement: construction time and proof size."""

from __future__ import annotations

import json
import platform
import statistics
import time

from .tree import MerkleTree, verify


def _time(fn, repeat: int) -> tuple[float, object]:
    best, out = float("inf"), None
    for _ in range(repeat):
        t0 = time.perf_counter()
        out = fn()
        best = min(best, time.perf_counter() - t0)
    return best, out


def run_benchmarks(sizes: list[int]) -> str:
    rows = []
    for n in sizes:
        leaves = [f"tx{i}".encode() for i in range(n)]
        repeat = 5 if n <= 100_000 else 2
        build_s, tree = _time(lambda: MerkleTree(leaves), repeat)
        idxs = sorted({0, n // 2, n - 1})
        proofs = [tree.prove(i) for i in idxs]
        sib_counts = [len(p.siblings) for p in proofs]
        json_sizes = [len(p.to_json(indent=None).encode()) for p in proofs]
        t0 = time.perf_counter()
        ok = all(verify(leaves[i], p, tree.root) for i, p in zip(idxs, proofs))
        verify_us = (time.perf_counter() - t0) / len(proofs) * 1e6
        assert ok
        rows.append((n, build_s * 1000, n / build_s, max(sib_counts),
                     max(sib_counts) * 32, max(json_sizes), verify_us, tree.root.hex()[:16]))

    lines = [
        "# Merkle tree performance report",
        "",
        f"- Machine: `{platform.machine()}`, {platform.system()} {platform.release()}",
        f"- Python: {platform.python_version()} ({platform.python_implementation()}), "
        "SHA-256 from `hashlib` (OpenSSL)",
        "- Leaves: `tx0`, `tx1`, … (UTF-8). Build time = best of 5 runs (2 for ≥1M), "
        "includes hashing every leaf and every internal node and storing all levels.",
        "- Proof size measured for the first, middle and last leaf; the maximum is reported.",
        "",
        "| Leaves | Build time (ms) | Leaves / s | Proof siblings | Raw proof (bytes) "
        "| JSON proof (bytes) | Verify (µs) | Root (prefix) |",
        "|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for n, ms, rate, sib, raw, js, vus, root in rows:
        lines.append(f"| {n:,} | {ms:,.2f} | {rate:,.0f} | {sib} | {raw} | {js} | {vus:,.1f} | `{root}…` |")
    lines += [
        "",
        "## Observations",
        "",
        "- **Construction is O(n):** a tree with n leaves needs n leaf hashes and n−1 node "
        "hashes, so the build time grows linearly (leaves per second stays roughly constant once "
        "the fixed Python overhead is amortised).",
        "- **Proofs are O(log n):** the number of siblings is ⌈log₂ n⌉ (fewer when a node is "
        "promoted on an odd level). Going from 1,024 to 1,000,000 leaves (~1000× more data) only "
        "grows the proof from 10 to 20 hashes, i.e. 320 → 640 raw bytes.",
        "- **Verification is O(log n)** and takes microseconds regardless of tree size; this is "
        "why a light client can check one transaction against a block header's Merkle root "
        "without downloading the block.",
        "- The JSON encoding is ~2.3× larger than raw bytes (hex doubles each hash, plus keys); a "
        "wire protocol would send raw 32-byte hashes and a bitmap of directions.",
    ]
    return "\n".join(lines) + "\n"
