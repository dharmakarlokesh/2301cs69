"""merkle CLI: root / prove / verify / bench / diagram.

Leaves file formats (--format):
  lines (default): one leaf per line; the leaf is the UTF-8 bytes of the line
                   WITHOUT its '\\n' terminator. A '\\r' before '\\n' is rejected
                   (save the file with LF endings) so bytes are never ambiguous.
  hex:             one leaf per line, written as hex (empty line = empty leaf).
"""

from __future__ import annotations

import argparse
import sys

from .bench import run_benchmarks
from .diagram import render_diagram
from .tree import MerkleTree, Proof, ProofError, root_from_proof


def read_leaves(path: str, fmt: str) -> list[bytes]:
    raw = sys.stdin.buffer.read() if path == "-" else open(path, "rb").read()
    if raw == b"":
        return []
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    lines = raw.split(b"\n")
    if any(l.endswith(b"\r") for l in lines):
        raise ValueError("CRLF line endings found; convert the leaves file to LF")
    if fmt == "hex":
        out = []
        for n, l in enumerate(lines, 1):
            try:
                out.append(bytes.fromhex(l.decode("ascii")) if l else b"")
            except ValueError:
                raise ValueError(f"line {n}: malformed hex") from None
        return out
    return lines


def _leaf_arg(a) -> bytes:
    if a.leaf_hex is not None:
        try:
            return bytes.fromhex(a.leaf_hex)
        except ValueError:
            raise ValueError("--leaf-hex is malformed") from None
    return a.leaf.encode("utf-8")


def cmd_root(a) -> int:
    t = MerkleTree(read_leaves(a.leaves, a.format))
    print(f"tree_size: {t.size}")
    print(f"root: {t.root.hex()}")
    return 0


def cmd_prove(a) -> int:
    leaves = read_leaves(a.leaves, a.format)
    t = MerkleTree(leaves)
    proof = t.prove(a.index)
    text = proof.to_json()
    if a.output:
        with open(a.output, "w") as f:
            f.write(text + "\n")
        print(f"root: {t.root.hex()}", file=sys.stderr)
        print(f"proof written to {a.output} ({len(proof.siblings)} siblings)", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_verify(a) -> int:
    with open(a.proof) as f:
        proof = Proof.from_json(f.read())
    root = a.root.lower()
    if len(root) != 64 or any(c not in "0123456789abcdef" for c in root):
        raise ValueError("--root must be 64 hex characters")
    if a.tree_size is not None and proof.tree_size != a.tree_size:
        print(f"INVALID: proof claims tree_size {proof.tree_size}, trusted size is {a.tree_size}")
        return 1
    computed = root_from_proof(_leaf_arg(a), proof)
    if computed == bytes.fromhex(root):
        print("VALID: leaf is included at index", proof.leaf_index)
        return 0
    print(f"INVALID: computed root {computed.hex()} != expected {root}")
    return 1


def cmd_bench(a) -> int:
    report = run_benchmarks(a.sizes)
    if a.output:
        with open(a.output, "w") as f:
            f.write(report)
        print(f"report written to {a.output}", file=sys.stderr)
    print(report)
    return 0


def cmd_diagram(a) -> int:
    print(render_diagram(a.index))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="merkle", description="Merkle tree root / prove / verify")
    sub = p.add_subparsers(dest="cmd", required=True)

    def leaves_args(sp):
        sp.add_argument("leaves", help="leaves file ('-' = stdin)")
        sp.add_argument("--format", choices=["lines", "hex"], default="lines")

    r = sub.add_parser("root", help="print the Merkle root of a leaves file")
    leaves_args(r)
    r.set_defaults(fn=cmd_root)

    pr = sub.add_parser("prove", help="emit an inclusion proof as JSON")
    leaves_args(pr)
    pr.add_argument("--index", type=int, required=True)
    pr.add_argument("-o", "--output")
    pr.set_defaults(fn=cmd_prove)

    v = sub.add_parser("verify", help="verify a proof using only leaf, proof and root")
    g = v.add_mutually_exclusive_group(required=True)
    g.add_argument("--leaf", help="leaf as UTF-8 text")
    g.add_argument("--leaf-hex", help="leaf as hex bytes")
    v.add_argument("--proof", required=True)
    v.add_argument("--root", required=True)
    v.add_argument("--tree-size", type=int,
                   help="trusted tree size (e.g. from a block header); authenticates the index")
    v.set_defaults(fn=cmd_verify)

    b = sub.add_parser("bench", help="measure build time and proof size")
    b.add_argument("--sizes", type=int, nargs="+", default=[8, 1024, 100_000, 1_000_000])
    b.add_argument("-o", "--output")
    b.set_defaults(fn=cmd_bench)

    d = sub.add_parser("diagram", help="Mermaid diagram of the proof path for 5 transactions")
    d.add_argument("--index", type=int, default=2)
    d.set_defaults(fn=cmd_diagram)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except (ProofError, ValueError, IndexError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
