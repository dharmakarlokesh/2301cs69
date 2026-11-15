"""Merkle tree with domain-separated hashing and strict inclusion proofs.

Specification (also in readme.md)
---------------------------------
H            = SHA-256
leaf hash    = H(0x00 || data)
node hash    = H(0x01 || left || right)
empty tree   = H("")              (tree_size 0 has no leaves and no proofs)
odd levels   = the unpaired LAST node of a level is promoted unchanged to the
               next level (it is NOT duplicated). This is exactly the RFC 6962
               (Certificate Transparency) tree shape and avoids Bitcoin's
               duplicate-last-leaf ambiguity (CVE-2012-2459).
proof        = list of sibling hashes from the leaf level up to the root; each
               entry says on which SIDE the sibling sits ("left"/"right").
               Levels where the node was promoted contribute no entry.

Because the tree shape is fully determined by (leaf_index, tree_size), a
verifier recomputes the expected sequence of sides and rejects any proof
whose length or directions differ - so wrong indexes and over-long proofs
are rejected, not silently accepted.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Iterable, Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").digest()
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ProofError(ValueError):
    """Malformed or inconsistent proof."""


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _next_level(level: Sequence[bytes]) -> list[bytes]:
    sha = hashlib.sha256
    nxt = [sha(NODE_PREFIX + level[i] + level[i + 1]).digest()
           for i in range(0, len(level) - 1, 2)]
    if len(level) % 2:
        nxt.append(level[-1])                       # promote, don't duplicate
    return nxt


class MerkleTree:
    """Stores every level so proofs are O(log n) lookups after O(n) build."""

    def __init__(self, leaves: Iterable[bytes]):
        level = [leaf_hash(d) for d in leaves]
        self.levels: list[list[bytes]] = [level]
        while len(level) > 1:
            level = _next_level(level)
            self.levels.append(level)

    @classmethod
    def from_leaf_hashes(cls, hashes: Sequence[bytes]) -> "MerkleTree":
        t = cls.__new__(cls)
        level = list(hashes)
        t.levels = [level]
        while len(level) > 1:
            level = _next_level(level)
            t.levels.append(level)
        return t

    @property
    def size(self) -> int:
        return len(self.levels[0])

    @property
    def root(self) -> bytes:
        return EMPTY_ROOT if self.size == 0 else self.levels[-1][0]

    def prove(self, index: int) -> "Proof":
        if not 0 <= index < self.size:
            raise IndexError(f"leaf_index {index} out of range for tree_size {self.size}")
        siblings: list[tuple[str, bytes]] = []
        i = index
        for level in self.levels[:-1]:
            if i % 2 == 1:
                siblings.append(("left", level[i - 1]))
            elif i + 1 < len(level):
                siblings.append(("right", level[i + 1]))
            # else: last unpaired node, promoted -> no sibling at this level
            i //= 2
        return Proof(index, self.size, siblings)


def merkle_root(leaves: Iterable[bytes]) -> bytes:
    """Root without keeping all levels in memory (O(n) time, O(n) peak for level 0)."""
    level = [leaf_hash(d) for d in leaves]
    if not level:
        return EMPTY_ROOT
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def expected_sides(index: int, size: int) -> list[str]:
    """The exact sequence of sibling sides a valid proof must have."""
    if size < 1 or not 0 <= index < size:
        raise ProofError(f"leaf_index {index} invalid for tree_size {size}")
    sides: list[str] = []
    i, n = index, size
    while n > 1:
        if i % 2 == 1:
            sides.append("left")
        elif i + 1 < n:
            sides.append("right")
        i //= 2
        n = (n + 1) // 2
    return sides


@dataclass(frozen=True)
class Proof:
    leaf_index: int
    tree_size: int
    siblings: list[tuple[str, bytes]]

    # ---- JSON (de)serialization ------------------------------------------------
    def to_json_obj(self) -> dict:
        return {
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "siblings": [{"side": s, "hash": h.hex()} for s, h in self.siblings],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_json_obj(), indent=indent)

    @classmethod
    def from_json(cls, text: str) -> "Proof":
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            raise ProofError(f"proof is not valid JSON: {e}") from None
        return cls.from_json_obj(obj)

    @classmethod
    def from_json_obj(cls, obj) -> "Proof":
        if not isinstance(obj, dict):
            raise ProofError("proof must be a JSON object")
        if set(obj) != {"leaf_index", "tree_size", "siblings"}:
            raise ProofError(f"proof keys must be exactly leaf_index, tree_size, siblings; got {sorted(obj)}")
        idx, size, sibs = obj["leaf_index"], obj["tree_size"], obj["siblings"]
        for name, v in (("leaf_index", idx), ("tree_size", size)):
            if type(v) is not int:            # bool is an int subclass: reject it too
                raise ProofError(f"{name} must be an integer")
        if size < 1:
            raise ProofError("tree_size must be >= 1")
        if not 0 <= idx < size:
            raise ProofError(f"leaf_index {idx} out of range for tree_size {size}")
        if not isinstance(sibs, list):
            raise ProofError("siblings must be a list")
        parsed: list[tuple[str, bytes]] = []
        for n, s in enumerate(sibs):
            if not isinstance(s, dict) or set(s) != {"side", "hash"}:
                raise ProofError(f"sibling {n} must have exactly 'side' and 'hash'")
            if s["side"] not in ("left", "right"):
                raise ProofError(f"sibling {n}: invalid direction {s['side']!r}")
            if not isinstance(s["hash"], str) or not _HEX64.match(s["hash"]):
                raise ProofError(f"sibling {n}: malformed hash (need 64 lowercase hex chars)")
            parsed.append((s["side"], bytes.fromhex(s["hash"])))
        return cls(idx, size, parsed)


def root_from_proof(leaf: bytes, proof: Proof) -> bytes:
    """Recompute the root after checking the proof's shape against (index, size)."""
    want = expected_sides(proof.leaf_index, proof.tree_size)
    got = [s for s, _ in proof.siblings]
    if len(got) > len(want):
        raise ProofError(f"proof too long: {len(got)} siblings, expected {len(want)}")
    if len(got) < len(want):
        raise ProofError(f"proof too short: {len(got)} siblings, expected {len(want)}")
    if got != want:
        raise ProofError(f"sibling directions {got} do not match leaf_index "
                         f"{proof.leaf_index} in tree_size {proof.tree_size} (expected {want})")
    h = leaf_hash(leaf)
    for side, sib in proof.siblings:
        h = node_hash(sib, h) if side == "left" else node_hash(h, sib)
    return h


def verify(leaf: bytes, proof: Proof, expected_root: bytes,
           tree_size: int | None = None) -> bool:
    """True iff `leaf` is at proof.leaf_index in a tree of proof.tree_size with that root.

    IMPORTANT: the root alone does not commit to tree_size, so a proof's
    (leaf_index, tree_size) claim is only meaningful if the verifier knows the
    real size from a trusted source (e.g. the tx count in a block header).
    Pass it as `tree_size` and any mismatching proof is rejected. Without it,
    the leaf is still proven to be *in* the tree, but its index is unauthenticated.
    """
    if tree_size is not None and proof.tree_size != tree_size:
        return False
    try:
        return root_from_proof(leaf, proof) == expected_root
    except ProofError:
        return False
