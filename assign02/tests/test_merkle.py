import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from merkle import (EMPTY_ROOT, MerkleTree, Proof, ProofError, expected_sides, leaf_hash,
                    merkle_root, node_hash, root_from_proof, verify)

HERE = Path(__file__).resolve().parent
SRC = str(HERE.parent / "src")


# ---------------------------------------------------------------------------
# Independent reference: RFC 6962 section 2.1 recursive definition
# MTH({})      = SHA-256()
# MTH({d0})    = SHA-256(0x00 || d0)
# MTH(D[n])    = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),  k = largest power of 2 < n
# ---------------------------------------------------------------------------
def rfc6962_root(d):
    if len(d) == 0:
        return hashlib.sha256(b"").digest()
    if len(d) == 1:
        return hashlib.sha256(b"\x00" + d[0]).digest()
    k = 1
    while k * 2 < len(d):
        k *= 2
    return hashlib.sha256(b"\x01" + rfc6962_root(d[:k]) + rfc6962_root(d[k:])).digest()


# Certificate Transparency test inputs (from the RFC 6962 reference implementation tests)
CT_LEAVES = [bytes.fromhex(h) for h in [
    "", "00", "10", "2021", "3031", "40414243", "5051525354555657",
    "606162636465666768696a6b6c6d6e6f"]]
CT_ROOT_8 = "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"


def test_ct_known_root_8_leaves():
    assert MerkleTree(CT_LEAVES).root.hex() == CT_ROOT_8


def test_domain_separation():
    assert leaf_hash(b"x") == hashlib.sha256(b"\x00x").digest()
    assert node_hash(b"a" * 32, b"b" * 32) == hashlib.sha256(b"\x01" + b"a" * 32 + b"b" * 32).digest()
    # a 64-byte leaf whose bytes equal two child hashes must NOT collide with that node
    l, r = leaf_hash(b"l"), leaf_hash(b"r")
    assert leaf_hash(l + r) != node_hash(l, r)


def test_zero_leaves():
    t = MerkleTree([])
    assert t.size == 0 and t.root == EMPTY_ROOT == hashlib.sha256(b"").digest()
    with pytest.raises(IndexError):
        t.prove(0)


def test_one_leaf():
    t = MerkleTree([b"only"])
    assert t.root == leaf_hash(b"only")
    p = t.prove(0)
    assert p.siblings == []
    assert verify(b"only", p, t.root)


@pytest.mark.parametrize("n", list(range(0, 34)) + [100, 255, 256, 257, 1000])
def test_root_matches_rfc6962_reference(n):
    leaves = [f"tx{i}".encode() for i in range(n)]
    assert MerkleTree(leaves).root == rfc6962_root(leaves) == merkle_root(leaves)


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 33])
def test_every_proof_verifies_and_has_log_length(n):
    leaves = [f"tx{i}".encode() for i in range(n)]
    t = MerkleTree(leaves)
    for i in range(n):
        p = t.prove(i)
        assert verify(leaves[i], p, t.root)
        assert len(p.siblings) <= max(0, (n - 1).bit_length())
        assert [s for s, _ in p.siblings] == expected_sides(i, n)
        # round trip through JSON
        assert verify(leaves[i], Proof.from_json(p.to_json()), t.root)


def test_odd_tree_promotes_not_duplicates():
    a, b, c = (leaf_hash(x) for x in (b"a", b"b", b"c"))
    assert MerkleTree([b"a", b"b", b"c"]).root == node_hash(node_hash(a, b), c)
    # Bitcoin-style duplication would make [a,b,c] and [a,b,c,c] collide; ours must not
    assert MerkleTree([b"a", b"b", b"c"]).root != MerkleTree([b"a", b"b", b"c", b"c"]).root


def test_five_tx_example_proof_shape():
    t = MerkleTree([f"tx{i}".encode() for i in range(5)])
    p = t.prove(2).to_json_obj()
    assert p["leaf_index"] == 2 and p["tree_size"] == 5
    assert [s["side"] for s in p["siblings"]] == ["right", "left", "right"]


# ---- vectors file -----------------------------------------------------------
def test_vectors_file():
    vec = json.loads((HERE / "vectors.json").read_text())
    for case in vec["roots"]:
        leaves = [bytes.fromhex(h) for h in case["leaves_hex"]]
        assert MerkleTree(leaves).root.hex() == case["root"], case["name"]
    for case in vec["proofs"]:
        p = Proof.from_json_obj(case["proof"])
        assert verify(bytes.fromhex(case["leaf_hex"]), p, bytes.fromhex(case["root"])) is case["valid"], case["name"]


# ---- rejection of bad proofs --------------------------------------------------
@pytest.fixture
def setup5():
    leaves = [f"tx{i}".encode() for i in range(5)]
    t = MerkleTree(leaves)
    return leaves, t, t.prove(2).to_json_obj()


def _bad(obj):
    with pytest.raises(ProofError):
        Proof.from_json_obj(obj)


def test_reject_malformed_hash(setup5):
    _, _, p = setup5
    for bad in ["zz" * 32, "ab" * 31, "AB" * 32, "ab" * 33, 123, None]:
        q = copy.deepcopy(p)
        q["siblings"][0]["hash"] = bad
        _bad(q)


def test_reject_invalid_direction(setup5):
    _, _, p = setup5
    for bad in ["up", "LEFT", "", None, 0]:
        q = copy.deepcopy(p)
        q["siblings"][0]["side"] = bad
        _bad(q)


def test_reject_structural_problems(setup5):
    _, _, p = setup5
    for mutate in [
        lambda q: q.pop("tree_size"),
        lambda q: q.update(extra=1),
        lambda q: q.update(leaf_index=-1),
        lambda q: q.update(leaf_index=5),
        lambda q: q.update(leaf_index=True),
        lambda q: q.update(tree_size=0),
        lambda q: q.update(tree_size="5"),
        lambda q: q.update(siblings={}),
        lambda q: q["siblings"][0].update(extra="x"),
    ]:
        q = copy.deepcopy(p)
        mutate(q)
        _bad(q)
    with pytest.raises(ProofError):
        Proof.from_json("{not json")
    with pytest.raises(ProofError):
        Proof.from_json("[]")


def test_reject_wrong_index(setup5):
    leaves, t, p = setup5
    for wrong in (0, 1, 3, 4):
        q = copy.deepcopy(p)
        q["leaf_index"] = wrong
        proof = Proof.from_json_obj(q)          # well-formed ...
        assert not verify(leaves[2], proof, t.root)   # ... but does not verify
        with pytest.raises(ProofError):
            root_from_proof(leaves[2], proof)        # direction mismatch is detected


def test_reject_unnecessarily_long_proof(setup5):
    leaves, t, p = setup5
    q = copy.deepcopy(p)
    q["siblings"].append({"side": "right", "hash": "00" * 32})
    proof = Proof.from_json_obj(q)
    assert not verify(leaves[2], proof, t.root)
    with pytest.raises(ProofError, match="too long"):
        root_from_proof(leaves[2], proof)


def test_reject_short_proof_and_wrong_tree_size(setup5):
    leaves, t, p = setup5
    q = copy.deepcopy(p)
    q["siblings"].pop()
    with pytest.raises(ProofError, match="too short"):
        root_from_proof(leaves[2], Proof.from_json_obj(q))
    # same side-sequence, different claimed size: the root alone cannot tell,
    # so a verifier that knows the real size (from a header) must reject it
    q = copy.deepcopy(p)
    q["tree_size"] = 8
    assert verify(leaves[2], Proof.from_json_obj(q), t.root)            # documented limitation
    assert not verify(leaves[2], Proof.from_json_obj(q), t.root, tree_size=5)


def test_index_is_authenticated_only_with_trusted_size():
    leaves = [f"tx{i}".encode() for i in range(5)]
    t = MerkleTree(leaves)
    real = t.prove(4).to_json_obj()           # tx4 is promoted twice -> single 'left' sibling
    assert [s["side"] for s in real["siblings"]] == ["left"]
    forged = dict(real, leaf_index=1, tree_size=2)
    assert verify(leaves[4], Proof.from_json_obj(forged), t.root)       # index not bound by root
    assert not verify(leaves[4], Proof.from_json_obj(forged), t.root, tree_size=5)
    assert verify(leaves[4], Proof.from_json_obj(real), t.root, tree_size=5)


def test_reject_wrong_leaf_or_root_or_tampered_sibling(setup5):
    leaves, t, p = setup5
    proof = Proof.from_json_obj(p)
    assert not verify(b"tx9", proof, t.root)
    assert not verify(leaves[2], proof, b"\x00" * 32)
    q = copy.deepcopy(p)
    h = q["siblings"][1]["hash"]
    q["siblings"][1]["hash"] = ("0" if h[0] != "0" else "1") + h[1:]
    assert not verify(leaves[2], Proof.from_json_obj(q), t.root)


def test_large_tree_100k():
    leaves = [f"tx{i}".encode() for i in range(100_000)]
    t = MerkleTree(leaves)
    assert t.root == merkle_root(leaves)
    for i in (0, 54_321, 99_999):
        p = t.prove(i)
        assert len(p.siblings) <= 17           # ceil(log2(100000)) = 17
        assert verify(leaves[i], p, t.root)


# ---- CLI end to end -----------------------------------------------------------------
def run(*args):
    return subprocess.run([sys.executable, "-m", "merkle", *args], capture_output=True,
                          text=True, env=dict(os.environ, PYTHONPATH=SRC))


def test_cli_root_prove_verify(tmp_path):
    lf = tmp_path / "leaves.txt"
    lf.write_text("tx0\ntx1\ntx2\ntx3\ntx4\n")
    r = run("root", str(lf))
    root = r.stdout.split("root: ")[1].strip()
    assert root == MerkleTree([f"tx{i}".encode() for i in range(5)]).root.hex()
    pf = tmp_path / "p.json"
    assert run("prove", str(lf), "--index", "2", "-o", str(pf)).returncode == 0
    ok = run("verify", "--leaf", "tx2", "--proof", str(pf), "--root", root)
    assert ok.returncode == 0 and "VALID" in ok.stdout
    bad = run("verify", "--leaf", "tx3", "--proof", str(pf), "--root", root)
    assert bad.returncode == 1
    sized = run("verify", "--leaf", "tx2", "--proof", str(pf), "--root", root, "--tree-size", "8")
    assert sized.returncode == 1
    obj = json.loads(pf.read_text())
    obj["siblings"][0]["side"] = "up"
    pf.write_text(json.dumps(obj))
    mal = run("verify", "--leaf", "tx2", "--proof", str(pf), "--root", root)
    assert mal.returncode == 2 and "invalid direction" in mal.stderr


def test_cli_hex_format_and_crlf(tmp_path):
    lf = tmp_path / "h.txt"
    lf.write_text("\n".join(l.hex() for l in CT_LEAVES) + "\n")
    assert CT_ROOT_8 in run("root", str(lf), "--format", "hex").stdout
    crlf = tmp_path / "c.txt"
    crlf.write_bytes(b"a\r\nb\r\n")
    assert run("root", str(crlf)).returncode == 2
