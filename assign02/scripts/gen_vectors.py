"""Regenerate tests/vectors.json (roots are cross-checked against an independent
RFC 6962 implementation in tests/test_merkle.py, and the 8-leaf CT vector is a
published value)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from merkle import MerkleTree  # noqa: E402

ct = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657",
      "606162636465666768696a6b6c6d6e6f"]
roots = [{"name": "rfc6962-ct-8", "leaves_hex": ct,
          "root": MerkleTree([bytes.fromhex(h) for h in ct]).root.hex()}]
for n in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9):
    leaves = [f"tx{i}".encode() for i in range(n)]
    roots.append({"name": f"tx0..tx{n-1}" if n else "empty", "leaves_hex": [l.hex() for l in leaves],
                  "root": MerkleTree(leaves).root.hex()})

leaves = [f"tx{i}".encode() for i in range(5)]
t = MerkleTree(leaves)
good = t.prove(2).to_json_obj()
long = json.loads(json.dumps(good)); long["siblings"].append({"side": "left", "hash": "00" * 32})
wrong_idx = json.loads(json.dumps(good)); wrong_idx["leaf_index"] = 3
proofs = [
    {"name": "5tx-index2-valid", "leaf_hex": b"tx2".hex(), "root": t.root.hex(), "proof": good, "valid": True},
    {"name": "5tx-index2-wrong-leaf", "leaf_hex": b"tx3".hex(), "root": t.root.hex(), "proof": good, "valid": False},
    {"name": "5tx-index2-too-long", "leaf_hex": b"tx2".hex(), "root": t.root.hex(), "proof": long, "valid": False},
    {"name": "5tx-wrong-index", "leaf_hex": b"tx2".hex(), "root": t.root.hex(), "proof": wrong_idx, "valid": False},
]
for i in range(5):
    proofs.append({"name": f"5tx-index{i}", "leaf_hex": leaves[i].hex(), "root": t.root.hex(),
                   "proof": t.prove(i).to_json_obj(), "valid": True})
out = Path(__file__).resolve().parents[1] / "tests" / "vectors.json"
out.write_text(json.dumps({"spec": "leaf=SHA256(0x00||d), node=SHA256(0x01||L||R), empty=SHA256(''), "
                           "odd: last node promoted (RFC 6962 shape)", "roots": roots, "proofs": proofs},
                          indent=2) + "\n")
print("wrote", out)
