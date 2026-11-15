#!/usr/bin/env python3
"""Independent verifier written ONLY from docs/transaction_format.md.

It does not import toywallet. It shows that an instructor can verify a student's
signed transaction from the public data (signed JSON + public key) and the spec.

usage: python3 scripts/independent_verify.py examples/signed_tx.json [network_id]
"""

import hashlib
import json
import struct
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
VERSION_BYTE = {"course-testnet": 0x6F, "course-mainnet": 0x00}
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def sha(b):
    return hashlib.sha256(b).digest()


def b58check(s):
    n = 0
    for c in s:
        n = n * 58 + ALPH.index(c)
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")
    payload, chk = raw[:-4], raw[-4:]
    assert sha(sha(payload))[:4] == chk, "bad checksum"
    assert len(payload) == 21, "bad address length"
    return payload


def main(path, network="course-testnet"):
    d = json.load(open(path))
    tx = d["tx"]
    assert tx["network_id"] == network, "wrong network"
    snd, rcp = b58check(tx["sender"]), b58check(tx["recipient"])
    assert snd[0] == rcp[0] == VERSION_BYTE[network], "address not for this network"
    net = tx["network_id"].encode()
    msg = (b"TOYCHAIN-TX-V1\x00\x00" + struct.pack(">BB", tx["version"], len(net)) + net + snd + rcp
           + struct.pack(">QQ", tx["amount_units"], tx["nonce"]) + bytes.fromhex(tx["memo_hash"]))
    pub33 = bytes.fromhex(d["public_key"])
    assert sha(pub33)[:20] == snd[1:], "public key does not own sender address"
    sig = bytes.fromhex(d["signature"])
    # strict DER: 30 L 02 lr r 02 ls s, minimal ints, low-S
    assert sig[0] == 0x30 and sig[1] == len(sig) - 2
    lr = sig[3]; r = sig[4:4 + lr]; ls = sig[5 + lr]; s = sig[6 + lr:6 + lr + ls]
    assert sig[2] == 0x02 and sig[4 + lr] == 0x02 and 6 + lr + ls == len(sig)
    for v in (r, s):
        assert not v[0] & 0x80 and not (len(v) > 1 and v[0] == 0 and not v[1] & 0x80), "non-minimal DER"
    assert int.from_bytes(s, "big") <= N // 2, "high-S"
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub33)
    try:
        pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("INVALID signature")
        return 1
    print("signed bytes :", msg.hex())
    print("txid         :", sha(msg).hex())
    print("VALID (independently verified from the specification)")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
