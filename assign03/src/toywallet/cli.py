"""toywallet CLI: keygen / address / sign / verify (+ memo-hash helper)."""

from __future__ import annotations

import argparse
import json
import sys

from .encoding import AddressError, NETWORK_VERSION_BYTES, decode_address, make_address
from .keys import KeyFileError, generate_private_key, load_dev_keyfile, write_dev_keyfile
from .tx import (NonceStore, Transaction, TxError, memo_hash, sign_transaction, strict_json,
                 verify_signed)

NETWORKS = sorted(NETWORK_VERSION_BYTES)


def cmd_keygen(a) -> int:
    public = write_dev_keyfile(a.keyfile, generate_private_key(), a.network)
    print(f"# private key written to {a.keyfile} (mode 0600, TEST ONLY - not printed)", file=sys.stderr)
    print(json.dumps(public, indent=2))           # only public data is exported
    return 0


def cmd_address(a) -> int:
    if a.public_key:
        pub33 = bytes.fromhex(a.public_key)
    else:
        _, data = load_dev_keyfile(a.keyfile)
        pub33 = bytes.fromhex(data["public_key"])
    print(make_address(pub33, a.network))
    return 0


def cmd_check_address(a) -> int:
    payload = decode_address(a.address, a.network)
    print(f"valid {a.network} address; version=0x{payload[0]:02x} pubkey_hash={payload[1:].hex()}")
    return 0


def cmd_memo_hash(a) -> int:
    print(memo_hash(a.memo))
    return 0


def cmd_sign(a) -> int:
    priv, _ = load_dev_keyfile(a.keyfile)
    with open(a.tx) as f:
        obj = strict_json(f.read())
    if a.memo is not None:
        obj["memo_hash"] = memo_hash(a.memo)
    tx = Transaction.from_obj(obj)
    signed = sign_transaction(tx, priv)
    text = json.dumps(signed, indent=2)
    if a.output:
        with open(a.output, "w") as f:
            f.write(text + "\n")
        print(f"signed transaction written to {a.output}; txid {signed['txid']}", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_verify(a) -> int:
    with open(a.signed) as f:
        try:
            obj = strict_json(f.read())
        except TxError as e:
            print(f"INVALID: {e}")
            return 1
    store = NonceStore(a.nonce_db) if a.nonce_db else None
    r = verify_signed(obj, a.network, store)
    if r.ok:
        print(f"VALID: txid {r.tx.txid()} from {r.tx.sender} -> {r.tx.recipient}, "
              f"{r.tx.amount_units} units, nonce {r.tx.nonce}")
        return 0
    print(f"INVALID: {r.reason}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="toywallet", description="Educational secp256k1 wallet")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate a key pair; prints only public data")
    k.add_argument("--keyfile", required=True, help="where to store the TEST-ONLY private key (0600)")
    k.add_argument("--network", choices=NETWORKS, default="course-testnet")
    k.set_defaults(fn=cmd_keygen)

    ad = sub.add_parser("address", help="derive the address of a public key")
    g = ad.add_mutually_exclusive_group(required=True)
    g.add_argument("--public-key", help="33-byte compressed public key (hex)")
    g.add_argument("--keyfile")
    ad.add_argument("--network", choices=NETWORKS, default="course-testnet")
    ad.set_defaults(fn=cmd_address)

    ca = sub.add_parser("check-address", help="validate an address (checksum, version)")
    ca.add_argument("address")
    ca.add_argument("--network", choices=NETWORKS, default="course-testnet")
    ca.set_defaults(fn=cmd_check_address)

    m = sub.add_parser("memo-hash", help="SHA-256 of a UTF-8 memo")
    m.add_argument("memo")
    m.set_defaults(fn=cmd_memo_hash)

    s = sub.add_parser("sign", help="sign a transaction JSON")
    s.add_argument("tx")
    s.add_argument("--keyfile", required=True)
    s.add_argument("--memo", help="set memo_hash = SHA-256(memo)")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_sign)

    v = sub.add_parser("verify", help="verify a signed transaction independently")
    v.add_argument("signed")
    v.add_argument("--network", choices=NETWORKS, default="course-testnet",
                   help="the network this verifier is on")
    v.add_argument("--nonce-db", help="JSON file of accepted nonces (enables replay rejection)")
    v.set_defaults(fn=cmd_verify)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except (TxError, AddressError, KeyFileError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
