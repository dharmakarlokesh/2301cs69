"""Key generation and the (test-only) private-key file.

Randomness: 32 bytes from the OS CSPRNG via `secrets.token_bytes` (getrandom /
/dev/urandom / BCryptGenRandom), rejected and redrawn until 1 <= k < n.
The scalar is turned into a key by the `cryptography` library; no curve math here.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys

from cryptography.hazmat.primitives.asymmetric import ec

from .encoding import SECP256K1_N, make_address
from .tx import public_key_bytes

TEST_ONLY_WARNING = (
    "TEST-ONLY DEVELOPMENT KEY for the course toy chain. Stored UNENCRYPTED. "
    "Never use it on any real network, never fund it with real value, never commit it to git."
)


class KeyFileError(ValueError):
    pass


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    while True:
        k = int.from_bytes(secrets.token_bytes(32), "big")
        if 1 <= k < SECP256K1_N:
            return ec.derive_private_key(k, ec.SECP256K1())


def write_dev_keyfile(path: str, priv: ec.EllipticCurvePrivateKey, network_id: str) -> dict:
    pub33 = public_key_bytes(priv.public_key())
    k = priv.private_numbers().private_value
    data = {
        "WARNING": TEST_ONLY_WARNING,
        "curve": "secp256k1",
        "network_id": network_id,
        "address": make_address(pub33, network_id),
        "public_key": pub33.hex(),
        "private_key": f"{k:064x}",
    }
    # O_EXCL: never overwrite an existing key. Mode 0600: owner read/write only.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    if os.name == "posix":
        os.chmod(path, 0o600)   # in case a umask/ACL widened it
    return {k: v for k, v in data.items() if k != "private_key"}


def load_dev_keyfile(path: str) -> tuple[ec.EllipticCurvePrivateKey, dict]:
    if os.name == "posix":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            raise KeyFileError(f"refusing to use {path}: permissions {oct(mode)} are too open "
                               f"(run: chmod 600 {path})")
    with open(path) as f:
        data = json.load(f)
    print(f"warning: {data.get('WARNING', TEST_ONLY_WARNING)}", file=sys.stderr)
    k = int(data["private_key"], 16)
    if not 1 <= k < SECP256K1_N:
        raise KeyFileError("private key out of range")
    priv = ec.derive_private_key(k, ec.SECP256K1())
    if public_key_bytes(priv.public_key()).hex() != data["public_key"]:
        raise KeyFileError("key file is corrupt: public key does not match private key")
    return priv, data
