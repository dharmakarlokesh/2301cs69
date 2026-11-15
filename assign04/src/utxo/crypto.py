"""Keys, pay-to-public-key-hash and strict ECDSA signatures (secp256k1).

All curve math, signing and randomness come from the maintained `cryptography`
library and the OS; this module only handles encodings.
"""

from __future__ import annotations

import hashlib
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def pubkey_hash(pub33: bytes) -> bytes:
    """20-byte P2PKH hash: first 20 bytes of SHA-256(compressed public key)."""
    return sha256(pub33)[:20]


class Key:
    """A secp256k1 key pair (private key kept in memory only)."""

    def __init__(self, priv: ec.EllipticCurvePrivateKey):
        self._priv = priv
        self.pub = priv.public_key().public_bytes(serialization.Encoding.X962,
                                                  serialization.PublicFormat.CompressedPoint)
        self.pkh = pubkey_hash(self.pub)

    @classmethod
    def generate(cls) -> "Key":
        while True:
            k = int.from_bytes(secrets.token_bytes(32), "big")
            if 1 <= k < N:
                return cls(ec.derive_private_key(k, ec.SECP256K1()))

    @classmethod
    def from_seed(cls, label: str) -> "Key":
        """Deterministic TEST key derived from a label (reproducible demos only)."""
        k = int.from_bytes(sha256(b"utxo-demo-key:" + label.encode()), "big") % (N - 1) + 1
        return cls(ec.derive_private_key(k, ec.SECP256K1()))

    def sign(self, msg: bytes) -> bytes:
        r, s = decode_dss_signature(self._priv.sign(msg, ec.ECDSA(hashes.SHA256())))
        if s > N // 2:
            s = N - s
        return der_encode(r, s)


def _der_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def der_encode(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def strict_der_decode(sig: bytes) -> tuple[int, int] | None:
    """Return (r, s) for a canonical DER low-S signature, else None."""
    try:
        if sig[0] != 0x30 or sig[1] != len(sig) - 2:
            return None
        i, vals = 2, []
        for _ in range(2):
            if sig[i] != 0x02:
                return None
            ln = sig[i + 1]
            v = sig[i + 2:i + 2 + ln]
            if ln == 0 or len(v) != ln or v[0] & 0x80 or (ln > 1 and v[0] == 0 and not v[1] & 0x80):
                return None
            vals.append(int.from_bytes(v, "big"))
            i += 2 + ln
        if i != len(sig):
            return None
        r, s = vals
        if not (1 <= r < N and 1 <= s <= N // 2):
            return None
        return r, s
    except IndexError:
        return None


def verify_sig(pub33: bytes, sig: bytes, msg: bytes) -> bool:
    if strict_der_decode(sig) is None:
        return False
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub33)
        pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
