"""Base58Check addresses and strict DER signature encoding.

Only *encodings* are implemented here. All elliptic-curve arithmetic, signing,
verification and randomness come from the maintained `cryptography` library
(OpenSSL) and the operating system - never from this code.
"""

from __future__ import annotations

import hashlib

# --------------------------------------------------------------------------- #
# Address = Base58Check( version_byte || pubkey_hash )
#   pubkey_hash = first 20 bytes of SHA-256(compressed 33-byte public key)
#   checksum    = first 4 bytes of SHA-256(SHA-256(version || pubkey_hash))
# --------------------------------------------------------------------------- #
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}

# network_id -> address version byte. Distinct bytes make a testnet address
# unusable on the (pretend) mainnet and vice-versa ("accidental mainnet use").
NETWORK_VERSION_BYTES = {
    "course-testnet": 0x6F,   # addresses start with 'm' or 'n'
    "course-mainnet": 0x00,   # addresses start with '1'
}
PKH_LEN = 20
ADDRESS_PAYLOAD_LEN = 1 + PKH_LEN       # version + pkh


class EncodingError(ValueError):
    pass


class AddressError(EncodingError):
    pass


class SignatureEncodingError(EncodingError):
    pass


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, r = divmod(n, 58)
        out.append(B58_ALPHABET[r])
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + "".join(reversed(out))


def b58decode(s: str) -> bytes:
    if not s:
        raise AddressError("empty Base58 string")
    n = 0
    for c in s:
        if c not in _B58_INDEX:
            raise AddressError(f"invalid Base58 character {c!r}")
        n = n * 58 + _B58_INDEX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def pubkey_hash(pubkey33: bytes) -> bytes:
    if len(pubkey33) != 33 or pubkey33[0] not in (2, 3):
        raise AddressError("public key must be 33-byte SEC1 compressed")
    return sha256(pubkey33)[:PKH_LEN]


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + sha256(sha256(payload))[:4])


def b58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    if len(raw) < 5:
        raise AddressError("address too short")
    payload, check = raw[:-4], raw[-4:]
    if sha256(sha256(payload))[:4] != check:
        raise AddressError("invalid address checksum")
    return payload


def make_address(pubkey33: bytes, network_id: str) -> str:
    if network_id not in NETWORK_VERSION_BYTES:
        raise AddressError(f"unknown network {network_id!r}")
    return b58check_encode(bytes([NETWORK_VERSION_BYTES[network_id]]) + pubkey_hash(pubkey33))


def decode_address(addr: str, network_id: str) -> bytes:
    """Return the 21-byte payload (version||pkh) after full validation."""
    if not isinstance(addr, str):
        raise AddressError("address must be a string")
    payload = b58check_decode(addr)
    if len(payload) != ADDRESS_PAYLOAD_LEN:
        raise AddressError(f"address payload must be {ADDRESS_PAYLOAD_LEN} bytes, got {len(payload)}")
    if b58check_encode(payload) != addr:          # rejects non-canonical spellings
        raise AddressError("non-canonical address encoding")
    want = NETWORK_VERSION_BYTES.get(network_id)
    if want is None:
        raise AddressError(f"unknown network {network_id!r}")
    if payload[0] != want:
        raise AddressError(f"address version 0x{payload[0]:02x} is not valid on {network_id} "
                           f"(expected 0x{want:02x})")
    return payload


# --------------------------------------------------------------------------- #
# Strict DER + low-S (BIP-66 / BIP-62 style) for ECDSA over secp256k1
# --------------------------------------------------------------------------- #
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_N = SECP256K1_N // 2


def _der_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def der_encode(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def _parse_der_int(buf: bytes, i: int) -> tuple[int, int]:
    if i + 2 > len(buf) or buf[i] != 0x02:
        raise SignatureEncodingError("expected DER INTEGER tag 0x02")
    ln = buf[i + 1]
    if ln == 0 or ln > 33:
        raise SignatureEncodingError("bad INTEGER length")
    start, end = i + 2, i + 2 + ln
    if end > len(buf):
        raise SignatureEncodingError("INTEGER runs past end of signature")
    v = buf[start:end]
    if v[0] & 0x80:
        raise SignatureEncodingError("negative INTEGER")
    if ln > 1 and v[0] == 0x00 and not (v[1] & 0x80):
        raise SignatureEncodingError("INTEGER has unnecessary leading zero (non-minimal)")
    return int.from_bytes(v, "big"), end


def der_decode_strict(sig: bytes) -> tuple[int, int]:
    """Parse a DER ECDSA signature, rejecting every non-canonical form."""
    if len(sig) < 8 or len(sig) > 72:
        raise SignatureEncodingError(f"bad signature length {len(sig)}")
    if sig[0] != 0x30:
        raise SignatureEncodingError("expected DER SEQUENCE tag 0x30")
    if sig[1] != len(sig) - 2:
        raise SignatureEncodingError("SEQUENCE length does not match (trailing or missing bytes)")
    r, i = _parse_der_int(sig, 2)
    s, i = _parse_der_int(sig, i)
    if i != len(sig):
        raise SignatureEncodingError("trailing bytes after s")
    if not 1 <= r < SECP256K1_N or not 1 <= s < SECP256K1_N:
        raise SignatureEncodingError("r or s out of range [1, n-1]")
    if s > HALF_N:
        raise SignatureEncodingError("high-S signature (malleable); s must be <= n/2")
    if der_encode(r, s) != sig:                    # belt and braces
        raise SignatureEncodingError("signature is not canonical DER")
    return r, s


def normalize_low_s(r: int, s: int) -> tuple[int, int]:
    return (r, SECP256K1_N - s) if s > HALF_N else (r, s)
