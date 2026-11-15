"""Canonical transaction format, signing and verification.

Byte layout of the signed message (see docs/transaction_format.md):

  offset  size  field
  0       16    domain tag  b"TOYCHAIN-TX-V1\\x00\\x00" (fixed, prevents cross-protocol reuse)
  16      1     version            u8   (must be 1)
  17      1     len(network_id)    u8   (1..32)
  18      L     network_id         ASCII [a-z0-9-]
  ..      21    sender             version byte || 20-byte pubkey hash
  ..      21    recipient          version byte || 20-byte pubkey hash
  ..      8     amount_units       u64 big-endian, 1..2^64-1
  ..      8     nonce              u64 big-endian
  ..      32    memo_hash          raw 32 bytes (SHA-256 of the UTF-8 memo)

The JSON form is only a carrier: it is parsed strictly and re-encoded into
these bytes, so whitespace and key order can never change what is signed.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .encoding import (AddressError, SignatureEncodingError, decode_address, der_decode_strict,
                       der_encode, normalize_low_s, pubkey_hash, sha256)

DOMAIN_TAG = b"TOYCHAIN-TX-V1\x00\x00"
assert len(DOMAIN_TAG) == 16
TX_VERSION = 1
TX_FIELDS = ("version", "network_id", "sender", "recipient", "amount_units", "nonce", "memo_hash")
_NET_RE = re.compile(r"^[a-z0-9-]{1,32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
U64_MAX = 2**64 - 1


class TxError(ValueError):
    pass


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise TxError(f"duplicate JSON key {k!r}")
        d[k] = v
    return d


def strict_json(text: str):
    try:
        return json.loads(text, object_pairs_hook=_no_dupes,
                          parse_float=lambda s: (_ for _ in ()).throw(TxError(f"float {s} not allowed")),
                          parse_constant=lambda s: (_ for _ in ()).throw(TxError(f"{s} not allowed")))
    except json.JSONDecodeError as e:
        raise TxError(f"invalid JSON: {e}") from None


def _int(obj, name, lo, hi):
    v = obj[name]
    if type(v) is not int or not lo <= v <= hi:
        raise TxError(f"{name} must be an integer in [{lo}, {hi}]")
    return v


@dataclass(frozen=True)
class Transaction:
    version: int
    network_id: str
    sender: str
    recipient: str
    amount_units: int
    nonce: int
    memo_hash: str

    @classmethod
    def from_obj(cls, obj) -> "Transaction":
        if not isinstance(obj, dict):
            raise TxError("transaction must be a JSON object")
        if set(obj) != set(TX_FIELDS):
            missing, extra = set(TX_FIELDS) - set(obj), set(obj) - set(TX_FIELDS)
            raise TxError(f"transaction fields mismatch; missing={sorted(missing)} extra={sorted(extra)}")
        version = _int(obj, "version", TX_VERSION, TX_VERSION)
        net = obj["network_id"]
        if not isinstance(net, str) or not _NET_RE.match(net):
            raise TxError("network_id must match [a-z0-9-]{1,32}")
        amount = _int(obj, "amount_units", 1, U64_MAX)
        nonce = _int(obj, "nonce", 0, U64_MAX)
        memo = obj["memo_hash"]
        if not isinstance(memo, str) or not _HEX64.match(memo):
            raise TxError("memo_hash must be 64 lowercase hex characters")
        tx = cls(version, net, obj["sender"], obj["recipient"], amount, nonce, memo)
        tx.signing_bytes()          # validates both addresses for this network
        return tx

    @classmethod
    def from_json(cls, text: str) -> "Transaction":
        return cls.from_obj(strict_json(text))

    def to_obj(self) -> dict:
        return {k: getattr(self, k) for k in TX_FIELDS}

    def signing_bytes(self) -> bytes:
        net = self.network_id.encode("ascii")
        try:
            sender = decode_address(self.sender, self.network_id)
            recipient = decode_address(self.recipient, self.network_id)
        except AddressError as e:
            raise TxError(f"address error: {e}") from None
        return b"".join([
            DOMAIN_TAG,
            struct.pack(">BB", self.version, len(net)), net,
            sender, recipient,
            struct.pack(">QQ", self.amount_units, self.nonce),
            bytes.fromhex(self.memo_hash),
        ])

    def txid(self) -> str:
        return sha256(self.signing_bytes()).hex()


def memo_hash(memo: str) -> str:
    return sha256(memo.encode("utf-8")).hex()


# --------------------------------------------------------------------------- #
# Signing / verification
# --------------------------------------------------------------------------- #
def public_key_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def load_public_key(pub33: bytes) -> ec.EllipticCurvePublicKey:
    if len(pub33) != 33 or pub33[0] not in (2, 3):
        raise TxError("public key must be 33-byte compressed SEC1")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub33)
    except ValueError:
        raise TxError("public key is not a valid secp256k1 point") from None


def sign_transaction(tx: Transaction, priv: ec.EllipticCurvePrivateKey) -> dict:
    pub33 = public_key_bytes(priv.public_key())
    sender_payload = decode_address(tx.sender, tx.network_id)
    if sender_payload[1:] != pubkey_hash(pub33):
        raise TxError("this key does not own the sender address")
    msg = tx.signing_bytes()
    r, s = normalize_low_s(*decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256()))))
    return {
        "tx": tx.to_obj(),
        "txid": tx.txid(),
        "public_key": pub33.hex(),
        "signature": der_encode(r, s).hex(),
        "scheme": "ECDSA-secp256k1-SHA256, strict DER, low-S",
    }


@dataclass
class VerifyResult:
    ok: bool
    reason: str
    tx: Transaction | None = None


def verify_signed(signed_obj, expected_network: str, nonce_store=None,
                  record: bool = True) -> VerifyResult:
    """Full independent verification. Never raises for bad input; returns a reason."""
    try:
        if not isinstance(signed_obj, dict):
            raise TxError("signed transaction must be a JSON object")
        for k in ("tx", "public_key", "signature"):
            if k not in signed_obj:
                raise TxError(f"missing field {k!r}")
        extra = set(signed_obj) - {"tx", "txid", "public_key", "signature", "scheme"}
        if extra:
            raise TxError(f"unexpected fields {sorted(extra)}")
        tx = Transaction.from_obj(signed_obj["tx"])
        if tx.network_id != expected_network:
            return VerifyResult(False, f"wrong network: tx is for {tx.network_id!r}, "
                                       f"verifier is on {expected_network!r}", tx)
        if "txid" in signed_obj and signed_obj["txid"] != tx.txid():
            return VerifyResult(False, "txid does not match transaction contents", tx)
        try:
            pub33 = bytes.fromhex(signed_obj["public_key"])
            sig = bytes.fromhex(signed_obj["signature"])
        except (ValueError, TypeError):
            raise TxError("public_key and signature must be hex strings") from None
        pub = load_public_key(pub33)
        if decode_address(tx.sender, tx.network_id)[1:] != pubkey_hash(pub33):
            return VerifyResult(False, "wrong signer: public key does not match sender address", tx)
        try:
            r, s = der_decode_strict(sig)
        except SignatureEncodingError as e:
            return VerifyResult(False, f"non-canonical signature encoding: {e}", tx)
        try:
            pub.verify(der_encode(r, s), tx.signing_bytes(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return VerifyResult(False, "bad signature: signed bytes were changed or wrong key", tx)
        if nonce_store is not None:
            ok, why = nonce_store.check(tx.sender, tx.nonce)
            if not ok:
                return VerifyResult(False, why, tx)
            if record:
                nonce_store.record(tx.sender, tx.nonce)
        return VerifyResult(True, "valid", tx)
    except (TxError, AddressError) as e:
        return VerifyResult(False, str(e))


class NonceStore:
    """Replay protection: per-sender highest accepted nonce; a new tx must use a larger one."""

    def __init__(self, path: str | None = None):
        self.path = path
        self.seen: dict[str, int] = {}
        if path:
            try:
                with open(path) as f:
                    self.seen = json.load(f)
            except FileNotFoundError:
                pass

    def check(self, sender: str, nonce: int) -> tuple[bool, str]:
        last = self.seen.get(sender)
        if last is not None and nonce <= last:
            return False, f"replayed nonce: {nonce} <= last accepted nonce {last} for sender"
        return True, "ok"

    def record(self, sender: str, nonce: int) -> None:
        self.seen[sender] = nonce
        if self.path:
            with open(self.path, "w") as f:
                json.dump(self.seen, f, indent=2, sort_keys=True)
