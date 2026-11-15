import copy
import json
import os
import stat
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from toywallet.encoding import (HALF_N, SECP256K1_N, AddressError, SignatureEncodingError,
                                b58check_encode, b58decode, b58encode, decode_address,
                                der_decode_strict, der_encode, make_address, pubkey_hash)
from toywallet.keys import KeyFileError, generate_private_key, load_dev_keyfile, write_dev_keyfile
from toywallet.tx import (DOMAIN_TAG, NonceStore, Transaction, TxError, memo_hash,
                          public_key_bytes, sign_transaction, verify_signed)

ROOT = Path(__file__).resolve().parents[1]
NET = "course-testnet"


# ---------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def alice():
    return generate_private_key()


@pytest.fixture(scope="module")
def bob():
    return generate_private_key()


def addr(priv, net=NET):
    return make_address(public_key_bytes(priv.public_key()), net)


@pytest.fixture
def tx_obj(alice, bob):
    return {"version": 1, "network_id": NET, "sender": addr(alice), "recipient": addr(bob),
            "amount_units": 1_250_000, "nonce": 7, "memo_hash": memo_hash("rent")}


@pytest.fixture
def signed(alice, tx_obj):
    return sign_transaction(Transaction.from_obj(tx_obj), alice)


def reject(signed_obj, contains, **kw):
    r = verify_signed(signed_obj, kw.pop("network", NET), **kw)
    assert not r.ok, "expected rejection"
    assert contains in r.reason, r.reason
    return r


# ---------------------------------------------------------------- keys
def test_keygen_uses_valid_scalar_and_distinct_keys():
    ks = {generate_private_key().private_numbers().private_value for _ in range(20)}
    assert len(ks) == 20 and all(1 <= k < SECP256K1_N for k in ks)


def test_keyfile_permissions_warning_and_no_overwrite(tmp_path):
    p = tmp_path / "k.dev-key.json"
    public = write_dev_keyfile(str(p), generate_private_key(), NET)
    assert "private_key" not in public                       # only public data returned
    data = json.loads(p.read_text())
    assert "TEST-ONLY" in data["WARNING"]
    if os.name == "posix":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        write_dev_keyfile(str(p), generate_private_key(), NET)
    priv, _ = load_dev_keyfile(str(p))
    assert public_key_bytes(priv.public_key()).hex() == data["public_key"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_keyfile_refused_when_world_readable(tmp_path):
    p = tmp_path / "k.json"
    write_dev_keyfile(str(p), generate_private_key(), NET)
    os.chmod(p, 0o644)
    with pytest.raises(KeyFileError, match="too open"):
        load_dev_keyfile(str(p))


def test_cli_keygen_prints_only_public(tmp_path):
    p = tmp_path / "a.json"
    r = subprocess.run([sys.executable, "-m", "toywallet", "keygen", "--keyfile", str(p)],
                       capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=str(ROOT / "src")))
    assert r.returncode == 0
    priv_hex = json.loads(p.read_text())["private_key"]
    assert priv_hex not in r.stdout and priv_hex not in r.stderr
    assert json.loads(r.stdout)["public_key"]


# ---------------------------------------------------------------- addresses
def test_base58_vectors():
    assert b58encode(b"hello world") == "StV1DL6CwTryKyV"
    assert b58encode(b"\x00\x00\x01") == "112"
    assert b58decode("112") == b"\x00\x00\x01"
    # Bitcoin genesis coinbase address: version 0x00 + hash160
    assert b58check_encode(bytes.fromhex("0062e907b15cbf27d5425399ebf6f0fb50ebb88f18")) == \
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_address_format(alice):
    a = addr(alice)
    assert a[0] in "mn"                                     # testnet version byte 0x6f
    payload = decode_address(a, NET)
    assert payload == b"\x6f" + pubkey_hash(public_key_bytes(alice.public_key()))
    assert addr(alice, "course-mainnet")[0] == "1"


@pytest.mark.parametrize("mutate,msg", [
    (lambda a: a[:-1] + ("2" if a[-1] != "2" else "3"), "checksum"),   # invalid checksum
    (lambda a: a[:5] + "0" + a[6:], "invalid Base58 character"),       # '0' not in alphabet
    (lambda a: a[:5] + "l" + a[6:], "invalid Base58 character"),
    (lambda a: a[:10], None),                                          # truncated
    (lambda a: "", "empty"),
])
def test_malformed_addresses_rejected(alice, mutate, msg):
    with pytest.raises(AddressError, match=msg):
        decode_address(mutate(addr(alice)), NET)


def test_address_wrong_length_and_wrong_network(alice):
    with pytest.raises(AddressError, match="payload must be 21"):
        decode_address(b58check_encode(b"\x6f" + b"\x11" * 19), NET)
    with pytest.raises(AddressError, match="not valid on course-testnet"):
        decode_address(addr(alice, "course-mainnet"), NET)


# ---------------------------------------------------------------- canonical bytes
def test_byte_layout_is_exact(tx_obj):
    tx = Transaction.from_obj(tx_obj)
    b = tx.signing_bytes()
    net = NET.encode()
    expected = (DOMAIN_TAG + bytes([1, len(net)]) + net + decode_address(tx.sender, NET)
                + decode_address(tx.recipient, NET) + struct.pack(">QQ", 1_250_000, 7)
                + bytes.fromhex(tx.memo_hash))
    assert b == expected
    assert len(b) == 16 + 2 + len(net) + 21 + 21 + 8 + 8 + 32


def test_whitespace_and_key_order_give_same_signed_bytes(alice, tx_obj):
    a = json.dumps(tx_obj)
    b = json.dumps(dict(reversed(list(tx_obj.items()))), indent=7, separators=(" ,", " :   "))
    ta, tb = Transaction.from_json(a), Transaction.from_json(b)
    assert a != b and ta.signing_bytes() == tb.signing_bytes()
    s = sign_transaction(ta, alice)
    s2 = dict(s, tx=json.loads(b))
    assert verify_signed(s2, NET).ok


@pytest.mark.parametrize("field,value", [
    ("amount_units", 0), ("amount_units", -5), ("amount_units", 2**64), ("amount_units", 1.5),
    ("amount_units", "10"), ("amount_units", True), ("nonce", -1), ("version", 2),
    ("network_id", "Course Testnet"), ("memo_hash", "AB" * 32), ("memo_hash", "ab" * 31),
])
def test_bad_field_values_rejected(tx_obj, field, value):
    with pytest.raises(TxError):
        Transaction.from_obj(dict(tx_obj, **{field: value}))


def test_extra_missing_duplicate_and_float_json(tx_obj):
    with pytest.raises(TxError, match="extra"):
        Transaction.from_obj(dict(tx_obj, fee=1))
    o = dict(tx_obj); o.pop("nonce")
    with pytest.raises(TxError, match="missing"):
        Transaction.from_obj(o)
    with pytest.raises(TxError, match="duplicate"):
        Transaction.from_json(json.dumps(tx_obj)[:-1] + ', "nonce": 8}')
    with pytest.raises(TxError, match="float"):
        Transaction.from_json(json.dumps(tx_obj).replace("1250000", "1250000.0"))


# ---------------------------------------------------------------- sign / verify
def test_valid_signature_low_s_strict_der(signed):
    assert verify_signed(signed, NET).ok
    r, s = der_decode_strict(bytes.fromhex(signed["signature"]))
    assert s <= HALF_N


def test_sign_refuses_key_that_does_not_own_sender(bob, tx_obj):
    with pytest.raises(TxError, match="does not own"):
        sign_transaction(Transaction.from_obj(tx_obj), bob)


@pytest.mark.parametrize("field,value", [
    ("amount_units", 9_999_999), ("nonce", 8), ("memo_hash", "00" * 32),
])
def test_changing_any_signed_field_fails(signed, field, value):
    t = copy.deepcopy(signed)
    t["tx"][field] = value
    t.pop("txid")
    reject(t, "bad signature")


def test_changed_recipient_fails(signed, alice):
    t = copy.deepcopy(signed)
    t["tx"]["recipient"] = addr(generate_private_key())
    t.pop("txid")
    reject(t, "bad signature")


def test_changed_amount_detected_by_txid_too(signed):
    t = copy.deepcopy(signed)
    t["tx"]["amount_units"] += 1
    reject(t, "txid does not match")


def test_wrong_network(signed, alice, bob):
    reject(signed, "wrong network", network="course-mainnet")
    # re-labelling the tx's own network field breaks the addresses' version bytes
    t = copy.deepcopy(signed)
    t["tx"]["network_id"] = "course-mainnet"
    reject(t, "not valid on course-mainnet", network="course-mainnet")


def test_wrong_signer(signed, alice, bob, tx_obj):
    # 1) Bob's public key attached to Alice's transaction
    t = copy.deepcopy(signed)
    t["public_key"] = public_key_bytes(bob.public_key()).hex()
    reject(t, "wrong signer")
    # 2) signature produced by Bob's key over Alice's tx, with Alice's pubkey
    msg = Transaction.from_obj(tx_obj).signing_bytes()
    r, s = decode_dss_signature(bob.sign(msg, ec.ECDSA(hashes.SHA256())))
    s = min(s, SECP256K1_N - s)
    t = copy.deepcopy(signed)
    t["signature"] = der_encode(r, s).hex()
    reject(t, "bad signature")


def test_replayed_nonce(signed, alice, tx_obj, tmp_path):
    store = NonceStore(str(tmp_path / "nonces.json"))
    assert verify_signed(signed, NET, nonce_store=store).ok
    reject(signed, "replayed nonce", nonce_store=store)                    # exact replay
    store2 = NonceStore(str(tmp_path / "nonces.json"))                     # persisted
    reject(signed, "replayed nonce", nonce_store=store2)
    older = sign_transaction(Transaction.from_obj(dict(tx_obj, nonce=3)), alice)
    reject(older, "replayed nonce", nonce_store=store2)                    # lower nonce
    newer = sign_transaction(Transaction.from_obj(dict(tx_obj, nonce=8)), alice)
    assert verify_signed(newer, NET, nonce_store=store2).ok


def test_malformed_and_bad_checksum_address_in_signed_tx(signed):
    t = copy.deepcopy(signed)
    a = t["tx"]["recipient"]
    t["tx"]["recipient"] = a[:-1] + ("2" if a[-1] != "2" else "3")
    reject(t, "invalid address checksum")
    t["tx"]["recipient"] = "not-an-address"
    reject(t, "invalid Base58 character")


def _sig_parts(signed):
    return der_decode_strict(bytes.fromhex(signed["signature"]))


def test_non_canonical_signature_encodings(signed):
    r, s = _sig_parts(signed)
    good = der_encode(r, s)

    def with_sig(b):
        t = copy.deepcopy(signed)
        t["signature"] = b.hex()
        return t

    # high-S twin: mathematically valid ECDSA, but malleable -> rejected
    reject(with_sig(der_encode(r, SECP256K1_N - s)), "high-S")
    # extra leading zero in r (non-minimal INTEGER)
    rb = r.to_bytes((r.bit_length() + 7) // 8, "big")
    if rb[0] & 0x80:
        rb = b"\x00" + rb
    sb = good[4 + good[3] + 2:]
    padded = b"\x02" + bytes([len(rb) + 1]) + b"\x00" + rb + b"\x02" + bytes([len(sb)]) + sb
    reject(with_sig(b"\x30" + bytes([len(padded)]) + padded), "non-canonical")
    # trailing garbage byte
    reject(with_sig(good + b"\x00"), "non-canonical")
    # BER long-form length 0x81 xx
    reject(with_sig(b"\x30\x81" + bytes([len(good) - 2]) + good[2:]), "non-canonical")
    # wrong outer tag
    reject(with_sig(b"\x31" + good[1:]), "non-canonical")
    # raw 64-byte r||s instead of DER
    reject(with_sig(r.to_bytes(32, "big") + s.to_bytes(32, "big")), "non-canonical")
    # r = 0
    reject(with_sig(der_encode(0, s)), "non-canonical")


def test_der_decoder_unit():
    assert der_decode_strict(der_encode(1, 1)) == (1, 1)
    with pytest.raises(SignatureEncodingError):
        der_decode_strict(der_encode(1, SECP256K1_N - 1))
    with pytest.raises(SignatureEncodingError):
        der_decode_strict(bytes.fromhex("3006020180020101"))      # negative r


def test_invalid_public_key_rejected(signed):
    t = copy.deepcopy(signed)
    t["public_key"] = "02" + "ff" * 32                             # x not on curve
    assert not verify_signed(t, NET).ok


# ---------------------------------------------------------------- independent verification
def test_independent_verifier_script(signed, tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps(signed))
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "independent_verify.py"), str(p)],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "VALID" in r.stdout
    assert signed["txid"] in r.stdout


def test_committed_example_verifies():
    """The example in examples/ must verify with only public data."""
    obj = json.loads((ROOT / "examples" / "signed_tx.json").read_text())
    assert verify_signed(obj, NET).ok
