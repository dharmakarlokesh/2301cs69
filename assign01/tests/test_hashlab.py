import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tracemalloc
from pathlib import Path

import pytest

from hashlab import cli
from hashlab.core import (
    HashlabError,
    avalanche,
    canonical_json,
    canonical_json_bytes,
    demo_cases,
    flip_bit,
    hamming_distance,
    hash_bytes,
    hash_file,
    parse_hex,
    parse_json_strict,
    text_to_bytes,
)

SRC = str(Path(__file__).resolve().parents[1] / "src")


def run_cli(*args, stdin=None):
    env = dict(os.environ, PYTHONPATH=SRC)
    return subprocess.run([sys.executable, "-m", "hashlab", *args], input=stdin,
                          capture_output=True, env=env)


def field(out: bytes, name: str) -> str:
    for line in out.decode().splitlines():
        if line.startswith(name + ":"):
            return line.split(":", 1)[1].strip()
    raise KeyError(name)


# ---- known-answer vectors (FIPS 180-2 / NIST) ---------------------------------
@pytest.mark.parametrize("msg,expected", [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
])
def test_known_vectors(msg, expected):
    d = hash_bytes(msg)
    assert d.hex == expected
    assert d.b64 == base64.b64encode(bytes.fromhex(expected)).decode()
    assert d.length == len(msg)


def test_text_mode_bytes_and_digest():
    r = run_cli("text", "Alice pays Bob 10")
    assert r.returncode == 0
    assert field(r.stdout, "bytes") == "17"
    assert field(r.stdout, "sha256") == hashlib.sha256(b"Alice pays Bob 10").hexdigest()
    assert len(field(r.stdout, "sha256")) == 64


def test_text_utf8_multibyte_length():
    assert hash_bytes(text_to_bytes("₹")).length == 3   # U+20B9 -> 3 UTF-8 bytes


def test_trailing_newline_is_distinguished():
    a, b = hash_bytes(b"Alice pays Bob 10"), hash_bytes(b"Alice pays Bob 10\n")
    assert (a.length, b.length) == (17, 18)
    assert a.raw != b.raw


# ---- hex parsing ---------------------------------------------------------------
@pytest.mark.parametrize("s,expected", [
    ("", b""), ("00", b"\x00"), ("0x416c", b"Al"), ("DEADbeef", b"\xde\xad\xbe\xef"),
])
def test_hex_ok(s, expected):
    assert parse_hex(s) == expected


@pytest.mark.parametrize("bad", ["0", "abc", "zz", "12 34", "0x0g", "--", "12\n", "0x"*1 + "1"])
def test_hex_malformed_rejected(bad):
    with pytest.raises(HashlabError):
        parse_hex(bad)


def test_hex_cli_rejects_with_nonzero_exit():
    r = run_cli("hex", "abc")
    assert r.returncode != 0 and b"malformed hex" in r.stderr


def test_hex_and_text_agree():
    assert hash_bytes(parse_hex("416c696365")).raw == hash_bytes(b"Alice").raw


# ---- files: match an independent SHA-256 utility, stream large input -----------
def _independent_sha256(path: Path) -> str:
    tool = shutil.which("sha256sum") or shutil.which("shasum")
    if tool is None:
        pytest.skip("no sha256sum/shasum utility on this machine")
    args = [tool] if tool.endswith("sha256sum") else [tool, "-a", "256"]
    return subprocess.run(args + [str(path)], capture_output=True, check=True,
                          text=True).stdout.split()[0]


@pytest.mark.parametrize("content", [b"", b"x", b"\x00\xff" * 50_000, os.urandom(200_001)],
                         ids=["empty", "one-byte", "100KB-pattern", "200KB-random"])
def test_file_matches_independent_utility(tmp_path, content):
    p = tmp_path / "f.bin"
    p.write_bytes(content)
    r = run_cli("file", str(p))
    assert r.returncode == 0
    assert field(r.stdout, "sha256") == _independent_sha256(p)
    assert field(r.stdout, "bytes") == str(len(content))


def test_file_from_stdin():
    r = run_cli("file", "-", stdin=b"hello\n")
    assert field(r.stdout, "sha256") == hashlib.sha256(b"hello\n").hexdigest()


def test_large_file_is_streamed(tmp_path):
    """Hash a 100 MB file; Python-heap peak must stay tiny (O(chunk), not O(file))."""
    p = tmp_path / "big.bin"
    block = os.urandom(1024 * 1024)
    ref = hashlib.sha256()
    with open(p, "wb") as f:
        for _ in range(100):
            f.write(block)
            ref.update(block)
    tracemalloc.start()
    d = hash_file(str(p))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert d.length == 100 * 1024 * 1024
    assert d.hex == ref.hexdigest()
    assert peak < 2 * 1024 * 1024, f"peak {peak} bytes - file was not streamed"


# ---- avalanche -----------------------------------------------------------------
def test_flip_bit_msb_first():
    assert flip_bit(b"\x00", 0) == b"\x80"
    assert flip_bit(b"\x00", 7) == b"\x01"
    assert flip_bit(b"\x00\x00", 8) == b"\x00\x80"
    with pytest.raises(HashlabError):
        flip_bit(b"\x00", 8)
    with pytest.raises(HashlabError):
        flip_bit(b"\x00", -1)


def test_hamming():
    assert hamming_distance(b"\x00", b"\xff") == 8
    assert hamming_distance(b"\x0f\x00", b"\x00\x00") == 4


def test_avalanche_example():
    r = run_cli("avalanche", "--text", "Alice pays Bob 10", "--bit", "7")
    assert r.returncode == 0
    n = int(field(r.stdout, "changed_bits_in_digest"))
    assert 0 <= n <= 256
    data = b"Alice pays Bob 10"
    flipped = flip_bit(data, 7)
    assert n == hamming_distance(hashlib.sha256(data).digest(), hashlib.sha256(flipped).digest())


def test_avalanche_statistics():
    data = b"Alice pays Bob 10"
    dists = [avalanche(data, i).changed_bits for i in range(len(data) * 8)]
    mean = sum(dists) / len(dists)
    assert 118 < mean < 138          # ~128 expected for an ideal hash
    assert min(dists) > 80


# ---- canonical JSON ------------------------------------------------------------
def test_canonical_key_order_and_whitespace():
    a = canonical_json_bytes('{"to":"Bob","from":"Alice","amount":10}')
    b = canonical_json_bytes('{\n  "amount": 10,\n  "from": "Alice",\n  "to": "Bob"\n}')
    assert a == b == b'{"amount":10,"from":"Alice","to":"Bob"}'


def test_canonical_nested_and_escapes():
    v = parse_json_strict('{"b":[1,{"z":null,"a":true}],"a":"\\u00e9\\n\\u0001"}')
    assert canonical_json(v) == '{"a":"é\\n\\u0001","b":[1,{"a":true,"z":null}]}'


def test_canonical_utf16_sort_order():
    # U+E000 (BMP private use) sorts BEFORE U+1F600 under UTF-16, after it under code points
    v = {"\U0001F600": 1, "": 2}
    assert canonical_json(v) == '{"\U0001F600":1,"":2}'


def test_canonical_int_vs_string_differ():
    assert hash_bytes(canonical_json_bytes('{"amount":10}')).raw != \
        hash_bytes(canonical_json_bytes('{"amount":"10"}')).raw


@pytest.mark.parametrize("bad", [
    '[1,2]', '"x"', '{"a":1.5}', '{"a":1e3}', '{"a":NaN}', '{"a":1,"a":2}',
    '{"a":9007199254740992}', '{"a":', '{"a":{"b":1,"b":2}}',
])
def test_canonical_rejects(bad):
    with pytest.raises(HashlabError):
        canonical_json_bytes(bad)


def test_canonical_cli(tmp_path):
    p = tmp_path / "tx.json"
    p.write_text('{ "to": "Bob", "from": "Alice" }')
    r = run_cli("canonical-json", str(p))
    assert field(r.stdout, "canonical") == '{"from":"Alice","to":"Bob"}'
    assert field(r.stdout, "sha256") == hashlib.sha256(b'{"from":"Alice","to":"Bob"}').hexdigest()


# ---- demonstrations ------------------------------------------------------------
def test_demo_cases_all_differ():
    for c in demo_cases():
        assert c.bytes_a != c.bytes_b, c.title
        assert hash_bytes(c.bytes_a).raw != hash_bytes(c.bytes_b).raw, c.title


def test_normalization_option():
    nfd = "café"
    assert text_to_bytes(nfd) != text_to_bytes("café")
    assert text_to_bytes(nfd, "NFC") == text_to_bytes("café")


def test_demo_cli_runs(capsys):
    assert cli.main(["demo"]) == 0
    assert "identical canonical bytes? True" in capsys.readouterr().out
