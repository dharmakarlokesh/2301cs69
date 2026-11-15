"""Core byte-handling and hashing helpers for hashlab.

SHA-256 itself is NOT implemented here: every digest comes from Python's
standard-library ``hashlib`` (OpenSSL-backed), as the assignment requires.
"""

from __future__ import annotations

import base64
import hashlib
import json
import string
import unicodedata
from dataclasses import dataclass
from typing import IO, Any, Iterable

CHUNK_SIZE = 64 * 1024  # 64 KiB per read; memory use is O(CHUNK_SIZE), not O(file)

_HEX_DIGITS = frozenset(string.hexdigits)


class HashlabError(ValueError):
    """Raised for malformed user input (bad hex, bad JSON, bad bit index...)."""


@dataclass(frozen=True)
class Digest:
    length: int        # number of input bytes hashed
    raw: bytes         # 32-byte SHA-256 digest

    @property
    def hex(self) -> str:
        return self.raw.hex()

    @property
    def b64(self) -> str:
        return base64.b64encode(self.raw).decode("ascii")


# --------------------------------------------------------------------------- #
# Input decoding
# --------------------------------------------------------------------------- #
def text_to_bytes(text: str, normalize: str | None = None) -> bytes:
    """Encode text as UTF-8. Optionally apply a Unicode normal form first.

    By default NO normalization is applied: the bytes are exactly the code
    points the user supplied. That is deliberate - see ``demo`` for why.
    """
    if normalize is not None:
        if normalize not in ("NFC", "NFD", "NFKC", "NFKD"):
            raise HashlabError(f"unknown normalization form: {normalize}")
        text = unicodedata.normalize(normalize, text)
    return text.encode("utf-8")


def parse_hex(s: str) -> bytes:
    """Strictly parse a hexadecimal byte string.

    Rules (documented in readme.md):
      * an optional leading ``0x`` / ``0X`` prefix is allowed;
      * ASCII whitespace is NOT allowed anywhere (ambiguity is rejected);
      * only characters 0-9, a-f, A-F;
      * the number of hex digits must be even (whole bytes only).
    The empty string is valid and denotes zero bytes.
    """
    body = s[2:] if s[:2] in ("0x", "0X") else s
    bad = [c for c in body if c not in _HEX_DIGITS]
    if bad:
        raise HashlabError(f"malformed hex: invalid character {bad[0]!r}")
    if len(body) % 2:
        raise HashlabError(
            f"malformed hex: odd number of digits ({len(body)}); "
            "each byte needs exactly two hex digits"
        )
    return bytes.fromhex(body)


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #
def hash_bytes(data: bytes) -> Digest:
    return Digest(len(data), hashlib.sha256(data).digest())


def hash_stream(stream: IO[bytes], chunk_size: int = CHUNK_SIZE) -> Digest:
    """Hash a binary stream incrementally - never holds more than one chunk."""
    h = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
        total += len(chunk)
    return Digest(total, h.digest())


def hash_file(path: str, chunk_size: int = CHUNK_SIZE) -> Digest:
    with open(path, "rb") as f:
        return hash_stream(f, chunk_size)


# --------------------------------------------------------------------------- #
# Avalanche
# --------------------------------------------------------------------------- #
def flip_bit(data: bytes, bit: int) -> bytes:
    """Flip one bit. Bit numbering is MSB-first across the whole message:
    bit 0 is the most-significant bit of byte 0, bit 7 its least-significant
    bit, bit 8 the MSB of byte 1, and so on."""
    nbits = len(data) * 8
    if not 0 <= bit < nbits:
        raise HashlabError(f"bit index {bit} out of range 0..{nbits - 1}")
    out = bytearray(data)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise HashlabError("hamming distance needs equal-length inputs")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


@dataclass(frozen=True)
class AvalancheResult:
    bit: int
    original: bytes
    flipped: bytes
    original_digest: Digest
    flipped_digest: Digest

    @property
    def changed_bits(self) -> int:
        return hamming_distance(self.original_digest.raw, self.flipped_digest.raw)


def avalanche(data: bytes, bit: int) -> AvalancheResult:
    flipped = flip_bit(data, bit)
    return AvalancheResult(bit, data, flipped, hash_bytes(data), hash_bytes(flipped))


# --------------------------------------------------------------------------- #
# Canonical JSON
# --------------------------------------------------------------------------- #
CANONICAL_RULES = """\
Canonical JSON rules used by hashlab (a strict subset of RFC 8785 / JCS):
  1. The top-level value must be a JSON object.
  2. Duplicate keys at any depth are rejected (the input is ambiguous).
  3. Object keys are sorted by their UTF-16 code units (same order as RFC 8785).
  4. No insignificant whitespace: separators are exactly ',' and ':'.
  5. Strings are emitted as UTF-8, escaping only '"', '\\\\' and control
     characters U+0000-U+001F (as \\b \\f \\n \\r \\t or \\u00XX, lowercase hex).
     NO Unicode normalization is applied - different code points stay different.
  6. Numbers must be integers in the range [-(2^53-1), 2^53-1]; floats,
     exponents, NaN and Infinity are rejected (they have no single spelling).
  7. true, false and null are emitted literally.
  8. The resulting text is encoded as UTF-8 and hashed with SHA-256.
"""

_MAX_SAFE_INT = 2**53 - 1


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise HashlabError(f"duplicate key in JSON object: {k!r}")
        out[k] = v
    return out


def _reject_float(s: str):
    raise HashlabError(f"non-integer number {s!r} is not allowed in canonical JSON")


def _reject_constant(s: str):
    raise HashlabError(f"{s} is not valid JSON")


def parse_json_strict(text: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as e:
        raise HashlabError(f"invalid JSON: {e}") from None


_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
            "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be")


def _encode(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        if not -_MAX_SAFE_INT <= value <= _MAX_SAFE_INT:
            raise HashlabError(f"integer {value} outside the safe range ±(2^53-1)")
        return str(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_encode(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(f"{_encode_string(k)}:{_encode(v)}" for k, v in items) + "}"
    raise HashlabError(f"unsupported JSON value type: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    if not isinstance(value, dict):
        raise HashlabError("canonical-json input must be a JSON object at top level")
    return _encode(value)


def canonical_json_bytes(text: str) -> bytes:
    return canonical_json(parse_json_strict(text)).encode("utf-8")


# --------------------------------------------------------------------------- #
# Demonstrations: visually similar, byte-wise different
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DemoCase:
    title: str
    label_a: str
    bytes_a: bytes
    label_b: str
    bytes_b: bytes
    lesson: str


def demo_cases() -> list[DemoCase]:
    nfc = unicodedata.normalize("NFC", "café")   # é = U+00E9
    nfd = unicodedata.normalize("NFD", "café")   # e + U+0301 combining acute
    return [
        DemoCase(
            "Trailing newline",
            '"Alice pays Bob 10"', b"Alice pays Bob 10",
            '"Alice pays Bob 10\\n"  (what `echo` produces)', b"Alice pays Bob 10\n",
            "A single invisible LF byte changes the whole digest.",
        ),
        DemoCase(
            "Line endings (LF vs CRLF)",
            '"line1\\nline2"', b"line1\nline2",
            '"line1\\r\\nline2"  (Windows)', b"line1\r\nline2",
            "Editors and git autocrlf can silently rewrite line endings.",
        ),
        DemoCase(
            "Unicode normalization (NFC vs NFD)",
            '"café" NFC (U+00E9)', nfc.encode("utf-8"),
            '"café" NFD (e + U+0301)', nfd.encode("utf-8"),
            "Both render identically, but are different code points and bytes.",
        ),
        DemoCase(
            "Integer vs string",
            '{"amount":10}', b'{"amount":10}',
            '{"amount":"10"}', b'{"amount":"10"}',
            "Same 'value' to a human; different type, different bytes.",
        ),
        DemoCase(
            "Key order (raw vs canonical)",
            '{"from":"Alice","to":"Bob"}', b'{"from":"Alice","to":"Bob"}',
            '{"to":"Bob","from":"Alice"}', b'{"to":"Bob","from":"Alice"}',
            "Same object, different serialization -> canonicalize before hashing "
            "(canonical-json gives both the same digest).",
        ),
    ]


def iter_chunks(data: bytes, size: int) -> Iterable[bytes]:  # small helper for tests
    for i in range(0, len(data), size):
        yield data[i:i + size]
