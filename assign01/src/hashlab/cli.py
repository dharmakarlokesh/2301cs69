"""hashlab command-line interface.

    hashlab text "Alice pays Bob 10"
    hashlab hex 416c696365
    hashlab file big.bin            (streamed; use '-' for stdin)
    hashlab avalanche --text "Alice pays Bob 10" --bit 7
    hashlab canonical-json tx.json  (or --json '{"b":1,"a":2}', or '-' for stdin)
    hashlab demo
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import (
    CANONICAL_RULES,
    Digest,
    HashlabError,
    avalanche,
    canonical_json,
    demo_cases,
    hash_bytes,
    hash_file,
    hash_stream,
    parse_hex,
    parse_json_strict,
    text_to_bytes,
)


def _print_digest(d: Digest, show_b64: bool = True) -> None:
    print(f"bytes: {d.length}")
    print(f"sha256: {d.hex}")
    if show_b64:
        print(f"sha256_base64: {d.b64}")


def cmd_text(a: argparse.Namespace) -> int:
    data = text_to_bytes(a.text, a.normalize)
    if a.show_bytes:
        print(f"utf8_hex: {data.hex()}")
    _print_digest(hash_bytes(data))
    return 0


def cmd_hex(a: argparse.Namespace) -> int:
    _print_digest(hash_bytes(parse_hex(a.hex)))
    return 0


def cmd_file(a: argparse.Namespace) -> int:
    d = hash_stream(sys.stdin.buffer) if a.path == "-" else hash_file(a.path)
    _print_digest(d)
    return 0


def _avalanche_input(a: argparse.Namespace) -> bytes:
    if a.text is not None:
        return text_to_bytes(a.text)
    if a.hex is not None:
        return parse_hex(a.hex)
    with open(a.file, "rb") as f:
        return f.read()


def cmd_avalanche(a: argparse.Namespace) -> int:
    r = avalanche(_avalanche_input(a), a.bit)
    byte_i, bit_in_byte = divmod(a.bit, 8)
    print(f"bytes: {len(r.original)}")
    print(f"flipped_bit: {a.bit} (byte {byte_i}, mask 0x{0x80 >> bit_in_byte:02x})")
    print(f"original_sha256: {r.original_digest.hex}")
    print(f"flipped_sha256:  {r.flipped_digest.hex}")
    print(f"changed_bits_in_digest: {r.changed_bits}")
    print(f"changed_fraction: {r.changed_bits / 256:.3f}  (ideal ~0.5)")
    return 0


def cmd_canonical_json(a: argparse.Namespace) -> int:
    if a.rules:
        print(CANONICAL_RULES, end="")
        return 0
    if a.json is not None:
        text = a.json
    elif a.path in (None, "-"):
        text = sys.stdin.buffer.read().decode("utf-8")
    else:
        with open(a.path, "rb") as f:
            text = f.read().decode("utf-8")
    canon = canonical_json(parse_json_strict(text))
    data = canon.encode("utf-8")
    print(f"canonical: {canon}")
    _print_digest(hash_bytes(data))
    return 0


def cmd_demo(_: argparse.Namespace) -> int:
    for i, c in enumerate(demo_cases(), 1):
        da, db = hash_bytes(c.bytes_a), hash_bytes(c.bytes_b)
        print(f"[{i}] {c.title}")
        print(f"    A = {c.label_a}")
        print(f"        bytes={da.length} hex={c.bytes_a.hex()}")
        print(f"        sha256={da.hex}")
        print(f"    B = {c.label_b}")
        print(f"        bytes={db.length} hex={c.bytes_b.hex()}")
        print(f"        sha256={db.hex}")
        print(f"    same digest? {da.raw == db.raw}  ->  {c.lesson}")
        print()
    a = canonical_json(parse_json_strict('{"from":"Alice","to":"Bob"}'))
    b = canonical_json(parse_json_strict('{ "to": "Bob",  "from": "Alice" }'))
    print("[*] After canonical-json both key orders become:", a)
    print("    identical canonical bytes?", a == b)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hashlab", description="SHA-256 byte diagnostics")
    p.add_argument("--version", action="version", version=f"hashlab {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("text", help="hash UTF-8 encoded text")
    t.add_argument("text")
    t.add_argument("--normalize", choices=["NFC", "NFD", "NFKC", "NFKD"],
                   help="apply a Unicode normal form before encoding (default: none)")
    t.add_argument("--show-bytes", action="store_true", help="also print the UTF-8 bytes")
    t.set_defaults(fn=cmd_text)

    h = sub.add_parser("hex", help="hash a hexadecimal byte string")
    h.add_argument("hex")
    h.set_defaults(fn=cmd_hex)

    f = sub.add_parser("file", help="hash a file as a stream ('-' = stdin)")
    f.add_argument("path")
    f.set_defaults(fn=cmd_file)

    av = sub.add_parser("avalanche", help="flip one input bit, compare digests")
    src = av.add_mutually_exclusive_group(required=True)
    src.add_argument("--text")
    src.add_argument("--hex")
    src.add_argument("--file")
    av.add_argument("--bit", type=int, required=True,
                    help="bit index, MSB-first: 0 = top bit of byte 0")
    av.set_defaults(fn=cmd_avalanche)

    cj = sub.add_parser("canonical-json", help="canonicalize a JSON object and hash it")
    cj.add_argument("path", nargs="?", help="JSON file ('-' or omitted = stdin)")
    cj.add_argument("--json", help="JSON text given inline")
    cj.add_argument("--rules", action="store_true", help="print the canonicalization rules")
    cj.set_defaults(fn=cmd_canonical_json)

    d = sub.add_parser("demo", help="show visually similar inputs with different bytes")
    d.set_defaults(fn=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except HashlabError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (OSError, UnicodeDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
