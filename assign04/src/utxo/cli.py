"""utxo CLI: demo (trace + snapshots), show / check a snapshot."""

from __future__ import annotations

import argparse
import sys

from .demo import run
from .ledger import Ledger


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="utxo", description="UTXO ledger and transaction validator")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="run the scripted scenario; writes reports/trace.md and snapshots/")
    d.add_argument("--out-dir", default=".")
    s = sub.add_parser("show", help="load a snapshot (verifies its state hash) and list UTXOs")
    s.add_argument("snapshot")
    a = p.parse_args(argv)
    if a.cmd == "demo":
        print(run(a.out_dir))
        return 0
    try:
        led = Ledger.load(a.snapshot)
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"state_hash: {led.state_hash()} (verified)")
    print(f"utxos: {len(led.utxos)}  total_value: {led.total_value()}")
    for u in led.utxo_listing():
        print(f"  {u['outpoint'][:16]}…:{u['outpoint'].split(':')[1]}  {u['value']:>8}  pkh={u['pubkey_hash']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
