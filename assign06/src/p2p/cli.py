"""p2p CLI: run the 5-node experiment, or run a single node."""

from __future__ import annotations

import argparse
import asyncio
import sys

from .sim import run_experiment


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="p2p", description="Peer-to-peer mempool and block relay network")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("experiment", help="5 nodes: discovery, relay, partition, heal, attacks")
    e.add_argument("--out-dir", default="reports")
    a = p.parse_args(argv)
    if a.cmd == "experiment":
        print(asyncio.run(run_experiment(a.out_dir)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
