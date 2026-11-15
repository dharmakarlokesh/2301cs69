"""chain CLI: demo (fork simulation + report), mine, bench."""

from __future__ import annotations

import argparse
import sys
import time

from .block import BlockHeader, target_from_bits, work_for_target
from .miner import mine_header
from .sim import pow_benchmark, run_all


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="chain", description="Toy PoW chain with most-work selection")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="fork simulation, reorg, invalid blocks, PoW measurement")
    d.add_argument("-o", "--output", default="reports/report.md")
    m = sub.add_parser("mine", help="mine one header at a toy target and show the hex dump")
    m.add_argument("--bits", type=int, default=16, help="required leading zero bits (difficulty)")
    b = sub.add_parser("bench", help="hashes/s and expected vs observed attempts")
    b.add_argument("--bits", type=int, nargs=3, default=[8, 12, 16])
    b.add_argument("--samples", type=int, nargs=3, default=[500, 200, 60])
    a = p.parse_args(argv)
    if a.cmd == "demo":
        print(run_all(a.output))
        print(f"report written to {a.output}", file=sys.stderr)
    elif a.cmd == "mine":
        tgt = target_from_bits(a.bits)
        hdr = BlockHeader(1, b"\x00" * 32, b"\x00" * 32, int(time.time()), tgt, 0)
        t0 = time.perf_counter()
        solved, attempts = mine_header(hdr)
        dt = time.perf_counter() - t0
        print(solved.hexdump())
        print(f"\nattempts: {attempts:,} (expected {work_for_target(tgt):,}), "
              f"{dt:.3f}s, {attempts / dt:,.0f} H/s")
    else:
        print("\n".join(pow_benchmark(a.bits, a.samples)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
