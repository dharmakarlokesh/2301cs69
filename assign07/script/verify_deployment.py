#!/usr/bin/env python3
"""Verify the Anvil deployment produced by script/Deploy.s.sol (run via script/demo.sh).

Checks, using only the node's JSON-RPC and the compiled artifact:
  * every transaction receipt has status 1; gas used per transaction is reported
  * emitted events (decoded from the ABI) match the expected state-machine sequence
  * final balances: escrows hold 0; each EOA's change equals payouts - deposits - gas cost
  * deployed address == CREATE address of (deployer, nonce)
  * deployed runtime bytecode == compiled runtime bytecode (immutable slots masked)
Writes reports/deployment.md and reports/receipts.json.
"""

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
ETH = 10**18
PRICE = 1 * ETH


def rpc(method, *params):
    req = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                                                  "params": list(params)}).encode(),
                                 {"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # localhost: no proxy
    with opener.open(req, timeout=10) as r:
        out = json.load(r)
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def cast(*args):
    return subprocess.run(["cast", *args], capture_output=True, text=True, check=True).stdout.strip()


def main() -> int:
    run = json.loads((ROOT / "broadcast/Deploy.s.sol/31337/run-latest.json").read_text())
    art = json.loads((ROOT / "out/Escrow.sol/Escrow.json").read_text())
    abi = art["abi"]

    topics = {}
    for ev in (x for x in abi if x["type"] == "event"):
        sig = f"{ev['name']}({','.join(i['type'] for i in ev['inputs'])})"
        topics[cast("keccak", sig)] = ev

    def decode(log):
        ev = topics.get(log["topics"][0])
        if not ev:
            return "unknown"
        idx = [i for i in ev["inputs"] if i["indexed"]]
        non = [i for i in ev["inputs"] if not i["indexed"]]
        vals = {}
        for i, t in zip(idx, log["topics"][1:]):
            vals[i["name"]] = _fmt(i["type"], int(t, 16))
        data = bytes.fromhex(log["data"][2:])
        for k, i in enumerate(non):
            vals[i["name"]] = _fmt(i["type"], int.from_bytes(data[32 * k:32 * k + 32], "big"))
        return f"{ev['name']}(" + ", ".join(f"{k}={v}" for k, v in vals.items()) + ")"

    rows, problems = [], []
    gas_cost: dict[str, int] = {}
    deployments = []
    events_by_contract: dict[str, list[str]] = {}
    for tx, rc in zip(run["transactions"], run["receipts"]):
        sender = tx["transaction"]["from"].lower()
        status = int(rc["status"], 16)
        gas = int(rc["gasUsed"], 16)
        price = int(rc["effectiveGasPrice"], 16)
        gas_cost[sender] = gas_cost.get(sender, 0) + gas * price
        fn = tx.get("function") or ("constructor" if tx["transactionType"] == "CREATE" else "?")
        to = (rc.get("contractAddress") or tx["transaction"].get("to") or "").lower()
        evs = [decode(l) for l in rc["logs"]]
        events_by_contract.setdefault(to, []).append(f"{fn.split('(')[0]}: " + "; ".join(evs))
        if status != 1:
            problems.append(f"tx {rc['transactionHash']} failed")
        if tx["transactionType"] == "CREATE":
            deployments.append((rc["contractAddress"].lower(), sender, int(tx["transaction"]["nonce"], 16)))
        rows.append(f"| `{rc['transactionHash'][:12]}…` | {fn.split('(')[0]} | `{to[:10]}…` | "
                    f"{'✔' if status == 1 else '✘'} | {gas:,} | {'<br>'.join(evs) or '—'} |")

    # expected event sequences
    expected = {
        0: ["constructor: ", "fund: StateChanged(from=0, to=1); Funded", "release: StateChanged(from=1, to=2); Released",
            "withdraw: Withdrawn"],
        1: ["constructor: ", "fund: StateChanged(from=0, to=1); Funded", "dispute: StateChanged(from=1, to=3); Disputed",
            "resolveToBuyer: StateChanged(from=3, to=4); Resolved", "withdraw: Withdrawn"],
    }
    for k, (addr, _, _) in enumerate(deployments):
        got = events_by_contract[addr]
        for g, want in zip(got, expected[k]):
            if not g.startswith(want):
                problems.append(f"escrow {k}: event mismatch: got {g!r}, want prefix {want!r}")
        if len(got) != len(expected[k]):
            problems.append(f"escrow {k}: {len(got)} txs, expected {len(expected[k])}")

    # addresses and bytecode
    runtime = art["deployedBytecode"]["object"][2:]
    imm = art["deployedBytecode"].get("immutableReferences", {})
    masks = [(r["start"], r["length"]) for refs in imm.values() for r in refs]

    def masked(hexcode):
        b = bytearray(bytes.fromhex(hexcode))
        for s, ln in masks:
            b[s:s + ln] = b"\x00" * ln
        return bytes(b)

    code_rows = []
    for addr, deployer, nonce in deployments:
        computed = cast("compute-address", deployer, "--nonce", str(nonce)).split()[-1].lower()
        onchain = rpc("eth_getCode", addr, "latest")[2:]
        same = masked(onchain) == masked(runtime)
        code_rows.append(f"| `{addr}` | `{deployer[:10]}…` nonce {nonce} | `{computed}` | "
                         f"{'✔' if computed == addr else '✘'} | {len(onchain) // 2:,} B | "
                         f"`{cast('keccak', '0x' + onchain)[:18]}…` | {'✔' if same else '✘'} |")
        if computed != addr:
            problems.append(f"address mismatch for {addr}")
        if not same:
            problems.append(f"runtime bytecode mismatch at {addr}")

    # balances: before = block 0, after = latest
    tx0 = run["transactions"]
    deployer = deployments[0][1]
    buyer = next(t["transaction"]["from"].lower() for t in tx0 if (t.get("function") or "").startswith("fund"))
    seller = next(t["transaction"]["from"].lower() for t in tx0 if (t.get("function") or "").startswith("dispute"))
    arbiter = next(t["transaction"]["from"].lower() for t in tx0 if (t.get("function") or "").startswith("resolve"))
    names = {deployer: "deployer", buyer: "buyer", seller: "seller", arbiter: "arbiter"}
    payouts = {deployer: 0, buyer: -2 * PRICE + PRICE, seller: PRICE, arbiter: 0}
    bal_rows = []
    for addr, name in names.items():
        before = int(rpc("eth_getBalance", addr, "0x0"), 16)
        after = int(rpc("eth_getBalance", addr, "latest"), 16)
        expect = before + payouts[addr] - gas_cost.get(addr, 0)
        ok = after == expect
        if not ok:
            problems.append(f"balance mismatch for {name}")
        bal_rows.append(f"| {name} | `{addr[:10]}…` | {before / ETH:,.6f} | {after / ETH:,.6f} | "
                        f"{payouts[addr] / ETH:+.1f} | {gas_cost.get(addr, 0) / ETH:.6f} | {'✔' if ok else '✘'} |")
    for addr, _, _ in deployments:
        b = int(rpc("eth_getBalance", addr, "latest"), 16)
        st = int(rpc("eth_call", {"to": addr, "data": "0xc19d93fb"}, "latest"), 16)   # state()
        bal_rows.append(f"| escrow (state {st}) | `{addr[:10]}…` | – | {b / ETH:.6f} | – | – | "
                        f"{'✔' if b == 0 else '✘'} |")
        if b != 0:
            problems.append(f"escrow {addr} still holds funds")

    md = ["# Local deployment (Anvil, chain id 31337) — verified", "",
          "Produced by `script/demo.sh`, which starts Anvil, runs `forge script script/Deploy.s.sol --broadcast`, "
          "and then runs `script/verify_deployment.py` against the node.", "",
          "## Transaction receipts", "",
          "| Tx | Call | To / created | Status | Gas used | Events emitted |", "|---|---|---|---|---:|---|",
          *rows, "",
          "## Deployed bytecode and addresses", "",
          "| Contract | Deployer / nonce | CREATE address computed | Match | Runtime size | keccak256(code) "
          "| Equals compiled runtime (immutables masked) |", "|---|---|---|---|---:|---|---|", *code_rows, "",
          "## Final balances (ETH)", "",
          "| Account | Address | Before (block 0) | After | Escrow payouts | Gas paid | before + payouts − gas == after |",
          "|---|---|---:|---:|---:|---:|---|", *bal_rows, "",
          f"**Result:** {'all checks passed ✔' if not problems else 'PROBLEMS: ' + '; '.join(problems)}", ""]
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports/deployment.md").write_text("\n".join(md))
    slim = [{"hash": r["transactionHash"], "from": t["transaction"]["from"], "function": t.get("function"),
             "contractAddress": r.get("contractAddress"), "status": r["status"], "gasUsed": r["gasUsed"],
             "effectiveGasPrice": r["effectiveGasPrice"], "blockNumber": r["blockNumber"],
             "logs": [{"address": l["address"], "topics": l["topics"], "data": l["data"]} for l in r["logs"]]}
            for t, r in zip(run["transactions"], run["receipts"])]
    (ROOT / "reports/receipts.json").write_text(json.dumps(slim, indent=2) + "\n")
    print("\n".join(md))
    return 1 if problems else 0


def _fmt(typ, v):
    if typ == "address":
        return f"0x{v:040x}"[:12] + "…"
    if typ == "bool":
        return str(bool(v)).lower()
    if typ == "uint256" and v >= 10**15:
        return f"{v / ETH:g} ETH"
    return str(v)


if __name__ == "__main__":
    sys.exit(main())
