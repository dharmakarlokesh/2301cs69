"""Fork simulation with two miners, most-work demo, invalid-block demo, and PoW benchmark."""

from __future__ import annotations

import os
import platform
import statistics
import time

from .block import Block, BlockHeader, merkle_root, target_from_bits, work_for_target
from .chain import ChainManager, ChainParams, make_genesis
from .crypto import Key
from .miner import build_block, mine_header
from .tx import OutPoint, Transaction, TxOut, sign_tx

T0 = 1_700_000_000
ALICE, BOB, CAROL, MINER_A, MINER_B = (Key.from_seed(n) for n in
                                       ("alice", "bob", "carol", "miner-a", "miner-b"))
NAMES = {ALICE.pkh: "Alice", BOB.pkh: "Bob", CAROL.pkh: "Carol",
         MINER_A.pkh: "MinerA", MINER_B.pkh: "MinerB"}


def balances(node: ChainManager) -> str:
    return ", ".join(f"{n}={node.utxo.balance(k)}" for k, n in NAMES.items())


def mermaid_tree(node: ChainManager, labels: dict[bytes, str]) -> str:
    out = ["```mermaid", "graph LR"]
    active = set(node.active)
    for h, e in sorted(node.index.items(), key=lambda kv: kv[1].height):
        lab = labels.get(h, f"h{e.height}")
        bits = 256 - e.block.header.target.bit_length()
        txt = f"{lab}<br/>h={e.height} · {h.hex()[:8]}<br/>{bits}-bit target · cum work {e.cum_work}"
        out.append(f'    B{h.hex()[:8]}["{txt}"]')
        if e.height > 0:
            out.append(f"    B{e.block.header.prev_hash.hex()[:8]} --> B{h.hex()[:8]}")
    out.append("    classDef active fill:#c8f7c5,stroke:#2e7d32,stroke-width:2px;")
    out.append("    classDef stale fill:#eeeeee,stroke:#9e9e9e,stroke-dasharray: 4 3;")
    out.append("    classDef invalid fill:#ffcdd2,stroke:#c62828;")
    for h, e in node.index.items():
        cls = "invalid" if e.invalid else ("active" if h in active else "stale")
        out.append(f"    class B{h.hex()[:8]} {cls};")
    out.append("```")
    return "\n".join(out)


# ---------------------------------------------------------------------------------------------
def fork_simulation(lines: list[str]) -> dict:
    params = ChainParams(pow_limit=target_from_bits(8))
    tgt = target_from_bits(12)
    genesis = make_genesis(params, ALICE.pkh, T0)
    node_a, node_b = ChainManager(params, genesis, "nodeA"), ChainManager(params, genesis, "nodeB")
    labels = {genesis.hash: "Genesis"}

    def log(msg):
        lines.append(f"- {msg}")

    lines += ["## 1. Two miners produce competing blocks, then the fork resolves", ""]
    b1, att = build_block(node_a, MINER_A.pkh, [], T0 + 600, tgt)
    labels[b1.hash] = "A1"
    log(f"MinerA mines **A1** (height 1, {att} attempts); both nodes accept it: "
        f"A={node_a.submit_block(b1).status}, B={node_b.submit_block(b1).status}")

    alice_cb = OutPoint(genesis.txs[0].txid(), 0)
    tx_bob = sign_tx([(alice_cb, ALICE)], [TxOut(30, BOB.pkh), TxOut(19, ALICE.pkh)])     # fee 1
    tx_carol = sign_tx([(alice_cb, ALICE)], [TxOut(40, CAROL.pkh), TxOut(8, ALICE.pkh)])  # fee 2
    log(f"Alice double-spends her genesis output: tx `{tx_bob.txid().hex()[:10]}` pays Bob 30 "
        f"(seen by MinerA) and tx `{tx_carol.txid().hex()[:10]}` pays Carol 40 (seen by MinerB)")
    a2, _ = build_block(node_a, MINER_A.pkh, [tx_bob], T0 + 1200, tgt)
    b2, _ = build_block(node_b, MINER_B.pkh, [tx_carol], T0 + 1201, tgt)
    labels[a2.hash], labels[b2.hash] = "A2", "B2"
    log(f"Both mine height 2 at the same time: **A2** `{a2.short()}` (Bob paid) and **B2** "
        f"`{b2.short()}` (Carol paid); each node connects its own: "
        f"A={node_a.submit_block(a2).status}, B={node_b.submit_block(b2).status}")
    ra, rb = node_a.submit_block(b2), node_b.submit_block(a2)
    log(f"Blocks are exchanged. Equal work, so each node keeps its first-seen tip: "
        f"A gets B2 → **{ra.status}**, B gets A2 → **{rb.status}**")
    log(f"Temporary disagreement: nodeA tip {node_a.tip.block.short()} ({balances(node_a)}); "
        f"nodeB tip {node_b.tip.block.short()} ({balances(node_b)})")
    snap_before = node_a.utxo.state_hash()

    b3, _ = build_block(node_b, MINER_B.pkh, [], T0 + 1800, tgt)
    labels[b3.hash] = "B3"
    rb3 = node_b.submit_block(b3)
    ra3 = node_a.submit_block(b3)
    log(f"MinerB extends its branch with **B3**: nodeB {rb3.status}; nodeA **{ra3.status}**: "
        f"disconnected {[labels[h] for h in ra3.disconnected]}, connected "
        f"{[labels[h] for h in ra3.connected]}")
    log(f"Transactions returned from the stale block A2: "
        f"{[t.txid().hex()[:10] for t in ra3.returned_txs]}. Alice's genesis output was restored "
        f"on disconnect and then spent by B2, so the Bob payment is now a conflict (it is "
        f"rejected if re-validated: `{_revalidate(node_a, ra3.returned_txs)}`)")
    assert node_a.active == node_b.active
    assert node_a.utxo.state_hash() == node_b.utxo.state_hash() != snap_before
    log(f"**Converged:** both tips = {node_a.tip.block.short()}, height {node_a.height}, UTXO state "
        f"hash `{node_a.utxo.state_hash()[:16]}…` on both nodes. Final balances: {balances(node_a)}")

    # check the reorg produced exactly the UTXO set of a node that only ever saw the winning chain
    fresh = ChainManager(params, genesis, "fresh")
    for blk in (b1, b2, b3):
        fresh.submit_block(blk)
    assert fresh.utxo.state_hash() == node_a.utxo.state_hash()
    log("A third node that only ever saw Genesis→A1→B2→B3 has the identical UTXO set ✔")
    lines += ["", "Block tree as seen by nodeA (green = active chain, grey = stale branch):", "",
              mermaid_tree(node_a, labels), ""]
    return {"params": params, "genesis": genesis, "b3": b3, "node": node_a}


def _revalidate(node, txs):
    out = []
    for t in txs:
        try:
            node.utxo.validate(t)
            out.append("still valid")
        except Exception as e:  # noqa: BLE001
            out.append(str(e).split(":")[0])
    return ", ".join(out) or "none"


def most_work_demo(lines: list[str]) -> None:
    lines += ["## 2. A longer but lower-work branch loses to a shorter higher-work branch", ""]
    params = ChainParams(pow_limit=target_from_bits(4))
    genesis = make_genesis(params, ALICE.pkh, T0)
    node = ChainManager(params, genesis)
    labels = {genesis.hash: "Genesis"}
    prev = genesis.hash
    easy, hard = target_from_bits(8), target_from_bits(10)
    for i in range(1, 5):
        blk, _ = build_block(node, MINER_A.pkh, [], T0 + 60 * i, easy, prev_hash=prev)
        labels[blk.hash] = f"L{i}"
        node.submit_block(blk)
        prev = blk.hash
    l_work = node.tip.cum_work
    lines.append(f"- Branch **L** (4 blocks, 8-bit target, work {work_for_target(easy)} each) is active: "
                 f"height {node.height}, cumulative work {node.tip.cum_work}")
    prev = genesis.hash
    for i in range(1, 3):
        blk, _ = build_block(node, MINER_B.pkh, [], T0 + 61 * i, hard, prev_hash=prev)
        labels[blk.hash] = f"H{i}"
        r = node.submit_block(blk)
        prev = blk.hash
        lines.append(f"- Block **H{i}** (10-bit target, work {work_for_target(hard)}, cumulative "
                     f"{node.index[blk.hash].cum_work}) → **{r.status}**"
                     + (" (equal work: first-seen tip kept)" if r.status == "side-branch" else ""))
    assert node.height == 2 and labels[node.tip.block.hash] == "H2"
    lines.append(f"- Result: active chain is the **2-block** branch H (cumulative work "
                 f"{node.tip.cum_work}) instead of the 4-block branch L (work {l_work}). A node that counted "
                 f"blocks would have kept L.")
    lines += ["", mermaid_tree(node, labels), ""]


def invalid_blocks_demo(lines: list[str], ctx: dict) -> None:
    lines += ["## 3. Invalid blocks are rejected without changing the active chain", ""]
    node: ChainManager = ctx["node"]
    tip_before, state_before = node.tip.block.hash, node.utxo.state_hash()
    tgt = target_from_bits(12)
    good, _ = build_block(node, MINER_A.pkh, [], T0 + 2400, tgt)

    bad_pow_hdr = good.header
    n = bad_pow_hdr.nonce
    while True:                                   # find a nonce that does NOT meet the target
        n += 1
        h = BlockHeader(*[getattr(bad_pow_hdr, f) for f in
                          ("version", "prev_hash", "merkle_root", "timestamp", "target")], n)
        if not h.pow_ok():
            break
    cases = [("invalid PoW (hash > target)", Block(h, good.txs))]

    wrong_root = BlockHeader(1, good.header.prev_hash, b"\x11" * 32, good.header.timestamp, tgt, 0)
    cases.append(("incorrect Merkle root", Block(mine_header(wrong_root)[0], good.txs)))

    greedy, _ = build_block(node, MINER_A.pkh, [], T0 + 2400, tgt, coinbase_extra=1)
    cases.append(("excess coinbase value (subsidy + 1)", greedy))

    spent = OutPoint(ctx["genesis"].txs[0].txid(), 0)       # already spent in B2
    bad_tx = sign_tx([(spent, ALICE)], [TxOut(45, ALICE.pkh)])
    cb = Transaction.coinbase(node.height + 1, [TxOut(50, MINER_A.pkh)])
    hdr = BlockHeader(1, node.tip.block.hash, merkle_root([cb.txid(), bad_tx.txid()]), T0 + 2400, tgt, 0)
    cases.append(("contains an invalid transaction (double spend)", Block(mine_header(hdr)[0], (cb, bad_tx))))

    # an invalid block on a HEAVIER competing branch: reorg must be rolled back
    fork_parent = node.active[1]
    h_easy = target_from_bits(20)
    cbx = Transaction.coinbase(2, [TxOut(50, MINER_B.pkh)])
    badx = sign_tx([(OutPoint(b"\x42" * 32, 0), ALICE)], [TxOut(1, ALICE.pkh)])
    hx = BlockHeader(1, fork_parent, merkle_root([cbx.txid(), badx.txid()]), T0 + 2500, h_easy, 0)
    cases.append(("heavier fork block (20-bit target) with a missing input",
                  Block(mine_header(hx)[0], (cbx, badx))))

    lines += ["| Block | Result | Reason |", "|---|---|---|"]
    for label, blk in cases:
        r = node.submit_block(blk)
        assert r.status == "rejected", (label, r)
        assert node.tip.block.hash == tip_before and node.utxo.state_hash() == state_before
        lines.append(f"| {label} | **{r.status}** | {r.reason} |")
    lines += ["", f"After all five, the active tip is still `{tip_before.hex()[:10]}` and the UTXO "
                  f"state hash is unchanged ✔", ""]
    r = node.submit_block(good)
    lines += [f"The honest block `{good.short()}` with the same parent is then accepted: **{r.status}**.", ""]


def pow_benchmark(bits_list=(8, 12, 16), samples=(500, 200, 60)) -> list[str]:
    rows = ["| Target | Expected attempts 2^256/(T+1) | Blocks mined | Mean observed attempts "
            "| Observed / expected | Median | Hashes per second |", "|---|---:|---:|---:|---:|---:|---:|"]
    for bits, k in zip(bits_list, samples):
        tgt = target_from_bits(bits)
        expected = work_for_target(tgt)
        attempts, t0 = [], time.perf_counter()
        for i in range(k):
            hdr = BlockHeader(1, os.urandom(32), os.urandom(32), T0 + i, tgt, 0)
            _, a = mine_header(hdr)
            attempts.append(a)
        dt = time.perf_counter() - t0
        mean = statistics.mean(attempts)
        rows.append(f"| {bits} leading zero bits | {expected:,} | {k} | {mean:,.0f} | {mean / expected:.2f} "
                    f"| {statistics.median(attempts):,.0f} | {sum(attempts) / dt:,.0f} |")
    return rows


def run_all(out_path: str | None = None) -> str:
    lines = ["# Blocks, Proof of Work, forks and reorganisation — report", "",
             "Generated by `python -m chain demo`. Hashes and nonces change between runs because "
             "signatures and benchmark headers are randomised; the structure and outcomes are "
             "asserted by the code.", ""]
    ctx = fork_simulation(lines)
    most_work_demo(lines)
    invalid_blocks_demo(lines, ctx)
    lines += ["## 4. Block header hex dump (block B3 of the fork simulation)", "", "```",
              ctx["b3"].header.hexdump(), "```", ""]
    lines += ["## 5. Proof-of-Work measurements", "",
              f"Machine: `{platform.machine()}`, Python {platform.python_version()}. Each sample mines a "
              "header with random `prev_hash` and `merkle_root`, starting from nonce 0.", ""]
    lines += pow_benchmark()
    lines += ["", "Finding a block is a geometric trial with success probability p = (T+1)/2^256, "
              "so the expected number of attempts is 1/p = 2^256/(T+1). That is exactly the *work* the "
              "chain credits to the block. The observed means sit close to expectation (ratios near "
              "1.0, with sampling noise from the geometric distribution's large variance: the "
              "standard deviation is about the mean, and the median is about ln 2 ≈ 0.69 of the mean). The hash rate is constant across targets, so "
              "each extra zero bit doubles the expected time to find a block.", ""]
    report = "\n".join(lines) + "\n"
    if out_path:
        with open(out_path, "w") as f:
            f.write(report)
    return report
