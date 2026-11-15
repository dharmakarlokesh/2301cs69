"""Mermaid diagram of an inclusion proof path (default: 5 transactions, leaf 2)."""

from __future__ import annotations

from .tree import MerkleTree


def render_diagram(index: int = 2, n: int = 5) -> str:
    leaves = [f"tx{i}".encode() for i in range(n)]
    t = MerkleTree(leaves)
    proof = t.prove(index)
    # which node at each level is on the path, and which node is its sibling
    path_set, sib_set = set(), set()
    i = index
    for lvl, level in enumerate(t.levels):
        path_set.add((lvl, i))
        if lvl < len(t.levels) - 1:
            if i % 2 == 1:
                sib_set.add((lvl, i - 1))
            elif i + 1 < len(level):
                sib_set.add((lvl, i + 1))
        i //= 2
    promoted = set()
    for lvl in range(1, len(t.levels)):
        below = t.levels[lvl - 1]
        if len(below) % 2 == 1:
            promoted.add((lvl, len(t.levels[lvl]) - 1))

    out = ["```mermaid", "graph BT"]
    ids = {}
    for lvl, level in enumerate(t.levels):
        for pos, h in enumerate(level):
            nid = f"L{lvl}_{pos}"
            ids[(lvl, pos)] = nid
            short = h.hex()[:8]
            if lvl == 0:
                label = f"H_leaf(tx{pos})<br/>{short}"
            elif lvl == len(t.levels) - 1:
                label = f"ROOT<br/>{short}"
            elif (lvl, pos) in promoted:
                label = f"(promoted, same hash)<br/>{short}"
            else:
                label = f"H_node<br/>{short}"
            out.append(f'    {nid}["{label}"]')
    for pos in range(n):
        out.append(f'    D{pos}(["tx{pos}"]) --> L0_{pos}')
    for lvl in range(len(t.levels) - 1):
        level = t.levels[lvl]
        for pos in range(len(level)):
            parent = ids[(lvl + 1, pos // 2)]
            if len(level) % 2 == 1 and pos == len(level) - 1:
                out.append(f"    {ids[(lvl, pos)]} -. promoted unchanged .-> {parent}")
            else:
                out.append(f"    {ids[(lvl, pos)]} --> {parent}")
    out.append("    classDef path fill:#c8f7c5,stroke:#2e7d32,stroke-width:2px;")
    out.append("    classDef sib fill:#ffe0b2,stroke:#e65100,stroke-width:2px;")
    out.append("    classDef leafdata fill:#e3f2fd,stroke:#1565c0;")
    for (lvl, pos), nid in ids.items():
        if (lvl, pos) in path_set:
            out.append(f"    class {nid} path;")
        elif (lvl, pos) in sib_set:
            out.append(f"    class {nid} sib;")
    out.append(f"    class D{index} leafdata;")
    out.append("```")

    steps = [f"Proof for **tx{index}** in a tree of **{n}** transactions "
             f"(green = recomputed path, orange = siblings supplied by the proof):", "",
             f"1. `h = H(0x00 || \"tx{index}\")` = `{t.levels[0][index].hex()[:16]}…`"]
    for k, (side, h) in enumerate(proof.siblings, 2):
        expr = "H(0x01 || sibling || h)" if side == "left" else "H(0x01 || h || sibling)"
        steps.append(f"{k}. sibling on the **{side}** `{h.hex()[:16]}…` → `h = {expr}`")
    steps.append(f"{len(proof.siblings) + 2}. compare `h` with the root `{t.root.hex()}` ✔")
    return "\n".join(out + [""] + steps) + "\n"
