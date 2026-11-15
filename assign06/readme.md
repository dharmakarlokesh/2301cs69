# Assignment 6 — A Peer-to-Peer Mempool and Block Relay Network

 **Stack:** Python 3.11+ `asyncio` over **localhost TCP**, `cryptography` · tests with `pytest`

Five or more instances of the Assignment 5 node (the `chain` package is copied into `src/chain`)
connect over TCP. They discover each other, relay transactions and blocks with
inventory-before-data, keep a mempool, and stay responsive under malformed, repeated, or abusive
input. A scripted experiment partitions the network, mines on both sides, heals it, and shows
convergence on the most-work chain.

## Layout

```
assign06/
├── readme.md
├── pyproject.toml / requirements.txt
├── src/chain/          ← node from Assignment 5 (blocks, PoW, UTXO, most-work, reorg)
├── src/p2p/
│   ├── protocol.py     ← framing (magic + u32 length, 1 MiB max) and versioned message schema
│   ├── mempool.py      ← validation, duplicates, fee-rate order, expiry, conflicts / RBF
│   ├── node.py         ← TCP node: handshake, discovery, inv/getdata relay, rate limit, timeouts, scoring, logs
│   ├── sim.py          ← 5-node experiment + attacker client
│   └── cli.py          ← `p2p experiment`
├── tests/test_protocol_mempool.py, tests/test_network.py   ← 25 tests
└── reports/experiment.md, reports/logs/node0..4.jsonl      ← experiment output + structured logs
```

## How to run

```bash
cd assign06
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

p2p experiment          # ~8 s: 5 nodes on 127.0.0.1, writes reports/experiment.md and reports/logs/
pytest -q               # 25 tests (including the full experiment)
```

Without installing: `PYTHONPATH=src python3 -m p2p experiment`.

## Protocol

**Framing:** `"TOYN"` (4 bytes) ‖ `length` (u32, big-endian) ‖ `payload` (UTF-8 JSON). The maximum
payload is **1 MiB**. A wrong magic or an oversize length is **fatal**: the node disconnects
immediately, without reading the body. A frame whose JSON or schema is bad is **non-fatal**: the node
replies with `error`, adds to the peer's score, and keeps reading.

**Messages** are all `{"v": 1, "type": …}`:

| Type | Fields | Purpose |
|---|---|---|
| `hello` | node_id, listen_port, height, tip, user_agent | handshake (both sides; nothing else is accepted first) |
| `getaddr` / `addr` | addrs ≤ 100 | peer discovery |
| `inv` | items ≤ 500 `{kind: tx|block, id}` | inventory announcement |
| `getdata` / `notfound` | items | object request / not available |
| `tx` / `block` | object | the data itself |
| `ping` / `pong` | nonce | liveness |
| `error` | code, detail | error response to malformed input |

**Relay:** a node that accepts a new tx or block sends only an `inv` to its other peers. A peer that
lacks the object (and has not requested it in the last 2 s) asks with `getdata`, so peers request
only missing data. After a handshake each side announces its tip. When a received block is an
**orphan**, the node requests its parent from the same peer, which walks back to the common
ancestor. This is how nodes catch up after a partition.

## Node policies

| Feature | Implementation |
|---|---|
| Peer discovery | nodes 1–4 only know the seed `node0`; `getaddr`/`addr` plus a connector loop (every 0.3 s) build a full mesh; duplicate connections are resolved deterministically (keep the one opened by the lower node id) |
| Mempool | valid against the tip UTXO set; duplicate suppression; **fee-rate** ordering (fee / bytes); expiry (TTL); conflicts: replace only with a strictly higher fee rate *and* fee (RBF), otherwise `mempool-conflict`; capacity eviction of the lowest fee rate; on block connect, remove included and conflicting txs; after a reorg, **reconsider** txs from stale blocks and re-validate everything |
| Rate limiting | per-peer token bucket (200 msg/s, burst 400); excess messages are dropped and penalised |
| Timeouts | handshake 3 s; idle 10 s; ping every 2 s, and an unanswered ping disconnects |
| Malformed input | fatal vs non-fatal as above; any exception while handling a message is caught, answered with `error`, and penalised. A bad message never stops the node |
| Peer scoring | bad-json/bad-message +10, unknown type +5, rate-limited +2, invalid tx +10, invalid block +50; **ban at 100** for 60 s |
| Latency | each node adds a fixed one-way delay (20–80 ms) plus jitter to every message, delivered in order |
| Partition | `block_peers()` closes and refuses connections to the other group; `unblock_all()` heals, and the connector reconnects |
| Structured logs | one JSON object per line: `ts`, `node`, `peer`, `object`, `event` (+ details) in `reports/logs/node*.jsonl` |

## Example experiment (`reports/experiment.md`)

1. **Discovery:** a full mesh forms from a single seed.
2. **Relay:** a tx submitted at node3 reaches every mempool (`inv` → `getdata` → `tx`); a block mined at
   node1 reaches every node and clears the mempools.
3. **Partition** into {node0, node1} and {node2, node3, node4}. Alice's coin #3 is double-spent: tx_conf
   on side X, tx_y on side Y. Side X also has an unrelated tx_x. **One block is mined on each side**,
   so the tips disagree. Then an **additional block** is mined on side Y.
4. **Heal:** nodes reconnect within about 0.4 s and **all converge on the most-work chain** (side Y).
   node0 and node1 reorganise; tx_x from the stale block is **re-added** to the mempool and relayed to
   everyone, while tx_conf is **dropped** because it conflicts with the confirmed tx_y. A final block
   confirms tx_x, and every node ends with the same UTXO state hash.
5. **Attacks on node2:** garbage bytes, an oversize frame, a silent connection, invalid JSON, a
   1,500-message flood, 50 duplicate `inv`s, and an invalid-PoW block. Each is disconnected, banned,
   or ignored as appropriate. node2 keeps relaying and mines the next block.

## Tests

| Area | Tests |
|---|---|
| Framing and schema | `test_frame_roundtrip`, `test_bad_magic_is_fatal`, `test_oversize_is_fatal_before_reading_body`, `test_schema_errors_are_non_fatal` (9 cases), `test_inv_item_limit` |
| Mempool | validation, duplicates, fee-rate order, conflict/RBF, expiry, capacity, block removal, reconsideration |
| Network | `test_discovery_relay_and_non_fatal_bad_json` (inv precedes data), `test_handshake_timeout_and_message_before_hello`, `test_full_experiment` (partition, convergence, attacks, log format) |

## Video demo

YouTube (unlisted): _to be added_
