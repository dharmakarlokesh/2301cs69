# Assignment 5 — Blocks, Proof of Work, Forks, and Reorganisation

**Stack:** Python 3.11+, `cryptography` · tests with `pytest`

This turns the Assignment 4 validator into a chain. It adds block headers, an adjustable toy Proof
of Work, full block validation, cumulative-work chain selection, and reorganisation with undo data.
The difficulty is deliberately tiny (8–20 leading zero bits) so it runs on a laptop; this is not
cryptocurrency mining.

## Layout

```
assign05/
├── readme.md
├── pyproject.toml / requirements.txt
├── src/chain/
│   ├── crypto.py, tx.py   ← keys, transactions (from A4) + coinbase transactions
│   ├── utxoset.py         ← UTXO set with undo records (connect AND disconnect)
│   ├── block.py           ← 116-byte header, Merkle root (A2 rules), work, hex dump
│   ├── chain.py           ← node-local chain manager: validation, most-work, reorg, orphans
│   ├── miner.py           ← nonce search, block template builder (miner command)
│   ├── sim.py             ← two-miner fork simulation, most-work demo, invalid blocks, PoW benchmark
│   └── cli.py             ← `chain demo | mine | bench`
├── tests/test_chain.py    ← 20 tests (validation, fork choice, reorganisation)
└── reports/report.md      ← generated report: fork narrative, branch diagrams, header hex dump, hash-rate table
```

## How to run

```bash
cd assign05
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

chain mine --bits 16      # miner command: mines one header, prints the hex dump and H/s
chain demo                # fork simulation + report → reports/report.md (takes ~5 s)
chain bench               # expected vs observed attempts at 8/12/16-bit targets
pytest -q
```

Without installing: `PYTHONPATH=src python3 -m chain demo`.

## Block header (116 bytes, big-endian)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | `version` (u32) |
| 4 | 32 | `prev_hash` (SHA-256 of the parent header) |
| 36 | 32 | `merkle_root` of the block's txids. Assignment 2 rules: `H(0x00‖txid)` leaves, `H(0x01‖L‖R)` nodes, odd node promoted |
| 68 | 8 | `timestamp` (u64, Unix seconds) |
| 76 | 32 | `target` (full 256-bit integer) |
| 108 | 8 | `nonce` (u64) |

**Proof of Work:** a block is valid when `int(SHA-256(header), big-endian) ≤ target`. The miner hashes
the first 108 bytes once and then only updates a copy of the SHA-256 state with each new nonce
(about 2.1 M H/s in Python). `target_from_bits(k) = 2^(256−k) − 1` gives "k leading zero bits".

**Work** of a block is `2^256 / (target + 1)`, the expected number of hashes. A chain's work is the
sum over its blocks.

## Validation

| Stage | Checks (rejection code) |
|---|---|
| Context-free | `0 < target ≤ pow_limit` (`bad-target`); hash ≤ target (`bad-pow`); ≥ 1 tx (`no-transactions`); first tx is a coinbase (`first-tx-not-coinbase`) and no other is (`multiple-coinbase`); no duplicate txids (`duplicate-tx`); header Merkle root = root of txids (`bad-merkle-root`); every output positive, ≤ MAX_MONEY, no overflow (`bad-tx`) |
| Contextual | parent known (otherwise `orphan`, connected later), parent not invalid (`invalid-parent`); timestamp > median of the last 11 (`time-too-old`); ≤ now + 2 h (`time-too-new`); coinbase input index = height (`bad-coinbase-height`) |
| State transition | each non-coinbase tx passes the A4 rules against the UTXO set *including earlier txs in the same block*; coinbase value ≤ subsidy (50) + fees (`excess-coinbase`) |

A block is connected **all-or-nothing**: if any transaction fails, the already-applied transactions of
that block are undone and the block is rejected.

## Chain selection and reorganisation

- The manager keeps every valid block in an index with `(height, cumulative work)`. The active tip
  is the one with the **most cumulative work, not the most blocks**. Ties keep the first-seen tip.
- When a stored block gives a side branch more work than the tip, the manager runs a reorg:
  1. find the fork point;
  2. **disconnect** the old blocks newest-first, using the per-transaction undo records to delete
     created outputs and **restore spent outputs**;
  3. **connect** the winning branch oldest-first.
  If a block on the new branch turns out to be invalid, it and its descendants are marked invalid,
  the partial branch is disconnected, and the old branch is reconnected. **The active chain is
  unchanged.**
- Transactions from disconnected blocks that are not in the new branch are returned to the caller.
  The Assignment 6 mempool reconsiders them.
- Simplification: there is no difficulty retargeting. Any target ≤ `pow_limit` is accepted and
  credited with exactly its work, which is how the tests build branches of different weight.

## Fork simulation (see `reports/report.md`)

Two nodes, each with its own miner, start from the same genesis. Both accept A1. Alice then
double-spends her genesis coin: MinerA's **A2** pays Bob and MinerB's **B2** pays Carol. Each node
keeps its own block (equal work), so the network temporarily disagrees. MinerB finds **B3**. NodeA
reorganises: it disconnects A2, restores Alice's coin, then connects B2 and B3. Both nodes converge
on the same tip and an identical UTXO set, which also matches a third node that only ever saw the
winning chain. The report includes Mermaid diagrams of the competing branches and a full header hex
dump.

## Acceptance checks → tests

| Requirement | Test |
|---|---|
| A longer but lower-work branch loses to a shorter higher-work branch | `test_most_work_not_most_blocks` (4 and then 5 blocks at 8-bit lose to 2 blocks at 10-bit) |
| Invalid PoW rejects the block | `test_reject_invalid_pow`, `test_reject_target_above_pow_limit` |
| Incorrect Merkle root rejects the block | `test_reject_bad_merkle_root` |
| Excess coinbase value rejects the block | `test_reject_excess_coinbase`, `test_invalid_heavier_branch_leaves_active_chain` |
| Invalid transaction rejects the entire block | `test_reject_invalid_transaction_whole_block` (the valid tx before it is rolled back) |
| Active chain unchanged after an invalid block | all of the above plus `test_reorg_with_intermediate_invalid_block_rolls_back` |
| Reorg produces the correct final UTXO set | `test_reorg_restores_spent_outputs_and_final_utxo` (compared with a fresh node) |
| Coinbase and timestamp rules, orphans | `test_reject_coinbase_rules`, `test_reject_old_timestamp`, `test_reject_future_timestamp`, `test_orphan_is_connected_when_parent_arrives` |

## Measured Proof of Work (example run; numbers vary)

| Target | Expected attempts | Mean observed | Hashes/s |
|---|---:|---:|---:|
| 8 zero bits | 256 | ≈ 256 | ≈ 2.2 M |
| 12 zero bits | 4,096 | ≈ 4,000 | ≈ 2.1 M |
| 16 zero bits | 65,536 | ≈ 60,000–70,000 | ≈ 2.1 M |

See `reports/report.md` for the exact numbers of the committed run.

## Video demo

YouTube (unlisted): _to be added_
