import pytest

from chain.block import Block, BlockHeader, merkle_root, target_from_bits, work_for_target
from chain.chain import ChainManager, ChainParams, make_genesis
from chain.crypto import Key
from chain.miner import build_block, mine_header
from chain.sim import run_all
from chain.tx import OutPoint, Transaction, TxOut, sign_tx

T0 = 1_700_000_000
A, B, C, M = (Key.from_seed(n) for n in ("alice", "bob", "carol", "miner"))
TGT = target_from_bits(8)


@pytest.fixture
def setup():
    params = ChainParams(pow_limit=target_from_bits(4))
    g = make_genesis(params, A.pkh, T0, TGT)
    return params, g, ChainManager(params, g)


def mine_on(node, prev, ts, txs=(), target=TGT, pkh=M.pkh, extra=0, height=None):
    return build_block(node, pkh, list(txs), ts, target, prev_hash=prev, coinbase_extra=extra,
                       height=height)[0]


def extend(node, n, start_ts, target=TGT, prev=None):
    blocks = []
    prev = prev or node.tip.block.hash
    base = node.index[prev].height
    for i in range(n):
        b = mine_on(node, prev, start_ts + 60 * i, target=target, height=base + i + 1)
        blocks.append(b)
        prev = b.hash
    return blocks


# ------------------------------------------------------------------ headers and PoW
def test_header_fields_and_roundtrip(setup):
    _, g, node = setup
    b = mine_on(node, g.hash, T0 + 60)
    raw = b.header.serialize()
    assert len(raw) == 116
    assert BlockHeader.parse(raw) == b.header
    assert b.header.prev_hash == g.hash
    assert b.header.merkle_root == merkle_root([t.txid() for t in b.txs])


def test_mining_meets_target():
    hdr = BlockHeader(1, b"\x01" * 32, b"\x02" * 32, T0, target_from_bits(12), 0)
    solved, attempts = mine_header(hdr)
    assert int.from_bytes(solved.hash(), "big") <= solved.target
    assert solved.hash()[:1] == b"\x00" and solved.hash()[1] < 0x10
    assert attempts == solved.nonce + 1


def test_work_accounting():
    assert work_for_target(target_from_bits(8)) == 256
    assert work_for_target(target_from_bits(20)) == 2**20
    assert work_for_target(target_from_bits(10)) > 3 * work_for_target(target_from_bits(8))


# ------------------------------------------------------------------ block validation
def test_connect_and_utxo_update(setup):
    _, g, node = setup
    tx = sign_tx([(OutPoint(g.txs[0].txid(), 0), A)], [TxOut(30, B.pkh), TxOut(15, A.pkh)])
    b, _ = build_block(node, M.pkh, [tx], T0 + 60, TGT)
    assert node.submit_block(b).status == "connected"
    assert node.utxo.balance(B.pkh) == 30 and node.utxo.balance(M.pkh) == 55   # 50 + fee 5
    assert node.height == 1


def test_reject_invalid_pow(setup):
    _, g, node = setup
    b = mine_on(node, g.hash, T0 + 60)
    n = b.header.nonce
    while True:
        n += 1
        h = BlockHeader(1, b.header.prev_hash, b.header.merkle_root, b.header.timestamp, TGT, n)
        if not h.pow_ok():
            break
    r = node.submit_block(Block(h, b.txs))
    assert r.status == "rejected" and "bad-pow" in r.reason and node.height == 0


def test_reject_target_above_pow_limit(setup):
    _, g, node = setup
    cb = Transaction.coinbase(1, [TxOut(50, M.pkh)])
    h = BlockHeader(1, g.hash, merkle_root([cb.txid()]), T0 + 60, target_from_bits(2), 0)
    r = node.submit_block(Block(mine_header(h)[0], (cb,)))
    assert r.status == "rejected" and "bad-target" in r.reason


def test_reject_bad_merkle_root(setup):
    _, g, node = setup
    b = mine_on(node, g.hash, T0 + 60)
    h = BlockHeader(1, g.hash, b"\x00" * 32, T0 + 60, TGT, 0)
    r = node.submit_block(Block(mine_header(h)[0], b.txs))
    assert r.status == "rejected" and "bad-merkle-root" in r.reason


def test_reject_excess_coinbase(setup):
    _, g, node = setup
    before = node.utxo.state_hash()
    r = node.submit_block(mine_on(node, g.hash, T0 + 60, extra=1))
    assert r.status == "rejected" and "excess-coinbase" in r.reason
    assert node.height == 0 and node.utxo.state_hash() == before


def test_coinbase_may_collect_fees_exactly(setup):
    _, g, node = setup
    tx = sign_tx([(OutPoint(g.txs[0].txid(), 0), A)], [TxOut(40, B.pkh)])     # fee 10
    b, _ = build_block(node, M.pkh, [tx], T0 + 60, TGT)
    assert sum(o.value for o in b.txs[0].outputs) == 60
    assert node.submit_block(b).status == "connected"


def test_reject_invalid_transaction_whole_block(setup):
    _, g, node = setup
    good = sign_tx([(OutPoint(g.txs[0].txid(), 0), A)], [TxOut(10, B.pkh)])
    bad = sign_tx([(OutPoint(good.txid(), 0), M)], [TxOut(10, M.pkh)])     # Bob's coin, wrong key
    cb = Transaction.coinbase(1, [TxOut(50, M.pkh)])
    h = BlockHeader(1, g.hash, merkle_root([cb.txid(), good.txid(), bad.txid()]), T0 + 60, TGT, 0)
    before = node.utxo.state_hash()
    r = node.submit_block(Block(mine_header(h)[0], (cb, good, bad)))
    assert r.status == "rejected" and "pubkey-mismatch" in r.reason
    assert node.utxo.state_hash() == before and node.height == 0      # `good` was rolled back


def test_reject_coinbase_rules(setup):
    _, g, node = setup
    cb = Transaction.coinbase(1, [TxOut(50, M.pkh)])
    cb2 = Transaction.coinbase(1, [TxOut(1, M.pkh)])
    tx = sign_tx([(OutPoint(g.txs[0].txid(), 0), A)], [TxOut(10, B.pkh)])
    for txs, code in [((tx,), "first-tx-not-coinbase"), ((cb, cb2), "multiple-coinbase"),
                      ((cb, tx, tx), "duplicate-tx")]:
        h = BlockHeader(1, g.hash, merkle_root([t.txid() for t in txs]), T0 + 60, TGT, 0)
        r = node.submit_block(Block(mine_header(h)[0], txs))
        assert r.status == "rejected" and code in r.reason, (code, r.reason)
    wrong_height = Transaction.coinbase(7, [TxOut(50, M.pkh)])
    h = BlockHeader(1, g.hash, merkle_root([wrong_height.txid()]), T0 + 60, TGT, 0)
    r = node.submit_block(Block(mine_header(h)[0], (wrong_height,)))
    assert "bad-coinbase-height" in r.reason


def test_reject_old_timestamp(setup):
    _, g, node = setup
    r = node.submit_block(mine_on(node, g.hash, T0))          # == median-time-past
    assert r.status == "rejected" and "time-too-old" in r.reason


def test_reject_future_timestamp(setup):
    _, g, node = setup
    r = node.submit_block(mine_on(node, g.hash, T0 + 100_000), now=T0 + 60)
    assert r.status == "rejected" and "time-too-new" in r.reason


def test_orphan_is_connected_when_parent_arrives(setup):
    _, g, node = setup
    helper = ChainManager(node.params, g)
    b1 = mine_on(helper, g.hash, T0 + 60)
    helper.submit_block(b1)
    b2 = mine_on(helper, b1.hash, T0 + 120)
    assert node.submit_block(b2).status == "orphan"
    assert node.submit_block(b1).status == "connected"
    assert node.height == 2 and node.tip.block.hash == b2.hash


# ------------------------------------------------------------------ fork choice
def test_most_work_not_most_blocks(setup):
    _, g, node = setup
    for b in extend(node, 4, T0 + 60, target_from_bits(8)):   # 4 x 256 = 1024
        node.submit_block(b)
    assert node.height == 4
    heavy = extend(node, 2, T0 + 61, target_from_bits(10), prev=g.hash)   # 2 x 1024
    r1 = node.submit_block(heavy[0])
    assert r1.status == "side-branch"                            # 1024 == 1024: first seen wins
    r2 = node.submit_block(heavy[1])
    assert r2.status == "reorg" and node.height == 2 and node.tip.block.hash == heavy[1].hash
    light_tip = [h for h, e in node.index.items() if e.height == 4][0]
    for b in extend(node, 1, T0 + 400, target_from_bits(8), prev=light_tip):
        assert node.submit_block(b).status == "side-branch"    # 5 light blocks still lose
    assert node.tip.block.hash == heavy[1].hash


def test_equal_work_keeps_first_seen(setup):
    _, g, node = setup
    a = mine_on(node, g.hash, T0 + 60)
    b = mine_on(node, g.hash, T0 + 61)
    node.submit_block(a)
    assert node.submit_block(b).status == "side-branch" and node.tip.block.hash == a.hash


def test_reorg_restores_spent_outputs_and_final_utxo(setup):
    params, g, node = setup
    alice_cb = OutPoint(g.txs[0].txid(), 0)
    pay_bob = sign_tx([(alice_cb, A)], [TxOut(30, B.pkh), TxOut(20, A.pkh)])
    pay_carol = sign_tx([(alice_cb, A)], [TxOut(45, C.pkh), TxOut(5, A.pkh)])
    a1, _ = build_block(node, M.pkh, [pay_bob], T0 + 60, TGT)
    assert node.submit_block(a1).status == "connected"
    assert node.utxo.balance(B.pkh) == 30 and alice_cb not in node.utxo.utxos

    other = ChainManager(params, g)
    b1, _ = build_block(other, M.pkh, [pay_carol], T0 + 61, TGT)
    other.submit_block(b1)
    b2, _ = build_block(other, M.pkh, [], T0 + 120, TGT)
    other.submit_block(b2)

    assert node.submit_block(b1).status == "side-branch"
    r = node.submit_block(b2)
    assert r.status == "reorg" and r.disconnected == [a1.hash] and r.connected == [b1.hash, b2.hash]
    assert [t.txid() for t in r.returned_txs] == [pay_bob.txid()]
    assert node.utxo.balance(B.pkh) == 0 and node.utxo.balance(C.pkh) == 45
    assert node.utxo.state_hash() == other.utxo.state_hash()
    # disconnecting back to genesis gives back the original set
    fresh = ChainManager(params, g)
    for blk in (b1, b2):
        fresh.submit_block(blk)
    assert fresh.utxo.utxos == node.utxo.utxos


def test_invalid_heavier_branch_leaves_active_chain(setup):
    params, g, node = setup
    for b in extend(node, 2, T0 + 60):
        node.submit_block(b)
    tip, state = node.tip.block.hash, node.utxo.state_hash()
    cb = Transaction.coinbase(1, [TxOut(51, M.pkh)])                 # excess coinbase
    h = BlockHeader(1, g.hash, merkle_root([cb.txid()]), T0 + 90, target_from_bits(12), 0)
    bad = Block(mine_header(h)[0], (cb,))
    r = node.submit_block(bad)
    assert r.status == "rejected" and "excess-coinbase" in r.reason
    assert node.tip.block.hash == tip and node.utxo.state_hash() == state
    child = mine_on(node, bad.hash, T0 + 200, target=target_from_bits(12), height=2)
    assert node.submit_block(child).status == "rejected"             # builds on invalid block


def test_reorg_with_intermediate_invalid_block_rolls_back(setup):
    params, g, node = setup
    for b in extend(node, 3, T0 + 60):
        node.submit_block(b)
    tip, state = node.tip.block.hash, node.utxo.state_hash()
    helper = ChainManager(params, g)
    good1 = mine_on(helper, g.hash, T0 + 70, target=target_from_bits(9))
    helper.submit_block(good1)
    cb = Transaction.coinbase(2, [TxOut(50, M.pkh)])
    badtx = sign_tx([(OutPoint(b"\x99" * 32, 0), A)], [TxOut(1, A.pkh)])
    h = BlockHeader(1, good1.hash, merkle_root([cb.txid(), badtx.txid()]), T0 + 130,
                    target_from_bits(11), 0)
    bad2 = Block(mine_header(h)[0], (cb, badtx))
    node.submit_block(good1)                      # side branch (512 < 768)
    r = node.submit_block(bad2)                   # 512 + 2048 > 768 -> reorg attempt fails
    assert r.status == "rejected" and "missing-or-spent-input" in r.reason
    assert node.tip.block.hash == tip and node.utxo.state_hash() == state and node.height == 3


# ------------------------------------------------------------------ full simulation
def test_full_simulation_report(tmp_path):
    out = tmp_path / "r.md"
    rep = run_all(str(out))
    assert "**Converged:**" in rep and "reorg" in rep
    assert rep.count("**rejected**") == 5
