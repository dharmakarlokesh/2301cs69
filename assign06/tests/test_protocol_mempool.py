import asyncio
import struct

import pytest

from chain.block import target_from_bits
from chain.chain import ChainManager, ChainParams, make_genesis
from chain.crypto import Key
from chain.miner import build_block
from chain.tx import OutPoint, TxOut, sign_tx
from p2p.mempool import Mempool, tx_size
from p2p.protocol import MAGIC, MAX_MESSAGE_SIZE, ProtocolError, decode, encode, read_frame

A, B, C, M = (Key.from_seed(n) for n in ("alice", "bob", "carol", "miner"))


# ---------------------------------------------------------------- framing / schema
def _read(data: bytes):
    async def go():
        r = asyncio.StreamReader()
        r.feed_data(data)
        r.feed_eof()
        return await read_frame(r, 1)
    return asyncio.run(go())


def test_frame_roundtrip():
    msg = {"type": "ping", "nonce": 42}
    raw = encode(msg)
    assert raw[:4] == MAGIC and struct.unpack(">I", raw[4:8])[0] == len(raw) - 8
    assert decode(_read(raw)) == {"v": 1, **msg}


def test_bad_magic_is_fatal():
    with pytest.raises(ProtocolError) as e:
        _read(b"XXXX" + struct.pack(">I", 2) + b"{}")
    assert e.value.code == "bad-magic" and e.value.fatal


def test_oversize_is_fatal_before_reading_body():
    with pytest.raises(ProtocolError) as e:
        _read(MAGIC + struct.pack(">I", MAX_MESSAGE_SIZE + 1))
    assert e.value.code == "oversize" and e.value.fatal


def test_encode_refuses_oversize():
    with pytest.raises(ValueError):
        encode({"type": "error", "code": "x", "detail": "a" * (MAX_MESSAGE_SIZE + 10)})


@pytest.mark.parametrize("payload,code", [
    (b"{not json", "bad-json"),
    (b"\xff\xfe", "bad-json"),
    (b"[1,2]", "bad-message"),
    (b'{"v":2,"type":"ping","nonce":1}', "bad-version"),
    (b'{"v":1,"type":"launch_missiles"}', "unknown-type"),
    (b'{"v":1,"type":"inv","items":[{"kind":"tx","id":"zz"}]}', "bad-message"),
    (b'{"v":1,"type":"inv","items":[{"kind":"car","id":"' + b"0" * 64 + b'"}]}', "bad-message"),
    (b'{"v":1,"type":"ping","nonce":"1"}', "bad-message"),
    (b'{"v":1,"type":"hello","node_id":"x","listen_port":1,"height":0,"tip":"nothex"}', "bad-message"),
])
def test_schema_errors_are_non_fatal(payload, code):
    with pytest.raises(ProtocolError) as e:
        decode(payload)
    assert e.value.code == code and not e.value.fatal


def test_inv_item_limit():
    items = [{"kind": "tx", "id": "00" * 32}] * 501
    with pytest.raises(ProtocolError):
        decode(encode({"type": "inv", "items": items})[8:])


# ---------------------------------------------------------------- mempool
@pytest.fixture
def chain():
    params = ChainParams(pow_limit=target_from_bits(4))
    g = make_genesis(params, A.pkh, 1_700_000_000, target_from_bits(6))
    c = ChainManager(params, g)
    for i in range(3):
        blk, _ = build_block(c, A.pkh, [], 1_700_000_000 + 60 * (i + 1), target_from_bits(6))
        c.submit_block(blk)
    coins = sorted(op for op, o in c.utxo.utxos.items() if o.pubkey_hash == A.pkh)
    return c, coins


def pay(coin, to, amount, fee, key=A):
    return sign_tx([(coin, key)], [TxOut(amount, to.pkh), TxOut(50 - amount - fee, key.pkh)])


def test_accept_and_duplicate_suppression(chain):
    c, coins = chain
    mp = Mempool()
    tx = pay(coins[0], B, 10, 1)
    assert mp.add(tx, c.utxo, 0) == (True, "accepted")
    assert mp.add(tx, c.utxo, 0) == (False, "already-in-mempool")
    assert len(mp) == 1


def test_invalid_tx_rejected(chain):
    c, coins = chain
    mp = Mempool()
    assert mp.add(pay(coins[0], B, 10, 1, key=M), c.utxo, 0) == (False, "pubkey-mismatch")
    assert mp.add(sign_tx([(coins[0], A)], [TxOut(60, B.pkh)]), c.utxo, 0)[1] == "outputs-exceed-inputs"
    assert mp.add(pay(OutPoint(b"\x01" * 32, 0), B, 1, 1), c.utxo, 0)[1] == "missing-or-spent-input"


def test_fee_rate_ordering_and_selection(chain):
    c, coins = chain
    mp = Mempool()
    low, mid, high = pay(coins[0], B, 10, 1), pay(coins[1], B, 10, 5), pay(coins[2], B, 10, 9)
    for t in (low, high, mid):
        mp.add(t, c.utxo, 0)
    assert [e.tx.txid() for e in mp.ordered()] == [high.txid(), mid.txid(), low.txid()]
    assert [t.txid() for t in mp.select(c.utxo, 2)] == [high.txid(), mid.txid()]
    assert mp.ordered()[0].fee_rate == 9 / tx_size(high)


def test_conflict_lower_fee_rejected_higher_replaces(chain):
    c, coins = chain
    mp = Mempool()
    first = pay(coins[0], B, 10, 3)
    assert mp.add(first, c.utxo, 0)[0]
    assert mp.add(pay(coins[0], C, 10, 2), c.utxo, 0) == (False, "mempool-conflict")
    assert mp.add(pay(coins[0], C, 10, 3), c.utxo, 0) == (False, "mempool-conflict")   # equal fee
    ok, why = mp.add(pay(coins[0], C, 10, 8), c.utxo, 0)
    assert ok and "replaced" in why and first.txid() not in mp and len(mp) == 1


def test_expiry(chain):
    c, coins = chain
    mp = Mempool(ttl=60)
    a, b = pay(coins[0], B, 10, 1), pay(coins[1], B, 10, 1)
    mp.add(a, c.utxo, now=0)
    mp.add(b, c.utxo, now=50)
    assert mp.expire(now=100) == [a.txid()]
    assert b.txid() in mp and a.txid() not in mp
    assert mp.add(pay(coins[0], C, 10, 1), c.utxo, now=100)[0]    # its coin is free again


def test_capacity_evicts_lowest_fee_rate(chain):
    c, coins = chain
    mp = Mempool(max_size=2)
    mp.add(pay(coins[0], B, 10, 2), c.utxo, 0)
    mp.add(pay(coins[1], B, 10, 5), c.utxo, 0)
    assert mp.add(pay(coins[2], B, 10, 1), c.utxo, 0) == (False, "mempool-full")
    assert mp.add(pay(coins[2], B, 10, 7), c.utxo, 0)[0]
    assert sorted(e.fee for e in mp.entries.values()) == [5, 7]


def test_block_removes_included_and_conflicting(chain):
    c, coins = chain
    mp = Mempool()
    a, b = pay(coins[0], B, 10, 1), pay(coins[1], B, 10, 1)
    conflict_with_a = pay(coins[0], C, 20, 2)
    mp.add(a, c.utxo, 0)
    mp.add(b, c.utxo, 0)
    blk, _ = build_block(c, M.pkh, [conflict_with_a, b], 1_700_001_000, target_from_bits(6))
    assert c.submit_block(blk).status == "connected"
    mp.block_connected(blk)
    assert len(mp) == 0


def test_reconsider_after_reorg(chain):
    c, coins = chain
    mp = Mempool()
    still_valid = pay(coins[0], B, 10, 1)
    res = mp.reconsider([still_valid], c.utxo, 0)
    assert res == [(still_valid.txid(), True, "accepted")]
    spent = pay(OutPoint(b"\x02" * 32, 0), B, 10, 1)
    assert mp.reconsider([spent], c.utxo, 0)[0][1] is False
