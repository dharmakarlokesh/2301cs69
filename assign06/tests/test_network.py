import asyncio
import json

from p2p.protocol import MAGIC, encode
from p2p.sim import ALICE, BOB, Attacker, converged, frame, full_mesh, make_network, run_experiment, wait_for
from chain.tx import TxOut, sign_tx


def test_full_experiment(tmp_path):
    report = asyncio.run(run_experiment(str(tmp_path)))
    assert "full mesh" in report
    assert "**disagrees**" in report
    assert report.count("reorganised") == 2
    assert "**re-added**" in report and "**dropped**" in report
    assert "identical UTXO state hash" in report
    for line in report.splitlines():
        if line.startswith("| ") and ": " in line and "|---" not in line:
            assert "False" not in line, line
    logs = list((tmp_path / "logs").glob("node*.jsonl"))
    assert len(logs) == 5
    for p in logs:
        for raw in p.read_text().splitlines()[:200]:
            rec = json.loads(raw)
            assert {"ts", "node", "peer", "object", "event"} <= set(rec)


def test_discovery_relay_and_non_fatal_bad_json():
    async def go():
        nodes, genesis = await make_network(n=5, latency=(0.0, 0.01))
        try:
            await full_mesh(nodes)
            n0, n4 = nodes[0], nodes[4]
            await n0.mine(ALICE.pkh)
            await wait_for(lambda: converged(nodes) and n4.chain.height == 1)
            coin = sorted(op for op, o in n4.chain.utxo.utxos.items() if o.pubkey_hash == ALICE.pkh)[0]
            tx = sign_tx([(coin, ALICE)], [TxOut(5, BOB.pkh), TxOut(44, ALICE.pkh)])
            await n4.submit_local_tx(tx)
            await wait_for(lambda: all(tx.txid() in n.mempool for n in nodes))
            # inventory precedes the object at every receiving node
            for n in nodes[:4]:
                evs = [e["event"] for e in n.events if tx.txid().hex()[:12] in (e["object"] or "")]
                assert evs.index("recv-inv") < evs.index("recv-tx")
            # bad JSON: error reply, connection stays open
            async with Attacker(*nodes[1].addr) as a:
                await a.hello("tester")
                await a.send_raw(frame(b"{oops"))
                await a.send_raw(encode({"type": "ping", "nonce": 7}))
                got = b""
                while b'"pong"' not in got:
                    got += await asyncio.wait_for(a.r.read(4096), 3)
                assert b'"error"' in got and b'"bad-json"' in got
        finally:
            for n in nodes:
                await n.stop()
    asyncio.run(go())


def test_handshake_timeout_and_message_before_hello():
    async def go():
        nodes, _ = await make_network(n=1, handshake_timeout=0.5)
        try:
            async with Attacker(*nodes[0].addr) as a:
                assert await a.closed_by_peer(3)
            async with Attacker(*nodes[0].addr) as a:
                await a.send_raw(encode({"type": "ping", "nonce": 1}))
                assert await a.closed_by_peer(3)
        finally:
            await nodes[0].stop()
    asyncio.run(go())
