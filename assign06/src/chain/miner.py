"""Toy Proof-of-Work miner: vary the nonce until SHA-256(header) <= target."""

from __future__ import annotations

import hashlib
import struct
import time

from .block import Block, BlockHeader, merkle_root
from .tx import Transaction, TxOut
from .utxoset import UtxoSet

U64_MAX = 2**64 - 1


def mine_header(hdr: BlockHeader, start_nonce: int = 0,
                max_attempts: int | None = None) -> tuple[BlockHeader, int]:
    """Return (solved header, attempts). The 108-byte prefix is hashed once and the
    SHA-256 state copied per attempt, so only the 8 nonce bytes are re-hashed."""
    base = hashlib.sha256(hdr.prefix())
    target = hdr.target
    pack = struct.Struct(">Q").pack
    nonce, attempts = start_nonce, 0
    while max_attempts is None or attempts < max_attempts:
        h = base.copy()
        h.update(pack(nonce))
        attempts += 1
        if int.from_bytes(h.digest(), "big") <= target:
            return BlockHeader(hdr.version, hdr.prev_hash, hdr.merkle_root, hdr.timestamp,
                               hdr.target, nonce), attempts
        nonce += 1
        if nonce > U64_MAX:
            raise RuntimeError("nonce space exhausted; change the timestamp")
    raise TimeoutError(f"no solution in {attempts} attempts")


def build_block(chain, miner_pkh: bytes, txs: list[Transaction], timestamp: int | None = None,
                target: int | None = None, prev_hash: bytes | None = None,
                height: int | None = None, coinbase_extra: int = 0) -> tuple[Block, int]:
    """Assemble and mine a block on top of `prev_hash` (default: the active tip).

    Fees are computed by validating `txs` in order against a copy of the active UTXO set
    (only possible when building on the tip; otherwise fees are passed as 0 unless
    `coinbase_extra` is given). `coinbase_extra` lets tests create an INVALID block
    that pays more than allowed."""
    prev_hash = prev_hash or chain.tip.block.hash
    if height is None:
        height = chain.index[prev_hash].height + 1     # parent must be known unless height given
    fees = 0
    if prev_hash == chain.tip.block.hash:
        u = chain.utxo.copy()
        for t in txs:
            fees += u.validate(t)
            u.apply(t)
    cb = Transaction.coinbase(height, [TxOut(chain.params.subsidy + fees + coinbase_extra, miner_pkh)])
    all_txs = (cb, *txs)
    ts = timestamp if timestamp is not None else max(int(time.time()),
                                                     chain.median_time_past(prev_hash) + 1)
    hdr = BlockHeader(1, prev_hash, merkle_root([t.txid() for t in all_txs]), ts,
                      target if target is not None else chain.params.pow_limit, 0)
    solved, attempts = mine_header(hdr)
    return Block(solved, all_txs), attempts
