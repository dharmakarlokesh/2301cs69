# Local deployment (Anvil, chain id 31337) — verified

Produced by `script/demo.sh`, which starts Anvil, runs `forge script script/Deploy.s.sol --broadcast`, and then runs `script/verify_deployment.py` against the node.

## Transaction receipts

| Tx | Call | To / created | Status | Gas used | Events emitted |
|---|---|---|---|---:|---|
| `0xa5c348bc26…` | constructor | `0x5fbdb231…` | ✔ | 1,233,535 | — |
| `0x1b7f0af5ac…` | fund | `0x5fbdb231…` | ✔ | 69,002 | StateChanged(from=0, to=1)<br>Funded(buyer=0x70997970c5…, amount=1 ETH) |
| `0x79e173ada2…` | release | `0x5fbdb231…` | ✔ | 74,991 | StateChanged(from=1, to=2)<br>Released(by=0x70997970c5…, seller=0x3c44cdddb6…, amount=1 ETH) |
| `0xb0932fc43a…` | withdraw | `0x5fbdb231…` | ✔ | 36,091 | Withdrawn(payee=0x3c44cdddb6…, amount=1 ETH) |
| `0xa8de314991…` | constructor | `0xe7f1725e…` | ✔ | 1,233,535 | — |
| `0xe118054f2e…` | fund | `0xe7f1725e…` | ✔ | 69,002 | StateChanged(from=0, to=1)<br>Funded(buyer=0x70997970c5…, amount=1 ETH) |
| `0x97aeb274c4…` | dispute | `0xe7f1725e…` | ✔ | 29,534 | StateChanged(from=1, to=3)<br>Disputed(by=0x3c44cdddb6…) |
| `0x5189b4f2f3…` | resolveToBuyer | `0xe7f1725e…` | ✔ | 75,255 | StateChanged(from=3, to=4)<br>Resolved(arbiter=0x90f79bf6eb…, payee=0x70997970c5…, amount=1 ETH, toBuyer=true) |
| `0x9495a79ae4…` | withdraw | `0xe7f1725e…` | ✔ | 36,091 | Withdrawn(payee=0x70997970c5…, amount=1 ETH) |

## Deployed bytecode and addresses

| Contract | Deployer / nonce | CREATE address computed | Match | Runtime size | keccak256(code) | Equals compiled runtime (immutables masked) |
|---|---|---|---|---:|---|---|
| `0x5fbdb2315678afecb367f032d93f642f64180aa3` | `0xf39fd6e5…` nonce 0 | `0x5fbdb2315678afecb367f032d93f642f64180aa3` | ✔ | 5,281 B | `0xec3706fa422daab8…` | ✔ |
| `0xe7f1725e7734ce288f8367e1bb143e90bb3f0512` | `0xf39fd6e5…` nonce 1 | `0xe7f1725e7734ce288f8367e1bb143e90bb3f0512` | ✔ | 5,281 B | `0x9ac8a22686d01f36…` | ✔ |

## Final balances (ETH)

| Account | Address | Before (block 0) | After | Escrow payouts | Gas paid | before + payouts − gas == after |
|---|---|---:|---:|---:|---:|---|
| deployer | `0xf39fd6e5…` | 10,000.000000 | 9,999.998034 | +0.0 | 0.001966 | ✔ |
| buyer | `0x70997970…` | 10,000.000000 | 9,998.999832 | -1.0 | 0.000168 | ✔ |
| seller | `0x3c44cddd…` | 10,000.000000 | 10,000.999962 | +1.0 | 0.000038 | ✔ |
| arbiter | `0x90f79bf6…` | 10,000.000000 | 9,999.999970 | +0.0 | 0.000030 | ✔ |
| escrow (state 2) | `0x5fbdb231…` | – | 0.000000 | – | – | ✔ |
| escrow (state 4) | `0xe7f1725e…` | – | 0.000000 | – | – | ✔ |

**Result:** all checks passed ✔
