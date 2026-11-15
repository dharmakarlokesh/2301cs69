#!/usr/bin/env bash
# Start a local Anvil node, deploy + interact via a Foundry script (not a GUI),
# then verify receipts, events, balances, gas and bytecode. Output: reports/deployment.md
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${PORT:-8545}"
export RPC_URL="http://127.0.0.1:${PORT}"
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}"

anvil --port "$PORT" --silent &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null || true' EXIT
for _ in $(seq 50); do cast chain-id --rpc-url "$RPC_URL" >/dev/null 2>&1 && break; sleep 0.2; done

forge script script/Deploy.s.sol:DeployAndInteract --rpc-url "$RPC_URL" --broadcast --slow -vv
python3 script/verify_deployment.py
