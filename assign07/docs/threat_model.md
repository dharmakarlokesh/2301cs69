# Threat model — `Escrow.sol`

**Assets:** the escrowed ETH and the correct payee. **Actors:** buyer, seller, arbiter (each may be
dishonest), arbitrary outsiders, payee contracts with hostile `receive()` code, and relayers that
submit EIP-712 signatures.

| # | Threat | Mitigation | Test(s) |
|---|---|---|---|
| 1 | **Unauthorised transition**: an outsider or the wrong party releases, disputes, resolves, or cancels | Each transition has an explicit role check (`Unauthorized(caller)`) and a state check (`InvalidState(current)`). Roles are `immutable`. There is no owner or admin and no upgradeability | `test_transitionMatrix_everyRejectedTransition` (7 states × 6 actions × 4 callers), `testFuzz_callerRoles`, `test_*_only*` |
| 2 | **Redirecting funds**: someone changes who gets paid | Payees are fixed: release always credits `seller`, resolution credits `buyer` or `seller`. No function takes a payee argument. `withdraw()` pays only `msg.sender`'s own credit | `test_withdraw_nothingForStrangerOrArbiter`, `invariant_creditsSum` (arbiter is never a payee) |
| 3 | **Reentrancy** during payout | No ETH is sent during transitions (pull payments). `withdraw()` follows checks–effects–interactions (the credit is zeroed before the call) and has OpenZeppelin `nonReentrant` | `test_reentrancy_cannotDrain` (a hostile seller re-enters from `receive`; paid exactly once) |
| 4 | **Paying twice from a terminal state** | Each payout transition moves `escrowed` into credits once, and the state then becomes terminal, so no later transition is possible. `withdraw()` zeroes the credit | `test_terminal_cannotPayTwice`, `testFuzz_everyPathPaysExactlyOnce`, `invariant_noDoublePay` |
| 5 | **Repeated funding or wrong amount** | `fund()` only works in `Created` and requires `msg.value == price`. Plain transfers revert because there is no `receive` or `fallback` | `test_fund_rejectsRepeatedFunding`, `test_fund_rejectsWrongAmount`, `testFuzz_depositAmounts`, `test_plainEtherTransferRejected` |
| 6 | **Funds locked** without an intended path | Every funded state has an exit (Funded → Released/Disputed → Resolved*). Credited funds can always be withdrawn by their payee. A payee that rejects ETH only blocks its own withdrawal, and its credit is kept | `test_rejectingPayee_onlyBlocksItself`, `invariant_terminalHoldsNoEscrow` |
| 7 | **Arbiter disappears or is bribed** (residual) | Not solvable on-chain without new trust assumptions. A dispute waits for the arbiter. Mitigations would be a time-bounded recovery path (for example, refund the buyer after N days without resolution) or a multisig arbiter. The arbiter can pick the wrong side but **cannot** pay itself | documented |
| 8 | **Role overlap / zero addresses** | Constructor rejects `address(0)` and any overlap among buyer, seller, and arbiter (a party cannot judge its own dispute) | `test_constructor_*`, `testFuzz_rolesAtConstruction` |
| 9 | **Forced ETH** (`selfdestruct`) breaks equality checks | The logic never relies on `address(this).balance`. It tracks `escrowed` and `totalCredits`, so extra balance is harmless (`balance ≥ liabilities`) | `test_forcedEther_doesNotBreakAccounting` |
| 10 | **Signature replay / phishing** (EIP-712 stretch) | The domain binds chain id and contract address. The nonce is consumed. Release is single-shot by state. The deadline uses a strict `>`. OpenZeppelin `ECDSA` rejects high-`s` and invalid signatures. The relayer cannot change payee or amount. *Residual:* a leaked signature releases funds until its deadline, so use short deadlines | `test_releaseWithSig_*`, `test_domainSeparator_bindsChainAndContract` |
| 11 | **Front-running** | Transitions are role-gated and amount-fixed, so front-running gains nothing. A seller racing to `dispute()` before the buyer's `release()` only moves the deal to the arbiter, which is intended | — |
| 12 | Coding pitfalls | Solidity 0.8.28 checked arithmetic; no `tx.origin`; no loops; no timestamp equality; no unchecked low-level call (OZ `Address.sendValue` reverts on failure); custom errors and events for every transition | review, `forge test` |

**Out of scope:** private-key compromise of a party (other than the signature deadline note),
compiler bugs, and L1 consensus failures.
