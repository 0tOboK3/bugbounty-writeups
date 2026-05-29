# D-004 — Permanent Withdrawal Queue Freeze via Off-By-One in IndexOutOfBounds Check (Ember ETH Vault)

**Program:** Ember Finance (Immunefi)  
**Contract:** `EmberETHVault.sol` — `_updateAccountState()`  
**Severity:** Critical  
**Affected function:** `_updateAccountState()` / `_executeWithdrawalWithETH()`

---

## TL;DR

`EmberETHVault._updateAccountState()` has an off-by-one bounds check that permanently freezes the entire withdrawal queue whenever a request is skipped because the owner or receiver was blacklisted (not user-cancelled). The bug: when `indexToUse = cancelLength` (set by the skipping logic), the check `index >= cancelLength` evaluates to true and reverts with `IndexOutOfBounds()` — permanently. The identical function in `EmberVault.sol` uses a soft bounds check (`if (index < cancelLength)`) and doesn't have this bug. Additionally, a malicious actor can intentionally trigger the freeze by submitting a withdrawal to a contract that rejects ETH, forcing the owner to blacklist the receiver, which then activates the permanent freeze.

---

## Root Cause

### Bug B — Off-By-One (Primary: Permanent Freeze)

When a withdrawal request is skipped because the owner or receiver is blacklisted, the skipping logic sets:

```solidity
// EmberETHVault.sol L1249-1252
if (skipped) {
    if (!cancelled) {
        indexToUse = accountState.cancelWithdrawRequestSequenceNumbers.length; // = cancelLength
    }
}
_updateAccountState(request, false, indexToUse);
```

In `_updateAccountState()`:

```solidity
// EmberETHVault.sol L1392-1400
if (index != type(uint256).max) {
    uint256[] storage cancelSeqNums = accountState.cancelWithdrawRequestSequenceNumbers;
    uint256 cancelLength = cancelSeqNums.length;

    if (index >= cancelLength) revert IndexOutOfBounds(); // BUG: when 0 cancels exist:
    //                                                     index=0 >= cancelLength=0 → TRUE
    cancelSeqNums[index] = cancelSeqNums[cancelLength - 1];
    cancelSeqNums.pop();
}
```

When a user has zero cancellations, `cancelLength = 0` and `indexToUse = 0`. The check `0 >= 0` evaluates to true → revert. The queue is permanently frozen because `processWithdrawalRequests` can never advance past this request.

**The correct implementation (from EmberVault.sol for ERC-20):**

```solidity
// EmberVault.sol — soft check, no revert
if (index < cancelLength) {
    cancelSeqNums[index] = cancelSeqNums[cancelLength - 1];
    cancelSeqNums.pop();
}
```

### Bug A — ETH Transfer to Rejecting Receiver (Prerequisite for Attack Chain)

`_executeWithdrawalWithETH` uses a low-level `.call` with no fallback for failed transfers:

```solidity
(bool success, ) = request.receiver.call{ value: withdrawAmount }("");
if (!success) revert ETHTransferFailed(); // reverts the entire processWithdrawalRequests
```

Unlike the ERC-20 vault which uses `SafeERC20.safeTransfer`, there is no skip mechanism for ETH transfers to contracts that reject ETH.

---

## Attack Scenarios

### Path 1 — Compliance Trigger (Unintentional)

1. Alice creates a withdrawal request with `receiver = alice`
2. Admin blacklists Alice for compliance reasons after the request is created
3. Operator calls `processWithdrawalRequests` → `revert IndexOutOfBounds()`
4. Queue permanently frozen for all users behind Alice
5. No recovery without proxy upgrade

### Path 2 — Malicious Freeze (Intentional — Bug A + Bug B)

1. Attacker deposits ETH, creates withdrawal request with `receiver = MaliciousContract` (rejects ETH on receive)
2. Operator calls `processWithdrawalRequests` → `revert ETHTransferFailed()` (Bug A — temporary, fixable)
3. Owner blacklists `MaliciousContract` to unblock the queue
4. Operator calls `processWithdrawalRequests` again → `revert IndexOutOfBounds()` (Bug B — **permanent**)
5. Queue is permanently frozen. Attacker's shares were returned via the skip mechanism — attacker only spent gas.
6. Attack repeatable with new `MaliciousContract` addresses indefinitely.

---

## Proof of Concept

Foundry test file: `test/foundry/poc/ETHVaultQueueDoS.t.sol`

```bash
forge test --match-contract ETHVaultQueueDoSTest -vv
```

Output:
```
[PASS] test_BugA_MaliciousReceiverBlocksQueue()
[PASS] test_BugB_BlacklistCausesPermaDoS()
[PASS] test_BugAB_AttackerForcesPermamentDoS()

Test output (Bug B):
[1] user1 created withdrawal request (receiver = user1)
[2] user2 created withdrawal request after user1
[3] Owner blacklisted user1 AFTER request was created
[4] processWithdrawalRequests(1) REVERTED with IndexOutOfBounds
[5] processWithdrawalRequests(2) also REVERTS
CRITICAL: user2's 2 ETH permanently locked — no recovery without proxy upgrade
```

---

## Impact

- **Permanent fund loss:** All ETH pending in withdrawal requests behind the frozen position is permanently inaccessible to users.
- **Irrecoverable state:** No on-chain function can unfreeze the queue without a proxy upgrade.
- **Low attacker cost:** Gas only — attacker recovers their shares via the skip mechanism. Repeatable indefinitely.
- **Compliance-triggered unintentional freeze:** Even without a malicious actor, a routine blacklisting action (AML/compliance) can permanently freeze the queue.

---

## Recommended Fix

**Fix 1 — Align `_updateAccountState` with EmberVault:**

```solidity
// EmberETHVault.sol — change hard revert to soft check
// BEFORE:
if (index >= cancelLength) revert IndexOutOfBounds();
cancelSeqNums[index] = cancelSeqNums[cancelLength - 1];
cancelSeqNums.pop();

// AFTER:
if (index < cancelLength) {
    cancelSeqNums[index] = cancelSeqNums[cancelLength - 1];
    cancelSeqNums.pop();
}
```

**Fix 2 — Handle failed ETH transfers gracefully:**

```solidity
(bool success, ) = request.receiver.call{ value: withdrawAmount }("");
if (!success) {
    _transfer(address(this), request.owner, request.shares); // return shares
    skipped = true;
    finalWithdrawAmount = 0;
}
```

---

## Lessons Learned

- **Code duplication between similar contracts is a bug magnet.** The ERC-20 vault (`EmberVault.sol`) had the correct soft check. The ETH vault (`EmberETHVault.sol`) had the buggy hard revert. Divergence between "identical" implementations is always worth examining.
- **Off-by-one in a bounds check + queue processing = permanent DoS.** An unchecked `>=` instead of `>` in a withdrawal queue that processes sequentially means the entire queue freezes permanently, not just one request.
- **Compliance mechanisms can create security vulnerabilities.** The blacklisting feature is a legitimate compliance tool, but its interaction with the withdrawal queue's state machine created an irrecoverable state. Security features must be designed with failure modes in mind.
- **Attack chain = Bug A enables the trigger for Bug B.** Each bug alone had limited impact. Combined, they create a grief vector where an attacker can permanently freeze the queue at will.
