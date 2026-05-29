# D-001 — AccountRecovered Event Always Emits address(0) (Ether.fi)

**Program:** Ether.fi Cash v3 (Immunefi)  
**Contract:** `MultiSig.sol` — EtherFiSafe implementation  
**Function:** `_currentOwner()` (line 347–353)  
**Severity:** Low  
**CWE:** CWE-667 (Improper Locking) / incorrect event semantics  
**Testing date:** 2026-05-xx

---

## TL;DR

In `MultiSig._currentOwner()`, the `AccountRecovered` event is emitted **after** `delete $.incomingOwner` sets the storage slot to `address(0)`. As a result, every `AccountRecovered` event logs `address(0)` as the recovered owner, regardless of who actually triggered the recovery. On-chain state is correct — ownership transfers properly. Only the event data is wrong.

---

## Discovery Process

### 1. Identifying the audit gap

Ether.fi Cash had a Certora audit in March 2025 covering the Cash Module and Safe. Checking the audit scope revealed `MultiSig.sol` was explicitly **not in scope** for that audit. This made it a candidate for a fresh review.

### 2. Reading the account recovery flow

The account recovery process in `MultiSig.sol` involves a timelock: a new owner (`incomingOwner`) is nominated and can finalize recovery after a waiting period. The finalization happens inside `_currentOwner()`, which is called as a side effect of any state-mutating operation after the timelock expires.

### 3. Spotting the delete-before-emit pattern

```solidity
// MultiSig.sol lines 347–353
$.owners.add($.incomingOwner);      // Step 1: correct — adds the new owner
$.threshold = 1;

delete $.incomingOwnerStartTime;    // Step 2: clears start time
delete $.incomingOwner;             // Step 3: sets $.incomingOwner to address(0)

emit AccountRecovered($.incomingOwner);  // Step 4: reads address(0) — BUG
```

`delete` in Solidity sets the storage slot to its zero value (`address(0)` for addresses). The event on step 4 reads the now-zeroed storage, so it always emits `AccountRecovered(address(0))`.

### 4. Checking the existing test suite

`test/safe/Recovery.t.sol` contained 50 recovery tests. None validated the `AccountRecovered` event parameter. The bug had existed undetected.

### 5. Comparing with a pattern in the same contract

`fundRequest` (line 1045) already performs the check:

```solidity
if (metadata.sender == address(0)) revert UnknownRequest();
```

This shows awareness of the zero-address issue elsewhere in the codebase — making the omission in `_currentOwner()` a consistency gap.

---

## Vulnerability

```solidity
// BUGGY (current code):
delete $.incomingOwner;                   // sets to address(0)
emit AccountRecovered($.incomingOwner);   // reads address(0)

// FIXED:
address recoveredOwner = $.incomingOwner; // cache before deletion
delete $.incomingOwnerStartTime;
delete $.incomingOwner;
emit AccountRecovered(recoveredOwner);    // uses the real address
```

One line of addition. No architectural changes required.

---

## Proof of Concept

```solidity
// test/safe/PoC_AccountRecoveredZeroAddress.t.sol
function test_poc_AccountRecovered_emits_zero_address() public {
    address victimNewOwner = makeAddr("victimNewOwner");
    
    // Setup: nominate new owner and advance past timelock
    // [setup code omitted for brevity — see full test file]
    
    // Expect the event — it will emit address(0), not victimNewOwner
    vm.expectEmit(true, false, false, false);
    emit AccountRecovered(address(0));  // this is what the contract actually emits
    
    // Trigger finalization (any state-mutating call after timelock)
    safe.setThreshold(1);
    
    // On-chain state is CORRECT: victimNewOwner is the actual owner
    address[] memory owners = safe.getOwners();
    assertEq(owners[0], victimNewOwner);  // passes — state is fine
    // But the event said address(0)
}
```

**Run:**
```bash
TEST_CHAIN=10 forge test --match-test test_poc_AccountRecovered_emits_zero_address -vvvv
```

---

## Impact

1. **Off-chain indexers and monitoring tools** that subscribe to `AccountRecovered(address)` always receive `address(0)`, making ownership history untrackable via event logs.

2. **Security alerting systems** watching for `AccountRecovered(maliciousAddress)` will never trigger correctly — they only see `AccountRecovered(0x000...0)`. A malicious account recovery attempt would be invisible to standard event monitoring.

3. **Unexpected emission contexts:** `AccountRecovered` is emitted as a side effect of `_currentOwner()`, which is called from `setThreshold`, `cancelRecovery`, `configureOwners`, and other functions when the timelock has expired. This makes the event appear in unexpected places with incorrect data.

This is Low severity because:
- No financial loss is possible from this bug alone
- On-chain ownership state is correct
- Exploitation requires the timelock expiry condition

---

## Remediation

Cache `$.incomingOwner` before deletion:

```solidity
address recoveredOwner = $.incomingOwner;
delete $.incomingOwnerStartTime;
delete $.incomingOwner;
emit AccountRecovered(recoveredOwner);
```

Apply the same pattern to `IncomingOwnerSet` emissions for consistency.

---

## Lessons Learned

- **"Not in scope for the previous audit" = high-value surface.** Always check what was explicitly excluded from prior audits — those areas have the same code quality but less scrutiny.
- **Delete-before-emit is a subtle and recurring Solidity mistake.** After `delete x`, reading `x` gives the zero value, not the pre-deletion value. Caching in a local variable before deletion is the standard pattern to prevent this.
- **Event correctness matters for security tooling.** Incorrect events don't break on-chain logic, but they break the monitoring infrastructure that operators and security teams rely on. A malicious recovery that emits `address(0)` instead of the attacker's address is effectively invisible.
- **Test the emitted parameters, not just that the event fires.** The existing 50 recovery tests all passed — but none used `vm.expectEmit` to validate the address argument. Adding parameter assertions to event tests catches this class of bug.
