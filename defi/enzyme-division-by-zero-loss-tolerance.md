# D-003 — Division by Zero Permanently Bricks Smart Account When lossTolerancePeriodDuration=0 (Enzyme)

**Program:** Enzyme Finance (Immunefi)  
**Contract:** `SharePriceThrottledAssetManagerLib` (`0xFdE8c198BeF60D026332a671F64c34D65C60C935`)  
**Severity:** Low  
**On-chain evidence:** Factory has 3 proxy deployments (June–September 2024)  
**Prior audits:** ChainSecurity XV (March 2024) — CS-SUL15-004 is a different bug

---

## TL;DR

`SharePriceThrottledAssetManagerLib` can be deployed with `lossTolerancePeriodDuration = 0`. After the first call that causes any share price loss, the throttle state records `cumulativeLoss > 0`. Every subsequent loss-causing call then divides by `getLossTolerancePeriodDuration()` — which returns 0 — triggering a `Panic(0x12)` (Solidity 0.8 division by zero). The smart account is permanently bricked for any operation that reduces share price. No fund loss, but recovery requires deploying a new proxy.

---

## Root Cause

Neither `deployProxy()` nor `init()` validates that `_lossTolerancePeriodDuration` is non-zero when `_lossTolerance > 0`:

```solidity
// init() — only lossTolerance is range-checked, not lossTolerancePeriodDuration
function init(..., uint64 _lossTolerance, uint32 _lossTolerancePeriodDuration, ...) external {
    if (_lossTolerance > ONE_HUNDRED_PERCENT) revert ExceedsOneHundredPercent();
    // No check: _lossTolerance > 0 && _lossTolerancePeriodDuration == 0
    lossTolerancePeriodDuration = _lossTolerancePeriodDuration; // stored as 0
}
```

The division by zero occurs in `__validateAndUpdateThrottle`:

```solidity
function __validateAndUpdateThrottle(uint256 _prevSharePrice) private {
    // ...
    if (nextCumulativeLoss > 0) {  // true after first loss event
        uint256 cumulativeLossToRestore =
            getLossTolerance() * (block.timestamp - throttle.lastLossTimestamp)
            / getLossTolerancePeriodDuration(); // ← PANIC(0x12) when duration == 0
    }
}
```

The semantic intent of `duration = 0` may be "loss never replenishes." The actual behavior — permanent bricking after one loss — is undocumented and unexpected.

---

## Steps to Reproduce

1. Deploy via `SharePriceThrottledAssetManagerFactory.deployProxy()` with `_lossTolerance = 1e16` (1%) and `_lossTolerancePeriodDuration = 0`.
2. Register the proxy as the asset manager for an Enzyme vault.
3. Call `executeCalls()` with operations that reduce share price by < 1%: **succeeds** — first loss recorded, `throttle.cumulativeLoss > 0`.
4. Call `executeCalls()` again with any share-price-reducing operation: **REVERT Panic(0x12)** — division by zero.
5. All subsequent `executeCalls()` calls that cause any share price decrease revert permanently.

---

## Impact

- Smart account instances deployed with `duration = 0` and `lossTolerance > 0` become permanently non-functional for loss-causing calls after the first such call succeeds.
- Underlying vault is unaffected — funds remain accessible via other vault mechanisms.
- Recovery requires deploying a new proxy with correct parameters and updating vault configuration.
- No direct fund loss.

**On-chain context:** The factory (`0x0883ba10f44217b97bde11900e197738a7df911b`) has 3 confirmed proxy deployments between June and September 2024, confirming production use.

---

## Proof of Concept

```solidity
// Minimal reproduction — no external RPC needed
contract ENZ001Test is Test {
    function test_ENZ001_DivisionByZeroAfterFirstLoss() public {
        // Deploy proxy with duration=0, tolerance=1%
        address proxy = factory.deployProxy(
            owner, vaultProxy, 
            1e16,  // lossTolerance = 1%
            0,     // lossTolerancePeriodDuration = 0  ← bug trigger
            shutdowner
        );

        // First loss call succeeds — stores cumulativeLoss > 0
        vm.prank(owner);
        ISharePriceThrottledAssetManager(proxy).executeCalls(lossArgs1);
        // ✓ success

        // Second loss call — Panic(0x12) division by zero
        vm.prank(owner);
        vm.expectRevert(); // Panic(0x12)
        ISharePriceThrottledAssetManager(proxy).executeCalls(lossArgs2);
    }
}
```

---

## Remediation

**Option A (reject invalid configuration):**
```solidity
if (_lossTolerance > 0 && _lossTolerancePeriodDuration == 0) {
    revert InvalidLossTolerancePeriodDuration();
}
```

**Option B (handle gracefully — duration=0 means no replenishment):**
```solidity
if (nextCumulativeLoss > 0 && getLossTolerancePeriodDuration() > 0) {
    uint256 cumulativeLossToRestore = getLossTolerance()
        * (block.timestamp - throttle.lastLossTimestamp)
        / getLossTolerancePeriodDuration();
}
```

Option A is cleaner — eliminates ambiguous semantics at deployment time.

---

## Prior Audit Gap

ChainSecurity XV (March 2024) audited `SharePriceThrottledAssetManagerLib` and found **CS-SUL15-004** (reinitialization bypass via `_vaultProxyAddress = 0x0`, Low, Risk Accepted). The division-by-zero in `__validateAndUpdateThrottle` when `lossTolerancePeriodDuration = 0` does not appear in any of the 7 findings from that audit or in any prior Enzyme audit (extensions I–XIV).

---

## Lessons Learned

- **Missing input validation for "zero value" edge cases is common in factory patterns.** Factories pass parameters through to initializers without necessarily validating their combined semantics.
- **Solidity 0.8 division by zero is a `Panic`, not just a gas waste.** It reverts the entire transaction with `Panic(0x12)` — making the affected path permanently unusable, not just incorrect.
- **Read the audit reports before starting.** The CS-SUL15-004 finding confirmed the auditors looked at initialization logic. Finding that their finding was about a *different* initialization parameter told me my finding was novel.
- **"No funds at risk" ≠ not a valid finding.** A smart account that bricks itself after one operation has direct user impact (forced re-deployment, potential vault reconfiguration) even without fund loss.
