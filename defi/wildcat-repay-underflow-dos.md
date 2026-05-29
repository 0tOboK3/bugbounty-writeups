# D-008 — Arithmetic Underflow DoS in repayAndProcessUnpaidWithdrawalBatches (Wildcat Finance)

**Program:** Wildcat Finance (Immunefi)  
**Contract:** `WildcatMarketWithdrawals.sol` — `repayAndProcessUnpaidWithdrawalBatches()`  
**Severity:** Low (DoS, no fund loss, workaround exists)  
**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` = **5.3**  
**PoC:** Forge — 3/3 tests pass

---

## TL;DR

`repayAndProcessUnpaidWithdrawalBatches()` contains an unchecked subtraction at line 299 that reverts with arithmetic underflow whenever `totalAssets() < normalizedUnclaimedWithdrawals + accruedProtocolFees`. This is the normal state of a delinquent market where the borrower has borrowed more than the reserve. The function is the only code path that can process expired, unpaid withdrawal batches — meaning borrowers must provide the complete fee+unclaimed shortfall in a single transaction. Partial repayment strategies are blocked.

The fix pattern using `satSub()` already exists in the same codebase for the equivalent calculation in `availableLiquidityForPendingBatch()`.

---

## Root Cause

```solidity
// WildcatMarketWithdrawals.sol lines 299-300 — vulnerable
uint256 availableLiquidity = totalAssets() -
    (state.normalizedUnclaimedWithdrawals + state.accruedProtocolFees);
//  ^^^^^^ unchecked subtraction — Panic(0x11) when totalAssets < the sum
```

**The existing correct pattern in the same file:**

```solidity
// Withdrawal.sol — availableLiquidityForPendingBatch() uses satSub()
return totalAssets.satSub(state.liquidityRequired());
// satSub: returns max(a-b, 0) — never underflows
```

`satSub()` is already defined in `MathUtils.sol`. The fix is a one-line swap.

---

## Steps to Reproduce

**Prerequisites:** Market with non-zero protocol fee, borrower takes the full deposit.

1. Deploy market with `reserveRatioBips=0`, `protocolFeeBips=1000` (10% annual).
2. Alice deposits `1000e18` tokens. Borrower calls `borrow(1000e18)` — full deposit taken. `totalAssets() = 0`.
3. Alice calls `queueFullWithdrawal()`. Batch created.
4. Time advances past batch expiry. Batch expires unpaid. Even 1 day of accrual creates `accruedProtocolFees > 0`.
5. Call `repayAndProcessUnpaidWithdrawalBatches(0, 1)`:
   - `totalAssets() = 0`
   - `normalizedUnclaimedWithdrawals + accruedProtocolFees > 0`
   - **→ REVERT Panic(0x11) — arithmetic underflow**

**Extension:** Even partial repayment fails if insufficient:

```
totalAssets() after 5e18 repayment = 5e18
accruedProtocolFees after 1 year ≈ 100e18
5e18 - (0 + 100e18) = underflow → revert
```

---

## Proof of Concept

```solidity
contract PoC_RepayUnderflow is BaseMarketTest {
    function setUp() public override {
        parameters.reserveRatioBips = 0;
        super.setUp();
    }

    function test_PoC_underflow_zeroRepay() public {
        _deposit(alice, 1_000e18);
        _borrow(1_000e18);
        vm.prank(alice);
        uint32 expiry = market.queueFullWithdrawal();
        vm.warp(expiry + 1); // batch expires, fees accrue

        vm.expectRevert(); // Panic(0x11)
        market.repayAndProcessUnpaidWithdrawalBatches(0, 1);
    }

    function test_PoC_underflow_partialRepay() public {
        _deposit(alice, 1_000e18);
        _borrow(1_000e18);
        vm.prank(alice);
        uint32 expiry = market.queueFullWithdrawal();
        vm.warp(expiry + 365 days); // ~100 tokens in protocol fees

        uint256 partialRepay = 5e18;
        asset.mint(borrower, partialRepay);
        vm.prank(borrower);
        asset.approve(address(market), partialRepay);

        vm.expectRevert(); // 5e18 < ~100e18 fees → still underflows
        vm.prank(borrower);
        market.repayAndProcessUnpaidWithdrawalBatches(partialRepay, 1);
    }

    function test_PoC_fullRepay_succeeds() public {
        _deposit(alice, 1_000e18);
        _borrow(1_000e18);
        vm.prank(alice);
        uint32 expiry = market.queueFullWithdrawal();
        vm.warp(expiry + 365 days);

        uint256 totalDebt = market.totalDebts();
        asset.mint(borrower, totalDebt);
        vm.prank(borrower);
        asset.approve(address(market), totalDebt);

        vm.prank(borrower);
        market.repayAndProcessUnpaidWithdrawalBatches(totalDebt, 1); // succeeds
    }
}
```

**Output:**
```
[PASS] test_PoC_underflow_zeroRepay()
[PASS] test_PoC_underflow_partialRepay()
[PASS] test_PoC_fullRepay_succeeds()
Suite result: ok. 3 passed; 0 failed
```

---

## Impact

1. **Primary:** `repayAndProcessUnpaidWithdrawalBatches()` is the only function that processes entries in the `_withdrawalData.unpaidBatches` FIFO queue. In a delinquent market, calling with `repayAmount=0` always reverts — even when there is some liquidity.

2. **Secondary:** Borrowers cannot use incremental repayment strategies. They must provide the complete `(normalizedUnclaimedWithdrawals + accruedProtocolFees)` shortfall in one transaction.

**No direct fund loss:** Funds are not at risk of theft. Workaround: pre-fund via separate `repay()` calls until balance covers the full shortfall, then call `repayAndProcessUnpaidWithdrawalBatches(0, N)`.

---

## Recommended Fix

```solidity
// BEFORE (vulnerable):
uint256 availableLiquidity = totalAssets() -
    (state.normalizedUnclaimedWithdrawals + state.accruedProtocolFees);

// AFTER (fixed — consistent with availableLiquidityForPendingBatch):
uint256 availableLiquidity = totalAssets().satSub(
    state.normalizedUnclaimedWithdrawals + state.accruedProtocolFees
);
```

`satSub()` is already defined in `MathUtils.sol` and used in `availableLiquidityForPendingBatch()`. This makes the fix consistent with the existing codebase pattern.

---

## Lessons Learned

- **"Same calculation, different location" is a checklist item.** When you see a calculation pattern using a safe helper (`satSub`) in one place, grep for the same calculation elsewhere without the helper.
- **Delinquent markets hit the path.** `totalAssets() < fees + unclaimed` is the normal state of any market where the borrower took the full deposit. This isn't an edge case — it's the primary use case for `repayAndProcessUnpaidWithdrawalBatches`.
- **A function that can only succeed at full repayment is a UX/liveness risk.** Incremental repayment is the natural pattern when a borrower is recovering. Blocking it creates unnecessary coordination overhead.
- **"Workaround exists" lowers severity but doesn't eliminate the finding.** The code has a documented intent (process batches with partial repayment) that the implementation fails to fulfill in the most common scenario.
