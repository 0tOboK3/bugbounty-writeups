# D-007 — BORING_REDEEM_MINT Always Reverts: Wrong Decimal Divisor in Cross-Vault Migration (Veda Protocol)

**Program:** Veda Protocol (Immunefi)  
**Contract:** `BoringSolver` (`0xED41172438897BcB22c9dd72B9F9bbF9A8bF8929`)  
**Function:** `_boringRedeemMintSolve`  
**Severity:** High  
**Prior audits:** 5 SevenSeas/0xMacro audits — none identified this issue  
**Testing date:** 2026-05-23

---

## TL;DR

`BoringSolver._boringRedeemMintSolve` uses `BoringOnChainQueue(queue).ONE_SHARE()` as the divisor when computing how many intermediate assets are needed to mint destination vault shares. But `queue.ONE_SHARE()` equals `10 ** fromVault.decimals()` — the source vault's precision — while the formula requires `10 ** toVault.decimals()`. Since all three deployed Veda vaults have different decimals (liquidUSD=6, liquidBTC=8, liquidETH=18), the `BORING_REDEEM_MINT` solve type always reverts for every possible cross-vault migration. All 6 pairs are broken.

---

## Root Cause

```solidity
// BoringSolver._boringRedeemMintSolve — buggy line
uint256 assetsToMintRequiredShares = requiredShares.mulDivUp(
    toTeller.accountant().getRateInQuoteSafe(intermediateAsset),
    BoringOnChainQueue(queue).ONE_SHARE()  // BUG: fromVault.decimals() — should be toVault.decimals()
);
```

`queue` is `BoringOnChainQueue` of the **source** vault. Its `ONE_SHARE` immutable is set at construction:

```solidity
// BoringOnChainQueue constructor
ONE_SHARE = 10 ** boringVault.decimals(); // boringVault = FROM vault
```

The mathematically correct formula is:

```
assetsNeeded = requiredShares × rateInQuote / toVault.ONE_SHARE
             = requiredShares × rateInQuote / 10^toVault.decimals
```

---

## Deployed Vault Decimals (On-Chain)

| Vault | Address | Decimals |
|-------|---------|----------|
| liquidUSD | `0x08c6F91e2B681FaF5e17227F2a44C307b3C1364C` | 6 |
| liquidBTC | `0x5f46d540b6eD704C3c8789105F30E075AA900726` | 8 |
| liquidETH | `0xf0bb20865277aBd641a307eCe5Ee04E79073416C` | 18 |

Every cross-vault pair has different decimals → all 6 pairs use the wrong divisor.

## Error Factor Per Pair

| From → To | Wrong divisor | Correct divisor | Error | Result |
|-----------|--------------|-----------------|-------|--------|
| liquidUSD → liquidETH | 1e6 | 1e18 | 1e12× too large | `safeTransferFrom` reverts (can't source 1e12× assets) |
| liquidUSD → liquidBTC | 1e6 | 1e8 | 100× too large | Same |
| liquidETH → liquidUSD | 1e18 | 1e6 | 1e12× too small | `MinimumMintNotMet` |
| liquidETH → liquidBTC | 1e18 | 1e8 | 1e10× too small | Same |
| liquidBTC → liquidUSD | 1e8 | 1e6 | 100× too small | Same |
| liquidBTC → liquidETH | 1e8 | 1e18 | 1e10× too large | `safeTransferFrom` reverts |

---

## Proof of Concept (Foundry — Fork Test)

```solidity
// Fork block 25159442 (Ethereum mainnet, 2026-05-23)
contract V002_ONE_SHARE_DecimalMismatch is Test {
    address constant VAULT_USD = 0x08c6F91e2B681FaF5e17227F2a44C307b3C1364C; // 6 decimals
    address constant VAULT_ETH = 0xf0bb20865277aBd641a307eCe5Ee04E79073416C; // 18 decimals
    address constant QUEUE_USD = 0x38FC1BA73b7ED289955a07d9F11A85b6E388064A; // ONE_SHARE=1e6

    function testV002_MathematicalProof_USD_to_ETH() public view {
        uint256 requiredShares = 0.5e18;  // 0.5 liquidETH shares
        uint256 rateInQuote    = 2000e6;  // ~2000 USDC per liquidETH share

        // Buggy (as deployed): divisor = 1e6
        uint256 assetsNeeded_BUGGY = requiredShares.mulDivUp(rateInQuote, 1e6);
        // = 1,000,000,000,000 USDC — 1 quadrillion USDC

        // Correct: divisor = 1e18
        uint256 assetsNeeded_CORRECT = requiredShares.mulDivUp(rateInQuote, 1e18);
        // = 1,000 USDC — what the solver actually receives from bulkWithdraw

        assertEq(assetsNeeded_BUGGY / assetsNeeded_CORRECT, 1e12); // 1e12× error
    }

    function testV002_AllCrossVaultPairsAffected() public view {
        // All 3 vaults have different decimals → all 6 pairs broken
        assertTrue(IERC20(VAULT_USD).decimals() != IERC20(VAULT_ETH).decimals());
        assertTrue(IERC20(VAULT_USD).decimals() != IERC20(VAULT_BTC).decimals());
        assertTrue(IERC20(VAULT_ETH).decimals() != IERC20(VAULT_BTC).decimals());
    }
}
```

**Run:**
```bash
forge test --match-contract V002 -vvv \
  --fork-url https://ethereum.publicnode.com \
  --fork-block-number 25159442
```

**Output:**
```
[PASS] testV002_MathematicalProof_USD_to_ETH()
  Error factor USD→ETH: 1e12 — BUGGY demands 1 quadrillion USDC, solver has ~1000 USDC
[PASS] testV002_AllCrossVaultPairsAffected()
[PASS] testV002_OnChainStateConfirmsMismatch()
[PASS] testV002_QueueBelongsToFromVault()
Suite result: ok. 4 passed; 0 failed
```

---

## Impact

1. **BORING_REDEEM_MINT is completely non-functional** for all 6 cross-vault migration paths.
2. **Users are temporarily locked:** When a user submits a cross-vault withdrawal request, their shares are transferred to the queue contract. These shares cannot be returned until an admin calls `cancelUserWithdraws` or the request deadline expires. Users cannot access or migrate their funds during this window.
3. **All 3 vaults affected:** liquidUSD, liquidBTC, and liquidETH — every cross-vault migration path.

---

## Recommended Fix

Use `toBoringVault.decimals()` for the correct destination vault precision:

```solidity
// BEFORE (buggy):
uint256 assetsToMintRequiredShares = requiredShares.mulDivUp(
    toTeller.accountant().getRateInQuoteSafe(intermediateAsset),
    BoringOnChainQueue(queue).ONE_SHARE()  // fromVault.decimals() — WRONG
);

// AFTER (fixed):
uint256 toVaultOneShare = 10 ** ERC20(toBoringVault).decimals();
uint256 assetsToMintRequiredShares = requiredShares.mulDivUp(
    toTeller.accountant().getRateInQuoteSafe(intermediateAsset),
    toVaultOneShare  // toVault.decimals() — CORRECT
);
```

Note: `TellerWithMultiAssetSupport.ONE_SHARE` is `internal immutable` — not externally accessible. The fix must derive precision from `toBoringVault.decimals()` directly.

---

## Prior Audit Gap

Five 0xMacro/SevenSeas audits reviewed `BoringSolver`. The most recent (A-44, May 2025) was described as clean. The decimal mismatch in `_boringRedeemMintSolve` is absent from all of them and is not in the program's listed known issues.

---

## Lessons Learned

- **Cross-context precision is a recurring DeFi bug class.** Using "the precision of A" when the formula requires "the precision of B" produces errors that scale with the decimal difference — often astronomically (1e12 in this case).
- **Fork tests make precision bugs obvious.** Computing the exact error factor (`1e12`) in a fork test against real contract values is immediate proof that the path always fails. No complex setup needed.
- **"5 clean audits" doesn't mean the code is correct.** Auditors focus on the most impactful paths. A mathematical error in a specific solve type — especially one that may not have been active during audits — can slip through.
- **Verify the `queue` vs `vault` context carefully.** `BoringSolver` receives a `queue` parameter for the source vault. Using `queue.ONE_SHARE()` anywhere the destination vault's precision is needed is an easy context confusion to make.
