# D-005 — Premature Proxy Cleanup in sweepRedemptions Permanently Locks User USDC (NUVA)

**Program:** NUVA Protocol (Immunefi)  
**Contract:** `DedicatedVaultRouter` — `sweepRedemptions()`  
**Severity:** High (Permanent freezing of unclaimed principal — smart contracts)  
**Audit coverage:** Zero — contract added Feb 2026, after both Sherlock (Dec 2025) and Halborn (Dec 2025) audits

---

## TL;DR

`DedicatedVaultRouter.sweepRedemptions()` deletes the proxy-to-user mapping whenever a proxy's USDC balance is 0 — but a proxy's USDC balance is 0 immediately after `requestRedeem()` because the USDC delivery is async (happening hours or days later). A keeper calling with `amount=0` to skip a pending proxy triggers the cleanup anyway, permanently deleting the mapping. When USDC later arrives at the orphaned proxy, there is no recovery path — the user's USDC is locked forever.

---

## Vulnerability

### The Async Redemption Architecture

NUVA's redemption is two-phase:
1. User calls `requestRedeem()` → proxy deployed, shares unwound, `assetVault.requestRedeem()` submitted. **Proxy USDC balance = 0** at this point.
2. Hours or days later: Hastra assetVault delivers USDC to the proxy.
3. KEEPER calls `sweepRedemptions([proxy], [amount])` to forward USDC to the user.

### The Bug

```solidity
function sweepRedemptions(
    address[] calldata _proxyAddresses,
    uint256[] calldata _amounts
) external nonReentrant onlyRole(KEEPER_ROLE) {
    for (uint256 i = 0; i < length; ++i) {
        address proxyAddress = _proxyAddresses[i];
        uint256 amountToSweep = _amounts[i];
        address user = redemptionProxyToUser[proxyAddress];

        if (user != address(0) && amountToSweep > 0) {
            // Only sweeps when amount > 0
            totalSwept += IRedemptionProxy(proxyAddress).sweep(amountToSweep);
        }

        // BUG: fires for ANY proxy with 0 USDC, including those awaiting delivery
        if (IERC20(asset).balanceOf(proxyAddress) == 0) {
            delete redemptionProxyToUser[proxyAddress];       // permanent deletion
            delete redemptionProxyToTimestamp[proxyAddress];
            INuvaVault(address(nuvaVault)).removeAuthorizedCaller(proxyAddress);
        }
    }
}
```

The cleanup condition `balanceOf(proxy) == 0` cannot distinguish:

| Scenario | USDC balance | Should cleanup? |
|----------|-------------|-----------------|
| Proxy fully swept to user | 0 | YES |
| Proxy awaiting async USDC | 0 | **NO — but cleanup fires** |

### Why There Is No Recovery

After `delete redemptionProxyToUser[proxy]`:
- `sweepUserRedemption(proxy)` → checks `redemptionProxyToUser[proxy] == msg.sender` → reverts `Unauthorized` (value is now `address(0)`)
- `sweepRedemptions([proxy], [amount])` → reads `user = address(0)` → `if (user != 0 && amount > 0)` is FALSE → no sweep
- `proxy.sweep()` is `onlyRouter` with no external callable path for unregistered proxies

---

## Trigger Scenario

A well-intentioned but naive keeper bot (common in production) can trigger this:

```
T=0:  User calls requestRedeem(100 shares)
      → proxy P1 created, async USDC pending
      → P1.balanceOf(USDC) = 0
      → redemptionProxyToUser[P1] = user

T=1h: Keeper runs routine sweep pass
      For proxies with no USDC, passes amount=0 to "skip" them

      keeper.sweepRedemptions([P1, P2, P3], [0, 500e6, 0])

      P1: amount=0 → skip sweep; balanceOf(P1)=0 → CLEANUP FIRES!
          redemptionProxyToUser[P1] = deleted  ← BUG
      P2: amount=500e6 → sweep 500 USDC; balanceOf(P2)=0 → cleanup (correct)

T=24h: assetVault fulfills → sends 1,000 USDC to P1
       But redemptionProxyToUser[P1] = address(0) — mapping was deleted

T=25h: User calls sweepUserRedemption(P1) → REVERT: Unauthorized
       Keeper calls sweepRedemptions([P1], [1000e6]) → user=0 → no sweep
       → 1,000 USDC permanently locked in P1
```

---

## Proof of Concept

```solidity
function test_PrematureCleanup_LocksUserFunds() public {
    // Proxy registered, USDC not yet arrived
    assertEq(router.redemptionProxyToUser(address(proxy)), user);
    assertEq(usdc.balanceOf(address(proxy)), 0);

    // Keeper passes amount=0 to skip this proxy
    address[] memory proxies = new address[](1);
    proxies[0] = address(proxy);
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 0;

    vm.prank(keeper);
    router.sweepRedemptions(proxies, amounts);

    // Mapping was deleted prematurely
    assertEq(router.redemptionProxyToUser(address(proxy)), address(0));

    // Async USDC arrives
    usdc.mint(address(proxy), 1_000e6);

    // No recovery possible
    vm.prank(user);
    vm.expectRevert("Unauthorized");
    router.sweepUserRedemption(address(proxy));

    assertEq(usdc.balanceOf(address(proxy)), 1_000e6); // permanently stuck
    assertEq(usdc.balanceOf(user), 0);
}
```

All 3 tests pass: bug confirmed, normal flow works, fix prevents the issue.

---

## Impact

- **Permanent fund loss:** USDC arriving at an orphaned proxy is inaccessible to the user, the keeper, and the protocol admin. No emergency withdrawal function exists.
- **Trigger ease:** A standard keeper pattern (iterate all proxies, pass 0 for pending ones) is enough to trigger this on every pending redemption.
- **Scale:** The Hastra PRIME vault holds ~99,021 PRIME tokens backing the NuvaVault. Every user with a pending redemption is at risk during the window between `requestRedeem()` and USDC arrival.

---

## Recommended Fix

Only cleanup when a sweep was actually performed AND the balance is now 0:

```solidity
// FIXED:
if (amountToSweep > 0 && IERC20(asset).balanceOf(proxyAddress) == 0) {
    delete redemptionProxyToUser[proxyAddress];
    delete redemptionProxyToTimestamp[proxyAddress];
    INuvaVault(address(nuvaVault)).removeAuthorizedCaller(proxyAddress);
}
```

This ensures cleanup only happens after confirmed USDC delivery.

---

## Lessons Learned

- **"Balance == 0" is not a reliable state discriminator in async systems.** Zero balance means "nothing yet" as much as it means "fully swept." The cleanup condition must use explicit state tracking, not inferred state from balance.
- **Keeper bots follow the path of least resistance.** Passing `amount=0` for proxies without USDC is the natural "skip" pattern for a keeper. If that pattern can trigger irreversible side effects, the contract is broken.
- **Zero-audit-coverage code is the highest-value surface.** Both Sherlock and Halborn audited NUVA — but this specific contract was added two months later. Anything added after a formal audit has had no formal review.
- **The fix is a one-condition change.** The existing `amountToSweep > 0` check for the sweep itself was already present. Adding it to the cleanup guard is the minimal correct fix. Simple bugs can have large impacts.
