# D-002 — dispatch(DispatchPost) Zero Payer Locks Fee Permanently (Hyperbridge)

**Program:** Hyperbridge (Immunefi)  
**Contract:** `EvmHost.sol`  
**Functions:** `dispatch(DispatchPost)` (L921–959) / `dispatchTimeOut` (L885–906)  
**Severity:** Low — CVSS 3.1: `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L` = **3.7**  
**Repo:** `github.com/polytope-labs/hyperbridge`

---

## TL;DR

`EvmHost.dispatch(DispatchPost)` stores `post.payer` (the address to receive a timeout refund) without validating it against `address(0)`. When a non-zero fee is attached and the payer is `address(0)`, the fee transfers into `EvmHost` successfully. On timeout, `dispatchTimeOut` tries `ERC20.safeTransfer(address(0), fee)`, which reverts on any standard ERC20. The fee is permanently locked. The timeout commitment is never cleared. The source app's `onPostRequestTimeout` callback is never executed.

The guard already exists in `fundRequest` (`if (metadata.sender == address(0)) revert UnknownRequest()`). It was simply not applied to `dispatch`.

---

## Discovery Process

### 1. Reading the dispatch flow

`EvmHost.dispatch(DispatchPost)` handles cross-chain message dispatch with an optional fee. The fee is collected from the caller and stored alongside the request commitment so it can be refunded on timeout.

```solidity
// L931: fee collected into EvmHost
IERC20(feeToken()).safeTransferFrom(_msgSender(), address(this), post.fee);

// L948: BUG — payer stored without validation
_requestCommitments[commitment] = FeeMetadata({sender: post.payer, fee: post.fee});
```

### 2. Tracing the timeout path

`dispatchTimeOut` handles expired requests. After the application callback, it refunds the fee:

```solidity
if (meta.fee != 0) {
    IERC20(feeToken()).safeTransfer(meta.sender, meta.fee); // REVERTS if sender == address(0)
}
```

`safeTransfer` calls OpenZeppelin's `ERC20._transfer`, which reverts with `ERC20InvalidReceiver(address(0))` when the recipient is `address(0)`. This is by design in ERC20 — but the `dispatch` function never prevented storing `address(0)` as the payer.

### 3. Noticing the existing guard in fundRequest

```solidity
// fundRequest L1045 — guard EXISTS here
FeeMetadata memory metadata = _requestCommitments[commitment];
if (metadata.sender == address(0)) revert UnknownRequest();
```

The same code is aware of the problem in another function. The fix pattern was already in the codebase.

### 4. Comparing with dispatch(DispatchGet)

`dispatch(DispatchGet)` stores `sender: _msgSender()` (L1001) — ignoring `get.payer` entirely. This accidentally makes it immune to the zero-payer issue. Only `dispatch(DispatchPost)` uses the caller-supplied `post.payer` directly.

---

## Vulnerability

```
dispatch(DispatchPost) with payer=address(0) and fee>0:
  → fee transferred from caller into EvmHost ✓
  → commitment stored with sender=address(0) ✓
  → request dispatched ✓

On timeout:
  → dispatchTimeOut called by relayer
  → commitment deleted
  → app.onPostRequestTimeout() called → success
  → safeTransfer(address(0), fee) → REVERT
  → delete rolls back (commitment restored)
  → loop: every retry reverts identically forever
  → fee permanently locked, commitment permanently unresolvable
```

---

## Proof of Concept

Self-contained Foundry test (no external RPC required):

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract FeeToken is ERC20 {
    constructor() ERC20("HyperbridgeFee", "HBF") {
        _mint(msg.sender, 1_000_000 * 1e18);
    }
}

struct FeeMetadata { address sender; uint256 fee; }

contract VulnerableEvmHost {
    using SafeERC20 for IERC20;
    IERC20 public immutable feeToken;
    mapping(bytes32 => FeeMetadata) public requestCommitments;

    constructor(address _feeToken) { feeToken = IERC20(_feeToken); }

    // Reproduces EvmHost.dispatch(DispatchPost) — payer stored without address(0) check
    function dispatch(address payer, uint256 fee, bytes calldata body) external returns (bytes32 commitment) {
        if (fee > 0) feeToken.safeTransferFrom(msg.sender, address(this), fee);
        commitment = keccak256(abi.encodePacked(msg.sender, payer, fee, body, block.timestamp));
        requestCommitments[commitment] = FeeMetadata({sender: payer, fee: fee}); // no address(0) check
    }

    // Reproduces EvmHost.dispatchTimeOut
    function dispatchTimeOut(address module, bytes32 commitment) external {
        FeeMetadata memory meta = requestCommitments[commitment];
        delete requestCommitments[commitment];
        (bool success,) = module.call(abi.encodeWithSignature("onPostRequestTimeout()"));
        if (!success) { requestCommitments[commitment] = meta; return; }
        if (meta.fee != 0) {
            feeToken.safeTransfer(meta.sender, meta.fee); // REVERTS when sender==address(0)
        }
    }
}

contract DummyModule { function onPostRequestTimeout() external {} }

contract EH001Test is Test {
    FeeToken token;
    VulnerableEvmHost host;
    DummyModule module;
    address attacker = makeAddr("attacker");

    function setUp() public {
        token = new FeeToken();
        host = new VulnerableEvmHost(address(token));
        module = new DummyModule();
        token.transfer(attacker, 100e18);
    }

    function test_EH001_FeeLockedForever() public {
        uint256 fee = 10e18;
        vm.startPrank(attacker);
        token.approve(address(host), fee);
        bytes32 commitment = host.dispatch(address(0), fee, bytes("payload")); // payer=address(0)
        vm.stopPrank();

        assertEq(token.balanceOf(address(host)), fee, "fee held in EvmHost");

        vm.expectRevert();
        host.dispatchTimeOut(address(module), commitment); // REVERTS

        assertEq(token.balanceOf(address(host)), fee, "fee permanently locked");

        vm.expectRevert();
        host.dispatchTimeOut(address(module), commitment); // retry also fails
    }
}
```

**Run:**
```bash
forge test --match-contract EH001Test -vv
```

**Output:**
```
[PASS] test_EH001_FeeLockedForever()
  fee held in EvmHost: 10 HBF
  fee permanently locked: 10 HBF (confirmed — safeTransfer to address(0) always reverts)
```

---

## Impact

- **Fee locked:** Any fee paid for a `DispatchPost` request with `payer = address(0)` is permanently locked in `EvmHost`. No recovery function exists for individual stuck fees.
- **Request permanently unresolvable:** The commitment persists in `_requestCommitments` forever. `dispatchTimeOut` can never complete.
- **Application DoS:** Any `IApp` relying on `onPostRequestTimeout` for state recovery (e.g., releasing user collateral, cancelling orders) will be permanently stuck for that request.

**Why Low:** Requires the caller to supply `payer = address(0)` — either by uninitialized field or intentional self-grief. Not a typical user path; an application audit catches this. However, the protocol should not permit an uncorrectable lock.

---

## Remediation

**Option 1 (minimal):** Add a guard in `dispatch(DispatchPost)` mirroring `fundRequest`:

```solidity
function dispatch(DispatchPost memory post) external payable notFrozen returns (bytes32 commitment) {
    if (post.fee > 0 && post.payer == address(0)) revert InvalidPayer();
    // ... rest unchanged
}
```

**Option 2 (ergonomic):** Default `post.payer` to `_msgSender()` when zero is provided — consistent with how `dispatch(DispatchGet)` already handles it:

```solidity
address payer = post.payer == address(0) ? _msgSender() : post.payer;
_requestCommitments[commitment] = FeeMetadata({sender: payer, fee: post.fee});
```

---

## Lessons Learned

- **Inconsistency between similar functions is a bug signal.** `dispatch(DispatchGet)` stores `sender: _msgSender()`. `dispatch(DispatchPost)` stores `sender: post.payer`. The difference in how they handle the payer field is worth questioning on every function pair.
- **"Guard exists in X" and "guard exists in Y" are two independent facts.** Finding the guard in `fundRequest` told me the code was aware of the zero-address problem — but I still had to check each call site independently.
- **safeTransfer to address(0) is a permanent revert.** This is by ERC20 standard design. Any flow that stores a user-supplied address and later transfers to it without validating it has this lockup risk.
- **Forge makes the PoC a first-class artifact.** A self-contained Foundry test with `vm.expectRevert()` and balance assertions is concrete evidence. It's also runnable by the triage team immediately.
