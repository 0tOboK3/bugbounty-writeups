# W-010 — Private Key for Fee Delegation Exposed in Production JS Bundle (SuperEarn)

**Program:** SuperEarn Web & Smart Contracts (HackenProof)  
**Asset:** `superearn.io` (Web High)  
**Severity:** High  
**Testing date:** 2026-05-28

---

## TL;DR

The production Vite/Rollup JavaScript bundle at `superearn.io` contains the private key of the `FEE_DELESENDER` address — the account that signs fee delegation transactions on Kaia blockchain. Any user who loads the page can extract this key from the publicly-served bundle. Additional credentials exposed in the same file: a production Sentry DSN and a Formo analytics write-key JWT (without expiry).

---

## Discovery Process

### 1. Inspecting the bundle

SPAs built with Vite/Rollup often consolidate configuration into a named bundle chunk. The naming pattern `app-config.constant-*.js` suggested a configuration constant file. Fetching it revealed multiple secrets hardcoded as JavaScript constants.

### 2. Identifying the private key

The file exported a constant named `FEE_DELESENDER` containing a hex string matching the length and format of an Ethereum/EVM private key (64 hex characters). Cross-referencing the associated address against the Kaia blockchain confirmed it was a real key for an account used in SuperEarn's fee delegation system.

### 3. Understanding the impact

SuperEarn uses Kaia's fee delegation feature (`TxTypeFeeDelegatedSmartContractExecution`) to pay gas fees on behalf of users. The `FEE_DELESENDER` signs these transactions. An attacker with this private key could potentially:
- Sign fee-delegated transactions targeting arbitrary contracts
- Abuse the fee delegation pool (confirmed balance: ~999 KLAY on the fee payer contract) if the fee delegation server doesn't restrict destination contracts

### 4. Additional credentials in the same file

| Secret | Type | Impact |
|--------|------|--------|
| `FEE_DELESENDER` private key | Kaia fee delegation signing key | Sign arbitrary fee-delegated txs |
| Sentry DSN (production) | Write-only event ingestion | Inject fake errors into production monitoring |
| Formo Write Key JWT (no `exp`) | Analytics write key, never-expiring | Write arbitrary analytics events |
| Privy App ID | Semi-public by design | Low |
| WalletConnect Project ID | Semi-public by design | Low |

---

## Vulnerability

```bash
# The bundle is publicly served — no auth required
curl -sk "https://superearn.io/assets/app-config.constant-[HASH].js" \
  | grep -o "FEE_DELESENDER[^,]*"
# Output: FEE_DELESENDER:{PRIVATE_KEY:"[64-char hex key]", ADDRESS:"0x82428F8B1B5F32c50B339F18E36dB2eC76634582"}
```

The key is hardcoded as a JavaScript constant in the production bundle, served to every visitor.

The associated fee payer contract (`0x22a4ebd6c88882f7c5907ec5a2ee269fecb5ed7a`) held ~999 KLAY in fee delegation balance at time of discovery. The account controlled by this key (`0x82428F8B1B5F32c50B339F18E36dB2eC76634582`) had 0 KLAY directly — but the key's value is in its signing authority, not its balance.

---

## Impact

1. **Fee delegation abuse:** An attacker with the private key can create `TxTypeFeeDelegatedSmartContractExecution` transactions signed by `0x82428F8B1B5F32c50B339F18E36dB2eC76634582` and submit them to SuperEarn's fee delegation server. If the server doesn't restrict destination contracts, this can drain the ~999 KLAY fee delegation pool.

2. **CDN persistence:** Vite bundles use content-addressable hashes for cache-busting. The compromised bundle remains cached at all CDN edges until the file is updated and re-deployed. Rotating the key requires a new deploy to invalidate cached copies.

3. **Sentry write access:** Production monitoring can be flooded with fake errors, potentially burying legitimate security incidents.

---

## Remediation

1. **Rotate immediately:** Generate a new keypair for `FEE_DELESENDER` and update it server-side. Invalidate the existing key at the fee delegation server level.
2. **Move signing to the backend:** The private key for fee delegation must never appear in client-side code. The transaction signing should happen in a backend service via a secure API, never exposed to the browser.
3. **Invalidate the bundle:** Force a new hash for the affected bundle file so CDN-cached copies of the compromised version stop being served.
4. **Audit the fee delegation server:** Verify that the server restricts which contracts and functions can be called with fee-delegated transactions signed by this key.

---

## Lessons Learned

- **Vite/Rollup bundle inspection is a standard recon step for SPAs.** Named chunk files (`app-config.constant-*.js`, `app-settings-*.js`) often consolidate environment configuration. Always check them.
- **Fee delegation signing keys are equivalent to hot wallet private keys.** They control signing authority over blockchain transactions, not just read access. Treat them with the same sensitivity as private keys.
- **Content-hash naming (cache-busting) creates a window of exposure.** Once a secret is committed to a bundle and deployed, CDN copies persist until the bundle is re-deployed with a new hash. "Rotate the key" is necessary but not sufficient — the old bundle keeps serving the old key until cache expiry or forced invalidation.
- **Multiple secrets in one file multiply the impact.** Finding one secret in a config file is reason to read the entire file carefully.
