# W-012 — Unauthenticated Risk Model Endpoint Exposes Proprietary IMF/MMF Coefficients (Backpack Exchange)

**Program:** Backpack Exchange (HackenProof)  
**Asset:** `api.backpack.exchange`  
**Severity:** Low — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = **5.3**  
**CWE:** CWE-862 (Missing Authorization)  
**Testing date:** 2026-05-22

---

## TL;DR

Eight endpoints under `/wapi/v1/riskDashboard/` return live risk model data without authentication. Every other endpoint in the `/wapi/v1/` namespace requires authentication. The exposed data includes exact interest rate model coefficients, throttle factors, and non-linear IMF/MMF curves — proprietary parameters not available in Backpack's public API.

---

## Discovery Process

### 1. Mapping the /wapi/v1/ namespace

While exploring the Backpack API, I noticed two distinct namespaces: `/api/v1/` (public) and `/wapi/v1/` (requires auth). All `/wapi/v1/` endpoints I tested returned HTTP 401 without credentials — except the `riskDashboard/` sub-path.

### 2. Testing riskDashboard endpoints

All eight endpoints under `/wapi/v1/riskDashboard/` returned HTTP 200 with live data, no credentials required:

```bash
# IMF model for SOL borrow — no auth header
curl -s -X POST "https://api.backpack.exchange/wapi/v1/riskDashboard/borrowImfModel" \
  -H "Content-Type: application/json" \
  -d '{"symbol":"SOL","xAxis":["1000"]}'
# Response: ["0.125"]   HTTP 200

# Collateral weight for SOL
curl -s -X POST "https://api.backpack.exchange/wapi/v1/riskDashboard/collateralModel" \
  -H "Content-Type: application/json" \
  -d '{"symbol":"SOL","xAxis":["1000"]}'
# Response: ["0.95"]   HTTP 200

# Interest rate model (NOT in public API)
curl -s -X POST "https://api.backpack.exchange/wapi/v1/riskDashboard/lendInterestRateModel" \
  -H "Content-Type: application/json" \
  -d '{"symbol":"SOL","xAxis":["1000"]}'
# Response: ["4247059"]   HTTP 200
```

### 3. Discovering the non-linear curve

Passing a range of xAxis values revealed the exact breakpoint where IMF increases:

```bash
curl -s -X POST ".../borrowImfModel" \
  -H "Content-Type: application/json" \
  -d '{"symbol":"SOL","xAxis":["100","1000","10000","100000","1000000"]}'
# Response: ["0.125","0.125","0.125","0.125","0.24"]
# SOL borrow IMF jumps from 12.5% to 24% above a specific size threshold
```

This breakpoint is not in the public `/api/v1/collateral` endpoint.

### 4. Comparing with authenticated endpoints**

```bash
curl -s "https://api.backpack.exchange/wapi/v1/user"
# Response: {"code":"UNAUTHORIZED","message":"Unauthorized"}   HTTP 401

curl -s "https://api.backpack.exchange/wapi/v1/capital/deposits"
# Response: HTTP 401
```

All other `/wapi/v1/` endpoints enforce auth. The `riskDashboard/` endpoints do not.

---

## Affected Endpoints

| Endpoint | Data | Auth Required? |
|----------|------|----------------|
| `/wapi/v1/riskDashboard/borrowImfModel` | Borrow Initial Margin Factor | **No** |
| `/wapi/v1/riskDashboard/borrowMmfModel` | Borrow Maintenance Margin Factor | **No** |
| `/wapi/v1/riskDashboard/positionImfModel` | Position IMF (perp futures) | **No** |
| `/wapi/v1/riskDashboard/positionMmfModel` | Position MMF (perp futures) | **No** |
| `/wapi/v1/riskDashboard/lendInterestRateModel` | Lending interest rate coefficients | **No** |
| `/wapi/v1/riskDashboard/borrowInterestRateModel` | Borrowing interest rate coefficients | **No** |
| `/wapi/v1/riskDashboard/borrowLendThrottleModel` | Borrow/lend throttle factor | **No** |
| `/wapi/v1/riskDashboard/collateralModel` | Asset collateral weight | **No** |

**Complete risk model mapping (no auth):**

| Asset | Collateral Weight | Borrow IMF |
|-------|-------------------|-----------|
| USDC | 1.00 | 1% |
| SOL, ETH, BTC, USDT | 0.95 | 12.5% |
| BNB | 0.70 | 20% |
| SUI, XRP, DOGE | 0.75–0.80 | 30% |
| LINK | No collateral metadata (not supported as collateral) |

---

## Impact

Note: Backpack's public `/api/v1/collateral` already exposes base IMF, MMF, and collateral weights. The `riskDashboard/` endpoints expose additional data not available publicly:

1. **Interest rate model coefficients** (`lendInterestRateModel`, `borrowInterestRateModel`) — not in the public API. These coefficients price lending/borrowing rates.
2. **Throttle factor** (`borrowLendThrottleModel`) — proprietary operational parameter.
3. **Non-linear IMF curve outputs** — while base IMF is public, the exact breakpoints (where IMF increases at large position sizes) let sophisticated traders construct positions precisely at margin thresholds.
4. **An error message oracle** — querying an unsupported asset (e.g., LINK for collateral) returns `"Asset without collateral metadata"`, revealing which assets are not supported as collateral — internal configuration not documented publicly.

---

## Remediation

Apply the same authentication middleware to all `/wapi/v1/riskDashboard/*` endpoints. If this data is intentionally public (for transparency), move it to the `/api/v1/` namespace and document it explicitly.

---

## Lessons Learned

- **Auth middleware must be applied at the endpoint level, not just the namespace level.** Registering routes under `/wapi/v1/` doesn't automatically inherit auth middleware — each route or route group must explicitly apply it.
- **Consistency within a namespace is a useful signal.** When every other endpoint in a namespace requires auth and one doesn't, the gap is almost always a mistake, not a design decision.
- **Proprietary model data has economic value.** Risk model parameters, liquidation breakpoints, and interest rate coefficients can inform trading strategies. Even if not immediately exploitable, their exposure is a business risk.
- **Range inputs reveal curve shapes.** Passing `xAxis: ["100","1000","10000","100000","1000000"]` to a model endpoint returns the full non-linear curve — more information than the public API exposes.
