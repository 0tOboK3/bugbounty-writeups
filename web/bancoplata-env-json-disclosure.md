# W-008 — env.json Exposes API Key, Sentry DSN, and Internal Architecture (Banco Plata)

**Program:** Banco Plata (HackerOne — private)  
**Asset:** `empresa.bancoplata.mx`  
**Severity:** Medium — CVSS 4.0: `AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` = **6.9**  
**Testing date:** 2026-05-17, re-verified 2026-05-21

---

## TL;DR

The business portal serves its frontend configuration file at `/envs/env.json` publicly, with no authentication and `Access-Control-Allow-Origin: *`. The file contains a Google Maps API key with no restrictions (usable for billable API calls), an active Sentry DSN (write access confirmed), and the complete URL map of all internal backend API services for the SME product. The credentials persisted unchanged across two deployments four days apart.

---

## Discovery Process

### 1. Standard recon on frontend assets

When testing SPAs, a reliable early step is checking for externally-loaded configuration files. The application made a request to `/envs/env.json` during page load — visible in the browser Network tab. The file was served publicly with no authentication.

### 2. Content analysis

The file contained three classes of sensitive data:
- A Google Maps API key with no HTTP referrer restrictions or API restrictions
- A Sentry DSN with write access (confirmed by submitting a test event)
- A complete map of all internal backend service URLs

### 3. Verifying credential impact

For the Maps API key, I made requests to six different Google Cloud APIs (Geocoding, Directions, Distance Matrix, Places, Elevation, Static Maps) — all returned `status: OK` with no referrer headers. The key was unrestricted.

For the Sentry DSN, a POST to the DSN endpoint returned HTTP 200 with an event ID — write access to the production error monitoring project confirmed.

### 4. Persistence check

I re-verified four days later (2026-05-21). The app version hash had changed (`pyme-web-0f51c21c` → `pyme-web-2c75f3d7`), indicating an active deployment between checks. Neither the API key nor the DSN had been rotated.

---

## Vulnerability

```bash
curl -s "https://empresa.bancoplata.mx/envs/env.json"
```

Response (HTTP 200):
```json
{
  "version": "pyme-web-2c75f3d7",
  "env": "prod",
  "googleMaps": {
    "apiKey": "[REDACTED — unrestricted key]"
  },
  "sentry": {
    "dsn": "[REDACTED — production DSN]"
  },
  "apiUrls": {
    "pymePagoApiUrl": "https://prime.bancoplata.mx/pyme/pago/web/v1",
    "processorGatewayApiUrl": "https://prime.bancoplata.mx/processor-gateway/client/api/v1/processor-gateway",
    "pymeProductApiUrl": "https://prime.bancoplata.mx/pyme/web/gateway/v1",
    "pymeFacturaManagerApiUrl": "https://prime.bancoplata.mx/pyme/web/factura/v1",
    "pymeOriginationWebApiUrl": "https://prime.bancoplata.mx/pyme/origination/web/v1",
    "confirmationServiceApiBaseUrl": "https://prime.bancoplata.mx/confirmation/api/v1/confirmation-service",
    "originationDeligateApiUrl": "https://prime.bancoplata.mx/deligate"
  },
  "auth": {
    "authApiUrl": "https://prime.bancoplata.mx/auth/api/v1/auth-flow",
    "clientId": "SME"
  }
}
```

---

## Impact

**Google Maps API key (most concrete):**  
An unrestricted key can be used to make billable Google Cloud API calls — Geocoding, Directions, Distance Matrix, Places — generating charges on Banco Plata's account. All six APIs I tested returned `status: OK` with no referrer header.

**Sentry DSN (confirmed write access):**  
A POST to the DSN endpoint returned HTTP 200 with an event ID. An attacker can inject fake error events into production monitoring, potentially burying legitimate security alerts in noise. Self-hosted Sentry instances can also contain sensitive data in stack traces (session tokens, transaction IDs, PII).

**API architecture disclosure:**  
The complete service map of all backend APIs reduces reconnaissance effort for any subsequent attack on authenticated endpoints. Payment gateway, processor gateway, origination service, auth flow — all documented for free.

**Persistence:**  
The file is served separately from the JavaScript bundle (separate HTTP request), meaning a new deployment doesn't automatically rotate the credentials. This was confirmed by observing the version hash change while credentials remained unchanged across two deployments.

---

## Remediation

1. **Google Maps key:** Rotate immediately. New key should have HTTP referrer restrictions (`*.empresa.bancoplata.mx`) and be limited to only the APIs the frontend actually uses (Maps JavaScript API only).
2. **Sentry DSN:** Rotate. Serve as a build-time bundle variable (injected into JS at compile time, not a separately-fetchable file), or implement referrer-based ingestion filtering.
3. **env.json:** Either bake configuration into the JavaScript bundle at build time (no separate network-fetchable file), or require authentication before serving any path under `empresa.bancoplata.mx`.

---

## Lessons Learned

- **SPAs often load a separate config file at startup.** Always watch the Network tab during initial page load — `env.json`, `config.json`, `settings.json`, `app.config.js` are common paths worth checking.
- **Credentials that survive a deployment are higher severity.** A key exposed in a single bundle version might have been rotated. One that persists across multiple deployments indicates a structural issue, not a one-time mistake.
- **Sentry DSNs are often undervalued.** They grant write access to production monitoring. In self-hosted or team-plan Sentry instances, event flooding can bury real security alerts — which makes this useful to an attacker even without read access.
- **`Access-Control-Allow-Origin: *` on a config file is a red flag.** It means the file was designed to be fetched cross-origin — usually for CDN delivery. It also means any web page can silently exfiltrate the credentials via fetch().
