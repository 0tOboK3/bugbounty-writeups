# Disclosure gate

This public repository contains only research that passes an explicit
publication gate. It is not a mirror of private bounty-platform submissions.

## Required before publication

At least one of the following must be retained in the private ledger:

- the platform marks the specific report as publicly disclosed;
- the program or affected organization gives written permission to publish;
- the program policy explicitly permits researcher disclosure under conditions
  that have been satisfied; or
- an official public advisory includes the relevant technical details and no
  program restriction still prohibits the researcher's writeup.

`Submitted`, `New`, `Triaged`, `Resolved`, rewarded, duplicate, informative,
not applicable, fixed, or a reasonable remediation interval are not disclosure
authorization.

## Content review

Before a writeup is committed:

1. Record the disclosure authority, date, URL or private authorization
   reference.
2. Remove bearer tokens, cookies, credentials, private API keys and raw session
   material.
3. Exclude real-user data, customer records and internal-only assets.
4. Use controlled synthetic identifiers and evidence.
5. Check screenshots, archives and Git history for metadata or deleted secrets.
6. Separate demonstrated impact from speculation and current behavior from the
   historical vulnerable state.

Public source code alone does not authorize publication of a private report,
platform conversation, triage rationale, attachment, or undisclosed fix.

## Holding states

| State | Public action |
|---|---|
| Explicitly authorized/disclosed | Sanitize, review, then publish |
| Explicitly prohibited | Keep private |
| Active or embargoed | Keep private |
| Policy unknown | Keep private until confirmed |
| Authorization revoked or disputed | Remove public detail pending review |
