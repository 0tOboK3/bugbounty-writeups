# Bug Bounty Writeups — otoboke

Public writeups of my bug bounty work across web application security and smart contract auditing.

Each writeup covers methodology, payloads, severity reasoning, and lessons learned.
Some of these were rewarded; others were valid findings that arrived as duplicates — both are equally worth documenting.

> **Note:** All writeups are published after the programs have had reasonable time to remediate. No real user data, credentials, or internal assets are included. Account references use researcher-controlled test accounts only.

---

## Web Application Security

| # | Target | Vulnerability | Severity | Platform | Status |
|---|--------|--------------|----------|----------|--------|
| W-001 | Paddle | [SSRF Filter Incomplete Fix — IPv4-Mapped IPv6 Bypass](web/paddle-ssrf-ipv6-bypass.md) | Medium 5.3 | YesWeHack | Submitted |
| W-002 | BookBeat | [HLS Token Wildcard ACL Exposes Audiobook Opening](web/bookbeat-hls-acl-wildcard.md) | Medium 5.3 | YesWeHack | Submitted |
| W-003 | Tickets.ua | [IDOR — Delete Any User's Saved Passenger Profile](web/tickets-ua-idor-passenger.md) | High 7.1 | HackenProof | Submitted |
| W-004 | Toom | [Unauthenticated Cart Read/Write via quoteMaskedId](web/toom-unauth-cart.md) | Medium 6.0 | YesWeHack | Submitted |
| W-005 | Parity/Polkadot | [CI/CD RCE on Self-Hosted Runner via /cmd bench](web/parity-cicd-runner-rce.md) | High 8.2 | HackenProof | Submitted |

## Smart Contract / DeFi

| # | Target | Vulnerability | Severity | Platform | Status |
|---|--------|--------------|----------|----------|--------|
| D-001 | Ether.fi | [AccountRecovered Event Always Emits address(0)](defi/etherfi-accountrecovered-zero-address.md) | Low | Immunefi | Submitted |
| D-002 | Hyperbridge | [dispatch(DispatchPost) Zero Payer Locks Fee Permanently](defi/hyperbridge-fee-locked-zero-payer.md) | Low | Immunefi | Submitted |

---

## About

- **Focus:** Business logic bugs, access control, SSRF, smart contract event correctness
- **Approach:** Manual testing on researcher-owned accounts; conservative severity; PoC before report
- **Platforms:** HackerOne · YesWeHack · HackenProof · Immunefi

Feedback and corrections welcome via Issues.
