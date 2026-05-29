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
| W-006 | Aikido | [SSRF via openapi_spec_url + Webhook: Confirmed ECS Metadata Access](web/aikido-ssrf-two-vectors.md) | High 7.7 | Intigriti | Submitted |
| W-007 | AMLBot | [SSRF via Webhook URL: Confirmed OOB + Cloud Metadata Reach](web/amlbot-ssrf-webhook.md) | High 8.5 | HackenProof | Submitted |
| W-008 | Banco Plata | [env.json Exposes API Key, Sentry DSN, and Internal Architecture](web/bancoplata-env-json-disclosure.md) | Medium 6.9 | HackerOne | Submitted |
| W-009 | OTTO Jobs | [ATO via Unauthenticated Credential Binding to Existing ConsumerId](web/otto-jobs-ato-credential-binding.md) | High 7.4 | HackerOne | Submitted |
| W-010 | SuperEarn | [Private Key for Fee Delegation Exposed in Production JS Bundle](web/superearn-private-key-in-bundle.md) | High | HackenProof | Submitted |
| W-011 | SuperEarn | [Unauthenticated GraphQL Exposes Full Financial History of Any User](web/superearn-graphql-unauth-portfolio.md) | Medium 7.5 | HackenProof | Submitted |
| W-012 | Backpack | [Unauthenticated Risk Model Endpoints Expose IMF/MMF Coefficients](web/backpack-risk-model-unauth.md) | Low 5.3 | HackenProof | Submitted |

## Smart Contract / DeFi

| # | Target | Vulnerability | Severity | Platform | Status |
|---|--------|--------------|----------|----------|--------|
| D-001 | Ether.fi | [AccountRecovered Event Always Emits address(0)](defi/etherfi-accountrecovered-zero-address.md) | Low | Immunefi | Submitted |
| D-002 | Hyperbridge | [dispatch(DispatchPost) Zero Payer Locks Fee Permanently](defi/hyperbridge-fee-locked-zero-payer.md) | Low | Immunefi | Submitted |
| D-003 | Enzyme Finance | [Division by Zero Bricks Smart Account When lossTolerancePeriodDuration=0](defi/enzyme-division-by-zero-loss-tolerance.md) | Low | Immunefi | Submitted |
| D-004 | Ember Finance | [Permanent Withdrawal Queue Freeze via Off-By-One IndexOutOfBounds](defi/ember-permanent-queue-freeze.md) | Critical | Immunefi | Submitted |
| D-005 | NUVA Protocol | [Premature Proxy Cleanup in sweepRedemptions Permanently Locks USDC](defi/nuva-sweep-redemptions-premature-cleanup.md) | High | Immunefi | Submitted |
| D-006 | Pinto (Beanstalk fork) | [combinePlots() Fails to Cancel Pod Listing on plotIndexes[0]](defi/pinto-combine-plots-uncancelled-listing.md) | Medium | Immunefi | Submitted |
| D-007 | Veda Protocol | [BORING_REDEEM_MINT Always Reverts: Wrong Decimal Divisor](defi/veda-boring-redeem-mint-decimal-mismatch.md) | High | Immunefi | Submitted |
| D-008 | Wildcat Finance | [Arithmetic Underflow DoS in repayAndProcessUnpaidWithdrawalBatches](defi/wildcat-repay-underflow-dos.md) | Low | Immunefi | Submitted |

---

## About

- **Focus:** Business logic bugs, access control, SSRF, smart contract event correctness
- **Approach:** Manual testing on researcher-owned accounts; conservative severity; PoC before report
- **Platforms:** HackerOne · YesWeHack · HackenProof · Immunefi

Feedback and corrections welcome via Issues.
