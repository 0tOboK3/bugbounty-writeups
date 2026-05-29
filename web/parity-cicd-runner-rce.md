# W-005 — CI/CD RCE on Self-Hosted Runner via /cmd bench (Parity/Polkadot)

**Program:** Parity Polkadot Release Infrastructure (HackenProof)  
**Asset:** `github.com/paritytech/polkadot-sdk` — GitHub Actions workflows  
**Severity:** High — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H` = **8.2**  
**CWE:** CWE-862 (Missing Authorization) / CWE-77 (Command Injection)  
**Analysis date:** 2026-05-24

---

## TL;DR

The `cmd.yml` GitHub Actions workflow in `paritytech/polkadot-sdk` responds to any comment matching `/cmd` — including on pull requests from external contributors. It dispatches `cmd-run.yml` to a self-hosted runner (`parity-weights`) for the `bench` command. The critical flaw: the membership check job (`is-org-member`) exists and runs, but its output is **never used as a gate** in the `if:` condition for the job that triggers the dispatch. Any external GitHub user can open a PR with malicious code in `substrate/utils/frame/omni-bencher/src/main.rs`, post `/cmd bench`, and have that code compiled and executed on Parity's self-hosted infrastructure.

---

## Discovery Process

### 1. Identifying the attack surface

CI/CD workflows triggered by `issue_comment` events on pull requests are a known high-value target. The `pull_request_target` context and `workflow_dispatch` with attacker-controlled inputs are common escalation paths.

I searched the repo for workflows using `issue_comment` as a trigger:

```bash
grep -r "issue_comment" .github/workflows/
# → cmd.yml: on: issue_comment
```

### 2. Tracing the authorization flow

`cmd.yml` had four jobs:
1. `get-pr-info` — extracts the command from the comment
2. `set-image` — determines runner and Docker image based on the command
3. `is-org-member` — checks if the commenter is a Parity org member
4. `run-cmd-workflow` — dispatches `cmd-run.yml`

I read the `if:` condition on `run-cmd-workflow`:

```yaml
run-cmd-workflow:
  needs: [set-image, get-pr-info, is-org-member, check-pr-author]
  if: ${{ startsWith(github.event.comment.body, '/cmd') && !contains(github.event.comment.body, '--help') }}
```

The `is-org-member` job is listed in `needs:` — it must complete before `run-cmd-workflow` — but its **output is not referenced in the `if:` condition**. The condition only checks whether the comment starts with `/cmd`.

The check was performed but the result was thrown away.

### 3. Identifying what gets executed

`cmd-run.yml` runs on the `parity-weights` self-hosted runner and does:

1. Checks out the PR branch (the attacker's fork)
2. Runs `cmd.py bench --pallet pallet_system`
3. `cmd.py` executes: `cargo install --path substrate/utils/frame/omni-bencher`

The path `substrate/utils/frame/omni-bencher` is resolved relative to the checked-out PR branch — the attacker's repository. If the attacker modified `src/main.rs` in that path, `cargo install` compiles and runs the attacker's code.

### 4. Verifying the file exists in the repo

```
GET /repos/paritytech/polkadot-sdk/contents/substrate/utils/frame/omni-bencher
→ {Cargo.toml, README.md, src/, tests/}
```

Confirmed: `frame-omni-bencher` is a real crate in the repo with its own `main.rs`.

### 5. Tracing the historical origin

| Date | PR | Change |
|------|-----|--------|
| 2025-03-06 | #7711 | "cmd-bot: divide workflow into 2 steps" — **origin of the vulnerability** |
| 2025-10-15 | #9915 | Added `/cmd label` — auth check added to `cmd.py` for `label` only |
| 2025-10-18 | #10050 | Added `check-pr-author` job but didn't use it as a gate |

PR #7711 split the workflow into two steps as a security measure (referencing `paritytech/security/issues/103`). The split introduced the auth gap: `is-org-member` was added but its output was never wired into `run-cmd-workflow`'s condition. Subsequent patches added auth only for the `label` subcommand, leaving `bench`, `fmt`, `update-ui`, and `prdoc` ungated.

---

## Vulnerability

The authorization check exists but is not enforced:

```yaml
# cmd.yml — the gap
run-cmd-workflow:
  needs: [set-image, get-pr-info, is-org-member, check-pr-author]
  # BUG: only checks comment syntax — never checks membership
  if: ${{ startsWith(github.event.comment.body, '/cmd') && !contains(github.event.comment.body, '--help') }}
  env:
    IS_ORG_MEMBER: ${{ needs.is-org-member.outputs.member }}  # computed, never used
    IS_PR_AUTHOR: ${{ needs.check-pr-author.outputs.is_author }}  # computed, never used
```

**What the missing gate should look like:**

```yaml
if: |
  ${{ 
    startsWith(github.event.comment.body, '/cmd') && 
    !contains(github.event.comment.body, '--help') &&
    (needs.is-org-member.outputs.member == 'true' || 
     needs.check-pr-author.outputs.is_author == 'true')
  }}
```

---

## Steps to Reproduce (conceptual — not executed against production)

1. Fork `paritytech/polkadot-sdk`.
2. In your fork's branch, modify `substrate/utils/frame/omni-bencher/src/main.rs`:

```rust
fn main() {
    // Proof of concept: print runner environment
    let output = std::process::Command::new("sh")
        .args(["-c", "env; hostname; id"])
        .output()
        .unwrap_or_default();
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
```

3. Open a PR from your fork to `paritytech/polkadot-sdk:master`.
4. Comment `/cmd bench --pallet pallet_system` on your own PR.
5. The workflow executes:
   - Checks out your fork's branch
   - Runs `cargo install --path substrate/utils/frame/omni-bencher`
   - Your modified `main.rs` is compiled and executed on `parity-weights`

---

## Impact

| Vector | Impact |
|--------|--------|
| Code execution on `parity-weights` | RCE on Parity's self-hosted runner |
| Network access from the runner | Access to Parity's internal network, cloud metadata |
| Resource abuse | Crypto mining, CI/CD capacity exhaustion |
| Potential escalation | Cached Docker credentials, SSH keys on the runner host |

The `cmd-run.yml` job has `permissions: contents: read` (GITHUB_TOKEN is scoped), but code executed in the container can reach external and internal networks.

---

## Remediation

**Minimal fix:** Add the membership check to the `if:` condition:

```yaml
run-cmd-workflow:
  if: |
    ${{ 
      startsWith(github.event.comment.body, '/cmd') && 
      !contains(github.event.comment.body, '--help') &&
      (needs.is-org-member.outputs.member == 'true' || 
       needs.check-pr-author.outputs.is_author == 'true')
    }}
```

**Recommended:** Use `pull_request_target` with required reviewer approval for any workflow that compiles and executes PR code on self-hosted runners. External PRs touching self-hosted runners should require explicit maintainer approval before CI runs.

---

## Lessons Learned

- **"Exists in `needs:`" ≠ "gates execution."** A job in `needs:` only controls ordering. The `if:` condition must explicitly reference the check's output.
- **Audit the output usage, not just the check.** Security reviews of CI/CD often verify that membership checks exist — but not that their output is actually wired into the gate condition.
- **`cargo install --path <pr-branch>` is arbitrary code execution.** Any workflow that compiles and runs code from a PR branch on a self-hosted runner is a potential RCE if unguarded.
- **Partial auth fixes are dangerous.** Adding auth for `label` but not `bench` created false confidence that the authorization issue had been addressed. Always audit which subcommands/branches a partial fix missed.
- **Historical analysis reveals the origin.** Reading the PR history (`git log --grep="security"`) showed exactly when the gap was introduced and which patches failed to close it.
