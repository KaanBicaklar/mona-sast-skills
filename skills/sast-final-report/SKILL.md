---
name: sast-final-report
description: >-
  Run LAST, after all per-class SAST detection skills have produced their
  findings/*.md files. Aggregates every finding, de-duplicates, scores severity,
  and — the core purpose — reasons about attack chaining: which individual
  weaknesses combine into full kill chains. Writes SECURITY-ASSESSMENT-REPORT.md.
---

# SAST Final Report & Attack-Chaining

**Run this only after the detection skills have run — and only when the user asks
for a report and/or chained vulnerabilities (it is on-demand, not automatic).** It
does not hunt for new bugs; it synthesizes what the per-class skills wrote into a
single decision-grade report whose centerpiece is **how findings chain together**.

The chain section is **Stage 1** of chaining: it proposes candidate chains as
*hypotheses* and presents them for the user to choose. Proving them is **Stage 2**
(`sast-finding-validation` Phase 3). If the user only wants the chain ideas, you can
emit just the chains section (e.g. `CHAINS.md`) without the full report.

## Inputs

- Every file in `findings/*.md` (one per vulnerability class).
- `references/attack-chaining-catalog.md` (primitive graph + named chains).
- `references/severity-model.md` (per-link and chain severity + chain uplift).
- `findings/VALIDATION-LOG.md` if it exists (per-finding and per-chain verdicts from
  `sast-finding-validation`).

If `findings/` is empty or missing, stop and report that no detection skills have
run yet — do not fabricate findings.

## Procedure

### 1. Ingest & normalize
- Read all `findings/*.md`. Parse each finding block (template fields).
- Assign/verify stable `FINDING-ID`s. Build a table: ID, class, severity,
  confidence, location, `provides`, `consumes`.

### 2. De-duplicate & cluster
- Merge findings that are the same root cause at the same location reported by two
  skills (e.g. a reflected value flagged by both XSS and CRLF). Keep one, note both
  classes. Cluster related findings by shared source or shared sink.

### 3. Score & apply validation verdicts
- Confirm each finding's standalone severity via `severity-model.md`.
- Keep `Confidence` orthogonal — never downgrade severity for uncertainty; mark
  `Tentative` items for manual confirmation instead.
- Read each finding's `Validation` verdict (set by `sast-finding-validation`):
  - **Confirmed (PoC)** → keep in the active risk list; these anchor the chains.
  - **False positive** → move to a separate "Validated false positives" section
    with its FP rationale; exclude from the risk totals and chains.
  - **Inconclusive** / **Not validated** → keep in the risk list, flagged as
    "needs manual/dynamic confirmation". Do not silently treat as confirmed.
  - If `findings/VALIDATION-LOG.md` exists, cite it. If no validation run happened,
    say so in §6 and label all findings "static, unvalidated".

### 4. Build the chain graph (the point of this skill)
These chains are **hypotheses (Stage 1)** — present them as candidate chains the
user can choose to validate (Stage 2), and never imply a graph-derived chain is
proven unless a validation run says so.
- For every finding, take its `provides`/`consumes` primitives.
- Draw edge A→B when `provides(A)` satisfies `consumes(B)` (per catalog §2/§4).
- Match against the named chains (catalog §3) **and** surface novel ≥2-link paths
  ending in a high-impact primitive (`CODE_EXEC`, `IDENTITY_FORGE`, org-wide
  `AUTHZ_BYPASS`, `SECRET_LEAK`→auth).
- For each chain: list the ordered links (with finding IDs), the end impact, the
  single precondition that unlocks it, and the **chain severity** (uplift = highest
  impact reachable at the end, even if each link is individually lower).
- **Apply chain-validation verdicts** (from `sast-finding-validation` Phase 3 /
  `findings/VALIDATION-LOG.md`). Tag each chain: **Validated** (end-to-end PoC),
  **Links-confirmed** (handoff unproven), **Broken** (a link is an FP or a handoff
  fails — drop or downgrade it), or **Theoretical** (an unvalidated/Inconclusive
  link). If no chain validation ran, tag every chain **Theoretical (static)** and
  say so — never present a graph-derived chain as if it were proven.

### 5. Prioritize
- Rank by: chain severity → standalone Critical/High → confidence.
- Produce a short "fix these first" list where one fix breaks multiple chains
  (identify choke-point findings that many chains route through).

## Output — `SECURITY-ASSESSMENT-REPORT.md`

Write to the repo root using this structure:

```markdown
# Security Assessment Report — <target>

## 1. Executive summary
- Scope, date, stack. Total findings by severity (table). Headline risk in 3 lines:
  the worst realistic chain and its business impact.

## 2. Findings summary table
| ID | Class | Severity | Confidence | Validation | Location | Chain(s) |
|----|-------|----------|------------|------------|----------|----------|

## 3. Attack chains  ← the centerpiece
For each chain:
### Chain C-<n>: <name> — <Chain severity>
- **Kill chain:** <FINDING-A> (provides X) → <FINDING-B> (consumes X, provides Y) → … ⇒ <end impact>
- **Validation status:** Validated | Links-confirmed | Broken | Theoretical (static)
- **Preconditions:** <the one thing an attacker needs to start>
- **Why it works:** 2-3 sentences tracing the primitive handoffs.
- **Break the chain:** the single highest-leverage fix that severs it.
(Include an ASCII/mermaid-style diagram of the chain graph if more than ~3 chains.)

## 4. Findings by class
One subsection per class that had findings. Full template blocks (or links to the
findings/*.md file) grouped and ordered by severity.

## 5. Choke points & remediation roadmap
- Choke-point findings that appear in multiple chains — fix first.
- Prioritized remediation list (Now / Next / Later) with effort vs risk.

## 6. Validated false positives
Findings that dynamic validation refuted, each with its FP rationale. Excluded
from the risk totals and chains but retained for transparency and audit.

## 7. Methodology & coverage
- Which detection skills ran, whether dynamic validation ran, which classes were
  out of scope, and any Tentative/Inconclusive findings needing manual
  confirmation. State coverage honestly — do not imply classes were checked if
  their skill did not run, or validated if no live run happened.

## 8. Appendix
- Primitive map used, tooling/commands, references (CWE/OWASP), and a pointer to
  `findings/VALIDATION-LOG.md` if a validation run occurred.
```

## Rules

- **Honesty of coverage.** If a class skill did not run, say so in §6. Never imply
  coverage you did not perform.
- **Every chain cites real finding IDs.** No hypothetical chains without at least
  one confirmed anchor link; label speculative extensions as such.
- **Both severities shown.** Per-link severity and chain severity, always.
- **English-only.** No Turkish anywhere in the report.
