---
name: sast-finding-validation
description: >-
  Dynamically validate SAST findings against a running target to separate real
  issues from false positives. Use AFTER the detection skills have produced
  findings/*.md and you have a reachable, IN-SCOPE, authorized environment. Gathers
  the credentials/scope needed, runs access-control checks FIRST, then tests each
  finding in priority order using its Burp-pasteable request, and finally validates
  the ATTACK CHAINS end-to-end (each primitive handoff). Default posture: PROVE
  EXISTENCE / FEASIBILITY with a benign PoC — do NOT weaponize or exploit.
---

# SAST Finding Validation

This is the only **active** skill in the pack: it sends real HTTP requests to a
running target to confirm or refute findings. Everything else is static. Treat it
accordingly — authorization and scope come before any packet.

## 0. Posture (non-negotiable defaults)

- **Prove existence, do not exploit.** The bar is a benign proof-of-existence, not
  impact. Boolean/time diff for SQLi; OOB callback for SSRF; `alert(document.domain)`
  for XSS; read your *own* neighbouring object for IDOR. Never dump data, write
  files, run shells, or pivot. Escalate to real exploitation ONLY if the user
  explicitly authorizes it for a specific finding.
- **In-scope only.** Only touch hosts/paths the user has confirmed are in scope and
  authorized for active testing.
- **Non-destructive.** Use test accounts and safe-to-write test data. No deletes,
  no state you can't undo, no bulk enumeration of real users.

## 1. Authorization & scope gate (do this before anything active)

Confirm, and record, before sending a single request:

- The user is authorized to actively test this target (engagement/pentest/CTF/own
  system). If they cannot confirm, **stop** — remain static-only.
- Environment: production vs staging/test. Prefer non-prod. If prod, get explicit
  go-ahead and tighten the non-destructive rules further.
- Scope allowlist (hosts/domains/paths) and explicit out-of-scope items.
- Testing window, rate limits, and any WAF/anti-automation the user knows about.

If any of these are missing, ask for them first (use AskUserQuestion for the
blockers). Do not proceed to Phase 2 with an unconfirmed scope.

## 2. Intake — information required from the user

Request the following (ask only for what's missing; group the questions):

**Targets**
- Web base URL(s); mobile/API base URL(s); which findings map to which host.
- For mobile: is there request signing / certificate pinning? (If yes, requests
  must be relayed through the instrumented app / Frida, not plain Repeater.)

**Identities (needed for access-control tests)**
- **Unauthenticated** baseline (no creds).
- **Low-privilege user A** — session cookie / bearer token / API key, or login creds.
- **Low-privilege user B** *of the same role* — for horizontal IDOR (A tries to
  reach B's objects). Provide B's object IDs where known.
- **High-privilege / admin** — to define what "vertical escalation" means.

**Session mechanics**
- How to authenticate (a login request, or ready-made tokens/cookies).
- CSRF token location and how to fetch a fresh one; token lifetime.
- MFA/step-up handling; how sessions expire and how to refresh.

**Test plumbing**
- Proxy (Burp) host:port if requests should route through it.
- An **OOB/collaborator domain** for blind SSRF/XXE/RCE/deser callbacks.
- Safe test data / disposable records you may create or modify.
- Any endpoints that are destructive and must NOT be triggered.

Store the answers as run configuration. Never write real secrets into
`findings/*.md` — keep them in the live session only; the request blocks stay
placeholdered.

## 3. Phase 1 — Access-control baseline (ALWAYS FIRST)

Before validating individual findings, establish the trust model. This both
catches the highest-impact class and produces the identities every later test uses.

1. **Verify each identity works** — confirm A, B, admin sessions are valid and
   map to the expected principal (hit a "who am I"/profile endpoint per identity).
2. **Unauthenticated access** — request a sample of protected endpoints with no
   session. Anything that returns protected data unauthenticated = confirmed BAC.
3. **Horizontal (IDOR/BOLA)** — as user A, request user B's object references
   (ids/UUIDs from the findings). Getting B's data proves it. Read-only, one object.
4. **Vertical (BFLA)** — as low-priv A, call admin-only functions/routes. Success =
   confirmed privilege escalation.
5. **Session/token scoping** — expired/rotated token still accepted? token from A
   accepted for B's tenant? Record.

Write each result to the relevant finding
(`findings/19-broken-access-control-idor.md` etc.) with a `Confirmed (PoC)` /
`False positive` verdict, and keep the identity map for Phase 2.

## 4. Phase 2 — Validate findings in priority order

Order: after the access-control baseline, take the remaining findings in
**descending priority** — chain-critical and Critical/High first, then Medium/Low
(follow the run order in `sast-methodology`; use `sast-final-report`'s ranking if
it has already run). Skip findings marked `Reachable over: N/A` — validate those by
code/config inspection or configuration review, not by HTTP.

For each finding:

1. **Load its Request block** from the findings file. Substitute real
   `TARGET_HOST`, session/token, CSRF, and the **benign** `<PAYLOAD-MARKER>`.
2. **Baseline first** — send the request with a neutral value; capture status,
   length, timing, reflection points.
3. **Send the proof probe** — the benign existence marker for that class (see the
   proof matrix in `references/burp-request-format.md`). For blind classes, point
   at the OOB domain and watch for the callback.
4. **Observe the indicator** — the specific differential that proves the flaw:
   status/length change, boolean true-vs-false divergence, time delay, reflected/
   executed marker, OOB hit, `Location` header, cross-identity data.
5. **Decide the verdict** (see §5). Re-run once to confirm it's stable, not noise.
6. **Record** into the finding's `Validation result` block and set the
   `Validation:` header field. Include the exact observed indicator and the
   identity used. Do not paste live secrets — reference them as placeholders.

## 5. Verdict rules

- **Confirmed (PoC)** — the benign proof produced the expected, repeatable
  indicator. State the one-line evidence. This is enough; stop here.
- **False positive** — the taint is actually neutralized or unreachable at runtime:
  effective server-side sanitization/parameterization observed, route/parameter
  doesn't exist or isn't attacker-controlled at runtime, framework encodes the
  context, or the sink is dead code. Explain *why* it's an FP.
- **Inconclusive** — blocked by a WAF, missing credentials, rate limit, or an
  environment gap. A WAF block is **not** a fix — mark Inconclusive and note the
  obstacle, do not downgrade to FP. Suggest what's needed to conclude.

Keep verdict independent of severity: a Confirmed Low stays Low; an FP Critical is
removed from the active risk list but kept with its FP rationale.

## 6. Phase 3 — Chain validation

Individual findings confirm *links*; this phase confirms the **chains** — that the
primitives actually hand off in sequence to reach the end impact.

This is **Stage 2** of the two-stage chain flow. **Stage 1 — proposing and
presenting the chain hypotheses to the user (ideas first)** — happens before this,
in `sast-methodology` Phase 5 / `sast-final-report`. Here you validate only the
chains the user chose to pursue. See `references/chain-validation-playbook.md` for
the per-chain benign handoff recipe and the manual-continuation-kit format.

**Extra authorization gate.** A chain reaches real impact (RCE, account takeover,
cloud compromise) far faster than a single link. Treat chain validation as a
higher-risk activity: confirm the user authorizes *chain* validation specifically,
and keep the default posture — prove the chain is **feasible** (each handoff works),
do not cause the end impact.

**Preconditions.** Only validate a chain whose every link is already
`Confirmed (PoC)`. If any link is `False positive`, the chain is **Broken**; if any
link is `Inconclusive` / `Not validated`, the chain is at best **Theoretical**.

**Method — prove each handoff, in order:**
1. Pull the chain's ordered links and the primitive each hands to the next
   (`provides` → `consumes`) from the report / catalog.
2. Re-establish link 1's primitive live (e.g. SSRF fires → `OUTBOUND_REQUEST`).
3. For each subsequent link, demonstrate that the previous primitive actually
   satisfies this link's precondition with a **benign** probe — e.g. the leaked
   token is *accepted* by the next endpoint (a harmless `whoami`), the reflected
   input is *executed* in the victim context, the open-redirect target is *honored*
   by the OAuth `redirect_uri`. Stop at feasibility; do not perform the destructive
   end action.
4. Record which handoff (if any) fails and why — that is the natural break point.

**Chain verdicts:**
- **Validated (end-to-end PoC)** — every link Confirmed and every handoff shown
  benignly. The chain is real.
- **Links-confirmed / handoff-unproven** — links are Confirmed but a handoff could
  not be shown non-destructively (needs authorized exploitation or specific state).
- **Broken** — a link is an FP, or a handoff provably fails (token rejected, WAF
  severs it, target not honored).
- **Theoretical** — one or more links unvalidated / Inconclusive; the graph says
  it is possible but it is not proven.

**When you can't validate it — hand off, don't drop.** If a chain ends
`Links-confirmed`, `Broken` at a handoff, or `Theoretical` — i.e. you could not
prove it end-to-end — emit a **manual continuation kit** so the user can continue
the attempt themselves:
- the chain hypothesis (ordered links + the primitive handoff each performs),
- which links are `Confirmed`, and exactly which handoff you got stuck on and why
  (rejected token, redirect not honored, state not reachable, scope/authorization
  limit, non-destructive ceiling),
- the exact next request(s) to try — Burp-pasteable — and the signal that would
  prove the handoff,
- any precondition still needed (funded/priv account, specific role, OOB host).

Record the kit in `findings/VALIDATION-LOG.md` and surface it to the user. The point
is that Claude failing to prove a chain must never block the user from proving it —
they pick up exactly where you stopped.

**Blind links.** For blind SSRF/XXE/RCE/deserialization the OOB callback IS the
proof of that link — no further pivot needed to count it Confirmed.

## 7. Stop conditions

Halt and report immediately if you: gain access clearly beyond the agreed scope,
risk data integrity or availability, hit real (non-test) user data, or trigger a
destructive action. Report what happened; do not continue "to be sure".

## 8. Output

- Update every validated finding in its `findings/<NN>-<slug>.md`: set
  `Validation:` and fill the `Validation result` block (verdict, method, observed
  indicator, tester identity).
- Write a run summary to **`findings/VALIDATION-LOG.md`**: a per-finding table
  `FINDING-ID | verdict | indicator | identity | notes`, AND a per-chain table
  `CHAIN-ID | links | chain verdict | failed handoff | notes`, plus the
  scope/identity map used (placeholdered) and the date of the run.
- Hand off to `sast-final-report`: Confirmed findings drive the chain analysis;
  chain verdicts (Validated / Links-confirmed / Broken / Theoretical) set each
  chain's status in the report; False positives are excluded from the risk list but
  retained with rationale; Inconclusive findings are listed as "needs manual
  confirmation".

## Rules

- English-only output.
- Never weaponize by default; existence proof is the deliverable.
- Never write live credentials/tokens into files — placeholders only.
- If not authorized or not in scope: stay static, validate nothing actively.
