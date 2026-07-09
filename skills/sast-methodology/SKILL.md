---
name: sast-methodology
description: >-
  Orchestrator for a source-to-sink static application security testing (SAST)
  engagement. Use this FIRST when asked to security-review, audit, or SAST a
  codebase. Defines scope, recon, the taint model, run order for the per-class
  detection skills, and how findings are written to per-vulnerability files
  before the final aggregated attack-chaining report.
---

# SAST Methodology — Orchestrator

You are performing a static security review. Your job in this skill is to set up
the engagement, map the attack surface, and drive the per-class detection skills.
Do not try to find everything in one pass — run the specialized skills.

## Operating principles

1. **Taint-driven.** Everything reduces to: *source → (no effective sanitizer) →
   sink → reachable*. See `references/source-sink-taxonomy.md`.
2. **One class, one file.** Each detection skill appends only to its own
   `findings/<NN>-<slug>.md`. Never mix classes in one file.
3. **Evidence over pattern.** A grep hit is a lead, not a finding. Confirm the data
   flow and the (missing) sanitizer before writing it up.
4. **Reachability matters.** Prove the sink is reachable or lower confidence.
5. **Request block for web/mobile-reachable findings.** If a finding can be
   triggered by an HTTP client (web/mobile/API), the finding MUST include a raw,
   Burp-pasteable HTTP request (see `references/burp-request-format.md`). This is
   what makes the later validation pass one-click reproducible.
6. **English-only output.**

## Phase 0 — Scope & ground rules

- Confirm the target path(s) and what is in/out of scope (vendored deps, tests,
  generated code).
- Ask for the language/framework set if not obvious; otherwise detect it.
- Create the output directory `findings/` if it does not exist.

## Phase 1 — Recon & attack-surface map

Build a mental (and written) model before hunting. Capture:

- **Languages & frameworks** — from manifests: `package.json`, `requirements.txt`/
  `pyproject.toml`, `pom.xml`/`build.gradle`, `go.mod`, `composer.json`, `Gemfile`,
  `*.csproj`, `Cargo.toml`.
- **Entry points (sources)** — routes/controllers, GraphQL resolvers, message
  consumers, CLI handlers, webhooks, scheduled jobs, deserialization endpoints.
- **Trust boundaries** — auth middleware, tenant isolation, admin vs user, internal
  vs external services.
- **Dangerous sinks inventory** — a fast pass for the sink categories in the
  taxonomy (raw SQL, `exec`, `eval`, template render, file ops, URL fetch, HTML
  output, deserialization, redirects).
- **Secrets & config** — env handling, config files, CI definitions, IaC.

Recon commands (adapt to stack; use ripgrep/Grep):

```
# framework & manifests
rg -l --hidden -g '!node_modules' -e 'package.json|requirements|pom.xml|go.mod|composer.json|Gemfile'
# routes / entry points (examples)
rg -n '@app.route|@RestController|@GetMapping|router\.(get|post)|app\.(get|post)|resolver|@Controller'
# broad dangerous-sink sweep
rg -n 'execute\(|eval\(|exec\(|system\(|Runtime\.exec|child_process|innerHTML|readObject|unserialize|yaml\.load|pickle\.loads'
```

## Phase 2 — Run the detection skills

For each in-scope class, invoke the corresponding skill. Prioritize by attack
surface: run the classes whose sinks you actually found in Phase 1 first. A sane
default order (highest historical impact first):

1. `insecure-deserialization`, `command-injection`, `code-injection`,
   `server-side-template-injection` (RCE-class first)
2. `sql-injection`, `nosql-injection`, `ssrf`, `xxe`, `path-traversal-and-file-inclusion`
3. `broken-access-control-idor`, `mass-assignment`, `authentication-flaws`,
   `jwt-vulnerabilities`, `oauth-oidc-saml-flaws`
4. `cross-site-scripting`, `prototype-pollution`, `open-redirect`,
   `cors-misconfiguration`, `csrf`, `dom-clobbering-and-postmessage`
5. `unrestricted-file-upload`, `crlf-and-header-injection`, `ldap-injection`,
   `xpath-and-xml-injection`, `graphql-injection-and-abuse`, `unsafe-parsers-and-yaml`
6. `weak-cryptography`, `hardcoded-secrets`, `insecure-randomness`
7. Modern/infra: `http-request-smuggling`, `web-cache-poisoning-and-deception`,
   `redos`, `race-conditions-and-toctou`, `business-logic-flaws`,
   `cicd-and-pipeline-injection`, `iac-misconfiguration`,
   `dependency-and-supply-chain`, `llm-and-ai-application-security`

Each skill self-contains its sources, sinks, sanitizers, grep/AST heuristics,
niche variants, false-positive filters, and remediation, and writes to its own
findings file using `references/finding-template.md`.

---

**The scan above (Phases 0–2) is the baseline and always runs — it produces
`findings/`, one file per class. Everything below is ON-DEMAND: do it only when the
user explicitly asks for it.** A plain SAST scan stops after Phase 2.

## Phase 3 — Finding validation (on request; needs a live authorized target)

Only if the user asks to validate against a running, in-scope, authorized target,
invoke `sast-finding-validation`. It gathers the needed credentials/scope, runs
access-control checks first, then tests each finding in priority order using its
Burp request, marking each `Confirmed (PoC)` / `False positive` / `Inconclusive`
with a benign, non-destructive existence proof (no weaponization by default). Skip
entirely for a pure static review — findings stay `Validation: Not validated`.

## Phase 4 — Final report (on request)

Only when the user asks for a report, invoke `sast-final-report`. It reads every
`findings/*.md`, de-duplicates, drops/annotates false positives, and writes
`SECURITY-ASSESSMENT-REPORT.md`.

## Phase 5 — Attack-chain analysis (on request; two stages, in order)

Chaining is its own on-demand step — run it only when the user asks for chained
vulnerabilities. It always runs in **two stages**:

**Stage 1 — Hypotheses (ideas first).** From the findings' `provides`/`consumes`
primitives and `references/attack-chaining-catalog.md`, propose candidate chains
and **present them to the user as ideas** — each with its ordered links, the
primitive handoffs, the end impact, and what proving it would take. Tag them
`Theoretical (static)`. **Pause here** so the user can pick which chains to pursue,
or stop at ideas only.

**Stage 2 — Validation (only for the chosen chains).** Run `sast-finding-validation`
Phase 3 to prove each handoff non-destructively → `Validated` / `Links-confirmed` /
`Broken` / `Theoretical`. **If a chain cannot be validated, hand the user a *manual
continuation kit*** (the hypothesis, the confirmed links, the exact next request +
expected signal, and where it got stuck) so they can continue the attempt by hand.
Never silently drop an unproven chain — either the user takes over, or it stays a
clearly-labelled hypothesis.

## Deliverables checklist

Baseline scan (always):
- [ ] `findings/` contains one file per class that produced results.
- [ ] Every finding follows the template (source, sink, flow, chain potential).
- [ ] Web/mobile-reachable findings include a Burp-pasteable request block.
- [ ] No Turkish text anywhere in output.

On request only:
- [ ] Validation (Phase 3): findings carry a verdict and `findings/VALIDATION-LOG.md` exists.
- [ ] Report (Phase 4): `SECURITY-ASSESSMENT-REPORT.md` written.
- [ ] Chains (Phase 5): hypotheses presented first; chosen chains validated, and any
      unproven chain has a manual continuation kit for the user.
