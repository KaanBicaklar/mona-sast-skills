# mona-sast-skills

A modular, source-to-sink **Static Application Security Testing (SAST)** methodology,
packaged as composable Claude Code skills — one per vulnerability class — plus an
optional live validation pass and an attack-chaining report.

## What it is

Each vulnerability class is a self-contained skill with its own sources, sinks,
sanitizers, detection patterns, modern/niche variants, false-positive filters, and
remediation. Every class answers a single question: does attacker input (a *source*)
reach a dangerous operation (a *sink*) without an effective *sanitizer*, on a
*reachable* path? There are **47 classes** spanning the full injection family, access
control & authentication, cryptography & secrets, and a deep modern set — request
smuggling, ReDoS, CI/CD and IaC misconfig, supply chain, LLM/AI, mobile, native
memory safety, and smart contracts.

A plain scan writes one findings file per class (`findings/<NN>-<slug>.md`), and any
web/mobile-reachable finding ships with a raw, **Burp-pasteable HTTP request** so it
drops straight into Repeater. Everything past the scan is **on-demand**: an optional
dynamic skill validates findings against a live, authorized target — *non-destructively,
proving a vulnerability exists rather than exploiting it* — separating real issues from
false positives.

Finally, a shared primitive vocabulary lets a report skill compose individual findings
into **ranked attack chains**. Chaining runs in two stages: it first proposes candidate
chains as hypotheses, then (only if you ask) validates each handoff live; when it can't
prove a chain, it hands you a *manual continuation kit* so you can finish by hand. All
skills and generated output are English-only, and everything is meant for **authorized**
testing.

## Usage

Use it two ways: as **Claude Code skills** (invoked by name) or as a **manual playbook**
(open a `SKILL.md` and follow it). To install as skills, copy the ones you want into
your project (or `~/.claude/skills/`):

```bash
cp -r mona-sast-skills/skills/* your-project/.claude/skills/
```

Then run it in order — the first two are the baseline scan, the rest are on request:

1. **`sast-methodology`** — scopes the review, maps the attack surface, sets the run order.
2. **the class skills** — detect vulnerabilities and write `findings/<NN>-<slug>.md`.
3. **`sast-finding-validation`** *(optional)* — validate findings, then the chains, against a live authorized target.
4. **`sast-final-report`** *(optional)* — aggregate, drop false positives, and build the attack-chain report.

In Claude Code it looks like:

```
> Use sast-methodology to scope a SAST review of ./target-app
> Run the sql-injection, ssrf, and broken-access-control-idor skills on it
> Validate the findings against http://localhost:3000 (I authorize testing this local instance)
> Give me the chain ideas first, then try to validate them, then the final report
```

The full class list lives in `skills/`, and shared references (finding schema, severity
model, taint taxonomy, chaining catalog) in `references/`.

> Use only for authorized security testing — your own systems, engagements with
> permission, CTFs, or research. Validation is non-destructive by default; full
> exploitation requires explicit authorization.
