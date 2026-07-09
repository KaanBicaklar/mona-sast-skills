---
name: redos
description: >-
  SAST detection methodology for Regular Expression Denial of Service (CWE-1333,
  CWE-400), including catastrophic backtracking (nested quantifiers, overlapping
  alternation, backreferences), user-supplied regex compiled at runtime, and
  known-vulnerable library patterns. Use when reviewing regex used against
  untrusted input on a backtracking engine. Writes confirmed findings to
  findings/32-redos.md.
---

# ReDoS (Regular Expression Denial of Service) — SAST Methodology

**Class:** ReDoS · **CWE-1333** (and **CWE-400**) · **OWASP:** A05 Security Misconfiguration
**Findings file:** `findings/32-redos.md`

## 1. Overview

ReDoS occurs when a regex with **catastrophic backtracking** is evaluated against
attacker-controlled input on a backtracking engine (PCRE-style), causing
super-linear (often exponential) CPU time and a denial of service. On
single-threaded runtimes (Node's event loop) one crafted string freezes the whole
process. The core test: does a regex containing an ambiguous, quantifier-nested
construct get applied to input whose length/content an attacker controls, on an
engine that backtracks (JS, Java, Python `re`, .NET, PCRE) rather than a linear
engine (RE2, Rust `regex`, Go `regexp`)?

## 2. Where it lives

- Input validation regexes (email, URL, phone, username, password policy) applied
  to unbounded user input.
- Runtime-compiled regexes from user input: `new RegExp(userInput)`,
  `re.compile(userInput)`, `Pattern.compile(userInput)`, search/filter features.
- Parsers and sanitizers built on regex (markdown, HTML, CSS, log parsing,
  templating, `String.replace` with a regex).
- Known-vulnerable library versions (old `validator.js`, `moment` durations,
  `marked`, `lodash` template, `ua-parser-js`, `semver`, `ansi-regex`).
- Route/path matchers, `Content-Type`/header parsers, WAF rules.

## 3. Sources (tainted input)

Any attacker-controlled string the regex is run against: HTTP query/body/path/
header/cookie values, uploaded file contents/names, imported data, and — most
dangerous — a **regex pattern itself supplied by the user** (search-by-regex,
admin rule builders). Length matters: ReDoS needs the input long enough to force
backtracking, so also flag missing upstream length limits. Trace both the *subject*
string and the *pattern* to their sources.

## 4. Sinks (dangerous operations)

The "sink" is the **regex evaluation on a backtracking engine**. Two danger axes:
a vulnerable *pattern*, and a *user-supplied pattern*.

```javascript
// JS/Node — DANGEROUS patterns (nested/overlapping quantifiers) on user input
const re1 = /^(a+)+$/;                 // nested quantifier -> exponential
const re2 = /^(\d+)*$/;                // quantified group * quantifier
const re3 = /^(\w+\s?)*$/;             // overlapping ' ?' -> catastrophic
const re4 = /(a|a)*$/;                 // overlapping alternation
re1.test(req.query.q);                 // attacker controls the subject
// DANGEROUS: user-supplied pattern compiled at runtime
new RegExp(req.query.pattern).test(data);   // attacker controls the regex itself
```
```python
# Python re (backtracking) — DANGEROUS
EMAIL = re.compile(r'^([a-zA-Z0-9]+)*@')     # (…+)* nested quantifier
EMAIL.match(user_input)
re.compile(request.args["rx"]).search(text)  # user-supplied pattern
```
```java
// Java java.util.regex (backtracking) — DANGEROUS
Pattern p = Pattern.compile("^(\\d+)+$");     // nested quantifier
p.matcher(request.getParameter("v")).matches();
"^(([a-z])+.)+[A-Z]([a-z])+$".matches(input); // classic exponential validator
```
```
# Dangerous CONSTRUCTS to recognize (engine-agnostic):
(a+)+        (a*)*        (a+)*        nested quantifiers
(a|a)*       (a|ab)*      overlapping / ambiguous alternation under a quantifier
(\d+)*\d     quantified group followed by a required char that overlaps it
(.*a){10}    quantified group with '.' and a bounded repeat
(\w+)*$      quantifier over a group whose atom also repeats, anchored at end
\b(\w+)\1+   backreference forcing re-scan
```

## 5. Sanitizers / safe patterns

**Safe:** use a **linear-time engine** for untrusted input — RE2 (`re2` bindings,
`node-re2`), Rust `regex`, Go `regexp` — which cannot backtrack catastrophically.
On backtracking engines: rewrite patterns to remove ambiguity (atomic groups
`(?>…)`, possessive quantifiers `a++`, anchoring, avoiding nested/overlapping
quantifiers), enforce a strict **input length cap before** matching, and apply a
**match timeout** (.NET `Regex` `matchTimeout`, Java via a watchdog thread, Node
worker with timeout). Never compile a user-supplied pattern on a backtracking
engine; if you must, run it on RE2 with length and timeout limits.

**Fails / not a real sanitizer:**
- Length cap set *after* the match, or too generous (thousands of chars still
  backtrack exponentially).
- Anchoring only one end (`^…` without `$`, or vice versa) — many ReDoS patterns
  still blow up.
- Trusting a "validated" library regex from a version with a known ReDoS CVE.
- `try/catch` around the match — backtracking hangs, it does not throw.
- Rate limiting alone — a single request can pin a core for minutes.
- Escaping the input (`RegExp.escape`-style) when the *pattern* is the vulnerable
  part, not the subject.

## 6. Detection methodology

1. **Find runtime-compiled / user-supplied patterns (highest severity):**
   ```
   rg -in 'new RegExp\(|re\.compile\(|Pattern\.compile\(|new Regex\(|regexp\.Compile' 
   rg -in 'RegExp\([^/)]*req|compile\([^)]*request|Pattern\.compile\([^)]*get(Param|Header)'
   ```
2. **Find dangerous constructs in literal patterns:**
   ```
   rg -n '\([^)]*[+*]\)[+*]'                       # (…+)+  (…*)*  nested quantifiers
   rg -n '\(\w*\|\w*\)[+*]'                        # (a|a)* overlapping alternation
   rg -n '\)\?\)[+*]|\w[+*]\)[+*]'                 # quantified atom inside quantified group
   rg -n '\\[0-9]'                                 # backreferences (re-scan risk)
   ```
3. **Identify the engine:** which language/library runs the regex? Backtracking
   (JS, Java `java.util.regex`, Python `re`, .NET default, PCRE) vs linear (RE2,
   Rust `regex`, Go `regexp`, .NET with `matchTimeout` mitigation).
4. **Check the subject source:** is the matched string attacker-controlled and
   **unbounded**? Look for a length cap *before* the match.
5. **Check for a timeout guard:** .NET `matchTimeout`, worker/thread watchdog. No
   timeout + backtracking engine + vulnerable pattern = confirmed.
6. **Audit dependencies for known ReDoS CVEs:**
   ```
   rg -n '"(validator|moment|marked|lodash|semver|ansi-regex|ua-parser-js)"' package*.json
   ```
   Compare pinned versions against known-vulnerable ranges.

## 7. Modern & niche variants

- **Nested quantifiers** `(a+)+`, `(a*)*`, `(a+)*`: the canonical exponential case;
  each additional `a` roughly doubles the work.
- **Overlapping alternation under a quantifier** `(a|a)*`, `(a|ab)*`: ambiguous
  paths the engine must explore combinatorially.
- **Quantified group followed by a required, overlapping char** `(\d+)*\d` /
  `(\w+)*$`: forces massive backtracking when the final char fails to match.
- **Backreferences** `\b(\w+)\1+`: force the engine to re-scan; disable most
  linear-engine optimizations and can be super-linear.
- **User-supplied regex compiled at runtime** (`new RegExp(userInput)`): the
  attacker supplies *both* a catastrophic pattern and the subject — worst case.
- **Known-vulnerable library patterns:** old `validator.js` `isEmail`/`isURL`,
  `moment` duration/`marked` inline grammar, `ansi-regex`, `semver` — pinned
  vulnerable versions ship the bad pattern for you.
- **Single-threaded runtime amplification:** on Node, one ReDoS request blocks the
  event loop → full-process DoS, not just one slow request.

## 8. Common false positives

- Regex run only on **bounded, developer-controlled** or short constant input.
- Patterns evaluated on a **linear engine** (RE2, Go `regexp`, Rust `regex`) —
  structurally immune to catastrophic backtracking.
- Simple, unambiguous patterns (single quantifier, no nesting/overlap) — linear
  regardless of engine.
- Matches guarded by a strict length cap *before* the match, or a `matchTimeout`.
- Anchored, character-class-only patterns like `^[a-z0-9]{1,32}$`.

## 9. Severity & exploitability

Base **Medium** (availability impact / CWE-400 DoS). **High** when the vulnerable
regex is on an unauthenticated, high-traffic path or runs on a single-threaded
runtime where one request stalls the whole service, or when the attacker supplies
the pattern. Lower if authenticated-only, tightly length-bounded, or on a linear
engine. Note DoS does not compromise confidentiality/integrity directly. See
`references/severity-model.md`.

## 10. Remediation

Match untrusted input with a linear-time engine (RE2, Go `regexp`, Rust `regex`),
or rewrite patterns to remove nested/overlapping quantifiers (atomic groups,
possessive quantifiers, precise character classes) and add a match timeout. Cap
input length *before* matching. Never compile user-supplied patterns on a
backtracking engine. Upgrade libraries with known ReDoS CVEs.

## 11. Output

Append each confirmed finding to **`findings/32-redos.md`** using
`references/finding-template.md`. Set `Class: ReDoS`, `CWE: CWE-1333` (add
`CWE-400`), and in **Chain potential** note primitives such as *CPU exhaustion /
availability DoS* (→ mask other attacks, disrupt rate-limit or lockout timers),
*event-loop stall* (Node full-process freeze), and — for user-supplied patterns —
*attacker-controlled regex evaluation* (consumes an input-reflection primitive).

**Primitives (controlled):** provides none (availability DoS - terminal); consumes none

## References
- CWE-1333 (Inefficient Regular Expression Complexity); CWE-400 (Uncontrolled
  Resource Consumption); OWASP A05:2021; OWASP ReDoS guidance; RE2 / linear-engine
  documentation.
