# Finding Template

Every confirmed finding — regardless of which skill produced it — is appended to
that skill's `findings/<NN>-<slug>.md` file using **exactly** this schema. Uniform
structure is what lets `sast-final-report` parse, de-duplicate, and chain findings.

Append one block per finding. Do not overwrite existing findings in the file.

---

```markdown
### [<FINDING-ID>] <Short title>

- **Class:** <vulnerability class, e.g. SQL Injection>
- **CWE:** CWE-89
- **Severity:** Critical | High | Medium | Low | Info
- **Confidence:** Confirmed | Firm | Tentative
- **Validation:** Not validated | Confirmed (PoC) | False positive | Inconclusive
- **Reachable over:** Web | Mobile/API | Both | N/A (code/config-only)
- **Location:** `path/to/file.ext:LINE` (function/method if relevant)
- **Sink:** `the dangerous call`, e.g. `cursor.execute(...)`
- **Source:** `the tainted input`, e.g. `request.args["id"]` (HTTP query param)
- **Data flow:** source → (transforms) → sink, one arrow-chain line

**Description**
One paragraph: what the flaw is and why the taint reaches the sink unsanitized.

**Evidence**
```<lang>
// minimal excerpt showing source, the missing/broken sanitizer, and the sink
```

**Impact**
What an attacker gains (read/write/RCE/authz bypass/etc.), concretely.

**Exploitability**
- Preconditions: auth required? specific config? reachable route?
- Attacker-controlled: fully | partially | via chain only

**Request (Burp-pasteable)** — REQUIRED when `Reachable over` is Web / Mobile/API /
Both; otherwise write `N/A — <reason>`. See `references/burp-request-format.md`.
```http
POST /api/vulnerable/endpoint HTTP/1.1
Host: TARGET_HOST
Cookie: session=<SESSION>
Content-Type: application/json
Content-Length: <auto>

{"id":"<PAYLOAD-MARKER>"}
```
- Injection point: which parameter/header/field carries the payload.
- Payload marker: the benign proof value used (see validation skill — do NOT weaponize).
- Expected indicator: the response/timing/OOB signal that proves the flaw.

**Chain potential**
- Provides (controlled): `CODE_EXEC` | `SECRET_LEAK` | `FILE_READ` | … — use the
  exact tokens from `references/attack-chaining-catalog.md` §1, optionally with a
  plain-language gloss in parentheses.
- Consumes (controlled): `URL_CONTROL` | `SECRET_LEAK` | … | none.
- Candidate chains: <IDs of other findings this could combine with, or "TBD">

**Remediation**
Specific fix (parameterize, allowlist, encode, etc.) — not generic advice.

**False-positive check**
Why this is NOT a false positive (sanitizer absent/bypassable, sink confirmed
reachable, source confirmed attacker-controlled).

**Validation result** — filled by `sast-finding-validation` at runtime; leave as
`Pending` until then.
- Verdict: Pending | Confirmed (PoC) | False positive | Inconclusive
- Method: what benign proof was run (e.g. boolean-diff, time delay, OOB callback,
  reflected marker) — existence proof only, non-destructive.
- Observed indicator: the exact signal seen (status/length diff, delay ms, DNS hit).
- Tester identity/role: which account/session was used.
```

---

## Field rules

- **FINDING-ID** — `<CLASS-ABBR>-<NNN>`, e.g. `SQLI-001`, `SSRF-003`. Stable and unique.
- **Confidence** —
  - *Confirmed*: full taint path source→sink, no effective sanitizer.
  - *Firm*: sink and source proven; sanitizer likely absent but not 100% traced.
  - *Tentative*: pattern match only; flag for manual review, keep in report but marked.
- **Chain potential** is mandatory — it is the raw material for the final report.
  Always name the **primitive** the finding provides and/or consumes.
- Keep evidence minimal but complete: it must show source, (broken) sanitizer, sink.
- **Reachable over / Request** — if the flaw can be triggered by an HTTP client
  (web app, mobile app, or API), you MUST include a raw, Burp-pasteable HTTP
  request in the **Request** block so it can be dropped straight into Burp
  Repeater. Set `Reachable over: N/A` only for code/config-only classes with no
  HTTP trigger (e.g. IaC misconfig, hardcoded secret in a build artifact, weak
  crypto in an offline library) and explain why.
- **Validation / Validation result** — set by `sast-finding-validation`. Detection
  skills leave `Validation: Not validated` and `Verdict: Pending`. Never mark a
  finding validated from static analysis alone.
