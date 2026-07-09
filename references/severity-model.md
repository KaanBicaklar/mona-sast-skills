# Severity & Exploitability Model

A lightweight, deterministic scoring model so every skill rates findings the same
way. Do not import full CVSS — use this table, then adjust one band for context.

## 1. Base severity by impact primitive

| Impact primitive gained | Base |
|---|---|
| Remote code execution / deserialization RCE / SSTI RCE | **Critical** |
| Auth bypass to admin, full account takeover, IDOR over all users' data | **Critical** |
| SQL/NoSQL injection with data read/write | **High** (Critical if DB is crown-jewel / RCE-capable) |
| SSRF reaching internal services or cloud metadata | **High** (Critical if metadata → creds) |
| Arbitrary file read / path traversal of sensitive files | **High** |
| Stored XSS in authenticated context | **High** |
| Reflected XSS, CSRF on state-changing action | **Medium** |
| Open redirect, verbose errors, missing headers | **Low** |
| Info leak with no direct pivot | **Low / Info** |

## 2. Exploitability modifiers (shift ≤1 band total)

Raise a band if **two or more** apply; lower a band if **two or more** apply.

**Raise:**
- Unauthenticated / pre-auth reachable.
- Reachable from a documented, linked route (not dead code).
- Fully attacker-controlled input (no partial encoding).
- Default configuration is vulnerable.

**Lower:**
- Requires high privilege already (e.g. admin-only endpoint).
- Requires a non-default, unusual config.
- Input is heavily constrained (short length, strict charset upstream).
- Only reachable via an unproven chain.

## 3. Chain uplift (applied by `sast-final-report` only)

Individual findings keep their standalone severity. The **chain** gets its own
severity = the **highest impact reachable at the end of the chain**, even if each
link is individually Medium. Example: Open Redirect (Low) + OAuth `redirect_uri`
(Medium) → account takeover = **Critical chain**. Always report both the per-link
severity and the chain severity.

## 4. Confidence is not severity

Keep them orthogonal. A *Tentative* Critical stays Critical but is flagged for
manual confirmation. Never downgrade severity to express doubt — use the
`Confidence` field for that.
