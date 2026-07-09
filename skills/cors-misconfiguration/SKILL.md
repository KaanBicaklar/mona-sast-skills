---
name: cors-misconfiguration
description: >-
  SAST detection methodology for CORS misconfiguration (CWE-942, CWE-346),
  including reflected Origin with Access-Control-Allow-Credentials:true, null
  origin acceptance, weak origin regex (unescaped dot, prefix/suffix match,
  trailing-domain confusion), trusting all subdomains, and wildcard-with-
  credentials pitfalls. Use when reviewing server code or config that emits
  Access-Control-Allow-* headers or configures a CORS middleware. Writes
  confirmed findings to findings/17-cors-misconfiguration.md.
---

# CORS Misconfiguration — SAST Methodology

**Class:** CORS Misconfiguration · **CWE-942** (and **CWE-346**) · **OWASP:** A05 Security Misconfiguration
**Findings file:** `findings/17-cors-misconfiguration.md`

## 1. Overview

CORS misconfiguration occurs when a server's `Access-Control-Allow-Origin` (ACAO)
policy is broader than intended, letting a malicious web origin read authenticated
cross-origin responses. The dangerous combination is a **permissive/reflected ACAO
paired with `Access-Control-Allow-Credentials: true`** — the attacker's page then
issues credentialed requests (cookies/HTTP auth) and reads the response, achieving
cross-origin data theft equivalent to a read-side CSRF. The core test: is the ACAO
value derived from (or loosely matched against) the request `Origin`, and is ACAC
`true`? If both, any weakness in the origin check is exploitable.

## 2. Where it lives

- CORS middleware config: Express `cors()`, Django `django-cors-headers`, Flask-CORS,
  Spring `@CrossOrigin`/`CorsConfiguration`, ASP.NET `AddCors`/`WithOrigins`, Rails
  `rack-cors`, Go `rs/cors`, nginx/Apache `add_header Access-Control-Allow-Origin`.
- Hand-rolled header emission: code that reads `req.headers.origin` and echoes it
  into `Access-Control-Allow-Origin`.
- API gateways / CDN / edge functions setting CORS headers.
- Per-route decorators/annotations overriding a global policy.

## 3. Sources (tainted input)

The request **`Origin` header** is the primary source — attacker-controlled, it
drives reflected/regex-matched ACAO decisions. Secondary: any config value or
allowlist built from user/tenant data, and the `Access-Control-Request-*` preflight
headers when a handler echoes them (`Allow-Headers`/`Allow-Methods` reflection).

## 4. Sinks (dangerous operations)

```javascript
// Node/Express — dangerous: reflect Origin + credentials
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);   // reflected
  res.header('Access-Control-Allow-Credentials', 'true');          // → any origin reads response
  next();
});
app.use(cors({ origin: true, credentials: true }));                // 'true' reflects request origin
app.use(cors({ origin: (o, cb) => cb(null, true) }));              // accepts everything
```
```python
# Flask — dangerous
resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')
resp.headers['Access-Control-Allow-Credentials'] = 'true'
CORS(app, supports_credentials=True, origins='*')                  # * + credentials footgun
```
```java
// Spring — dangerous
@CrossOrigin(origins = "*", allowCredentials = "true")             // reflects/allows all + creds
config.addAllowedOriginPattern("*");                               // pattern reflects
config.setAllowCredentials(true);
```
```csharp
// ASP.NET — dangerous
services.AddCors(o => o.AddPolicy("p", b =>
  b.AllowAnyOrigin().AllowCredentials()));                         // invalid combo, or SetIsOriginAllowed(_ => true)
```
```javascript
// Weak origin validation — dangerous
if (origin.endsWith('.trusted.com')) allow(origin);               // evil.com/trusted.com? & sub.trusted.com.evil.com
if (/trusted\.com/.test(origin)) allow(origin);                   // unanchored, matches trusted.com.evil.com
if (origin.startsWith('https://trusted.com')) allow(origin);      // https://trusted.com.evil.com
if (origin === 'null') allow(origin);                             // sandboxed iframe / data: URI sends null
```

## 5. Sanitizers / safe patterns

**Safe:**
- **Exact-match** the request `Origin` against a hard-coded allowlist of full
  origins (scheme+host+port), and only then echo that exact value into ACAO; else
  omit ACAO entirely.
- Do not set `Access-Control-Allow-Credentials: true` unless strictly required, and
  never combine credentials with a reflected/wildcard origin.
- For public, non-credentialed APIs, use a static `Access-Control-Allow-Origin: *`
  **without** credentials (browsers forbid `*`+credentials anyway).
- Add `Vary: Origin` when the ACAO value depends on the request origin (cache
  correctness/safety).
- Keep the allowlist in config, reviewed; reject `null` explicitly.

**Fails / not a real sanitizer:**
- Reflecting `Origin` after any **substring** (`includes`/`indexOf`), **suffix**
  (`endsWith('.trusted.com')` matches `trusted.com.evil.com` and, without the leading
  dot, `eviltrusted.com`), or **prefix** (`startsWith('https://trusted.com')` matches
  `https://trusted.com.evil.com`) test.
- **Unanchored / unescaped-dot regex** (`/trusted\.com/` or `/^https:\/\/.*trusted/`)
  — matches `attacker-trusted.com`, `trusted.com.evil.com`.
- Allowing `null` — sandboxed iframes, `data:`/`file:` origins, and some redirects
  send `Origin: null`; an attacker triggers it from a sandboxed iframe.
- **Trusting all subdomains** (`*.trusted.com`) when any subdomain has an XSS,
  subdomain takeover, or user-content host — that subdomain reads the credentialed API.
- Believing `*` is safe with credentials — code that swaps `*`→reflected origin to
  "support credentials" reintroduces reflection.
- Setting ACAO correctly but reflecting `Access-Control-Allow-Headers`/`-Methods`
  broadly, or ignoring that **simple requests** (GET/POST `text/plain`) skip preflight
  entirely — a restrictive preflight policy doesn't protect them.

## 6. Detection methodology

1. **Find CORS header/middleware sinks:**
   ```
   rg -n 'Access-Control-Allow-(Origin|Credentials|Methods|Headers)'
   rg -n 'cors\(|CORS\(|@CrossOrigin|AddCors|WithOrigins|rack-cors|AllowAnyOrigin|allowCredentials|supports_credentials'
   ```
2. **Find Origin reflection:**
   ```
   rg -n 'headers\.origin|getHeader\(\s*["\x27]Origin|request\.headers\.get\(\s*["\x27]Origin|req\.header\(\s*["\x27]Origin'
   rg -n "origin:\s*true|origin:\s*['\"]?\*|SetIsOriginAllowed"
   ```
3. **Determine if credentials are enabled:** grep for `Allow-Credentials`/
   `credentials: true`/`supports_credentials`/`allowCredentials`. Reflected/broad
   ACAO **with** credentials is the exploitable case.
4. **Audit the origin check** where ACAO is derived from `Origin`: exact allowlist,
   or bypassable substring/suffix/prefix/regex? Test against `null`,
   `https://trusted.com.evil.com`, `https://eviltrusted.com`, `attacker.trusted.com`
   (if all subdomains trusted).
5. **Check what the endpoint returns:** does the credentialed response contain
   sensitive data (PII, tokens, CSRF tokens, account info)? That's the loot.
6. **Note simple-request exposure:** GET/`text/plain` POST endpoints are reachable
   without preflight; a permissive ACAO exposes them directly.
7. **Confirm reachability & auth model:** is the endpoint session/cookie-authed
   (so credentialed cross-origin reads matter)?

## 7. Modern & niche variants

- **Reflected Origin + `ACAC: true`:** the canonical high-impact bug — server echoes
  whatever `Origin` it receives and allows credentials, so `attacker.com` reads any
  authenticated response. Exploit page: `fetch(target, {credentials:'include'})`.
- **`null` origin allowed:** ACAO `null` + credentials is exploitable from a
  sandboxed `<iframe sandbox>` (its origin is `null`), a `data:` URL, or certain
  redirect chains — a common "we allowed null for local files" mistake.
- **Weak origin regex/matching:** unescaped `.` (`trusted.com` matches `trustedxcom`),
  missing anchors, suffix confusion `trusted.com.evil.com`, prefix confusion
  `trusted.com.evil.com` via `startsWith`, and no-leading-dot suffix `eviltrusted.com`.
- **Trust-all-subdomains + subdomain XSS/takeover:** `*.trusted.com` allowed; a
  forgotten/user-content/CI subdomain with XSS or a dangling DNS takeover becomes a
  trusted origin that reads the main API — CORS turns a low-value subdomain flaw into
  full data theft (chain with `dom-clobbering-and-postmessage`/`cross-site-scripting`).
- **`*` with credentials pitfalls:** browsers reject `ACAO: *` with credentials, so
  developers "fix" it by reflecting the origin — reintroducing the reflection bug.
  Also `Allow-Credentials: true` alongside a wildcard is simply ignored, giving a
  false sense of restriction.
- **Preflight bypass via simple requests:** GET and `POST` with `Content-Type:
  text/plain`/`application/x-www-form-urlencoded`/`multipart/form-data` are "simple"
  and skip the OPTIONS preflight; a strict `Allow-Methods`/`Allow-Headers` policy
  does nothing for them. Reflected ACAO still exposes their responses. (Also enables
  JSON-CSRF-style writes — see `csrf`.)

## 8. Common false positives

- Static `Access-Control-Allow-Origin: *` on a **public, non-credentialed** API with
  no sensitive data and `credentials` disabled.
- Exact-match allowlist echoing only a verified full origin, credentials scoped
  correctly.
- CORS configured but the endpoint returns no authenticated/sensitive data (nothing
  to steal cross-origin).
- Reflected origin without `Allow-Credentials` on non-sensitive data (lower risk;
  still note if it exposes anything of value).
- `@CrossOrigin`/policy present but overridden by a stricter global filter (verify
  effective config).

## 9. Severity & exploitability

Base **Medium**; **High** when a reflected/`null`/bypassable ACAO combines with
`Access-Control-Allow-Credentials: true` on endpoints returning sensitive
authenticated data (cross-origin account/data theft, CSRF-token exfiltration →
enables CSRF/ATO chains). **Low** for a permissive policy on non-credentialed,
non-sensitive endpoints. Raise for default-config-vulnerable middleware and
trust-all-subdomains where a subdomain XSS exists. See `references/severity-model.md`.

## 10. Remediation

Exact-match the request `Origin` against a hard-coded allowlist of full origins and
echo only that exact value; otherwise omit ACAO. Enable
`Access-Control-Allow-Credentials: true` only when required and never with a
reflected or wildcard origin. Reject `Origin: null`. Avoid `*.domain` subdomain
wildcards unless every subdomain is fully trusted. Anchor and escape any origin
regex. Add `Vary: Origin`. Remember simple requests skip preflight — protect
state-changing GET/`text/plain` endpoints with CSRF defenses regardless of CORS.

## 11. Output

Append each confirmed finding to **`findings/17-cors-misconfiguration.md`** using
`references/finding-template.md`. Set `Class: CORS Misconfiguration`, `CWE: CWE-942`
(or `CWE-346` for origin-validation errors), and in **Chain potential** name the
primitive it **provides**: *cross-origin authenticated read* (→ steal PII / session
data / CSRF tokens, feeding `csrf` and account-takeover chains) and note when it
**consumes** a subdomain `cross-site-scripting`/takeover to reach a trust-all-
subdomains allowlist. Record whether credentials are enabled and what sensitive data
the endpoint returns — that determines the chain payoff.

**Primitives (controlled):** provides `DATA_READ` (cross-origin); consumes `JS_EXEC`

## References
- CWE-942, CWE-346; OWASP A05:2021; OWASP CORS guidance; PortSwigger CORS
  misconfiguration research; Fetch Standard CORS protocol.
