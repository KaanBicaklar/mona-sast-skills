---
name: security-misconfiguration-and-headers
description: >-
  SAST detection methodology for security misconfiguration and missing/weak
  security headers (CWE-16), including absent CSP/HSTS/X-Content-Type-Options,
  clickjacking via missing X-Frame-Options / CSP frame-ancestors (CWE-1021),
  insecure cookie attributes (Secure/HttpOnly/SameSite, cookie scope, __Host-/
  __Secure- prefixes), cleartext/mixed content (CWE-319), verbose banners,
  default pages/credentials, directory listing, and dangerous HTTP methods.
  Use when reviewing server/framework config, response headers, cookie setup,
  and web-server hardening. Writes confirmed findings to
  findings/39-security-misconfiguration-and-headers.md.
---

# Security Misconfiguration & Headers — SAST Methodology

**Class:** Security Misconfiguration & Headers · **CWE-16** (and **CWE-1021** clickjacking, **CWE-693**, **CWE-614**, **CWE-319**) · **OWASP:** A05 Security Misconfiguration
**Findings file:** `findings/39-security-misconfiguration-and-headers.md`

## 1. Overview

Security misconfiguration is the absence of hardening that a secure default would
provide: missing security response headers, permissive cookie attributes,
framable pages, cleartext transport, verbose banners, default content, and
dangerous HTTP verbs left enabled. Each item is individually low-to-medium but
they are *force multipliers* — a missing `frame-ancestors` enables clickjacking,
a missing `HttpOnly` turns any XSS into full session theft, `SameSite=None`
without a token re-opens CSRF. The core test: for every response and cookie the
app emits, does it set the protective directive, and is the value actually strict
(not a placeholder/report-only/self-defeating value)?

## 2. Where it lives

- Response-header emission: framework middleware (`helmet`, Django
  `SecurityMiddleware`/`SECURE_*` settings, Spring Security `headers()`,
  ASP.NET `UseHsts`/`UseXContentTypeOptions`, Rails `default_headers`), and
  web-server/edge config (nginx `add_header`, Apache `Header set`, CDN rules).
- Cookie construction: `Set-Cookie` flags anywhere a session/auth/CSRF cookie is
  created (`res.cookie`, `SESSION_COOKIE_*`, `CookieBuilder`, `HttpCookie`).
- TLS/transport config: HSTS, redirect-to-HTTPS, mixed-content references in
  templates (`http://` asset URLs).
- Server hardening: `server_tokens`/`ServerSignature`/`X-Powered-By`, directory
  autoindex, default landing pages, sample apps, allowed HTTP methods
  (`limit_except`, `<LimitExcept>`, WebDAV/`PUT`/`DELETE`/`TRACE`).

## 3. Sources (tainted input)

Unlike injection classes there is often no per-request taint — the "source" is
the **attacker's browser/network position**: a malicious framing page (clickjacking),
a network MITM (cleartext/no-HSTS), a sibling subdomain (cookie scope/tossing),
or any `JS_EXEC` foothold that a missing `HttpOnly` lets escalate to cookie theft.
For header-reflection variants (HPP, host/`X-Forwarded-*`) the request
header/parameter *is* the tainted source.

## 4. Sinks (dangerous operations)

```javascript
// Node/Express — dangerous: no security headers, weak cookies
app.get('/', (req, res) => res.send(html));            // no CSP, no X-Frame-Options → framable
res.cookie('session', sid);                            // no Secure/HttpOnly/SameSite
res.cookie('session', sid, { sameSite: 'none' });      // None without Secure/token → CSRF re-opened
app.use(helmet({ frameguard: false }));                // clickjacking protection disabled
```
```python
# Django/Flask — dangerous
SESSION_COOKIE_SECURE = False                          # cookie sent over http
SESSION_COOKIE_HTTPONLY = False                        # JS-readable session
SECURE_HSTS_SECONDS = 0                                # no HSTS
CSP = "default-src * 'unsafe-inline' 'unsafe-eval'"    # CSP that permits everything
resp.set_cookie('sid', v, secure=False, httponly=False)
```
```nginx
# nginx — dangerous
server_tokens on;                                      # leaks version banner
autoindex on;                                          # directory listing
# no add_header Strict-Transport-Security ...          # missing HSTS
# no add_header Content-Security-Policy ...            # missing CSP → framable + XSS-amplified
dav_methods PUT DELETE;                                # dangerous write methods enabled
```
```java
// Spring Security — dangerous
http.headers(h -> h.frameOptions(f -> f.disable()));   // framable → clickjacking
http.headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives("default-src *")));
// Cookie: HttpOnly/Secure false
ResponseCookie.from("SESSION", v).httpOnly(false).secure(false).sameSite("None").build();
```
```html
<!-- Template — dangerous: mixed content on an https page -->
<script src="http://cdn.example.com/app.js"></script>  <!-- MITM-able, breaks HSTS intent -->
```

## 5. Sanitizers / safe patterns

**Safe:**
- `Content-Security-Policy` with a strict `default-src 'self'`, per-response
  nonces/hashes for scripts, `object-src 'none'`, `base-uri 'none'`, and
  `frame-ancestors 'none'` (or an explicit allowlist) to stop framing.
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` with
  a full HTTP→HTTPS redirect.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`
  (or stricter), `Permissions-Policy` denying unused features.
- Cookies: `Secure; HttpOnly; SameSite=Lax` (or `Strict`) for session/auth
  cookies, scoped to the exact host (no broad `Domain=.example.com`), using the
  `__Host-` prefix (forces Secure, no Domain, Path=/) or `__Secure-` where scope
  is needed.
- `server_tokens off`, `X-Powered-By` removed, `autoindex off`, default/sample
  pages removed, only required HTTP methods allowed.

**Fails / not a real sanitizer:**
- **`Content-Security-Policy-Report-Only`** — reports violations but blocks
  nothing; commonly mistaken for enforcement.
- CSP with `'unsafe-inline'`/`'unsafe-eval'`, wildcard `*` sources, or a
  `script-src` allowlisting a host with a JSONP/gadget endpoint — trivially
  bypassed (see §7).
- **`X-Frame-Options` set but no `frame-ancestors`** on browsers that ignore XFO
  in some contexts, or `ALLOW-FROM` (deprecated, ignored) — framable anyway.
- HSTS with `max-age=0` or without `includeSubDomains`, or set but the site still
  serves/redirects over plain HTTP first (first-request MITM).
- `SameSite=None` **without** `Secure` (rejected by browsers → attribute dropped)
  or without a CSRF token (re-opens CSRF).
- Setting `HttpOnly` on non-session cookies while the session cookie lacks it.
- `Domain=.example.com` cookie scope — any subdomain (including a taken-over or
  user-content one) can read/overwrite it (**cookie tossing**, §7).
- Blocking `X-Powered-By` but leaving a distinctive default error page / stack
  trace that fingerprints the stack anyway (cross-ref `information-disclosure`).

## 6. Detection methodology

1. **Find where headers are (not) set:**
   ```
   rg -n 'helmet|frameOptions|Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options|X-Frame-Options|Referrer-Policy|Permissions-Policy'
   rg -n 'add_header|Header (set|always set)|server_tokens|autoindex|X-Powered-By'
   ```
2. **Audit cookie flags at every Set-Cookie site:**
   ```
   rg -n 'set_cookie|res\.cookie|Set-Cookie|ResponseCookie|CookieBuilder|SESSION_COOKIE_|new HttpCookie'
   rg -n 'httponly\s*[:=]\s*[Ff]alse|secure\s*[:=]\s*[Ff]alse|[Ss]ame[Ss]ite\s*[:=]\s*["\x27]?[Nn]one'
   rg -n 'Domain\s*=|domain\s*[:=]'          # broad cookie scope
   ```
3. **Check TLS/HSTS and mixed content:**
   ```
   rg -n 'SECURE_HSTS_SECONDS|UseHsts|Strict-Transport-Security'
   rg -n 'src=["\x27]http://|href=["\x27]http://|url\(http://'   # mixed content
   ```
4. **Confirm CSP actually enforces:** is it `-Report-Only`? Does `script-src`
   contain `'unsafe-inline'`, `*`, or an allowlisted CDN/JSONP host? Is
   `frame-ancestors` present?
5. **Check server hardening & methods:** banner suppression, directory listing,
   and which HTTP methods are allowed (`TRACE`/`PUT`/`DELETE`/WebDAV).
6. **Look for default content/credentials:** admin consoles, sample apps, default
   login pages, framework welcome pages left deployed.
7. **Confirm reachability:** each item is web-observable — the response is served
   to any client, so it is reachable over Web by definition.

## 7. Modern & niche variants

- **CSP bypass:** `'unsafe-inline'` (any injected `<script>` runs), reused/guessable
  nonces across responses, `script-src` allowlisting a CDN/host that serves a
  JSONP endpoint or an AngularJS/known gadget (`https://cdnjs...`), missing
  `object-src 'none'` (`<object data=...>` and legacy plugins), and missing
  `base-uri` (base-tag hijack). A CSP that lists a domain with an open redirect
  or JSONP callback is effectively `unsafe-inline`.
- **Clickjacking / UI redress:** no `X-Frame-Options`/`frame-ancestors` lets an
  attacker frame a sensitive action (transfer, delete, OAuth consent) under a
  transparent overlay — provides `FORCED_REQUEST` (the victim's click drives the
  action). Also drag-and-drop and double-click variants.
- **Cookie tossing via subdomain:** a `Domain=.example.com` or subdomain-scoped
  cookie set from `evil.example.com` (or a taken-over subdomain) is sent to the
  parent, letting an attacker overwrite session/CSRF cookies (session fixation —
  cross-ref `session-management`).
- **SameSite=Lax GET gap:** `Lax` still allows cross-site **top-level GET**, so a
  state-changing GET remains forgeable; also the browser "Lax-by-default" 2-minute
  post-set exemption. `SameSite` is defense-in-depth, not a token (cross-ref `csrf`).
- **HTTP Parameter Pollution (HPP):** duplicate parameters (`?id=1&id=2`) parsed
  differently by the front-end proxy, framework, and backend — bypasses WAF/ACL
  rules, smuggles values past validation, and corrupts server-side URL building.
- **Missing HttpOnly amplifier:** any reflected/stored XSS becomes full account
  takeover because `document.cookie` yields the session — this finding *amplifies*
  a `cross-site-scripting` `JS_EXEC`.
- **Dangerous methods:** `TRACE` (XST to read HttpOnly cookies on old stacks),
  `PUT`/`DELETE`/WebDAV enabling file write, `OPTIONS` leaking the method set.

Cross-ref `cors-misconfiguration` (ACAO/credentials) and `csrf` (token/SameSite
defenses) rather than duplicating those; this skill covers the *header/cookie/
server-hardening* posture.

## 8. Common false positives

- CSP/headers absent on a purely static, unauthenticated, non-framable asset host
  with no cookies (lower risk; still note framing/sniffing exposure).
- `SameSite=None; Secure` deliberately used for a cross-site SSO cookie that is
  additionally protected by a verified CSRF token / bearer flow.
- Missing `HttpOnly` on a cookie that carries no security value (e.g. a UI theme
  preference) — confirm it is not the session/auth cookie.
- HSTS absent on an internal-only service never exposed over untrusted networks.
- Banner present but the version is patched/irrelevant (info-only; still note).

## 9. Severity & exploitability

Base **Low** for a single missing header/verbose banner (per the model). Raise to
**Medium/High** when it directly enables an attack: missing `frame-ancestors`/XFO
on a sensitive action (clickjacking → `FORCED_REQUEST`), missing `HttpOnly` on the
session cookie combined with any XSS (session theft → ATO), `SameSite=None`
without a token on state-changing endpoints, broad cookie scope enabling tossing/
fixation, or cleartext/no-HSTS on an authenticated app (MITM session capture).
Chain severity follows the amplified end impact. See `references/severity-model.md`.

## 10. Remediation

Emit a strict CSP (`default-src 'self'`, nonce/hash scripts, `object-src 'none'`,
`base-uri 'none'`, `frame-ancestors 'none'`/allowlist) in **enforce** mode, plus
HSTS with `includeSubDomains; preload`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy`, and `Permissions-Policy`. Set every session/auth cookie
`Secure; HttpOnly; SameSite=Lax|Strict`, scoped to the exact host with a
`__Host-` prefix. Redirect all HTTP to HTTPS and remove mixed content. Suppress
server/framework banners, disable directory listing, remove default pages and
credentials, and allow only the HTTP methods each endpoint needs. Normalize
duplicate parameters (reject or canonicalize) to close HPP.

## 11. Output

Append each confirmed finding to
**`findings/39-security-misconfiguration-and-headers.md`** using
`references/finding-template.md`. Set `Class: Security Misconfiguration & Headers`,
the specific `CWE` (`CWE-1021` for clickjacking, `CWE-614` for insecure cookie,
`CWE-319` for cleartext, `CWE-693`/`CWE-16` otherwise), and **`Reachable over: Web`**.
Because every item is web-reachable, include a **Burp-pasteable raw HTTP request**
per `references/burp-request-format.md` that shows the missing/weak header or cookie
in the response (e.g. a plain `GET /` whose response lacks CSP/`Set-Cookie` flags),
and mark the injection point (for HPP, the duplicated parameter). For clickjacking,
note the framing PoC page as the indicator.

**Primitives (controlled):** provides `FORCED_REQUEST`(clickjacking frames a victim
action); amplifies `JS_EXEC`(missing HttpOnly → cookie theft → session takeover);
consumes `JS_EXEC`.

## References
- CWE-16, CWE-1021, CWE-693, CWE-614, CWE-319; OWASP A05:2021 Security
  Misconfiguration; OWASP Secure Headers Project; MDN CSP / SameSite / Cookie
  Prefixes; OWASP Clickjacking & HTTP Parameter Pollution guidance.
