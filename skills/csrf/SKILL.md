---
name: csrf
description: >-
  SAST detection methodology for cross-site request forgery (CWE-352),
  including missing/unverified anti-CSRF tokens, tokens not tied to session,
  SameSite gaps (Lax bypass via top-level GET state change, SameSite=None),
  JSON CSRF via simple content-types, login/logout CSRF, HTTP method override,
  CORS-enabled state-changing endpoints, and GET requests that change state.
  Use when reviewing state-changing endpoints and their CSRF defenses. Writes
  confirmed findings to findings/18-csrf.md.
---

# Cross-Site Request Forgery (CSRF) — SAST Methodology

**Class:** Cross-Site Request Forgery · **CWE-352** · **OWASP:** A01 Broken Access Control
**Findings file:** `findings/18-csrf.md`

## 1. Overview

CSRF occurs when a state-changing endpoint authenticates requests using only
ambient credentials the browser sends automatically (session cookies, HTTP auth)
and lacks an unpredictable, request-bound token an attacker cannot forge. A
malicious page then makes the victim's browser issue an authenticated request that
performs an action the victim never intended. The core test: for each
state-changing route, is there an anti-CSRF control (synchronizer token, correct
SameSite cookies, or origin verification) that is present, verified server-side,
and tied to the user's session?

## 2. Where it lives

- Any authenticated POST/PUT/PATCH/DELETE route/controller/action that mutates
  state (settings change, password/email change, money transfer, role grant,
  delete, admin actions).
- Framework CSRF middleware config and its exemptions: Django `csrf_exempt`,
  Rails `skip_before_action :verify_authenticity_token`/`protect_from_forgery`,
  Spring Security `csrf().disable()`, Express `csurf` scope, `@csrf` exclusions,
  Laravel `VerifyCsrfToken::$except`.
- Cookie/session config (`SameSite`, `Secure`), login/logout handlers, and JSON
  APIs authenticated by cookies rather than an `Authorization` header.

## 3. Sources (tainted input)

CSRF's "source" is the **cross-site attacker's ability to make the victim's browser
send an authenticated request** — via an auto-submitting `<form>`, `<img>`/`<link>`
GET, `fetch`/XHR (subject to CORS/preflight), or a top-level navigation. The
relevant signals to analyze are: what authenticates the request (cookie vs bearer
token), what CSRF token is required, and the cookie `SameSite` attribute.

## 4. Sinks (dangerous operations)

```python
# Django — dangerous: CSRF protection removed on a state-changing view
@csrf_exempt
def change_email(request):                      # cookie-authed, no token check
    user.email = request.POST['email']; user.save()
```
```ruby
# Rails — dangerous
class AccountsController < ApplicationController
  skip_before_action :verify_authenticity_token   # disables CSRF for all actions
  def update; current_user.update(params); end
end
```
```java
// Spring Security — dangerous: CSRF globally disabled with cookie auth
http.csrf(csrf -> csrf.disable());               // any cookie-authed POST is forgeable
```
```javascript
// Express — dangerous: state change with no CSRF token, cookie session
app.post('/transfer', requireLogin, (req, res) => {   // no csurf / no token check
  transfer(req.session.userId, req.body.to, req.body.amount);
});
// GET performing a state change — dangerous (also SameSite=Lax bypass)
app.get('/account/delete', requireLogin, (req, res) => deleteAccount(req.session.userId));
```
```php
// PHP — dangerous
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    update_settings($_SESSION['uid'], $_POST);   // no token compared
}
```
```html
<!-- Token present in form but never validated server-side — dangerous -->
<input type="hidden" name="csrf" value="{{ token }}">   <!-- server ignores it on submit -->
```

## 5. Sanitizers / safe patterns

**Safe:**
- **Synchronizer token pattern:** a per-session (or per-request) unpredictable token
  in a hidden field/custom header, **compared server-side** with a constant-time
  check on every state-changing request; token bound to the user's session.
- **Double-submit cookie** done correctly (token in a cookie *and* a header, compared;
  ideally signed/HMAC'd so a subdomain can't forge it).
- **`SameSite=Lax` or `Strict` session cookies** (Lax blocks cross-site POST/`fetch`;
  Strict also blocks cross-site top-level GET) — plus `Secure` and `HttpOnly`.
- **Origin/Referer verification** against an allowlist for state-changing requests.
- **Bearer-token auth** in an `Authorization` header (not a cookie) — not
  auto-attached by the browser, so not CSRF-able (watch for cookie fallback).
- Requiring a non-simple content-type (`application/json`) *and* verifying it, so a
  cross-site HTML form (which can't set it) triggers preflight/rejection.

**Fails / not a real sanitizer:**
- Token present in the page but **never verified** on submit (very common).
- Token **not tied to the session** — a global/static/predictable token, or one an
  attacker can fetch from an unauthenticated endpoint and replay.
- Checking the token only on some methods while the action is also reachable via
  another (GET performing the change, or an HTTP **method-override** header
  `_method`/`X-HTTP-Method-Override` bypassing the POST-only check).
- **`SameSite=Lax` reliance with a state-changing GET** — Lax still allows top-level
  cross-site GET navigations, so a GET that mutates state is forgeable; also Lax has
  a ~2-minute post-set exemption in some browsers and `SameSite=None` removes the
  defense entirely.
- **Referer/Origin check that is optional** (skips when header absent) or matched by
  substring/suffix (see `open-redirect`/`cors-misconfiguration` bypass patterns).
- Relying only on a custom-header requirement while **CORS is misconfigured** to
  allow the attacker origin to send it (chain with `cors-misconfiguration`).
- Assuming JSON body ⇒ safe: a form can POST JSON-looking data as
  `text/plain`/`application/x-www-form-urlencoded` (**JSON CSRF**) if the server
  parses it regardless of content-type.

## 6. Detection methodology

1. **Enumerate state-changing routes** and their auth model (cookie session vs
   bearer):
   ```
   rg -n '@app\.(post|put|patch|delete)|router\.(post|put|patch|delete)|@(Post|Put|Patch|Delete)Mapping|methods=\[.*(POST|PUT|DELETE)'
   ```
2. **Find CSRF protection being disabled/exempted:**
   ```
   rg -n 'csrf_exempt|verify_authenticity_token|protect_from_forgery|csrf\(\)\.disable|csrf\.disable|VerifyCsrfToken|WithoutMiddleware'
   rg -n 'SameSite\s*[:=]\s*["\x27]?(None|none)|samesite=none'
   ```
3. **Confirm the token is actually verified server-side**, not just rendered: is
   there a compare on the incoming request? Is it session-bound and constant-time?
4. **Check SameSite on the session cookie** and whether any state change is reachable
   via **GET** or a **method-override** header (bypasses POST-only + Lax).
5. **Check content-type handling:** does the body parser accept `text/plain`/
   form-encoded for JSON endpoints (JSON CSRF)? Is a custom header the *only* defense
   while CORS allows it?
6. **Prioritize sensitive actions:** password/email change, MFA disable, fund
   transfer, role/permission change, account delete, and **login/logout** CSRF.
7. **Confirm exploitability:** cookie-authenticated + no verified token + reachable
   cross-site (form or simple request) = confirmed.

## 7. Modern & niche variants

- **Missing/unverified token:** either no token at all, or a token rendered but not
  compared on submit (the single most common real finding). Grep for exemptions and
  then verify the *positive* check exists.
- **Token not tied to session:** static/global tokens, tokens issued by an
  unauthenticated endpoint, or tokens shared across users — attacker fetches/knows a
  valid token and replays it.
- **SameSite gaps:** `SameSite=Lax` does **not** stop cross-site **top-level GET**
  navigations, so any state-changing GET remains forgeable; `SameSite=None` (or no
  attribute on legacy browsers) removes cookie-level protection entirely. Lax also
  has browser-specific timing exemptions. SameSite is a defense-in-depth layer, not
  a substitute for tokens.
- **JSON CSRF via simple content-type:** endpoints that parse a JSON body regardless
  of `Content-Type` can be hit by an HTML form posting `enctype="text/plain"` or
  `application/x-www-form-urlencoded` with a crafted body — no preflight, so CORS
  doesn't block it. Only a verified non-simple content-type + token stops it.
- **Login/logout CSRF:** forging a **login** logs the victim into the *attacker's*
  account (data captured under attacker's account) or fixes a session; forging
  **logout** is a nuisance/denial and can reset flows. Both bypass "sensitive action"
  intuition because they precede authentication.
- **HTTP method override:** frameworks honoring `_method`/`X-HTTP-Method-Override`/
  `X-HTTP-Method` let a simple POST (or even GET) masquerade as PUT/DELETE, dodging
  method-scoped CSRF checks.
- **CORS-enabled state-changing endpoints:** if a custom header is the only CSRF
  defense but CORS is configured to allow the attacker origin (reflected/`null`
  origin + credentials), the attacker's `fetch` can set the header and pass preflight
  — chain with `cors-misconfiguration`.
- **GET performing state change:** any mutation on GET is inherently CSRF-prone
  (prefetch, `<img>`, link, Lax cookies all fire it) and often also a REST/semantics
  bug.

## 8. Common false positives

- Endpoints authenticated purely by a bearer `Authorization` header (not cookies)
  with no cookie fallback — browser won't auto-attach it, so not CSRF-able.
- Framework CSRF middleware enabled globally with the token verified, and the route
  not exempted.
- `SameSite=Strict`/`Lax` cookies where the only state changes are non-GET and no
  method-override path exists (Lax) — plus tokens.
- Idempotent/read-only endpoints (no state change) — not CSRF-relevant.
- JSON endpoints that strictly require and verify `Content-Type: application/json`
  (triggering preflight) with a correct CORS policy.

## 9. Severity & exploitability

Base **Medium** for CSRF on a state-changing action (per the model). Raise toward
**High/Critical** when the forced action is high-value and one-shot — password/email
change or MFA disable leading to **account takeover**, fund transfer, or admin
role/permission grant — especially if reachable via a simple request (no token, GET,
or Lax-bypassing method). **Low** for logout CSRF or low-impact toggles. Chain
severity follows the end impact (e.g. CSRF → email change → password reset → ATO).
See `references/severity-model.md`.

## 10. Remediation

Implement the synchronizer token pattern: an unpredictable, session-bound token on
every state-changing request, verified server-side with a constant-time comparison;
prefer the framework's built-in CSRF middleware and do not exempt sensitive routes.
Set session cookies `SameSite=Lax` (or `Strict`) + `Secure` + `HttpOnly` as
defense-in-depth. Never perform state changes on GET. For JSON APIs, require and
verify `Content-Type: application/json` and/or a custom header, backed by a correct
CORS policy. Verify `Origin`/`Referer` against an allowlist for sensitive actions.
Disable HTTP method-override unless required.

## 11. Output

Append each confirmed finding to **`findings/18-csrf.md`** using
`references/finding-template.md`. Set `Class: Cross-Site Request Forgery`,
`CWE: CWE-352`, and in **Chain potential** name the primitive it **provides**:
*forced authenticated state change* (→ email/password change → account takeover;
→ privilege grant), and note what it **consumes** — e.g. a `cors-misconfiguration`
(to send a custom header cross-origin) or an `open-redirect`/`cross-site-scripting`
to deliver/upgrade the attack. Record the specific action forced and its cookie
`SameSite`/token state, since that determines the chain payoff.

**Primitives (controlled):** provides `FORCED_REQUEST`; consumes `DATA_WRITE`

## References
- CWE-352; OWASP A01:2021; OWASP CSRF Prevention Cheat Sheet; SameSite cookie spec;
  PortSwigger CSRF (SameSite bypass, JSON CSRF, login CSRF) research.
