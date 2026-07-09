---
name: session-management
description: >-
  SAST detection methodology for session management flaws (CWE-384 session
  fixation), including session id not rotated after login/privilege change,
  no invalidation on logout / password change / role change (CWE-613 absent
  expiry, CWE-565 cookie-trust), predictable or exposed session identifiers,
  session id in URL, weak cookie scope/flags (CWE-614), remember-me tokens not
  rotated, and CSRF-token-vs-session binding. Use when reviewing login/logout,
  session lifecycle, and session-cookie configuration. Writes confirmed findings
  to findings/43-session-management.md.
---

# Session Management — SAST Methodology

**Class:** Session Management · **CWE-384** (and **CWE-613**, **CWE-614**, **CWE-565**) · **OWASP:** A07 Identification and Authentication Failures
**Findings file:** `findings/43-session-management.md`

## 1. Overview

A session identifier is a bearer credential: whoever holds it *is* the user until
it expires or is invalidated. Session-management flaws break that contract —
**session fixation** (the id is not rotated when the trust level changes, so an
attacker-planted id survives login and now authenticates the victim), missing
invalidation on logout / password change / role change (a stolen or shared id
stays valid), absent or excessive timeouts, predictable/leaked identifiers, and
ids exposed in URLs. The core test: is a fresh, unpredictable session id issued at
every privilege boundary (login, step-up, role change) and fully invalidated
server-side at every teardown (logout, password reset, revocation)?

## 2. Where it lives

- Login/authentication success handlers (where the id should be regenerated).
- Logout, password-change, password-reset, MFA-change, and role-change handlers
  (where the old session must be invalidated server-side).
- Session store/framework config: `express-session`, Django
  `SESSION_*`/`cycle_key`, Spring Session / `sessionFixation()`, PHP
  `session_regenerate_id`/`session.*` ini, ASP.NET `Session`/forms-auth,
  Rails `reset_session`.
- Session-id generation (RNG quality — cross-ref `insecure-randomness`), cookie
  attributes/scope (cross-ref `security-misconfiguration-and-headers`), and
  remember-me / persistent-token handling.

## 3. Sources (tainted input)

The attacker's levers are: (1) the **session identifier value** — supplied by the
attacker before login (fixation via a `Set-Cookie`-controllable path, URL param,
or a subdomain-scoped cookie), or predicted/leaked (`SECRET_LEAK` consumed from a
weak RNG or a disclosure finding); and (2) the **session lifecycle events**
(logout/password-change requests) whose handlers may fail to invalidate. For
fixation the tainted input is literally the pre-authentication session id the
attacker plants into the victim's browser.

## 4. Sinks (dangerous operations)

```javascript
// Express — dangerous: id not rotated on login (fixation)
app.post('/login', (req, res) => {
  if (auth(req.body)) { req.session.userId = user.id; res.redirect('/'); } // same session id kept
});
// Logout that only clears the client cookie — dangerous
app.post('/logout', (req, res) => res.clearCookie('connect.sid'));         // server session still valid
```
```python
# Django — dangerous: no cycle_key / long-lived session
def login_view(request):
    if user: request.session['uid'] = user.id      # no request.session.cycle_key() → fixation
SESSION_COOKIE_AGE = 60 * 60 * 24 * 365            # 1-year session, no idle timeout
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
```
```php
// PHP — dangerous: no regenerate on privilege change
if (login_ok($u, $p)) { $_SESSION['user'] = $u; }  // missing session_regenerate_id(true) → fixation
// session id accepted from URL — dangerous
session.use_trans_sid = 1                           // SID in URL → leaks via Referer/logs
```
```java
// Spring Security — dangerous: fixation protection disabled
http.sessionManagement(s -> s.sessionFixation().none());   // id survives authentication
// password change without invalidating other sessions — dangerous
public void changePassword(...) { user.setPassword(hash); }  // existing sessions stay valid
```
```csharp
// ASP.NET — dangerous: reusing session across auth boundary
FormsAuthentication.SetAuthCookie(user, true);      // pre-login session id not regenerated
```

## 5. Sanitizers / safe patterns

**Safe:**
- **Regenerate the session id at every privilege boundary** — on login and on any
  step-up/role change — discarding the old server-side entry (`req.session.regenerate`,
  `session_regenerate_id(true)`, `request.session.cycle_key()`, Spring
  `sessionFixation().newSession()`/`migrateSession()`, `reset_session`).
- **Invalidate server-side** on logout, password change, password reset, MFA
  change, and admin revocation — destroy the store entry, not just the client
  cookie; ideally revoke *all* of the user's sessions on password/role change.
- **Absolute + idle timeouts**: short idle expiry and a bounded absolute lifetime,
  enforced server-side.
- **Unpredictable ids** from a CSPRNG with ≥128 bits of entropy (framework default
  store, not a home-rolled counter/timestamp — cross-ref `insecure-randomness`).
- Session id only in a cookie, never in the URL; cookie set `Secure; HttpOnly;
  SameSite=Lax|Strict`, host-scoped with `__Host-` (cross-ref
  `security-misconfiguration-and-headers`).
- Rotate remember-me/persistent tokens on each use and bind them so a used token
  cannot be replayed.

**Fails / not a real sanitizer:**
- Setting the user id on the **existing** session after login without regenerating
  — classic fixation; anything that could plant a pre-auth id now owns the account.
- **Logout that only clears the client cookie** (`clearCookie`/expiring it) while
  the server-side session remains valid — a captured id still works.
- Password reset/change that leaves other active sessions alive — a stolen session
  survives the "remediation".
- Idle "timeout" enforced only client-side (JS/`max-age`) while the server keeps
  the session indefinitely.
- Predictable ids (sequential, timestamp, MD5(userid), weak RNG) — guess/enumerate
  (consumes/needs `SECRET_LEAK`; cross-ref `insecure-randomness`).
- `SameSite` alone as fixation defense — a subdomain-scoped cookie (`Domain=.site`)
  set by a sibling host still fixes the parent session (**subdomain cookie
  tossing**, §7).
- Rotating the cookie value but keeping the same server-side session record
  (no real invalidation).

## 6. Detection methodology

1. **Find login/privilege-change handlers and check for id regeneration:**
   ```
   rg -n 'login|sign_in|authenticate|SetAuthCookie|session\[.*\]\s*=|req\.session\.\w+\s*='
   rg -n 'regenerate|cycle_key|session_regenerate_id|sessionFixation|migrateSession|reset_session|renewSession'
   ```
   A login that sets session state but has **no** regenerate call = fixation candidate.
2. **Find logout / password-change / reset handlers and check invalidation:**
   ```
   rg -n 'logout|sign_out|clearCookie|session\.destroy|invalidate\(\)|session\.flush|reset_session|changePassword|reset_password'
   ```
   Flag handlers that only clear the client cookie or don't destroy the store entry
   / don't revoke other sessions.
3. **Check timeouts:**
   ```
   rg -n 'SESSION_COOKIE_AGE|maxAge|MaxInactiveInterval|timeout|expires|SESSION_EXPIRE'
   ```
   Look for missing idle expiry or absolute lifetimes measured in months/years.
4. **Check id generation & exposure:** home-rolled ids (cross-ref
   `insecure-randomness`), and SID-in-URL (`use_trans_sid`, session id in query/path).
5. **Check cookie flags/scope** (cross-ref `security-misconfiguration-and-headers`):
   `Secure`/`HttpOnly`/`SameSite`, broad `Domain=`.
6. **Confirm reachability & trust boundary:** the login/logout endpoints are
   web-reachable; determine whether fixation is pre-auth exploitable.

## 7. Modern & niche variants

- **Session fixation (no rotation on login):** attacker obtains a valid session id,
  plants it in the victim's browser (URL param, `Set-Cookie` via a header-injection/
  meta path, or a subdomain cookie), the victim logs in, the id is not rotated, and
  the attacker now shares the authenticated session → `IDENTITY_FORGE`/`AUTHZ_BYPASS`.
- **Fixation via subdomain cookie:** a cookie set from `evil.example.com` with
  `Domain=.example.com` is sent to the parent; even `SameSite`/`Secure` don't stop
  it — the attacker fixes the parent session (cookie tossing; cross-ref
  `security-misconfiguration-and-headers`).
- **Logout that only clears the client cookie:** no server-side destroy, so a
  previously captured id (via XSS, sharing, proxy logs) stays valid after "logout".
- **No invalidation on password change/reset:** the very action taken after a
  compromise fails to kill the attacker's live session(s).
- **Remember-me token not rotated:** a long-lived persistent token that is not
  rotated on use (or not invalidated on password change) is a replayable credential.
- **Predictable/leaked id:** weak RNG or an id exposed in URL/Referer/logs lets an
  attacker guess or harvest a valid session (consumes `SECRET_LEAK`).
- **CSRF-token-vs-session binding:** a CSRF token not bound to the session (static/
  global) undermines both CSRF defense and session integrity (cross-ref `csrf`).
- **JWT-as-session pointer:** if a JWT is used as the session and cannot be revoked
  server-side, logout/password-change can't invalidate it — cross-ref
  `jwt-vulnerabilities`.

## 8. Common false positives

- Framework login that regenerates the id by default (e.g. `login()` in Django
  cycles the key; verify the framework/version actually does and it isn't disabled).
- Logout / password change that calls `session.destroy`/`invalidate()` server-side
  and (ideally) revokes other sessions.
- Stateless bearer-token APIs with short-lived access tokens + server-side
  refresh revocation (session semantics handled at the token layer — check that
  layer instead).
- Long `maxAge` on a genuinely low-value, unauthenticated preference cookie.
- Session id only ever in a `Secure; HttpOnly` cookie with a CSPRNG-generated value.

## 9. Severity & exploitability

Base **High** for session fixation or missing invalidation on an authenticated app
(leads to account takeover / persistent access — `IDENTITY_FORGE`). **Critical**
when it yields admin takeover or when combined with a leak/predictability that
makes it trivially exploitable pre-auth. **Medium** for over-long timeouts or
SID-in-URL exposure without a direct takeover path; **Low** for minor lifecycle
gaps on low-value sessions. Raise when fixation is pre-auth and default-config
reachable. See `references/severity-model.md`.

## 10. Remediation

Regenerate the session id (new server-side record) on every login and privilege
change, and fully invalidate the session server-side on logout, password change,
password reset, and MFA/role change — revoking all of the user's sessions on
credential changes. Enforce idle and absolute timeouts server-side. Generate ids
from a CSPRNG (≥128 bits); never place a session id in a URL. Set the session
cookie `Secure; HttpOnly; SameSite=Lax|Strict` and host-scope it with `__Host-`
(no broad `Domain=`). Rotate remember-me tokens on use and invalidate them on
password change. Bind CSRF tokens to the session.

## 11. Output

Append each confirmed finding to **`findings/43-session-management.md`** using
`references/finding-template.md`. Set `Class: Session Management`, the specific
`CWE` (`CWE-384` fixation, `CWE-613` absent/insufficient expiry, `CWE-614` insecure
cookie, `CWE-565` cookie-supplied-value trust), and **`Reachable over: Web`**.
Because login/logout are web-reachable, include a **Burp-pasteable raw HTTP request**
per `references/burp-request-format.md` — e.g. the login `POST` with a
pre-set/attacker-known session cookie to demonstrate the id is not rotated
(fixation), or the logout/password-change request followed by a replay of the old
id. Mark the injection point (the planted/observed session cookie) and the expected
indicator (same `Set-Cookie` value survives login, or old id still authenticates
after logout).

**Primitives (controlled):** provides `IDENTITY_FORGE`(ride/plant an authenticated
session via fixation or non-invalidation), `AUTHZ_BYPASS`(act as the victim);
consumes `SECRET_LEAK`(a predictable or leaked session id).

## References
- CWE-384, CWE-613, CWE-614, CWE-565; OWASP A07:2021 Identification and
  Authentication Failures; OWASP Session Management Cheat Sheet; OWASP ASVS V3
  (Session Management).
