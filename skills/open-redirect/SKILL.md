---
name: open-redirect
description: >-
  SAST detection methodology for open redirect (CWE-601), including filter
  bypasses (//evil.com, backslash tricks, @ userinfo, substring/suffix
  whitelist flaws, CRLF), redirect_uri / RelayState / next / returnUrl
  parameter abuse in OAuth/SSO flows, and header/meta-refresh/JS location
  sinks. Emphasizes its role as a chaining primitive for token theft,
  phishing, and SSRF filter bypass. Use when reviewing code that redirects a
  browser to a URL derived from input. Writes confirmed findings to
  findings/16-open-redirect.md.
---

# Open Redirect — SAST Methodology

**Class:** Open Redirect · **CWE-601** · **OWASP:** A01 Broken Access Control
**Findings file:** `findings/16-open-redirect.md`

## 1. Overview

Open redirect occurs when attacker-controlled input determines the destination of
a browser redirect without validation restricting it to the application's own
origin. Low impact alone, but a potent **chaining primitive**: it lends the
target's trusted domain to phishing, steals OAuth/SSO tokens via a poisoned
`redirect_uri`, and defeats SSRF/URL-allowlist filters that trust the first host.
The core test: does a source reach a redirect sink (`Location` header, framework
`redirect()`, `window.location`, meta-refresh), and is the destination validated
against a strict same-origin/allowlist rule that a bypass string can't slip past?

## 2. Where it lives

- Post-login/logout landing: `?next=`, `?returnUrl=`, `?redirect=`, `?url=`,
  `?dest=`, `?continue=`, `?callback=`, `?return_to=`, `?RelayState=`.
- OAuth/OIDC `redirect_uri` and SAML `RelayState` handling.
- Generic "go back" / deep-link handlers, URL shorteners, tracking/exit redirectors,
  language/region switchers that preserve the current path.
- Any place setting `Location`, calling `res.redirect`/`redirect()`/`RedirectView`,
  `sendRedirect`, or assigning `window.location`/`location.href`/`window.open`.

## 3. Sources (tainted input)

All HTTP inputs (query/body/path/header/cookie) supplying a URL or path — most
commonly the `next`/`returnUrl`/`redirect`/`url`/`callback`/`RelayState` family.
Also `document.referrer`, `location.hash`/`search` for client-side redirects, and
second-order: a stored "home URL"/"post-login destination" read back and redirected
to.

## 4. Sinks (dangerous operations)

```python
# Python — dangerous
return redirect(request.args.get('next'))          # Flask, no validation
return HttpResponseRedirect(request.GET['url'])    # Django
response.headers['Location'] = user_url            # raw header
```
```javascript
// Node/Express — dangerous
res.redirect(req.query.url);
res.writeHead(302, { Location: req.query.next });
// Client-side — dangerous
window.location = params.get('redirect');
location.href = decodeURIComponent(location.hash.slice(1));
window.open(userUrl);
```
```java
// Java — dangerous
response.sendRedirect(request.getParameter("url"));
return new RedirectView(request.getParameter("next"));   // Spring
return "redirect:" + userUrl;                             // Spring MVC prefix
```
```csharp
// C# / ASP.NET — dangerous
return Redirect(returnUrl);                          // not LocalRedirect
Response.Redirect(Request.QueryString["url"]);
```
```php
// PHP — dangerous
header("Location: " . $_GET['url']);
```
```html
<!-- Meta refresh — dangerous -->
<meta http-equiv="refresh" content="0;url={{ user_url }}">
```

## 5. Sanitizers / safe patterns

**Safe:**
- Don't redirect to a full URL from input at all — accept a **relative path only**
  and reject anything with a scheme or host. Enforce it starts with a single `/`
  and **not** `//` or `/\`.
- Map an opaque token/enum to a server-side allowlist of destinations
  (`?next=dashboard` → `{'dashboard': '/app/home'}`).
- Framework-native local-only helpers: ASP.NET `LocalRedirect`/`Url.IsLocalUrl`,
  Django `url_has_allowed_host_and_scheme(url, allowed_hosts)`, Rails
  `redirect_to` with `only_path: true`.
- Parse with a real URL parser, then compare the resulting **host** against an
  exact allowlist (`parsed.host === 'app.example.com'`), rejecting non-http(s)
  schemes.
- For OAuth `redirect_uri`: exact-match against pre-registered URIs (full string,
  including path), never prefix/substring.

**Fails / not a real sanitizer:**
- `startsWith('/')` alone — `//evil.com` and `/\evil.com` are protocol-relative /
  backslash escapes to another host.
- `startsWith('https://trusted.com')` — matches `https://trusted.com.evil.com` and
  `https://trusted.com@evil.com`.
- `contains('trusted.com')` / suffix `endsWith('trusted.com')` — matches
  `evil-trusted.com`, `trusted.com.evil.com`, `eviltrusted.com`.
- Blocking `http://`/`https://` but allowing `//host`, `\/\/host`, `https:evil.com`
  (scheme-relative), `javascript:`/`data:` (for JS-location sinks), or
  backslash/tab/newline obfuscation the browser normalizes.
- Validating a decoded value but redirecting with a re-encoded/raw one (or vice
  versa) — double-encoding and `@` userinfo confusion.
- Regex host checks with an unescaped `.` or no anchors.
- CRLF (`%0d%0a`) in the value splitting the `Location` header (also header
  injection) — the redirect filter that ignores control chars.

## 6. Detection methodology

1. **Find redirect sinks:**
   ```
   rg -n 'redirect\(|sendRedirect|RedirectView|HttpResponseRedirect|writeHead\([^)]*Location|res\.redirect'
   rg -n 'Location["\x27]?\s*[:=]|header\(\s*["\x27]Location'
   rg -n 'window\.location|location\.(href|assign|replace)|window\.open\('
   rg -n 'http-equiv=["\x27]?refresh'
   ```
2. **Find the redirect-param sources:**
   ```
   rg -n '\b(next|returnUrl|return_to|redirect|redirect_uri|url|dest|destination|continue|callback|RelayState)\b'
   ```
3. **Confirm the destination is input-derived** and reaches the sink.
4. **Audit the validation:** is it relative-path-only / exact-host allowlist / a
   framework local-redirect helper? Or a bypassable `startsWith`/`contains`/suffix
   check? Test mentally against `//evil.com`, `/\evil.com`, `https:evil.com`,
   `https://trusted@evil.com`, `https://trusted.com.evil.com`, backslash and CRLF.
5. **Check OAuth/SSO context:** if the param is `redirect_uri`/`RelayState`, is it
   exact-matched against registered values? A loose match here is token-theft grade.
6. **Confirm reachability** (route exposed, pre-auth login redirect is worst case).

## 7. Modern & niche variants

- **Protocol-relative & backslash bypasses:** `//evil.com`, `/\evil.com`,
  `\/\/evil.com`, `/%5cevil.com`, `https:/evil.com`, `https:evil.com` (scheme with
  missing slashes the browser fixes up). A `startsWith('/')` check passes them all.
- **`@` userinfo confusion:** `https://trusted.com@evil.com` — everything before `@`
  is userinfo; the real host is `evil.com`. Substring/prefix checks for `trusted.com`
  are fooled.
- **Whitelist-as-substring/suffix:** `trusted.com.evil.com` (suffix confusion),
  `evil-trusted.com`, `trusted.com.attacker.io`, unescaped-dot regex — the allowlist
  domain appears in the string but isn't the effective host.
- **CRLF into `Location`:** `%0d%0aSet-Cookie:…` or header/body splitting via the
  redirect param — overlaps `crlf-and-header-injection`; note both.
- **OAuth `redirect_uri` / OIDC / SAML `RelayState`:** the highest-impact form. A
  loose `redirect_uri` (prefix match, wildcard subdomain, path not checked) lets an
  attacker receive the authorization `code`/token → **account takeover**. `RelayState`
  and `next`/`returnUrl` in SSO flows carry the same risk. Always check for exact,
  full-URI registration.
- **Meta-refresh & JS-location sinks:** `<meta http-equiv=refresh content="0;url=…">`
  and `window.location`/`location.href`/`window.open` assignment — client-side, may
  also accept `javascript:`/`data:` schemes escalating to XSS.
- **Chaining primitive (emphasize):** open redirect on a trusted domain is the glue
  for other attacks — (1) *token theft*: steal OAuth codes / leak `Authorization`
  or session via redirect to attacker; (2) *phishing*: attacker URL wears the
  victim's domain; (3) *SSRF filter bypass*: a server-side fetcher that allowlists an
  internal/trusted host but follows redirects is walked to an arbitrary target;
  (4) *CSP/referrer/OAuth-state laundering*. Report it as a link that **provides a
  trusted-origin redirect primitive**.

## 8. Common false positives

- Redirects to a hard-coded/constant URL or a server-side enum→path map.
- Relative-path-only redirects that reject scheme/host and `//`/`/\` (verified).
- ASP.NET `LocalRedirect`/`IsLocalUrl`, Django `url_has_allowed_host_and_scheme`,
  Rails `only_path: true`, or exact-host allowlist parsing.
- OAuth `redirect_uri` exact-matched against registered URIs.
- Redirects to a value that is the app's own request path echoed back after strict
  validation.

## 9. Severity & exploitability

Base **Low** standalone. Rises sharply in a chain: **Medium** when it enables
phishing on a trusted domain or leaks referrer-borne secrets; **High/Critical** as a
chain when it steals OAuth/SSO tokens (`redirect_uri`/`RelayState` → account
takeover) or bypasses an SSRF/URL allowlist to reach internal services. Per the
model, the chain severity = the highest impact reached at the chain's end. See
`references/severity-model.md`.

## 10. Remediation

Prefer never redirecting to an input-supplied absolute URL: accept a relative path
only, or map an opaque token to a server-side allowlist. If external redirects are
required, parse the URL and exact-match the host against an allowlist while
rejecting non-http(s) schemes and `//`/`/\` protocol-relative forms. Use framework
local-redirect helpers (`LocalRedirect`, `url_has_allowed_host_and_scheme`,
`only_path: true`). For OAuth, exact-match `redirect_uri` against pre-registered
full URIs. Strip CR/LF from any value placed in `Location`.

## 11. Output

Append each confirmed finding to **`findings/16-open-redirect.md`** using
`references/finding-template.md`. Set `Class: Open Redirect`, `CWE: CWE-601`, and in
**Chain potential** always name the primitive it **provides**: *trusted-origin
redirect* → candidate chains include OAuth/SSO token theft (→ account takeover),
phishing delivery, `ssrf` URL-allowlist bypass (follows redirect to internal host),
and `crlf-and-header-injection` when CRLF is accepted. Note what it **consumes**
(usually nothing — it is a starting/pivot link). Given its low standalone severity,
its value in the final report is almost entirely as a chain link — flag the chains.

**Primitives (controlled):** provides `URL_CONTROL`; consumes none

## References
- CWE-601; OWASP A01:2021; OWASP Unvalidated Redirects & Forwards Cheat Sheet;
  OAuth 2.0 Security BCP (redirect_uri validation); PortSwigger SSRF-via-open-redirect notes.
