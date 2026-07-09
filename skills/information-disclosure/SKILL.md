---
name: information-disclosure
description: >-
  SAST detection methodology for information disclosure (CWE-200), including
  verbose errors/stack traces (CWE-209), debug mode (Flask/Werkzeug console,
  Django DEBUG=True, Rails detailed errors, ASP.NET custom errors off),
  exposed .git/.svn/.env/backup/swap/.DS_Store files, source-map (.map)
  exposure, directory listing (CWE-548), framework actuator/diagnostic
  endpoints (Spring Boot /actuator/heapdump, /env, phpinfo), sensitive data
  in responses/JS bundles/HTML comments (CWE-540), and XSSI/JSONP data leakage.
  Use when reviewing error handling, debug config, deployed artifacts, and
  response bodies. Writes confirmed findings to findings/40-information-disclosure.md.
---

# Information Disclosure — SAST Methodology

**Class:** Information Disclosure · **CWE-200** (and **CWE-209**, **CWE-215**, **CWE-540**, **CWE-548**) · **OWASP:** A01 / A05
**Findings file:** `findings/40-information-disclosure.md`

## 1. Overview

Information disclosure is any response, artifact, or endpoint that hands an
attacker data they should not see: secrets, internal structure, source code,
stack traces, or configuration. Its value is almost always as a **chain seed** —
a leaked stack trace reveals paths and framework versions, an exposed `.env` or
heapdump yields live credentials (`SECRET_LEAK`), a source map reconstructs
client logic and hidden endpoints. The core test: does any response body, error
page, deployed file, or diagnostic endpoint expose data beyond what the feature
functionally requires, especially secrets or internals?

## 2. Where it lives

- Error/exception handling: default framework error pages, un-caught exception
  handlers that echo stack traces or SQL to the client.
- Debug/diagnostic config: `DEBUG`/`FLASK_ENV=development`, Werkzeug interactive
  console, Rails `config.consider_all_requests_local`, ASP.NET `<customErrors
  mode="Off">`, `phpinfo()`, Node `NODE_ENV != production`.
- Deployed artifacts under webroot: `.git/`, `.svn/`, `.env`, `*.bak`/`*.old`/
  `*~`/`*.swp`, `.DS_Store`, config backups, `composer.lock`/`.map` files.
- Framework management/diagnostic endpoints: Spring Boot `/actuator/*`
  (`/heapdump`, `/env`, `/mappings`, `/threaddump`), `/debug`, `/status`,
  `/metrics`, GraphQL introspection.
- Response content: secrets/PII/internal IDs in JSON, HTML comments, JS bundles,
  hidden fields, verbose API error objects.

## 3. Sources (tainted input)

The "source" is usually the **attacker's fetch of an over-exposing endpoint or
artifact**, not per-request taint: a direct `GET` of a deployed file
(`/.git/config`, `/.env`, `/app.js.map`), a diagnostic endpoint
(`/actuator/heapdump`), or a request crafted to force an error path (malformed
input, wrong type, oversized value) so a verbose stack trace is returned. Where a
leak is toggled by input, the relevant source is the request header/param that
selects debug/verbose behavior (e.g. a `?debug=1` switch or an `Accept`/host
header that changes the error renderer).

## 4. Sinks (dangerous operations)

```python
# Flask/Django — dangerous: debug enabled in production
app.run(debug=True)                       # Werkzeug interactive console → RCE via PIN bypass
DEBUG = True                              # Django: full settings + stack traces to client
app.config['ENV'] = 'development'
```
```ruby
# Rails — dangerous
config.consider_all_requests_local = true # detailed exception pages for everyone
config.action_dispatch.show_exceptions = :all
```
```xml
<!-- ASP.NET web.config — dangerous -->
<customErrors mode="Off" />               <!-- yellow-screen stack traces to client -->
```
```javascript
// Node — dangerous: leak internals in error response
app.use((err, req, res, next) => res.status(500).json({ stack: err.stack, sql: err.query }));
```
```yaml
# Spring Boot application.yml — dangerous: actuators exposed unauthenticated
management.endpoints.web.exposure.include: "*"   # /actuator/heapdump, /env → SECRET_LEAK
management.endpoint.env.show-values: ALWAYS
```
```nginx
# nginx — dangerous: serves VCS/dotfiles/backups under webroot
autoindex on;                             # directory listing
# no rule blocking /.git /.env *.bak *.map → downloadable source & secrets
```
```html
<!-- Template/bundle — dangerous -->
<!-- TODO admin creds: admin / S3cr3t! -->        <!-- secret in HTML comment -->
<script src="/static/app.js.map"></script>        <!-- source map reveals server routes/keys -->
```

## 5. Sanitizers / safe patterns

**Safe:**
- Production sets `DEBUG=False`/`NODE_ENV=production`/`customErrors mode="On"`;
  generic error pages with a correlation ID, full detail only in server logs.
- Web server denies dotfiles, VCS dirs, backups, and `.map` under webroot (`location
  ~ /\.(git|svn|env)`), `autoindex off`.
- Management/actuator endpoints bound to an internal port, authenticated, and
  `exposure.include` limited to `health`; sensitive values masked.
- Build strips source maps (or ships them only to an internal store), removes
  `console.log`/comments/secrets from client bundles.
- Responses return only fields the client needs (DTO/serializer allowlist), no
  raw ORM objects, no internal IDs/paths/versions.

**Fails / not a real sanitizer:**
- Catching the exception but still returning `err.message`/`err.stack`/DB error
  text to the client (the message itself leaks schema/paths).
- `DEBUG=False` in one settings file while an env override or a second entrypoint
  re-enables it; or debug toggled by an attacker-settable header/param.
- Blocking `/.git/` directory listing but leaving `/.git/HEAD`, `/.git/config`,
  and pack files individually fetchable (**git-pack reconstruction**).
- Masking a secret in the UI but shipping it in the JSON/JS bundle or a `.map`.
- Requiring auth on `/actuator` but leaving `/actuator/heapdump` on a different
  path/port unauthenticated.
- "Removing" a comment/secret in the rendered HTML while it persists in a cached
  or minified bundle.

## 6. Detection methodology

1. **Find debug/verbose-error config:**
   ```
   rg -n 'DEBUG\s*=\s*True|debug\s*=\s*True|consider_all_requests_local|show_exceptions|customErrors\s+mode="Off"|FLASK_ENV|NODE_ENV'
   rg -n 'err\.stack|err\.message|printStackTrace|traceback\.format_exc|\.getStackTrace\(\)' 
   ```
2. **Find exposed artifacts & missing deny rules:**
   ```
   rg -n 'autoindex\s+on|Options\s+.*Indexes'
   rg -n '\.git|\.svn|\.env|\.bak|\.old|\.swp|\.DS_Store|\.map'    # in webroot config / build output
   ```
3. **Find diagnostic/actuator endpoints:**
   ```
   rg -n 'actuator|heapdump|threaddump|/env|phpinfo|/debug|/metrics|management\.endpoints'
   ```
4. **Grep response bodies/bundles for leaks:**
   ```
   rg -n 'res\.(json|send)\(.*(stack|sql|password|token|secret)|<!--.*(pass|secret|todo|key)'
   rg -n 'sourceMappingURL|\.js\.map'
   ```
5. **Classify the payoff:** does the leak yield a live secret (`.env`, heapdump,
   `/actuator/env`) → high-impact `SECRET_LEAK` chain seed, or only internals
   (paths, versions, stack) → recon.
6. **Confirm reachability:** artifact/endpoint served under webroot to any client;
   error path triggerable by malformed input.

## 7. Modern & niche variants

- **XSSI / JSONP data leakage:** a sensitive JSON endpoint authenticated by
  cookies that can be included cross-origin via `<script src>` — if it is a JSONP
  callback, a top-level JS array/object, or assigns to a global, another origin
  reads the authenticated data despite SOP (pre-CORS legacy leak). Cross-ref
  `cors-misconfiguration`.
- **Git-pack reconstruction:** even with directory listing off, fetching
  `/.git/HEAD`, `/config`, `/index`, and `objects/pack/*` reconstructs the full
  source tree and history (often including committed secrets).
- **Heapdump credential mining:** `/actuator/heapdump` downloads a full JVM heap;
  strings/OQL over it recover DB passwords, API keys, session tokens, and JWT
  signing keys — a direct `SECRET_LEAK` and a strong chain seed.
- **Source-map exposure:** `.map` files de-minify the bundle, exposing internal
  API routes, feature flags, and occasionally embedded keys/comments.
- **GraphQL introspection:** `__schema` enabled in production reveals every type,
  hidden mutation, and field — recon for BFLA/IDOR. Cross-ref the GraphQL skill.
- **Verbose API error objects:** REST/GraphQL errors returning stack frames, SQL,
  file paths, or internal hostnames.
- **Debug-console RCE:** Werkzeug/Flask interactive debugger reachable in prod is
  not just disclosure — the console executes Python (PIN is bypassable), so treat
  it as `CODE_EXEC`-adjacent and escalate severity accordingly.

## 8. Common false positives

- A generic error page returning only a correlation ID and no internals.
- `.map` files intentionally served for a public, non-sensitive static site with
  no secrets/internal routes in the bundle.
- `/actuator/health` (liveness) exposed alone with values masked.
- Internal IDs that are random/opaque and non-enumerable with no authz meaning
  (still check IDOR separately).
- Debug flag present only in a dev-only settings file never loaded in production
  (verify the effective runtime config).

## 9. Severity & exploitability

Base **Low/Info** for pure recon leaks (versions, paths, stack traces) per the
model. Raise to **High/Critical** when the leak is a live secret: exposed `.env`,
`/actuator/heapdump` or `/actuator/env`, git-reconstructed secrets, or a reachable
debug console (Werkzeug) that executes code. These are direct `SECRET_LEAK` (or
`CODE_EXEC`) chain seeds — the chain severity is the end impact of the leaked
credential (e.g. DB/cloud takeover). See `references/severity-model.md`.

## 10. Remediation

Disable debug and detailed errors in production (`DEBUG=False`, generic error
pages, log detail server-side only). Deny dotfiles, VCS directories, backups, and
source maps under the webroot and turn off directory listing. Bind management/
actuator endpoints to an internal network, authenticate them, and expose only
`health`; never expose `heapdump`/`env`. Strip secrets, comments, and source maps
from client bundles. Return response DTOs with an explicit field allowlist. Add
an anti-XSSI prefix (`)]}',\n`) or require a non-simple content-type / custom
header on sensitive JSON, and disable GraphQL introspection in production.

## 11. Output

Append each confirmed finding to **`findings/40-information-disclosure.md`** using
`references/finding-template.md`. Set `Class: Information Disclosure`, the specific
`CWE` (`CWE-209` verbose error, `CWE-215` debug info, `CWE-540` source/config,
`CWE-548` directory listing, `CWE-200` otherwise), and **`Reachable over: Web`**.
Because every case is web-reachable, include a **Burp-pasteable raw HTTP request**
per `references/burp-request-format.md` (e.g. `GET /.git/config`,
`GET /actuator/heapdump`, `GET /app.js.map`, or the malformed request that triggers
the stack trace), mark the injection/trigger point, and state the expected
indicator (leaked secret/stack/listing). Flag heapdump/`.env`/debug-console cases
as high-impact `SECRET_LEAK` chain seeds.

**Primitives (controlled):** provides `SECRET_LEAK`(stack traces, debug consoles,
`.git`/`.env`, heapdump, source maps, XSSI/JSONP); consumes none.

## References
- CWE-200, CWE-209, CWE-215, CWE-540, CWE-548; OWASP A01:2021 / A05:2021; OWASP
  Testing Guide (error handling, source-code disclosure); Spring Boot Actuator
  hardening; PortSwigger information-disclosure & XSSI research.
