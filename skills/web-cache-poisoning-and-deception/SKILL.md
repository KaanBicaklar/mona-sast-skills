---
name: web-cache-poisoning-and-deception
description: >-
  SAST detection methodology for web cache poisoning and web cache deception
  (CWE-524 / CWE-436), including unkeyed-header reflection, cache-key confusion,
  fat GET, and caching of authenticated content. Use when reviewing header
  reflection into responses, Cache-Control/Vary usage, or CDN/cache
  configuration. Writes confirmed findings to
  findings/31-web-cache-poisoning-and-deception.md.
---

# Web Cache Poisoning & Deception — SAST Methodology

**Class:** Web Cache Poisoning / Deception · **CWE-524 / CWE-436** · **OWASP:** A05 Security Misconfiguration
**Findings file:** `findings/31-web-cache-poisoning-and-deception.md`

## 1. Overview

Two related flaws exploit the gap between what a cache uses as its **key** and
what actually influences a response. **Cache poisoning:** an attacker sends
input that is *not part of the cache key* (an unkeyed header, cookie, or param)
but *is* reflected into a cacheable response — the poisoned response is then
served to every subsequent victim. **Cache deception:** an attacker tricks a
cache into storing a *sensitive authenticated* response under a URL the attacker
can later fetch (e.g. appending `.css` to `/account`). The core test: can
attacker-influenced content enter a response that the cache will store and
serve to others, or can a sensitive response be coerced into a public cache
entry? SAST review targets header reflection, `Cache-Control`/`Vary` usage, and
CDN/cache configuration.

## 2. Where it lives

- CDN / cache config: Varnish VCL, nginx `proxy_cache`, Cloudflare/Akamai/Fastly
  page rules, `Cache-Control`, `Vary`, `s-maxage`, cache-key definitions.
- Application code that reflects request headers into responses (canonical URLs,
  `Location`, absolute links, `<base href>`, self-referencing redirects).
- Framework "trusted proxy" / forwarded-host handling (`X-Forwarded-Host`,
  `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Original-URL`).
- Static-file / route mapping that decides what path suffixes are cached.
- Any endpoint returning per-user data that is nonetheless marked cacheable.

## 3. Sources (tainted input)

Attacker-controlled inputs that are typically **unkeyed** (ignored by the cache
key) yet influence the response: `X-Forwarded-Host`, `X-Forwarded-Scheme`/`-Proto`,
`X-Forwarded-Port`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`,
non-keyed cookies, and extra query/body params on a GET ("fat GET"). For
deception, the source is the **URL path/suffix** the attacker chooses
(`/profile.css`, `/profile;foo`, `/profile/..%2f`, `/profile%00.js`). Trace which
of these reach the response body/headers *and* whether the cache keys on them.

## 4. Sinks (dangerous operations)

The "sink" is the **caching layer storing a response influenced by unkeyed input**,
or a **sensitive path made cacheable**.

```python
# Flask — DANGEROUS: reflects X-Forwarded-Host into an absolute URL on a
# cacheable page; the header is unkeyed, so the poisoned link is served to all.
@app.route("/")
def home():
    host = request.headers.get("X-Forwarded-Host", request.host)
    resp = make_response(render_template("index.html",
        canonical=f"https://{host}/"))          # reflected, unkeyed source
    resp.headers["Cache-Control"] = "public, max-age=300"  # cached -> poisoned
    return resp
```
```javascript
// Express — DANGEROUS: builds asset/base URL from a forwarded header, cached.
app.get('/', (req, res) => {
  const host = req.get('X-Forwarded-Host') || req.hostname;
  res.set('Cache-Control', 'public, max-age=600');
  res.send(`<script src="https://${host}/app.js"></script>`); // XSS via poison
});
```
```nginx
# nginx — DANGEROUS cache key: keys only on path, ignores Host/forwarded headers
# and caches regardless of Authorization -> deception + poisoning surface.
proxy_cache_key "$request_uri";                 # no $http_host, no auth in key
location ~* \.(css|js|png|jpg)$ {               # suffix-based caching...
    proxy_cache STATIC;
    proxy_cache_valid 200 10m;                  # ...will cache /account.css too
}
```
```
# Fat GET — DANGEROUS if the app reads a body/param on GET that the cache ignores:
GET /home?utm=x HTTP/1.1        (cache keys on ?utm=x maybe, but not on...)
X-Forwarded-Host: evil.com      (...this unkeyed header that changes the body)
```
```
# Web cache deception — DANGEROUS route/suffix mapping:
GET /my-account/settings.css    -> app returns the authenticated HTML page,
                                   CDN caches it as a static .css publicly.
GET /api/user;background.js      -> path-parameter / matrix-param confusion.
```

## 5. Sanitizers / safe patterns

**Safe:** never reflect `X-Forwarded-*`/`Host` into a cacheable response unless
the value is validated against an allowlist of known hosts. Include every
request element that influences the body in the **cache key** (or add it to
`Vary`). Mark all per-user/authenticated responses `Cache-Control: private,
no-store` and ensure the CDN honors it (many ignore `private` unless configured).
For deception, make caching **content-type / route driven, not suffix driven** —
never cache a response whose `Content-Type` is `text/html` or that carries a
`Set-Cookie`/`Authorization`; normalize paths and reject `.css`/`.js` suffixes on
dynamic routes.

**Fails / not a real sanitizer:**
- Adding `Vary: X-Forwarded-Host` but the CDN strips/ignores `Vary` on some
  headers — still poisonable.
- Setting `Cache-Control: private` at the app while the CDN caches by file
  extension regardless (deception still works).
- Validating `Host` but not the *forwarded* variants the framework actually trusts.
- Keying on the full query string but leaving a header (`X-Forwarded-Scheme`,
  cookies, `Accept-Language`) unkeyed while it changes the body.
- Relying on `Cache-Control: no-cache` (which still allows storage + revalidation
  on some proxies) instead of `no-store`.

## 6. Detection methodology

1. **Find header reflection into responses:**
   ```
   rg -in 'X-Forwarded-Host|X-Forwarded-Proto|X-Forwarded-Scheme|X-Host|X-Original-URL|X-Rewrite-URL|Forwarded' 
   rg -in 'request\.host|req\.hostname|getHeader\(.?host|HTTP_X_FORWARDED|SERVER_NAME|url_for.*_external'
   ```
2. **Find cacheable responses & their controls** (config-file inspection required):
   ```
   rg -in 'Cache-Control|s-maxage|max-age|Surrogate-Control|Vary|Expires|no-store|private'
   rg -in 'proxy_cache|proxy_cache_key|fastcgi_cache|beresp\.ttl|hash_data|sub vcl_hash|CDN-Cache' -g '*.conf' -g '*.vcl'
   ```
3. **Correlate:** is any reflected unkeyed input on a route that also sets a
   *public/shared* cache directive? That intersection is the poisoning bug.
4. **Check the cache key definition:** does it include Host/forwarded headers,
   cookies, and all body-influencing params? Anything influential but unkeyed is
   the poisoning vector.
5. **Check deception surface:** are static assets cached by **suffix/extension**
   or path prefix? Can a sensitive dynamic route be reached with an appended
   `.css`/`.js`/`;x`/`%00`, and does the app still return the sensitive body?
   ```
   rg -in 'location ~\*|\.css|\.js|static|StaticFiles|express\.static|send_static' -g '*.conf'
   ```
6. **Confirm reachability & shared cache:** is the cache shared across users
   (CDN/reverse proxy), not a private browser cache? Only shared caches poison.

## 7. Modern & niche variants

- **Unkeyed header reflection:** `X-Forwarded-Host`/`-Scheme` reflected into
  absolute links, redirects, `<base>`, or imported script URLs → stored XSS or
  redirect to attacker infra, served from cache to all users.
- **Cache-key confusion / normalization:** cache and origin normalize the URL
  differently (case, trailing slash, `%2f`, dup params) so the attacker poisons a
  key victims will hit.
- **Fat GET:** origin reads a request body or extra param on a GET that the cache
  excludes from its key — poison stored under the clean key.
- **Web cache deception:** append `.css`/`.js`/`.jpg`, add a path parameter
  (`;foo`), or use path traversal so a CDN caches an *authenticated* page under a
  public, attacker-fetchable URL.
- **CDN/Vary misconfig:** `Cache-Control: private`/`no-store` ignored by the CDN,
  or `Vary` omitted, causing authenticated content to be cached and cross-served.
- **Unkeyed cookie / port / Accept-Language:** less-obvious unkeyed inputs that
  still change the body.

## 8. Common false positives

- Reflected header on a response explicitly marked `no-store`/`private` *and* the
  CDN is confirmed to honor it.
- Private (browser-only) cache with no shared/CDN layer — no cross-user impact.
- Reflected value passed through strict host allowlist validation.
- Suffix-based caching on routes that only ever serve genuinely static, public files.
- `Vary` correctly enumerates every influential header and the CDN honors it.

## 9. Severity & exploitability

Base **Medium–High**. **High/Critical** when poisoning injects executable content
(XSS via reflected script/host) served to all users, or when deception exposes
session tokens / PII / CSRF tokens of authenticated victims. **Medium** for
redirect-to-attacker or defacement without script execution. Lower if only a
private cache is involved or the CDN provably strips the vector. See
`references/severity-model.md`.

## 10. Remediation

Validate or drop `X-Forwarded-*`/`Host` before reflecting; add every
body-influencing input to the cache key or `Vary`. Mark authenticated/per-user
responses `no-store` and verify the CDN honors it. Drive caching by content-type
and explicit route allowlists, not file-extension suffixes; normalize paths and
reject static suffixes on dynamic endpoints. Confirm CDN and origin normalize
URLs identically.

## 11. Output

Append each confirmed finding to
**`findings/31-web-cache-poisoning-and-deception.md`** using
`references/finding-template.md`. Set `Class: Web Cache Poisoning / Deception`,
`CWE: CWE-524` (deception) or `CWE-436` (interpretation conflict/poisoning), and
in **Chain potential** note primitives such as *reflected/stored content served
to all users* (→ mass XSS, consumes an XSS payload), *forced redirect to attacker
host* (→ combine with open-redirect/OAuth chains), *cached authenticated data*
(→ session/PII disclosure), and *consumes a request-smuggling primitive* (a
smuggled request is a classic poisoning delivery vector).

**Primitives (controlled):** provides `CACHE_CONTROL`; consumes `HTML_OUTPUT`

## References
- CWE-524 (Use of Cache Containing Sensitive Information); CWE-436 (Interpretation
  Conflict); OWASP A05:2021; PortSwigger Web Cache Poisoning & Web Cache Deception
  research.
