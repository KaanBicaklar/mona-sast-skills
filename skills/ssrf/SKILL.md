---
name: ssrf
description: >-
  SAST detection methodology for Server-Side Request Forgery (CWE-918),
  including blind/OOB SSRF, DNS rebinding, cloud-metadata credential theft
  (169.254.169.254), redirect-following and protocol-smuggling bypasses
  (gopher/file/dict), URL-parser confusion, and encoding/allowlist bypasses.
  Use when reviewing code that fetches a URL or opens a connection whose target
  is influenced by input. Writes confirmed findings to findings/24-ssrf.md.
---

# Server-Side Request Forgery — SAST Methodology

**Class:** SSRF · **CWE-918** · **OWASP:** A10 Server-Side Request Forgery
**Findings file:** `findings/24-ssrf.md`

## 1. Overview

SSRF occurs when attacker-controlled data determines the destination of a request
the *server* makes — the host, port, scheme, or any component that resolves to a
network endpoint. The server becomes a proxy into places the attacker cannot
reach directly: the loopback interface, internal services, the cloud metadata
endpoint, or arbitrary external hosts. The core test: does a source value control
(any part of) the target of an outbound request, and is the **final resolved
destination** constrained by an allowlist enforced *at connection time*? Anything
weaker — string checks, blocklists, validating a URL that is then redirected or
re-resolved — is bypassable.

## 2. Where it lives

- Any "fetch this URL for me" feature: webhooks, import-from-URL, avatar/logo-from-
  URL, RSS/feed readers, link previews / URL unfurling, OAuth/OIDC discovery and
  JWKS fetch, SSO/SAML metadata loaders, remote-file mirrors.
- Document/media renderers that dereference URLs: PDF/HTML-to-PDF (wkhtmltopdf,
  headless Chrome/Puppeteer), image proxies and thumbnailers, SVG rasterizers,
  XSLT/XML processors (overlaps XXE), office-doc converters.
- Server-side HTTP clients driven by config the user can set (webhook target,
  callback URL, proxy host, S3-compatible endpoint).
- "Health check", "test connection", and open-proxy/gateway endpoints.

## 3. Sources (tainted input)

All HTTP inputs, but especially any field that *is* or *becomes* a URL/host/port:
`?url=`, JSON body URLs, webhook/callback config, `Location`-style redirect
targets, a hostname assembled from parts. **Second-order** is common and
high-miss: a webhook URL or avatar URL stored at configuration time and fetched by
a background job later — trace the stored value back to its write. Also indirect:
a filename or ID that is concatenated into an internal URL, or a `Host`/`X-
Forwarded-Host` header reflected into a server-side fetch.

## 4. Sinks (dangerous operations)

```python
# Python — dangerous
requests.get(user_url)                          # host fully attacker-controlled
urllib.request.urlopen(url)                     # also honors file://, ftp://
httpx.get(url, follow_redirects=True)           # redirect can jump to 169.254.169.254
requests.get(url, allow_redirects=True)         # validate-then-redirect bypass
```
```javascript
// Node — dangerous
await fetch(req.query.url);                      // no destination allowlist
axios.get(userUrl);                              // follows redirects by default
http.get(new URL(target));                       // SSRF into internal services
require('request')({ url: target, followRedirect: true });
```
```java
// Java — dangerous
new URL(userUrl).openConnection().getInputStream();
restTemplate.getForObject(userUrl, String.class);      // follows redirects
HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(u)).build(), ...);
```
```go
// Go — dangerous
http.Get(userURL)                                // default client follows redirects
```
```php
// PHP — dangerous
file_get_contents($_GET['url']);                 // wrappers: php://, file://, gopher://
curl_setopt($ch, CURLOPT_URL, $_GET['url']);     // + CURLOPT_FOLLOWLOCATION
```

Dangerous whenever the host/URL is source-derived and the client will connect to
whatever it resolves to — including after a redirect, and including non-`http`
schemes (`file://`, `gopher://`, `dict://`, `ftp://`) that some clients accept.

## 5. Sanitizers / safe patterns

**Safe:**
- **Allowlist the destination host**, and enforce it against the **resolved IP at
  connection time**, not the URL string. Resolve the hostname once, reject the IP
  if it is private/loopback/link-local/reserved (`127.0.0.0/8`, `10/8`,
  `172.16/12`, `192.168/16`, `169.254/16`, `::1`, `fc00::/7`, `0.0.0.0`), then
  connect to *that pinned IP* so the name cannot re-resolve (defeats DNS
  rebinding).
- Restrict the scheme to `http`/`https` only; forbid redirects, or re-validate the
  target on every hop.
- Route outbound fetches through a dedicated egress proxy / isolated network with
  no route to metadata or internal ranges; disable the cloud metadata endpoint or
  require IMDSv2 (session-token) so a bare GET fails.
- Prefer a mapping table (user picks an ID → server holds the real URL) over
  fetching a raw user URL at all.

**Fails / not a real sanitizer:**
- **Blocklisting hostnames/IPs by string** — bypassed by `127.0.0.1` alternates:
  decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`, `0`, `[::]`,
  `127.1`, enclosed-alphanumeric/Unicode digits, and `localtest.me`-style names
  that resolve to loopback.
- **Validate-then-fetch with redirects on** — the URL passes the check, then a
  `302` sends the client to `http://169.254.169.254/`. TOCTOU.
- **DNS rebinding** — the name resolves to a public IP during validation, then to
  `169.254.169.254`/internal at connection time (low TTL). Any design that
  resolves twice is vulnerable.
- **Parser confusion** — the validator and the HTTP client disagree on the host.
  `http://expected.com@169.254.169.254/`, `http://169.254.169.254#@expected.com/`,
  `http://expected.com\@evil`, backslash/whitespace tricks; one library reads the
  host as `expected.com`, the other connects to the attacker's host.
- **Allowlist by substring** (`if "expected.com" in url`) — `expected.com.evil.tld`
  or `evil.tld/expected.com` passes.

## 6. Detection methodology

1. **Find sinks:** grep for outbound HTTP/URL-open APIs.
   ```
   rg -n 'requests\.(get|post|put|head|request)\(|urlopen\(|httpx\.|urllib'
   rg -n 'fetch\(|axios\.|http\.get\(|https\.get\(|got\(|\brequest\(' 
   rg -n 'new URL\(|openConnection|HttpClient|RestTemplate|WebClient|http\.Get\('
   rg -n 'file_get_contents\(|curl_setopt|CURLOPT_URL|fopen\(|fsockopen'
   ```
2. **Confirm the target is source-derived:** is the URL/host argument a variable
   traceable to request input or stored config, not a constant?
3. **Trace redirect and re-resolution behavior:** does the client follow redirects?
   Is the host resolved separately from where the connection actually goes?
4. **Check for a real destination control:** allowlist enforced on the resolved IP
   at connect time? Or only string checks / blocklists (see §5)?
5. **Confirm reachability:** exposed route/webhook/job; pre-auth? Note whether the
   response is returned to the attacker (in-band) or not (blind).
6. **Classify:** in-band vs blind/OOB; reachable targets (loopback, internal
   range, metadata); usable non-http schemes.

## 7. Modern & niche variants

- **Blind / OOB SSRF:** the response is never returned. Still fully exploitable —
  confirm via out-of-band interaction (attacker-controlled DNS/HTTP callback) and
  exploit timing/side effects. Common in webhook, PDF-render, and background-fetch
  paths. Do not dismiss because "the output isn't shown."
- **DNS rebinding (TOCTOU on resolution):** validation resolves the hostname to a
  benign IP; the HTTP client re-resolves (low TTL) to `169.254.169.254` or an
  internal IP at connection time. The fix is to resolve once and connect to the
  pinned IP — flag any validate-then-connect design that resolves twice.
- **Cloud metadata → credentials (the key chain):** `http://169.254.169.254/…`
  on AWS IMDSv1 returns temporary IAM credentials
  (`/latest/meta-data/iam/security-credentials/<role>`); GCP requires header
  `Metadata-Flavor: Google` at `metadata.google.internal`; Azure uses
  `169.254.169.254/metadata/instance?api-version=…` with `Metadata: true`.
  SSRF that reaches these turns into **stolen cloud credentials** → full account
  pivot. This is why metadata reachability elevates severity to Critical.
- **Redirect-following bypass:** the URL is validated but the client follows a
  `30x` to an internal/metadata host. Disable redirects or re-validate each hop.
- **Protocol smuggling:** clients that honor `gopher://`, `file://`, `dict://`,
  `ftp://` let the attacker read local files (`file:///etc/passwd`) or craft raw
  TCP payloads. `gopher://127.0.0.1:6379/_…` speaks the Redis line protocol
  (write keys, schedule cron → RCE); `dict://`/`gopher://` also hit unauthenticated
  internal services (Memcached, Elasticsearch, internal HTTP).
- **URL-parser confusion:** validator and fetcher disagree on the host —
  `user@host`, `#`/`?` fragment tricks, backslashes, embedded whitespace/tabs, and
  differing WHATWG-vs-RFC parsing. A prime allowlist bypass.
- **Encoding bypasses for the host:** decimal/octal/hex IP forms, `0x7f.1`,
  IPv6 `[::ffff:127.0.0.1]` and `[::1]`, IPv4-mapped IPv6, enclosed-alphanumeric
  and Unicode digit look-alikes, and short forms (`127.1`, `0`).
- **Allowlist bypass via `@`/`#`/`?`:** `https://allowed.com@attacker/`,
  `https://attacker/#allowed.com`, `https://attacker/?x=allowed.com` — the
  attacker's host is the real authority while the check sees `allowed.com`.
- **Feature-driven SSRF:** webhooks, PDF/HTML renderers, image proxies, import-
  from-URL, SVG (external `<image href>`/`xlink`), and link previews are the most
  common real-world entry points — each fetches a URL by design.

## 8. Common false positives

- The target host is a hard-coded constant or selected from a fixed server-side
  map (user only picks an ID).
- Fetch is confined to a dedicated egress proxy with no route to internal ranges
  or metadata, verified in config.
- Destination is allowlisted **and** enforced on the resolved IP at connect time
  with redirects disabled.
- Client library restricted to `https` to a single external SaaS with pinned host.

## 9. Severity & exploitability

Base **High** (reaching internal services). **Critical** when it reaches cloud
metadata and yields credentials (metadata → creds → account pivot), enables
protocol smuggling to an unauthenticated internal service (Redis/gopher → RCE), or
is pre-auth. Blind SSRF keeps High if internal reachability is proven. Lower to
**Medium** when egress is provably confined to an isolated network with no
sensitive internal targets. See `references/severity-model.md`.

## 10. Remediation

Do not fetch raw user URLs — map an ID to a server-held URL where possible. Where a
URL must be fetched: enforce a strict destination allowlist against the **resolved
IP at connection time**, pin that IP for the actual connection (defeat rebinding),
restrict schemes to `http`/`https`, and disable or re-validate redirects. Isolate
outbound fetches on a network with no route to internal ranges or metadata, and
require IMDSv2. Never rely on hostname blocklists or string checks.

## 11. Output

Append each confirmed finding to **`findings/24-ssrf.md`** using
`references/finding-template.md`. Set `Class: SSRF`, `CWE: CWE-918`, and in
**Chain potential** name primitives such as *internal service access* (→ pivot to
unauthenticated internal APIs), *cloud credential theft* (metadata → IAM creds,
provides leaked-credentials for privilege-escalation/lateral chains), *arbitrary
file read* (`file://`), and *internal RCE* (`gopher://` → Redis). Note whether the
finding **consumes** an open-redirect or allowlist-bypass primitive from another
finding.

**Primitives (controlled):** provides `OUTBOUND_REQUEST`,`SECRET_LEAK` (metadata),`FILE_READ` (`file://`); consumes `URL_CONTROL` (redirect/allowlist bypass)

## References
- CWE-918 Server-Side Request Forgery; OWASP A10:2021 SSRF; OWASP SSRF Prevention
  Cheat Sheet; cloud provider IMDS hardening guides (AWS IMDSv2, GCP/Azure
  metadata headers).
