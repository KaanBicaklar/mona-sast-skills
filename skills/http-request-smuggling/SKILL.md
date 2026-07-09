---
name: http-request-smuggling
description: >-
  SAST detection methodology for HTTP request smuggling / desync (CWE-444),
  including CL.TE, TE.CL, TE.TE obfuscation, HTTP/2 downgrade smuggling (h2c,
  H2.CL/H2.TE), and client-side desync. Use when reviewing custom HTTP
  parsing/forwarding code or reverse-proxy/gateway configuration. Writes
  confirmed findings to findings/30-http-request-smuggling.md.
---

# HTTP Request Smuggling — SAST Methodology

**Class:** HTTP Request Smuggling · **CWE-444** · **OWASP:** A05 Security Misconfiguration
**Findings file:** `findings/30-http-request-smuggling.md`

## 1. Overview

Request smuggling occurs when two HTTP agents in a chain (front-end proxy/CDN and
back-end server) disagree on where one request ends and the next begins. An
attacker crafts a request whose body is interpreted by the back-end as the start
of a *second* request, poisoning the connection for the next victim. The core
test: does any agent in the chain forward a request with **ambiguous message
length** — both `Content-Length` and `Transfer-Encoding`, a malformed `TE`, or a
downgraded HTTP/2 request — instead of rejecting it? This is partly an
infrastructure issue; SAST review focuses on custom parsing/forwarding code and
on proxy/gateway configuration.

## 2. Where it lives

- Reverse-proxy / gateway config: nginx, HAProxy, Envoy, Apache `mod_proxy`,
  Traefik, AWS ALB/CloudFront, Akamai — anywhere a front-end forwards to a back-end.
- Custom HTTP parsers or servers (raw socket handling, hand-rolled framing,
  header-length calculation) in Go, Node, Python, Java, Rust.
- Application code that reads/rewrites `Content-Length` or `Transfer-Encoding`,
  or that buffers and re-emits requests (WAFs, API gateways, service meshes).
- HTTP/2 front-ends that downgrade to HTTP/1.1 for an upstream (h2c cleartext
  upgrade, ALB→target, service-to-service).
- Middleware that concatenates or rebuilds requests before forwarding.

## 3. Sources (tainted input)

The tainted input is the **raw request framing** an attacker controls: the
`Content-Length` and `Transfer-Encoding` headers, header names/values with
obfuscated whitespace or duplicated fields, chunk-size lines, and (for HTTP/2)
pseudo-headers and the `:authority`/content-length mismatch. Unlike a value flaw,
the danger is the *structural interpretation*, so trace how each agent computes
message length, not just a variable.

## 4. Sinks (dangerous operations)

The "sink" is the **parsing / forwarding / length-computation layer** that
resolves an ambiguous request instead of rejecting it.

```nginx
# nginx — DANGEROUS: proxy_pass to a back-end that disagrees on framing,
# with request buffering off and no rejection of conflicting length headers.
location / {
    proxy_pass http://backend;          # front-end + back-end may parse TE/CL differently
    proxy_http_version 1.0;             # downgrades; back-end may still honor TE
    # no explicit rejection of duplicate/ambiguous length headers
}
```
```haproxy
# HAProxy — DANGEROUS on old versions / relaxed parsing
defaults
    option accept-invalid-http-request   # accepts malformed framing -> smuggling
    # (fixed by 'option httpchk' strictness + h1-case-adjust hardening)
```
```go
// Go — DANGEROUS custom proxy: trusting client Content-Length while a chunked
// body is present, or forwarding both headers unchanged.
func forward(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)                 // length from CL, ignores TE
    req, _ := http.NewRequest(r.Method, upstream, bytes.NewReader(body))
    for k, v := range r.Header { req.Header[k] = v } // copies TE + CL verbatim
    http.DefaultClient.Do(req)                     // upstream may prefer TE -> desync
}
```
```
# TE.TE obfuscation — DANGEROUS if one agent ignores the malformed TE and the
# other honors it:
Transfer-Encoding: chunked
Transfer-Encoding : chunked        (space before colon)
Transfer-Encoding: xchunked
Transfer-Encoding:\tchunked        (tab)
X: X\nTransfer-Encoding: chunked   (header injection into TE)
```
```
# HTTP/2 downgrade (H2.CL / H2.TE) — DANGEROUS: front-end speaks h2, rewrites to
# h1 for upstream but keeps an attacker-supplied content-length / te header.
:method POST      :path /       content-length: 0
transfer-encoding: chunked      <-- smuggled once downgraded to HTTP/1.1
```

## 5. Sanitizers / safe patterns

**Safe:** reject any request that presents **both** `Content-Length` and
`Transfer-Encoding` (RFC 7230 §3.3.3 — treat as invalid, return 400 and close the
connection). Prefer `Transfer-Encoding: chunked` and strip/ignore `Content-Length`
when both are present, but *consistently across every hop*. Use a single,
well-tested HTTP library on both sides; normalize headers at the edge; disable
connection reuse to the back-end (or use HTTP/2 end-to-end) to prevent socket
poisoning. For HTTP/2 front-ends, validate `content-length` against the actual
DATA frame length and refuse to emit a `Transfer-Encoding` header on downgrade.

**Fails / not a real sanitizer:**
- Front-end and back-end using *different* HTTP stacks with different tolerance
  (the classic desync — each is "compliant" but they disagree).
- Rejecting only the exact string `Transfer-Encoding: chunked` while honoring
  obfuscated variants (`xchunked`, leading space, tab, duplicated header).
- Downgrading HTTP/2→HTTP/1.1 while faithfully copying client-supplied length
  headers (H2.CL/H2.TE) — the front-end must regenerate framing.
- A WAF that inspects the first request but not the smuggled prefix.
- Keeping upstream keep-alive connections pooled across users (turns any framing
  discrepancy into cross-user poisoning).

## 6. Detection methodology

1. **Map the chain:** identify every hop (CDN → proxy → app). Smuggling needs at
   least two agents; a single server rarely smuggles against itself.
2. **Inspect proxy/gateway config** — code alone is insufficient here:
   ```
   rg -n 'proxy_pass|proxy_http_version|proxy_request_buffering|merge_slashes' -g '*.conf' -g 'nginx*'
   rg -n 'accept-invalid-http-request|option http-|h1-case-adjust|http-reuse' -g 'haproxy*'
   rg -n 'proxyProtocol|http2|allowChunkedLength|max_http_header|downstream_.*http' -g '*envoy*' -g '*.yaml'
   ```
3. **Find custom framing code:**
   ```
   rg -in 'transfer-encoding|content-length|chunked|read.*chunk|http1|http/1\.0' --type go --type js --type py --type java
   rg -in 'io.ReadAll\(r.Body\)|request.buffer|rawRequest|socket.*recv|parseHeaders'
   ```
4. **Check length resolution:** when both CL and TE are present, does the code
   reject, or pick one? Does it forward headers verbatim to an upstream?
5. **Check HTTP/2 downgrade:** does a front-end terminate h2 and re-emit h1 while
   preserving client `content-length`/`transfer-encoding`? Look for h2c upgrade
   handling and ALB/gateway→HTTP/1.1 targets.
6. **Check connection reuse:** is the upstream connection pooled across clients?
   Poolable + ambiguous framing = exploitable. Note client-side desync if the
   *front-end* can be desynced against the victim's own browser.

## 7. Modern & niche variants

- **CL.TE:** front-end uses `Content-Length`, back-end uses `Transfer-Encoding`.
  The back-end sees a smuggled request in the leftover chunked body.
- **TE.CL:** front-end uses `Transfer-Encoding`, back-end uses `Content-Length`.
  Reverse of the above; often needs a crafted final chunk.
- **TE.TE:** both support `Transfer-Encoding` but one is tricked into ignoring an
  *obfuscated* TE header (leading space/tab, `xchunked`, duplicated header,
  embedded newline) — the core of most modern smuggles.
- **HTTP/2 downgrade smuggling (H2.CL / H2.TE):** h2 front-end rewrites to h1 for
  an upstream, carrying an attacker-controlled `content-length` or
  `transfer-encoding` that only becomes ambiguous after downgrade. Includes
  **h2c** cleartext upgrade smuggling.
- **Client-side desync:** the front-end itself can be desynced so the victim's
  *browser* poisons its own connection (no back-end disagreement needed) — often
  via a POST whose body is treated as a new request.
- **Header-normalization discrepancies:** front-end and back-end normalize header
  names/whitespace/duplicates differently (case folding, line folding, `\r`
  vs `\r\n`), producing framing disagreement.

## 8. Common false positives

- Single-server deployments with one HTTP stack end-to-end (no second agent to
  disagree) and no upstream forwarding.
- Modern proxy versions that already reject dual `CL`/`TE` and close the
  connection by default (check the pinned version, not just the product).
- HTTP/2 end-to-end with no downgrade hop.
- Code that reads the body but rebuilds framing from scratch for the upstream
  (regenerates `Content-Length`, strips `Transfer-Encoding`).

## 9. Severity & exploitability

Base **High**: smuggling enables request hijacking, cache poisoning, auth-header
capture, WAF bypass, and cross-user response leakage. **Critical** when it yields
credential/session capture from other users, admin-endpoint access, or feeds a
cache-poisoning primitive affecting all clients. Lower if only reachable with an
unusual non-default proxy config or a single-hop deployment. See
`references/severity-model.md`.

## 10. Remediation

Normalize and validate request framing at the edge: reject requests carrying both
`Content-Length` and `Transfer-Encoding`, reject obfuscated `Transfer-Encoding`,
and return 400 + close the connection. Use HTTP/2 end-to-end where possible; when
downgrading, regenerate framing rather than copying client headers. Use one
hardened, up-to-date HTTP stack across all hops and disable ambiguous
back-end connection reuse. Do not rely on a WAF as the sole control.

## 11. Output

Append each confirmed finding to **`findings/30-http-request-smuggling.md`** using
`references/finding-template.md`. Set `Class: HTTP Request Smuggling`,
`CWE: CWE-444`, and in **Chain potential** note primitives such as *request
hijack / cross-user response capture* (→ session/credential theft),
*cache-poisoning primitive* (consumed by web-cache-poisoning), *WAF/auth bypass*
(→ reach otherwise-blocked sinks like SQLi/SSRF), and *client-side desync*
(→ stored-XSS-like impact in the victim's browser).

**Primitives (controlled):** provides `AUTHZ_BYPASS`,`CACHE_CONTROL`,`SECRET_LEAK` (request capture); consumes none

## References
- CWE-444 (HTTP Request/Response Smuggling); OWASP A05:2021; RFC 7230 §3.3.3;
  PortSwigger HTTP Request Smuggling & HTTP/2 desync research.
