---
name: crlf-and-header-injection
description: >-
  SAST detection methodology for CRLF and header injection (CWE-93, CWE-113,
  CWE-117), including HTTP response splitting, Location/Set-Cookie header
  injection, log forging, SMTP/email (BCC) header injection, and Host header
  injection. Use when reviewing code that writes user input into HTTP headers,
  redirects, log lines, or email envelopes. Writes confirmed findings to
  findings/08-crlf-and-header-injection.md.
---

# CRLF & Header Injection — SAST Methodology

**Class:** CRLF / Header Injection · **CWE-93** · **OWASP:** A03 Injection
**Findings file:** `findings/08-crlf-and-header-injection.md`

## 1. Overview

CRLF injection occurs when attacker-controlled data containing carriage-return
(`\r`, `%0d`) and line-feed (`\n`, `%0a`) sequences reaches a sink that treats
newlines as protocol delimiters — HTTP headers, log lines, or SMTP envelopes.
The core test: does a source value flow into a header/redirect/log/mail sink
without stripping or rejecting `\r`/`\n` (and their encoded forms)? A single
injected CRLF lets an attacker append headers, split a response into a second
attacker-controlled response (CWE-113 response splitting), forge log entries
(CWE-117), or inject extra mail recipients.

## 2. Where it lives

- Redirect helpers seeded from user input: `Location:` built from `?next=`,
  `?url=`, `?returnTo=`.
- Cookie writers echoing user data into `Set-Cookie` (session, locale, tracking).
- Custom header echoes: reflecting `X-Request-Id`, filename in
  `Content-Disposition`, CORS `Access-Control-Allow-Origin` from `Origin`.
- Logging pipelines that concatenate raw request fields into a log line.
- Email senders that place user input into `To`/`From`/`Subject`/`Cc`/`Bcc`.
- Reverse-proxy / gateway config that forwards `Host` or `X-Forwarded-Host`
  into downstream URLs, password-reset links, or cache keys.

## 3. Sources (tainted input)

All HTTP inputs (query/body/path/**header**/cookie), with headers being a
first-class source here: `Host`, `Referer`, `X-Forwarded-*`, `User-Agent`,
`Origin`, `Content-Disposition` filenames. **Second-order:** a username, display
name, or filename stored earlier and later emitted into a header, redirect, log,
or email. Trace stored values back to their original write source.

## 4. Sinks (dangerous operations)

```java
// Java — dangerous
response.setHeader("Location", request.getParameter("next"));   // response splitting
response.sendRedirect(userUrl);                                  // no CRLF filter (old containers)
response.addCookie(new Cookie("locale", request.getParameter("loc")));
response.addHeader("X-Trace", req.getHeader("X-Request-Id"));
logger.info("login for user=" + username);                      // CWE-117 log forging
```
```javascript
// Node — dangerous
res.setHeader('Location', req.query.next);        // Node throws on \n since ~v6, but
res.writeHead(302, { Location: req.query.url });  // custom raw writers / old libs don't
res.setHeader('Set-Cookie', 'lang=' + req.query.lang);
logger.info(`request from ${req.headers['user-agent']}`);   // log injection
```
```python
# Python — dangerous
self.send_header("Location", environ["QUERY_STRING"])   # raw wsgi/http.server
response['X-Filename'] = request.GET['name']            # Django header from input
logging.info("user %s logged in" % username)            # log forging → parser exploits
msg['To'] = request.form['email']                       # email header injection
```
```php
// PHP — dangerous
header("Location: " . $_GET['url']);        # header() blocks \n since 5.1.2, but
header("X-Lang: " . $_GET['lang']);         # older/patched builds and raw fwrite() do not
mail($to, $subject, $body,                  # $_POST['email'] → Cc/Bcc injection
     "From: " . $_POST['email']);
```

Dangerous whenever the value can carry a raw or decoded `\r\n`. Even where a
runtime blocks bare `\n` in HTTP headers today, the same value is unsafe in
logs, email envelopes, and any custom/raw socket writer.

## 5. Sanitizers / safe patterns

**Safe:** reject or strip all of `\r`, `\n`, `%0d`, `%0a`, `%0D`, `%0A`, and null
bytes **before** the value reaches the sink; better, allowlist the value (e.g.
resolve `?next=` against a fixed set of relative paths, or validate it is a
same-site relative path with no scheme/host). For redirects, prefer a mapping
table (key → known URL) over echoing the raw URL. For `Host`, validate against a
configured allowlist of expected hostnames. For logs, use structured/JSON logging
so newlines are encoded as data, not row separators. For email, use a library
that builds MIME headers via typed setters (`msg['To'] = Address(...)`).

**Fails / not a real sanitizer:**
- Stripping `\n` but not `\r` (or vice versa) — many parsers accept a lone `\r`
  or `\n` as a line terminator.
- Filtering the literal bytes but not the URL-encoded/double-encoded forms
  (`%0d`, `%250a`) when the sink decodes later.
- Relying on the runtime "already blocks header injection" — true only for the
  HTTP-header sink on modern versions, not for logs, email, or raw writers.
- Trimming only leading/trailing whitespace (`trim()`), which leaves interior
  CRLF intact.
- Allowlisting the redirect host but ignoring userinfo/`\`/backslash tricks that
  some URL parsers treat as host separators.

## 6. Detection methodology

1. **Find sinks:** grep for header/redirect/cookie/log/mail writers.
   ```
   rg -n 'setHeader\(|addHeader\(|sendRedirect\(|writeHead\(|send_header|header\s*\(|addCookie\(|Set-Cookie'
   rg -n 'response\[|res\.setHeader|res\.writeHead|redirect\(|Location'
   rg -n 'logger\.(info|warn|error|debug)\(|logging\.(info|warning|error)\(|log\.Print'
   rg -n "mail\(|smtplib|MimeMessage|['\"](To|Cc|Bcc|From|Subject)['\"]\s*[:=]"
   ```
2. **Confirm the value is concatenated/interpolated** from a variable into the
   header/redirect/log/mail argument (not a constant).
3. **Trace the operand to a source:** request param, header, cookie, or a stored
   value (second-order). Stop at a literal/constant.
4. **Check for a real neutralizer on the path:** is `\r`/`\n` (and encoded forms)
   stripped or the value allowlisted before the sink? Verify it is not one of the
   broken patterns in §5.
5. **Confirm reachability:** exposed route/handler, reachable (pre-auth?).
6. **Classify the impact:** response splitting/header injection (HTTP), log
   forging (CWE-117), email header injection (BCC), or Host-header poisoning.

## 7. Modern & niche variants

- **HTTP response splitting (CWE-113):** injected CRLF plus a second set of
  headers and a body creates a fully attacker-controlled second response —
  historically used for cache poisoning and reflected XSS via the split body.
  Rare on modern app servers but alive in raw socket writers, custom gateways,
  and legacy containers.
- **Location / Set-Cookie header injection:** the most common live variant —
  `next=/%0d%0aSet-Cookie:%20session=attacker` fixes a session, or injects a
  `Location` plus `Content-Length: 0` to split the response.
- **Log injection / log forging (CWE-117):** newlines in a logged field forge
  fake log lines (spoof a successful login, hide traces). This is also a **pivot
  primitive**: forged content that a downstream log parser, SIEM rule, or
  templating log appender interprets can escalate — e.g. a Log4Shell-style
  `${jndi:ldap://...}` payload landing in a Log4j-formatted message turns log
  injection into RCE. Flag any path where an unsanitized field reaches a lookup-
  enabled log formatter.
- **SMTP / email header injection (BCC injection):** a `\n` in a user-supplied
  `From`/`Subject` field lets an attacker append `Bcc:` recipients or inject a
  new body — turning a contact form into an open spam relay or exfiltration
  channel. PHP `mail()` additional-headers and hand-built MIME are classic sites.
- **Host header injection:** a forged `Host`/`X-Forwarded-Host` that the app
  reflects into absolute URLs poisons password-reset links (account takeover),
  web-cache keys, and `<base>`-derived resource URLs. Especially dangerous when
  the reset-token email URL is built from the request `Host`.

## 8. Common false positives

- Values written to headers/logs that are server-generated constants or numeric
  IDs with no newline-carrying charset.
- Redirects whose target is selected from a hard-coded allowlist/map, not echoed.
- Frameworks/runtimes that hard-reject `\r\n` in the specific header sink AND the
  value never reaches a log/email/raw-writer sink.
- Structured logging where the field is passed as a typed argument and the
  formatter encodes newlines.

## 9. Severity & exploitability

Base **Medium** for header/log injection. **High** when it yields session
fixation (`Set-Cookie` injection), password-reset poisoning via Host header
(→ account takeover), or reflected XSS via response splitting; **Critical** when
log injection reaches a lookup-enabled formatter enabling RCE (Log4Shell-style).
Email header injection is **Medium–High** (spam relay / data exfiltration).
Raise for pre-auth reachable, lower for admin-only echoes.
See `references/severity-model.md`.

## 10. Remediation

Strip or reject all CR/LF (raw and encoded) before any header/redirect/log/mail
sink; prefer allowlisting redirect targets and Host values. Use framework header
APIs that reject control characters, and structured/JSON logging that encodes
newlines. Build email headers with typed MIME setters, never string concatenation.
Configure a trusted-host allowlist and derive links from configuration, not the
request `Host`.

## 11. Output

Append each confirmed finding to **`findings/08-crlf-and-header-injection.md`**
using `references/finding-template.md`. Set `Class: CRLF / Header Injection` and
`CWE: CWE-93` (use `CWE-113` for response splitting, `CWE-117` for log forging).
In **Chain potential** note primitives such as *response header control* (→
session fixation / cache poisoning), *reflected content injection* (→ XSS via
split response), *Host-derived link poisoning* (→ account takeover, consumes
nothing / provides the reset-link primitive), and *log-content injection* (→
feeds a downstream log-parser/Log4Shell chain).

**Primitives (controlled):** provides `HTML_OUTPUT`,`CACHE_CONTROL` (seed); consumes none

## References
- CWE-93 CRLF Injection; CWE-113 HTTP Response Splitting; CWE-117 Improper
  Output Neutralization for Logs; OWASP A03:2021 Injection; OWASP Log Injection
  and Unvalidated Redirects & Forwards Cheat Sheets.
