---
name: security-logging-and-monitoring-failures
description: >-
  SAST detection methodology for security logging and monitoring failures
  (CWE-778), including missing logging of security events (auth success/failure,
  access-control denials, high-value transactions, input-validation failures),
  logging of secrets/PII/tokens (CWE-532), insufficient log context for forensics
  (CWE-223), absent alerting/monitoring, and non-tamper-resistant/uncentralized
  logs. Use when reviewing logging configuration, security-event handlers, and
  what data is written to logs. Largely a code/config-review class. Writes
  confirmed findings to findings/42-security-logging-and-monitoring-failures.md.
---

# Security Logging & Monitoring Failures — SAST Methodology

**Class:** Security Logging & Monitoring Failures · **CWE-778** (and **CWE-223**, **CWE-532**) · **OWASP:** A09 Security Logging and Monitoring Failures
**Findings file:** `findings/42-security-logging-and-monitoring-failures.md`

## 1. Overview

This class has two opposite failure modes. **Under-logging:** security-relevant
events (login success/failure, access-control denials, high-value transactions,
input-validation rejections) are not recorded, or are recorded without the context
needed for detection and forensics — so an attack is invisible and un-alertable.
**Over-logging:** secrets, PII, session tokens, or full request bodies are written
*into* the logs (CWE-532), turning the log store into a credential trove. It is
primarily an **amplifier**: on its own it rarely gives an attacker a primitive, but
by hiding other chains it removes the defender's ability to detect and respond —
except the secrets-in-logs sub-case, which is a direct `SECRET_LEAK`. The core
test: is every security event logged with sufficient context and shipped/alerted,
and is nothing sensitive ever written to a log?

## 2. Where it lives

- Authentication/authorization code: login handlers, session/JWT verification,
  access-control decision points (the `else`/`deny`/`403` branch that is often
  silent).
- Logging configuration: log level in production, appenders/handlers, format,
  centralization/shipping, retention, and alerting rules.
- High-value business actions: payment, transfer, role/permission change, data
  export, admin operations.
- Any log/print statement that serializes a request, user object, exception with
  payload, token, or config (`logger.info(request)`, `log.debug(user)`,
  `console.log(token)`).

## 3. Sources (tainted input)

For the **secrets-in-logs** sub-case the source is whatever sensitive value flows
into a log sink: passwords, API keys, session/JWT tokens, PANs, PII, `Authorization`
headers, or full request/response bodies. For **log injection** the source is
attacker-controlled request input written unsanitized into a log line (forged
entries, broken parsing — cross-ref `crlf-and-header-injection`). For the
**missing-logging** cases there is no taint source; the finding is the *absence* of
a log/alert at a security decision point, established by code/config review.

## 4. Sinks (dangerous operations)

```python
# Python — dangerous: secrets/PII written to logs (CWE-532)
logger.info("login attempt: %s", request.__dict__)      # dumps password/token
logger.debug(f"jwt={token} authz header={request.headers['Authorization']}")
logging.info("user=%s card=%s", user, card_number)      # PII/PAN in logs
```
```java
// Java — dangerous: full request / credentials logged
log.info("Request: {}", request);                       // may include body/headers/cookies
log.debug("password=" + password);
```
```javascript
// Node — dangerous
console.log('session', req.cookies);                     // session token to stdout log
logger.info({ body: req.body });                         // logs passwords/secrets in body
```
```python
# Python — dangerous: security event NOT logged (under-logging)
def login(u, p):
    if not check(u, p):
        return 401          # no log of failed auth → brute force is invisible
def transfer(a, amt):
    do_transfer(a, amt)     # no audit log of a high-value transaction
```
```java
// Access-control denial with no log — dangerous (silent deny)
if (!user.canAccess(obj)) { return forbidden(); }        // no logger.warn(...) → IDOR probing unseen
```
```xml
<!-- Production log level too low / no shipping — dangerous -->
<root level="ERROR"/>   <!-- misses WARN security events; no central appender, no alerting -->
```

## 5. Sanitizers / safe patterns

**Safe:**
- Log **every** security event — auth success and failure, logout, password/role
  change, access-control denials, input-validation failures, and high-value
  transactions — at an appropriate level, with rich context: timestamp, actor id,
  source IP, action, target resource, and outcome.
- **Redact/allowlist fields** before logging: never log passwords, tokens, secrets,
  full PII/PANs, `Authorization`/`Cookie` headers, or raw request bodies; use a
  masking serializer.
- Ship logs to a **centralized, append-only/tamper-resistant** store with integrity
  protection and enforced retention.
- Wire **alerting** on suspicious patterns (auth-failure spikes, repeated denials,
  anomalous transactions) so detection is timely.
- Encode/neutralize newlines and control chars in any user-derived value written to
  a log (log-injection defense).

**Fails / not a real sanitizer:**
- Logging the event but at `DEBUG` while production runs at `ERROR`/`WARN` — the
  event is effectively not recorded.
- Logging locally only, no shipping/centralization — logs are lost on host
  compromise or destroyed by the attacker (no tamper-resistance).
- "Redacting" a secret in one code path while another logs the whole object/
  request that still contains it.
- Logging occurs but there is **no alerting/monitoring** — data exists but nobody
  is notified; detection never happens.
- Recording an event without actor/IP/resource context — useless for forensics
  (CWE-223 insufficient context).
- Assuming an APM/error tracker (which captures exceptions) substitutes for a
  security audit log of *successful* sensitive actions.

## 6. Detection methodology

1. **Find security decision points and check for a log at each:**
   ```
   rg -n 'login|authenticate|check_password|verify|forbidden|403|401|AccessDenied|unauthorized|hasPermission|canAccess'
   ```
   For each auth/authorization branch (especially the deny/failure branch), confirm
   a corresponding `logger.*` call with context exists.
2. **Find high-value actions lacking an audit log:** payment/transfer/role-change/
   export/admin handlers with no logging call.
3. **Find secrets/PII being logged (CWE-532):**
   ```
   rg -n '(log|logger|logging|console)\.(info|debug|warn|error|log)\(.*(password|passwd|secret|token|jwt|api[_-]?key|authorization|cookie|card|ssn|request|req\.body|__dict__)'
   ```
4. **Audit logging config:** production log level, presence of a central/remote
   appender, retention, and any alerting integration.
   ```
   rg -n 'level\s*[:=]\s*(ERROR|FATAL|OFF)|log4j|logback|winston|serilog|LOGGING\s*=|LOG_LEVEL'
   ```
5. **Check log-injection handling:** user input written to logs without newline/
   control-char neutralization (cross-ref `crlf-and-header-injection`).
6. **Classify the sub-case:** missing-logging (review-only, no primitive) vs
   secrets-in-logs (`SECRET_LEAK`) vs log-injection.

## 7. Modern & niche variants

- **Secrets/PII in logs (CWE-532):** the highest-impact sub-case — passwords,
  tokens, API keys, or PANs in application/access logs (or in a third-party log
  aggregator with broad read access) are a direct `SECRET_LEAK`; anyone with log
  access (or another leak that exposes logs) harvests live credentials.
- **Silent access-control denials:** the deny branch returns 403 without logging,
  so IDOR/BFLA enumeration and forced-browsing produce no signal — the most common
  under-logging gap and the reason breaches go undetected for months.
- **Insufficient context (CWE-223):** events logged without actor/IP/resource/
  outcome, defeating forensic reconstruction and correlation.
- **No centralization / tamper-resistance:** logs only on the compromised host,
  writable/erasable by the attacker, or with no integrity control — post-incident
  they cannot be trusted.
- **No alerting/monitoring:** logs exist but nothing watches them; detection is
  effectively absent even with perfect logging.
- **Log injection / forgery:** unsanitized CRLF in a logged value lets an attacker
  inject fake log lines, break log parsers/SIEM rules, or frame another user
  (cross-ref `crlf-and-header-injection`).
- **Chain-concealment amplifier:** because this class hides other findings, an
  under-logging finding raises the effective severity of co-located
  injection/IDOR/auth findings (slower detection, longer dwell time).

## 8. Common false positives

- Security events logged with context at a level that production actually emits,
  shipped centrally with alerting — the control is present.
- A `logger.debug(user)` on an object whose serializer already masks all sensitive
  fields (verify the masking).
- Verbose request logging confined to a dev/test profile never active in
  production (confirm the effective config).
- Business-only actions with no security relevance and no audit requirement.
- Absence of logging in library/utility code whose callers log the event.

## 9. Severity & exploitability

Base **Low** for a missing-logging/monitoring gap on its own (per the model:
"info leak with no direct pivot" tier, valued mainly as an amplifier). Raise to
**Medium/High** when the missing logging covers authentication or access-control
on a high-value system (breach goes undetected) or when combined with a co-located
exploitable finding whose detection it suppresses. The **secrets-in-logs**
sub-case is scored as its `SECRET_LEAK` impact — **High/Critical** if live
credentials/tokens are written where an attacker (or another leak) can read them.
See `references/severity-model.md`.

## 10. Remediation

Log all security events (auth success/failure, logout, privilege/role change,
access-control denials, input-validation failures, high-value transactions) with
full context (who/what/where/when/outcome) at a level production emits. Never log
secrets, tokens, credentials, `Authorization`/`Cookie` headers, full PII, or raw
request bodies — apply a masking/allowlist serializer. Ship logs to a centralized,
append-only, integrity-protected store with enforced retention, and configure
alerting on anomalous security patterns. Neutralize newlines/control characters in
user-derived log values.

## 11. Output

Append each confirmed finding to
**`findings/42-security-logging-and-monitoring-failures.md`** using
`references/finding-template.md`. Set `Class: Security Logging & Monitoring
Failures` and the specific `CWE` (`CWE-532` secrets-in-logs, `CWE-223`
insufficient context, `CWE-778` missing logging). For the **missing-logging /
no-monitoring** findings set **`Reachable over: N/A (code/config)`** and write the
Request block as `N/A — code/config review; reproduction is triggering the event
(e.g. a failed login or a denied access) and confirming no log/alert is produced`.
For the **secrets-in-logs** sub-case, if the value that reaches the log is carried
in an HTTP request (e.g. a password/token in a body that gets logged), you MAY
include a **Burp-pasteable raw HTTP request** per `references/burp-request-format.md`
showing the request whose sensitive field lands in the log, and note the log file/
sink as the indicator; otherwise keep it `N/A (code/config)`.

**Primitives (controlled):** provides `SECRET_LEAK`(only when secrets/tokens are
written to logs) else none (amplifier — conceals other chains and delays
detection); consumes none.

## References
- CWE-778, CWE-223, CWE-532; OWASP A09:2021 Security Logging and Monitoring
  Failures; OWASP Logging Cheat Sheet; OWASP ASVS V7 (Logging & Error Handling).
