---
name: websocket-security
description: >-
  SAST detection methodology for WebSocket security (CWE-346), centred on
  Cross-Site WebSocket Hijacking (CSWSH) — handshakes authenticated by cookies
  with no Origin validation — plus missing authN/authZ on WS messages (CWE-862),
  injection through WS payloads into downstream sinks, ws:// cleartext, and
  message flooding / resource exhaustion. Use when reviewing WebSocket handshake
  handlers and message routers (ws, socket.io, Spring, Django Channels, ASP.NET
  SignalR). Writes confirmed findings to findings/41-websocket-security.md.
---

# WebSocket Security — SAST Methodology

**Class:** WebSocket Security · **CWE-346** (and **CWE-1385**, **CWE-862**) · **OWASP:** A01 / A05
**Findings file:** `findings/41-websocket-security.md`

## 1. Overview

WebSockets upgrade an HTTP request into a full-duplex channel, but they inherit
none of the same-origin protections HTTP clients rely on: the browser attaches
cookies to the handshake yet **does not enforce CORS or SameSite on it**. If the
server authenticates the WebSocket solely from those ambient cookies and never
validates the `Origin` header, any attacker page can open an authenticated socket
for the victim — **Cross-Site WebSocket Hijacking (CSWSH)** — and read/write on
their behalf. Beyond CSWSH, WS channels frequently skip per-message authZ, tunnel
untrusted payloads into SQL/command/other sinks, and run over cleartext `ws://`.
The core test: is the handshake's `Origin` validated against an allowlist, and is
every message authenticated and authorized as strictly as the equivalent HTTP API?

## 2. Where it lives

- Handshake/upgrade handlers: `ws`/`websocket` `verifyClient`/`handleUpgrade`,
  `socket.io` `io.on('connection')` + `allowRequest`, Spring
  `WebSocketHandler`/`setAllowedOrigins`, Django Channels
  `AllowedHostsOriginValidator`/consumer `connect`, ASP.NET SignalR hubs / raw
  `WebSocketMiddleware`, Go `gorilla/websocket` `Upgrader.CheckOrigin`.
- Message routers: the `on('message')`/`receive`/`OnMessageReceived` handlers that
  dispatch by a `type`/`action` field, and any downstream sink they call.
- Transport/config: `ws://` vs `wss://`, reverse-proxy upgrade config, and
  connection/rate limits.

## 3. Sources (tainted input)

Two sources. (1) The **handshake request** itself — attacker-controlled `Origin`,
`Sec-WebSocket-Protocol`, cookies, and query string; a cross-site page fully
controls everything except the auto-attached cookies, which is exactly what makes
CSWSH work. (2) Each **inbound WS message payload** — fully attacker-controlled
bytes/JSON that flow into message handlers and any sink (DB, shell, template,
broadcast) with the same taint status as an HTTP body.

## 4. Sinks (dangerous operations)

```javascript
// Node ws — dangerous: no Origin check, cookie-authenticated handshake
const wss = new WebSocket.Server({ server });          // no verifyClient → any origin
wss.on('connection', (ws, req) => {
  const user = sessionFromCookie(req.headers.cookie);  // trusts ambient cookie
  ws.on('message', m => db.query(`SELECT * FROM msg WHERE room='${JSON.parse(m).room}'`)); // WS→SQLi
});
```
```javascript
// socket.io — dangerous: origin wide open
const io = new Server(server, { cors: { origin: '*', credentials: true } }); // reflects/any origin
io.on('connection', s => s.on('cmd', d => exec(d.shell)));  // WS payload → command sink, no authz
```
```java
// Spring — dangerous: all origins allowed
registry.addHandler(handler, "/ws").setAllowedOrigins("*");     // CSWSH
// no per-message principal/authority check in handleTextMessage(...)
```
```python
# Django Channels — dangerous: no origin validator, accept-all
class ChatConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()                                  # no self.scope origin/authz check
    def receive(self, text_data):
        run_command(json.loads(text_data)['q'])        # payload → sink
# routing without AllowedHostsOriginValidator wrapper → cross-origin handshakes accepted
```
```go
// gorilla/websocket — dangerous: CheckOrigin always true
var up = websocket.Upgrader{ CheckOrigin: func(r *http.Request) bool { return true } } // CSWSH
```

## 5. Sanitizers / safe patterns

**Safe:**
- **Validate `Origin`** on the handshake against a strict allowlist of full origins
  (Spring `setAllowedOrigins(exact)`, gorilla `CheckOrigin` exact-match, Channels
  `AllowedHostsOriginValidator`, socket.io exact `cors.origin`) and reject others.
- Bind the socket to a **CSRF-style token** passed in the handshake (query/subprotocol)
  that is verified server-side, not just the cookie — so a cross-site page cannot
  supply it.
- Re-check **authentication and authorization on every message** (the principal and
  their permission for the specific action/resource), not only at connect time.
- Treat each message payload as untrusted: parameterize/validate before any SQL,
  command, template, or broadcast sink (cross-ref the relevant injection skill).
- Use `wss://` only; enforce connection/message rate limits and max frame size.

**Fails / not a real sanitizer:**
- **No `CheckOrigin`/`setAllowedOrigins` (or returning `true`/`*`)** — the default
  in several libraries is to accept any origin, so CSWSH works out of the box.
- Validating `Origin` but also accepting a **missing/`null` Origin** (non-browser
  clients, sandboxed iframes) — attacker strips or forges it from a non-browser
  context.
- Authenticating only at the handshake and then trusting the connection for the
  whole session — no per-message authZ lets a low-priv user invoke admin actions.
- Relying on cookies alone (no handshake token): cookies are auto-attached
  cross-site, which is the CSWSH precondition, not a defense.
- Substring/suffix `Origin` matching (`endsWith('.trusted.com')`,
  `origin.includes('trusted')`) — same bypasses as CORS (cross-ref
  `cors-misconfiguration`).
- "It's JSON so it's safe" — a `JSON.parse`'d field still flows unescaped into SQL/
  shell/HTML sinks.

## 6. Detection methodology

1. **Find handshake/upgrade handlers and their origin check:**
   ```
   rg -n 'WebSocket\.Server|new Server\(|socket\.io|handleUpgrade|verifyClient|allowRequest|Upgrader|CheckOrigin|setAllowedOrigins|WebsocketConsumer|AddSignalR|MapHub'
   rg -n 'CheckOrigin|setAllowedOrigins|AllowedHostsOriginValidator|allowRequest|verifyClient'   # is one present?
   ```
2. **Flag missing/permissive origin validation:** no `CheckOrigin`, `return true`,
   `"*"`, `origin: true`, or missing `AllowedHostsOriginValidator` wrapper = CSWSH
   candidate.
3. **Confirm the handshake is cookie-authenticated** (session pulled from
   `req.headers.cookie`/`scope`) with no separate handshake token — required for
   CSWSH to yield the victim's identity.
4. **Audit message handlers for authZ and sinks:**
   ```
   rg -n "on\(['\"]message|onmessage|handleTextMessage|def receive|OnMessageReceived|socket\.on\("
   ```
   For each, check: is the acting principal re-authorized? Does the payload reach a
   SQL/command/template/broadcast sink unsanitized?
5. **Check transport & limits:** `ws://` in code/config, absence of rate/size limits.
6. **Confirm reachability:** the upgrade endpoint is an HTTP `GET` — reachable over
   Web by any client.

## 7. Modern & niche variants

- **CSWSH exfiltration:** attacker page opens `new WebSocket('wss://target/ws')`;
  the browser attaches the victim's cookies, the server accepts (no `Origin`
  check), and the attacker's JS reads every message the victim's socket receives —
  provides `DATA_READ` (private messages, tokens) and can send actions
  (`FORCED_REQUEST`/`AUTHZ_BYPASS`).
- **Sub-protocol abuse:** `Sec-WebSocket-Protocol` used to carry auth/role hints
  that the server trusts, or protocol negotiation that selects a
  less-authenticated code path.
- **Lack of per-message authZ:** connect-time auth only; a user's socket can emit
  `type:"admin:deleteUser"` and it is executed because the router never checks the
  action against the principal — `AUTHZ_BYPASS` / BFLA over the socket.
- **JSON-in-WS injection:** message fields flow into SQL/command/NoSQL/HTML sinks
  exactly like an HTTP body — a CSWSH or an authenticated client thereby reaches
  those sinks (chain with `sql-injection`/`command-injection`/`cross-site-scripting`).
- **Tunneling past controls:** routing sensitive actions over WS to dodge
  HTTP-layer WAF/CSRF/authz filters that only inspect REST endpoints.
- **Resource exhaustion:** unbounded message size/rate or connection count → DoS;
  amplified when each message triggers expensive backend work.

## 8. Common false positives

- Handshake authenticated by a **bearer/handshake token** (not just cookies) that a
  cross-site page cannot supply — not CSWSH-able.
- `Origin` exact-matched against an allowlist and `null`/missing rejected.
- Read-only public feed with no cookies, no sensitive data, and no message-driven
  sinks.
- Per-message authZ enforced and payloads parameterized before every sink.
- `wss://` enforced end-to-end with rate/size limits in place.

## 9. Severity & exploitability

Base **High** for CSWSH on an authenticated socket that exposes or mutates
sensitive data (cross-origin `DATA_READ` + `FORCED_REQUEST` with the victim's
identity, no user interaction beyond visiting a page). **Critical** if a WS payload
reaches an RCE/SQL sink (`CODE_EXEC`/`DATA_WRITE`) or if missing per-message authZ
grants admin actions. **Medium/Low** for `ws://` cleartext or DoS-only issues with
no data exposure. Raise when the handshake is pre-auth/default-vulnerable. See
`references/severity-model.md`.

## 10. Remediation

Validate the handshake `Origin` against a strict allowlist and reject
missing/`null`; additionally bind the socket to a server-verified CSRF/handshake
token rather than trusting cookies alone. Enforce authentication **and**
per-message authorization for every action/resource. Treat every message payload
as untrusted and parameterize/encode before any downstream sink. Serve only over
`wss://`. Apply connection, message-rate, and frame-size limits.

## 11. Output

Append each confirmed finding to **`findings/41-websocket-security.md`** using
`references/finding-template.md`. Set `Class: WebSocket Security`, the specific
`CWE` (`CWE-346` CSWSH/origin, `CWE-862` missing per-message authZ, `CWE-1385`
cross-site WS request forgery), and **`Reachable over: Web`**. Because the WS
handshake **is** an HTTP `GET`, include a **Burp-pasteable raw HTTP request** per
`references/burp-request-format.md` — the upgrade request with a cross-site
`Origin` — for example:

```http
GET /ws HTTP/1.1
Host: TARGET_HOST
Upgrade: websocket
Connection: Upgrade
Origin: https://attacker.example
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: <BASE64-16-BYTES>
Cookie: session=<SESSION_TOKEN>
```

Mark the injection point (the forged `Origin`; for payload-injection variants, the
message field), and state the expected indicator (`101 Switching Protocols` from a
foreign origin = CSWSH; sink signal for injection).

**Primitives (controlled):** provides `AUTHZ_BYPASS`(act without/beyond
authorization over the socket), `DATA_READ`(read the victim's channel via CSWSH),
`FORCED_REQUEST`(drive authenticated actions from a cross-site page); consumes none.

## References
- CWE-346, CWE-1385, CWE-862; OWASP A01:2021 / A05:2021; OWASP Testing Guide
  (WebSockets); PortSwigger Cross-Site WebSocket Hijacking research; RFC 6455 §4/§10
  (handshake & security considerations).
