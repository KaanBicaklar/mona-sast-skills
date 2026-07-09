# Burp-Pasteable Request Format

Every web/mobile-reachable finding carries a **raw HTTP request** in its `Request`
block so a tester can paste it directly into **Burp Repeater** (or `curl`/Caido)
and reproduce the issue. This file defines the exact format.

## Why raw HTTP (not curl)

Burp Repeater's "Paste" and the proxy both speak raw HTTP/1.1. A raw request is
the lowest-friction artifact: select the fenced block, paste into Repeater, adjust
the host/session, send. Provide `curl` only as a secondary convenience.

## Format rules

Put the request in a fenced ```` ```http ```` block:

```http
POST /path/to/endpoint?query=1 HTTP/1.1
Host: TARGET_HOST
User-Agent: sast-validation
Accept: */*
Cookie: session=<SESSION_TOKEN>
Authorization: Bearer <TOKEN>
Content-Type: application/json
Content-Length: <auto>
Connection: close

{"field":"<PAYLOAD-MARKER>"}
```

- **Request line first:** `METHOD SP path[?query] SP HTTP/1.1`. Use the full path,
  not a URL. Keep the exact method the endpoint expects.
- **`Host` header is mandatory** and must be a placeholder (`TARGET_HOST`) unless a
  concrete in-scope host is authorized.
- **Placeholders in ALL-CAPS/angle brackets:** `TARGET_HOST`, `<SESSION_TOKEN>`,
  `<TOKEN>`, `<CSRF>`, `<PAYLOAD-MARKER>` — never bake in real secrets.
- **One blank line** between headers and body (represents CRLFCRLF). Body only for
  methods that carry one.
- **`Content-Length`** — write `<auto>` and let Burp recompute, or the real length
  if you hand-craft it. Never leave a wrong fixed length.
- **Mark the injection point** right below the block: which parameter/header/JSON
  field/multipart part carries the payload, and where the `<PAYLOAD-MARKER>` sits.
- **Keep it minimal:** only the headers needed to reach and trigger the sink. Strip
  unrelated tracking headers.

## Payload markers — proof, not weaponization

The request must demonstrate the flaw with a **benign existence proof**, matching
the validation skill's default posture (prove it exists, do not exploit it):

| Class | Benign proof marker (default) | Avoid (weaponized) |
|---|---|---|
| SQLi | boolean `' AND 1=1--` vs `' AND 1=2--`, or `SLEEP(5)` timing | dumping tables, `INTO OUTFILE` |
| Command inj. | `;sleep 5` timing, or OOB `;nslookup <ID>.oob` | reverse shell, file writes |
| SSRF | OOB callback to `http://<ID>.oob` | reading cloud metadata creds |
| XSS | `"><b>sast</b>` / `alert(document.domain)` in a PoC | keylogger/cookie exfil |
| Path traversal | read a known-benign file (`/etc/hostname`) | `/etc/shadow`, app secrets |
| IDOR/BAC | read *your own* neighbour object id, note it differs | mass-harvest other users |
| Deserialization | non-destructive gadget (sleep/DNS) | RCE payload |
| XXE | OOB DTD callback | full `/etc/passwd` exfil |
| Open redirect | redirect to `example.com` and observe `Location` | live phishing/token theft |

State the marker used in the finding's `Payload marker` line.

## Mobile / API specifics

- Mobile findings are almost always the **backend HTTP API** the app calls —
  capture with Burp/Frida, then record the same raw HTTP request here.
- Include the app-specific auth header (`Authorization: Bearer …`, custom
  `X-Api-Key`, HMAC-signed headers). If the API uses **request signing / cert
  pinning**, note it under the request so the tester knows to sign/relay via the
  instrumented app rather than plain Repeater.
- For gRPC/GraphQL, still express it as the underlying HTTP POST (GraphQL query in
  the JSON body; gRPC-web as the framed POST) so it stays Repeater-usable.

## Secondary curl form (optional)

If helpful, add a one-liner after the raw block:

```bash
curl -sk 'https://TARGET_HOST/path' -H 'Cookie: session=<SESSION_TOKEN>' \
  -H 'Content-Type: application/json' --data '{"field":"<PAYLOAD-MARKER>"}'
```
