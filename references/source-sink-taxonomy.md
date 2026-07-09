# Source–Sink–Sanitizer Taxonomy

Shared taint vocabulary. Every detection skill inherits these definitions and adds
its class-specific sinks. SAST is, at its core, answering one question:

> **Does attacker-controlled data (a source) reach a dangerous operation (a sink)
> without passing through an effective neutralizer (a sanitizer)?**

## 1. Sources (where taint enters)

Treat all of these as attacker-controlled until proven otherwise.

**HTTP / network**
- Query string, path params, request body (form, JSON, XML, multipart), headers
  (incl. `Host`, `Referer`, `X-Forwarded-*`, `User-Agent`), cookies, uploaded files.
- WebSocket messages, gRPC fields, GraphQL variables, webhook payloads.

**Stored / second-order** (taint that was persisted earlier and re-read)
- Database rows, cache entries, message-queue payloads, config written by users.
- **Second-order is the #1 missed source** — data that was safe on write becomes a
  sink input on a later read. Always trace stored data back to its original source.

**Environment / supply chain**
- Environment variables and CLI args on multi-tenant/CI systems.
- Filenames/paths in archives (zip slip), image/document metadata.
- Third-party API responses, package metadata, LLM/model output.

**Inter-process / client**
- `postMessage`, `window.name`, URL fragment (`location.hash`), `localStorage`.

## 2. Sinks (where taint becomes dangerous) — by class

| Sink category | Representative operations |
|---|---|
| SQL | `execute`, string-built queries, ORM `.raw()`, `WHERE` concatenation |
| NoSQL | Mongo `find`/`$where`, dynamic operator objects |
| OS command | `system`, `exec`, `popen`, `Runtime.exec`, `child_process`, backticks |
| Code eval | `eval`, `exec`, `Function()`, `pickle.loads`, template compile |
| File path | `open`, `readFile`, `sendFile`, `include`, `require`, archive extract |
| URL fetch | `requests.get`, `fetch`, `URLConnection`, `curl`, image loaders |
| HTML/JS output | `innerHTML`, `document.write`, unescaped template render, `res.send` |
| Serialization | `readObject`, `unserialize`, `Marshal.load`, `yaml.load` |
| Redirect/header | `Location:` set, `setHeader`, raw response write |
| Auth/authz | permission checks, `role ==`, object-ownership comparisons |

## 3. Sanitizers (what breaks the taint) — and how they fail

A neutralizer only counts if it is **correct, complete, and applied on the path
that reaches the sink**. Common failure modes to look for:

- **Wrong tool for the sink** — HTML-escaping SQL, URL-encoding shell args, etc.
  Encoding must match the sink's grammar.
- **Blocklist instead of allowlist** — enumerating bad chars; always bypassable.
- **Applied then bypassed** — sanitized value overwritten, re-decoded, or a second
  concatenation happens after sanitizing.
- **Partial coverage** — one branch sanitizes, another doesn't; numeric context
  assumed but string passed.
- **Canonicalization gaps** — check happens before decoding/normalization (path
  `../`, Unicode, double-encoding, mixed case).
- **Trusting the framework** — ORM/template "auto-escapes" but a `raw`/`safe`/
  `bypass` API is used, or escaping is off for the relevant context (attribute vs
  text vs JS vs URL).

## 4. Reachability (the fourth question)

A source→sink path only matters if the sink is **reachable**:
- Is the route registered/exposed? Is the function actually called?
- Is there an auth gate before it, and can it be reached pre-auth?
- Is it dead code, test-only, or behind a disabled feature flag?

Findings on unreachable code are `Info`/`Tentative`, not High. Prove reachability
or mark confidence down.
