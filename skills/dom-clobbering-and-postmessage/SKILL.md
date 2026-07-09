---
name: dom-clobbering-and-postmessage
description: >-
  SAST detection methodology for DOM clobbering and insecure cross-window
  messaging (CWE-79, CWE-451). Covers id/name attributes overwriting JS globals
  and document properties, postMessage receivers with missing/weak origin
  checks, wildcard targetOrigin data leaks, window.name / location.hash /
  document.referrer as DOM sources, and document.domain relaxation. Use when
  reviewing client-side JS that reads DOM-derived globals or handles postMessage.
  Writes confirmed findings to findings/15-dom-clobbering-and-postmessage.md.
---

# DOM Clobbering & Insecure postMessage — SAST Methodology

**Class:** DOM Clobbering / Cross-Window Messaging · **CWE-79** (and **CWE-451**) · **OWASP:** A03 Injection
**Findings file:** `findings/15-dom-clobbering-and-postmessage.md`

## 1. Overview

Two related client-side trust failures.
**DOM clobbering:** an attacker who can inject *non-script* HTML (a name/id
attribute is enough, so it survives many sanitizers and CSP) overwrites JS
variables and `document`/`window` properties, because named elements are exposed
as globals (`window.x`, `document.x`). Logic that reads an "expected" global then
consumes an attacker-shaped object/string.
**Insecure postMessage:** a receiver that acts on `event.data` without verifying
`event.origin` trusts messages from any window; a sender using `'*'` targetOrigin
leaks data to any framing/opener origin. The core tests: *does code read a global/
`document` property that a named DOM element could clobber?* and *does a `message`
handler validate origin before using the data (and is that check correct)?*

## 2. Where it lives

- `addEventListener('message', …)` / `window.onmessage` handlers, especially in
  SDKs, payment/auth iframes, chat widgets, embeds, and cross-origin iframe bridges.
- Bootstrap/config code reading globals: `if (window.CONFIG)`, `document.currentScript`,
  `document.getElementById(x)` fallbacks, `var x = window.x || default`.
- HTML sinks that consume clobbered values (`document.write`, `innerHTML`, `src`
  set from a global, `<script src>` built from a clobberable variable).
- `window.postMessage(data, '*')` senders; `document.domain = …` relaxation code.

## 3. Sources (tainted input)

- **DOM-clobbering source:** attacker-injectable HTML with `id`/`name` attributes
  (stored comments, profile HTML, markdown, sanitized-but-tag-allowed content,
  ad/embed slots). No script needed — clobbering is the injection.
- **postMessage source:** `event.data` from any window (opener, parent, child
  iframe, popup) when origin is unchecked.
- **Other DOM sources feeding sinks:** `window.name` (survives cross-origin
  navigation → cross-domain data smuggling), `location.hash`/`location.search`,
  `document.referrer`, `document.cookie`. Second-order: a value read from one of
  these, stored, then rendered.

## 4. Sinks (dangerous operations)

```javascript
// DOM clobbering — dangerous reads of clobberable globals
if (window.CONFIG) { load(window.CONFIG.url); }   // <a id=CONFIG> clobbers to an element
let s = document.getElementById;                  // can be clobbered by <img id=getElementById>
var url = window.APP_BASE || '/';                 // <a id=APP_BASE href="//evil"> → url is element, .toString()→href
document.write('<script src="' + window.tpl + '">');  // window.tpl clobbered
element.innerHTML = someGlobalFromDom;
// nested clobbering: <form id=x><input id=y> makes window.x.y an attacker value
config = window.settings.token;                   // form/input pair clobbers .token
```
```javascript
// postMessage RECEIVER — dangerous: no / weak origin check
window.addEventListener('message', (e) => {
  // MISSING origin check entirely
  document.getElementById('out').innerHTML = e.data.html;   // → DOM XSS
  eval(e.data.cmd);                                          // → code exec
  location = e.data.redirect;                                // → open redirect
});

// Weak origin checks — dangerous
if (e.origin.indexOf('trusted.com') !== -1) { … }   // matches evil-trusted.com.attacker.com
if (e.origin.match(/trusted\.com/)) { … }           // unanchored, unescaped dot
if (e.origin.startsWith('https://trusted.com')) { … } // matches https://trusted.com.evil.com
```
```javascript
// postMessage SENDER — dangerous: wildcard target leaks data
otherWindow.postMessage({ token: authToken }, '*');   // any framing origin receives it
parent.postMessage(sensitiveData, '*');
```
```javascript
// document.domain relaxation — dangerous
document.domain = 'example.com';   // widens same-origin to every subdomain → one XSS'd subdomain owns all
```

## 5. Sanitizers / safe patterns

**Safe (clobbering):**
- Don't rely on globals/`document` properties for security-relevant values; read
  config from a `const` in module scope, `JSON.parse` of a data attribute you fetch
  explicitly, or a `Map`.
- Use `typeof x === 'string'`/type guards before use; clobbered values are
  `HTMLElement`/`HTMLCollection`, not the expected primitive.
- Sanitize output HTML with a config that strips or namespaces `id`/`name`
  (DOMPurify `SANITIZE_DOM: true` / `SANITIZE_NAMED_PROPS: true`).
- Reference DOM APIs via a saved local (`const gebi = document.getElementById.bind(document)`)
  captured before any untrusted HTML is inserted — or just don't shadow them.

**Safe (postMessage):**
- Receiver: **strict, exact** origin allowlist — `if (e.origin === 'https://app.example.com')`,
  ideally plus a `e.source === expectedWindow` check and a message-type/nonce schema.
- Sender: specify the **exact** targetOrigin, never `'*'`, when data is sensitive.
- Validate `e.data` shape before use; never route it to `eval`/`innerHTML`/`location`.

**Fails / not a real sanitizer:**
- `origin.indexOf(x) !== -1`, `.includes(x)`, `.match(/x/)` (unanchored),
  `.endsWith('trusted.com')` (matches `nottrusted.com`), `.startsWith('https://trusted.com')`
  (matches `…trusted.com.evil.com`) — all bypassable via substring/suffix/prefix tricks.
- Checking `e.origin` but with an unescaped `.` in the regex (`trusted.com` matches
  `trustedxcom`).
- Sanitizing tags but allowing `id`/`name` attributes (clobbering still works).
- `document.domain` set to a "safe" parent — it *broadens* the origin; not a fix.
- Trusting `e.source`/referrer without also pinning origin.

## 6. Detection methodology

1. **Find postMessage receivers and audit the origin check:**
   ```
   rg -n "addEventListener\(\s*['\"]message['\"]|onmessage\s*="
   rg -n "e(vent)?\.origin\s*(===|==|!=|!==|\.(indexOf|includes|match|startsWith|endsWith|search))"
   ```
   For each handler: is there an origin check at all? Is it an **exact `===`** match
   against an allowlist, or a bypassable substring/regex? Where does `e.data` flow?
2. **Find wildcard senders:**
   ```
   rg -n "postMessage\([^,]+,\s*['\"]\*['\"]\)"
   ```
3. **Find DOM-clobbering-prone global reads:**
   ```
   rg -n "window\.\w+\s*\|\||document\.\w+\s*\|\||if\s*\(\s*window\.\w+"
   rg -n "getElementById|document\.(all|forms|images|cookie)|document\.currentScript"
   ```
4. **Find other DOM sources into sinks:**
   ```
   rg -n "window\.name|location\.(hash|search|href)|document\.referrer"
   rg -n "document\.domain\s*="
   ```
5. **Confirm data flow:** clobbered/`event.data`/`window.name` value → does it reach
   an HTML/`src`/`eval`/`location` sink or a security decision?
6. **Confirm the injection surface (clobbering):** can the attacker actually inject
   an element with a controlled `id`/`name`? (stored HTML, allowed tags in sanitizer)
7. **Confirm reachability:** is the handler/embed loaded on a real, framed/opened page?

## 7. Modern & niche variants

- **DOM clobbering fundamentals:** `<a id=x>` exposes `window.x`; two elements with
  the same `name` create an `HTMLCollection`; a `<form id=x>` containing
  `<input id=y>`/`<input name=y>` yields `window.x.y` — enabling **nested/multi-level
  clobbering** of dotted property paths (`config.api.url`). `document.getElementById`
  and other `document` props can themselves be clobbered by matching `id`/`name`.
  Clobbering survives sanitizers that only strip scripts and survives script-src CSP.
- **Clobbering → code load / XSS:** a clobbered `window.tpl`/base-URL used to build a
  `<script src>` or `innerHTML` turns HTML injection into script execution without
  ever injecting a `<script>` tag.
- **postMessage receiver, no/weak origin check:** the classic bug — handler routes
  `e.data` to `innerHTML`/`eval`/`location`/DOM without verifying `e.origin`, so any
  page that frames or opens the target sends the payload. Weak checks (`indexOf`,
  unanchored regex, `startsWith`/`endsWith`) are effectively no check.
- **Wildcard `targetOrigin` data leak:** `postMessage(secret, '*')` delivers to
  whatever origin currently occupies the target window — an attacker who controls
  framing/timing harvests tokens (CWE-451 / information exposure to wrong origin).
- **`window.name` as a source:** persists across cross-origin navigations, so an
  attacker page can seed `window.name` then navigate the victim to the target,
  smuggling a large payload into a DOM sink.
- **`location.hash` / `document.referrer` DOM sinks:** hash-based routing/config that
  feeds `innerHTML`/`eval`; referrer echoed into the page.
- **`document.domain` relaxation:** setting `document.domain` to a shared parent
  broadens same-origin to all subdomains, so a single subdomain XSS/takeover
  compromises the main app — turns a low-value subdomain into a full-origin foothold.

## 8. Common false positives

- postMessage handlers with an exact `e.origin === 'https://…'` allowlist (and no
  bypassable operator) that also validate `e.data` shape.
- Senders using a specific, hard-coded targetOrigin (not `'*'`) for sensitive data,
  or `'*'` used only for non-sensitive ping/handshake messages.
- Global reads whose value is type-guarded and never reaches a dangerous sink, or
  where the page never renders attacker-injectable HTML (no clobbering surface).
- `location.hash`/`window.name` read but only routed to `textContent`/safe APIs.
- `document.domain` assignments that were removed/deprecated (dead code) — verify.

## 9. Severity & exploitability

Base **Medium**. Raise to **High** when the flow yields DOM XSS / code execution
(postMessage `e.data` → `innerHTML`/`eval`; clobbered value → `<script src>`), or
when a wildcard sender leaks auth tokens (→ account takeover, chain-Critical).
`document.domain` relaxation is **Medium/High** as an amplifier (one subdomain XSS →
whole origin). Lower if the DOM sink is safe or the clobbering surface can't be
reached. See `references/severity-model.md`.

## 10. Remediation

postMessage receivers: validate `event.origin` against an **exact** allowlist
(`===`), optionally pin `event.source`, and schema-validate `event.data` before use;
never route it to `eval`/`innerHTML`/`location`. Senders: always pass the specific
target origin, never `'*'`, for sensitive data. DOM clobbering: don't derive
security-relevant values from named globals/`document` properties — use lexical
constants/`Map`, add type guards, and sanitize output HTML to strip/namespace
`id`/`name` (DOMPurify `SANITIZE_NAMED_PROPS`). Avoid `document.domain`; use
`postMessage`/CORS with explicit origins for cross-subdomain communication.

## 11. Output

Append each confirmed finding to **`findings/15-dom-clobbering-and-postmessage.md`**
using `references/finding-template.md`. Set `Class: DOM Clobbering / Cross-Window
Messaging`, `CWE: CWE-79` (or `CWE-451` for wrong-origin data leaks), and in
**Chain potential** name primitives such as *cross-origin message injection*
(provides a route to `cross-site-scripting` DOM sinks or `open-redirect`),
*global variable override* (arms a DOM XSS gadget, related to `prototype-pollution`),
*sensitive-data leak to arbitrary origin* (consumes framing control; **provides**
stolen tokens), or *origin-scope broadening* (`document.domain`). These findings are
usually chain links — always name the downstream sink the clobbered/message value
reaches.

**Primitives (controlled):** provides `JS_EXEC`,`GADGET`; consumes `HTML_OUTPUT`

## References
- CWE-79, CWE-451; OWASP A03:2021; HTML Living Standard named-access rules;
  PortSwigger DOM clobbering & postMessage research; OWASP DOM XSS Prevention Cheat Sheet.
