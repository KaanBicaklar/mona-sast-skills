---
name: cross-site-scripting
description: >-
  SAST detection methodology for cross-site scripting (CWE-79), including
  reflected, stored, and DOM-based XSS, mutation XSS (mXSS), framework sink
  gadgets (dangerouslySetInnerHTML, v-html, bypassSecurityTrust), template
  auto-escape bypasses, and HTML/attribute/JS/URL/CSS context confusion. Use
  when reviewing code that emits user data into HTML, the DOM, or a template.
  Writes confirmed findings to findings/13-cross-site-scripting.md.
---

# Cross-Site Scripting (XSS) — SAST Methodology

**Class:** Cross-Site Scripting · **CWE-79** · **OWASP:** A03 Injection
**Findings file:** `findings/13-cross-site-scripting.md`

## 1. Overview

XSS occurs when attacker-controlled data reaches an HTML/DOM/script rendering
sink without encoding appropriate to the **output context**, letting the attacker
inject markup or script that executes in a victim's browser session. The core
test: does a source reach a sink that interprets its value as markup/code, and is
the encoding on that path (a) present and (b) correct for *that specific context*?
Encoding that is safe in HTML text is unsafe in an attribute, a URL, a `<script>`
block, or a `style` value — context is everything.

## 2. Where it lives

- Server-side templates that interpolate values (`render`, `f-strings` into HTML,
  `String.format`, PHP echo, JSP `<%= %>`, ERB `<%= %>`).
- Client-side DOM manipulation in JS/TS (`innerHTML`, `document.write`, jQuery).
- SPA framework escape hatches (`dangerouslySetInnerHTML`, `v-html`,
  `[innerHTML]`, `bypassSecurityTrustHtml`).
- API responses reflected into the DOM by a front-end; JSON injected into inline
  `<script>` bootstrap blocks (`window.__STATE__ = {{ data }}`).
- Error pages, search results, chat/comment rendering, markdown-to-HTML,
  WYSIWYG/rich-text fields, filenames, `Referer`/`User-Agent` echoed into pages.

## 3. Sources (tainted input)

All HTTP inputs (query/body/path/header/cookie), plus DOM-local sources for
DOM XSS: `location.href/search/hash/pathname`, `document.URL`, `document.referrer`,
`document.cookie`, `window.name`, `postMessage` data, `localStorage`/
`sessionStorage`. Plus **stored/second-order**: values persisted (DB, cache, file)
then rendered later (comments, profile fields, admin dashboards viewing user data).
Trace stored values back to their write source.

## 4. Sinks (dangerous operations)

```javascript
// DOM XSS — dangerous JS sinks
el.innerHTML = location.hash.slice(1);        // markup parsed
el.outerHTML = userInput;
el.insertAdjacentHTML('beforeend', userInput);
document.write(userInput);                     // and document.writeln
el.setAttribute('href', 'javascript:' + x);   // URL/JS context
new Function(userInput); eval(userInput);      // script context via XSS gadget
$('#x').html(userInput); $('#x').append(userInput);  // jQuery parses HTML
$(userInput);                                  // jQuery( '<img onerror=..>' )
```
```jsx
// React — dangerous
<div dangerouslySetInnerHTML={{ __html: userInput }} />
<a href={userInput}>            // javascript: URL not blocked by React
```
```html
<!-- Vue — dangerous -->
<div v-html="userInput"></div>
```
```typescript
// Angular — dangerous (defeats built-in sanitizer)
this.sanitizer.bypassSecurityTrustHtml(userInput);
this.sanitizer.bypassSecurityTrustResourceUrl(userInput);
element.innerHTML = userInput;                 // outside Angular binding
```
```python
# Jinja2 / Django — dangerous (auto-escape disabled/bypassed)
Markup(user_input)                             # marks safe, no escaping
"{{ user_input | safe }}"                       # Jinja |safe
mark_safe(user_input)                           # Django
render_template_string(user_input)              # SSTI-adjacent, also XSS
```
```php
// PHP — dangerous
echo $_GET['q'];                                // no htmlspecialchars
print "<div>{$_POST['bio']}</div>";
```
```handlebars
{{! Handlebars — dangerous: triple-stash disables escaping }}
{{{ userInput }}}
```
```twig
{# Twig — dangerous #}
{{ userInput | raw }}
```

## 5. Sanitizers / safe patterns

**Safe:**
- Context-correct output encoding at the sink: HTML-entity encode for HTML text
  (`htmlspecialchars`, `escape`, template auto-escape ON), attribute encoding for
  attribute context, JS-string encoding + `JSON.stringify` for script context,
  URL encoding for URL context, and URL-scheme allowlisting (`https:`/`http:`/
  relative) for `href`/`src`.
- Assigning via safe DOM APIs: `textContent`, `innerText`, `setAttribute` for
  non-URL attributes, `el.classList`, framework text interpolation (`{{ }}` with
  escaping, React `{value}` children, `[textContent]`).
- HTML sanitizer libraries for rich text with a strict allowlist: DOMPurify
  (`DOMPurify.sanitize`), OWASP Java HTML Sanitizer, Bleach (with tight config),
  Ruby `sanitize`.

**Fails / not a real sanitizer:**
- **Right encoder, wrong context** — HTML-encoding a value placed inside a
  `<script>` block, a `javascript:` URL, an unquoted attribute, or a CSS `style`.
- **Blocklist/regex stripping** of `<script>`, `onerror`, etc. — bypassed by
  case, nesting (`<scr<script>ipt>`), event handlers, SVG/MathML, `data:`/
  `javascript:` URLs, HTML entities.
- **Encode-then-decode** — value encoded server-side but a later `decodeURIComponent`
  / `unescape` / `.innerHTML` re-parses it (mXSS territory).
- **DOMPurify misconfig** — `ALLOWED_ATTR` including `href`/`on*`, `ADD_TAGS`
  re-enabling dangerous elements, `RETURN_DOM_FRAGMENT` re-inserted via `innerHTML`
  after mutation (mXSS), or sanitizing then modifying the string.
- **`URL`/scheme check that misses** `javascript:` variants (`java\tscript:`,
  `JaVaScRiPt:`, `data:text/html`, leading whitespace/control chars).
- Angular `bypassSecurityTrust*` — by name it *disables* the sanitizer; never a fix.
- Escaping only one of several interpolation points on the same sink.

## 6. Detection methodology

1. **Find DOM/HTML sinks:**
   ```
   rg -n 'innerHTML|outerHTML|insertAdjacentHTML|document\.write(ln)?|\.html\(|\.append\(|\.prepend\(|\.before\(|\.after\('
   rg -n 'dangerouslySetInnerHTML|v-html|\[innerHTML\]|bypassSecurityTrust'
   rg -n 'eval\(|new Function\(|setTimeout\(\s*[\'"]|setInterval\(\s*[\'"]'
   ```
2. **Find template escape bypasses:**
   ```
   rg -n '\|\s*safe|\|\s*raw|mark_safe|Markup\(|\{\{\{|render_template_string|autoescape\s*(off|false)'
   rg -n 'html\.escape|htmlspecialchars|escapeHtml' -l   # inventory who *does* encode
   ```
3. **Find DOM sources feeding sinks:**
   ```
   rg -n 'location\.(hash|search|href|pathname)|document\.(URL|referrer|cookie)|window\.name|localStorage|\.data\b.*addEventListener\([\'"]message'
   ```
4. **Determine the output context** of each sink hit: HTML text, attribute
   (quoted/unquoted), URL attribute (`href`/`src`/`action`/`formaction`), inline
   JS/`<script>`, event handler, or CSS. The context dictates which encoder is
   correct.
5. **Trace the operand to a source** (direct, DOM-local, or stored/second-order).
   Stop at a literal/constant.
6. **Check for a real, context-correct sanitizer** on the path (see §5). Verify it
   isn't bypassable and matches the context.
7. **Confirm reachability & persistence:** reflected (needs a crafted request),
   stored (persists, hits other users/admins), or DOM (no server round-trip).

## 7. Modern & niche variants

- **Reflected vs stored vs DOM:** DOM XSS never touches the server response body —
  a server-side grep will miss it; you must trace client JS source→sink. Stored is
  highest-impact (fires for every viewer, including admins) and often second-order.
- **Mutation XSS (mXSS):** markup that is inert as a string but becomes active
  after the browser's HTML parser *re-serializes and re-parses* it — e.g. inside
  `<template>`, `<noscript>`, `<svg>`/`<math>` foreign-content, or namespace
  confusion. Bypasses naive sanitizers that inspect the pre-mutation string.
  Sanitize-then-reinsert-as-HTML and innerHTML round-trips are the classic trigger.
- **Sink-specific JS gadgets:** `innerHTML`/`outerHTML`/`insertAdjacentHTML`/
  `document.write` parse markup; jQuery `.html()/.append()/.after()` and even
  `$(selector)` parse HTML if the string looks like a tag. React
  `dangerouslySetInnerHTML`, Vue `v-html`, Angular `[innerHTML]` all bypass the
  framework's default escaping.
- **Framework sink gadgets:** Angular `bypassSecurityTrust{Html,Url,ResourceUrl,
  Script,Style}` and template-injection into Angular expressions; React `href`/
  `src` accepting `javascript:`; Vue render functions with `domProps.innerHTML`.
- **Template auto-escape bypass:** Jinja `|safe`/`Markup`, Twig `|raw`, Handlebars
  `{{{ }}}`, Django `mark_safe`/`|safe`, ERB `<%== %>` (Rails `raw`/`html_safe`),
  Go `template.HTML`/`template.JS`/`template.URL` type casts, EJS `<%- %>`.
- **Context confusion:** the same value is safe in one context and lethal in
  another. HTML-text-encoded data in an **attribute** (breaks out via `"` or space),
  in a **`javascript:` URL**, in an **inline `<script>`/JSON island** (breaks out
  via `</script>` or ` `), or in **CSS** (`expression()`, `url(javascript:)`).
- **`href="javascript:"` / URL-scheme sinks:** any sink setting `href`, `src`,
  `action`, `formaction`, `xlink:href`, `data`, `poster` where the scheme isn't
  allowlisted; `javascript:`, `data:text/html`, `vbscript:`.
- **SVG/MathML vectors:** `<svg><script>`, `<svg onload=…>`, `<math>` with
  `xlink:href`, `<foreignObject>` — foreign-content parsing rules enable mXSS and
  sanitizer bypass.

## 8. Common false positives

- Value emitted only via `textContent`/`innerText`/escaped interpolation.
- Framework text binding (`{value}`, `{{ }}` with auto-escape ON) — safe unless a
  `dangerously*`/`v-html`/`|safe` escape hatch is used.
- Static/constant strings or hard-coded HTML not reachable from a source.
- Value passed through a correctly-configured DOMPurify/sanitizer for that context.
- `href` bound to a value that is scheme-allowlisted before assignment.
- `innerHTML` set from a trusted, developer-authored constant template.

## 9. Severity & exploitability

Base **Medium** for reflected/DOM XSS; **High** for stored XSS in an authenticated
context (fires for every viewer, can hit admins → session/account takeover).
Raise toward **Critical** when it yields admin session theft, CSRF-token
exfiltration enabling full account takeover, or executes in a privileged
origin/extension context. Lower if the sink is behind strict CSP that blocks the
payload class, or requires improbable victim interaction. See
`references/severity-model.md`.

## 10. Remediation

Encode output for the exact context at the sink (HTML, attribute, JS, URL, CSS) —
prefer framework auto-escaping and never disable it. Use safe DOM APIs
(`textContent`) instead of `innerHTML`. For rich text, run a well-configured
allowlist sanitizer (DOMPurify) and re-sanitize after any DOM mutation. Allowlist
URL schemes for `href`/`src`. Deploy a strict `Content-Security-Policy`
(nonce/hash-based, no `unsafe-inline`) as defense-in-depth. Never use
`bypassSecurityTrust*`, `|safe`, `raw`, `{{{ }}}`, or `mark_safe` on tainted data.

## 11. Output

Append each confirmed finding to **`findings/13-cross-site-scripting.md`** using
`references/finding-template.md`. Set `Class: Cross-Site Scripting`, `CWE: CWE-79`,
and in **Chain potential** note primitives such as *script execution in victim
origin* (→ session/CSRF-token theft, credential capture, keylogging), *DOM sink
gadget* (consumes prototype-pollution or DOM-clobbering primitives), or *stored
payload delivery* (→ privileged-user compromise). XSS frequently **consumes** an
open-redirect or CORS misconfig and **provides** the execution primitive that
turns other flaws into account takeover.

**Primitives (controlled):** provides `JS_EXEC`; consumes `HTML_OUTPUT`,`GADGET`

## References
- CWE-79; OWASP A03:2021 Injection; OWASP XSS Prevention & DOM XSS Prevention
  Cheat Sheets; DOMPurify documentation; Google mXSS research.
