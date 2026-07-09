---
name: server-side-template-injection
description: >-
  SAST detection methodology for server-side template injection (CWE-1336,
  CWE-94), including Jinja2/Twig/Freemarker/Velocity/ERB SSTI→RCE, Spring
  SpEL/OGNL, sandbox escapes, and client-side template injection. Use when
  reviewing code that renders templates, especially where user input becomes
  part of the template itself. Writes confirmed findings to
  findings/05-server-side-template-injection.md.
---

# Server-Side Template Injection — SAST Methodology

**Class:** Server-Side Template Injection · **CWE-1336 (and CWE-94)** ·
**OWASP:** A03 Injection
**Findings file:** `findings/05-server-side-template-injection.md`

## 1. Overview

SSTI occurs when attacker-controlled data is embedded into a template that is then
**compiled and evaluated** by the template engine — so the input is interpreted as
*template syntax*, not just data. Because template languages expose object graphs,
built-ins, and (in many engines) arbitrary method calls, SSTI typically escalates
to remote code execution. The decisive distinction: **rendering user input AS a
template** (`render_template_string(user)`) is SSTI; **interpolating user input
INTO a template's data context** (`render("page.html", name=user)`) is normal and
safe unless output-escaping is off (that is XSS, a different class).

## 2. Where it lives

- Templates built by concatenation, then rendered: `Template(header + user)`,
  `render_template_string(f"...{user}...")`.
- Email/notification/report systems that let users author templates or subjects
  ("Hi {{name}}") and render them server-side.
- CMS/marketing tools with "liquid"/"twig"/"mustache" fields editable by users.
- Framework surfaces that evaluate expressions: Spring SpEL in
  `@Value`/Thymeleaf/`@PreAuthorize`, Struts2 OGNL, Freemarker/Velocity in Java
  apps, ERB in Rails, Handlebars/EJS/Pug in Node, Mako/Jinja2 in Python, Smarty/
  Twig/Blade in PHP.
- Client-side frameworks rendering server-provided strings as templates
  (Angular, Vue, AngularJS) → CSTI.

## 3. Sources (tainted input)

All HTTP inputs, but especially fields intended as *content*: display names,
subjects, bios, custom email/report templates, filenames, and any "personalize
this message" feature. **Second-order** is common: a template snippet stored at
one step (profile, campaign) and rendered later for other users. Also
config/tenant-authored templates and webhook/third-party content rendered
server-side.

## 4. Sinks (dangerous operations)

```python
# Python (Jinja2 / Mako) — dangerous
from flask import render_template_string
render_template_string("Hello " + name)            # input IS the template → RCE
Template("Hi {}".format(user)).render()            # Jinja2 Template() on input
mako.template.Template(user).render()              # Mako executes Python
# Payload probe: {{7*7}} → 49 ; {{''.__class__.__mro__[1].__subclasses__()}} → RCE
```
```java
// Java — dangerous
new Template("t", new StringReader("Hi " + user), cfg).process(m, out); // Freemarker
Velocity.evaluate(ctx, w, "log", "Hi " + user);    // Velocity
parser.parseExpression(user).getValue();           // Spring SpEL → T(Runtime)
// Thymeleaf: fragment/expression from input → SpEL RCE
```
```ruby
# Ruby (ERB) — dangerous
ERB.new("Hello #{params[:name]}").result(binding)  # ERB compiles Ruby
Liquid::Template.parse(user).render                # Liquid (safer, but misuse leaks)
```
```javascript
// Node — dangerous
const t = handlebars.compile(req.body.tpl);        // user-authored template
ejs.render(req.query.tpl, data);                    # EJS runs JS via <%= %>
pug.render(userTemplate);                            // Pug compiles to JS
```
```php
// PHP (Twig / Smarty) — dangerous
$twig->createTemplate($_GET['tpl'])->render();      // Twig on input (sandbox escapable)
$smarty->display("string:".$_GET['tpl']);           // Smarty string resource → PHP
```

## 5. Sanitizers / safe patterns

**Safe:**
- **Never render user input as a template.** Pass it as a *variable* into a static,
  pre-authored template file (`render_template("page.html", name=user)`), letting
  the engine escape it as data.
- If users must supply templates, use a **logic-less** engine (Mustache) or a
  genuinely sandboxed one with a strict allowlist of filters/attributes and *no*
  object/attribute access, method calls, or globals.
- Keep autoescaping ON for the correct context (HTML/attr/JS/URL) to prevent the
  XSS variant.

**Fails / not a real sanitizer:**
- Blocklisting `{{`, `}}`, `__`, `class` — engines offer alternative syntax
  (`{% %}`, `${}`, `#{}`, attribute access via `attr()`, hex/unicode) and gadget
  chains route around any keyword list.
- Relying on the engine's **sandbox** (Jinja2 `SandboxedEnvironment`, Twig sandbox,
  Freemarker `?api`, Velocity `SecureUberspector`) — each has documented escapes;
  a sandbox reduces but does not eliminate risk, and misconfiguration re-opens it.
- HTML-escaping the input — SSTI executes *before* output escaping; escaping stops
  XSS, not template evaluation.
- Sanitizing the value but still building the template string via concatenation.

## 6. Detection methodology

1. **Find sinks:** grep for engines rendering *strings* (not template files).
   ```
   rg -n 'render_template_string|Template\(|from_string|env\.from_string'
   rg -n 'new Template\(|Velocity\.evaluate|freemarker|parseExpression|SpelExpression|Ognl\.'
   rg -n 'ERB\.new|Liquid::Template\.parse|Mustache\.render'
   rg -n 'handlebars\.compile|ejs\.render|pug\.(render|compile)|_\.template\('
   rg -n 'createTemplate|Smarty|->display\([\'"]string:|Twig'
   ```
2. **Decide template-vs-data:** is user input part of the **template string**
   (SSTI) or only a **bound variable** (safe/XSS-only)? This is the whole call.
3. **Trace to a source** (direct or second-order stored template). Stop at a
   constant/template file on disk.
4. **Assess sandboxing:** if a sandbox is used, note the engine/version and treat
   escapes as possible; if none, it is likely RCE.
5. **Confirm reachability** and pre-auth status. Note framework-expression
   surfaces (SpEL/OGNL/Thymeleaf) that don't look like "templates" but evaluate
   expressions — cross-reference the code-injection skill.
6. **Classify engine capability:** Python/Ruby/PHP/Freemarker/Velocity/SpEL/OGNL →
   RCE-capable; Mustache/Liquid → usually data-leak/limited unless misused.

## 7. Modern & niche variants

- **Jinja2 → RCE:** probe `{{7*7}}`; escalate via the object graph —
  `{{''.__class__.__mro__[1].__subclasses__()}}` to find `subprocess`/`os`, or
  `{{cycler.__init__.__globals__.os.popen('id').read()}}`,
  `{{request.application.__globals__.__builtins__.__import__('os')}}`. `config`,
  `lipsum`, `cycler`, `joiner` are common gadget entrypoints even under partial
  sandboxes.
- **Freemarker / Velocity:** Freemarker `<#assign
  ex="freemarker.template.utility.Execute"?new()>${ex("id")}`; Velocity
  `$class.inspect("java.lang.Runtime")...` — both reach `Runtime` for RCE.
- **Thymeleaf:** expression/fragment injection evaluates SpEL —
  `${T(java.lang.Runtime).getRuntime().exec(...)}`; also fragment-selector
  injection (`__${...}__::`).
- **Twig / Smarty (PHP):** Twig `{{_self.env.registerUndefinedFilterCallback
  ("system")}}` / `{{_self.env.getFilter("id")}}`; Smarty `{php}` /
  `{system(...)}` and `string:` resources → PHP execution. Twig sandbox is
  escapable via `_self`/`filter` gadgets.
- **ERB / Slim / Haml (Ruby):** ERB `<%= system('id') %>` — full Ruby, trivially
  RCE when input is the template.
- **Handlebars / EJS / Pug / Nunjucks (Node):** Handlebars via prototype/helper
  gadgets and `Function` constructor; EJS/Pug compile to JS and expose `process`/
  `require`. Nunjucks (`{{range.constructor("...")()}}`).
- **Mako:** executes arbitrary Python inline (`<% %>`, `${}`) with no sandbox —
  any input-as-template is immediate RCE.
- **Spring SpEL / OGNL injection:** the non-obvious SSTI cousins. SpEL in
  `@Value("#{...}")`, `@PreAuthorize`, SpEL-backed queries; OGNL in Struts2
  (`%{...}`, historic CVEs). `T(...)` type references reach any class → RCE.
- **Sandbox escapes:** treat Jinja2 `SandboxedEnvironment`, Twig sandbox,
  Freemarker restrictions as *hardening*, not a boundary — each has public
  escapes; flag input-as-template even when a sandbox is present.
- **Client-side template injection (CSTI):** AngularJS `{{}}` / Angular / Vue
  rendering server-supplied strings as templates → sandbox-escape XSS
  (`constructor.constructor`), sometimes escalating beyond the CSP. Distinct from
  server RCE but shares the template-vs-data root cause.

## 8. Common false positives

- User input passed only as a **bound variable** into a static template file
  (`render_template("t.html", x=user)`) — that is data interpolation, not SSTI.
- Logic-less Mustache with no lambdas and no attribute access.
- Template strings assembled solely from constants/allowlisted fragments.
- Autoescaped output where the concern is XSS, not template evaluation (route to
  the XSS skill instead).

## 9. Severity & exploitability

Base **Critical** for RCE-capable engines (Jinja2, Mako, ERB, Freemarker,
Velocity, Smarty, Twig-with-escape, SpEL/OGNL) — full RCE. **High** when a
genuine sandbox meaningfully constrains impact to data disclosure, or for CSTI
(client-side execution / XSS). Raise for pre-auth/default-config reachability. See
`references/severity-model.md`.

## 10. Remediation

Never render user input as a template — pass it as escaped data into a static
template. If user-authored templates are a hard requirement, use a logic-less
engine or a strictly sandboxed one with attribute access, method calls, and
globals disabled and a filter allowlist. Lock down SpEL/OGNL evaluation contexts
and avoid expression evaluation on untrusted input. Keep contextual autoescaping
on.

## 11. Output

Append each confirmed finding to **`findings/05-server-side-template-injection.md`**
using `references/finding-template.md`. Set `Class: Server-Side Template
Injection`, `CWE: CWE-1336` (or `CWE-94` for expression-engine cases), and in
**Chain potential** name primitives such as *remote code execution* (terminal),
*arbitrary file read* (template `include`/globals), or *info disclosure* (config/
secrets via the object graph under a sandbox — leaked creds feed other chains).
For CSTI, note *client-side code execution / XSS*.

**Primitives (controlled):** provides `CODE_EXEC`; consumes none

## References
- CWE-1336; CWE-94; OWASP A03:2021 Injection; PortSwigger SSTI research; OWASP
  Testing Guide — Template Injection.
