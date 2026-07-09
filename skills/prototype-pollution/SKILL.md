---
name: prototype-pollution
description: >-
  SAST detection methodology for JavaScript/Node prototype pollution (CWE-1321),
  including client-side PP feeding DOM XSS gadgets and server-side PP escalating
  to RCE via child_process and template-engine option gadgets. Covers vulnerable
  recursive merge/extend/clone/set utilities, __proto__/constructor.prototype
  keys, and nested-object parsers. Use when reviewing JS that merges, clones, or
  deep-sets objects from untrusted input. Writes confirmed findings to
  findings/14-prototype-pollution.md.
---

# Prototype Pollution — SAST Methodology

**Class:** Prototype Pollution · **CWE-1321** · **OWASP:** A08 Software & Data Integrity Failures
**Findings file:** `findings/14-prototype-pollution.md`

## 1. Overview

Prototype pollution occurs when attacker-controlled keys reach an object-mutation
operation that walks a property path (`__proto__`, `constructor`, `prototype`) and
writes onto `Object.prototype` instead of the intended object. Because nearly all
JS objects inherit from `Object.prototype`, a single injected property becomes a
default on *every* object, altering program logic globally. The core test: does a
source supply both the **key(s)** and **value** to a recursive merge/set/clone that
does not block `__proto__`/`constructor`/`prototype` segments?

## 2. Where it lives

- Config/option merging: `Object.assign` misuse, `lodash.merge`/`_.merge`/
  `_.mergeWith`/`_.defaultsDeep`/`_.set`/`_.setWith`, `jQuery.extend(true, …)`
  (deep), `deep-assign`, `merge-deep`, `deep-extend`, hand-rolled `deepMerge`.
- Nested-object builders: query-string parsers (`qs`, older `express` body parsing)
  and body parsers that expand `a[b][c]=v` or dotted `a.b.c=v` into nested objects.
- Generic "set property by path" helpers (`set(obj, path, val)`), and JSON-to-object
  hydration that trusts keys.
- Client-side: URL/`location.hash`/`postMessage` parsed into a config object then
  merged; server-side: request body/query merged into defaults or into a
  template-engine/`child_process` options object.

## 3. Sources (tainted input)

All HTTP inputs where the attacker controls **object keys**, not just values:
JSON request bodies (arbitrary keys), query strings parsed into nested objects
(`?__proto__[x]=y`, `?constructor[prototype][x]=y`, `?a.b.c=y`), URL fragments,
`postMessage` payloads, and any deserialized structure (YAML/JSON config, stored
documents) whose keys are attacker-influenced. Second-order: a polluted value
stored and later merged into a fresh object.

## 4. Sinks (dangerous operations)

```javascript
// Vulnerable recursive merge — dangerous
function merge(target, source) {
  for (const key in source) {                 // key can be "__proto__"
    if (typeof source[key] === 'object')
      merge(target[key], source[key]);        // walks into Object.prototype
    else
      target[key] = source[key];              // writes global default
  }
}
merge({}, JSON.parse(req.body));

// Library sinks — dangerous with attacker-controlled keys
_.merge({}, req.body);                          // lodash <4.17.12
_.defaultsDeep({}, req.query);
_.set(obj, req.query.path, req.query.val);      // path = "__proto__.polluted"
$.extend(true, {}, userSuppliedObject);         // jQuery deep extend
Object.assign(config, ...);                      // shallow, but a[__proto__] on nested merge

// Nested-object parser — dangerous
const q = qs.parse(req.url.split('?')[1]);       // ?__proto__[admin]=true
```
```javascript
// Server-side PP → RCE gadget: child_process options
const opts = merge({}, req.body);                // pollutes Object.prototype.shell / .env / .NODE_OPTIONS
child_process.execSync('ls', opts);              // shell / env now attacker-influenced
child_process.spawn(cmd, args, opts);            // gadget: options.shell, options.env

// Server-side PP → RCE gadget: template engine options
// pollute Object.prototype with pug/handlebars compile internals, e.g.
// __proto__.outputFunctionName / .compileDebug / .client → injected JS in compiled fn
res.render('view', userData);                    // engine reads polluted defaults
```
```javascript
// Client-side PP → DOM XSS gadget
// pollute __proto__.src / .innerHTML / .attributes so a library that reads a
// missing option falls through to the polluted prototype value:
element.innerHTML = config.template || '';       // config.template undefined → prototype hit
```

## 5. Sanitizers / safe patterns

**Safe:**
- Block dangerous keys before writing: reject/skip `__proto__`, `constructor`,
  `prototype` path segments in any recursive walk.
- Use `Object.create(null)` (null-prototype) or `Map` for untrusted key/value
  stores — no `Object.prototype` to pollute.
- `Object.freeze(Object.prototype)` as a hardening layer.
- Schema validation (JSON Schema/`ajv` with `additionalProperties:false`, `zod`,
  `joi`) that rejects unknown keys before any merge.
- Patched library versions: lodash ≥ 4.17.21, `qs` current, that guard `__proto__`.
- `JSON.parse` reviver that drops `__proto__` keys; `hasOwnProperty` checks in the
  merge loop (`Object.hasOwn(source, key)` won't help alone — see fails).

**Fails / not a real sanitizer:**
- Blocking only `__proto__` but not `constructor.prototype` or the bracket form
  `["__proto__"]` / `["constructor"]["prototype"]`.
- `hasOwnProperty` filtering on the **source** only — the *target* traversal
  (`target[key]`) is where `__proto__` resolves to the prototype; you must guard
  the key name, not just own-ness.
- Sanitizing top-level keys but recursing without re-checking nested keys.
- Removing `__proto__` as a literal string but the parser having already created a
  real prototype link (`JSON.parse` does not, but `qs`/dotted parsers may).
- Freezing a subclass prototype while `Object.prototype` stays writable.
- Version pin claimed but a transitive dependency ships the vulnerable merge.

## 6. Detection methodology

1. **Find merge/set/clone sinks:**
   ```
   rg -n '\b(_\.|lodash\.)(merge|mergeWith|defaultsDeep|set|setWith)\b|\bmergeDeep\b|deep-?assign|deep-?extend|merge-deep'
   rg -n '\$\.extend\(\s*true|jQuery\.extend\(\s*true|Object\.assign\('
   rg -n 'for\s*\(\s*(const|let|var)?\s*\w+\s+in\s+\w+\)'   # hand-rolled recursive merge
   ```
2. **Find nested-object parsers:**
   ```
   rg -n "qs\.parse|querystring\.parse|require\(['\"]qs['\"]\)|extended:\s*true"
   rg -n 'set\(\s*\w+\s*,\s*\w*(path|key)'                   # set-by-path helpers
   ```
3. **Confirm attacker controls keys:** does the source supply object keys (JSON
   body, `a[b][c]`/`a.b.c` query expansion), not only values?
4. **Check for a key guard** on the path: is `__proto__`/`constructor`/`prototype`
   blocked in *all* forms (dotted, bracket, nested)? Is the store a null-prototype
   object/`Map`? Is there schema validation rejecting unknown keys? (see §5)
5. **Classify the impact / find the gadget:**
   - Client-side → look for a library that reads an *unset* option and falls through
     to the prototype (`config.x || default`), feeding a DOM XSS/`src`/`innerHTML`
     sink.
   - Server-side → look for a downstream `child_process` (options `shell`/`env`),
     template render, or other library reading polluted defaults → RCE.
6. **Confirm reachability:** is the sink on an exposed route/handler, pre-auth?

## 7. Modern & niche variants

- **Client-side PP → DOM XSS gadget chain:** pollution alone rarely executes; it
  arms a *gadget* — a library reading a normally-unset property that flows into an
  HTML/`src`/`script` sink (jQuery, sanitizer configs, ad/analytics loaders,
  Google Tag Manager, sanitize-html option defaults). Report PP + the reachable
  gadget as a chain, not just the pollution.
- **Server-side PP → RCE:** the highest-severity form. Gadgets:
  - **`child_process` options:** polluting `Object.prototype.shell = '/bin/sh'`,
    `.env`, `.NODE_OPTIONS='--require /proc/self/…'`, or argument arrays so a later
    `spawn/exec/fork` runs attacker commands.
  - **Template-engine options:** Pug/Handlebars/EJS/Lodash templates read compile
    options off the prototype (`compileDebug`, `client`, `outputFunctionName`,
    delimiters) → injected JS in the compiled render function → RCE on `res.render`.
- **Vulnerable utilities:** `lodash.merge`/`mergeWith`/`defaultsDeep`/`set`/`setWith`
  (pre-patch), `jQuery.extend(true, …)`, `deep-assign`, `merge-deep`, `deep-extend`,
  `hoek`/`assign`, and any hand-rolled recursive `for…in` merge without a key guard.
- **Key forms to test:** `__proto__`, `constructor.prototype`, bracket
  `["__proto__"]`, `["constructor"]["prototype"]`, and dotted `a.__proto__.b` /
  `a[__proto__][b]` produced by query-string/dotted-path parsers. A guard that
  misses any one form is bypassable.
- **Parser-built nesting:** `qs`/`express` extended body parsing and dotted-path
  expanders create the nested `__proto__` object automatically from flat input —
  the developer never wrote a merge but the parser did the walk.

## 8. Common false positives

- Merges where keys are developer-controlled constants, not from a source.
- Stores built on `Object.create(null)` / `Map`, or validated by strict schema
  (`additionalProperties:false`) before merging.
- Patched library versions with a documented `__proto__` guard, and no vulnerable
  transitive copy.
- Shallow `Object.assign`/spread of a flat, key-validated object (no recursion, no
  attacker-controlled `__proto__` at top level after guard).
- Pollution with no reachable gadget/sink (still note as low/info if source→sink of
  the pollution is confirmed but no impact path exists).

## 9. Severity & exploitability

Base **High**. **Critical** when a reachable gadget escalates to RCE (server-side
`child_process`/template-engine option gadget) or to auth bypass (polluting an
`isAdmin`/`role` default that a downstream check reads). **Medium/High** for
client-side PP that arms a DOM XSS gadget (chain severity = the XSS impact).
**Low/Info** if pollution is confirmed but no gadget/sink is reachable. Raise for
pre-auth, default-config-vulnerable dependencies. See `references/severity-model.md`.

## 10. Remediation

Reject `__proto__`/`constructor`/`prototype` keys in every recursive merge/set in
all forms (dotted, bracket, nested). Store untrusted key/value data in
`Object.create(null)` objects or `Map`. Validate input against a strict schema
(`additionalProperties:false`) before merging. Upgrade lodash/`qs`/merge utilities
to patched versions and check transitive deps. `Object.freeze(Object.prototype)` as
defense-in-depth. Avoid deep-merging untrusted input into option objects consumed
by `child_process` or template engines.

## 11. Output

Append each confirmed finding to **`findings/14-prototype-pollution.md`** using
`references/finding-template.md`. Set `Class: Prototype Pollution`, `CWE: CWE-1321`,
and in **Chain potential** name the primitive precisely: *global property injection*
(consumes attacker keys; **provides** a gadget trigger) → then name the reachable
gadget it feeds: *RCE via child_process/template-engine options*, *DOM XSS via
library gadget* (chains into `cross-site-scripting`), or *auth-flag bypass*. PP is
almost always reported as a **chain** with its gadget — always identify the
downstream sink the pollution reaches.

**Primitives (controlled):** provides `GADGET` (-> `CODE_EXEC` server / `JS_EXEC` client); consumes none

## References
- CWE-1321; OWASP A08:2021; PortSwigger prototype-pollution research (client & server);
  Snyk/lodash & qs advisories; "Server-Side Prototype Pollution" gadget catalogues.
