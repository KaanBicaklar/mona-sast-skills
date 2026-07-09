---
name: code-injection
description: >-
  SAST detection methodology for code injection / dynamic evaluation (CWE-94,
  CWE-95), including eval/exec/Function(), Python compile/__import__, Node
  vm/vm2 sandbox escape, PHP preg_replace /e, assert/create_function, dynamic
  require/import, and expression-engine evaluation. Use when reviewing code that
  evaluates strings as code. Writes confirmed findings to
  findings/04-code-injection.md.
---

# Code Injection — SAST Methodology

**Class:** Code Injection · **CWE-94 (and CWE-95)** · **OWASP:** A03 Injection
**Findings file:** `findings/04-code-injection.md`

## 1. Overview

Code injection occurs when attacker-controlled data reaches a sink that
**evaluates it as program code** in the application's own language runtime —
`eval`, `exec`, `Function()`, dynamic `require`/`import`, expression evaluators,
or a regex-with-eval modifier. Distinct from command injection (which targets the
OS shell): here the injected payload runs *in-process* with full language power.
The core test: does a source flow into an API that compiles or executes a string
as code, without that string being a fixed literal?

## 2. Where it lives

- Direct dynamic-eval APIs: Python `eval`/`exec`/`compile`/`__import__`, JS
  `eval`/`new Function`/`setTimeout("…")`, PHP `eval`/`assert`/`create_function`/
  `preg_replace` `/e`, Ruby `eval`/`instance_eval`/`send`, Java scripting
  (`ScriptEngine.eval`, Nashorn, Groovy `Eval`), .NET `CSharpScript`/`DataTable.
  Compute`.
- "Sandboxes": Node `vm`/`vm2`, Python `RestrictedPython`, Lua sandboxes — often
  escapable.
- Rule/expression/formula engines: SpEL, OGNL, MVEL, JEXL, JsonLogic, math/formula
  parsers, feature-flag and workflow DSLs that `eval` conditions.
- Dynamic module loading: `require(userVar)`, `import(userVar)`, `importlib.
  import_module`, class/method dispatch by name.
- Deserialization that reconstructs code objects (adjacent class; cross-reference
  the deserialization skill).

## 3. Sources (tainted input)

All HTTP inputs, plus **config/rule content** authored by users or tenants (a
formula field, a "custom script" setting), plugin/template metadata, DB-stored
expressions re-evaluated later (**second-order**), and third-party/LLM output
that is `eval`'d. Any place that says "let users write a small expression" is a
source.

## 4. Sinks (dangerous operations)

```python
# Python — dangerous
eval(request.args["expr"])                         # arbitrary expression
exec(user_code)                                    # arbitrary statements
compile(src, "<s>", "exec")                        # then exec'd
__import__(request.args["mod"])                    # dynamic import
getattr(obj, request.args["m"])()                  # method dispatch by name
```
```javascript
// Node — dangerous
eval(req.body.code);
const f = new Function("x", req.query.body);        // Function constructor = eval
setTimeout(req.query.cb, 100);                       // string arg is eval'd
vm.runInNewContext(userCode);                        // vm is NOT a security boundary
const vm2 = require("vm2"); new vm2.VM().run(code);  // vm2 has known escapes (deprecated)
require(userModule);                                 // dynamic require → load/run
```
```php
// PHP — dangerous
eval($_GET['x']);
assert($_GET['x']);                                  // assert() evaluates strings (<8.0)
$f = create_function('$a', $_POST['body']);          // internal eval
preg_replace('/./e', $_GET['x'], $s);                // /e modifier = eval (removed in 7.0)
call_user_func($_GET['fn']);
```
```ruby
# Ruby — dangerous
eval(params[:code])
instance_eval(params[:code])
obj.send(params[:m])                                 # arbitrary method dispatch
```
```java
// Java — dangerous (JSR-223 / expression engines)
new ScriptEngineManager().getEngineByName("js").eval(userInput);
parser.parseExpression(userInput).getValue();        // Spring SpEL → RCE
Ognl.getValue(userInput, root);                       // OGNL → RCE
```

## 5. Sanitizers / safe patterns

**Safe:**
- **Don't evaluate input.** Replace "user expression" with a fixed set of
  operations selected by an allowlisted key, or a purpose-built parser that emits
  a restricted AST (no attribute access, no calls, no imports).
- For math, use a safe numeric evaluator (`ast.literal_eval` for literals only,
  `simpleeval`/`expr-eval` with functions disabled) — not `eval`.
- Dispatch by a hard-coded map (`{"add": add_fn}[key]`), never `getattr`/`send`
  on raw input.
- For dynamic imports, map an allowlisted name to a known module; never import a
  raw string.

**Fails / not a real sanitizer:**
- Blocklisting keywords (`import`, `__`, `os`, `system`) — Python gadgets
  (`().__class__.__bases__`, `__builtins__`, `getattr` chains, unicode
  homoglyphs, `\x` escapes) bypass every blocklist; JS uses
  `constructor.constructor`.
- `RestrictedPython`/`vm`/`vm2`/Lua sandboxes treated as trust boundaries — all
  have documented escapes (`vm2` is deprecated precisely because it is escapable;
  Node core `vm` was never a security boundary).
- Stripping parentheses/quotes — insufficient given attribute-access and template
  gadgets.
- `ast.literal_eval` believed safe but code actually calls `eval`, or
  `literal_eval` used on input that then feeds `exec`.
- Length/charset limits — RCE payloads can be very short (``__import__('os')``).

## 6. Detection methodology

1. **Find sinks:** grep the eval/compile/dynamic-dispatch APIs per language.
   ```
   rg -n '\beval\s*\(|\bexec\s*\(|\bcompile\s*\(|__import__|importlib\.import_module'
   rg -n 'new Function\s*\(|\bFunction\s*\(|setTimeout\([^,]*[\'"]|vm\.run|vm2|runInNewContext'
   rg -n '\beval\s*\(|\bassert\s*\(|create_function|preg_replace\s*\(.*/e|call_user_func'
   rg -n 'instance_eval|class_eval|\.send\s*\(|getattr\s*\('
   rg -n 'ScriptEngine|getEngineByName|parseExpression|Ognl\.|MVEL|JexlEngine|SpelExpressionParser'
   ```
2. **Confirm the argument is not a literal:** is any operand a variable, template
   literal, or formatted string derived from input?
3. **Trace to a source** (direct, stored rule/config, or third-party). Stop at a
   constant.
4. **Assess any "sandbox":** is it `vm`/`vm2`/RestrictedPython/keyword blocklist?
   Treat as bypassable unless proven otherwise (see §5).
5. **Confirm reachability** and note whether it is pre-auth. Expression-engine
   sinks (SpEL/OGNL) often hide behind framework features (SpEL in `@Value`,
   Spring Security expressions, Thymeleaf) — see the SSTI skill for template
   overlap.
6. **Classify:** direct `eval` (Critical RCE) vs constrained expression engine vs
   dynamic dispatch (may be limited to method selection).

## 7. Modern & niche variants

- **`eval`/`exec`/`Function()` with gadget chains:** even "restricted" contexts
  fall to language-native gadgets. Python: `().__class__.__base__.__subclasses__()`,
  `__builtins__`, `__import__`. JS: `[].constructor.constructor("return
  process")()` reaches `process`/`require` even inside `Function`.
- **Node `vm` / `vm2` sandbox escape:** `vm` is explicitly *not* a security
  boundary; `vm2` (now deprecated/unmaintained) had a series of escapes via
  `Proxy`, error stack traces, and `Symbol` handling. Any user code run in
  `vm`/`vm2` is effectively RCE. `isolated-vm` is the closer-to-safe option but
  still misusable.
- **PHP `preg_replace` `/e` modifier:** the replacement string is `eval`'d;
  `preg_replace('/(.*)/e', $_GET['x'], $s)`. Removed in PHP 7 but lives in legacy
  code. Pair with `assert($str)` (evaluates in <8.0) and `create_function`
  (internal `eval`).
- **`assert()` / `create_function()`:** both evaluate strings; still found in old
  frameworks and obfuscated webshells.
- **Dynamic `require`/`import`:** `require(userVar)` runs the module's top-level
  code; path traversal to attacker-writable files, or npm-style dependency
  confusion, turns it into RCE. Python `__import__`/`importlib` and
  `pickle`-adjacent `find_class` behave similarly.
- **Expression / rule-engine evaluators:** SpEL (`T(java.lang.Runtime)`), OGNL
  (Struts2 CVEs), MVEL, JEXL, JsonLogic, and formula parsers. Injected into
  `@Value("#{...}")`, Spring Security `@PreAuthorize`, or Thymeleaf `[[${...}]]`.
  These are the modern, high-impact server-side variants — cross-reference SSTI.
- **`setTimeout`/`setInterval` with a string argument:** the string is `eval`'d in
  global scope — an overlooked JS eval sink.
- **Deserialization → code execution:** `pickle.loads`, `yaml.load` (full loader),
  PHP `unserialize` with POP chains reconstruct objects that execute code; treat
  as a sibling class.

## 8. Common false positives

- `eval`/`Function` argument is a compile-time constant or built only from an
  allowlisted map.
- `ast.literal_eval` on data that never reaches `eval`/`exec`.
- Dynamic dispatch resolved through a hard-coded whitelist map, not raw input.
- Expression engine parsing a constant template with only bound data variables (no
  method/type access) — verify the evaluation context is locked down.

## 9. Severity & exploitability

Base **Critical** — in-process code execution. Confirmed direct `eval`/`exec`/
`Function`/`vm`/expression-engine-with-type-access sinks are Critical RCE, higher
priority when pre-auth or default-config. Constrained dynamic dispatch limited to
selecting among safe methods may drop to **High/Medium**. See
`references/severity-model.md`.

## 10. Remediation

Eliminate dynamic evaluation of input. Replace expressions with an allowlisted
operation set or a restricted, side-effect-free parser. Use safe literal/math
evaluators instead of `eval`. Dispatch through hard-coded maps. Do not rely on
`vm`/`vm2`/RestrictedPython or keyword blocklists as trust boundaries. Lock down
expression-engine evaluation contexts (disable type/method references).

## 11. Output

Append each confirmed finding to **`findings/04-code-injection.md`** using
`references/finding-template.md`. Set `Class: Code Injection`, `CWE: CWE-94`
(use `CWE-95` for eval-specific `eval`/`exec` cases), and in **Chain potential**
name primitives such as *remote code execution* (terminal — usually chain end),
or note when the finding *consumes* a primitive like *arbitrary file write* (drop
a module then `require` it) or *stored input* (a persisted expression re-evaluated
server-side).

**Primitives (controlled):** provides `CODE_EXEC`; consumes none

## References
- CWE-94; CWE-95; OWASP A03:2021 Injection; OWASP Code Injection; SpEL/OGNL
  injection advisories (Struts2, Spring).
