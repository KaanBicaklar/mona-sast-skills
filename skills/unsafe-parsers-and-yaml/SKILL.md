---
name: unsafe-parsers-and-yaml
description: >-
  SAST detection methodology for unsafe parser configurations (CWE-502,
  CWE-1236, CWE-776), covering PyYAML yaml.load without SafeLoader, SnakeYAML
  (Java), Jackson polymorphic deserialization, CSV/spreadsheet formula injection
  (DDE), and resource-exhaustion via billion-laughs / deeply-nested JSON/XML/TOML
  and archive/entity expansion. Use when reviewing code that loads YAML, uses
  polymorphic JSON typing, exports CSV/XLSX, or parses untrusted structured data.
  Cross-references the xxe and insecure-deserialization skills. Writes confirmed
  findings to findings/12-unsafe-parsers-and-yaml.md.
---

# Unsafe Parsers & YAML — SAST Methodology

**Class:** Unsafe Parsers & YAML · **CWE-502 / CWE-1236 / CWE-776** · **OWASP:** A08 / A03
**Findings file:** `findings/12-unsafe-parsers-and-yaml.md`

## 1. Overview

Structured-data parsers become dangerous in three ways: (1) **object-instantiating
tags** — YAML/JSON parsers configured to build arbitrary types from the document
(RCE, a CWE-502 cousin of deserialization); (2) **formula injection** —
CSV/spreadsheet cells beginning with `= @ + -` that a spreadsheet app executes as
formulas/DDE (CWE-1236); and (3) **resource exhaustion** — entity/nesting/archive
expansion that a permissive parser lets balloon (CWE-776). The core tests: does a
parser reconstruct types from untrusted input (unsafe YAML/polymorphic Jackson)?
does exported data flow to a spreadsheet without neutralizing leading formula
characters? and is any parser missing depth/size limits on untrusted input?

## 2. Where it lives

- Config/import features that load YAML/TOML/JSON supplied or influenced by users
  (CI pipelines, plugin manifests, "import settings", Kubernetes-style specs).
- Java services using SnakeYAML or Jackson with default typing enabled.
- Any endpoint accepting JSON that a polymorphic mapper deserializes.
- CSV/XLSX **export** paths that write user-controlled fields (reports, contact
  exports, admin dumps) later opened in Excel/LibreOffice/Sheets.
- Bulk-parse workers handling untrusted JSON/XML/TOML or nested archives.

## 3. Sources (tainted input)

All HTTP inputs carrying structured data (body, uploaded YAML/JSON/CSV/archives),
imported config, and webhook payloads. For formula injection the source is any
user-controlled field that later lands in an exported cell (name, address, note).
**Second-order:** a stored profile field exported to CSV weeks later, or an
uploaded YAML processed by a background job — trace to the original write/upload.

## 4. Sinks (dangerous operations)

```python
# Python — dangerous (object construction / RCE)
import yaml
yaml.load(untrusted)                       # default Loader honors !!python/object tags
yaml.load(untrusted, Loader=yaml.Loader)   # explicit full loader = still unsafe
yaml.unsafe_load(untrusted)
```
```ruby
# Ruby — dangerous
YAML.load(untrusted)                        # pre-3.1 default resolves !ruby/object tags
Psych.load(untrusted)
```
```java
// Java — dangerous
new org.yaml.snakeyaml.Yaml().load(untrusted);   // default constructor → arbitrary types (SnakeYAML <2.0)
ObjectMapper m = new ObjectMapper();
m.enableDefaultTyping();                          // polymorphic → gadget via @class/@type
// or a field annotated @JsonTypeInfo(use = Id.CLASS) on an untrusted payload
```
```javascript
// Node — dangerous
require('js-yaml').load(str, { schema: DEFAULT_FULL_SCHEMA });  // custom !!js tags
```
```csv
# CSV / spreadsheet formula injection — dangerous exported cell
=cmd|'/C calc'!A0          ; leading = triggers DDE / command exec on open
@SUM(1+1)*cmd|'/C ...'      ; leading @ + - also start formulas
+1+1   -1+1                 ; leading + / - likewise
```

Dangerous whenever: a YAML/JSON loader reconstructs types from untrusted input,
or an exported cell begins with `= @ + -` (or `\t`/`\r` then one of them), or a
parser processes untrusted input with no depth/size cap.

## 5. Sanitizers / safe patterns

**Safe:**
- **YAML:** `yaml.safe_load` (PyYAML) / `SafeLoader`; `YAML.safe_load`
  (Ruby); SnakeYAML with a `SafeConstructor`/typed constructor and, on 2.0+, the
  default no-global-tags behavior; js-yaml default `load` (safe schema since v4).
- **Jackson:** leave default typing **off** (`TypeNameHandling.None` equivalent);
  if polymorphism is required, restrict with `PolymorphicTypeValidator`
  (`BasicPolymorphicTypeValidator`) allowlisting exact base/subtypes.
- **CSV/formula:** prefix any cell starting with `= @ + -` (or tab/CR) with a
  single quote `'` or a leading space, or wrap in quotes and strip control chars;
  better, export in a non-formula format (native XLSX cells typed as text, or
  set the cell type explicitly) rather than raw CSV.
- **Resource limits:** set max document size, max nesting depth, entity-expansion
  caps, and decompressed-size limits (zip-bomb guard) on every parser touching
  untrusted input; stream rather than fully materialize.

**Fails / not a real sanitizer:**
- `yaml.load(data, Loader=yaml.Loader)` or `FullLoader` on untrusted input —
  `FullLoader` still constructs many Python objects; only `SafeLoader` is safe.
- Jackson `PolymorphicTypeValidator` with an over-broad base type (e.g. `Object`)
  — effectively re-permits gadgets.
- CSV neutralization that only checks `=` but not `@`, `+`, `-`, or leading
  tab/carriage-return that shift the trigger character.
- HTML-escaping or SQL-escaping an exported cell — wrong grammar; the spreadsheet
  formula engine is the sink, not HTML/SQL.
- Depth limit on JSON but not on the archive/entity layer (zip bomb, billion
  laughs still land).
- Assuming "it's just config" — attacker-influenced config is untrusted input.

## 6. Detection methodology

1. **Find unsafe loaders and polymorphic typing.**
   ```
   rg -n 'yaml\.load\b|yaml\.unsafe_load|Loader\s*=\s*(yaml\.)?(Loader|FullLoader|UnsafeLoader)'
   rg -n 'YAML\.load\b|Psych\.load\b'
   rg -n 'new Yaml\(|SnakeYAML|enableDefaultTyping|@JsonTypeInfo|activateDefaultTyping'
   rg -n "js-yaml.*(FULL_SCHEMA|DEFAULT_FULL)"
   ```
2. **Find CSV/spreadsheet export sinks and check neutralization.**
   ```
   rg -n 'csv\.writer|DictWriter|StringWriter.*csv|createCSV|to_csv|WriteRecords|fputcsv|openpyxl|XSSFWorkbook'
   ```
   Then verify each user-controlled cell is prefixed/escaped for leading `= @ + -`.
3. **Confirm untrusted input reaches the loader/export** (directly or
   second-order). Constant/config-from-trusted-source is not a finding.
4. **Check the loader mode / validator:** SafeLoader? PTV allowlist? For Jackson,
   is default typing enabled anywhere globally?
5. **Check resource limits** on untrusted-input parsers: max size, depth, entity
   expansion, decompression cap.
6. **Classify:** type-instantiation RCE (→ overlaps `insecure-deserialization`),
   formula injection (CWE-1236), or resource exhaustion (CWE-776).

## 7. Modern & niche variants

- **PyYAML `yaml.load` without SafeLoader:** the default and `FullLoader`/`Loader`
  honor tags like `!!python/object/apply:os.system ["id"]`, instantiating and
  calling arbitrary callables — direct RCE from a config/import feature. Ruby
  `YAML.load`/`Psych.load` (pre-3.1) do the same via `!ruby/object`.
- **SnakeYAML (Java):** the default `Yaml().load` constructor resolves global
  tags (`!!javax.script.ScriptEngineManager`, `!!com.sun...`) to build arbitrary
  types — a well-known SSRF/RCE gadget (SnakeYAML < 2.0; 2.0 disables global tags
  by default). Spring Boot config/actuator paths have been affected.
- **Jackson polymorphic deserialization:** `enableDefaultTyping()` /
  `activateDefaultTyping()` or `@JsonTypeInfo(use = Id.CLASS/MINIMAL_CLASS)` let a
  `@class`/`@type` field name a gadget (`TemplatesImpl`, JNDI-backed data sources)
  → RCE. This is the JSON analogue of Java deserialization; cross-reference the
  `insecure-deserialization` skill.
- **CSV / spreadsheet formula injection (CWE-1236, DDE):** an exported cell such
  as `=cmd|'/C calc'!A0` or `@WEBSERVICE(...)` executes when the victim opens the
  file in Excel/LibreOffice/Sheets — turning a benign export into client-side
  command execution or silent data exfiltration (`=HYPERLINK`, `=WEBSERVICE`,
  DDE). The trigger characters are `=`, `@`, `+`, `-` (and after a leading tab/CR).
- **Resource exhaustion (CWE-776):** **billion-laughs** entity expansion (XML —
  overlaps `xxe`), deeply nested JSON/TOML/YAML that blows the stack or heap, and
  **archive/decompression bombs** (zip/gzip expanding to gigabytes). A permissive
  parser with no depth/size/expansion cap is a one-request DoS.
- **Boundary with dedicated skills:** object-instantiating **XML** entities belong
  to `xxe`; native binary serializers (`pickle`, `ObjectInputStream`,
  `BinaryFormatter`, PHP `unserialize`) belong to `insecure-deserialization`. This
  skill owns YAML/JSON-typing config, spreadsheet formula injection, and
  parser resource limits — but always cross-reference when a gadget chain is the
  real payload.

## 8. Common false positives

- `yaml.safe_load`/`SafeLoader`, `YAML.safe_load`, js-yaml default `load`, or
  SnakeYAML 2.0+/`SafeConstructor` on the untrusted path.
- Jackson with default typing off, or a tight `PolymorphicTypeValidator`
  allowlist of exact expected subtypes.
- CSV exports of purely numeric/enumerated server data, or exports that neutralize
  all four trigger characters (and tab/CR).
- Parsers with configured size/depth/expansion limits on untrusted input.
- YAML/JSON loaded exclusively from trusted, non-attacker-writable config.

## 9. Severity & exploitability

Base **Critical** for unsafe YAML/SnakeYAML/Jackson type instantiation on
untrusted input (RCE). **Medium–High** for CSV/formula injection (client-side
code execution/exfiltration, but requires the victim to open the file and enable
formulas). **Medium** for resource-exhaustion DoS (**High** if trivially
pre-auth and unbounded). Raise for pre-auth reachable, lower for trusted-only
config sources. See `references/severity-model.md`.

## 10. Remediation

Use safe loaders (`safe_load`/`SafeLoader`, `YAML.safe_load`, SnakeYAML
`SafeConstructor` or 2.0+, js-yaml default schema). Keep Jackson default typing
off; if unavoidable, constrain with a strict `PolymorphicTypeValidator`. Neutralize
CSV cells starting with `= @ + -` (and leading tab/CR) or export typed XLSX text
cells. Enforce max size, nesting depth, entity-expansion, and decompressed-size
limits on every parser handling untrusted input.

## 11. Output

Append each confirmed finding to **`findings/12-unsafe-parsers-and-yaml.md`**
using `references/finding-template.md`. Set `Class: Unsafe Parsers & YAML` and
`CWE: CWE-502` (type-instantiation), `CWE-1236` (formula injection), or `CWE-776`
(resource exhaustion) as appropriate. In **Chain potential** note primitives such
as *arbitrary code execution* (unsafe YAML/Jackson — provides the terminal RCE
primitive, overlapping `insecure-deserialization`), *client-side command
execution / data exfiltration* (CSV formula injection — provides a phishing-grade
primitive), and *denial of service* (resource exhaustion). Cross-link to related
`xxe` / `insecure-deserialization` findings when the same untrusted input feeds
both.

**Primitives (controlled):** provides `CODE_EXEC`,`FILE_READ`; consumes `GADGET`

## References
- CWE-502; CWE-1236 Improper Neutralization of Formula Elements in a CSV File;
  CWE-776 Improper Restriction of Recursive Entity References; OWASP A08:2021 /
  A03:2021; OWASP CSV Injection and Deserialization Cheat Sheets; SnakeYAML and
  Jackson polymorphic-typing advisories.
