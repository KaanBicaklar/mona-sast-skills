---
name: insecure-deserialization
description: >-
  SAST detection methodology for insecure deserialization (CWE-502) across Java
  (ObjectInputStream/ysoserial/Commons-Collections/Spring/JNDI), .NET
  (BinaryFormatter, LosFormatter/ViewState, Json.NET TypeNameHandling,
  ObjectStateFormatter), Python (pickle, unsafe PyYAML), PHP (unserialize + POP
  chains, phar://), Ruby (Marshal/YAML), and Node (node-serialize, funcster,
  unserialize). Covers magic-method gadget chains and how untrusted bytes reach a
  deserializer. Use when reviewing code that deserializes data. Writes confirmed
  findings to findings/10-insecure-deserialization.md.
---

# Insecure Deserialization — SAST Methodology

**Class:** Insecure Deserialization · **CWE-502** · **OWASP:** A08 Software and Data Integrity Failures
**Findings file:** `findings/10-insecure-deserialization.md`

## 1. Overview

Insecure deserialization occurs when attacker-controlled bytes are handed to a
deserializer that reconstructs arbitrary object graphs and, during
reconstruction, invokes type constructors, setters, or "magic" lifecycle methods.
If any reachable class (a *gadget*) performs a dangerous action in those methods,
chaining gadgets turns byte control into remote code execution. The core test:
do untrusted bytes reach a native-object deserializer (not a data-only parser)
that permits arbitrary or polymorphic types? If yes, assume RCE is possible
unless a strict type allowlist gates it.

## 2. Where it lives

- Session/state stores: serialized objects in cookies, hidden form fields, cache,
  message queues, or a database blob column.
- RPC/messaging: Java RMI, JMX, JMS, AMQP/Kafka payloads, .NET remoting.
- API bodies that deserialize with type information (`TypeNameHandling`,
  polymorphic Jackson, `phar://` stream wrappers).
- File uploads/imports that are `unserialize`d, `pickle.load`ed, or `Marshal.load`ed.
- Framework internals: ASP.NET `ViewState`/`__VIEWSTATE`, Node objects passed to
  `node-serialize`.

## 3. Sources (tainted input)

All HTTP inputs (body, cookies, hidden fields, headers), uploaded/imported files,
queue/RPC payloads, and cache entries. **Second-order:** a serialized blob stored
earlier (session in DB/Redis, a queued job) and later deserialized — trace it to
the original write. PHP `phar://` is a niche source: a filesystem operation on an
attacker-influenced path can trigger deserialization of embedded metadata.

## 4. Sinks (dangerous operations)

```java
// Java — dangerous
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object o = ois.readObject();                       // arbitrary gadget graph → RCE
XMLDecoder dec = new XMLDecoder(inputStream); dec.readObject();
// ysoserial payloads target: Commons-Collections, Spring, Groovy, JDK gadgets;
// many pivot to JNDI: InitialContext.lookup(attackerUrl) → remote class load.
```
```csharp
// .NET — dangerous
new BinaryFormatter().Deserialize(stream);         // banned by MS, still found
new LosFormatter().Deserialize(viewState);         // ViewState w/o MAC → RCE
new ObjectStateFormatter().Deserialize(data);
JsonConvert.DeserializeObject(json,
    new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }); // gadget via $type
```
```python
# Python — dangerous
import pickle;  pickle.loads(data)                 # __reduce__ → arbitrary call
import yaml;    yaml.load(data)                    # no SafeLoader → object construction
jsonpickle.decode(data)                            # reconstructs arbitrary types
```
```php
// PHP — dangerous
$obj = unserialize($_COOKIE['data']);              // POP chain via __wakeup/__destruct
file_exists("phar://" . $userPath);                // phar:// → metadata deserialization
```
```ruby
# Ruby — dangerous
Marshal.load(data)                                 # gadget chain → RCE
YAML.load(data)                                    # pre-3.1 default = unsafe (Psych)
```
```javascript
// Node — dangerous
require('node-serialize').unserialize(userInput);  // IIFE payload → RCE
require('funcster').deepDeserialize(userInput);
require('serialize-to-js') / 'cryo' with untrusted input
```

Any of these on untrusted bytes is dangerous. The distinguishing feature is
**type reconstruction**: the deserializer instantiates classes named or implied
in the data, versus a data-only parser that only produces strings/numbers/maps.

## 5. Sanitizers / safe patterns

**Safe:** do not deserialize untrusted data with native/polymorphic serializers.
Use **data-only formats** (JSON/Protobuf/MessagePack) mapped to known DTOs with
**no polymorphic typing**. Where native deserialization is unavoidable, enforce a
**strict class allowlist**: Java `ObjectInputFilter`/`setObjectInputFilter`
(JEP 290) or a look-ahead `resolveClass` allowlist; .NET avoid `BinaryFormatter`
entirely and set `TypeNameHandling.None`; Python use `yaml.safe_load` and never
`pickle` untrusted data; PHP `unserialize($data, ['allowed_classes' => false])`;
Ruby `YAML.safe_load`, avoid `Marshal.load` on untrusted input. Add integrity:
sign/MAC serialized state (e.g. ViewState MAC, HMAC cookies) so tampering is
rejected before deserialization.

**Fails / not a real sanitizer:**
- **Blocklisting known gadget classes** — the gadget space is open-ended; new
  chains appear constantly. Only allowlisting works.
- Encryption/encoding (base64, gzip) mistaken for a security control — it hides
  nothing from an attacker who controls the plaintext.
- MAC present but the **key is default/leaked/hard-coded** (classic ViewState
  RCE) — the signature is bypassable.
- `allowed_classes` set to an over-broad list, or `true` (no restriction).
- Type allowlist applied to one deserializer while another unguarded call exists.
- Assuming a "safe" JSON library is safe while `TypeNameHandling`/`enableDefaultTyping`
  or a `$type`/`!!python/object` tag re-enables polymorphism.

## 6. Detection methodology

1. **Find deserializer sinks.**
   ```
   rg -n 'readObject\(|ObjectInputStream|XMLDecoder|readUnshared'
   rg -n 'BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter'
   rg -n 'TypeNameHandling|enableDefaultTyping|@JsonTypeInfo'
   rg -n 'pickle\.loads?|yaml\.load\b|jsonpickle|Marshal\.load|YAML\.load\b'
   rg -n 'unserialize\(|phar://|node-serialize|funcster|serialize-to-js'
   ```
2. **Confirm the input is untrusted:** trace the byte source to HTTP/file/queue/
   cache (directly or second-order). Constant/local test data is not a finding.
3. **Determine type freedom:** does the call reconstruct arbitrary/polymorphic
   types (native serializer, `TypeNameHandling.All`, `yaml.load`, `pickle`)? or is
   it a data-only parse into a fixed DTO?
4. **Check for a real gate:** JEP 290 filter / `resolveClass` allowlist / `safe_load`
   / `allowed_classes=false` / MAC on the path? Verify it is not one of the §5
   failures.
5. **Assess gadget availability:** are known gadget libraries on the classpath
   (Commons-Collections, Spring, Groovy, Jackson databind; .NET gadgets)? Presence
   raises confidence to RCE.
6. **Confirm reachability:** exposed endpoint/consumer, reachable (pre-auth?).

## 7. Modern & niche variants

- **Java `ObjectInputStream.readObject` + gadget chains:** the archetypal case.
  `ysoserial` weaponizes gadget chains in **Commons-Collections**, **Spring**,
  **Groovy**, **BeanShell**, and pure-JDK classes; execution rides
  `readObject`/`readResolve`/`InvocationHandler` hops. Many chains **pivot through
  JNDI** — a gadget calls `InitialContext.lookup(attackerUrl)`, and the JNDI/LDAP
  reference loads a remote factory class = RCE (the Log4Shell mechanism). Also
  `XMLDecoder.readObject` executes arbitrary `java.beans` expressions.
- **.NET:** `BinaryFormatter`/`SoapFormatter`/`NetDataContractSerializer` on
  untrusted input are RCE by design (ysoserial.net gadgets). **ViewState**:
  `LosFormatter`/`ObjectStateFormatter` without MAC — or with a known/default
  machine key — deserializes attacker `__VIEWSTATE` to RCE. **Json.NET**
  `TypeNameHandling.All`/`Objects`/`Auto` lets `$type` name a gadget type
  (`ObjectDataProvider`, `WindowsIdentity`) for RCE.
- **Python:** `pickle.loads` runs `__reduce__`/`__reduce_ex__`, letting a payload
  return `(os.system, ('cmd',))` — direct RCE. Unsafe **PyYAML** `yaml.load`
  honors `!!python/object/apply:os.system` tags to instantiate/call arbitrary
  callables. `jsonpickle`, `dill`, and `shelve` share the pickle risk.
- **PHP:** `unserialize` on untrusted data drives **POP (Property-Oriented
  Programming) chains** — magic methods `__wakeup`, `__destruct`, `__toString`,
  `__call` on in-scope classes are chained into file writes or code execution.
  **`phar://`** deserialization triggers object instantiation from crafted PHAR
  metadata via *any* filesystem function on an attacker-influenced path
  (`file_exists`, `fopen`, `getimagesize`), no explicit `unserialize` needed.
- **Ruby:** `Marshal.load` reconstructs arbitrary objects (universal RDoc/Rails
  gadget chains → RCE). `YAML.load` (Psych) before safe-by-default honored
  `!ruby/object` tags to instantiate arbitrary classes.
- **Node:** `node-serialize`/`funcster`/`serialize-to-js`/`cryo` reconstruct
  functions from serialized `_$$ND_FUNC$$_` payloads; an embedded IIFE executes
  on deserialization = RCE.
- **Magic-method gadget-chain intuition:** the danger is never the top-level type
  — it is the *lifecycle callbacks* invoked during reconstruction (`readObject`,
  `__wakeup`/`__destruct`, `__reduce__`, `readResolve`, property setters). Spotting
  a finding = "untrusted bytes reach a reconstructor that calls user-defined
  lifecycle code on classes available in the app."

## 8. Common false positives

- Data-only parsers mapping to fixed DTOs with no polymorphic typing
  (`JsonConvert` with `TypeNameHandling.None`, `yaml.safe_load`, Jackson without
  default typing).
- Deserialization of trusted, integrity-protected data (validated MAC with a
  secret, non-default key) from a trusted source.
- Local/config/test fixtures deserialized from constants, not request data.
- `pickle`/`Marshal` over an internal, non-attacker-reachable channel (still note
  as defense-in-depth, but lower severity/confidence).

## 9. Severity & exploitability

Base **Critical** — native/polymorphic deserialization of untrusted input is RCE
by default, especially with gadget libraries present. **High** if type freedom is
constrained but not fully allowlisted, or the sink is reachable only post-auth.
Lower only when a proven strict allowlist/`safe_load` gate is on the path (then
it is not a finding) or the channel is genuinely unreachable by attackers.
See `references/severity-model.md`.

## 10. Remediation

Prefer data-only formats mapped to known types with no polymorphic typing. Where
native deserialization is required, enforce a strict class allowlist (JEP 290
`ObjectInputFilter`, `resolveClass`), disable `TypeNameHandling`/`enableDefaultTyping`,
use `yaml.safe_load`/`YAML.safe_load`, `unserialize(..., ['allowed_classes' => false])`,
and never `pickle`/`Marshal` untrusted data. Sign/MAC any serialized state with a
strong non-default key. Remove unused gadget-prone libraries from the classpath.

## 11. Output

Append each confirmed finding to **`findings/10-insecure-deserialization.md`**
using `references/finding-template.md`. Set `Class: Insecure Deserialization` and
`CWE: CWE-502`. In **Chain potential** note that this class typically **provides
the terminal RCE primitive** (arbitrary code execution / arbitrary object
instantiation) and may **provide** a *JNDI/SSRF pivot* (remote class load) or
*arbitrary file write*; it commonly **consumes** an *info-leak of a signing key /
machine key* from another finding (turning a MAC-protected sink exploitable) or a
*second-order write* that plants the serialized blob.

**Primitives (controlled):** provides `CODE_EXEC`,`OUTBOUND_REQUEST` (JNDI/SSRF),`FILE_WRITE`; consumes `GADGET`,`SECRET_LEAK` (signing/machine key)

## References
- CWE-502; OWASP A08:2021 Software and Data Integrity Failures; OWASP
  Deserialization Cheat Sheet; ysoserial / ysoserial.net gadget research.
