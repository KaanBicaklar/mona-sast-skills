---
name: xpath-and-xml-injection
description: >-
  SAST detection methodology for XPath and XML injection (CWE-643, CWE-91),
  including XPath authentication bypass, blind/boolean XPath, XQuery injection,
  and XML structure injection. Use when reviewing code that builds XPath/XQuery
  queries or XML documents from user input. For external entities see the
  separate xxe skill. Writes confirmed findings to
  findings/07-xpath-and-xml-injection.md.
---

# XPath & XML Injection — SAST Methodology

**Class:** XPath / XML Injection · **CWE-643 (and CWE-91)** · **OWASP:** A03
Injection
**Findings file:** `findings/07-xpath-and-xml-injection.md`

## 1. Overview

XPath injection occurs when attacker-controlled data is concatenated into an
XPath/XQuery expression, letting the attacker alter the query's *logic* — widen a
node match, inject boolean conditions, or bypass an authentication predicate.
XML (structure) injection occurs when input is written into an XML document
without encoding, letting the attacker inject tags/attributes and change the
document's structure. The core test: does a source reach an XPath/XQuery evaluator
or an XML serializer as part of the expression/markup rather than as
properly-escaped data? (For DTD/external-entity attacks, use the separate `xxe`
skill — do not duplicate XXE here.)

## 2. Where it lives

- XPath-backed authentication and lookups over XML user stores or config
  (`//user[name/text()='<u>' and password/text()='<p>']`).
- Search/filter features that query XML documents or XML databases (BaseX,
  eXist-db, MarkLogic via XQuery).
- SOAP/XML API handlers and config processors that select nodes by user input.
- XML document construction: building request/response/SAML/SOAP bodies by string
  concatenation instead of a DOM/serializer.
- Java (`javax.xml.xpath`), Python (`lxml`/`ElementTree` `.xpath`/`.find`), PHP
  (`DOMXPath::query`, SimpleXML `xpath`), .NET (`XPathNavigator`/`SelectNodes`),
  Node (`xpath`, `xmldom`).

## 3. Sources (tainted input)

All HTTP inputs — especially login fields, search terms, and IDs used to select
XML nodes. **Second-order**: values stored in the XML store or DB and re-used to
build a later XPath/XQuery. SOAP/XML request bodies and any user-authored config
that becomes part of a query or document are sources.

## 4. Sinks (dangerous operations)

```java
// Java — dangerous
String q = "//user[name='" + user + "' and pass='" + pw + "']";
xpath.evaluate(q, doc, XPathConstants.NODE);        // concat → auth bypass
```
```python
# Python (lxml / ElementTree) — dangerous
tree.xpath("//user[name='" + user + "']")
root.find(f".//user[@id='{uid}']")                  # f-string into XPath
```
```php
// PHP — dangerous
$x = new DOMXPath($dom);
$x->query("//user[name/text()='".$_GET['u']."']");
$sx->xpath("//user[@id='".$_GET['id']."']");        // SimpleXML
```
```csharp
// .NET — dangerous
nav.Select("//user[name='" + user + "']");
doc.SelectNodes("//user[@id='" + id + "']");
```
```javascript
// Node — dangerous
xpath.select(`//user[name='${user}']`, doc);
```
```java
// XML structure injection — dangerous
String xml = "<order><item>" + name + "</item><qty>" + qty + "</qty></order>";
// name = "x</item><price>0</price><item>" rewrites the document structure
```

## 5. Sanitizers / safe patterns

**Safe:**
- **Parameterize the XPath/XQuery**: bind variables via `XPath.setXPathVariable
  Resolver` / `XPathExpression` with `$var`, XQuery external variables
  (`declare variable $u external`), or a library that supports variable binding —
  values never touch the expression grammar.
- If binding is unavailable, encode values for the XPath string context: escape
  quotes correctly, or (better) construct string literals with `concat()` so a
  quote cannot terminate the literal.
- For XML **construction**, always build with a DOM/serializer (`DocumentBuilder`,
  `lxml.etree`, `XmlWriter`) that XML-encodes text/attribute values — never
  string-concatenate markup.
- Validate IDs against a strict allowlist where the format is known.

**Fails / not a real sanitizer:**
- Escaping single quotes only, while the query uses double quotes (or vice
  versa) — the attacker uses the other delimiter.
- HTML-escaping instead of XPath/XML encoding — `&lt;` etc. is the wrong grammar
  and often ineffective for XPath.
- Blocklisting `'` / `"` while `*`, `[`, `]`, `or`, `and`, `|` (union), and
  `text()`/`position()` still let the attacker alter logic without a quote break.
- Encoding the value but concatenating a second field raw.
- Relying on schema validation that permits the injected element/attribute.

## 6. Detection methodology

1. **Find sinks:** grep for XPath/XQuery evaluators and XML string-building.
   ```
   rg -n 'XPath|\.evaluate\(|compile\(.*//|XPathExpression|setXPathVariableResolver'
   rg -n '\.xpath\(|\.find\(|\.findall\(|DOMXPath|->query\(|->xpath\(|SelectNodes|SelectSingleNode'
   rg -n 'xpath\.select|xmldom|declare variable|xquery|BaseX|eXist|MarkLogic'
   rg -n '"<[a-zA-Z]+>"\s*\+|\+\s*"</|String\.format\(.*<'
   ```
2. **Confirm concatenation:** is a variable spliced into an XPath/XQuery string or
   into XML markup (`+`, f-string, `.format`, template literal)?
3. **Trace the operand to a source** (direct, SOAP body, or second-order). Stop at
   a constant.
4. **Check for binding/encoding on the path:** variable resolver / external
   variable (safe), correct quote handling or `concat()` (partial), or a
   DOM/serializer for XML construction. Missing/wrong = finding.
5. **Confirm reachability** — XML-backed login and search endpoints are often
   pre-auth.
6. **Classify:** auth bypass, blind boolean extraction, XQuery logic injection, or
   XML structure/tag injection.

## 7. Modern & niche variants

- **XPath authentication bypass:** the signature attack. For
  `//user[name='<u>' and password='<p>']`, a username or password of `' or '1'='1`
  (or `' or ''='`) makes the predicate always true, returning a user node and
  bypassing login. Also `x' or name()='user` and comment-free tautologies —
  XPath has no `--` comment, so attackers close the literal and append `or`.
- **Blind / boolean XPath injection:** when node contents aren't returned, inject
  boolean tests and observe true/false responses to extract the XML tree
  character-by-character: `and substring(//user[1]/password,1,1)='a'`,
  `and string-length(//user[1]/password)=32`, using `count()`, `position()`, and
  `substring()` as an oracle. Fully equivalent in power to blind SQLi over the XML
  store.
- **XQuery injection:** richer than XPath — FLWOR expressions, `declare`, and
  function calls. Injection can invoke built-in/extension functions (file access,
  HTTP, or even command execution in some XML DBs like BaseX `proc:system`,
  eXist/MarkLogic extension modules), escalating from data disclosure toward RCE.
  Look for XQuery built from input in native XML databases.
- **XML structure injection (CWE-91):** input written into a document without
  encoding injects new elements/attributes. Injecting `</item><price>0</price>` to
  alter an order, adding `<admin>true</admin>`, or breaking out of an attribute
  value. In SAML/SOAP contexts this borders on **XML signature wrapping** — moving
  or duplicating signed elements to change interpreted content while keeping a
  valid signature.
- **Union / node-set widening:** injecting `| //*` or `*` to return nodes outside
  the intended scope (e.g. dump all users/config).
- **Second-order XPath:** a stored attribute later concatenated into an XPath query
  for another operation.
- **XXE boundary:** external entities, parameter entities, and DTD abuse are a
  *distinct* class — do not analyze them here; route to the `xxe` skill. This skill
  covers only query-logic and structure injection.

## 8. Common false positives

- Queries using a variable resolver / external variables (bound, not
  concatenated).
- XPath/XQuery built solely from constants or an allowlisted identifier.
- XML produced by a DOM/serializer that encodes text and attributes.
- Read-only queries over non-sensitive XML behind strong auth (note, but severity
  drops).

## 9. Severity & exploitability

Base **High**. **Critical** when it yields authentication bypass, blind
extraction of credentials/secrets from the XML store, or XQuery injection reaching
file access / command execution in an XML database — especially pre-auth. XML
structure injection ranges **Medium–High** depending on what the injected markup
controls (order tampering, SAML/SOAP assertion manipulation). See
`references/severity-model.md`.

## 10. Remediation

Parameterize XPath/XQuery with bound variables / external variables so input never
enters the expression grammar; where unavailable, build string literals with
`concat()` and validate IDs against an allowlist. Construct XML exclusively with a
DOM/serializer that encodes values — never concatenate markup. For XML DBs,
disable dangerous extension functions and apply least privilege.

## 11. Output

Append each confirmed finding to
**`findings/07-xpath-and-xml-injection.md`** using
`references/finding-template.md`. Set `Class: XPath / XML Injection`, `CWE:
CWE-643` (use `CWE-91` for XML structure injection), and in **Chain potential**
name primitives such as *auth bypass* (`' or '1'='1` in an XML login), *arbitrary
data read* (blind XPath extraction → leaked secrets for other chains), *file read
/ command execution* (XQuery extension functions — consumed by the
command-injection chain), or *structure tampering* (SAML/SOAP assertion
manipulation → privilege escalation).

**Primitives (controlled):** provides `DATA_READ`,`AUTHZ_BYPASS`; consumes none

## References
- CWE-643; CWE-91; OWASP A03:2021 Injection; OWASP XPath Injection & Testing for
  XML Injection guides. For external entities, see the separate XXE skill (CWE-611).
