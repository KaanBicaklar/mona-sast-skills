---
name: ldap-injection
description: >-
  SAST detection methodology for LDAP injection (CWE-90), including search-filter
  injection, authentication-bypass filters, blind LDAP injection, and DN
  injection. Use when reviewing code that builds LDAP search filters or
  distinguished names from user input (JNDI/DirContext, ldap3, python-ldap, PHP
  ldap_search, .NET DirectorySearcher). Writes confirmed findings to
  findings/06-ldap-injection.md.
---

# LDAP Injection — SAST Methodology

**Class:** LDAP Injection · **CWE-90** · **OWASP:** A03 Injection
**Findings file:** `findings/06-ldap-injection.md`

## 1. Overview

LDAP injection occurs when attacker-controlled data is concatenated into an LDAP
**search filter** or **distinguished name (DN)** without escaping the special
characters of RFC 4515 (filters) or RFC 4514 (DNs). Because LDAP filters use a
prefix-notation grammar with `(`, `)`, `&`, `|`, `!`, `*`, and `=`, injected
characters can broaden a filter (`*` matches everything), inject additional
clauses, or bypass authentication. The core test: is any part of a filter or DN
built by concatenation from a source, and is it passed through the correct
LDAP-escaping routine before the search/bind?

## 2. Where it lives

- Authentication that builds `(uid=<user>)` or `(&(uid=<user>)(userPassword=<pw>))`
  filters from login form fields.
- User/group lookup and directory-search features (search by name, email, dept).
- DN construction for bind/modify/delete (`uid=<user>,ou=people,dc=x`).
- Java JNDI `DirContext.search`, Spring LDAP, Python `ldap3`/`python-ldap`, PHP
  `ldap_search`/`ldap_bind`, .NET `DirectorySearcher.Filter`, Node `ldapjs`.

## 3. Sources (tainted input)

All HTTP inputs — especially **login username/password**, search terms, and any
identifier used to locate a directory entry. **Second-order**: attributes read
from the directory or DB and re-used to build another filter (e.g. a stored
`mail` value used in a follow-up group query). Headers used for SSO/username
mapping are also sources.

## 4. Sinks (dangerous operations)

```java
// Java (JNDI / Spring LDAP) — dangerous
String f = "(uid=" + user + ")";
ctx.search("ou=people,dc=x", f, controls);          // filter concat → injection
String dn = "uid=" + user + ",ou=people,dc=x";
ctx.lookup(dn);                                      // DN concat → DN injection
ldapTemplate.search("", "(cn=" + name + ")", mapper);
```
```python
# Python (ldap3 / python-ldap) — dangerous
conn.search("ou=people,dc=x", "(uid=" + user + ")")  # python-ldap
conn.search("dc=x", f"(&(uid={user})(pw={pw}))")     # ldap3 f-string → auth bypass
```
```php
// PHP — dangerous
$r = ldap_search($ds, "ou=people,dc=x", "(uid=".$_GET['u'].")");
$dn = "uid=".$_POST['u'].",ou=people,dc=x";
ldap_bind($ds, $dn, $pw);                             // DN injection
```
```csharp
// .NET — dangerous
var s = new DirectorySearcher(entry);
s.Filter = "(uid=" + user + ")";                     // no escaping → injection
```
```javascript
// Node (ldapjs) — dangerous
client.search("ou=people,dc=x", { filter: "(uid=" + user + ")" });
```

## 5. Sanitizers / safe patterns

**Safe:**
- Escape **filter** values with the RFC 4515 routine before concatenation:
  Java `javax.naming.ldap` / Spring `LdapEncoder.filterEncode`, python-ldap
  `ldap.filter.escape_filter_chars`, ldap3 parameterized `safe_str`/attribute
  builders, PHP `ldap_escape($v, "", LDAP_ESCAPE_FILTER)`, .NET manual RFC-4515
  encode. Escape `\ * ( ) NUL` (→ `\5c \2a \28 \29 \00`).
- Escape **DN** components with the RFC 4514 routine (a *different* function):
  `ldap_escape(..., LDAP_ESCAPE_DN)`, `LdapEncoder.nameEncode`. Do not reuse the
  filter escaper for DNs.
- Prefer building filters/DNs with a library that binds components (Spring LDAP
  `LdapQueryBuilder`, ldap3 abstraction) rather than string assembly.
- Validate identifiers against a strict allowlist (`[A-Za-z0-9._-]`) where the
  format is known.

**Fails / not a real sanitizer:**
- Escaping filter chars but forgetting `*` — leaving `*` in lets `uid=*` match
  every entry (the core auth-bypass/enumeration vector).
- Using the **filter** escaper on a **DN** (or vice versa) — different special
  sets; DNs also care about `, + " \ < > ; =` and leading/trailing spaces.
- HTML/SQL escaping applied instead of LDAP escaping — wrong grammar entirely.
- Escaping one field of a multi-clause filter but concatenating another raw.
- Blocklisting `)` or `(` — incomplete; `*`, `\`, and NUL still break out.

## 6. Detection methodology

1. **Find sinks:** grep for LDAP search/bind APIs and filter strings.
   ```
   rg -n 'DirContext|InitialDirContext|\.search\(|ldapTemplate|LdapQuery'
   rg -n 'ldap_search|ldap_bind|ldap_list|ldap_read|ldap_escape'
   rg -n 'ldap3|python-ldap|\.search\(|escape_filter_chars|Server\(|Connection\('
   rg -n 'DirectorySearcher|\.Filter\s*=|DirectoryEntry'
   rg -n '\(uid=|\(cn=|\(sAMAccountName=|\(mail=|\(&\(|\(\|\('
   ```
2. **Confirm concatenation:** is a variable spliced into a filter string
   (`"(uid=" + x + ")"`, f-string, `.format`, template literal) or into a DN?
3. **Trace the operand to a source** (direct, header/SSO, or second-order
   directory attribute). Stop at a constant.
4. **Check for the correct escaper on the path:** filter-encode for filters,
   DN-encode for DNs, and confirm `*` is handled. Missing/wrong/one-branch escaping
   = finding.
5. **Confirm reachability** — login and directory-search endpoints are usually
   pre-auth or low-privilege, raising severity.
6. **Classify:** auth bypass, entry enumeration, blind boolean extraction, or DN
   injection (redirecting a bind/modify to another entry).

## 7. Modern & niche variants

- **Search-filter injection:** classic concatenation into `(attr=<input>)`.
  Injecting `)(...` adds clauses; injecting `*` widens matches; injecting
  `)(objectClass=*` returns the whole subtree.
- **Authentication-bypass filters:** for a login filter
  `(&(uid=<user>)(userPassword=<pw>))`, a username of `*)(uid=*))(|(uid=*` or a
  password of `*` restructures the filter so it always matches — the signature
  payload `*)(uid=*))(|(uid=*`. Any login that builds a bind/compare filter from
  raw fields is a prime target.
- **Blind LDAP injection:** when results aren't returned, use boolean-differential
  filters — inject `)(attr=value*)` and observe success/failure to extract
  attribute values (e.g. password hashes, tokens) character by character, similar
  to blind SQLi. Time-based variants exist on some servers.
- **DN injection:** input concatenated into a distinguished name used for
  bind/modify/delete. Injecting `,` or extra RDNs can point the operation at a
  different entry (e.g. bind as `admin` or modify another user), or add attributes
  during add operations. Requires the DN-specific escaper (RFC 4514), which teams
  frequently omit even when they escape filters.
- **Missing / partial filter escaping:** the most common root cause — some fields
  escaped, `*` left unescaped, or the escaper applied after concatenation.
- **AND/OR/NOT logic abuse:** injecting `)(&)`, `)(|)`, or `!` to invert or
  short-circuit access-control filters (e.g. bypass an `(memberOf=admins)`
  restriction).
- **Attribute/scope smuggling:** injecting into the search *base* or requested
  attributes list, not just the filter, to exfiltrate `userPassword`,
  `unicodePwd`, or operational attributes.

## 8. Common false positives

- Values passed through the correct RFC-4515/4514 escaper (including `*`) before
  concatenation.
- Filters/DNs built entirely from constants or an allowlisted identifier
  (`[A-Za-z0-9._-]` validated).
- Library query builders that bind components rather than assembling strings.
- Read-only lookups on non-sensitive attributes behind strong auth (still note,
  but severity drops).

## 9. Severity & exploitability

Base **High**. **Critical** when it yields authentication bypass, blind
extraction of credentials/secrets, or DN injection redirecting a
bind/modify/delete — especially pre-auth on a login endpoint. Lower to **Medium**
for read-only enumeration of non-sensitive attributes behind authentication. See
`references/severity-model.md`.

## 10. Remediation

Escape every user-supplied value with the correct routine — RFC 4515 filter
encoding for filters (including `*`), RFC 4514 DN encoding for DN components —
before building the query, or use a library that binds components. Validate
identifiers against a strict allowlist. Never build login filters from raw
fields; bind with a fixed service account then compare, and enforce
least-privilege directory ACLs.

## 11. Output

Append each confirmed finding to **`findings/06-ldap-injection.md`** using
`references/finding-template.md`. Set `Class: LDAP Injection`, `CWE: CWE-90`, and
in **Chain potential** name primitives such as *auth bypass* (login-filter
restructuring), *arbitrary directory read* (blind extraction / subtree dump →
leaked credentials for other chains), or *entry redirection* (DN injection into a
modify/bind → privilege escalation).

**Primitives (controlled):** provides `AUTHZ_BYPASS`,`DATA_READ`,`SECRET_LEAK`; consumes none

## References
- CWE-90; OWASP A03:2021 Injection; OWASP LDAP Injection Prevention Cheat Sheet;
  RFC 4515 (filters), RFC 4514 (DNs).
