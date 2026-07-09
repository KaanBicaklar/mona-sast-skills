---
name: sql-injection
description: >-
  SAST detection methodology for SQL injection (CWE-89), including second-order,
  blind boolean/time-based, ORM raw-query leaks, and JSON/JSONB-path injection.
  Use when reviewing code that builds or executes SQL against a relational
  database. Writes confirmed findings to findings/01-sql-injection.md.
---

# SQL Injection — SAST Methodology

**Class:** SQL Injection · **CWE-89** · **OWASP:** A03 Injection
**Findings file:** `findings/01-sql-injection.md`

## 1. Overview

SQL injection occurs when attacker-controlled data reaches a SQL execution sink
as part of the query *structure* rather than as a bound parameter. The core test:
is any part of the query string built by concatenation/interpolation from a
source, and does that value reach `execute` without parameterization?

## 2. Where it lives

- Raw string queries in any language (Python, PHP, Java, C#, Go, Node, Ruby).
- ORM escape hatches: `.raw()`, `.extra()`, `sequelize.query`, `createNativeQuery`,
  `EntityManager.createQuery` with concatenation, `DB::raw`, `Model.where("… #{x}")`.
- Dynamic query builders where column/table/`ORDER BY`/direction is interpolated
  (identifiers can't be parameterized — allowlist required).
- Stored procedures that internally build dynamic SQL (`EXEC(@sql)`).

## 3. Sources (tainted input)

All HTTP inputs (query/body/path/header/cookie), plus **second-order**: values
previously stored in the DB, cache, or config that are re-read into a new query.
Trace stored values back to their original write source.

## 4. Sinks (dangerous operations)

```python
# Python — dangerous
cursor.execute("SELECT * FROM users WHERE id = " + uid)
cursor.execute(f"... WHERE name = '{name}'")
Model.objects.raw("SELECT ... %s" % val)        # % formatting = injection
session.execute(text("... " + val))             # SQLAlchemy text() concat
```
```java
// Java — dangerous
stmt.executeQuery("SELECT ... WHERE id=" + id);
entityManager.createQuery("FROM User WHERE name='" + n + "'");
jdbcTemplate.queryForObject("... " + n, ...);   // no bind params
```
```javascript
// Node — dangerous
db.query(`SELECT * FROM t WHERE id = ${id}`);
sequelize.query("SELECT ... WHERE x = '" + x + "'");
knex.raw(`... ${x}`);
```
```php
// PHP — dangerous
mysqli_query($c, "SELECT ... WHERE id=".$_GET['id']);
$pdo->query("... '".$name."'");                 // query() with concat, not prepare()
```
```csharp
// C# — dangerous
new SqlCommand("SELECT ... WHERE id=" + id, conn);
```

## 5. Sanitizers / safe patterns

**Safe:** parameterized/prepared statements with bound values — `execute(sql,
(param,))`, `?`/`:name` placeholders, `PreparedStatement.setX`, ORM query methods
that bind (`filter(id=uid)`, `where({id})`). Identifiers (table/column/order)
**cannot** be bound → must be validated against a strict allowlist.

**Fails / not a real sanitizer:**
- Manual quote-escaping (`replace("'", "''")`) — bypassable, wrong charset,
  numeric contexts need no quotes.
- Blocklisting keywords (`UNION`, `--`) — trivially bypassed.
- `int()`/cast applied on one branch only, or after the concat.
- `addslashes`, HTML-escaping, or generic "sanitize" helpers not designed for SQL.
- Parameterizing the value but concatenating the column name from input.

## 6. Detection methodology

1. **Find sinks:** grep for the execution APIs and raw-query escape hatches.
   ```
   rg -n 'execute\(|executeQuery|createQuery|\.raw\(|\.query\(|DB::raw|jdbcTemplate|text\(' 
   rg -n 'f".*SELECT|f".*INSERT|f".*UPDATE|f".*DELETE|\+\s*\w+\s*\+.*(SELECT|WHERE|FROM)'
   ```
2. **Confirm concatenation/interpolation:** is any operand of the query a variable,
   f-string field, template literal, or `%`/`.format`/`+`?
3. **Trace the operand to a source:** follow the variable back. Is it request-
   derived (directly or second-order)? Stop when you reach a literal/constant.
4. **Check for a real sanitizer on the path:** parameterization? allowlist for
   identifiers? If a "sanitizer" exists, verify it's correct for SQL and not
   bypassable (see §5).
5. **Confirm reachability:** is the enclosing function an exposed route/resolver
   /job, reachable (pre-auth?)?
6. **Classify blind vs error-based:** if the result isn't returned to the user,
   it's blind (boolean/time) — still exploitable, note it.

## 7. Modern & niche variants

- **Second-order:** input stored safely, then concatenated into a later query on
  read (e.g. username set at signup, used raw in an admin search). Highest miss rate.
- **ORM leaks:** safe-looking ORM with a hidden `.raw()`/`.extra()`/`whereRaw`.
- **JSON/JSONB path injection:** Postgres `->>`, `jsonb_path_query`, MySQL
  `JSON_EXTRACT` with interpolated path.
- **`ORDER BY` / `LIMIT` / direction injection:** identifiers/keywords that can't
  be bound and are taken from input without allowlist.
- **Batch/stacked queries** where the driver allows multiple statements.
- **Boolean/time-based blind** in filters, counts, and existence checks.
- **SQLi via headers/UA in logging-to-DB pipelines** (source is a header).

## 8. Common false positives

- Fully parameterized queries where the variable is only the bound value.
- Constant/enum interpolation not reachable from any source.
- Identifiers interpolated from a hard-coded allowlist/map.
- ORM `filter`/`where` with dict/kwarg binding (safe unless `raw`).

## 9. Severity & exploitability

Base **High**; **Critical** if it enables RCE (e.g. `xp_cmdshell`, `COPY … PROGRAM`,
`LOAD_FILE`/`INTO OUTFILE`, stacked queries) or exposes crown-jewel data, or is
pre-auth. Lower if strictly read-only on non-sensitive data behind admin auth.
See `references/severity-model.md`.

## 10. Remediation

Use parameterized queries / prepared statements everywhere. For dynamic
identifiers, map user input through a strict allowlist. Apply least-privilege DB
accounts. Never rely on manual escaping.

## 11. Output

Append each confirmed finding to **`findings/01-sql-injection.md`** using
`references/finding-template.md`. Set `Class: SQL Injection`, `CWE: CWE-89`, and in
**Chain potential** note primitives such as *arbitrary data read* (→ leaked
secrets/creds for other chains), *file read/write* (`INTO OUTFILE`), or *auth
bypass* (injected `WHERE` in a login query).

**Primitives (controlled):** provides `DATA_READ`,`DATA_WRITE`,`SECRET_LEAK` (and `FILE_READ`/`FILE_WRITE`/`CODE_EXEC` on capable DBs); consumes none

## References
- CWE-89; OWASP A03:2021 Injection; OWASP SQLi Prevention Cheat Sheet.
