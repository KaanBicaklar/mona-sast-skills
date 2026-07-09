---
name: nosql-injection
description: >-
  SAST detection methodology for NoSQL injection (CWE-943), including MongoDB
  operator injection ($ne/$gt/$regex type-confusion), $where JavaScript
  execution, aggregation-pipeline abuse, and GraphQL→Mongo flows. Use when
  reviewing code that queries MongoDB, Redis, CouchDB, or similar document
  stores. Writes confirmed findings to findings/02-nosql-injection.md.
---

# NoSQL Injection — SAST Methodology

**Class:** NoSQL Injection · **CWE-943** · **OWASP:** A03 Injection
**Findings file:** `findings/02-nosql-injection.md`

## 1. Overview

NoSQL injection occurs when attacker-controlled data reaches a document-store
query and alters its *structure* — usually by smuggling query **operators**
(`$ne`, `$gt`, `$regex`, `$where`) or JavaScript into a query object. Unlike SQL,
the classic vector is not string concatenation but **type confusion**: a field
the code expects to be a string arrives as an object (`{"$ne": null}`), because
JSON bodies and query strings can encode nested objects. The core test: does a
request value get placed into a query object *as-is*, letting the attacker choose
its type or inject operator keys?

## 2. Where it lives

- Query objects built directly from `req.body` / `req.query` in Node/Mongoose/
  native `mongodb`: `User.find({ user: req.body.user, pass: req.body.pass })`.
- `$where`, `$expr`, `mapReduce`, and `group` clauses that evaluate server-side
  JavaScript from interpolated input.
- Aggregation pipelines assembled from user input (`$match`, `$lookup`,
  `$function`, `$accumulator`).
- Python/pymongo filters built from `request.json` dicts without type checks.
- PHP MongoDB driver queries built from `$_GET`/`$_POST` arrays (PHP auto-parses
  `q[$ne]=1` into a nested array).
- Redis (Lua `EVAL`, `SORT ... GET` patterns), CouchDB (Mango `$` selectors,
  temporary views), and GraphQL resolvers that forward args straight into a Mongo
  filter.

## 3. Sources (tainted input)

All HTTP inputs, but with a critical twist: the **shape** of the input is part of
the attack. Query strings (`?user[$ne]=`), JSON bodies (`{"user":{"$ne":null}}`),
and multipart fields can all deserialize into nested objects/arrays before your
code sees them. Also **second-order**: operator strings stored in the DB, cache,
or a message queue and later spread into a new filter object. GraphQL variables
and webhook payloads are common indirect sources.

## 4. Sinks (dangerous operations)

```javascript
// Node / Mongoose / mongodb — dangerous
User.find({ username: req.body.username, password: req.body.password });
// If body is {"username":"admin","password":{"$ne":null}} → auth bypass.
db.collection('u').find({ age: { $gt: req.query.age } });   // operator passthrough
User.find({ $where: `this.name == '${req.query.name}'` });  // JS execution → sandboxed RCE
db.collection('u').aggregate([{ $match: req.body.filter }]);// whole stage attacker-shaped
Model.find({ name: { $regex: req.query.q } });              // ReDoS / data exfil via regex
```
```python
# Python / pymongo — dangerous
db.users.find({"user": request.json["user"], "pw": request.json["pw"]})
# request.json can carry {"pw": {"$ne": null}} → returns first user
db.users.find({"$where": "this.pin == " + request.args["pin"]})  # JS injection
```
```php
// PHP — dangerous (nested-array parsing)
$c->users->find(['user' => $_GET['user'], 'pass' => $_GET['pass']]);
// URL ?user=admin&pass[$ne]=  makes pass an array {'$ne': ''} → bypass
```

## 5. Sanitizers / safe patterns

**Safe:**
- **Enforce the type** before it reaches the query: cast/validate that the value
  is a string/number (`typeof x === 'string'`, pydantic/`isinstance`, schema
  validation with `express-validator`, Mongoose typed schemas with
  `sanitizeFilter`/`strictQuery`).
- Reject or strip keys beginning with `$` and containing `.` (e.g.
  `mongo-sanitize`, `express-mongo-sanitize`) *before* building the filter.
- Never use `$where`/`$expr`/`mapReduce` with user input; disable server-side JS
  (`--noscripting`).
- For aggregation, build stages from a fixed template and bind only leaf values.

**Fails / not a real sanitizer:**
- HTML/SQL escaping — irrelevant to operator/type injection.
- Casting on one branch only, or after the filter object is built.
- Stripping `$` but not the `.` dotted-path notation (or vice versa), or checking
  top-level keys but not nested ones inside `$or`/`$and` arrays.
- Trusting Mongoose to coerce — coercion applies to *typed* schema paths; `Mixed`,
  `find` on unindexed fields, or `strictQuery:false` let objects through.
- Blocklisting the literal string `$where` while allowing `$expr`/`$function`.

## 6. Detection methodology

1. **Find sinks:** grep for query APIs receiving request objects directly.
   ```
   rg -n '\.(find|findOne|update|updateMany|deleteOne|deleteMany|aggregate|count|distinct)\s*\(' 
   rg -n '\$where|\$expr|mapReduce|\$function|\$accumulator|\$regex'
   rg -n 'find\([^)]*req\.(body|query|params)|find\([^)]*request\.(json|args|form)'
   ```
2. **Confirm passthrough:** is a request value used as a query-object *value* or a
   whole `$match`/`filter` stage without a type check or `$`-key filter?
3. **Trace type enforcement:** is the value guaranteed to be a scalar before the
   query? Look for casts, schema validation, or a sanitize middleware applied
   *globally and before* the handler (not just on some routes).
4. **Check for JS-eval sinks:** any `$where`/`$expr`/`$function` with interpolated
   input is code injection inside the DB (see the code-injection skill for the
   sandbox-escape angle).
5. **Confirm reachability:** exposed route/GraphQL resolver? Pre-auth (login,
   password-reset, search endpoints are prime)?
6. **Classify:** auth bypass, blind boolean/regex data exfiltration, ReDoS, or
   server-side JS execution.

## 7. Modern & niche variants

- **Operator injection via type confusion:** the flagship NoSQL bug. `{"$ne":
  null}`, `{"$gt":""}`, `{"$in":[...]}` submitted where a string was expected.
  Bypasses login checks (`password: {$ne: null}` matches any user) and filters.
  Highest-value finding; look for any query field fed straight from `req.body`.
- **`$regex` blind extraction:** attacker supplies `{"$regex":"^A"}` and observes
  hit/no-hit to exfiltrate secrets (tokens, PINs) character-by-character — a blind
  boolean oracle. Also a ReDoS vector via catastrophic patterns.
- **`$where` / `$expr` / `$function` JavaScript execution:** server evaluates a JS
  predicate. Interpolating input into the string yields JS injection running in
  the DB's (sandboxed but abusable) engine — infinite loops (DoS), data access
  across the doc, and historically sandbox escapes.
- **Aggregation-pipeline abuse:** a whole `$match`/`$lookup`/`$group` stage taken
  from input. `$lookup` can join across collections to leak other tenants' data;
  `$function`/`$accumulator` run JS; `$out`/`$merge` can *write* to arbitrary
  collections.
- **Dynamic query objects:** code spreads user input into the filter
  (`{...req.query, tenantId}`) — attacker overrides `tenantId` or injects `$or`.
- **PHP nested-array injection:** `param[$ne]=` in the query string becomes a PHP
  array; historically the easiest NoSQLi to reach.
- **GraphQL→Mongo:** resolver forwards a `filter`/`where` arg object into a Mongo
  query, exposing operator injection through a typed-looking API.
- **Redis/CouchDB:** Redis Lua `EVAL` with interpolated `KEYS`/`ARGV` or command
  injection via unescaped args; CouchDB Mango `$` selectors and temporary
  map/reduce views that execute user JavaScript.

## 8. Common false positives

- Values cast to a scalar (`String(x)`, `parseInt`, schema-validated) before the
  query — type confusion is closed.
- Global `mongo-sanitize`/`express-mongo-sanitize` middleware confirmed applied
  before all handlers.
- `$where`/`$regex` with only hard-coded constants.
- Mongoose queries on strictly typed schema paths where coercion rejects objects.

## 9. Severity & exploitability

Base **High** (data read/write). **Critical** if it yields authentication bypass,
cross-tenant reads via `$lookup`, arbitrary writes via `$out`/`$merge`, or if a
`$where`/`$function` sink reaches code execution — and higher still when pre-auth.
Lower to **Medium** if strictly read-only on non-sensitive data behind admin auth
or the input is provably scalar-constrained. See `references/severity-model.md`.

## 10. Remediation

Enforce scalar types on every query input via schema validation before building
the filter; reject keys starting with `$` or containing `.`. Never pass whole
request objects into `find`/`aggregate`. Disable server-side JavaScript and avoid
`$where`/`$expr`/`$function` with any dynamic content. Bind only leaf values in
aggregation templates and apply least-privilege DB roles.

## 11. Output

Append each confirmed finding to **`findings/02-nosql-injection.md`** using
`references/finding-template.md`. Set `Class: NoSQL Injection`, `CWE: CWE-943`,
and in **Chain potential** name primitives such as *auth bypass* (`{$ne:null}` in
a login query), *arbitrary data read* (blind `$regex` / `$lookup` cross-tenant →
leaked secrets for other chains), *arbitrary write* (`$out`/`$merge`), or *code
execution* (`$where`/`$function` → consumed by the code-injection chain).

**Primitives (controlled):** provides `DATA_READ`,`DATA_WRITE`,`SECRET_LEAK`,`AUTHZ_BYPASS` (auth-bypass filter),`CODE_EXEC` (`$where` JS); consumes none

## References
- CWE-943; OWASP A03:2021 Injection; OWASP Testing Guide — NoSQL Injection;
  MongoDB security checklist (disable server-side scripting).
