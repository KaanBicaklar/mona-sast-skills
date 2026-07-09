---
name: graphql-injection-and-abuse
description: >-
  SAST detection methodology for GraphQL injection and abuse (CWE-400, CWE-285),
  covering introspection in production, batching/aliasing/deep-nesting DoS,
  missing depth/complexity/cost limits, object- and field-level authorization
  gaps in resolvers (BOLA/BFLA), injection propagating through resolvers into
  SQL/NoSQL/OS sinks, mutation IDOR, and verbose schema-leaking errors. Use when
  reviewing GraphQL schemas, resolvers, or server config (Apollo, graphql-js,
  graphene, graphql-java). Writes confirmed findings to
  findings/09-graphql-injection-and-abuse.md.
---

# GraphQL Injection & Abuse — SAST Methodology

**Class:** GraphQL Injection & Abuse · **CWE-400 / CWE-285** · **OWASP:** API Security Top 10
**Findings file:** `findings/09-graphql-injection-and-abuse.md`

## 1. Overview

GraphQL exposes a single flexible endpoint whose safety depends almost entirely
on server configuration and per-resolver logic. Two failure families dominate:
**abuse** (a well-formed query that is expensive or over-broad — introspection,
deeply nested/aliased/batched queries with no cost limit) and **injection/authz**
(a resolver that trusts client-supplied arguments and passes them into a backend
sink, or that skips object/field authorization). The core tests: is the query
cost bounded? is every resolver authorizing the *object and field* it returns?
and does any argument flow into a SQL/NoSQL/OS sink unsanitized?

## 2. Where it lives

- Server bootstrap: `ApolloServer({ ... })`, `graphqlHTTP({ ... })`, `graphene`
  `Schema(...)`, `graphql-java` `GraphQL.newGraphQL(...)` — introspection,
  validation rules, and error masking are configured here.
- Resolver functions/methods: `Query`/`Mutation`/`Subscription` field resolvers,
  `@Resolver` classes, `graphene.ObjectType` methods, `DataFetcher`s.
- DataLoaders and repository calls invoked from resolvers.
- Gateway/federation layers that forward args downstream.

## 3. Sources (tainted input)

GraphQL **variables**, inline **arguments**, **query/mutation body** (fields,
aliases, fragments, directives), operation name, and persisted-query IDs. HTTP
headers/cookies still apply for auth context. **Second-order:** an ID or filter
stored from an earlier mutation and later used by a resolver in a backend query.
Treat every resolver argument as attacker-controlled.

## 4. Sinks (dangerous operations)

```javascript
// Node / Apollo — dangerous
new ApolloServer({ introspection: true, csrfPrevention: false });   // prod introspection
// resolver passing arg straight into a sink:
Query: {
  user: (_, { id }) => db.query(`SELECT * FROM users WHERE id = ${id}`),      // SQLi
  search: (_, { q }) => users.find({ $where: `this.name == '${q}'` }),        // NoSQLi
  export: (_, { path }) => fs.readFileSync(path),                             // path traversal
  order: (_, { id }, ctx) => Order.findById(id),   // NO ownership check → BOLA/IDOR
}
```
```python
# Python / graphene — dangerous
class Query(graphene.ObjectType):
    user = graphene.Field(User, id=graphene.ID())
    def resolve_user(self, info, id):
        return db.execute("SELECT * FROM users WHERE id=" + id)   # SQLi via resolver
        # no info.context.user check → BFLA/BOLA
schema = graphene.Schema(query=Query)   # introspection on by default
```
```java
// Java / graphql-java — dangerous
DataFetcher df = env -> jdbc.queryForObject(
    "SELECT * FROM acct WHERE id=" + env.getArgument("id"), ...);   // SQLi
GraphQL.newGraphQL(schema).build();   // no MaxQueryDepthInstrumentation / complexity limit
```

Dangerous patterns: introspection enabled in production; no depth/complexity/cost
instrumentation; resolvers concatenating arguments into SQL/NoSQL/OS/file APIs;
resolvers returning objects without an ownership/role check; verbose errors that
echo the schema or stack traces.

## 5. Sanitizers / safe patterns

**Safe:** disable introspection and field suggestions in production; enforce a
**query depth limit**, **complexity/cost limit**, and **alias/array-batch caps**
(e.g. `graphql-depth-limit`, `graphql-cost-analysis`, `MaxQueryDepthInstrumentation`,
Apollo `@cost`/operation limits); require an explicit **authorization check in
every resolver** (object ownership *and* field-level role), ideally centralized
via directives/middleware or a policy layer; use **parameterized queries** in
resolvers exactly as elsewhere; disable batching or bound it; mask errors in
production (`formatError` returning a generic message). Use allowlisted persisted
queries to remove arbitrary-query freedom entirely.

**Fails / not a real sanitizer:**
- Depth limit set but **complexity/alias batching** left unbounded — a shallow
  query with thousands of aliases still exhausts resources.
- Auth checked at the top-level `Query` resolver but **not on nested field
  resolvers** — attacker pivots through a relation to unauthorized data (BFLA).
- Checking that the user is authenticated but **not that they own the object**
  (`Order.findById(id)` returns any order) — classic BOLA/IDOR.
- Introspection "disabled" but field-suggestion error messages still leak schema.
- Type coercion (`graphene.ID`, `Int`) treated as sanitization — it validates
  shape, not SQL/NoSQL safety.
- Rate limiting on the HTTP endpoint but a single request still runs an unbounded
  query.

## 6. Detection methodology

1. **Find server config and resolvers.**
   ```
   rg -n 'ApolloServer|graphqlHTTP|makeExecutableSchema|buildSchema|GraphQL\.newGraphQL|graphene\.Schema'
   rg -n 'introspection\s*[:=]\s*true|__schema|IntrospectionQuery'
   rg -n 'depthLimit|createComplexityLimitRule|costAnalysis|MaxQueryDepthInstrumentation|MaxQueryComplexity'
   ```
2. **Audit abuse controls:** is introspection off in prod? are depth, complexity,
   and batch/alias limits configured? are errors masked? If any is missing, that
   is a finding on its own.
3. **Enumerate resolvers and their sinks.**
   ```
   rg -n 'resolve[_A-Z]\w*|DataFetcher|@Resolver|Query:|Mutation:'
   rg -n 'db\.query|execute\(|\.raw\(|find\(|\$where|readFile|exec\(|child_process'
   ```
4. **Per resolver, ask the two questions:** does any argument reach a backend
   sink via concatenation (→ injection)? and is there an ownership + field-level
   authorization check before returning the object (→ BOLA/BFLA/IDOR)?
5. **Trace mutation IDs:** does `updateX(id)`/`deleteX(id)` verify the caller owns
   `id`? Missing check = mutation IDOR.
6. **Confirm reachability:** is the endpoint exposed, is the field in the schema,
   and can it be reached pre-auth?

## 7. Modern & niche variants

- **Introspection enabled in production:** `__schema`/`__type` hands an attacker
  the full type graph, hidden fields, and deprecated/admin operations — the map
  for every other attack. Field-suggestion ("did you mean") errors leak the same
  even when introspection is nominally off.
- **Batching / aliasing / deep-nesting DoS (CWE-400):** array-batched operations
  and hundreds of aliases multiply work in one request; cyclic relations
  (`user { friends { friends { ... } } }`) explode without a depth cap — a single
  small request causes resource exhaustion. Also enables **brute-force
  amplification** (many `login` aliases per request, bypassing per-request rate
  limits).
- **Missing depth/complexity/cost limits:** the root cause behind most GraphQL
  DoS. A schema with unbounded lists and no cost instrumentation is exploitable
  by construction.
- **Object- and field-level authorization gaps (BOLA/BFLA):** resolvers that
  return an object by ID without an ownership check (BOLA), or expose a
  privileged field/mutation without a role check (BFLA). Nested resolvers are the
  usual blind spot — auth enforced at the top but not on traversed relations.
- **Injection propagating through resolvers:** a resolver argument concatenated
  into SQL, a Mongo `$where`/operator object, an OS command, or a file path —
  standard injection, but hidden one layer down inside a resolver. Cross-reference
  the `sql-injection`, `nosql-injection`, and command-injection skills for the sink.
- **Mutation IDOR:** `updateProfile(id, ...)` / `deleteResource(id)` that trusts
  the client-supplied ID without verifying ownership — write-side BOLA, often
  higher impact than read.
- **Verbose errors leaking schema:** unmasked resolver exceptions, stack traces,
  and type errors expose internal types, table/column names, and file paths that
  seed further attacks.

## 8. Common false positives

- Introspection enabled only in a dev/test config guarded by `NODE_ENV`/profile.
- Resolvers that call parameterized queries or ORM binding methods (no concat).
- Depth/complexity limits present and covering aliases and batching.
- Ownership checks centralized in middleware/directives applied to the field,
  even if the resolver body itself looks unchecked.
- Fields exposed only to an internal/federated gateway not reachable by clients.

## 9. Severity & exploitability

Base **Medium** for introspection-in-prod and verbose errors (info leak);
**High** for unbounded query DoS and BOLA/BFLA over other users' data;
**Critical** when a resolver argument reaches an RCE-capable sink, when authz
gaps expose admin operations/full-account data, or mutation IDOR enables mass
account/data takeover. Raise for pre-auth reachable, lower for internal-only
schemas. See `references/severity-model.md`.

## 10. Remediation

Disable introspection and field suggestions in production and mask errors.
Enforce query depth, complexity/cost, and alias/batch limits via instrumentation.
Authorize in every resolver — object ownership and field-level role — preferably
through centralized directives/policies. Parameterize all backend queries built
in resolvers. Prefer persisted/allowlisted operations for public clients.

## 11. Output

Append each confirmed finding to **`findings/09-graphql-injection-and-abuse.md`**
using `references/finding-template.md`. Set `Class: GraphQL Injection & Abuse`
and `CWE: CWE-400` (DoS), `CWE-285` (authorization), or the sink-specific CWE
(e.g. `CWE-89`) when injection propagates. In **Chain potential** note primitives
such as *schema disclosure* (→ maps sinks for other findings), *object/field
authz bypass* (→ cross-tenant data read/write), *unbounded cost* (→ DoS /
brute-force amplification), and *resolver-propagated injection* (→ consumes the
argument, provides the SQL/NoSQL/OS primitive of the downstream skill).

**Primitives (controlled):** provides `AUTHZ_BYPASS`,`DATA_READ`; consumes none

## References
- OWASP API Security Top 10 (API1 BOLA, API3 BOPLA/excessive data, API4
  unrestricted resource consumption, API5 BFLA); CWE-400; CWE-285; OWASP GraphQL
  Cheat Sheet.
