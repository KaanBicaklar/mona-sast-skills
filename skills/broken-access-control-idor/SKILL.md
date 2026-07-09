---
name: broken-access-control-idor
description: >-
  SAST detection methodology for broken access control (CWE-284/862) and
  insecure direct object references / BOLA (CWE-639), including function-level
  authorization gaps (BFLA), horizontal/vertical privilege escalation, missing
  ownership checks, "UUID is not access control", and inconsistent auth
  middleware. Use when reviewing routes/controllers/resolvers that read or mutate
  a resource identified by a request-supplied id. Writes confirmed findings to
  findings/19-broken-access-control-idor.md.
---

# Broken Access Control / IDOR — SAST Methodology

**Class:** Broken Access Control / IDOR · **CWE-639 / CWE-284 / CWE-862** · **OWASP:** A01 Broken Access Control
**Findings file:** `findings/19-broken-access-control-idor.md`

## 1. Overview

Broken access control is a *missing check*, not a bad transformation — so there is
no tainted string to trace, only an authorization decision that never happens.
The two dominant shapes are **IDOR/BOLA** (an object id comes from the request and
the handler loads/updates that object *without verifying the caller owns or may
access it*) and **BFLA / function-level** (a privileged route or action is missing
its role/permission gate). The core test for every handler that touches a
resource: given an authenticated but *unprivileged* attacker who changes the id
(or hits the URL directly), does any code compare the resource's owner/tenant/role
requirement against the current principal *before* returning or mutating data? If
the only thing standing between users is that ids are hard to guess, there is no
access control.

## 2. Where it lives

- REST controllers/route handlers taking an id from path/query/body:
  `GET /api/orders/:id`, `PUT /users/{id}`, `POST /documents/:id/share`.
- GraphQL resolvers that fetch by `args.id` with no per-object check; batch
  resolvers and `nodes(ids:[...])` bulk lookups.
- "Admin" or "internal" routes protected only by being unlinked in the UI
  (forced browsing / path-based) — `/admin`, `/api/internal/*`, `/actuator`.
- Middleware/guard registration: an auth filter mounted on *some* router groups
  but not others; a decorator applied to most actions but forgotten on one.
- Multi-tenant code where `tenantId`/`orgId` is read from the token *or* from the
  request body (and the request one is trusted).
- Direct-object file/blob access: `/files/{key}`, signed-URL generators, export
  endpoints, report downloads.
- Mass/bulk operations: `DELETE /items?ids=1,2,3`, `PATCH /users` with an array.

## 3. Sources (attacker-controlled identifiers/tokens/roles)

Any request-supplied value that *selects a resource* or *asserts a privilege*:
path params (`:id`, `{uuid}`), query/body ids, `X-Account-Id`/`X-Tenant`
headers, a `role`/`isAdmin`/`org` field in the JSON body, a cookie or JWT claim
that the app trusts without re-checking against server state. Treat the current
**principal** (session/JWT `sub`) as the only trustworthy identity; every other
id in the request is attacker-chosen. **Second-order:** an id stored earlier
(e.g. a `next` resource id in a workflow row) and later dereferenced without
re-authorizing the current actor.

## 4. Sinks (the authorization check — or its absence)

The "sink" is the data access/mutation that should have been preceded by an
ownership/role check. Dangerous = the load/update happens with the request id and
**no comparison to the principal**.

```javascript
// Express — dangerous: object id from request, no ownership check (IDOR/BOLA)
app.get('/api/orders/:id', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);   // any logged-in user → any order
  res.json(order);                                     // missing: order.userId === req.user.id
});
// Express — dangerous BFLA: admin action, only login enforced, no role check
app.post('/api/users/:id/promote', requireLogin, promote);  // any user can promote
// Express — dangerous: trusts client-sent tenant/role
const tenant = req.body.tenantId || req.headers['x-tenant'];  // attacker picks tenant
```
```java
// Spring — dangerous: loads by path id, no @PreAuthorize / ownership check
@GetMapping("/api/documents/{id}")
public Document get(@PathVariable Long id) {
    return repo.findById(id).orElseThrow();            // no check owner == principal
}
// Spring — dangerous: security config secures /api/** but /internal/** is left open
http.authorizeHttpRequests(a -> a.requestMatchers("/api/**").authenticated());
// (an @RequestMapping("/internal/report") controller is now unauthenticated)
```
```python
# Django / DRF — dangerous: get_object by pk with no object-level permission
class InvoiceView(RetrieveAPIView):
    queryset = Invoice.objects.all()                   # not scoped to request.user
    # missing get_queryset filter or has_object_permission → any pk readable
def download(request, doc_id):
    doc = Document.objects.get(id=doc_id)              # no owner filter
    return FileResponse(doc.file)
```
```ruby
# Rails — dangerous: unscoped find, plus a route with no before_action gate
class InvoicesController < ApplicationController
  def show
    @invoice = Invoice.find(params[:id])               # any user → any invoice
  end                                                  # should be current_user.invoices.find
end
```

## 5. Sanitizers / safe patterns (correct enforcement, and how it's bypassed)

**Correct enforcement:**
- **Scope every query to the principal**: `current_user.invoices.find(id)`,
  `Order.where(user: req.user.id).findById`, DRF `get_queryset` filtered by
  `request.user`, JPA `findByIdAndOwnerId(id, principalId)`. The check and the
  fetch are one atomic query — impossible to forget the comparison.
- **Object-level authorization** enforced centrally: DRF
  `has_object_permission`, Rails Pundit/CanCanCan `authorize @invoice`, Spring
  `@PreAuthorize("@authz.canRead(#id, principal)")` or `@PostAuthorize`, a policy
  layer called by *every* handler.
- **Function-level (role) gates** on privileged routes: `@PreAuthorize("hasRole
  ('ADMIN')")`, a `requireRole('admin')` middleware, DRF `permission_classes`.
- **Deny-by-default routing**: secure `/**` then open specific public paths, so a
  new controller is protected unless explicitly exempted.
- **Trust only server-derived identity**: tenant/role come from the session/token,
  never from a body field or header.

**Fails / not real access control:**
- **Unguessable ids** (UUID/GUID, hashids, sequential-but-large) — obscurity, not
  authorization. Ids leak via referers, logs, emails, other endpoints, or the
  object itself. "It's a UUID" is never a mitigation.
- **Client-side hiding** — button removed from the UI but the API still serves the
  action (classic BFLA / forced browsing).
- **Authentication mistaken for authorization** — `requireLogin` proves *who*, not
  *whether they may touch this object*.
- **Check on one verb only** — `GET` scoped to owner but `PUT`/`DELETE` not (or
  vice versa); read protected, write forgotten.
- **Check then re-fetch** — authorizes id `A`, then loads from a *different*
  request field (TOCTOU / parameter confusion).
- **Inconsistent middleware** — guard applied per-router and one route group is
  registered outside it; a decorator forgotten on a new action.
- **Trusting a client-sent role/tenant/`isAdmin`**, or a JWT claim never
  re-validated against current server state (stale/forged role).
- **Allowlist by prefix** that a path-traversal or alternate encoding escapes
  (`/admin` blocked but `/Admin`, `/admin/`, `//admin`, `/api/../admin`).

## 6. Detection methodology

1. **Enumerate resource handlers and their id sources.**
   ```
   rg -n '@(Get|Post|Put|Patch|Delete)Mapping|@(app|router)\.(get|post|put|patch|delete)\(' 
   rg -n 'req\.params\.(id|.*Id)|req\.query\.(id|.*Id)|params\[:id\]|\{id\}|<int:.*_id>'
   rg -n 'findById|find\(params\[:id\]\)|objects\.get\(|findByIdAndDelete|getById'
   ```
2. **For each, ask: is the fetch scoped to the principal?** Look for the
   comparison — `== req.user.id`, `.where(user…)`, `current_user.`,
   `AndOwnerId`, a policy/`authorize` call. Its **absence** is the finding.
   ```
   rg -n 'current_user|req\.user\.(id|sub)|principal|@PreAuthorize|has_object_permission|authorize|Pundit|can\?'
   ```
3. **Find function-level gaps (BFLA):** list privileged/admin actions and check
   each has a role gate, not just a login gate.
   ```
   rg -n 'promote|makeAdmin|is_?admin|setRole|/admin|/internal|delete_?all|impersonate'
   rg -n 'requireLogin|isAuthenticated|@login_required' -l   # then diff against role checks
   ```
4. **Map middleware/guard coverage:** where is the auth filter mounted, and which
   routers/blueprints/controllers fall *outside* it? A route registered before or
   beside the guard is unprotected.
5. **Check tenant/role trust:** is `tenantId`/`orgId`/`role` ever read from body
   or headers rather than the token?
   ```
   rg -n 'req\.body\.(role|tenantId|orgId|isAdmin|accountId)|headers\[.x-(tenant|account|role)'
   ```
6. **Classify horizontal vs vertical, single vs bulk:** does changing the id reach
   *another user's* object (horizontal), a *higher-privilege* function (vertical),
   or *many* objects at once (mass/bulk id array)?
7. **Confirm reachability & auth level:** is it exposed, and is it pre-auth,
   any-authenticated-user, or admin-only?

## 7. Modern & niche variants

- **IDOR / BOLA (the flagship):** id from request, object loaded, no ownership
  check. #1 API risk. Prime targets: `/orders/:id`, `/messages/:id`, profile,
  invoice, and file-download endpoints. Horizontal escalation across peers.
- **BFLA / broken function-level authorization:** the *action* is privileged but
  gated only by authentication — any user hits `POST /users/:id/roles` or an
  admin CRUD endpoint. Vertical escalation. Often the admin UI hides the button
  while the API happily serves it.
- **Horizontal vs vertical escalation:** horizontal = same privilege, other
  user's data (change the id); vertical = gain higher privilege (reach an
  admin-only function). Report which, because impact and severity differ.
- **Mass / bulk object references:** endpoints taking `ids=[…]`, GraphQL
  `nodes(ids:[…])`, or batch export — one request dereferences many objects, and
  the per-object check is skipped or applied to only the first. Amplifies IDOR to
  "all users' data" (Critical).
- **"UUID/GUID is not access control":** teams swap sequential ids for UUIDs and
  believe the IDOR is fixed. It is not — the check is still missing; the id is
  just harder to guess (and still leaks). Flag any handler whose *only* defense is
  id unpredictability.
- **Path-based / forced browsing:** unlinked admin/debug/actuator routes reachable
  by direct URL; also directory-style traversal to sibling resources
  (`/reports/2024/../2023/other-team`).
- **Inconsistent middleware:** auth applied to some route groups but not others —
  a new blueprint/router mounted outside the guard, or a decorator forgotten on
  one action. Diff the protected set against the full route table.
- **Trusting client-sent role/tenant:** `tenantId`/`role`/`isAdmin` taken from
  body/header/query and used for scoping, letting the attacker pick their tenant
  or elevate. Also stale JWT role claims never re-checked against the DB.
- **GraphQL object-level gaps:** field/resolver-level auth missing while
  top-level query auth passes; `node(id:)` global-object lookup that ignores
  ownership.

## 8. Common false positives

- Query is scoped to the principal (`current_user.x.find`, `findByIdAndOwnerId`,
  DRF `get_queryset` filtered by user) — ownership is enforced in the fetch.
- A central policy/guard (`authorize`, `@PreAuthorize`, `has_object_permission`)
  is invoked for the handler and covers this object and verb.
- The resource is genuinely public/shared by design (published post, public
  profile) — no confidentiality expectation.
- The id maps only to the caller's own scope (e.g. `/me/...` where id is derived
  from the token, not the request).
- Admin route sits behind a confirmed, deny-by-default role gate.

## 9. Severity & exploitability

Base **High**. **Critical** when it yields access to *all* users' data (unscoped
list/bulk id endpoint), full account takeover, or a vertical escalation to admin
functions — and when reachable by any authenticated user or pre-auth. Horizontal
IDOR on sensitive per-user records is **High**; the same read-only on
low-sensitivity data behind admin auth drops toward **Medium**. Apply the
exploitability modifiers (unauthenticated reach, fully attacker-controlled id,
default config) per `references/severity-model.md`.

## 10. Remediation

Enforce authorization at the data layer: scope every fetch/mutation to the
authenticated principal (`current_user.resources.find(id)` /
`findByIdAndOwnerId`) so the ownership comparison cannot be forgotten. Add a
central object-level policy layer (Pundit/CanCanCan, DRF permissions, Spring
`@PreAuthorize`/method security) invoked by every handler, and role gates on
every privileged function. Adopt deny-by-default routing. Derive tenant/role only
from server-side identity, never from client input. Never treat unguessable ids
as a control. Add automated tests that hit each object with a *non-owner* token.

## 11. Output

Append each confirmed finding to **`findings/19-broken-access-control-idor.md`**
using `references/finding-template.md`. Set `Class: Broken Access Control / IDOR`
and the matching `CWE` (`CWE-639` for object-level/IDOR, `CWE-862` for missing
function-level authorization, `CWE-284` general). In **Chain potential** name
primitives such as *arbitrary data read* (other users'/tenants' records → leaked
secrets/tokens feeding further chains), *arbitrary write/state change* (edit or
delete another user's object), *privilege escalation* (BFLA → admin, which the
account-takeover and mass-assignment chains consume), and *account takeover*
(IDOR on a password-reset/email-change endpoint). Note whether the finding
**consumes** a leaked id/secret from another finding (e.g. an id exposed by an
info leak or IDOR elsewhere).

**Primitives (controlled):** provides `AUTHZ_BYPASS`,`DATA_READ`,`SECRET_LEAK`; consumes none

## References
- CWE-639, CWE-284, CWE-862; OWASP A01:2021 Broken Access Control; OWASP API
  Security Top 10 (API1 BOLA, API5 BFLA); OWASP Authorization Cheat Sheet.
