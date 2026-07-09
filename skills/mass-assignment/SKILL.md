---
name: mass-assignment
description: >-
  SAST detection methodology for mass assignment / auto-binding (CWE-915),
  including whole-request-body binding to models (Rails strong-params gaps,
  Spring @ModelAttribute data-binder, Django ModelForm fields='__all__',
  Sequelize/Mongoose req.body spread), privilege escalation via isAdmin/role/
  is_verified/balance, nested/related-object over-posting, and GraphQL input
  over-binding. Use when reviewing create/update handlers that persist objects
  built from request data. Writes confirmed findings to
  findings/20-mass-assignment.md.
---

# Mass Assignment — SAST Methodology

**Class:** Mass Assignment · **CWE-915** · **OWASP:** A08 Software & Data Integrity Failures / A04 Insecure Design
**Findings file:** `findings/20-mass-assignment.md`

## 1. Overview

Mass assignment (a.k.a. auto-binding / over-posting) happens when a framework
copies attacker-controlled request fields directly onto a model's properties, so
the attacker can set fields the developer never intended to expose — most
dangerously `isAdmin`, `role`, `is_verified`, `balance`, `user_id`,
`email_verified`, or a related object's foreign key. There is no injection
string; the flaw is **binding surface**: the request body is trusted to name the
fields it may write. The core test: is a whole request object (`req.body`,
`params`, form/JSON) bound to a persistent model *without an allowlist* of
writable fields? If the set of settable properties is defined by the attacker's
payload rather than by the server, it is mass assignment.

## 2. Where it lives

- Create/update controller actions: `POST /users`, `PATCH /profile`,
  `PUT /orders/:id`, signup and settings handlers.
- ORM/ODM constructors and updaters fed the raw body: `new User(req.body)`,
  `User.update(req.body)`, `Model.create({...req.body})`, `Object.assign(user,
  req.body)`.
- Rails controllers using `update`/`create`/`update_attributes` with loosely
  permitted or unpermitted params.
- Spring MVC handlers with `@ModelAttribute`/command objects bound by
  `WebDataBinder` with no `setAllowedFields`.
- Django `ModelForm`/DRF `ModelSerializer` with `fields = '__all__'` or a
  too-broad field list; `Model(**request.data)`.
- Mongoose/Sequelize spreading `req.body` into `create`/`findOneAndUpdate`/`set`.
- GraphQL mutations whose `input` type includes privileged fields the resolver
  passes straight to the model.
- Deserialization of nested/related objects (`user.role`, `order.items[].price`,
  `account.owner`) where the graph is bound wholesale.

## 3. Sources (attacker-controlled fields)

The entire request body/params object, treated as a **map of field→value the
attacker fully chooses the keys of**. JSON bodies, form-encoded params, multipart
fields, and query strings can all name arbitrary model attributes — including ones
absent from the UI form. Nested objects and arrays extend the surface to related
models. **Second-order:** a stored payload (e.g. an imported record, a webhook, a
queued job body) later bound to a model on processing. The key insight vs other
classes: the danger is the *keys* the attacker supplies, not just the values.

## 4. Sinks (dangerous operations)

Dangerous = a model persist/update whose writable field set comes from the
request, not a server-defined allowlist.

```ruby
# Rails — dangerous: whole params bound, or over-broad permit
@user.update(params[:user])                      # no strong params → any column
@user.update_attributes(params[:user])           # legacy, same problem
User.create(params.require(:user).permit!)       # permit! allows everything
params.require(:user).permit(:name, :role)       # 'role' should NOT be permitted
```
```javascript
// Node / Sequelize / Mongoose — dangerous: req.body spread into the model
const user = await User.create({ ...req.body });                 // isAdmin settable
await User.update(req.body, { where: { id } });                  // over-post any column
await User.findByIdAndUpdate(req.params.id, req.body);           // Mongoose over-post
Object.assign(user, req.body); await user.save();                // classic over-post
```
```java
// Spring MVC — dangerous: command object bound with no field allowlist
@PostMapping("/account/update")
public String update(@ModelAttribute User form) {   // binds every matching field
    repo.save(form);                                // 'role','enabled' bindable
}
// Missing: @InitBinder { binder.setAllowedFields("name","email"); }
```
```python
# Django / DRF — dangerous
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'          # exposes is_staff, is_superuser, balance…
User.objects.create(**request.data)  # arbitrary attributes
form = UserForm(request.POST)         # ModelForm with fields='__all__'
```
```graphql
# GraphQL — dangerous: input type carries privileged fields
input UpdateUserInput { name: String, email: String, role: Role, isAdmin: Boolean }
# resolver: return db.user.update({ where:{id}, data: input })  # binds role/isAdmin
```

## 5. Sanitizers / safe patterns (correct enforcement, and how it's bypassed)

**Correct enforcement — allowlist the writable fields, server-side:**
- **Rails strong parameters** with an *explicit* `permit(:name, :email)` that omits
  every privileged column; never `permit!`.
- **Explicit DTO / view model:** bind the request to a dedicated input object that
  contains *only* user-writable fields, then map those to the entity (don't bind
  the entity directly). Applies to Spring command objects, Node handlers, etc.
- **Spring `@InitBinder` `setAllowedFields`/`setDisallowedFields`**, or better a
  request DTO distinct from the JPA entity.
- **DRF serializers** with an explicit `fields = (...)` allowlist and
  `read_only_fields` for server-controlled attributes; Django `ModelForm` with a
  named `fields` list, never `'__all__'`.
- **Pick/whitelist helper** in Node (`_.pick(req.body, ['name','email'])`) before
  `create`/`update`.
- **Set privileged fields explicitly** from server state (`user.role =
  DEFAULT_ROLE`) after binding, never from the payload.

**Fails / not real protection:**
- **Blocklists / `except`** (strip `isAdmin` but a new privileged column appears)
  — allowlist, don't blocklist; blocklists rot as the schema grows.
- **`permit!`, `fields='__all__'`, unrestricted `@ModelAttribute`** — these *are*
  the vulnerability.
- **Client-side / UI omission** — the field isn't in the form, but the binder
  still accepts it from a crafted request.
- **Nested-object gaps** — top-level fields allowlisted but `permit(user: {...},
  role_attributes: {...})` or `accepts_nested_attributes_for` re-opens related
  models; DRF nested serializers binding a related object's fields.
- **Case / alias bypass** — `IsAdmin` vs `isAdmin`, snake vs camel, or a
  serialized alias not covered by the filter.
- **Read-only enforced in serializer output only**, not on input (field displayed
  read-only but still writable on POST).
- **Allowlist applied on create but not update** (or vice versa).
- **`Object.assign`/spread after** the allowlist re-merges the raw body.

## 6. Detection methodology

1. **Find bulk-bind sinks** — model construction/update fed a request object.
   ```
   rg -n 'new \w+\(req\.body\)|\.(create|update|save|bulkCreate|findOneAndUpdate|findByIdAndUpdate)\((\{?\s*\.\.\.)?req\.(body|query|params)'
   rg -n 'Object\.assign\([^,]+,\s*req\.body|update_attributes|permit!|params\[:\w+\]\)'
   rg -n 'fields\s*=\s*.__all__.|ModelForm|ModelSerializer|@ModelAttribute'
   ```
2. **Check for an allowlist on the path.** Is there a `permit(...)`,
   `setAllowedFields`, explicit `fields=(...)`, `_.pick`, or a dedicated DTO? Its
   absence (or a `permit!`/`'__all__'`) is the finding.
   ```
   rg -n 'permit\(|setAllowedFields|read_only_fields|pick\(|@InitBinder'
   ```
3. **List the model's privileged columns** and confirm whether any are bindable:
   `role`, `is_admin`, `admin`, `is_staff`, `is_superuser`, `is_verified`,
   `email_verified`, `balance`, `credit`, `price`, `status`, `user_id`,
   `account_id`, `tenant_id`, `permissions`, `enabled`.
   ```
   rg -n 'is_?admin|is_staff|is_superuser|\brole\b|is_verified|email_verified|balance|credit|permission|tenant_id|owner_id'
   ```
4. **Trace nested/related binding:** `accepts_nested_attributes_for`, nested
   serializers, `permit(x: {})`, GraphQL nested `input` types — is a related
   object's foreign key or a join settable?
5. **Diff create vs update:** is the allowlist present on both verbs?
6. **Confirm reachability & principal:** signup and self-service settings routes
   are prime (attacker binds `role`/`isAdmin` on their own account, pre- or
   post-auth), so verify auth level and whether the bound field crosses a
   privilege/tenant boundary.

## 7. Modern & niche variants

- **Whole-body auto-binding (the flagship):** `Model.create({...req.body})`,
  `update(params[:user])`, `@ModelAttribute` with no allowlist, `fields='__all__'`
  — the attacker's JSON keys define the writable set. Highest hit rate on signup
  and profile-update endpoints.
- **Privilege-escalation fields:** the payoff column. Submitting
  `{"role":"admin"}`, `{"isAdmin":true}`, `{"is_verified":true}`,
  `{"email_verified":true}` on your own account → vertical escalation or bypassed
  verification. `{"balance":999999}` / `{"price":0}` on financial models → fraud.
  `{"user_id":<victim>}`/`{"tenant_id":…}` → cross-object/tenant writes.
- **Nested / related-object over-posting:** `accepts_nested_attributes_for`,
  `permit(profile_attributes: {}, roles_attributes: {})`, DRF/GraphQL nested
  inputs — over-posting reaches through the association to set a related record's
  privileged field or reassign a foreign key (attach your order to another user,
  add yourself to an admin group).
- **Sequelize/Mongoose spread:** `{...req.body}` into `create`/`findByIdAndUpdate`
  binds any schema path, including ones not in the form; Mongoose `strict` off or
  `Mixed` types widen it further.
- **Spring data-binder:** `WebDataBinder` binds nested paths
  (`user.account.role`) and, historically, dangerous ones; missing
  `setAllowedFields` plus an entity-as-command-object is the classic gap.
- **Django `ModelForm`/DRF `'__all__'`:** exposes `is_staff`/`is_superuser`;
  serializer `read_only` set on output but the field still writable on input.
- **GraphQL input over-binding:** a mutation `input` type includes privileged
  fields and the resolver forwards the whole `input` object to
  `prisma/sequelize.update` — same bug behind a typed schema. Introspection hands
  the attacker the exact field names.
- **JSON:API / PATCH-merge:** partial-update endpoints that merge arbitrary
  attributes; `application/merge-patch+json` binding straight to the entity.

## 8. Common false positives

- An explicit allowlist (`permit(:a,:b)`, DTO, `fields=(...)`, `_.pick`) that
  excludes every privileged/foreign-key column, on both create and update.
- Privileged fields marked `read_only`/`attr_readonly` on **input** and confirmed
  not settable, or set explicitly from server state after binding.
- Model has no security-relevant attributes (pure content object with no role,
  ownership, price, or verification fields).
- Binding target is a transient DTO whose fields are all user-writable and are
  later mapped selectively to the entity.

## 9. Severity & exploitability

Base **High** when a privileged field is bindable. **Critical** if binding grants
admin/role escalation, bypasses verification (`is_verified`/`email_verified`),
alters financial state (`balance`/`price`), or reassigns ownership/tenant — and
when reachable pre-auth or on a self-service endpoint any user can hit. Drops to
**Medium/Low** if the only over-postable fields are low-impact and the endpoint is
admin-gated. See `references/severity-model.md`.

## 10. Remediation

Bind requests through an explicit server-defined allowlist — strong parameters
with a named `permit`, a dedicated input DTO distinct from the persistence entity,
DRF/`ModelForm` explicit `fields` with `read_only_fields`, or Spring
`setAllowedFields`. Never use `permit!`, `fields='__all__'`, `{...req.body}`
spreads, or entity-as-command-object binding. Set privileged and server-owned
fields (role, ownership, verification, balance) explicitly from trusted state
after binding, and apply the same allowlist to nested/related objects and to both
create and update paths.

## 11. Output

Append each confirmed finding to **`findings/20-mass-assignment.md`** using
`references/finding-template.md`. Set `Class: Mass Assignment`, `CWE: CWE-915`,
and in **Chain potential** name primitives such as *privilege escalation*
(binding `role`/`isAdmin` → admin, consumed by the broken-access-control and
account-takeover chains), *authentication/verification bypass*
(`is_verified`/`email_verified`), *arbitrary write / integrity violation*
(reassigning `user_id`/`tenant_id`, zeroing `price`, inflating `balance`), and
*data tampering* feeding downstream trust decisions. Note when the finding
*consumes* a leaked model/field name (e.g. from a GraphQL introspection or
info-leak finding) to know which attributes are bindable.

**Primitives (controlled):** provides `AUTHZ_BYPASS`,`IDENTITY_FORGE` (set role); consumes `FORCED_REQUEST`

## References
- CWE-915; OWASP A08:2021 Software & Data Integrity Failures / A04:2021 Insecure
  Design; OWASP API Security Top 10 (API6 Mass Assignment); OWASP Mass Assignment
  Cheat Sheet; Rails Strong Parameters guide.
