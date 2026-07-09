---
name: business-logic-flaws
description: >-
  SAST detection methodology for business-logic flaws (CWE-840, CWE-841),
  including negative/overflow quantities, price/discount manipulation, trusting
  client-computed totals, workflow step-skipping, coupon/referral abuse, and
  replay of one-time actions. Use when reviewing server-side handling of
  business values and invariants. Writes confirmed findings to
  findings/34-business-logic-flaws.md.
---

# Business Logic Flaws — SAST Methodology

**Class:** Business Logic Flaw · **CWE-840** (and **CWE-841**) · **OWASP:** A04 Insecure Design
**Findings file:** `findings/34-business-logic-flaws.md`

## 1. Overview

Business-logic flaws are gaps where the code faithfully does what it was written to
do, but the *rules* it enforces are incomplete — it trusts client-supplied
business values, omits an invariant, or lets a workflow reach a privileged state
out of order. There is no injection or memory bug; the exploit is legitimate input
that violates an unstated assumption (a price can't be negative, a coupon applies
once, step 3 requires steps 1–2). The core test: does the server make a
security- or money-relevant decision using a value the client controls, **without
re-validating it server-side** against range, ownership, sequence, and uniqueness
invariants?

## 2. Where it lives

- Checkout / cart / pricing / discount / tax / shipping / refund calculation.
- Coupon, referral, loyalty-points, gift-card, and promotion redemption.
- Multi-step workflows: registration, KYC, checkout, password reset, onboarding
  wizards, approval chains (state machines).
- Quantity/limit handling: order quantity, transfer amount, withdrawal, top-up,
  bid, quota, rate limits.
- Anywhere a hidden/`readonly`/client field (`price`, `total`, `role`, `userId`,
  `status`, `isAdmin`, `currency`) is read from the request and trusted.

## 3. Sources (tainted input)

Attacker-controlled **business values** in the request: quantities, amounts,
prices, discount codes, currency, item IDs, account/recipient IDs, workflow step
identifiers/tokens, and any hidden or client-computed field (subtotal, total, tax,
`role`, `status`). Also **out-of-order or replayed requests** — invoking a step or
a one-time action at a time the workflow does not expect. Trace every business
field back to the request and ask whether the server independently recomputes or
re-authorizes it.

## 4. Sinks (dangerous operations)

The "sink" is the **security-/money-relevant decision or persistence made on
unvalidated business data**.

```python
# Python — DANGEROUS: trusts client-supplied price/total; no server recompute
def checkout(req):
    total = req.json["total"]          # client controls the amount charged
    price = req.json["price"]          # client controls unit price
    charge_card(user, total)           # SINK: charges attacker-chosen amount
```
```javascript
// Node — DANGEROUS: negative / no-bound quantity -> negative total or overflow
app.post('/cart/add', (req, res) => {
  const qty = req.body.quantity;               // e.g. -5 or 999999999
  const line = qty * product.price;            // negative line item credits user
  cart.total += line;                          // SINK: total can go negative
});
```
```java
// Java — DANGEROUS: workflow step-skipping, no server-side sequence check
@PostMapping("/order/confirm")
public void confirm(@RequestParam String orderId) {
    // never verifies payment step completed -> reach 'confirm' from 'cart'
    orderService.markPaidAndShip(orderId);     // SINK: ships without payment
}
```
```python
# DANGEROUS: coupon stacking / replay — no per-user uniqueness or exclusivity
for code in req.json["coupons"]:               # apply many, including duplicates
    total -= lookup_discount(code)             # SINK: stack N coupons, go to $0
```
```
# Invariants commonly MISSING at the sink (flag their absence):
- quantity/amount range: qty > 0 AND qty <= max; amount > 0 AND <= balance
- price/total: recomputed server-side from catalog, never read from client
- ownership: resource belongs to the authenticated user (also see IDOR)
- workflow: current_state permits this transition; step tokens verified
- uniqueness: coupon/referral/reward redeemable once per user (DB constraint)
- currency/rounding: single source of truth, banker's rounding, no negative FX
```

## 5. Sanitizers / safe patterns

**Safe:** treat every client-supplied business value as untrusted. **Recompute**
prices, totals, tax, and discounts server-side from authoritative catalog/data;
never trust a client `total`/`price`. Enforce explicit **range checks** (`qty > 0`,
`qty <= maxPerOrder`, `amount <= balance`, reject negatives/zero where meaningless)
and guard against integer/decimal **overflow**. Model workflows as an explicit
**state machine** and validate each transition (`assert state == EXPECTED`) with
server-side, tamper-proof step tokens. Enforce **one-time actions and coupon
exclusivity** with DB unique constraints / idempotency keys, not app flags. Use a
single currency/rounding authority.

**Fails / not a real sanitizer:**
- Client-side validation only (JS form checks, disabled/`readonly` fields) —
  trivially bypassed by editing the request.
- Recomputing the total but still honoring a client-supplied `discount`/`price`.
- Checking `qty > 0` but not an upper bound (overflow, over-claim), or vice versa.
- Blocklisting a few coupon codes instead of enforcing per-user single use.
- Verifying the *final* step's inputs but not that prior steps completed
  (step-skipping) — order-of-operations left implicit.
- Rounding independently in multiple places, enabling salami/rounding abuse.
- Relying on obscure/hidden fields ("no UI to set a negative qty") for security.

## 6. Detection methodology

1. **Find trusted client business values:**
   ```
   rg -in 'req(uest)?\.(body|json|params|query|form)\[?["'\'']?(price|total|amount|cost|subtotal|discount|tax|qty|quantity|currency|role|status|balance)'
   rg -in '\$_(POST|GET|REQUEST)\[.?(price|total|amount|qty|discount|role|status)'
   ```
   For each, check whether the server **recomputes** it or uses it directly.
2. **Find missing range/sign checks on quantities & amounts:**
   ```
   rg -in '(quantity|qty|amount|count|price|total) *[*+\-]' 
   rg -in 'parseInt|parseFloat|Number\(|Decimal\(|int\(|float\(' 
   ```
   Look for arithmetic on request values with no preceding `> 0` / `<= max` guard.
3. **Find workflow / state transitions without sequence checks:**
   ```
   rg -in 'status *=|state *=|step *=|stage *=|markPaid|approve|confirm|complete|activate|promote'
   ```
   Verify each state-changing handler asserts the prior required state.
4. **Find coupon/referral/reward redemption:**
   ```
   rg -in 'coupon|voucher|promo|discount|referral|loyalty|reward|giftcard|redeem|claim'
   ```
   Check for per-user uniqueness (DB unique constraint) and exclusivity/stacking rules.
5. **Find one-time actions relying on app flags** (replayable): compare against a
   DB unique constraint / idempotency key (overlaps with race-conditions §6).
6. **Confirm the broken invariant:** state it explicitly (price can be negative,
   coupon stacks, step 3 reachable without 1–2) and confirm no server-side control
   enforces it. Business-logic bugs are semantic — read the flow, not just patterns.

## 7. Modern & niche variants

- **Negative / zero / overflow quantities & amounts:** `qty = -1` credits the
  cart; huge values overflow an `int`/`money` type or bypass an upper bound;
  fractional quantities of indivisible goods.
- **Price / discount / tax manipulation:** client sends `price`/`discount`/`total`
  and the server honors it; percentage discounts `>100%`; negative shipping.
- **Trusting client-computed totals:** server charges the amount the client
  calculated instead of recomputing from the catalog.
- **Workflow / state-machine step skipping:** jump straight to `confirm`/`ship`/
  `getReward` without the prerequisite paid/verified steps; forced browsing of
  wizard steps; parameter-set state (`status=approved`).
- **Coupon / referral / loyalty abuse & stacking:** apply the same code N times,
  stack mutually-exclusive offers, self-referral loops, redeem before invalidation.
- **Replay of one-time actions:** re-submit a reward/refund/vote/withdrawal
  because uniqueness is enforced in app logic, not the DB.
- **Missing max/min limits & quotas:** no per-order/per-user/per-time cap → bulk
  abuse, inventory hoarding, resource exhaustion by design.
- **Currency / rounding abuse:** exploit FX conversion, sub-cent rounding
  (salami), or multi-currency mismatches to gain value.
- **Parameter tampering on business fields:** switching `userId`/`accountId`/
  `orderId`/`tier` to act on or as another entity (borders on IDOR/authorization).

## 8. Common false positives

- Values that are recomputed server-side from authoritative data (the client copy
  is display-only and never trusted for the decision).
- Fields constrained by strong server-side range/sign checks *and* type limits.
- Workflows that explicitly assert the prior state before each transition.
- Coupons/rewards protected by DB unique constraints / idempotency keys.
- "Client value" that is actually a signed, server-issued, tamper-evident token
  (verified before use).

## 9. Severity & exploitability

Base **Medium–High**, driven by concrete impact: direct monetary loss
(free/underpriced goods, over-refund, negative charges) or integrity breach
(skipped payment/KYC, unlimited redemption) is **High**; capped or low-value abuse
is **Medium**. Raise if unauthenticated/self-service and default configuration is
vulnerable; lower if it needs an unusual privilege or yields negligible value.
Because these are design flaws, confidence often rests on reading the flow — keep
severity and confidence orthogonal. See `references/severity-model.md`.

## 10. Remediation

Never trust client-supplied business values: recompute prices/totals/tax
server-side from authoritative data. Enforce explicit range, sign, and upper-bound
checks (guard overflow) on all quantities and amounts. Model workflows as a
server-side state machine and validate every transition. Enforce one-time actions
and coupon exclusivity with DB unique constraints / idempotency keys. Centralize
currency and rounding.

## 11. Output

Append each confirmed finding to **`findings/34-business-logic-flaws.md`** using
`references/finding-template.md`. Set `Class: Business Logic Flaw`,
`CWE: CWE-840` (add `CWE-841` for improper enforcement of workflow/behavioral
sequence), and in **Chain potential** note primitives such as *monetary
manipulation* (free/underpriced purchase, over-refund), *limit/quota bypass*
(→ pairs with race-conditions double-spend), *workflow-control bypass*
(→ reach privileged states, skip payment/verification), and *parameter tampering
on identity fields* (→ feeds/consumes IDOR & authorization chains).

**Primitives (controlled):** provides `DATA_WRITE`,`AUTHZ_BYPASS`; consumes none

## References
- CWE-840 (Business Logic Errors); CWE-841 (Improper Enforcement of Behavioral
  Workflow); OWASP A04:2021 Insecure Design; OWASP WSTG Business Logic Testing;
  OWASP Web Security Testing Guide.
