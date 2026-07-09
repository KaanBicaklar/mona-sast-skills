---
name: race-conditions-and-toctou
description: >-
  SAST detection methodology for race conditions and TOCTOU flaws (CWE-362,
  CWE-367, CWE-366), including limit-overrun / double-spend, non-atomic
  check-then-act, TOCTOU file races, and missing DB transactions/row locks. Use
  when reviewing check-then-act logic on shared state (balances, inventory,
  files, one-time actions). Writes confirmed findings to
  findings/33-race-conditions-and-toctou.md.
---

# Race Conditions & TOCTOU — SAST Methodology

**Class:** Race Condition / TOCTOU · **CWE-362 / CWE-367 / CWE-366** · **OWASP:** A04 Insecure Design
**Findings file:** `findings/33-race-conditions-and-toctou.md`

## 1. Overview

A race condition occurs when the correctness of a security decision depends on the
*ordering* of concurrent operations, and an attacker can interleave requests to
violate an invariant between a **check** and the **act** that relies on it
(time-of-check to time-of-use, TOCTOU). The classic exploit is **limit overrun**:
read a balance/quota, validate it, then update — but fire N concurrent requests so
all pass the check before any writes. The core test: is there a check-then-act (or
read-modify-write) on shared state that is **not atomic** — no transaction, row
lock, atomic operation, or idempotency key — and can the attacker trigger it
concurrently?

## 2. Where it lives

- Financial/quota logic: withdrawals, transfers, balance decrements, credit
  redemption, inventory/stock decrement, rate/usage counters.
- Coupon / gift-card / referral / vote / "claim once" endpoints.
- Any `SELECT` … (validate in app) … `UPDATE`/`INSERT` without a transaction or lock.
- File operations: `access()`/`stat()` then `open()`, temp-file creation,
  symlink-followed paths, lockfiles, upload-then-move.
- Multi-step state updates in caches or in-memory maps shared across requests.
- Distributed workers/cron acting on the same rows without coordination.

## 3. Sources (tainted input)

The "source" here is **attacker-controllable concurrency and timing** rather than a
single value: the ability to send many simultaneous requests (single-packet /
last-byte-sync attacks minimize jitter), replay the same request, or win a filesystem
race by swapping a symlink/file between check and use. The security-relevant
*shared state* (balance, stock count, "already claimed" flag, file path) is what the
attacker corrupts. Trace which endpoints let an unauthenticated or normal user
drive concurrent access to the same record.

## 4. Sinks (dangerous operations)

The "sink" is the **security decision or state mutation performed non-atomically on
shared data** — the act that trusts a stale check.

```python
# Python — DANGEROUS: check-then-act on a balance, no lock/transaction
def withdraw(user_id, amount):
    bal = db.query("SELECT balance FROM accounts WHERE id=%s", user_id)  # CHECK
    if bal >= amount:                                                    # gap!
        db.execute("UPDATE accounts SET balance = balance - %s WHERE id=%s",
                   amount, user_id)                                      # ACT
    # N concurrent calls all read the same bal -> overdraw / double-spend
```
```javascript
// Node — DANGEROUS: non-atomic coupon redeem, read-modify-write on shared row
async function redeem(code, user) {
  const c = await db.coupon.findOne({ code });      // CHECK: used == false
  if (c && !c.used) {                               // gap (await = interleave)
    await grantCredit(user, c.value);
    await db.coupon.update({ code }, { used: true });// ACT: too late
  }                                                 // redeem N times before update
}
```
```java
// Java — DANGEROUS TOCTOU file race: check then use, path can change between
if (file.exists() && file.canWrite()) {   // TIME-OF-CHECK
    FileWriter w = new FileWriter(file);  // TIME-OF-USE: symlink swapped -> write elsewhere
}
```
```c
// C — classic access()/open() TOCTOU
if (access("/tmp/f", W_OK) == 0) {   // check as real user
    int fd = open("/tmp/f", O_WRONLY);  // attacker swaps /tmp/f for a symlink -> privileged write
}
```
```
# Missing atomicity primitives to look for the ABSENCE of:
- SELECT ... FOR UPDATE / SELECT ... LOCK IN SHARE MODE
- UPDATE ... SET x = x - :n WHERE x >= :n   (atomic conditional decrement)
- optimistic concurrency: WHERE version = :v  (version/ETag column)
- BEGIN ... COMMIT transaction wrapping check+act
- idempotency key / unique constraint preventing replay
```

## 5. Sanitizers / safe patterns

**Safe:** make the check and act **atomic**. Options: wrap in a DB transaction with
`SELECT ... FOR UPDATE` (pessimistic lock); use an **atomic conditional write**
(`UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance >= :amt`
and require `rowcount == 1`); use **optimistic concurrency** (a `version` column,
retry on mismatch); enforce a **unique constraint / idempotency key** so a replay
fails at the DB; use atomic primitives (`Redis DECR`/`INCR`, compare-and-swap,
`SELECT ... FOR UPDATE SKIP LOCKED` for queues). For files: open with
`O_CREAT|O_EXCL`, operate on file descriptors not paths, use `openat`/`O_NOFOLLOW`,
`mkstemp` for temp files, avoid `access()`-then-`open()`.

**Fails / not a real sanitizer:**
- Reading, validating, then writing in **separate statements** without a
  transaction/lock — the textbook race.
- A DB transaction that only wraps the write but re-uses a value read *outside* it.
- Application-level `if (!used) { ...; used = true }` flags in memory or across
  awaits — non-atomic.
- Checking a unique value in the app then inserting (still racy) instead of a DB
  **unique constraint**.
- `access()` before `open()`, or validating a path then re-resolving it.
- Distributed locks with no fencing token (a stale lock holder still writes).
- Rate limiting that doesn't cover the specific overrun window.

## 6. Detection methodology

1. **Find check-then-act on shared state:**
   ```
   rg -in 'SELECT .*balance|SELECT .*stock|SELECT .*quota|findOne|find_by|get_by_id' 
   rg -in 'if .*(balance|stock|count|used|claimed|remaining) *(>=|<=|==|!=)' 
   ```
   Then check whether an UPDATE/INSERT on the same record follows without a lock.
2. **Confirm the absence of atomicity primitives:**
   ```
   rg -in 'FOR UPDATE|LOCK IN SHARE|SELECT.*LOCK|BEGIN;|transaction|@Transactional|with_for_update|SERIALIZABLE'
   rg -in 'version *=|optimistic|idempotenc|unique.*constraint|INCR|DECR|compareAndSet|CAS'
   ```
   A hit near the sink is reassuring; its absence around a check-then-act is the bug.
3. **Find TOCTOU file races:**
   ```
   rg -in 'access\(|os\.path\.exists|File\(.*\)\.exists|stat\(|canWrite\(|isFile\('
   rg -in 'mktemp|tmpnam|tempfile|O_CREAT|O_EXCL|O_NOFOLLOW|symlink|realpath'
   ```
   Flag `exists/access/stat` followed by `open/write` on the same path.
4. **Assess concurrency reachability:** is the sink an endpoint a user can call
   concurrently (no per-user serialization)? One-time actions (redeem, claim,
   vote, withdraw) are prime targets; note single-packet-attack relevance.
5. **Check idempotency/replay:** does a one-time action rely only on an app flag,
   or on a DB unique key/idempotency token? App-only = replayable.
6. **Confirm the invariant it breaks:** overdraft, over-claim, negative stock,
   duplicate reward, privileged file write.

## 7. Modern & niche variants

- **Limit overrun / double-spend:** N concurrent requests all pass a
  `balance >= amount` / `stock > 0` / `!used` check before any write — withdraw
  twice, redeem a coupon N times, over-claim inventory, vote repeatedly.
- **TOCTOU file races:** `access()`/`stat()` then `open()`; symlink swap between
  check and use; predictable temp-file names (`/tmp/app-<pid>`) enabling
  pre-creation or symlink attacks.
- **Missing DB transaction / row lock:** read-modify-write split across statements
  with no `SELECT ... FOR UPDATE`, transaction, or `SERIALIZABLE` isolation.
- **Missing optimistic concurrency:** no `version`/ETag column, so two writers
  clobber each other (lost update).
- **Single-packet / last-byte-sync attack:** modern technique to land ~20-30
  requests in the same server tick, defeating naive timing assumptions and making
  even tiny race windows exploitable.
- **Missing idempotency keys:** payment/order/reward endpoints replayable because
  uniqueness is enforced in app logic, not by a DB constraint.
- **Non-atomic read-modify-write on counters/balances** in caches or in-memory
  maps shared across worker threads/processes.

## 8. Common false positives

- Check and act wrapped in one transaction with an appropriate lock or executed as
  a single atomic conditional `UPDATE ... WHERE ...` (verify `rowcount` is checked).
- Operations on request-local / non-shared state (no concurrency across users).
- A DB unique constraint / idempotency key already blocks the replay at the DB.
- File ops using `O_CREAT|O_EXCL`, `mkstemp`, or fd-based APIs with `O_NOFOLLOW`.
- Endpoints serialized per-user (queue, mutex, single-writer) so concurrency can't
  reach the shared record.

## 9. Severity & exploitability

Base **High** when the race yields direct financial/data-integrity impact
(double-spend, over-withdraw, negative inventory, duplicated rewards) or a
privileged file write (TOCTOU → local privilege escalation). **Medium** for
limited over-claim of low-value resources or hard-to-win windows. Raise if
unauthenticated and single-packet-attack-feasible; lower if the window is tiny and
requires precise, authenticated timing. See `references/severity-model.md`.

## 10. Remediation

Make check-and-act atomic: wrap in a transaction with `SELECT ... FOR UPDATE`, use
an atomic conditional `UPDATE ... WHERE balance >= :amt` (check affected rows), or
optimistic concurrency with a `version` column. Enforce one-time actions with a DB
unique constraint / idempotency key. For files, use `O_CREAT|O_EXCL`, `mkstemp`,
and fd-based, `O_NOFOLLOW` operations instead of path re-resolution.

## 11. Output

Append each confirmed finding to
**`findings/33-race-conditions-and-toctou.md`** using
`references/finding-template.md`. Set `Class: Race Condition / TOCTOU`,
`CWE: CWE-362` (add `CWE-367` for file TOCTOU, `CWE-366` for shared-variable
races), and in **Chain potential** note primitives such as *limit/quota bypass*
(→ double-spend, free goods, over-claim feeds business-logic chains),
*integrity violation on shared state* (→ negative balances/stock), and
*privileged file write via TOCTOU* (→ local privilege escalation / arbitrary write).

**Primitives (controlled):** provides `DATA_WRITE`,`AUTHZ_BYPASS`; consumes none

## References
- CWE-362 (Concurrent Execution / Race Condition); CWE-367 (TOCTOU); CWE-366
  (Race Condition within a Thread); OWASP A04:2021 Insecure Design; PortSwigger
  race-condition / single-packet-attack research.
