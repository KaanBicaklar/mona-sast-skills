# Chain-Validation Playbook

How to validate an **attack chain** non-destructively — proving each primitive
handoff is *feasible* without causing the end impact. Used by
`sast-finding-validation` Phase 3. Pair with `attack-chaining-catalog.md` (the
chain definitions) and `severity-model.md` (chain uplift).

## The principle

A chain is a sequence of links where each link's `provides` primitive satisfies the
next link's `consumes`. Validating it means proving, in order, that:

1. every link fires on its own (already `Confirmed (PoC)` from Phase 2), and
2. each **handoff** actually works — the primitive produced by link *N* is really
   usable by link *N+1*.

Default posture holds: prove the handoff is **feasible**, then stop. Do not execute
the destructive end state (don't drain the cloud, don't take over the real victim
account, don't exfiltrate bulk data).

## Handoff proofs by primitive

For each primitive one link hands to the next, the benign "it works" proof:

| Handoff primitive | Benign feasibility proof (stop here) | Do NOT |
|---|---|---|
| `SECRET_LEAK` → auth/forge | The leaked key/token is *accepted*: sign a token with it and call a harmless `whoami`; get 200 + the forged identity echoed | Use it to act as the victim/admin |
| `OUTBOUND_REQUEST` (SSRF) | Server fetches an attacker-observable URL (OOB hit, or self-URL differential) | Read live cloud-metadata credentials |
| `URL_CONTROL` (open redirect) → OAuth | The `redirect_uri`/`next` honors the crafted host — observe the `Location`/authorize response points off-domain | Capture a real user's token |
| `IDENTITY_FORGE` | The forged/altered identity is accepted on one authenticated read endpoint | Perform privileged writes/actions |
| `AUTHZ_BYPASS` (IDOR/BFLA) | Read *one* of your own neighbour objects cross-identity | Bulk-harvest real users |
| `JS_EXEC` (XSS) | Marker executes in the authenticated origin (`document.domain` alert / DOM marker) | Steal real sessions at scale |
| `FORCED_REQUEST` (CSRF) | A cross-site-shaped request performs the state change on *your own* test account | Target real users |
| `CODE_EXEC` | Benign signal only — `sleep`/DNS callback / echo a marker | Reverse shell, file writes, persistence |
| `FILE_READ` | Read a known-benign file (`/etc/hostname`) to prove the primitive | Read secrets/keys beyond one proof |
| `CACHE_CONTROL` (cache poisoning) | Poison a benign marker into a throwaway cache key and observe it served back | Poison a shared production key |
| `GADGET` (PP/deser) | Show the injected property/gadget is reached (a benign side effect) | Trigger the RCE gadget |

## Per-chain recipes (catalog §3)

Each: **precondition → ordered handoff proofs → chain verdict criteria.**

- **C1 Cloud takeover (SSRF → metadata → creds → cloud):** prove SSRF reaches an
  OOB endpoint; then prove the metadata *path* is reachable (request it, observe a
  non-error shape) — STOP before reading live credentials unless cloud-exploitation
  is authorized. Verdict *Validated* if SSRF + metadata-reachability shown;
  *Links-confirmed* if creds step withheld.
- **C2 OAuth token theft (open redirect → redirect_uri):** prove the redirect
  honors an off-domain host AND the OAuth flow uses that param for the code/token
  delivery. STOP before capturing a real user's token.
- **C3 Reset-link poisoning (host header → reset email):** prove the reset email/
  link is built from the attacker-controlled Host (inspect the generated link on
  *your own* account). Don't harvest others' tokens.
- **C4 Forged admin identity (leaked signing key → forge JWT):** prove the leaked
  key verifies a self-forged token on a harmless authenticated endpoint. STOP —
  don't perform admin actions.
- **C5 SQLi→RCE / C7 LFI→RCE / C20 zip-slip→RCE:** prove the write/exec primitive
  with a benign marker (timing/DNS), not a shell.
- **C6 Stored-XSS privilege pivot:** prove the payload stores and executes in an
  admin/other-user view *you control* (a second test account), not a real admin.
- **C11 Mass-assign escalation (CSRF + role):** on your own test account, prove the
  forged request sets a privileged field; confirm the resulting token/profile
  reflects it. Don't escalate a real account.
- **C12 IDOR→takeover:** prove one cross-identity read exposes a reset token/API
  key field for a *test* neighbour; don't take over a real account.
- **C17 Supply-chain→prod RCE / C18 LLM tool abuse:** prove the injection reaches
  the execution/tool boundary with a benign marker; don't run real payloads.

For chains not listed, decompose into the handoff-primitive table above and prove
each hop in order.

## Verdict mapping (what to record)

- **Validated (end-to-end PoC)** — all links Confirmed + every handoff shown benignly.
- **Links-confirmed / handoff-unproven** — links Confirmed but a hop withheld for
  safety/scope, or not safely demonstrable. Note which hop and why.
- **Broken** — a link is an FP, or a handoff provably fails (key rejected, redirect
  not honored, WAF severs it).
- **Theoretical** — a link is Inconclusive / Not validated; feasible on the graph
  but unproven.

Record the verdict, the failed/withheld handoff, and the tester identity in
`findings/VALIDATION-LOG.md` and feed it to `sast-final-report`.

## Manual continuation kit (when Claude can't finish it)

Chain validation is best-effort and non-destructive. When a chain stalls
(`Links-confirmed`, `Broken` at a handoff, or `Theoretical`), do not just record a
verdict — package everything the user needs to continue **by hand**:

1. **Hypothesis** — the ordered links and the primitive each hands off.
2. **Progress** — which links are `Confirmed (PoC)`; the last handoff that worked.
3. **Blocker** — the exact handoff you got stuck on and why (token rejected,
   redirect not honored, state/role not reachable, scope/authorization ceiling,
   non-destructive limit).
4. **Next step** — the exact Burp-pasteable request(s) to try next and the precise
   signal that would confirm the handoff.
5. **Preconditions** — anything still required (funded/privileged account, specific
   role, OOB/collaborator host, timing).

Write it into `findings/VALIDATION-LOG.md` under the chain's entry and surface it to
the user. Claude failing to prove a chain must never be a dead end — the kit lets
the user resume exactly where automation stopped.
