# Attack-Chaining Catalog

Single findings are links; **chains** are the real risk. This catalog defines the
**primitive graph** (what each class *provides* and *consumes*) and a library of
known chains. `sast-final-report` uses it to connect findings across files.

The mechanic: every finding declares, in its `Chain potential` field, the
**primitive it provides** and any **primitive it consumes**. A chain exists when
finding A's *provides* satisfies finding B's *consumes*.

---

## 1. Primitive vocabulary

| Primitive | Meaning |
|---|---|
| `HTML_OUTPUT` | Attacker controls bytes in an HTML/JS response |
| `JS_EXEC` | JavaScript runs in a victim's authenticated origin (XSS) |
| `URL_CONTROL` | Attacker controls a redirect/fetch target (open redirect) |
| `OUTBOUND_REQUEST` | Server makes an attacker-influenced request (SSRF) |
| `FILE_READ` | Read arbitrary/sensitive files |
| `FILE_WRITE` | Write files to attacker-chosen paths |
| `DATA_READ` | Read arbitrary DB/store data |
| `DATA_WRITE` | Write arbitrary DB/store data |
| `SECRET_LEAK` | Obtain a key/token/credential/hash |
| `AUTHZ_BYPASS` | Access another principal's objects/functions (IDOR/BFLA) |
| `IDENTITY_FORGE` | Mint/alter a trusted identity (JWT/SAML/session) |
| `FORCED_REQUEST` | Cause a victim's browser to send a request (CSRF) |
| `GADGET` | A sink reachable given an injected object/class (PP, deser) |
| `CODE_EXEC` | Arbitrary code/command execution (RCE) — usually a terminal node |
| `CACHE_CONTROL` | Persist a response into a shared cache |
| `PROMPT_CONTROL` | Inject instructions into an LLM context |

## 2. Provides / Consumes map (by class)

| Class | Provides | Consumes |
|---|---|---|
| SQL / NoSQL injection | `DATA_READ`,`DATA_WRITE`,`SECRET_LEAK`, sometimes `FILE_READ`/`FILE_WRITE`/`CODE_EXEC` | — |
| Command / code injection, SSTI, deserialization | `CODE_EXEC` | sometimes `GADGET` (deser needs classpath gadget) |
| SSRF | `OUTBOUND_REQUEST`,`SECRET_LEAK` (metadata), `FILE_READ` (file://) | sometimes `URL_CONTROL` (open-redirect bypass) |
| XXE | `FILE_READ`,`OUTBOUND_REQUEST` | — |
| Path traversal / LFI | `FILE_READ`, LFI→`CODE_EXEC`; zip slip→`FILE_WRITE` | — |
| File upload | `FILE_WRITE`,`HTML_OUTPUT` (SVG/HTML), sometimes `CODE_EXEC` | — |
| XSS / DOM-clobbering / postMessage | `JS_EXEC` | often `HTML_OUTPUT`; DOM XSS consumes `GADGET` (PP) |
| Prototype pollution | `GADGET` (→`CODE_EXEC` or `JS_EXEC`) | — |
| Open redirect | `URL_CONTROL` | — |
| CORS misconfig | `DATA_READ` (cross-origin) | needs a victim with `JS_EXEC` or creds |
| CSRF | `FORCED_REQUEST` | pairs with `DATA_WRITE`/mass-assignment |
| Broken access control / IDOR | `AUTHZ_BYPASS`,`DATA_READ`,`SECRET_LEAK` | — |
| Mass assignment | `AUTHZ_BYPASS`,`IDENTITY_FORGE` (set role) | often `FORCED_REQUEST` |
| Auth flaws / insecure randomness | `IDENTITY_FORGE`,`AUTHZ_BYPASS` | sometimes `SECRET_LEAK` (host-header reset) |
| JWT / OAuth / SAML | `IDENTITY_FORGE` | JWT-key-confusion consumes `SECRET_LEAK`; OAuth consumes `URL_CONTROL` |
| Hardcoded secrets | `SECRET_LEAK` | — |
| Weak crypto | `IDENTITY_FORGE` (forge/decrypt tokens),`SECRET_LEAK` | — |
| CRLF / header injection | `HTML_OUTPUT`,`CACHE_CONTROL` seed, log forge | — |
| Web cache poisoning | `CACHE_CONTROL` (amplifies `HTML_OUTPUT`/`JS_EXEC`) | consumes reflected `HTML_OUTPUT` |
| Request smuggling | `AUTHZ_BYPASS`,`CACHE_CONTROL`,`SECRET_LEAK` (capture) | — |
| Race / TOCTOU, business logic | `DATA_WRITE`,`AUTHZ_BYPASS` (limit overrun) | — |
| CI/CD injection | `CODE_EXEC` (build),`SECRET_LEAK` | often untrusted PR `PROMPT_CONTROL`-like input |
| IaC / dependency-supply-chain | `CODE_EXEC`,`SECRET_LEAK`,`OUTBOUND_REQUEST` | — |
| LLM insecure output handling | forwards `PROMPT_CONTROL`→`CODE_EXEC`/`JS_EXEC`/`DATA_READ` | consumes `PROMPT_CONTROL` |
| Security misconfig & headers | `FORCED_REQUEST` (clickjacking); amplifies `JS_EXEC` (missing HttpOnly → cookie theft) | consumes `JS_EXEC` |
| Information disclosure | `SECRET_LEAK` (stack traces, debug consoles, `.git`/`.env`, heapdump, source maps, XSSI/JSONP) | — |
| WebSocket security (CSWSH) | `AUTHZ_BYPASS`,`DATA_READ`,`FORCED_REQUEST` | — |
| Logging & monitoring failures | — (amplifier: hides other chains; `SECRET_LEAK` if secrets logged) | — |
| Session management | `IDENTITY_FORGE`,`AUTHZ_BYPASS` (fixation, no logout invalidation) | sometimes `SECRET_LEAK` (predictable/leaked id) |
| Mobile — Android | `SECRET_LEAK` (insecure storage),`CODE_EXEC` (WebView JS bridge / deeplink→intent),`DATA_READ` | — |
| Mobile — iOS | `SECRET_LEAK` (Keychain/plist/pasteboard),`DATA_READ` | — |
| Memory safety (native) | `CODE_EXEC` (terminal); `SECRET_LEAK` (OOB read) | — |
| Smart contract (EVM) | `DATA_WRITE` (asset drain),`AUTHZ_BYPASS`,`SECRET_LEAK` | sometimes `OUTBOUND_REQUEST` (oracle/flash-loan) |

## 3. Named chains (curated)

Each is `link → link → …  ⇒ end impact (chain severity)`.

1. **Cloud takeover:** SSRF `OUTBOUND_REQUEST` → cloud metadata `SECRET_LEAK` (IAM creds) → cloud API ⇒ full account takeover. **Critical.**
2. **OAuth token theft:** Open redirect `URL_CONTROL` → weak `redirect_uri` validation → auth-code/token exfil ⇒ account takeover. **Critical.**
3. **Reset-link poisoning:** Host-header injection → password-reset email points to attacker host → `SECRET_LEAK` (reset token) ⇒ account takeover. **High/Critical.**
4. **Forged admin identity:** Hardcoded JWT signing key `SECRET_LEAK` → forge `IDENTITY_FORGE` admin token ⇒ auth bypass → reach admin-only RCE feature. **Critical.**
5. **SQLi to RCE:** SQLi `FILE_WRITE` (`INTO OUTFILE` webshell) **or** stacked query → `xp_cmdshell`/`COPY PROGRAM` ⇒ `CODE_EXEC`. **Critical.**
6. **Stored-XSS privilege pivot:** File upload (SVG/HTML) `HTML_OUTPUT` → stored XSS `JS_EXEC` in admin view → steal admin session/CSRF token ⇒ admin actions. **High/Critical.**
7. **LFI to RCE:** Path traversal `FILE_READ` → log/session poisoning → include → `CODE_EXEC`; or read `.env` `SECRET_LEAK` → DB/cloud creds. **High/Critical.**
8. **Prototype pollution to RCE:** PP `GADGET` → `child_process`/template option gadget ⇒ `CODE_EXEC` (server) or DOM sink ⇒ `JS_EXEC` (client). **Critical/High.**
9. **Cache-amplified XSS:** Reflected `HTML_OUTPUT` via unkeyed header + web cache poisoning `CACHE_CONTROL` ⇒ persistent `JS_EXEC` to all users. **High/Critical.**
10. **CORS data exfil:** CORS reflected-origin + credentials → `DATA_READ` cross-origin of authenticated API ⇒ mass data theft. **High.**
11. **Mass-assign escalation:** CSRF `FORCED_REQUEST` + mass assignment (`role=admin`) `IDENTITY_FORGE` ⇒ privilege escalation. **High.**
12. **IDOR to takeover:** IDOR `AUTHZ_BYPASS` enumerating other users → leak reset token / API key `SECRET_LEAK` ⇒ account takeover. **High/Critical.**
13. **XXE pivot:** XXE `FILE_READ`/`OUTBOUND_REQUEST` → read secrets or SSRF to metadata ⇒ (feeds chain 1 or 4). **High.**
14. **Predictable token takeover:** Insecure randomness → predict reset/session token `IDENTITY_FORGE` ⇒ account takeover. **High.**
15. **Smuggling bypass:** Request smuggling `AUTHZ_BYPASS` → reach internal-only endpoints / capture other users' requests `SECRET_LEAK`. **High/Critical.**
16. **GraphQL escalation:** Introspection → discover hidden mutation → BFLA `AUTHZ_BYPASS` ⇒ privilege escalation / data write. **High.**
17. **Supply-chain to prod RCE:** Dependency confusion / CI script injection `CODE_EXEC` in pipeline → `SECRET_LEAK` (deploy creds) ⇒ production compromise. **Critical.**
18. **LLM tool abuse:** Indirect prompt injection `PROMPT_CONTROL` → insecure output handling into a shell/SQL/HTTP sink ⇒ `CODE_EXEC`/`DATA_READ`/SSRF. **High/Critical.**
19. **Padding-oracle forge:** Weak crypto (CBC no MAC) → decrypt/forge auth cookie `IDENTITY_FORGE` ⇒ auth bypass. **High.**
20. **Zip-slip to RCE:** Archive extraction `FILE_WRITE` outside target → overwrite a served/startup file ⇒ `CODE_EXEC`. **High/Critical.**

## 4. Chain-discovery algorithm (for the final report)

1. Collect every finding's `provides` and `consumes` primitives.
2. Build a directed graph: edge A→B iff `provides(A) ∩ consumes(B) ≠ ∅`, or B is a
   known consumer of a primitive A provides per §2/§3.
3. Match against the named chains in §3; also surface **novel** paths of length ≥2
   that terminate in a high-impact primitive (`CODE_EXEC`, `IDENTITY_FORGE`,
   `SECRET_LEAK`→auth, `AUTHZ_BYPASS` over all users).
4. Rank chains by end-impact severity (see `severity-model.md` §3 — chain uplift).
5. For each reported chain, cite the concrete finding IDs of each link and state
   the single precondition that makes the whole chain reachable.
