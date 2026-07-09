---
name: jwt-vulnerabilities
description: >-
  SAST detection methodology for JWT/JWS verification flaws (CWE-347, CWE-345),
  including alg:none acceptance, HS/RS algorithm confusion, weak HMAC secrets,
  attacker-supplied keys via jwk/jku/x5u, kid header injection (path traversal /
  SQLi / command injection), missing exp/nbf/aud/iss validation, decode-without-
  verify, unpinned algorithms, and sensitive data in the payload. Use when
  reviewing code that issues or validates JSON Web Tokens. Writes confirmed
  findings to findings/22-jwt-vulnerabilities.md.
---

# JWT Vulnerabilities — SAST Methodology

**Class:** JWT Vulnerabilities · **CWE-347** (Improper Verification of Cryptographic Signature; also **CWE-345** Insufficient Verification of Data Authenticity) · **OWASP:** A02 Cryptographic Failures / A07 Identification & Authentication Failures
**Findings file:** `findings/22-jwt-vulnerabilities.md`

## 1. Overview

A JWT is only a security control if its signature is verified with a key and
algorithm the *server* chose — and if the standard claims (`exp`, `nbf`, `aud`,
`iss`) are checked. JWT vulnerabilities arise when the verifier trusts the
attacker-controlled **header** (its `alg`, `jwk`, `jku`, `x5u`, `kid`) to decide
*how* or *with what key* to verify, when the signature isn't verified at all, or
when a weak/known secret makes forgery trivial. The core test: does the server
verify with a **pinned algorithm and a server-held key**, reject `alg:none`,
ignore key material named in the token header, and validate expiry/audience/issuer?
If any of "how to verify" is derived from the token itself, an attacker can forge
tokens and impersonate anyone.

## 2. Where it lives

- Auth middleware / filters that validate a bearer token on every request.
- Token issuance (sign) and validation (verify) helpers, often a shared util.
- Library calls: `jsonwebtoken` (Node), `PyJWT`, `jose`/`jjwt`/`nimbus`/`auth0
  java-jwt` (Java), `golang-jwt`, `firebase/php-jwt`, `ruby-jwt`,
  `System.IdentityModel`/`Microsoft.IdentityModel` (.NET).
- Anywhere a JWT is `decode`d for its claims without a verify step ("just read the
  sub").
- `kid`/`jku`/`x5u` resolution code that loads a key by an id/URL from the header.
- Config: the HMAC secret (env var, hard-coded, or default), the accepted-algorithm
  list, and JWKS endpoint URLs.

## 3. Sources (attacker-controlled token material)

The **entire token** is attacker-supplied: header (`alg`, `kid`, `jwk`, `jku`,
`x5u`, `typ`), payload claims (`sub`, `role`, `iss`, `aud`, `exp`), and the
signature. The attacker fully controls the header, so any verification decision
that reads the header — algorithm selection, key lookup by `kid`, key fetch from
`jku`/`x5u`, or an embedded `jwk` — is choosing verification parameters from
untrusted input. `kid` is a string that often flows into a **file path, SQL query,
or shell command** to fetch a key — making it a secondary injection source.

## 4. Sinks (dangerous operations)

Dangerous = verification that trusts the header, skips the signature, uses a weak
key, or omits claim checks.

```javascript
// Node jsonwebtoken — dangerous
jwt.decode(token);                                   // NO signature verification at all
jwt.verify(token, PUBLIC_KEY);                       // algs not pinned → alg confusion/none
jwt.verify(token, secret, { algorithms: ['none'] }); // accepts unsigned tokens
jwt.verify(token, secret);                           // no { audience, issuer } → claims unchecked
const secret = 'secret';                             // weak/guessable HMAC secret
```
```python
# PyJWT — dangerous
jwt.decode(token, options={"verify_signature": False})   # decode-only, forged tokens pass
jwt.decode(token, key, algorithms=["HS256","RS256"])     # mixing HS+RS → algorithm confusion
jwt.decode(token, key)                                    # no audience/issuer/exp enforcement
```
```java
// java-jwt / jjwt — dangerous
JWT.decode(token).getClaim("role");                  // decode without verify()
Jwts.parser().setSigningKey(key).build().parse(t);   // if key is a public key + HS accepted
// verifier that picks algorithm from token header instead of pinning it
```
```php
// firebase/php-jwt — dangerous: passing the header-declared alg back in
$decoded = JWT::decode($jwt, $key, array_keys($ALL_ALGS));  // attacker chooses alg
```
```javascript
// kid header injection — dangerous: header value used to locate the key
const key = fs.readFileSync(`/keys/${header.kid}`);          // path traversal → ../../dev/null
const key = db.query(`SELECT k FROM keys WHERE id='${header.kid}'`); // SQLi in key lookup
// jku/x5u — dangerous: fetch verification key from URL in the token
const jwks = await fetch(header.jku).then(r => r.json());    // attacker-hosted key set
```

## 5. Sanitizers / safe patterns (correct enforcement, and how it's bypassed)

**Correct enforcement:**
- **Pin the algorithm server-side.** Pass an explicit single-algorithm allowlist
  matching your key type (`algorithms: ['RS256']` *only*), and reject tokens whose
  header `alg` differs. Never derive the algorithm from the token.
- **Always verify the signature** with a **server-held** key; never `decode`
  claims for trust decisions.
- **Reject `alg:none`** explicitly; never include `none` in the allowed list.
- **Strong HMAC secret:** high-entropy, random, ≥256-bit, from secrets management —
  not a word, not committed, not a default.
- **Resolve keys from a trusted source only.** Ignore `jwk`/`jku`/`x5u` in the
  header, or restrict `jku`/`x5u` to a strict allowlist of your own HTTPS hosts.
  Map `kid` through a **fixed lookup table**, never into a file path / SQL / shell.
- **Validate claims:** `exp`, `nbf`, and (for audience isolation) `aud` and `iss`,
  with clock-skew bounds. Enforce `typ` where relevant.

**Fails / commonly bypassed:**
- **`alg:none` accepted** — verifier honors the header and treats the token as
  unsigned; forge any claims (the canonical JWT bug).
- **Algorithm confusion (HS/RS)** — an RS256 verifier that also accepts HS256 can
  be tricked: the attacker signs `HS256` using the **public key** (which is public)
  as the HMAC secret; the server "verifies" with that same public key. Caused by
  passing a permissive `algorithms` list or a verifier that keys off the header.
- **Weak/guessable HMAC secret** — offline brute-force/dictionary (`secret`,
  `changeme`, project name) recovers the key → forge tokens.
- **`jwk`/`jku`/`x5u` trusted** — the token embeds or points to the key used to
  verify it; the attacker supplies their own key/JWKS URL and self-signs. SSRF
  bonus via `jku`/`x5u` fetch.
- **`kid` injection** — the `kid` string is concatenated into a path (traversal to
  a predictable file whose contents the attacker knows, e.g. `/dev/null` → empty
  key), a SQL query (SQLi to return a chosen key), or a command (RCE).
- **Missing claim validation** — no `exp` (tokens live forever / replay), no `aud`
  (a token for service B accepted by service A), no `iss` (foreign issuer
  accepted).
- **Decode-without-verify** — `jwt.decode(...)` / `verify_signature: False` used to
  read `sub`/`role` for authorization.
- **Sensitive data in payload** — JWT is signed, not encrypted; PII/secrets in
  claims are readable by anyone holding the (base64) token.

## 6. Detection methodology

1. **Find verify/decode calls and inspect their options.**
   ```
   rg -n 'jwt\.(verify|decode|sign)|JWT\.(decode|require|create)|Jwts\.parser|jwt\.decode\(|jose\.|jwtVerify|ParseWithClaims'
   ```
2. **alg:none & unpinned algorithms.**
   ```
   rg -n "algorithms?\s*[:=].*(none|None)|alg.*none|verify_signature\s*[:=]\s*False|noneAlgorithm|unsecured"
   rg -n 'jwt\.verify\([^,]+,[^,]+\)\s*[;)]'   # verify with no options obj → algs unpinned
   ```
3. **Algorithm confusion (HS+RS mixed, public key as secret).**
   ```
   rg -n "algorithms?\s*[:=]\s*\[?['\"](HS|RS|ES).*['\"].*(RS|HS|ES)"   # list mixes families
   rg -n 'verify\([^)]*public|PUBLIC_KEY|publicKey.*verify|\.pem'
   ```
4. **Header-driven key material (jwk/jku/x5u/kid).**
   ```
   rg -n 'header\.(kid|jku|x5u|jwk)|\bkid\b|\bjku\b|\bx5u\b|getKeyId|\.kid'
   rg -n 'kid.*(readFile|open\(|SELECT|exec|require\()|jku.*(fetch|http|requests\.get)'
   ```
5. **Weak/hard-coded HMAC secret.**
   ```
   rg -n "(secret|signingKey|JWT_SECRET)\s*[:=]\s*['\"][^'\"]{0,16}['\"]|['\"]secret['\"]|changeme|s3cr3t"
   ```
6. **Missing claim validation.**
   ```
   rg -n 'audience|issuer|verify_aud|verify_iss|verify_exp|maxAge|clockTolerance|requireExpiration'
   ```
   Absence around a verify call is the finding.
7. **Decode-for-authorization:** any `decode`/`verify_signature:False` whose result
   feeds a role/permission/ownership decision.
8. **Confirm reachability:** is this the middleware on authenticated routes? A flaw
   here forges *any* identity — treat as pre-auth-equivalent.

## 7. Modern & niche variants

- **`alg:none` accepted:** verifier trusts the header `alg`; a token with
  `{"alg":"none"}` and an empty signature passes. Forge arbitrary claims →
  impersonate any user/admin. Still found in misconfigured or hand-rolled verifiers.
- **HS/RS algorithm confusion:** the highest-value modern JWT bug. An endpoint
  expecting RS256 also accepts HS256; the attacker re-signs a forged token with
  **HS256 using the server's RSA public key** (public, often at a `/jwks.json` or
  cert endpoint) as the HMAC secret. The server verifies with that same public key
  and accepts it. Root cause: not pinning to a single algorithm, or a verify call
  that selects the algorithm from the token.
- **Weak/guessable HMAC secret:** short, dictionary, default, or committed secret →
  offline brute force (hashcat) recovers it, enabling unlimited forgery. Grep for
  short/quoted secrets and defaults.
- **`jwk`/`jku`/`x5u` header trust:** the token carries the verification key
  (`jwk`) or a URL to fetch it (`jku`/`x5u`). If honored, the attacker supplies
  their own key/JWKS and self-signs any token. `jku`/`x5u` also yield **SSRF** (the
  server fetches an attacker URL). Fix: ignore these headers or allowlist the host.
- **`kid` header injection:** `kid` locates the verification key and often flows
  into a sink — **path traversal** (`kid: "../../../../dev/null"` → empty key, then
  sign with empty HMAC secret), **SQL injection** (`kid` in `SELECT key WHERE
  id=…` → attacker returns a known key), or **command injection** (`kid` in a shell
  key-fetch). Turns a header into RCE/forgery. Treat `kid` as tainted input to
  those sinks.
- **Missing `exp`/`nbf`/`aud`/`iss` validation:** no `exp` → stolen tokens never
  expire and replay indefinitely; no `aud` → a token minted for one service is
  accepted by another (confused deputy); no `iss` → tokens from an unexpected
  issuer accepted; `nbf`/clock-skew handling absent or too loose.
- **Signature not verified (decode-only):** `jwt.decode`, `verify_signature:False`,
  or `JWT.decode(token)` used to read claims for authorization — anyone can craft a
  token with any `role`/`sub`. Frequent in "we already validated at the gateway"
  code paths that are also reachable directly.
- **Algorithm not pinned server-side:** verifier accepts whatever `alg` the header
  declares (the umbrella cause of none/confusion). Always pass an explicit
  single-family allowlist.
- **Sensitive data in payload:** JWTs are signed, not encrypted; PII, session
  secrets, or internal ids in claims are readable by anyone with the token
  (base64-decode). Use JWE or keep secrets server-side.

## 8. Common false positives

- `verify` called with a pinned single-algorithm allowlist, a server-held key, and
  `audience`/`issuer` options — signature and claims are enforced.
- HMAC secret sourced from secrets management with adequate entropy (verify the
  source, not just the variable name).
- `jku`/`x5u` restricted to a hard-coded allowlist of your own hosts; `kid` mapped
  through a fixed table, not a path/query/command.
- `decode` used purely for logging/telemetry on an already-verified token, not for
  a trust decision.
- Public-key-in-repo that is only ever used with RS/ES verification pinned (no HS
  in the allowed list) — confusion is closed.

## 9. Severity & exploitability

Base **High**; **Critical** when the flaw allows forging an arbitrary identity —
`alg:none`, HS/RS confusion, `jwk`/`jku`/`kid` key control, weak secret, or
decode-without-verify on auth tokens — because it is full authentication bypass /
account takeover, effectively pre-auth. `kid` command-injection is **Critical**
(RCE). Missing `exp`/`aud`/`iss` is **High** (replay / cross-service token use).
Sensitive-data-in-payload alone is **Medium/Low** (info disclosure) unless the
leaked data enables another chain. See `references/severity-model.md`.

## 10. Remediation

Verify every token's signature with a server-held key and an explicitly pinned,
single-algorithm allowlist matching the key type; reject `alg:none`. For RSA/EC,
never accept HMAC algorithms. Use a high-entropy random HMAC secret from secrets
management. Ignore `jwk`/`jku`/`x5u` header key material (or allowlist `jku`/`x5u`
hosts) and resolve `kid` only through a fixed lookup table — never into a path, SQL
query, or command. Validate `exp`, `nbf`, `aud`, and `iss` with bounded clock skew.
Never `decode` for authorization. Keep secrets/PII out of claims (use JWE if
needed) and rotate keys.

## 11. Output

Append each confirmed finding to **`findings/22-jwt-vulnerabilities.md`** using
`references/finding-template.md`. Set `Class: JWT Vulnerabilities`, `CWE: CWE-347`
(add `CWE-345` where authenticity of data is the core issue). In **Chain
potential** name primitives such as *authentication bypass / identity forgery*
(alg:none, HS/RS confusion, decode-only → the account-takeover and
broken-access-control chains consume this to become any user/admin), *SSRF* (`jku`/
`x5u` fetch → the SSRF chain), *RCE* (`kid` command injection), *injection*
(`kid`→SQLi/path traversal, handed to those chains), and *secret leak* (sensitive
payload claims feeding other chains). Note when the finding **consumes** a leaked
public key or secret from another finding to enable forgery.

**Primitives (controlled):** provides `IDENTITY_FORGE`; consumes `SECRET_LEAK` (key confusion / leaked key)

## References
- CWE-347, CWE-345; OWASP A02:2021 Cryptographic Failures / A07:2021; OWASP JWT
  and JSON Web Token Cheat Sheets; RFC 7519 (JWT) / RFC 7515 (JWS); Auth0/PortSwigger
  guidance on algorithm confusion and `kid`/`jku` attacks.
