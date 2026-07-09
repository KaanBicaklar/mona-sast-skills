---
name: oauth-oidc-saml-flaws
description: >-
  SAST detection methodology for federated-auth flaws in OAuth 2.0, OpenID
  Connect, and SAML (CWE-347/352/601), including missing/replayable state (login
  CSRF), missing PKCE, weak redirect_uri validation, implicit-flow token leakage,
  SAML signature wrapping (XSW) and unsigned/comment-injection assertions,
  unvalidated audience/issuer/nonce on ID tokens, confused-deputy across IdPs, and
  client_secret exposure. Use when reviewing OAuth/OIDC/SAML login and callback
  code. Writes confirmed findings to findings/23-oauth-oidc-saml-flaws.md.
---

# OAuth / OIDC / SAML Flaws — SAST Methodology

**Class:** OAuth / OIDC / SAML Flaws · **CWE-347 / CWE-352 / CWE-601** · **OWASP:** A07 Identification & Authentication Failures
**Findings file:** `findings/23-oauth-oidc-saml-flaws.md`

## 1. Overview

Federated login delegates identity to an Identity Provider (IdP), but the Relying
Party (RP) must still enforce the protocol's security invariants: bind the flow to
the user's session (`state`/PKCE/`nonce`), strictly validate where codes/tokens are
returned (`redirect_uri`), and cryptographically verify what the IdP asserts
(ID-token signature/claims, SAML assertion signature). Flaws here let an attacker
steal authorization codes/tokens, forge or replay assertions, or graft their login
onto a victim's session — usually ending in account takeover. The core tests: is
the callback bound to the initiating session and unforgeable? is `redirect_uri`
matched against an exact allowlist? are the ID token's signature, `iss`, `aud`,
`exp`, and `nonce` (and every SAML assertion's signature/conditions) verified
before trusting the identity? A "no" to any of these is a finding.

## 2. Where it lives

- OAuth/OIDC **authorization-request builders** (where `state`, `nonce`,
  `code_challenge`, `redirect_uri`, `scope` are set) and **callback/redirect
  handlers** (`/callback`, `/oauth2/callback`, `/auth/*/callback`, `/login/sso`).
- Token-exchange code (`/token` request, code→token, `client_secret` usage).
- ID-token / access-token validation (JWKS fetch, claim checks) — overlaps the JWT
  skill.
- SAML ACS (Assertion Consumer Service) endpoints and assertion parsing/signature
  verification.
- Passport/`openid-client`/`spring-security-oauth2`/`django-allauth`/`omniauth`/
  `python-social-auth`/`pysaml2`/`python3-saml`/`ruby-saml` configuration.
- IdP/client configuration: allowed redirect URIs, response types, PKCE settings,
  audiences, and stored `client_secret`s.

## 3. Sources (attacker-controlled protocol parameters)

Everything returned to the callback is attacker-influenceable: the `code`,
`state`, `id_token`/`access_token` (implicit), `error`, and — critically — the
`redirect_uri`/`RelayState` the attacker can craft in the *initial* request. In
SAML, the entire `SAMLResponse`/assertion XML is attacker-supplied and must be
signature-verified before any element is trusted. An attacker can also stand up a
**malicious IdP or client** (confused-deputy scenarios) and can present tokens
minted for a *different* audience. `client_secret` and signing keys are secrets the
attacker seeks to leak (front-end code, repos, mobile binaries).

## 4. Sinks (dangerous operations)

Dangerous = trusting a callback/assertion without binding, redirect validation, or
signature/claim verification.

```javascript
// OAuth callback — dangerous: no state check (login CSRF) + code trusted blindly
app.get('/callback', async (req, res) => {
  const { code } = req.query;                        // state never generated/compared
  const token = await exchange(code);                // attacker's code grafted onto victim session
  req.session.user = await me(token);
});
// redirect_uri — dangerous: prefix/substring match (open-redirect → code theft)
if (redirectUri.startsWith('https://app.example.com')) allow(redirectUri);
// bypass: https://app.example.com.attacker.com , https://attacker.com/#@app.example.com
```
```python
# OIDC ID token — dangerous: decode without verifying signature/aud/iss/nonce
claims = jwt.decode(id_token, options={"verify_signature": False})
user = get_or_create(claims["email"])               # forged/foreign-audience token trusted
# nonce from the auth request never compared to claims["nonce"] → replay
```
```java
// Public client (SPA/mobile) — dangerous: authorization code flow WITHOUT PKCE
authorizeUrl = base + "?response_type=code&client_id=" + id + "&redirect_uri=" + uri;
// no code_challenge/code_verifier → intercepted code is redeemable by an attacker
```
```xml
<!-- SAML ACS — dangerous: assertion consumed without verifying its signature -->
Assertion a = parse(samlResponse);                  <!-- signature not checked, or -->
verifySignature(response);                           <!-- signs response, trusts a moved/wrapped assertion -->
user = a.getSubject();                               <!-- XSW: attacker adds unsigned forged assertion -->
```
```html
<!-- Implicit flow / secret exposure — dangerous -->
response_type=token                                  <!-- access token in URL fragment, leaks via referer/history -->
const CLIENT_SECRET = "abc123";                      <!-- secret shipped to the browser / mobile app -->
```

## 5. Sanitizers / safe patterns (correct enforcement, and how it's bypassed)

**Correct enforcement:**
- **`state`:** generate a CSPRNG value per authorization request, store it bound to
  the user's session, and compare on callback (reject on mismatch/absence). Single-
  use. This is the CSRF/session-binding defense.
- **PKCE:** for every public client (and ideally all clients), send
  `code_challenge` (S256) and require the matching `code_verifier` at token
  exchange.
- **`redirect_uri`:** validate against an **exact, pre-registered allowlist** (full
  string, including path) — no prefix/substring/regex matching, no wildcards, no
  user-supplied path appended.
- **ID token (OIDC):** verify the JWS signature against the IdP JWKS with a pinned
  algorithm, then check `iss` (exact expected issuer), `aud` (equals your
  `client_id`), `exp`/`nbf`, and `nonce` (equals the one you sent). See the JWT
  skill for signature specifics.
- **SAML:** verify the XML signature over the **assertion** (not just the
  response), against the IdP's configured certificate; validate `Conditions`
  (`NotBefore`/`NotOnOrAfter`, `AudienceRestriction`), `Issuer`, `InResponseTo`,
  and `Recipient`; use a hardened parser (no DTD/XXE, canonicalization-aware,
  reject multiple/added assertions).
- **Confidential clients** keep `client_secret` server-side only; public clients
  use PKCE instead of a secret.

**Fails / commonly bypassed or missing:**
- **Missing/ignored/replayable `state`** — no CSRF binding → **login CSRF**: the
  attacker fixes the victim's account to the attacker's IdP identity, or forces
  their own code onto the victim's session (account grafting). `state` present but
  never compared, or a constant/predictable value, is equally broken.
- **No PKCE on public clients** — an intercepted authorization code (via referer,
  logs, a malicious app registered for the same URI scheme) is redeemable.
- **Weak `redirect_uri` validation** — prefix/substring/regex/wildcard matching, or
  appending user input, lets the code/token be sent to an attacker origin →
  code/token theft and account takeover. Classic open-redirect chain
  (`…example.com.evil.com`, `//evil.com`, `/redirect?url=` in the path, fragment
  `#@` tricks, missing-slash confusion).
- **Implicit flow** (`response_type=token`) — access token returned in the URL
  fragment leaks via `Referer`, browser history, and logs; deprecated in favor of
  code+PKCE.
- **ID token not verified / claims unchecked** — decode-only, or missing
  `iss`/`aud`/`exp`/`nonce`; accepting a token minted for another client (confused
  deputy) or a foreign/attacker IdP.
- **SAML signature wrapping (XSW)** — the parser verifies a signature but then reads
  a *different*, unsigned assertion the attacker injected elsewhere in the document
  (signature over one node, trust of another). Also **unsigned assertions**
  accepted, or **XML comment injection** splitting a signed value (e.g.
  `admin<!---->@evil.com` parsed as `admin@…`) to impersonate another user; plus
  XXE in the parser.
- **Nonce not validated (OIDC)** — enables ID-token replay.
- **Confused deputy across IdPs / multi-tenant** — the RP doesn't bind the token's
  issuer/tenant to the expected one, so a token from IdP-B or tenant-B is accepted
  for tenant-A.
- **`client_secret` exposure** — secret embedded in SPA/mobile/front-end code or
  committed to a repo, allowing token requests and impersonation of the client.

## 6. Detection methodology

1. **Locate the flow endpoints and library config.**
   ```
   rg -n '/callback|oauth2?/callback|/auth/.*/callback|/login/sso|acs|SAMLResponse|RelayState|passport|openid-client|omniauth|allauth|pysaml2|python3-saml|ruby-saml'
   ```
2. **state — generated, stored, compared?**
   ```
   rg -n '\bstate\b' | rg -n 'random|csrf|session|compare|==|!=|verify'
   rg -n 'req\.query\.code|params\[:code\]|authorization_code'   # then check a state check exists near it
   ```
   A callback that consumes `code` with no `state` comparison is the finding.
3. **PKCE presence (esp. public clients).**
   ```
   rg -n 'code_challenge|code_verifier|pkce|S256'
   ```
   Absence in an SPA/mobile/public-client config is the finding.
4. **redirect_uri validation quality.**
   ```
   rg -n 'redirect_uri|redirectUri|reply_url|returnTo|RelayState'
   rg -n 'startsWith|indexOf|contains|matches\(|RegExp|\.test\(|wildcard|\*'
   ```
   Any prefix/substring/regex/wildcard match on the redirect target → flag.
5. **ID-token verification & claims.**
   ```
   rg -n 'id_token|verify_signature|audience|aud\b|issuer|iss\b|nonce|verify_aud|verify_iss'
   ```
6. **Implicit flow / secret exposure.**
   ```
   rg -n 'response_type=token|response_type=.*token|grant_type=implicit'
   rg -n 'client_secret|clientSecret|CLIENT_SECRET' --glob '!**/server/**'   # secret in front-end paths
   ```
7. **SAML signature & parser hardening.**
   ```
   rg -n 'verifySignature|validateSignature|assertion|Assertion|wantAssertionsSigned|wantMessagesSigned|Conditions|AudienceRestriction|InResponseTo|DTD|resolveEntities|comment'
   ```
   Response-only signature check (not assertion), `wantAssertionsSigned=false`, or a
   parser with DTD/entity resolution enabled → flag.
8. **Confirm reachability & flow type:** which grant/response type, public vs
   confidential client, and does success set the session identity (account-takeover
   surface)?

## 7. Modern & niche variants

- **Missing/replayable/non-bound `state` (login CSRF):** the RP doesn't tie the
  callback to the initiating session. Attacker completes a flow with *their* IdP
  identity and delivers the callback to the victim (session grafting), or omits the
  CSRF binding entirely so a forged callback links accounts. Any callback that
  redeems `code` without a stored-and-compared `state` qualifies.
- **PKCE missing on public clients:** SPAs/mobile apps using the code flow without
  `code_challenge`/`code_verifier`. An authorization code intercepted (custom-URI-
  scheme hijack, referer, logs, a sibling app) is redeemable by the attacker. PKCE
  binds the code to the client that started the flow.
- **Weak `redirect_uri` validation → code/token theft:** prefix/substring/regex/
  wildcard matching or appended user input send the code/token to an attacker
  origin. **Chains with open redirect** — an open redirect on an allowlisted host
  bounces the code out. Bypass patterns: `app.example.com.evil.com`, `//evil.com`,
  `https://app.example.com@evil.com`, path/fragment `#@`, and missing-trailing-slash
  confusion. End state: account takeover.
- **Implicit-flow token leakage:** `response_type=token` puts the access token in
  the URL fragment, exposed via `Referer`, history, proxies, and logs. Deprecated;
  migrate to code+PKCE.
- **SAML signature wrapping (XSW):** the attacker restructures the XML so the
  library validates the signature over the original (moved/hidden) assertion but the
  application reads an injected, **unsigned** assertion with forged identity. Also
  **unsigned assertions accepted** (`wantAssertionsSigned=false`) and **comment
  injection** — an XML comment splits a signed attribute
  (`admin<!---->@example.com`) so the app reads a different value than was signed,
  impersonating another user. Watch for response-level-only signature checks and
  weak/XXE-prone parsers.
- **Audience/issuer/nonce not validated on ID tokens:** accepting a token whose
  `aud` isn't your `client_id` (confused deputy), whose `iss` is unexpected, or
  without a `nonce` match (replay). Frequent when ID tokens are `decode`d for
  `email`/`sub` without full verification (see the JWT skill).
- **Confused deputy across IdPs / tenants:** the RP trusts *any* configured IdP or
  tenant equally and doesn't bind the resulting identity to the tenant that started
  the flow, so a token from IdP-B/tenant-B is honored for tenant-A.
- **`client_secret` exposure:** secret shipped in SPA/mobile/front-end bundles or
  committed, letting an attacker impersonate the client during token exchange. Public
  clients must use PKCE, not an embedded secret.

## 8. Common false positives

- `state` generated with CSPRNG, stored in the session, compared on callback, and
  single-use — CSRF binding is intact.
- Exact-match `redirect_uri` against a hard-coded/registered allowlist (full
  string) with no user-supplied path.
- ID token verified against JWKS with pinned algorithm and `iss`/`aud`/`exp`/`nonce`
  checked; SAML assertion signature verified against the configured cert with
  `Conditions`/`AudienceRestriction`/`InResponseTo` validated.
- PKCE present, or the client is genuinely confidential (server-side) with the
  secret never leaving the backend.
- Library defaults known-safe and not overridden (e.g. `wantAssertionsSigned`
  left true) — verify the config isn't disabling the check.

## 9. Severity & exploitability

Base **High**; **Critical** when the flaw yields account takeover — weak
`redirect_uri` (code/token theft), SAML XSW/unsigned-assertion/comment-injection
identity forgery, unverified ID-token audience/issuer, or login-CSRF account
grafting — especially pre-auth and in default config. Missing PKCE and
implicit-flow leakage are **High** (conditional on interception). `client_secret`
exposure is **High** on its own and a force-multiplier in a chain. Login CSRF
without a further pivot may be **Medium**, but rises to **Critical** as the chain's
terminal takeover. Open-redirect + `redirect_uri` is the canonical chain uplift in
`references/severity-model.md`.

## 10. Remediation

Generate, store, and compare a per-request CSPRNG `state`; require PKCE (S256) for
all public clients. Validate `redirect_uri`/ACS URLs against an exact pre-registered
allowlist — never prefix/substring/regex/wildcard. Use the authorization-code flow,
not implicit. Verify ID tokens fully (signature via JWKS, pinned alg, `iss`, `aud`,
`exp`, `nonce`). For SAML, verify the signature over each **assertion** against the
configured IdP cert, require signed assertions, validate `Conditions`/audience/
`InResponseTo`/`Recipient`, and harden the XML parser against XSW/XXE/comment
injection. Keep `client_secret`s server-side. Bind identities to the expected
issuer/tenant.

## 11. Output

Append each confirmed finding to **`findings/23-oauth-oidc-saml-flaws.md`** using
`references/finding-template.md`. Set `Class: OAuth / OIDC / SAML Flaws` and the
fitting `CWE` (`CWE-352` for missing-`state` login CSRF, `CWE-601` for weak
`redirect_uri`/open-redirect, `CWE-347` for signature/assertion verification
failures). In **Chain potential** name primitives such as *account takeover*
(redirect_uri theft, XSW/unsigned assertion, ID-token forgery, login-CSRF grafting —
the terminal impact of these chains), *authorization-code/token theft*, *identity
forgery* (SAML/OIDC), and *client impersonation* (`client_secret` leak). Explicitly
note that this class **consumes** an *open-redirect* primitive (from the
open-redirect/SSRF findings) to weaponize weak `redirect_uri` validation, and
**consumes** JWT-verification flaws (from findings/22) for ID-token forgery — record
the candidate chain IDs.

**Primitives (controlled):** provides `IDENTITY_FORGE`; consumes `URL_CONTROL`,`SECRET_LEAK`

## References
- CWE-347, CWE-352, CWE-601; OWASP A07:2021 Identification & Authentication
  Failures; OAuth 2.0 Security BCP (RFC 9700), RFC 6749/6819, OpenID Connect Core;
  OWASP SAML Security Cheat Sheet; research on OAuth `redirect_uri` theft and SAML
  XSW / comment-injection.
