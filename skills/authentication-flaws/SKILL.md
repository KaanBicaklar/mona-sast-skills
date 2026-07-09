---
name: authentication-flaws
description: >-
  SAST detection methodology for authentication failures (CWE-287/640/307/620),
  including insecure password reset (predictable/non-expiring tokens, host-header
  poisoning, token in referer), user enumeration, missing rate-limiting/account
  lockout, MFA bypass, auth race conditions, insecure "remember me",
  non-constant-time credential comparison, and default/weak credentials. Use when
  reviewing login, registration, password-reset, and MFA flows. Writes confirmed
  findings to findings/21-authentication-flaws.md.
---

# Authentication Flaws — SAST Methodology

**Class:** Authentication Flaws · **CWE-287 / CWE-640 / CWE-307 / CWE-620** · **OWASP:** A07 Identification & Authentication Failures
**Findings file:** `findings/21-authentication-flaws.md`

## 1. Overview

Authentication flaws are failures in *proving who the caller is* and in the
supporting flows (registration, password reset, MFA, "remember me"). These are
rarely a single tainted-string sink; they are **missing or weak guarantees**:
tokens that are guessable or never expire, comparisons that leak or aren't
constant-time, verification steps that can be skipped, and endpoints with no
brute-force protection. The core tests: (1) can an attacker *obtain or reset*
someone's credentials without proving identity? (2) can they *guess* credentials
or codes because nothing rate-limits or locks the account? (3) can any required
step (MFA, email verification) be *skipped or replayed*? Model each auth flow as a
state machine and look for a transition that reaches "authenticated" without every
guard.

## 2. Where it lives

- Login handlers, registration, and session/token issuance.
- Password-reset flows: token generation, the reset link/email, token
  verification, and the set-new-password step.
- MFA/2FA: OTP/TOTP verification, backup-code check, the "MFA required" gate, and
  the step that marks a session fully authenticated.
- Credential comparison utilities and password hashing config.
- "Remember me" / persistent-login token issuance and validation.
- Rate-limiting / lockout middleware (or its absence) around the above.
- Account-recovery, email-change, and "verify email" endpoints (adjacent to auth).

## 3. Sources (attacker-controlled identifiers/tokens/secrets)

Login credentials (username, password), password-reset tokens, OTP/backup codes,
"remember me" cookies, the `Host`/`X-Forwarded-Host` header (poisons reset
links), the `Referer` (leaks tokens to third parties), and any user identifier
submitted to a recovery flow. Treat all of these as attacker-chosen and
**high-volume** — the attacker can submit millions of guesses unless something
stops them. The attacker also controls *timing* and *ordering* of requests (race
conditions) and can *tamper with responses/redirects* in a client-side MFA gate.

## 4. Sinks (dangerous operations)

Dangerous = a step that grants authentication, issues a recovery token, or
compares a secret, without the corresponding guard.

```python
# Password reset — dangerous: predictable / non-expiring token
token = str(random.randint(100000, 999999))        # guessable, not CSPRNG
token = md5(user.email).hexdigest()                 # deterministic → forgeable
reset = PasswordReset(user=u, token=token)          # no expires_at set
# Host-header poisoning of the reset link — dangerous
link = f"https://{request.headers['Host']}/reset?token={token}"  # attacker sets Host
send_email(u.email, link)                           # link now points to attacker host
```
```javascript
// Login — dangerous: non-constant-time compare + user enumeration
if (user == null) return res.status(404).send("No such user");     // enumeration
if (user.password === req.body.password) { login(user); }          // == leaks + plaintext
// No rate limit / lockout anywhere around this handler → credential stuffing
```
```java
// Credential compare — dangerous: early-exit string equality (timing oracle)
if (storedHash.equals(providedHash)) { authenticate(); }  // not constant-time
// MFA gate — dangerous: verification step skippable / response-tamperable
if (user.mfaEnabled && !otpValid) { /* only warns, still proceeds */ }
```
```python
# MFA / OTP — dangerous: unlimited attempts, code not invalidated
if request.form["otp"] == session["otp"]:           # brute-forceable 6 digits
    mark_authenticated()                            # no attempt counter, no expiry
```
```javascript
// "Remember me" — dangerous: predictable persistent token
res.cookie('remember', base64(userId + ':' + username));  // forgeable, no secret/HMAC
```

## 5. Sanitizers / safe patterns (correct enforcement, and how it's bypassed)

**Correct enforcement:**
- **Reset tokens:** ≥128-bit CSPRNG (`secrets.token_urlsafe`, `crypto.randomBytes`),
  single-use, short TTL, stored hashed, invalidated on use and on password change.
- **Reset link host:** build absolute URLs from a **server-configured** base URL,
  never from the `Host`/`X-Forwarded-Host` header; use `Referrer-Policy:
  no-referrer` on reset pages and keep the token out of the URL where possible.
- **Uniform responses:** identical message, status, and (as far as practical)
  timing for "user not found" vs "wrong password" and for existing vs non-existing
  accounts in registration/recovery.
- **Rate limiting + lockout:** per-account and per-IP throttling, exponential
  backoff, CAPTCHA, and temporary lockout on repeated failures (login, reset, OTP).
- **Constant-time comparison** for tokens/codes/hashes
  (`hmac.compare_digest`, `crypto.timingSafeEqual`, `MessageDigest.isEqual`), and a
  strong slow password hash (bcrypt/scrypt/Argon2), never `==`/`equals` on secrets.
- **MFA:** enforce server-side that the second factor is verified before the
  session is elevated; OTPs are single-use, short-TTL, attempt-limited; backup
  codes are hashed and rate-limited.
- **"Remember me":** unpredictable server-side token (random selector + hashed
  validator), rotated on use, revocable, bound to the user.

**Fails / commonly bypassed or missing:**
- **Token entropy/lifetime:** `Math.random`/`rand`/timestamp/sequential/hashed-PII
  tokens are guessable; tokens with no expiry or reusable after use.
- **Host-header trust:** reset link built from the request Host → attacker
  receives the victim's token when the victim clicks.
- **Referer leakage:** token in the URL leaks to analytics/third-party scripts via
  `Referer`.
- **Enumeration:** different message/status/redirect/timing for valid vs invalid
  users; register endpoint saying "email already taken"; reset saying "no such
  user".
- **No/weak rate limiting:** absent entirely, only client-side, only per-IP (defeated
  by rotating IPs), or reset by changing case/whitespace in the username.
- **Non-constant-time compare / plaintext or fast-hash passwords** (MD5/SHA-1, no
  salt).
- **MFA skippable:** the "verify OTP" step is a client-side redirect the attacker
  skips; unlimited OTP guesses; backup codes brute-forceable; response tampering
  (`{"mfa":"required"}`→`"success"`); the pre-MFA session already fully privileged.
- **Race conditions:** concurrent requests double-spend a one-time token, register
  duplicate accounts, or elevate before the guard commits (TOCTOU).
- **Insecure "remember me":** cookie is `userId`/`username` (forgeable), not
  HMAC'd, never expires, or not invalidated on password change/logout.
- **Default/weak credentials:** seeded `admin/admin`, hard-coded fallback
  passwords, or a debug bypass account.

## 6. Detection methodology

1. **Locate the flows.**
   ```
   rg -n 'reset[_-]?password|forgot[_-]?password|password[_-]?reset|verify[_-]?email|/login|signin|authenticate|def login|otp|mfa|2fa|totp|remember[_-]?me'
   ```
2. **Reset-token generation — check entropy, expiry, single-use, storage.**
   ```
   rg -n 'random\.(randint|random)|Math\.random|rand\(|uuid1\(|md5\(|sha1\(|token\s*=\s*str\('
   rg -n 'expires?_?at|expiry|ttl|used\b|invalidate|single.?use'   # absence is the flaw
   ```
3. **Host-header / referer in links & redirects.**
   ```
   rg -n "headers\[.[Hh]ost.\]|X-Forwarded-Host|request\.host|getHeader\(.Host.\)"
   ```
4. **Credential/token comparison — constant-time & hashing.**
   ```
   rg -n 'password\s*===?|\.equals\(.*(password|token|otp)|==\s*.*token|compare_digest|timingSafeEqual|isEqual\('
   rg -n 'md5|sha1|MessageDigest\.getInstance\(.MD5|bcrypt|scrypt|argon2|pbkdf2'
   ```
5. **Rate limiting / lockout presence around auth handlers.**
   ```
   rg -n 'rate.?limit|ratelimit|throttle|Bucket4j|express-rate-limit|AllowedAttempts|lockout|failed_attempts|captcha'
   ```
6. **Enumeration:** compare error branches in login/register/reset — do "not
   found" and "wrong password" differ in message, status, or early-return timing?
7. **MFA state machine:** find where the session is marked authenticated and verify
   the OTP/backup-code check *must* run first, is attempt-limited, single-use, and
   enforced server-side (not a client redirect / response flag).
8. **"Remember me" & defaults:** inspect persistent-cookie contents and grep for
   seeded/hard-coded credentials.
   ```
   rg -n 'remember|persistent.?login|admin.*password\s*=|password\s*=\s*.(admin|password|changeme|123456)'
   ```

## 7. Modern & niche variants

- **Insecure password reset:** predictable token (non-CSPRNG, sequential,
  timestamp, hashed email), token that never expires or is reusable, or token
  reflected/logged. Plus two link-delivery bugs — **host-header poisoning**
  (link built from attacker-controlled `Host`/`X-Forwarded-Host`, so the victim's
  click sends the token to the attacker's server) and **referer leakage** (token
  in the URL leaks via `Referer` to third-party scripts). Account takeover with no
  prior access.
- **User enumeration:** login/register/reset reveal account existence via message
  ("no such user" vs "wrong password"), HTTP status, redirect target, or
  **response-time differences** (bcrypt runs only for real users → timing oracle).
  Feeds targeted credential stuffing.
- **Missing rate-limiting / account lockout:** no throttle or lockout on login,
  reset, or OTP → credential stuffing and brute force. Watch for client-only
  limits, per-IP-only limits (rotating proxies defeat them), and limits bypassed
  by altering username case/whitespace.
- **MFA bypass:** (a) skip the verification step — the second-factor page is a
  client redirect the attacker omits and lands authenticated; (b) brute the OTP or
  backup code because attempts aren't limited/codes aren't single-use (6 digits =
  10^6, trivially brute-forced without a counter); (c) response tampering — flip
  `{"mfaRequired":true}`/status to success; (d) the pre-MFA session already carries
  full privileges.
- **Authentication race conditions:** concurrent requests exploit TOCTOU — reuse a
  one-time reset/OTP token before it's marked used, create duplicate/again-privileged
  accounts, or pass a check that hasn't yet committed. Look for read-check-then-write
  without a lock/atomic update.
- **Insecure "remember me":** persistent cookie contains a forgeable identity
  (`userId:username`, base64, no HMAC), never expires, isn't rotated, or survives
  password change/logout — a long-lived bypass of the whole login flow.
- **Non-constant-time credential comparison:** `==`/`.equals`/`===` on tokens,
  OTPs, HMACs, or password hashes leaks a timing side channel; also plaintext or
  fast-hash (MD5/SHA-1, unsalted) password storage.
- **Default / weak credentials:** seeded admin accounts, hard-coded fallback or
  debug-bypass passwords, or environments shipped with `admin/admin`.

## 8. Common false positives

- Reset token is CSPRNG, single-use, short-TTL, stored hashed, invalidated on use —
  even if it looks "random-ish" at the call site, verify the generator and lifecycle.
- Links/redirects built from a configured base URL, not the request Host.
- Uniform error responses and constant-time comparisons already in place.
- Rate limiting/lockout enforced by a gateway/WAF or middleware confirmed to wrap
  the handler (not visible in the handler body itself).
- MFA enforced server-side with attempt limits; the client redirect is cosmetic
  over a server gate.
- `Math.random`/`==` used on **non-security** values in the same file (don't flag
  comparisons that aren't secrets).

## 9. Severity & exploitability

Base **High**; **Critical** for full account takeover with no prior access — e.g.
predictable/host-poisoned reset token, MFA fully bypassable, or default admin
credentials — especially pre-auth and in default config. User enumeration and
missing rate-limiting are typically **Medium** standalone but **High/Critical** as
the enabling link in a credential-stuffing or reset chain. Timing-only oracles and
weak "remember me" scale with what they unlock. Apply modifiers per
`references/severity-model.md`; remember chain severity = the impact at the end of
the chain.

## 10. Remediation

Generate recovery tokens with a CSPRNG (≥128-bit), single-use, short-lived, stored
hashed, and invalidated on use and password change. Build reset/verification URLs
from a server-configured base URL and never from request headers; set
`Referrer-Policy: no-referrer`. Return uniform messages/statuses and use
constant-time comparisons; store passwords with bcrypt/scrypt/Argon2. Enforce
per-account and per-IP rate limiting plus lockout/backoff on login, reset, and OTP.
Enforce MFA server-side with single-use, attempt-limited codes and no skippable
client step. Make persistent-login tokens random, rotated, revocable, and bound to
the user. Remove default/hard-coded credentials.

## 11. Output

Append each confirmed finding to **`findings/21-authentication-flaws.md`** using
`references/finding-template.md`. Set `Class: Authentication Flaws` and the fitting
`CWE` (`CWE-640` weak reset, `CWE-307` improper restriction of excessive attempts,
`CWE-620` unverified password change, `CWE-287` general improper authentication).
In **Chain potential** name primitives such as *account takeover* (predictable/
host-poisoned reset, MFA bypass → the highest-value primitive many chains
terminate in), *credential guessing enabler* (enumeration + no rate limit, which
downstream brute-force consumes), *auth bypass* (default creds / race), and *token
leak* (referer/host poisoning). Note where the finding **consumes** another —
e.g. an open-redirect or host-header finding feeding reset-link poisoning, or a
leaked username from an info-leak finding feeding enumeration.

**Primitives (controlled):** provides `IDENTITY_FORGE`,`AUTHZ_BYPASS`; consumes `SECRET_LEAK` (host-header reset)

## References
- CWE-287, CWE-640, CWE-307, CWE-620; OWASP A07:2021 Identification &
  Authentication Failures; OWASP Authentication, Forgot-Password, and
  Credential-Stuffing Prevention Cheat Sheets; OWASP WSTG (Authentication Testing).
