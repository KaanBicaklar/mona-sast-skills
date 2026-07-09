---
name: insecure-randomness
description: >-
  SAST detection methodology for insecure randomness (CWE-330, CWE-338, CWE-331),
  where security-sensitive values (session IDs, password-reset/OTP/CSRF tokens,
  API keys, coupon codes) are generated with a non-CSPRNG (Math.random,
  java.util.Random, rand, mt_rand, Python random), a predictable seed, UUIDv1, or
  insufficient entropy. Use when reviewing code that generates tokens, IDs, keys,
  or nonces. Writes confirmed findings to findings/29-insecure-randomness.md.
---

# Insecure Randomness — SAST Methodology

**Class:** Insecure Randomness · **CWE-330** · **OWASP:** A02 Cryptographic Failures
**Findings file:** `findings/29-insecure-randomness.md`

## 1. Overview

Insecure randomness exists when a value that must be **unguessable** — a token,
session ID, key, nonce, OTP, or reset code — is produced by a non-cryptographic
PRNG or with insufficient entropy, so an attacker can predict past/future outputs
or brute-force the value. General PRNGs (`Math.random`, `java.util.Random`, C
`rand`, Python `random`, PHP `mt_rand`) are statistically uniform but
**deterministic and state-recoverable**: observing a few outputs (or knowing the
seed) reveals the rest. The core test: does a value that gates security flow from a
non-CSPRNG, a predictable/time-based seed, a non-random source like UUIDv1, or too
few bits of entropy?

## 2. Where it lives

- Session/CSRF token generation; password-reset and email-verification tokens;
  OTP/2FA codes; magic-link and invitation codes.
- API key / client-secret / device-token generation; coupon/voucher/gift-card
  codes; account/order reference numbers used as capabilities.
- OAuth `state`/PKCE verifier, nonce generation; temp-file and upload names that
  must be unguessable; IV/nonce/salt generation (overlaps weak-crypto).
- Homemade "random string" / "generate token" helpers built on the language's
  default PRNG.

## 3. Sources (tainted input)

Not a taint-flow class. The signal is a **weak RNG API whose output flows into a
security-sensitive consumer**. Identify (a) the generator — a non-CSPRNG call or a
CSPRNG that was seeded predictably — and (b) the consumer — a token/ID/key/nonce
that must be unguessable. Exploitability depends on the attacker's ability to
observe prior outputs (to recover PRNG state) or to know/narrow the seed (e.g. a
`time()`-based seed the attacker can bound), and on the value's entropy/length.

## 4. Sinks (dangerous operations)

```javascript
// Node / browser — dangerous
const token = Math.random().toString(36).slice(2);        // xorshift128+, recoverable
const otp = Math.floor(Math.random() * 1000000);          // predictable 6-digit OTP
const id = Date.now() + '' + Math.random();               // time + weak PRNG
```
```java
// Java — dangerous
new Random().nextInt();                                    // 48-bit LCG, fully predictable
String t = Long.toHexString(new Random(seed).nextLong());  // known/derivable seed
UUID.randomUUID();  // OK (CSPRNG-backed) — but time-based UUIDs are NOT:
```
```python
# Python — dangerous
import random
token = ''.join(random.choice(string.ascii_letters) for _ in range(16))  # MT19937
reset = random.randint(100000, 999999)                    # predictable OTP
random.getrandbits(128)                                    # not for secrets
```
```php
// PHP — dangerous
$token = md5(uniqid());              // uniqid = microtime, low entropy, guessable
$code  = mt_rand(100000, 999999);    // Mersenne Twister, seed brute-forceable
$key   = rand();                     // very weak
```
```c
// C — dangerous
srand(time(NULL)); int t = rand();   // seed = wall clock, tiny state
```
```go
// Go — dangerous
import "math/rand"
rand.Int63()                         // deterministic; use crypto/rand for secrets
```

Dangerous whenever the generated value gates security and the generator is any of
the above rather than a CSPRNG.

## 5. Sanitizers / safe patterns

**Safe (CSPRNGs):**
- **Python:** `secrets.token_urlsafe/​token_hex/​token_bytes`, `secrets.randbelow`,
  `os.urandom`.
- **Node:** `crypto.randomBytes`, `crypto.randomUUID()`, `crypto.randomInt`,
  browser `crypto.getRandomValues`.
- **Java:** `java.security.SecureRandom` (default constructor / `getInstanceStrong`)
  — never seeded with a fixed/known value.
- **Go:** `crypto/rand` (`rand.Read`). **PHP:** `random_bytes`, `random_int`.
- **C / Linux:** `getrandom(2)` or `/dev/urandom`.
- Use **≥128 bits** of entropy for tokens/keys; for numeric OTPs, compensate short
  length with strict rate-limiting, expiry, and lockout.

**Fails / not a real sanitizer:**
- **Seeding a CSPRNG predictably** — `SecureRandom` then `setSeed(fixedValue)`, or
  seeding any PRNG with `time()`/PID/counter, collapses entropy to a guessable
  space.
- **Hashing a weak-PRNG output** — `md5(mt_rand())`, `sha1(uniqid())`: a hash of a
  predictable input is still predictable (just recover the input and re-hash).
- **CSPRNG but truncated / small space** — a strong RNG cut to 4–6 chars or a
  6-digit code without rate-limiting is brute-forceable.
- **UUIDv1 as a secret** — encodes timestamp + MAC/clock-seq, not random; guessable.
  Only random-based UUIDv4 (from a CSPRNG) is unpredictable.
- **`uniqid()` used as a token** — it is microtime with tiny entropy, even with
  `more_entropy=true`.
- **Reusing one nonce/IV** from any generator (overlaps weak-crypto).

## 6. Detection methodology

1. **Find weak generators.**
   ```
   rg -n 'Math\.random\('
   rg -n 'new Random\(|java\.util\.Random|\.nextInt\(|\.nextLong\(|\.nextDouble\('
   rg -n '\brand\(|srand\(|\bmt_rand\(|mt_srand\(|\buniqid\(|lcg_value\('
   rg -n '\brandom\.(random|randint|randrange|choice|getrandbits|sample|shuffle)\('
   rg -n 'math/rand|rand\.Int|rand\.Int63|rand\.Seed'
   rg -n 'uuid1\(|UUID\.fromString|type[ =]*1|time_low'      # time-based UUID as secret
   ```
2. **Trace the output to a consumer:** does it become a session ID, reset/OTP/CSRF
   token, API key, nonce, coupon, or unguessable filename?
3. **Check the seed:** is the PRNG seeded from `time()`/PID/a constant, or a
   CSPRNG mis-seeded via `setSeed`?
4. **Estimate the effective search space:** token length × charset, or the seed
   space the attacker can bound; and whether prior outputs are observable (state
   recovery).
5. **Confirm reachability & observability:** can an attacker request tokens and see
   outputs, or repeatedly guess (no rate limit)?
6. **Classify:** predictable secret (state/seed recovery) vs brute-forceable
   (insufficient entropy) — both are findings.

## 7. Modern & niche variants

- **`Math.random()` for tokens:** V8's `xorshift128+` internal state is fully
  recoverable from a handful of consecutive outputs, letting an attacker predict
  every subsequent token from the same context. Never for anything security-bearing.
- **`java.util.Random`:** a 48-bit linear congruential generator — the full state
  is recoverable from one or two outputs, making all future values predictable.
- **C `rand()` / predictable seed:** small internal state and typically
  `srand(time(NULL))` — the seed is the wall clock, brute-forceable in a narrow
  window.
- **PHP `rand`/`mt_rand`/`uniqid`:** `mt_rand` is a Mersenne Twister whose seed can
  be brute-forced (historically from a couple of outputs); `uniqid()` is
  microtime-derived with tiny entropy; `md5(uniqid())` reset tokens are a classic
  account-takeover bug.
- **Python `random` for secrets:** MT19937 — its entire 19937-bit state is
  recoverable from 624 consecutive 32-bit outputs, exposing all future values. Use
  `secrets`/`os.urandom` instead.
- **Predictable / time-based seeds:** any generator seeded from `time()`, PID,
  request counter, or process start time — the attacker bounds the seed and
  replays the sequence.
- **Security values from a non-CSPRNG:** session IDs, password-reset tokens, OTPs,
  CSRF tokens, API keys, and coupon codes generated with the above — the highest-
  impact case, since predicting one enables account takeover or fraud.
- **UUIDv1 as a secret:** time + MAC address (+ clock sequence) — structured and
  guessable; distinct from UUIDv4. Flag `uuid1()`/version-1 UUIDs used where
  unpredictability is required.
- **Insufficient entropy / length:** even a CSPRNG yields a weak token if truncated
  to a few characters or a short numeric OTP without rate-limiting — a brute-force
  target.

## 8. Common false positives

- Non-security randomness: shuffling display order, sampling, jitter/backoff,
  load-balancing, cache-busters, A/B bucketing, test-data generation, game
  mechanics — a fast PRNG is appropriate there.
- CSPRNG-backed generators: `crypto.randomUUID()`, `uuid4()` from a CSPRNG, Java
  `SecureRandom` (unseeded), Go `crypto/rand`, `secrets`/`random_bytes`.
- Short OTPs that are strongly rate-limited, single-use, and short-expiry — weaker
  but mitigated (note, lower severity).
- A weak-PRNG value that is combined with, or replaced by, sufficient CSPRNG
  entropy before use.

## 9. Severity & exploitability

Base **Medium**. **High** when the predicted/brute-forced value directly enables
account or session compromise — a password-reset token, session ID, API key, or
2FA/OTP code from a non-CSPRNG or with insufficient entropy. Can reach **Critical**
via chain (predict a reset token → account takeover of any user; predict admin
session IDs). Raise for pre-auth reachability, observable prior outputs, and no
rate limiting; lower for non-secret uses or well-mitigated short OTPs. See
`references/severity-model.md`.

## 10. Remediation

Generate every security-sensitive value with a CSPRNG (`secrets`,
`crypto.randomBytes`/`randomUUID`, `SecureRandom`, `crypto/rand`, `random_bytes`,
`getrandom`) and never seed it from a predictable value. Use ≥128 bits of entropy
for tokens/keys and random-based UUIDv4 rather than v1. For short numeric codes,
add strict rate-limiting, single use, and short expiry. Do not hash a weak-PRNG
output and call it random. Keep fast PRNGs strictly for non-security use.

## 11. Output

Append each confirmed finding to **`findings/29-insecure-randomness.md`** using
`references/finding-template.md`. Set `Class: Insecure Randomness` and
`CWE: CWE-330` (use `CWE-338` for use of a non-crypto PRNG in a security context,
`CWE-331` for insufficient entropy). In **Chain potential** name primitives such as
*predictable token* (reset/verify/OTP → **account takeover**, the terminal
primitive of an auth chain), *session prediction* (→ session hijack), *predictable
nonce/IV* (feeds the weak-crypto forgery chain), and *guessable capability* (coupon/
reference-number fraud). Note when the finding **consumes** an information-leak
primitive that exposes prior RNG outputs or the seed.

**Primitives (controlled):** provides `IDENTITY_FORGE`,`SECRET_LEAK` (predictable token); consumes none

## References
- CWE-330 Use of Insufficiently Random Values; CWE-338 Use of Cryptographically
  Weak PRNG; CWE-331 Insufficient Entropy; OWASP A02:2021 Cryptographic Failures;
  OWASP Testing Guide — Testing for Weak Randomness; NIST SP 800-90A/B.
