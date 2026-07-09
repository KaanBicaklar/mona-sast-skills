---
name: weak-cryptography
description: >-
  SAST detection methodology for weak / misused cryptography (CWE-327, CWE-328,
  CWE-326, CWE-780), including ECB mode, static/reused IV or nonce, MD5/SHA1 and
  fast unsalted hashing for passwords, low KDF iterations, hardcoded keys,
  CBC-without-MAC padding oracles, textbook RSA, disabled TLS verification, and
  timing-unsafe comparison. Use when reviewing code that hashes, encrypts, signs,
  or verifies. Writes confirmed findings to findings/27-weak-cryptography.md.
---

# Weak Cryptography — SAST Methodology

**Class:** Weak Cryptography · **CWE-327** · **OWASP:** A02 Cryptographic Failures
**Findings file:** `findings/27-weak-cryptography.md`

## 1. Overview

Weak cryptography is a *misuse* class, not a taint class: the flaw lives in the
choice of algorithm, mode, parameter, or protocol setting, so that a
confidentiality, integrity, or authenticity guarantee the code appears to provide
is not actually delivered. The core test: does the code use a broken primitive
(MD5/SHA1/DES/RC4), a broken mode/parameter (ECB, static/zero/reused IV or nonce,
encryption without a MAC, RSA without OAEP/PSS), a fast hash for password storage,
or a disabled/weakened verification (TLS cert/hostname checks off, non-constant-
time comparison)? Detection is pattern- and configuration-driven; confirm by
identifying what the primitive protects and whether the weakness is reachable.

## 2. Where it lives

- Password/credential storage and verification; token/session/cookie signing and
  encryption; JWT signing and verification.
- Data-at-rest encryption (PII, card data, secrets vaults) and data-in-transit
  (TLS client configuration, gRPC/DB driver TLS).
- API request signing / HMAC verification, license and DRM checks, password-reset
  and email-verification token generation.
- "Homemade" crypto utilities (`encrypt()`/`obfuscate()` helpers), and default
  library modes selected implicitly.

## 3. Sources (tainted input)

Unlike injection classes, the signal is the **cryptographic call and its
parameters**, not a request-derived value. The relevant "inputs" are the
*algorithm/mode string*, the *key*, the *IV/nonce/salt*, and the *comparison* used
to verify a secret. Attacker interaction still matters for exploitability: a
padding oracle needs the attacker to submit ciphertexts; a timing side channel
needs many verification attempts; a reused GCM nonce needs two ciphertexts under
the same key. Note whether the ciphertext/oracle/token endpoint is attacker-
reachable.

## 4. Sinks (dangerous operations)

```python
# Python — dangerous
hashlib.md5(password).hexdigest()                 # fast, unsalted, for passwords
hashlib.sha1(password + salt).hexdigest()         # fast hash ≠ password KDF
AES.new(key, AES.MODE_ECB)                         # ECB leaks plaintext structure
AES.new(key, AES.MODE_CBC, iv=b"\x00"*16)          # static/zero IV
requests.get(url, verify=False)                    # TLS cert verification disabled
ssl._create_unverified_context()
if hmac_a == hmac_b:                               # non-constant-time comparison
```
```java
// Java — dangerous
MessageDigest.getInstance("MD5");                  // or "SHA-1" for secrets
Cipher.getInstance("AES/ECB/PKCS5Padding");        // ECB
Cipher.getInstance("DES");  Cipher.getInstance("RC4");
Cipher.getInstance("RSA/ECB/PKCS1Padding");        // no OAEP (Bleichenbacher)
// TrustManager that accepts all certs / HostnameVerifier returning true
```
```javascript
// Node — dangerous
crypto.createHash('md5').update(pw).digest('hex'); // password hashing
crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16)); // zero IV
new https.Agent({ rejectUnauthorized: false });    // TLS verification off
if (tokenA === tokenB) { /* timing leak */ }
```
```go
// Go — dangerous
md5.Sum(pw); sha1.Sum(pw)
cipher.NewCBCEncrypter(block, staticIV)
&tls.Config{ InsecureSkipVerify: true }            // TLS verification off
```
```php
// PHP — dangerous
md5($password); sha1($password);                   // fast hash for passwords
openssl_encrypt($p, 'aes-256-ecb', $key);          // ECB
```

## 5. Sanitizers / safe patterns

**Safe:**
- **Passwords:** a slow, salted KDF — **argon2id** (preferred), **scrypt**,
  **bcrypt**, or **PBKDF2** with a high, tuned work factor and a per-user random
  salt. Never a raw hash.
- **Symmetric encryption:** an AEAD mode — **AES-GCM** or **ChaCha20-Poly1305** —
  with a **random 96-bit nonce that is never reused** under a key; or CBC/CTR
  **encrypt-then-MAC** with a separate MAC key and a fresh random IV per message.
- **RSA:** **OAEP** for encryption, **PSS** for signatures; never raw/PKCS#1 v1.5
  "textbook" RSA.
- **Verification:** constant-time comparison for MACs/tokens (`hmac.compare_digest`,
  `crypto.timingSafeEqual`, `MessageDigest.isEqual`, `subtle.ConstantTimeCompare`).
- **TLS:** verification **on**, hostname checks **on**, modern protocol versions
  (TLS 1.2+); pin or use the system trust store.
- **Keys/IVs/salts:** from a CSPRNG or a KMS/HSM, never constants or values derived
  from a constant.

**Fails / not a real sanitizer:**
- **A constant/global "salt"** — defeats the salt's purpose (rainbow tables,
  cross-user comparison). Salt must be per-value and random.
- **PBKDF2 with too few iterations** — a low work factor makes the KDF nearly as
  fast to brute-force as a raw hash.
- **GCM nonce reuse** — reusing a nonce under one key is catastrophic: it leaks the
  authentication key and enables forgery. A predictable counter reused across keys
  is equally broken.
- **MAC verified after the plaintext is used** (decrypt-then-check, or no MAC at
  all) — a **padding oracle** (CBC) recovers plaintext byte-by-byte.
- **Disabling verification "temporarily"** for a self-signed cert instead of
  trusting the specific CA — reintroduces MITM.
- **Deriving the IV from the key** or reusing one IV for many messages under CBC —
  a chosen-plaintext distinguisher.
- **Homemade XOR/"encryption"** and blocklisting one weak algorithm while a second
  (RC4, DES, 3DES) remains configured.

## 6. Detection methodology

1. **Find sinks:** grep for weak primitives, modes, and disabled verification.
   ```
   rg -in 'md5|sha1|\bDES\b|\bRC4\b|MODE_ECB|/ECB/|aes-256-ecb|ecb'
   rg -in 'createHash\(.?(md5|sha1)|hashlib\.(md5|sha1)|MessageDigest\.getInstance\("?(MD5|SHA-1)'
   rg -in 'verify\s*=\s*False|rejectUnauthorized:\s*false|InsecureSkipVerify|_create_unverified_context'
   rg -in 'TrustManager|HostnameVerifier|checkServerTrusted|SSLv3|TLSv1(\.0|\.1)?'
   rg -in 'RSA/ECB/PKCS1|PKCS1Padding|new SecretKeySpec\(|IvParameterSpec\('
   rg -in 'compare|==\s*hmac|==\s*token|equals\(.*(hmac|mac|token|sig)'   # timing-unsafe
   ```
2. **Confirm the misuse:** broken algorithm, ECB/static-IV mode, fast hash for
   passwords, missing OAEP/PSS, disabled TLS check, or `==` on a secret?
3. **Identify what it protects:** password store, token integrity, data at rest,
   transport — this sets impact.
4. **Trace key/IV/nonce provenance:** constant? zero? reused? derived from a
   constant? (Overlaps hardcoded-secrets.)
5. **Confirm attacker interaction where needed:** oracle-reachable ciphertext,
   many verification attempts, or two ciphertexts under one nonce.
6. **Classify:** offline crack (weak hash), plaintext/key recovery (ECB, padding
   oracle, nonce reuse, textbook RSA), MITM (TLS off), or forgery (timing/HMAC).

## 7. Modern & niche variants

- **ECB mode:** identical plaintext blocks produce identical ciphertext blocks,
  leaking structure (the "ECB penguin") and enabling cut-and-paste forgery. Any
  `MODE_ECB`/`/ECB/`/`aes-*-ecb` on structured data is a finding.
- **Static / zero / reused IV or nonce:** a fixed IV under CBC is a chosen-plaintext
  distinguisher; a **reused GCM/CTR nonce** under one key is catastrophic — GCM
  nonce reuse leaks the auth key (forgery), CTR reuse XORs two plaintexts.
- **MD5/SHA1 for passwords & fast unsalted hashing:** GPUs compute billions/sec;
  even salted SHA-256 is a fast hash. Passwords need a memory-hard/slow KDF
  (argon2id/scrypt/bcrypt/PBKDF2).
- **Too-few KDF iterations / low work factor:** correct KDF, wrong parameter —
  bcrypt cost < 10, PBKDF2 iterations in the thousands, argon2 memory too low.
- **Hardcoded / derived-from-constant keys:** an AES/HMAC key that is a string
  literal, a value derived by hashing a constant, or shipped in the binary — the
  cipher is only as secret as the source. (Cross-links hardcoded-secrets.)
- **CBC-without-MAC padding oracle (Vaudenay):** decryption reveals padding-valid
  vs -invalid (distinct error/timing) → full plaintext recovery without the key.
  Flag CBC decryption whose validity is observable and no MAC-then-decrypt.
- **RSA without OAEP / textbook RSA:** raw or PKCS#1 v1.5 encryption is
  deterministic and malleable (Bleichenbacher/Manger padding oracles); textbook
  signatures allow existential forgery. Require OAEP/PSS.
- **Weak / disabled TLS:** `InsecureSkipVerify`/`verify=False`/`rejectUnauthorized:
  false`, all-trusting `TrustManager`, no-op `HostnameVerifier`, and legacy
  protocols (SSLv3 POODLE, TLS 1.0/1.1, RC4 ciphers) — each enables MITM.
- **Homemade crypto:** custom XOR, roll-your-own stream ciphers, ad-hoc "signing"
  by hashing `secret + data` (length-extension for MD5/SHA-1/SHA-2 without HMAC).
- **Timing-unsafe HMAC/token comparison:** `==`/`equals`/`strcmp` on a MAC, API
  token, or reset token leaks equality progress via timing → forgery/brute-force.
  Use a constant-time comparator.
- **Weak DSA/ECDSA nonce:** a reused or predictable per-signature nonce `k` leaks
  the private key from two signatures (Sony PS3, Android SecureRandom bug). Flag
  any deterministic/seeded nonce not per RFC 6979.

## 8. Common false positives

- MD5/SHA1 used as a **non-security** checksum: ETag, cache key, content-address,
  dedup, or a git-style identifier — not protecting a secret.
- ECB used on a single random block or as a building block inside a proven
  construction.
- `verify=False` / `InsecureSkipVerify` confined to tests or local dev with no
  production path.
- Fast hash of a high-entropy random token (already unguessable) rather than a
  low-entropy password.
- Non-constant-time comparison of values that are not secrets.

## 9. Severity & exploitability

Base **Medium–High**. **High** for password storage with a fast/unsalted hash or
low-iteration KDF (mass offline cracking), disabled TLS verification (MITM →
credential/session theft), or a reachable padding oracle. **Critical** when the
weakness directly yields plaintext/key recovery or token forgery that grants auth
bypass — e.g. ECDSA/DSA nonce reuse recovering the signing key, GCM nonce reuse
forging an admin token, or textbook-RSA signature forgery. Raise for pre-auth /
default-config; lower for non-secret checksum misuse. See
`references/severity-model.md`.

## 10. Remediation

Replace broken primitives with vetted ones: argon2id/scrypt/bcrypt/PBKDF2 (tuned
work factor, per-user random salt) for passwords; AES-GCM or ChaCha20-Poly1305
with unique random nonces (or encrypt-then-MAC) for data; RSA-OAEP/PSS for
public-key ops. Enable TLS certificate and hostname verification and require modern
protocol versions. Use constant-time comparison for all secret/MAC checks. Source
keys, IVs, nonces, and salts from a CSPRNG or KMS/HSM — never constants. Delete
homemade crypto in favor of a standard library.

## 11. Output

Append each confirmed finding to **`findings/27-weak-cryptography.md`** using
`references/finding-template.md`. Set `Class: Weak Cryptography` and `CWE: CWE-327`
(use `CWE-328` for weak/reversible hash, `CWE-326` for inadequate key strength,
`CWE-780` for RSA without OAEP). In **Chain potential** name primitives such as
*offline password recovery* (→ credential reuse across accounts/services),
*plaintext/key recovery* (ECB, padding oracle, nonce reuse → decrypts protected
data/secrets for other chains), *token forgery* (→ auth bypass / privilege
escalation), and *MITM* (disabled TLS → consumes network position, provides
credential capture). Note when the finding **consumes** a leaked key/secret from a
hardcoded-secrets finding.

**Primitives (controlled):** provides `IDENTITY_FORGE` (forge/decrypt tokens),`SECRET_LEAK`; consumes none

## References
- CWE-327 Broken/Risky Crypto Algorithm; CWE-328 Weak Hash; CWE-326 Inadequate
  Encryption Strength; CWE-780 RSA Without OAEP; OWASP A02:2021 Cryptographic
  Failures; OWASP Cryptographic Storage and Password Storage Cheat Sheets;
  NIST SP 800-131A / 800-63B.
