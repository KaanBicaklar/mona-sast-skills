---
name: hardcoded-secrets
description: >-
  SAST detection methodology for hardcoded / embedded secrets (CWE-798, CWE-259,
  CWE-321), including API keys, passwords, private keys, tokens and cloud
  credentials in source, git history, committed .env, CI config, and shipped
  mobile/front-end bundles, plus high-entropy and default-credential detection.
  Use when reviewing source, config, or build artifacts for embedded secrets.
  Writes confirmed findings to findings/28-hardcoded-secrets.md.
---

# Hardcoded Secrets — SAST Methodology

**Class:** Hardcoded Secrets · **CWE-798** · **OWASP:** A07 Identification & Authentication Failures
**Findings file:** `findings/28-hardcoded-secrets.md`

## 1. Overview

A hardcoded-secret flaw exists when a credential — password, API key, private key,
signing key, token, or connection string — is embedded in source, configuration,
build artifacts, or version-control history rather than injected from a secure
secret store at runtime. The secret is then readable by anyone with repo, artifact,
or client-bundle access, and cannot be rotated without a code change. The core
test: is there a literal (or trivially-derived) credential value in the tree or its
history, and does it grant access to a real system? Detection is signature- and
entropy-driven; confirm by classifying the secret type and its blast radius.

## 2. Where it lives

- Source literals: `password = "..."`, `apiKey = "..."`, `SECRET_KEY = "..."`,
  connection strings, and inline `Authorization: Bearer ...` headers.
- Config and env files committed to the repo: `.env`, `application.properties`,
  `settings.py`, `appsettings.json`, `config.yml`, Terraform `.tfvars`, k8s
  manifests/Secrets (base64 is *not* encryption).
- **Git history** — a secret removed in HEAD but still present in an earlier commit;
  and stale branches/tags.
- CI/CD config and logs: GitHub Actions, GitLab CI, Jenkinsfiles, Dockerfiles
  (`ENV`/`ARG` secrets), and echoed pipeline variables.
- **Client-shipped artifacts:** mobile app bundles (APK/IPA strings), front-end JS
  bundles/source maps, and desktop binaries — anything the attacker can download.
- Test fixtures and seed data that reuse real credentials.

## 3. Sources (tainted input)

This is not a taint-flow class — the "source" is the **repository, its history,
and its build artifacts**. The signal is a string that *looks like* and *functions
as* a credential: a known-format token (provider-prefixed), a private-key PEM
block, a URL with embedded userinfo, or a high-entropy blob assigned to a
secret-named identifier. Exploitability depends on whether the secret is live and
what it authorizes — so classify the provider and scope.

## 4. Sinks (dangerous operations)

Here the "sink" is any place a literal credential is written or used directly.

```python
# Python — dangerous
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgres://admin:S3cr3t!@db.internal:5432/app"   # creds in DSN
django SECRET_KEY = "django-insecure-8f3k...9d"                  # signing key literal
```
```javascript
// Node / front-end — dangerous
const stripe = new Stripe("sk_live_51H8x... ");   // LIVE secret key in bundle
const JWT_SECRET = "supersecret123";               // token signing key literal
fetch(url, { headers: { Authorization: "Bearer ghp_16C7e..." }}); // PAT in source
```
```java
// Java — dangerous
String password = "P@ssw0rd!";                     // default/admin credential
private static final String API_KEY = "AIzaSyD...";// GCP API key literal
```
```yaml
// CI / config — dangerous
env:
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE          # cloud cred in pipeline config
  SLACK_TOKEN: xoxb-2401...-...                     # bot token committed
```
```text
-----BEGIN RSA PRIVATE KEY-----                     # private key committed to repo
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
```

## 5. Sanitizers / safe patterns

**Safe:**
- Load secrets at runtime from a **secret manager** (Vault, AWS/GCP/Azure secret
  managers, sealed KMS) or from environment variables injected by the platform —
  not committed to the repo.
- Keep `.env`/secret files **git-ignored**; commit only `.env.example` with
  placeholder values.
- Use short-lived, scoped credentials (OIDC-federated CI, instance roles) instead
  of long-lived static keys.
- Run a secret scanner in pre-commit and CI (gitleaks/trufflehog) and enable
  provider push-protection; rotate on any exposure.
- For client apps, treat anything shipped as public — use per-user tokens minted
  server-side, never an embedded master key.

**Fails / not a real sanitizer:**
- **Base64 / hex / ROT / XOR "obfuscation"** — trivially reversible; the secret is
  still present.
- **Removing the secret in HEAD but not from history** — `git log`/`git show` on
  earlier commits still exposes it; the credential must be **rotated**, not just
  deleted.
- **`.gitignore` added after the file was already committed** — the tracked copy
  remains.
- **Splitting the secret across constants / building it at runtime from pieces** —
  reassembly is mechanical; entropy is still in the binary.
- **"Internal only" / low-value assumptions** — assume the repo and artifacts leak;
  scope and rotate anyway.
- **Public/publishable keys treated as secret (or vice versa)** — distinguish a
  Stripe `pk_` (public) from `sk_`/`rk_` (secret); flag the latter.

## 6. Detection methodology

1. **Scan for provider-formatted tokens and key material.**
   ```
   rg -n 'AKIA[0-9A-Z]{16}'                                   # AWS access key id
   rg -n 'ASIA[0-9A-Z]{16}'                                   # AWS temporary key id
   rg -n 'AIza[0-9A-Za-z_\-]{35}'                             # Google API key
   rg -n 'gh[pousr]_[0-9A-Za-z]{36}'                          # GitHub tokens
   rg -n 'sk_live_[0-9A-Za-z]{24,}|rk_live_[0-9A-Za-z]{24,}'  # Stripe secret keys
   rg -n 'xox[baprs]-[0-9A-Za-z-]{10,}'                       # Slack tokens
   rg -n 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.'        # JWTs
   rg -n 'BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY'    # private key blocks
   rg -n '(?i)(password|passwd|pwd|secret|api[_-]?key|token|client[_-]?secret)\s*[:=]\s*["'"'"'][^"'"'"']{6,}'
   rg -n '(?i)(postgres|mysql|mongodb|redis|amqp)://[^ \n"'"'"']*:[^@/ ]+@'  # creds in DSN
   ```
2. **Scan git history and untracked artifacts:** `git log -p`, `git grep` across
   refs, and grep built bundles / `.map` files / decompiled mobile strings.
3. **Confirm it is a real credential:** provider format match, PEM block, or a
   high-entropy string (≈ ≥3.5 bits/char over 20+ chars) assigned to a
   secret-named identifier — not a placeholder (`changeme`, `xxxx`, `example`,
   `<...>`).
4. **Classify scope:** what does it authorize (cloud account, DB, third-party API,
   token signing)? Is it `live`/production vs test/sandbox?
5. **Check for genuine externalization:** is the value actually loaded from env/
   secret manager, or is the literal the real value (fallback default is still a
   finding)?
6. **Determine live/rotated status:** present in history requires rotation
   regardless of HEAD.

## 7. Modern & niche variants

- **API keys / passwords / private keys / tokens in source:** the base case —
  literals assigned to secret-named identifiers, `Authorization` headers, or PEM
  blocks committed directly.
- **Secrets in git history / committed `.env`:** removed from HEAD but alive in an
  earlier commit, a reverted change, or a stale branch. `.env` files committed
  before being git-ignored. History exposure means the secret is compromised and
  must be rotated, not merely deleted.
- **Secrets in CI config:** hardcoded `env:`/`ARG` values in GitHub Actions,
  GitLab CI, Jenkinsfiles, and Dockerfiles; secrets echoed into build logs.
- **Cloud credentials:** AWS `AKIA…`/`ASIA…` access keys (often paired with a
  secret key literal), **GCP service-account JSON** (`"type":
  "service_account","private_key": "-----BEGIN PRIVATE KEY-----…"`), and **Azure
  connection strings** (`DefaultEndpointsProtocol=…;AccountKey=…`) — each grants
  broad account access.
- **JWT signing keys:** an HMAC secret or private key used to sign tokens; leaking
  it lets an attacker forge arbitrary tokens (auth bypass / privilege escalation —
  chains into weak-crypto/authz).
- **DB connection strings:** DSNs with inline `user:password@host`, giving direct
  database access.
- **High-entropy string detection:** catch unknown-format secrets by Shannon
  entropy on values assigned to secret-named keys or long base64/hex blobs, to
  cover custom tokens not matched by a provider regex.
- **Default credentials:** shipped admin/admin, `root`/empty, or framework default
  keys (e.g. a placeholder `SECRET_KEY` left unchanged) — CWE-259/1188.
- **Secrets in mobile / front-end bundles:** keys embedded in APK/IPA or JS
  bundles/source maps are effectively public — extract via `strings`/unzip or by
  reading the shipped JS. Anything client-side is not a secret; flag master/API
  keys embedded there.

## 8. Common false positives

- Placeholders and templates: `changeme`, `your-api-key-here`, `<TOKEN>`,
  `example`, values in `.env.example` / documentation.
- **Public** keys/identifiers intentionally shipped: Stripe `pk_`, publishable
  client IDs, public certificate/PEM *public* keys, OAuth client IDs.
- Test fixtures using well-known dummy values (e.g. AWS `AKIAIOSFODNN7EXAMPLE`) —
  still note if a real-looking secret sits beside it.
- High-entropy strings that are hashes, UUIDs, content digests, or minified code —
  not credentials.
- A literal that is only a **fallback default** overridden in every real
  environment — lower confidence, but flag if it is a working default.

## 9. Severity & exploitability

Base **High** for a live credential in source or history. **Critical** when it
grants broad or privileged access — cloud account keys (AWS/GCP/Azure), a JWT/
token signing key (forge any session), a production DB DSN, or a root private key —
or when the repo/artifact is public. Lower to **Medium/Low** for sandbox/test-only
keys, revoked/expired credentials, or values confined to a private repo behind
strict access with a rotation path. A secret in **client-shipped artifacts** is
always at least High (publicly extractable). See `references/severity-model.md`.

## 10. Remediation

Rotate the exposed credential immediately — deletion alone does not remediate a
secret that reached history or a shipped artifact. Move secrets to a secret
manager or platform-injected environment variables; commit only placeholder
`.env.example` files and git-ignore real ones. Prefer short-lived, scoped
credentials (OIDC/instance roles) over static keys. Purge history where feasible,
enable pre-commit/CI secret scanning with push protection, and never embed
master/API keys in mobile or front-end bundles — mint per-user tokens server-side.

## 11. Output

Append each confirmed finding to **`findings/28-hardcoded-secrets.md`** using
`references/finding-template.md`. Set `Class: Hardcoded Secrets` and `CWE: CWE-798`
(use `CWE-259` for hardcoded password, `CWE-321` for hardcoded crypto key). In
**Chain potential** name primitives such as *leaked credentials* (the canonical
chain feeder — provides access consumed by SSRF-metadata, lateral-movement, and
authz chains), *token-signing key* (→ auth bypass / privilege escalation, feeds
the weak-crypto forgery chain), and *direct data access* (DB DSN → read/write).
Note when the finding **consumes** a leak primitive from another finding (SSRF/
path-traversal/LFI exposing this secret).

**Primitives (controlled):** provides `SECRET_LEAK`; consumes none

## References
- CWE-798 Use of Hard-coded Credentials; CWE-259 Hard-coded Password; CWE-321
  Hard-coded Cryptographic Key; OWASP A07:2021 Identification and Authentication
  Failures and A05:2021 Security Misconfiguration; OWASP Secrets Management Cheat
  Sheet; provider token-format references (AWS, GCP, GitHub, Stripe, Slack).
