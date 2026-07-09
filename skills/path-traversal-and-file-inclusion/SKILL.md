---
name: path-traversal-and-file-inclusion
description: >-
  SAST detection methodology for path traversal and file inclusion (CWE-22,
  CWE-98, CWE-73), including ../ traversal, absolute-path override, encoded/
  double-encoded/Unicode/null-byte bypasses, LFI→RCE via PHP wrappers and log
  poisoning, RFI, zip slip, symlink following, and unconfined sendFile. Use when
  reviewing code that opens, serves, includes, or extracts a file whose path is
  influenced by input. Writes findings to findings/25-path-traversal-and-file-inclusion.md.
---

# Path Traversal & File Inclusion — SAST Methodology

**Class:** Path Traversal / File Inclusion · **CWE-22** · **OWASP:** A01 Broken Access Control
**Findings file:** `findings/25-path-traversal-and-file-inclusion.md`

## 1. Overview

Path traversal (CWE-22) occurs when attacker-controlled data reaches a filesystem
sink as part of the *path*, letting the attacker escape the intended directory
(`../`) or override it entirely (an absolute path) to read, write, or overwrite
arbitrary files. File inclusion (CWE-98) is the same flaw at an *interpreter* sink:
the path controls which file is `include`d/`require`d/rendered and therefore
executed — locally (LFI) or from a remote URL (RFI). CWE-73 is the general
"external control of filename or path." The core test: does a source value
influence a path passed to open/read/write/include/serve/extract, and is the
**canonicalized final path** confined to an intended base directory?

## 2. Where it lives

- File download / "view attachment" endpoints keyed by `?file=`, `?path=`,
  `?name=`, `?doc=`; static-file servers and export/report downloaders.
- Template/view resolution where the template name comes from input (render engine
  path injection), plugin/theme/locale/i18n file loaders.
- Upload destination paths built from the client filename (write-side traversal
  into the webroot → overlaps unrestricted-file-upload).
- Archive extraction (zip/tar) writing entries by their stored names (zip slip).
- Config/log/backup readers, image/font loaders, and any `include`/`require` whose
  argument is not a hard-coded literal.

## 3. Sources (tainted input)

All HTTP inputs (query/body/path/header/cookie), **plus the client-supplied
filename** in multipart uploads and **archive entry names** inside a user-supplied
zip/tar (each entry name is attacker-controlled). **Second-order:** a filename or
relative path stored earlier (upload record, profile field) and later joined into
a read/serve path — trace it back to its write.

## 4. Sinks (dangerous operations)

```python
# Python — dangerous
open(os.path.join(BASE, request.args["file"]))   # join(base, "/etc/passwd") → "/etc/passwd"
send_file(BASE + request.args["p"])               # concat, no confinement
tarfile.extractall(dest)                           # zip slip: entries with ../
```
```javascript
// Node — dangerous
fs.readFile(path.join(BASE, req.query.file), cb);  // "../" escapes BASE
res.sendFile(req.params.name);                      # no { root } → absolute/traversal
fs.createReadStream(BASE + req.query.p);
```
```java
// Java — dangerous
new FileInputStream(new File(base, request.getParameter("f")));   // ../ escapes
Files.newInputStream(Paths.get(base, userPath));                   // no realpath check
new ZipInputStream(...).getNextEntry().getName();                  // zip slip on write
```
```php
// PHP — dangerous (inclusion → code execution)
include($_GET['page'] . ".php");                    // LFI; also php://filter, data://
require($_GET['tpl']);                              // RFI if allow_url_include=On
readfile($_GET['file']);                            // arbitrary file read
```
```go
// Go — dangerous
http.ServeFile(w, r, filepath.Join(base, r.URL.Query().Get("f")))  // cleans but base may be escaped
os.Open(base + r.URL.Query().Get("p"))
```

Write-side sinks (`open(..., "w")`, `move_uploaded_file`, `extractall`,
`writeFile`) are worse: traversal there overwrites config, cron, web-shells, or
SSH keys. Interpreter sinks (`include`/`require`/`eval-file`/template render)
convert file read into **code execution**.

## 5. Sanitizers / safe patterns

**Safe:**
- **Canonicalize, then confine:** resolve the real path (`os.path.realpath`,
  `Path.resolve`/`toRealPath`, `filepath.Clean` + prefix check) and verify it
  starts with the intended base directory **followed by a separator** before
  opening. Reject otherwise.
- **Indirect reference:** map a user-supplied ID/token to a server-held path;
  never pass the raw name to the filesystem.
- Reduce to a basename (`os.path.basename`, `path.basename`) when only a flat
  directory is intended, and reject any input containing separators or `..`.
- Use framework-confined servers: Express `res.sendFile(name, { root: BASE })`,
  Flask `send_from_directory(BASE, name)`, which reject traversal — but only when
  actually given the `root`/base argument.
- For archives: validate each entry's resolved destination is inside the target
  before writing; skip absolute paths and symlink entries.
- Disable remote inclusion (`allow_url_include=Off`, `allow_url_fopen=Off`) and
  never build an `include` path from input.

**Fails / not a real sanitizer:**
- **Blocklisting `../`** — bypassed by `....//`, `..\/`, `..%2f`, double-encoded
  `%252e%252e%252f`, Unicode/overlong `%c0%ae`, `．` fullwidth dots, and (on
  vulnerable stacks) null-byte truncation `file.php%00.png`.
- **Checking before decoding** — the validator sees the encoded form; the runtime
  decodes it later at the sink.
- **`startsWith(base)` without a separator** — `/data` vs `/data-secret` both
  match; append the path separator to the base before comparing.
- **`os.path.join` / `Paths.get` with a user segment** — an **absolute** user
  segment *replaces* the base (`join("/safe", "/etc/passwd")` → `/etc/passwd`).
  Joining is not confinement.
- **Basename applied on one branch** or after the path is already used.
- **Symlink following** — the confined path is a symlink pointing outside the base;
  resolve links (`realpath`) and/or open with `O_NOFOLLOW`.

## 6. Detection methodology

1. **Find sinks:** grep for filesystem, include, serve, and extract APIs.
   ```
   rg -n 'open\(|readFile|createReadStream|FileInputStream|Files\.(newInputStream|readAll)|os\.Open|ioutil\.ReadFile'
   rg -n 'send_file|sendFile|send_from_directory|ServeFile|readfile\(|X-Sendfile'
   rg -n '\b(include|include_once|require|require_once)\b|php://|data://|expect://|zip://'
   rg -n 'extractall|ZipInputStream|getNextEntry|tarfile|unzip|extract\('
   rg -n 'os\.path\.join\(|path\.join\(|Paths\.get\(|filepath\.Join\(' 
   ```
2. **Confirm the path is source-derived:** is any path segment a variable from
   request/upload/archive, not a constant?
3. **Trace confinement:** is the *canonicalized* path checked against a base with a
   separator, or is it just joined/concatenated?
4. **Check the sink class:** read (info disclosure), write (overwrite → RCE), or
   include/render (direct code execution / LFI→RCE).
5. **Confirm reachability:** exposed route/handler; pre-auth? Is the file content
   returned (in-band) or only its side effect observable?
6. **Classify:** traversal read, traversal write/zip-slip, LFI, RFI.

## 7. Modern & niche variants

- **`../` traversal & absolute-path override:** the two base cases. Absolute
  override is frequently missed because `join`/`Paths.get` silently discard the
  base when the user segment is absolute — test with `/etc/passwd` and `C:\…`.
- **Encoded / double-encoded / Unicode / null-byte:** `%2e%2e%2f`, `%252e…`,
  overlong UTF-8 `%c0%ae`, fullwidth `．`, and legacy null-byte truncation
  (`page=../../etc/passwd%00.png` in old PHP/Java) that cut off an appended
  extension.
- **LFI → RCE (PHP):** the highest-impact traversal outcome.
  - `php://filter/convert.base64-encode/resource=index` reads source code (leak
    secrets) and, via chained filters, can inject code.
  - `data://text/plain;base64,<payload>` and `expect://` execute attacker code
    when wrappers are enabled.
  - **Log poisoning:** inject PHP into a value that lands in `access.log`/`error.log`
    or `/var/log/mail`, then `include` that log → the injected `<?php ?>` runs.
  - `/proc/self/environ`, `/proc/self/fd/*`, and **PHP session files**
    (`/tmp/sess_<id>` with attacker-controlled session data) are classic include
    targets that turn file read into execution.
- **Remote File Inclusion (RFI):** `include($_GET['p'])` with `allow_url_include=On`
  pulls and executes `http://attacker/shell.txt` — instant RCE. Rare on modern
  configs but check the ini/flags.
- **Zip slip (archive extraction):** an archive entry named `../../etc/cron.d/x`
  or `..\..\webroot\shell.jsp` writes outside the extraction target. Affects
  every language's zip/tar libs that don't validate entry destinations. Also
  covers symlink and absolute-path entries.
- **Symlink following:** upload or extraction creates a symlink, then a later read
  follows it out of the base; or a confined read resolves a pre-existing symlink.
- **`path.join`/`os.path.join` with user input:** treated as safe but neither
  confines — absolute override and residual `..` both slip through.
- **`sendFile`/`res.sendFile` without root confinement:** omitting the `{ root }`
  option (Express) or the base dir (Flask `send_file` vs `send_from_directory`)
  serves any absolute/traversed path.
- **Template / view path injection:** the *template name* is user-controlled —
  `render_template(user)`, a view resolver, or a partial include — enabling read of
  arbitrary template files and, on some engines, SSTI/execution.

## 8. Common false positives

- Path built entirely from constants or an ID mapped to a fixed server-held path.
- Canonicalized real path confirmed to start with the base dir + separator before
  every open, with symlinks resolved.
- Framework confined servers (`send_from_directory`, `res.sendFile(_, {root})`)
  given a proper base and a basename-only name.
- `include`/`require` targets that are hard-coded literals or from a fixed
  allowlist map.

## 9. Severity & exploitability

Base **High** for arbitrary read of sensitive files (config, keys, source).
**Critical** when it reaches code execution — LFI→RCE (PHP wrappers, log/session
poisoning), RFI, or a write/zip-slip that drops a web-shell / overwrites cron or
authorized_keys — or when it is pre-auth. Lower to **Medium** when confined to a
non-sensitive directory or reachable only behind admin auth with reads only.
See `references/severity-model.md`.

## 10. Remediation

Prefer indirect references (ID → server-held path). Where a path must be built:
canonicalize and verify the real path is confined to the intended base directory
(base + separator prefix check), reject `..`, separators, absolute paths, null
bytes, and encoded variants *after* decoding, and resolve symlinks. Never build an
`include`/`require`/template path from input; disable `allow_url_include`/
`allow_url_fopen`. For archives, validate each entry's destination before writing
and skip symlink/absolute entries.

## 11. Output

Append each confirmed finding to **`findings/25-path-traversal-and-file-inclusion.md`**
using `references/finding-template.md`. Set `Class: Path Traversal / File Inclusion`
and `CWE: CWE-22` (use `CWE-98` for remote/local file *inclusion*, `CWE-73` for
external control of filename). In **Chain potential** name primitives such as
*arbitrary file read* (→ leaked secrets/creds/source for other chains), *arbitrary
file write* (→ web-shell / config overwrite → RCE), *LFI→RCE* (wrapper/log/session
poisoning), and note when the finding **consumes** an upload primitive (attacker-
placed file to later include or serve).

**Primitives (controlled):** provides `FILE_READ`,`CODE_EXEC` (LFI),`FILE_WRITE` (zip slip); consumes none

## References
- CWE-22 Path Traversal; CWE-98 PHP File Inclusion; CWE-73 External Control of
  File Name or Path; OWASP A01:2021 Broken Access Control and A03:2021 Injection;
  OWASP Path Traversal and File Inclusion testing guides; "Zip Slip" advisory.
