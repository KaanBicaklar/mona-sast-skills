---
name: command-injection
description: >-
  SAST detection methodology for OS command injection (CWE-78), including shell
  metacharacter injection, argument/flag injection into git/curl/tar, wildcard
  injection, shell=True, and indirect injection via env vars and filenames. Use
  when reviewing code that spawns OS processes. Writes confirmed findings to
  findings/03-command-injection.md.
---

# Command Injection — SAST Methodology

**Class:** OS Command Injection · **CWE-78** · **OWASP:** A03 Injection
**Findings file:** `findings/03-command-injection.md`

## 1. Overview

Command injection occurs when attacker-controlled data reaches a process-spawning
sink and influences either the **command string** interpreted by a shell or the
**arguments** passed to a program. Two distinct failure modes: (1) a shell parses
the input and metacharacters (`;`, `|`, `&`, `$()`, backticks) start new commands;
(2) even with no shell, input becomes an argument that the target program treats
as an *option* (argument/flag injection). The core test: does a source reach an
`exec`/`system`/`spawn` sink, and is a shell involved *or* can the input pose as a
flag?

## 2. Where it lives

- Any process-spawn API: `os.system`, `subprocess` with `shell=True`,
  `child_process.exec`, `Runtime.exec`, `ProcessBuilder`, PHP `system`/`exec`/
  `passthru`/`shell_exec`/backticks, Ruby `system`/backticks/`%x`, Go `exec.Command`
  with `sh -c`.
- Shell-outs to CLI tools (git, curl, tar, ffmpeg, imagemagick, ping, nmap, zip)
  with user-supplied args, filenames, or URLs.
- "Glue" scripts, webhooks, CI runners, and file-conversion/thumbnail pipelines.
- Template/report generators that call `wkhtmltopdf`, `pandoc`, `latex`, etc.

## 3. Sources (tainted input)

All HTTP inputs, plus **indirect** sources that are easy to miss: environment
variables (multi-tenant/CI), **filenames** in uploads and archives (a file named
`;rm -rf` or `--upload-file`), image/document metadata read by a downstream tool,
DB-stored values re-used to build a command (**second-order**), and hostnames/URLs
passed to network tools. Trace stored/derived values back to their write source.

## 4. Sinks (dangerous operations)

```python
# Python — dangerous
os.system("ping -c1 " + host)                     # shell parses metachars
subprocess.run(f"tar czf out.tgz {path}", shell=True)   # shell=True = shell
subprocess.call(["git", "clone", url])            # NO shell, but url="--upload-pack=..." = arg injection
os.popen("convert " + name + " out.png")
```
```javascript
// Node — dangerous
child_process.exec(`ping -c1 ${host}`);           // exec spawns /bin/sh
child_process.execSync("tar czf o.tgz " + path);
spawn("sh", ["-c", `ls ${dir}`]);                 // explicit shell
spawn("git", ["clone", url]);                      // arg injection if url starts with -
```
```java
// Java — dangerous
Runtime.getRuntime().exec("sh -c \"ping " + host + "\"");
new ProcessBuilder("bash", "-c", "grep " + q + " f").start();
Runtime.getRuntime().exec(new String[]{"tar","xf",userFile}); // arg injection
```
```php
// PHP — dangerous
system("ping -c1 ".$_GET['host']);
exec("convert ".$file." out.png", $o);
passthru("git clone ".$url);
$out = shell_exec("ls ".$dir);
$x = `whois $domain`;                              // backticks
```
```ruby
# Ruby — dangerous
system("ping -c1 #{host}")                         # interpolation + shell
`tar czf out.tgz #{path}`                          # backticks
%x(git clone #{url})
```
```go
// Go — dangerous
exec.Command("sh", "-c", "ping "+host).Run()       // sh -c = shell
exec.Command("tar", "xf", userFile).Run()          // arg injection
```

## 5. Sanitizers / safe patterns

**Safe:**
- **No shell + argument vector:** pass a program and an **array of args**
  (`subprocess.run([...], shell=False)`, `execFile`/`spawn` without a shell,
  `ProcessBuilder(list)`, `exec.Command(name, args...)`). Metacharacters are inert.
- Use the `--` end-of-options separator and/or validate that user args don't start
  with `-` to stop flag injection (`git clone -- <url>`).
- Strict allowlist for the command/subcommand; validate hostnames, paths, and IDs
  against a tight regex/enum.
- Prefer native libraries over shelling out (HTTP client vs `curl`, archive lib
  vs `tar`).

**Fails / not a real sanitizer:**
- Escaping quotes but still running through a shell — many metachars need no
  quotes (`$()`, `` ` ``, `\n`, `;`).
- Blocklisting `;` and `|` while `&&`, `\n`, `$()`, `${IFS}`, backticks slip
  through; blocklists are always incomplete.
- `shlex.quote`/`escapeshellarg` applied to *one* arg but the command still built
  as a shell string, or applied but the value is later re-split.
- Array/exec vector used, but the value is a **flag** — arg injection is unblocked
  by shell-escaping (there is no shell to escape).
- Validating the value but passing the raw **filename** from an upload/archive.

## 6. Detection methodology

1. **Find sinks:** grep the spawn APIs and shell indicators.
   ```
   rg -n 'os\.system|subprocess\.(run|call|Popen|check_output)|os\.popen'
   rg -n 'shell\s*=\s*True|child_process|\.exec(Sync)?\(|execFile|spawn\('
   rg -n 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process\.Start'
   rg -n 'shell_exec|passthru|\bsystem\s*\(|\bexec\s*\(|popen|proc_open'
   rg -n '`[^`]*\$\{|%x\(|\bsystem\s*\(|IO\.popen|Open3'
   rg -n 'exec\.Command\([^)]*"(sh|bash|cmd|powershell)"'
   ```
2. **Determine if a shell is involved:** `shell=True`, a string command,
   `sh -c`/`cmd /c`/`bash -c`, or an API that spawns a shell (`exec`, `system`,
   backticks). If yes → metacharacter injection is in scope.
3. **If no shell, check argument injection:** can input become a leading `-`/`--`
   flag to the target tool? (git `--upload-pack`/`--output`, curl `-o`/`--config`,
   tar `--to-command`, find `-exec`, ssh `-o`).
4. **Trace input to a source** (direct, env, filename, or second-order). Stop at a
   constant.
5. **Check for a real neutralizer:** array vector *and* flag guard, or a strict
   allowlist. Verify it's on the reaching path and not bypassable (see §5).
6. **Confirm reachability** and note the platform (POSIX shell vs Windows
   `cmd`/PowerShell) — quoting and metachars differ.

## 7. Modern & niche variants

- **Argument / flag injection (no metachars needed):** input passed as a program
  argument that the program interprets as an option. `git clone
  --upload-pack='sh -c ...' host:repo`, `curl --config /attacker` or `-o /path`,
  `tar --to-command=cmd`, `find . -exec`, `ssh -o ProxyCommand=`, `zip -T
  --unzip-command`. Defeats shell-escaping entirely because there is no shell.
  Guard with `--` and a leading-dash check.
- **Wildcard injection:** attacker controls filenames in a directory later globbed
  (`tar czf a.tgz *`, `chown -R x *`). A file named `--checkpoint-action=exec=sh`
  or `-rf` is expanded by the shell into an argument — classic `tar`/`rsync`/`chown`
  wildcard attacks.
- **Indirect via environment variables:** input written to an env var consumed by
  a child process (`IFS`, `LD_PRELOAD`, `GIT_SSH`, `PAGER`, `PATH`, `PERL5OPT`).
  The command string looks clean; the env is the vector.
- **Indirect via filenames / archives:** upload or zip-slip filename becomes an
  arg or is globbed. Metadata (EXIF, PDF fields) read by a shelled-out tool.
- **`shell=True` and backtick/`%x` interpolation:** the most common Python/Ruby/PHP
  root cause — a formatted string with a shell.
- **`exec` vs `execve` semantics:** Java `Runtime.exec(String)` naively splits on
  spaces (no shell) — quoting breaks, and `exec(String[])` runs a program directly;
  neither parses metachars unless you explicitly invoke `sh -c`. Know which overload
  is used before judging.
- **Windows cmd vs PowerShell:** `cmd /c` metachars are `&`, `|`, `%VAR%`,
  `^`; PowerShell adds `;`, `` ` ``, `$()`, `|`, and expression injection. `.bat`
  wrappers re-parse arguments (the "BatBadBut" class) even from array-vector spawns.

## 8. Common false positives

- Array/exec-file vector with no shell **and** no possibility of flag injection
  (value is not a leading arg, or `--`/dash-guard present).
- Command and all args are hard-coded constants.
- User input validated against a strict allowlist/enum before use.
- A native library is used and the "command" string is unrelated dead code.

## 9. Severity & exploitability

Base **Critical** — command injection is remote code execution. Confirm and it is
Critical; pre-auth or default-config reachability keeps it there. Argument
injection may be **High** if it yields file write/read or option abuse short of
full RCE, rising to Critical when the flag reaches code execution (e.g. git
`--upload-pack`). Lower only if reachable exclusively behind strong admin auth with
constrained input. See `references/severity-model.md`.

## 10. Remediation

Avoid shelling out; use native libraries. When you must spawn, use the
array/argument vector with `shell=False` and never build a shell string. Add a
strict allowlist for commands and validate every argument; use `--` and reject
values starting with `-`. Never pass raw filenames/env into commands. Run with
least privilege.

## 11. Output

Append each confirmed finding to **`findings/03-command-injection.md`** using
`references/finding-template.md`. Set `Class: OS Command Injection`, `CWE:
CWE-78`, and in **Chain potential** name primitives such as *remote code
execution* (terminal primitive — usually the end of a chain), *arbitrary file
read/write* (via flag injection / redirection), or note when it *consumes* a
primitive like *arbitrary file write* or *SSRF* (a controlled URL fed to `curl`)
to reach RCE.

**Primitives (controlled):** provides `CODE_EXEC`; consumes none

## References
- CWE-78; OWASP A03:2021 Injection; OWASP Command Injection Prevention Cheat
  Sheet; GTFOBins/LOLBAS (argument-injection gadgets).
