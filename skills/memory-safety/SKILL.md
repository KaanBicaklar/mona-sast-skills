---
name: memory-safety
description: >-
  SAST detection methodology for native memory-safety flaws (CWE-119) in C/C++,
  unsafe Rust, cgo, and JNI — stack/heap buffer overflow, out-of-bounds read/
  write, use-after-free, double-free, integer overflow leading to undersized
  allocation, format-string, off-by-one, uninitialized memory, and type
  confusion. Use when reviewing native code or FFI boundaries. Writes confirmed
  findings to findings/46-memory-safety.md.
---

# Memory Safety (Native) — SAST Methodology

**Class:** Memory Safety · **CWE-119** (and CWE-120, CWE-121/122, CWE-787, CWE-125, CWE-416, CWE-415, CWE-190/191, CWE-134) · **OWASP:** native / A06-adjacent
**Findings file:** `findings/46-memory-safety.md`

## 1. Overview

Native memory-safety flaws occur when code reads or writes outside the bounds of a
live, correctly-sized allocation, or uses memory after it has been freed. The core
test: does attacker-influenced data control a **length, index, allocation size, or
format string** that reaches an unchecked memory operation? A single out-of-bounds
write or use-after-free is often a path to `CODE_EXEC`; an out-of-bounds read is a
`SECRET_LEAK`. These flaws live in the compiled binary; whether they are remotely
reachable depends on whether the vulnerable parser sits behind a network face
(see §9/§11).

## 2. Where it lives

- C/C++ source (`.c`/`.cc`/`.cpp`/`.h`) — string/buffer handling, parsers, codecs,
  serializers, network protocol handlers, and any manual `malloc`/`free`.
- **Unsafe Rust** (`unsafe { … }`, raw pointers, `std::mem::transmute`,
  `slice::get_unchecked`, `from_raw_parts`, FFI declarations).
- **cgo** (Go `import "C"` boundaries) and **JNI** (`Get*ArrayElements`,
  `GetStringUTFChars`, direct `ByteBuffer` pointers) — the FFI boundary is where
  Go/Java bounds guarantees are lost.
- Any place a length/size/index crosses from untrusted input into pointer
  arithmetic or an allocation.

## 3. Sources (tainted input)

Whatever feeds a size/index/format: network bytes (recv buffers, protocol
length fields), file/media contents (image/font/archive parsers), environment
variables and argv, IPC/shared memory, and data crossing an FFI boundary from a
memory-safe language. Especially dangerous: **length or count fields taken from
input** and used in arithmetic before allocation or in a `memcpy`/loop bound.

## 4. Sinks (dangerous operations)

```c
/* C/C++ — dangerous APIs (no bounds / target-size unaware) */
char buf[64];
strcpy(buf, input);                 /* stack overflow — no length limit */
strcat(buf, input);                 /* unbounded append */
sprintf(buf, "%s", input);          /* unbounded format into fixed buffer */
gets(buf);                          /* never safe — removed from C11 */
scanf("%s", buf);                   /* unbounded %s */
memcpy(dst, src, len);              /* len from input, dst undersized → heap/stack write */
alloca(n);                          /* n from input → stack clash */

/* Integer overflow → undersized allocation → OOB write */
size_t n = count * size;            /* wraps on 32-bit → tiny alloc */
char *p = malloc(n);
memcpy(p, src, count * size);       /* writes the un-wrapped amount */

/* Format string — %n lets attacker WRITE to memory */
printf(user);                       /* attacker controls format → %x leak, %n write */
syslog(LOG_INFO, user);             /* same class */

/* Off-by-one / OOB index */
for (i = 0; i <= len; i++) buf[i] = src[i];   /* <= writes one past end */
arr[user_index] = v;                          /* index unchecked */

/* Use-after-free / double-free */
free(p); use(p);                    /* UAF read/write */
free(p); free(p);                   /* double free → allocator corruption */
```
```rust
// unsafe Rust — dangerous
let s = unsafe { std::slice::from_raw_parts(ptr, len) };  // len from input → OOB
let v = unsafe { *arr.get_unchecked(i) };                 // no bounds check
let x: &T = unsafe { std::mem::transmute(bytes) };        // type confusion
```
```c
// JNI — dangerous: raw pointer + input-controlled length
jbyte *b = (*env)->GetByteArrayElements(env, arr, NULL);
memcpy(out, b, in_len);   // in_len not clamped to GetArrayLength(arr)
```

Dangerous patterns marked above: unbounded string APIs (`strcpy`/`strcat`/
`sprintf`/`gets`/`scanf`), `memcpy`/`alloca` with input-derived length, size
arithmetic before `malloc`, `printf(user)` / non-constant format, `<=` loop bounds,
unchecked index, and free-then-use / double-free.

## 5. Sanitizers / safe patterns

**Safe:** bounds-checked APIs that take the destination size —
`strlcpy`/`strlcat` (BSD), `snprintf`, `memcpy_s`/`strcpy_s` (Annex K), and
`fgets` with a size; **always** pass the *target* buffer size, not the source
length. Safe integer arithmetic: `__builtin_mul_overflow`/`__builtin_add_overflow`,
`SIZE_MAX` checks before `malloc`, or `calloc(count, size)` (overflow-checked).
Constant format strings (`printf("%s", user)`, never `printf(user)`). C++ RAII and
containers (`std::string`, `std::vector::at`, `std::span`, `std::make_unique`,
`shared_ptr`) instead of raw new/delete; set freed pointers to `NULL`. Safe Rust
(no `unsafe`) — the borrow checker and slice bounds checks eliminate the whole class;
keep `unsafe` blocks minimal and audited. Compiler/OS hardening: stack canaries
(`-fstack-protector-strong`), `_FORTIFY_SOURCE=2`/`=3`, ASLR + PIE (`-fPIE -pie`),
NX/DEP, CFI (`-fsanitize=cfi`), and RELRO. Test with **ASan/UBSan/MSan**, Valgrind,
and continuous **fuzzing** (libFuzzer/AFL++).

**Fails / not a real sanitizer (how safe-looking code still breaks):**
- `strncpy` — does **not** NUL-terminate when the source fills the buffer, leaving a
  non-terminated string that later overflows on read; also pads, hiding truncation.
- Passing the *source* length to `memcpy`/`strncpy` instead of the destination size —
  still overflows an undersized destination.
- A bounds check performed **after** the copy, or on a signed value that went
  negative (`if (len < CAP)` where `len` is a large unsigned cast to signed).
- Canaries/ASLR/NX are exploitation *mitigations*, not fixes — the bug is still a
  bug; info-leaks (OOB read) defeat ASLR, and OOB writes not adjacent to the canary
  bypass it.
- `_FORTIFY_SOURCE` only catches *some* known-size cases; dynamic sizes and
  `memcpy` with a runtime length are not covered.
- "Validated" length that is checked against the wrong buffer, or checked but then
  a separate arithmetic (`len + header`) overflows.

## 6. Detection methodology

1. **Grep for the dangerous APIs and format sinks:**
   ```
   rg -n '\b(strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf|memcpy|memmove|alloca|strncpy)\s*\(' 
   rg -n '\bprintf\s*\(\s*[A-Za-z_]|fprintf\s*\([^,]+,\s*[A-Za-z_]|syslog\s*\([^,]+,\s*[A-Za-z_]'   # non-literal format
   rg -n '%n'                                  # format-string write primitive
   rg -n 'malloc\(|calloc\(|realloc\(|alloca\('   # then inspect the size expression
   rg -n 'unsafe|from_raw_parts|get_unchecked|transmute'   # unsafe Rust
   rg -n 'GetByteArrayElements|GetStringUTFChars|GetPrimitiveArrayCritical'   # JNI
   ```
2. **For each `malloc`/`memcpy`, inspect the size expression:** is it
   `count * size`/`a + b` with input-derived operands and no overflow check? Trace
   the length/index/format back to a source (§3).
3. **Confirm the destination is fixed/undersized** relative to the copied length, or
   the index/loop bound can exceed the allocation (`<=`, off-by-one).
4. **Check lifetime for UAF/double-free:** find every `free`/`delete`; is the pointer
   used or freed again on any path (including error/cleanup paths and aliases)?
5. **Check for a real control (§5):** size-aware API with the *destination* size,
   overflow-checked arithmetic, constant format string, NUL-termination, RAII/safe
   Rust. Reject the non-sanitizers above.
6. **Assess reachability (§9):** is the vulnerable parser fed by network/file input
   (remotely reachable) or only local/trusted data?

## 7. Modern & niche variants

- **Integer overflow → undersized allocation → heap OOB write:** the highest-yield
  variant; the multiplication wraps, the copy does not.
- **Signedness/truncation:** a negative `int` length cast to `size_t` becomes huge, or
  a 64→32-bit truncation shrinks a checked value after the check.
- **Off-by-one / single-byte overflow ("poison null byte"):** one byte past the end,
  often enough to corrupt a heap chunk-size or a length field.
- **Type confusion:** a union/`reinterpret_cast`/`transmute` treats bytes as the wrong
  type, yielding an attacker-controlled pointer.
- **Uninitialized memory use:** stack/heap read before write leaks residual data
  (`SECRET_LEAK`) or yields a wild pointer.
- **Use-after-free via callbacks/iterators:** an object freed during iteration or in a
  reentrant callback while an alias is still live; common in C++ and in
  Objective-C/C++ bridging.
- **Format string with `%n`:** turns a printf into an arbitrary write.
- **FFI length desync:** JNI/cgo code trusts a length passed from the managed side
  without re-checking `GetArrayLength`, or vice-versa.
- **`alloca`/VLA stack clash:** input-sized stack allocation jumps the guard page.

## 8. Common false positives

- `strcpy`/`memcpy` where the source is a compile-time constant or provably ≤ the
  destination size on all paths.
- `sprintf` with a constant format and only numeric conversions of bounded size.
- `unsafe` Rust blocks whose length/pointer come from a checked `slice`/`Vec` and
  cannot be influenced by input.
- Size arithmetic on constants, or after a correct `__builtin_mul_overflow` guard.
- Freed pointers immediately set to `NULL` with no intervening use.

## 9. Severity & exploitability

Base **High** for OOB write / UAF / double-free (memory corruption). **Critical**
when the flaw is in a **network-facing** parser and yields reliable `CODE_EXEC`
(especially with weak/absent mitigations — no ASLR/PIE/canary/NX). OOB read is
typically **Medium–High** (`SECRET_LEAK` / ASLR-defeat that enables a write bug).
Lower when the input is fully local/trusted, the target is not attacker-adjacent,
or hardening makes exploitation impractical (still report — mitigations are not
fixes). Score with `references/severity-model.md`.

## 10. Remediation

Replace unbounded APIs with size-aware equivalents passing the **destination** size
(`snprintf`, `strlcpy`/`strlcat`, `memcpy_s`), and always NUL-terminate. Use
overflow-checked arithmetic (`__builtin_*_overflow`, `calloc`) before every
allocation and validate lengths/indices against the actual buffer size. Use
constant format strings. In C++ prefer RAII, `std::vector`/`std::string`/`std::span`
and smart pointers; null out freed pointers. In Rust, keep to safe code and shrink
audited `unsafe` blocks; re-check lengths at every JNI/cgo boundary. Build with
`-D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now`, run
ASan/UBSan in CI, and fuzz all input parsers.

## 11. Output

Append each confirmed finding to **`findings/46-memory-safety.md`** using
`references/finding-template.md`. Set `Class: Memory Safety` and the specific `CWE`
(e.g. CWE-121 stack overflow, CWE-122 heap overflow, CWE-787 OOB write, CWE-125 OOB
read, CWE-416 UAF, CWE-415 double-free, CWE-190 integer overflow, CWE-134 format
string).

**Reachable over:** `N/A (client/on-chain)` for a **local** native flaw — reproduce
with crafted input plus a memory-safety oracle rather than Burp: compile with
`-fsanitize=address,undefined`, feed the crafting input/file, and observe the
ASan/UBSan report or crash; drive with a **fuzzer** (libFuzzer/AFL++) to trigger and
minimize; inspect the core dump / registers under a debugger. **Note:** if the
vulnerable parser is behind a network service (e.g. a protocol/media handler on a
socket), the flaw *is* remotely reachable — set `Reachable over: Web` (or
`Mobile/API`) and reproduce by sending the crafted bytes over that protocol/socket;
this is still not a Burp-native HTTP request unless the service literally speaks HTTP,
in which case include one Burp-pasteable request carrying the crafted field.

**Primitives (controlled):** provides `CODE_EXEC`(OOB write / UAF / double-free /
format-string `%n` → control flow — terminal node), `SECRET_LEAK`(OOB read /
uninitialized memory disclosure); consumes `none`.

## References
- CWE-119, CWE-120, CWE-121, CWE-122, CWE-787, CWE-125, CWE-416, CWE-415,
  CWE-190/191, CWE-134; SEI CERT C/C++ Coding Standard; OWASP C-Based Toolchain
  Hardening; the Rustonomicon (unsafe Rust) and JNI specification.
