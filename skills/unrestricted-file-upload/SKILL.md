---
name: unrestricted-file-upload
description: >-
  SAST detection methodology for unrestricted / dangerous file upload (CWE-434),
  including extension and Content-Type trust bypass, double extension, polyglot
  files, filename-driven path traversal into the webroot, SVG/HTML stored XSS,
  and parser-exploit RCE (ImageMagick/Ghostscript/ExifTool/ffmpeg). Use when
  reviewing code that accepts, stores, serves, or parses uploaded files. Writes
  confirmed findings to findings/26-unrestricted-file-upload.md.
---

# Unrestricted File Upload — SAST Methodology

**Class:** Unrestricted File Upload · **CWE-434** · **OWASP:** A04 Insecure Design
**Findings file:** `findings/26-unrestricted-file-upload.md`

## 1. Overview

An upload flaw exists when the server accepts a file whose type, content, or name
is attacker-controlled and then does something dangerous with it: serves it from a
location where it executes, stores it under an attacker-chosen path, or parses it
with a fragile/unsafe processor. The core test: can an attacker upload a file that
(a) executes as server-side code when later requested, (b) is written to an
executable or attacker-chosen location, (c) triggers a parser/deserialization
exploit on ingest, or (d) is served back and rendered as active content (SVG/HTML
→ XSS)? Validation based on the *client's* extension or `Content-Type` is not a
control — both are attacker-supplied.

## 2. Where it lives

- Profile/avatar and cover-image uploads, document/attachment handlers, resume/CV
  and "import" features, media galleries, message attachments.
- CSV/XLSX/JSON import, plugin/theme/template upload, firmware/backup restore.
- Media pipelines that shell out to image/video processors on ingest
  (thumbnailing, transcoding, EXIF stripping, virus scan, OCR).
- "Fetch from URL" avatar/import features (the fetched bytes are the upload, and
  the fetch overlaps SSRF).

## 3. Sources (tainted input)

The uploaded **file bytes**, the **client filename**, and the **`Content-Type`**
header — all attacker-controlled. For archives, every **entry name and entry
content** inside the uploaded zip/tar. **Second-order:** a stored file re-served
later, or a stored filename joined into a later path (overlaps path traversal).

## 4. Sinks (dangerous operations)

```php
// PHP — dangerous
move_uploaded_file($_FILES['f']['tmp_name'],
    "/var/www/html/uploads/" . $_FILES['f']['name']);   // client name → shell.php in webroot
```
```javascript
// Node — dangerous
multer({ storage: multer.diskStorage({
  destination: 'public/uploads',                         // served & guessable dir
  filename: (r, file, cb) => cb(null, file.originalname) // attacker name: ../ or .php.jpg
})});
if (file.mimetype === 'image/png') accept();             // client-set MIME, trusted
```
```python
# Python — dangerous
f = request.files["upload"]
f.save(os.path.join(UPLOAD_DIR, f.filename))             # filename may contain ../
subprocess.run(["convert", tmp_path, out])               # ImageMagick on attacker bytes
Image.open(f).thumbnail((100,100))                        # parser exploits on ingest
```
```java
// Java — dangerous
String name = part.getSubmittedFileName();               // client-controlled
Files.copy(part.getInputStream(), Paths.get(webroot, name));  // → .jsp in served dir
```

Dangerous whenever: the storage path/filename comes from the client, the storage
directory is served and allows script execution, acceptance is decided by
extension/`Content-Type`, or the bytes are handed to a parser (image/video/office)
that has known RCE surface.

## 5. Sanitizers / safe patterns

**Safe:**
- **Decide type by content, not metadata:** verify magic bytes / sniff the real
  MIME (`file`/libmagic, `image/*` header checks), and require it to match an
  **allowlist** — while still not trusting the client extension or `Content-Type`.
- **Generate the stored name server-side** (random UUID) with a fixed, safe
  extension; never reuse the client filename for the path.
- **Store outside the webroot** or on object storage; serve through a handler that
  sets `Content-Type` from the verified type, `Content-Disposition: attachment`,
  and `X-Content-Type-Options: nosniff`.
- **Disable execution** in the upload directory (no PHP/CGI handler, `php_admin_flag
  engine off`, no `Options ExecCGI`).
- **Re-encode images** through a trusted library (strip to a clean canvas) so
  polyglots and embedded payloads are destroyed; sandbox/patch/limit media
  processors (ImageMagick `policy.xml`, Ghostscript `-dSAFER`, disable coders).
- For archives, validate each entry destination (zip slip) and re-check every
  extracted file's type.

**Fails / not a real sanitizer:**
- **Trusting the extension or `Content-Type`** — both are set by the attacker.
- **Blocklisting extensions** — bypassed by `.php5`, `.phtml`, `.pht`, `.phar`,
  `.jsp`/`.jspx`, `.asp`/`.aspx`/`.cshtml`, case (`.PHp`), trailing dot/space
  (`shell.php.`, `shell.php ` on Windows), and double extension `shell.php.jpg`
  (served as PHP where the web server maps by an interior known extension).
- **Magic-byte check only on the first bytes** — a polyglot has a valid image
  header *and* executable content after it.
- **Allowlisting the extension but keeping the client filename** for the path —
  `../../shell.php` still traverses into the webroot.
- **Checking type but storing in an executable, served directory** — a valid image
  that also contains PHP still runs if the URL ends in `.php`.
- **Re-encoding declared but skipped** for some formats (e.g. SVG passed through as
  "image").

## 6. Detection methodology

1. **Find sinks:** grep for upload receivers, storage writes, and media shell-outs.
   ```
   rg -n 'move_uploaded_file|\$_FILES|multipart|MultipartFile|getSubmittedFileName'
   rg -n 'multer|formidable|busboy|request\.files|part\.getInputStream|save\(|copyToLocal'
   rg -n 'originalname|filename|getName\(\)|submittedFileName'   # client-name into path
   rg -n 'convert |mogrify|gm |gs |ghostscript|exiftool|ffmpeg|Image\.open|ImageIO\.read'
   rg -n 'content[_-]?type|mimetype|getContentType'             # metadata-based checks
   ```
2. **Confirm trust in client metadata:** is acceptance gated on extension/
   `Content-Type` rather than content sniffing?
3. **Trace the stored path and name:** is the client filename used for the path?
   Is the destination inside the webroot / an executable directory?
4. **Check post-storage handling:** is it served with a sniffable type / inline
   disposition? Is it parsed by a fragile processor?
5. **Confirm reachability:** exposed upload route; pre-auth? Is the stored file
   retrievable at a predictable URL?
6. **Classify:** exec-in-webroot RCE, filename traversal, stored XSS (SVG/HTML),
   parser RCE, or archive-based traversal.

## 7. Modern & niche variants

- **Extension / `Content-Type` trust bypass:** the root cause — both are attacker-
  set. Any control built on them alone is defeated.
- **Double extension (`shell.php.jpg`):** exploits web-server handler mapping (e.g.
  legacy Apache `AddHandler`/`mod_mime` matching an interior `.php`) so a file that
  "looks" like a JPEG executes as PHP.
- **Polyglot files:** a single file valid as two formats — **GIFAR** (GIF + JAR),
  **phar-JPEG**, PDF-JS, and image+HTML polyglots — passes an image check yet is
  interpreted as code/archive by another consumer.
- **Attacker-controlled filename → path traversal into the webroot:** a filename
  like `../../var/www/html/shell.php` writes an executable file into a served
  directory (direct overlap with path-traversal write-side).
- **SVG / HTML upload → stored XSS:** SVG is an image but rendered as markup —
  `<script>`/`<foreignObject>`/event handlers execute in the app origin when the
  file is opened inline. HTML/`.xht` uploads served inline do the same. SVG can
  also trigger SSRF/XXE via external references.
- **Image-parser exploits:** ImageTragick (CVE-2016-3714) — ImageMagick delegate/
  MSL/coder abuse turns a crafted image into command execution during
  thumbnailing.
- **Deserialize / command execution on parse:** Ghostscript `-dSAFER` bypasses
  (PostScript/PDF → RCE), **ExifTool** DjVu injection (CVE-2021-22204 → RCE),
  ImageMagick `MVG`/`MSL`/`ephemeral:` coders, and **ffmpeg** HLS/`concat`/SSRF
  reads — any processor invoked on attacker bytes is an ingest RCE surface.
- **Missing magic-byte / MIME sniffing:** no content verification at all; the file
  is accepted on name alone.
- **Upload into an executable / served directory:** even a correctly typed file is
  dangerous if the storage dir runs scripts or the type can be sniffed by the
  browser (missing `nosniff`).
- **Archive upload:** uploaded zip/tar extracted server-side → zip slip writes a
  web-shell outside the target, or bombs the disk (DoS).

## 8. Common false positives

- Content verified by magic bytes against an allowlist, stored with a server-
  generated random name and safe extension, outside the webroot / on object
  storage.
- Files served only as `attachment` with `nosniff` and a fixed non-executable
  `Content-Type`, from a directory with script execution disabled.
- Images re-encoded through a trusted library that strips embedded payloads.
- Uploads never served back and never parsed by a media processor.

## 9. Severity & exploitability

Base **High**. **Critical** when it yields RCE — a web-shell executing in the
webroot, an ingest parser exploit (ImageMagick/Ghostscript/ExifTool/ffmpeg), or an
archive drop into an executable path — or when it is pre-auth. Stored XSS via
SVG/HTML is **High** in an authenticated context. Lower to **Medium** when the file
is stored inert (random name, outside webroot, attachment-only, never parsed) and
only metadata is questionable. See `references/severity-model.md`.

## 10. Remediation

Verify file type by content (magic bytes / sniffing) against a strict allowlist,
never by the client extension or `Content-Type`. Store with a server-generated
random name and a fixed safe extension, outside the webroot or on object storage,
in a directory where script execution is disabled; serve as `attachment` with
`nosniff`. Re-encode images through a trusted library and never render SVG/HTML
inline in the app origin. Sandbox, patch, and policy-restrict any media processor
(ImageMagick `policy.xml`, Ghostscript `-dSAFER`); validate archive entries against
zip slip.

## 11. Output

Append each confirmed finding to **`findings/26-unrestricted-file-upload.md`** using
`references/finding-template.md`. Set `Class: Unrestricted File Upload`,
`CWE: CWE-434`, and in **Chain potential** name primitives such as *RCE* (web-shell
or parser exploit — the terminal primitive of many chains), *arbitrary file write*
(consumes/overlaps a path-traversal primitive via the filename), *stored XSS*
(SVG/HTML → session/credential theft), and *SSRF* (SVG/ffmpeg external refs). Note
when the finding **consumes** a path-traversal primitive to control the stored path.

**Primitives (controlled):** provides `FILE_WRITE`,`HTML_OUTPUT` (SVG/HTML),`CODE_EXEC`; consumes none

## References
- CWE-434 Unrestricted Upload of File with Dangerous Type; OWASP A04:2021 Insecure
  Design and A08:2021 Software and Data Integrity Failures; OWASP File Upload
  Cheat Sheet; ImageTragick (CVE-2016-3714) and ExifTool (CVE-2021-22204)
  advisories.
