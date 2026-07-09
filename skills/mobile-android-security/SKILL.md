---
name: mobile-android-security
description: >-
  SAST detection methodology for Android app security flaws (CWE-926) — exported
  components & intent hijacking, insecure WebView/JS-bridge, insecure data
  storage, deep-link/App-Link hijacking, exported ContentProvider, cleartext
  traffic, missing certificate pinning, mutable PendingIntent, and allowBackup.
  Use when reviewing an APK, decompiled smali/Java/Kotlin, or an AndroidManifest.
  Writes confirmed findings to findings/44-mobile-android-security.md.
---

# Mobile — Android Security — SAST Methodology

**Class:** Mobile — Android · **CWE-926** (and CWE-919, CWE-312, CWE-749, CWE-79) · **OWASP:** Mobile Top 10 / MASVS
**Findings file:** `findings/44-mobile-android-security.md`

## 1. Overview

Android security flaws arise when an app exposes a component, sink, or data store
that a *co-located malicious app* (or a crafted intent/deep link) can reach
without the app's consent. The core test: does a component/API cross a trust
boundary — `exported` to other apps, a `WebView` that runs untrusted JS, a data
store readable outside the app sandbox, or a deep link that drives a privileged
action — without an enforcing permission, verification, or encryption? These
flaws live in the **manifest and the app binary**, not on the HTTP wire, so most
are not Burp-reproducible (see §11).

## 2. Where it lives

- `AndroidManifest.xml`: `<activity>`/`<service>`/`<receiver>`/`<provider>` with
  `android:exported="true"` (or an `<intent-filter>` that implies exported) and no
  `android:permission`; `<application>` flags `usesCleartextTraffic`,
  `allowBackup`, `debuggable`; `<data>` deep-link/App-Link filters.
- WebView setup code in Java/Kotlin/smali (`WebView`, `WebSettings`,
  `addJavascriptInterface`, `WebViewClient.shouldOverrideUrlLoading`).
- Data-storage code: `SharedPreferences`, `SQLiteDatabase`/Room, `openFileOutput`,
  `getExternalStorage*`, `File(...)` writes, `MODE_WORLD_READABLE/WRITEABLE`.
- Deep-link / App-Link intent handling (`getIntent().getData()`, `onNewIntent`).
- Network config: `res/xml/network_security_config.xml`, OkHttp/TrustManager,
  `CertificatePinner`, custom `HostnameVerifier`.
- `PendingIntent` construction; `res/values/strings.xml` and other resources
  (embedded secrets / Firebase config / API keys).

## 3. Sources (tainted input)

Cross-app and cross-boundary inputs: **intents** from other apps (extras, data
URI, action), **deep links / App Links** (attacker-crafted `https`/custom-scheme
URLs), **ContentProvider** query/path arguments from other apps, JavaScript
running in a `WebView` (loaded page or injected via MITM on cleartext), files on
**external/shared storage** writable by other apps, and IPC via exported
services/receivers. Second-order: a value stored insecurely (SharedPreferences,
external file) then read back into a trusted operation.

## 4. Sinks (dangerous operations)

```xml
<!-- AndroidManifest.xml — dangerous -->
<activity android:name=".AdminActivity" android:exported="true"/>          <!-- exported, no permission -->
<service  android:name=".SyncService"   android:exported="true"/>          <!-- other apps can bind/start -->
<provider android:name=".NotesProvider" android:authorities="com.x.notes"
          android:exported="true"/>                                        <!-- SQLi / path traversal surface -->
<receiver android:name=".CmdReceiver"   android:exported="true"/>          <!-- broadcast injection -->
<application android:usesCleartextTraffic="true"                           <!-- HTTP allowed → MITM -->
             android:allowBackup="true"                                    <!-- adb backup exfil -->
             android:debuggable="true">                                    <!-- run-as / debugger -->
  <activity android:name=".DeepLinkActivity">
    <intent-filter>                                                        <!-- App Link WITHOUT autoVerify -->
      <action android:name="android.intent.action.VIEW"/>
      <category android:name="android.intent.category.BROWSABLE"/>
      <data android:scheme="https" android:host="app.example.com"/>
    </intent-filter>
  </activity>
</application>
```
```java
// Java/Kotlin — dangerous WebView
WebView w = findViewById(R.id.web);
w.getSettings().setJavaScriptEnabled(true);
w.addJavascriptInterface(new NativeBridge(), "Android");      // JS→Java RCE if page untrusted (< API 17 all methods)
w.getSettings().setAllowFileAccess(true);
w.getSettings().setAllowFileAccessFromFileURLs(true);
w.getSettings().setAllowUniversalAccessFromFileURLs(true);    // file:// can XHR any origin
w.loadUrl(getIntent().getData().toString());                  // load attacker-controlled URL
```
```java
// Java — dangerous storage & IPC
getSharedPreferences("p", Context.MODE_WORLD_READABLE);       // world-readable prefs (any app reads)
SharedPreferences.Editor e = sp.edit(); e.putString("token", jwt);   // plaintext secret
File f = new File(getExternalStorageDirectory(), "creds.txt"); // shared storage, no sandbox
db.rawQuery("SELECT * FROM notes WHERE id=" + uri.getLastPathSegment(), null); // provider SQLi
PendingIntent.getActivity(ctx, 0, intent, 0);                 // MUTABLE (pre-M default) → intent hijack
String url = getIntent().getStringExtra("next"); startActivity(new Intent(ACTION_VIEW, Uri.parse(url))); // deeplink→intent redirect
```

Dangerous patterns marked above: `exported="true"` without `android:permission`,
`addJavascriptInterface` on an untrusted page, `setAllowUniversalAccessFromFileURLs`,
`MODE_WORLD_READABLE`, external-storage secret writes, unparameterized provider
queries, mutable `PendingIntent`, and App-Link filters lacking `autoVerify`.

## 5. Sanitizers / safe patterns

**Safe:** `android:exported="false"` (or omitted with no intent-filter) for
internal components; `android:permission` with a **signature-level** custom
permission on exported components; WebView with JS disabled *or*
`addJavascriptInterface` only on bundled/trusted content and `@JavascriptInterface`
annotation (API 17+); `setAllowFileAccess(false)` /
`setAllowUniversalAccessFromFileURLs(false)`; secrets in the **Android Keystore**
(`AndroidKeyStore`) or `EncryptedSharedPreferences`/`EncryptedFile` (Jetpack
Security); `MODE_PRIVATE` storage inside app-internal dirs; parameterized
provider queries with a `UriMatcher` + projection allowlist; App Links with
`android:autoVerify="true"` **and** a hosted `assetlinks.json`; `CertificatePinner`
or a pinned `network_security_config`; immutable `PendingIntent`
(`FLAG_IMMUTABLE`); `allowBackup="false"`.

**Fails / not a real sanitizer:**
- `exported="true"` "protected" by a `normal`-protection-level custom permission —
  any app can request it; only `signature` binds to your signing key.
- Client-side jailbreak/root or "trusted host" string checks the user's device (and
  a repackager) fully controls.
- WebView URL allowlists using `startsWith`/`contains` on the host — bypassable with
  `evil.com/app.example.com`, userinfo `@`, or subdomain tricks.
- Custom-scheme deep links with **no source validation** — any app/website can fire
  them; only App Links with `autoVerify` + `assetlinks.json` bind the domain.
- Certificate pinning with a `HostnameVerifier` that returns `true`, or a
  `TrustManager` that accepts all chains — pinning nullified.
- "Encrypting" with a hardcoded key baked into the APK (see hardcoded-secrets).

## 6. Detection methodology

1. **Inspect the manifest first** — decompile with `apktool d app.apk` and read
   `AndroidManifest.xml`. Enumerate every exported component and check for a
   `signature` permission; flag deep-link/App-Link filters, `usesCleartextTraffic`,
   `allowBackup`, `debuggable`.
   ```
   rg -n 'exported="true"' AndroidManifest.xml
   rg -n 'usesCleartextTraffic|allowBackup|android:debuggable|android:autoVerify' AndroidManifest.xml
   rg -n 'intent-filter|android:scheme|android:host' AndroidManifest.xml
   ```
2. **Grep the code (smali/Java/Kotlin) for dangerous sinks:**
   ```
   rg -n 'addJavascriptInterface|setJavaScriptEnabled|setAllowFileAccess|setAllowUniversalAccessFromFileURLs|loadUrl' 
   rg -n 'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getExternalStorage|getExternalFilesDir|openFileOutput' 
   rg -n 'getSharedPreferences|rawQuery|execSQL|PendingIntent\.(getActivity|getBroadcast|getService)' 
   rg -n 'getIntent\(\)\.getData|getStringExtra|onNewIntent|shouldOverrideUrlLoading' 
   ```
3. **Confirm the trust crossing:** is the exported component reachable from another
   app? Does the WebView load or bridge to a URL derived from an intent/remote page?
   Is the stored value sensitive (token/PII/key)?
4. **Check for a real control (§5):** signature permission, Keystore/Encrypted*,
   `autoVerify`+`assetlinks.json`, immutable PendingIntent, correct pinning.
5. **Check network config:** open `res/xml/network_security_config.xml` — is
   cleartext permitted, or `<trust-anchors>` including `user` CAs (defeats pinning)?
6. **Trace secrets:** grep `res/values/strings.xml`, `google-services.json`,
   and `strings` on the binary for API keys / Firebase URLs (cross-ref
   hardcoded-secrets skill for the leak itself).

## 7. Modern & niche variants

- **Intent redirection / "intent hijacking":** an exported component that extracts a
  nested `Intent`/URL from extras and `startActivity`/`startService` on it — lets a
  malicious app pivot through your app's privileges into non-exported components.
- **Read-only ContentProvider path traversal:** `openFile` implementing a file
  provider that resolves `../` in the requested path, leaking app-private files.
- **PendingIntent hijack:** a *mutable* `PendingIntent` with an implicit base intent
  handed to another app, which fills in the blank component/action.
- **`autoVerify` present but broken:** filter declares `autoVerify` but the hosted
  `/.well-known/assetlinks.json` is missing/mismatched → link falls back to the
  chooser and any app can claim it.
- **WebView `file://` universal access XSS→exfil:** local HTML + JS bridge +
  `setAllowUniversalAccessFromFileURLs(true)` lets injected JS read arbitrary files
  and POST them out.
- **Tapjacking / overlay:** sensitive screens without
  `filterTouchesWhenObscured`/`FLAG_SECURE`, enabling overlay-driven clickjacking.
- **Task hijacking (StrandHogg):** exported launcher activity with
  `taskAffinity`/`singleTask` misconfig allowing UI spoofing.
- **Firebase/backend misconfig referenced in the app:** world-readable Realtime DB /
  Storage bucket URL embedded in resources (the app is the *discovery* vector; the
  finding may become a backend HTTP issue — see §11).

## 8. Common false positives

- `exported="true"` on a `LAUNCHER` activity or a component gated by a genuine
  `signature`-level permission.
- WebView with JS enabled but loading only bundled `file:///android_asset` content
  and no `addJavascriptInterface`.
- `getExternalStorage` writes of non-sensitive, already-public media.
- `allowBackup`/cleartext defaults on a debug-only build variant that is not shipped.
- Deep links that only route to a read-only, non-privileged screen with no
  parameter-driven action.

## 9. Severity & exploitability

Base **Medium–High**. **Critical** when a WebView JS bridge or deep-link→intent
chain yields `CODE_EXEC`, or an exported provider/backup leaks credentials/tokens
(`SECRET_LEAK`) usable against the backend. Lower when the exposed data/action is
non-sensitive or the component requires a signature permission. Uplift when the
storage/JS-bridge leak feeds an account-takeover chain. Score with
`references/severity-model.md`.

## 10. Remediation

Set `exported="false"` unless truly needed; protect required exports with a
`signature` custom permission. Disable JS unless required; never
`addJavascriptInterface` to untrusted content; disable file-URL universal access.
Store secrets in the Android Keystore / `EncryptedSharedPreferences`; keep files in
`MODE_PRIVATE` internal storage. Use verified App Links (`autoVerify` +
`assetlinks.json`) and validate deep-link parameters. Enforce HTTPS via
`network_security_config` and pin certificates correctly. Use `FLAG_IMMUTABLE`
PendingIntents. Set `allowBackup="false"` and ship non-debuggable builds.

## 11. Output

Append each confirmed finding to **`findings/44-mobile-android-security.md`** using
`references/finding-template.md`. Set `Class: Mobile — Android` and the specific
`CWE` (e.g. CWE-926 exported component, CWE-919 WebView, CWE-312 cleartext storage,
CWE-749 exposed method, CWE-79 WebView XSS).

**Reachable over:** `N/A (client/on-chain)` for manifest/binary/on-device flaws.
Reproduce with device tooling, not Burp: `apktool d`/`jadx` to read the manifest and
smali; `adb shell am start`/`am broadcast`/`content query` to hit exported
components; a malicious PoC app + `Intent`/`PendingIntent` for intent hijacking;
`adb backup` to test `allowBackup`; **Frida** to hook JS bridges and pinning;
an emulator + MITM proxy to prove cleartext/pinning bypass. **Exception:** if the
finding is actually the *backend* (e.g. an open Firebase/REST endpoint the app
discloses), set `Reachable over: Mobile/API` and include one Burp-pasteable HTTP
request to that endpoint.

**Primitives (controlled):** provides `SECRET_LEAK`(insecure storage —
world-readable prefs, external files, backup, embedded keys), `CODE_EXEC`(WebView
JS bridge / deep-link→intent redirection), `DATA_READ`(exported provider /
component); consumes `none`.

## References
- CWE-926, CWE-919, CWE-312, CWE-749, CWE-79; OWASP Mobile Top 10 (M1–M10) &
  OWASP MASVS/MASTG; Android developer security guidance (App components,
  WebView, Data & file storage, App Links, Network security config).
