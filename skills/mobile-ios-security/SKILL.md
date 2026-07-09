---
name: mobile-ios-security
description: >-
  SAST detection methodology for iOS app security flaws (CWE-312) — insecure
  local storage (NSUserDefaults/plist/Core Data, Keychain misuse), pasteboard
  leakage, custom-URL-scheme & universal-link hijacking, WKWebView/UIWebView JS
  bridge & file access, ATS disabled, pinning bypass, weak jailbreak detection,
  screenshot caching, and secrets in Info.plist/binary. Use when reviewing an
  iOS app, Info.plist, or decompiled binary. Writes confirmed findings to
  findings/45-mobile-ios-security.md.
---

# Mobile — iOS Security — SAST Methodology

**Class:** Mobile — iOS · **CWE-312** (and CWE-522, CWE-919, CWE-79) · **OWASP:** Mobile Top 10 / MASVS
**Findings file:** `findings/45-mobile-ios-security.md`

## 1. Overview

iOS security flaws arise when sensitive data is persisted or transmitted without
the protection iOS makes available (data-protection classes, Keychain access
control, ATS), or when a trust boundary — a custom URL scheme, universal link, or
`WKWebView` bridge — drives a privileged action from attacker-controlled input.
The core test: does secret/PII data land in a store readable without the device
passcode (or off-device), or does an externally-invokable entry point reach a
sink without source validation? These flaws live in **Info.plist, on-device
storage, and the app binary**, so most are not Burp-reproducible (see §11).

## 2. Where it lives

- `Info.plist`: `NSAppTransportSecurity` (`NSAllowsArbitraryLoads`),
  `CFBundleURLTypes` (custom URL schemes), `com.apple.developer.associated-domains`
  (universal links), background modes, and any embedded config/keys.
- Storage code (Swift/Obj-C): `UserDefaults`/`NSUserDefaults`, plist writes,
  Core Data, `Keychain`/`SecItemAdd` with `kSecAttrAccessible*`, `Data.write(to:)`.
- `UIPasteboard.general` reads/writes of sensitive strings.
- URL-handling: `application(_:open:options:)`, `SceneDelegate`
  `openURLContexts`, `NSUserActivity`/`continue userActivity` for universal links.
- WebView code: `WKWebView`, `WKUserContentController`
  (`add(_:name:)` message handlers), `evaluateJavaScript`, `loadFileURL`,
  `allowsUniversalAccessFromFileURLs`; legacy `UIWebView`.
- Networking: `URLSession`/`URLSessionDelegate`
  `didReceive challenge` (pinning), pinning libs (TrustKit).
- Anti-tamper: jailbreak-detection helpers; screenshot/snapshot handling in
  `applicationDidEnterBackground`.

## 3. Sources (tainted input)

Externally-controlled entry points: **custom URL scheme** invocations and
**universal links** (any app/webpage can open `myapp://…`; universal-link URLs
can be crafted), **pasteboard** contents written by other apps, JavaScript in a
`WKWebView` (loaded remote page or MITM-injected over cleartext), and IPC via
**app extensions**/shared app-group containers. Second-order: values stored
insecurely (NSUserDefaults/plist/Keychain-with-weak-class) and later trusted.
Off-device: an iTunes/iCloud backup or a stolen/jailbroken device exposing the
app sandbox.

## 4. Sinks (dangerous operations)

```xml
<!-- Info.plist — dangerous -->
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSAllowsArbitraryLoads</key><true/>   <!-- ATS off globally → cleartext/MITM allowed -->
</dict>
<key>CFBundleURLTypes</key>                    <!-- custom scheme any app can invoke -->
<array><dict><key>CFBundleURLSchemes</key><array><string>myapp</string></array></dict></array>
<key>API_SECRET</key><string>sk_live_abc123</string>  <!-- secret embedded in plist -->
```
```swift
// Swift — dangerous storage / Keychain
UserDefaults.standard.set(authToken, forKey: "token")      // plaintext, unencrypted, in backup
let q: [String:Any] = [ kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways,  // available with device locked / off-device
    kSecValueData as String: token.data(using: .utf8)! ]
SecItemAdd(q as CFDictionary, nil)
try token.write(to: docsURL, atomically: true, encoding: .utf8)   // no data-protection class
UIPasteboard.general.string = creditCardNumber              // leaks to every app + Handoff
```
```swift
// Swift — dangerous WebView / URL handling
let web = WKWebView()
web.configuration.preferences.javaScriptEnabled = true
web.configuration.userContentController.add(self, name: "native")  // JS→native bridge
web.evaluateJavaScript("render('\(userControlled)')")       // JS injection into bridge
web.configuration.preferences.setValue(true, forKey: "allowUniversalAccessFromFileURLs")
func application(_ a: UIApplication, open url: URL, options: [...]) -> Bool {
    performSensitiveAction(url.queryParam("cmd"))           // NO source validation on scheme
}
```
```objc
// Obj-C — dangerous: deprecated UIWebView (no bridge sandboxing, unpatched)
UIWebView *w = [[UIWebView alloc] init];
[w stringByEvaluatingJavaScriptFromString: input];
```

Dangerous patterns marked above: `NSAllowsArbitraryLoads`,
`kSecAttrAccessibleAlways`, plaintext `UserDefaults`/plist/file secrets,
`UIPasteboard` of sensitive data, `evaluateJavaScript` with interpolated input,
`allowUniversalAccessFromFileURLs`, URL-scheme handlers with no source check, and
deprecated `UIWebView`.

## 5. Sanitizers / safe patterns

**Safe:** Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (or
`…AfterFirstUnlockThisDeviceOnly`) and, for high-value secrets, `SecAccessControl`
with biometry/`.userPresence`; files/Core Data protected with
`.completeFileProtection` / `NSFileProtectionComplete`; never storing secrets in
`UserDefaults`/plist. ATS **on** (no `NSAllowsArbitraryLoads`; per-domain
exceptions only with justification). Universal links (associated domains +
`apple-app-site-association`) instead of custom schemes, and **validating the
source/parameters** of any incoming URL. `WKWebView` (not `UIWebView`) with JS
disabled unless required, message handlers that validate payloads, and no
universal file access. Certificate pinning via `URLSessionDelegate` comparing the
server public key/SPKI hash. Marking sensitive views `isSecureTextEntry` and
covering the screen in `applicationDidEnterBackground` to prevent snapshot caching.
Clearing the pasteboard / using `UIPasteboard` with `expirationDate` and
`localOnly`.

**Fails / not a real sanitizer:**
- Keychain used but with `kSecAttrAccessibleAlways`/`…AlwaysThisDeviceOnly` — no
  passcode gate; readable on a jailbroken/backed-up device.
- Client-side jailbreak detection (checking for `/Applications/Cydia.app`,
  `fork()`, sandbox writes) — trivially bypassed with Frida/Liberty; never a
  control, only a speed bump.
- URL-scheme "validation" that trusts a `source`/`referrer` query param the caller
  supplies, or a scheme collision another app can also register.
- Pinning implemented but the `URLSessionDelegate` calls
  `completionHandler(.useCredential, serverTrust)` without comparing keys — accepts
  any cert.
- "Obfuscated"/XOR-ed secret in the binary — recoverable with `strings`/Hopper
  (cross-ref hardcoded-secrets).
- Universal link declared but `apple-app-site-association` misconfigured, so the
  app also keeps an insecure custom-scheme fallback.

## 6. Detection methodology

1. **Inspect `Info.plist` first** (convert binary plist with `plutil -convert xml1`
   or read via `otool`/`ideviceinstaller` pull). Check ATS, URL types, associated
   domains, and embedded keys.
   ```
   rg -n 'NSAllowsArbitraryLoads|NSAppTransportSecurity|CFBundleURLSchemes|associated-domains' Info.plist
   ```
2. **Grep the source/binary strings for dangerous sinks:**
   ```
   rg -n 'kSecAttrAccessibleAlways|SecItemAdd|kSecAttrAccessible' 
   rg -n 'UserDefaults|NSUserDefaults|UIPasteboard' 
   rg -n 'evaluateJavaScript|WKUserContentController|allowUniversalAccessFromFileURLs|UIWebView' 
   rg -n 'application\(.*open url|openURLContexts|continue userActivity|NSUserActivity' 
   ```
3. **Confirm the data is sensitive** (token/PII/key) and the store is
   passcode-unprotected or off-device-recoverable; or the WebView/URL handler
   reaches a privileged sink from external input.
4. **Check for a real control (§5):** correct `kSecAttrAccessible*ThisDeviceOnly`,
   file-protection class, ATS on, source-validated universal links, key-pinned
   session, snapshot cover.
5. **Test IPC surface:** enumerate custom schemes and app extensions/app-group
   containers shared with other apps.
6. **Trace secrets in the binary:** `strings`/Hopper/`nm` on the Mach-O and any
   bundled `.plist`/`.json`; cross-ref hardcoded-secrets for the leak.

## 7. Modern & niche variants

- **Keychain data-protection downgrade:** item added with `kSecAttrAccessibleAlways`
  so it survives in an unencrypted iTunes backup and is readable while locked.
- **Pasteboard exfil via Handoff/Universal Clipboard:** sensitive value on the
  general pasteboard syncs to the user's other devices and is readable by any app.
- **Snapshot caching:** the app backgrounds a screen showing a password/token; iOS
  stores a `.ktx`/snapshot in `Library/Caches/Snapshots` in cleartext.
- **URL-scheme command injection:** `myapp://pay?to=…&amount=…` reaching a money
  action without a confirmation or source check — any web page can trigger it.
- **Universal-link `aasa` gap:** app claims a domain but the file is stale/missing,
  so links open in Safari or a competing app claims them.
- **WKWebView message-handler injection:** JS on a loaded page posts to a
  `WKScriptMessageHandler` that maps message names to native selectors without an
  allowlist (`CODE_EXEC`-adjacent within app entitlements).
- **App-extension / app-group leakage:** secrets written to a shared container that
  a less-trusted extension (or a repackaged extension) can read.
- **Deprecated `UIWebView`** anywhere — unpatched, no per-frame origin controls.

## 8. Common false positives

- `UserDefaults` holding only non-sensitive UI preferences/flags.
- Keychain items correctly using `…WhenUnlockedThisDeviceOnly` with access control.
- ATS exception scoped to a single well-justified media/CDN domain over TLS.
- A custom scheme routing only to a read-only, non-privileged screen with validated,
  non-actionable parameters.
- Pasteboard writes the user explicitly initiated (a "copy" button) of non-secret
  content.

## 9. Severity & exploitability

Base **Medium–High**. **High/Critical** when a Keychain/plist/pasteboard leak
yields credentials or session tokens (`SECRET_LEAK`) usable against the backend,
or a URL-scheme/WebView bridge drives a sensitive action. Higher on a jailbroken/
lost-device threat model where storage is trivially read; lower when the data is
non-sensitive or protected `ThisDeviceOnly` with a passcode. Uplift when the leak
feeds an account-takeover chain. Score with `references/severity-model.md`.

## 10. Remediation

Store secrets only in the Keychain with `…WhenUnlockedThisDeviceOnly` (biometric
`SecAccessControl` for high value); never in `UserDefaults`/plist. Apply
`NSFileProtectionComplete` to sensitive files/Core Data. Keep ATS enabled; remove
`NSAllowsArbitraryLoads`. Prefer verified universal links and validate the source
and parameters of every incoming URL. Use `WKWebView`, disable JS where possible,
validate message-handler payloads, and disable universal file access. Pin the
server public key in `URLSessionDelegate`. Cover sensitive screens on background to
prevent snapshot caching and keep secrets out of the shipped binary.

## 11. Output

Append each confirmed finding to **`findings/45-mobile-ios-security.md`** using
`references/finding-template.md`. Set `Class: Mobile — iOS` and the specific `CWE`
(e.g. CWE-312 cleartext storage, CWE-522 insufficiently protected credentials,
CWE-919 WebView, CWE-79 WebView XSS).

**Reachable over:** `N/A (client/on-chain)` for plist/storage/binary flaws.
Reproduce with device tooling, not Burp: `plutil`/`otool` to read `Info.plist`;
pull the app container from a jailbroken **device** (or Xcode container download)
to inspect `UserDefaults`/plist/Core Data files; **Keychain-Dumper** to prove weak
access classes; **Frida** to hook `SecItem*`, WebView message handlers, pinning,
and jailbreak checks; **Hopper**/`strings` on the Mach-O for embedded secrets;
`xcrun simctl openurl` / another app to fire custom schemes; a MITM proxy to prove
ATS-off/pinning-bypass. **Exception:** if the finding is actually a *backend* HTTP
API the app talks to, set `Reachable over: Mobile/API` and include one
Burp-pasteable request.

**Primitives (controlled):** provides `SECRET_LEAK`(Keychain misuse / plist /
pasteboard / embedded binary secret), `DATA_READ`(insecure local store / app-group
container); consumes `none`.

## References
- CWE-312, CWE-522, CWE-919, CWE-79; OWASP Mobile Top 10 (M1–M10) & OWASP
  MASVS/MASTG; Apple developer docs (Keychain Services & data protection classes,
  App Transport Security, Universal Links, WKWebView, UIPasteboard).
