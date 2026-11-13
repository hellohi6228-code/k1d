# k1d — what's inside this app?

**Live:** https://hellohi6228-code.github.io/k1d/

k1d reads a mobile app file **in your browser** and shows what's inside it. Anyone can use it on an app they obtained lawfully: an app on their own phone, or an app their company publishes. Use it to check whether an app you rely on embeds trackers or connects to servers you wouldn't expect. The file is never uploaded, and there is no server.

| Platform | Formats |
|---|---|
| Android | `.apk`, `.aab` (App Bundle), `.xapk`, `.apks`, `.apkm` (split bundles) |
| iOS | `.ipa` |

## What it reports

- **Embedded SDKs**, with evidence and a confidence level. SDKs with China-nexus indicators are flagged.
  - Android: Java/Kotlin class packages, native libraries, manifest meta-data, config keys.
  - iOS: embedded frameworks, linked libraries, resource bundles, Info.plist keys, URL schemes, queried apps, Objective-C class names.
- **Data access.** Android permissions, or iOS usage-description keys with the app's own stated reason, plus capability frameworks (AdSupport/IDFA, App Tracking Transparency, StoreKit, CoreLocation, …).
- **Declared data (iOS).** Every privacy manifest (`PrivacyInfo.xcprivacy`) from the app and its SDKs: the data types collected, whether each is linked to identity or used for tracking, and tracking domains.
- **Endpoints.** URLs found in code, resources, assets, native/Mach-O string sections, plists, privacy manifests and associated domains. Hosts on PRC-headquartered clouds and `.cn` domains are flagged, as are cleartext connections.
- **App details & signing.**
  - Android: signing certificate (v1/v2/v3), exported components, cleartext/backup/debuggable flags.
  - iOS: code-signing certificate (leaf picked from the CMS chain), Team ID, entitlements, provisioning profile, store metadata, App Transport Security exceptions, App Store (FairPlay) encryption status, app extensions, background modes.
- **Privacy-policy check.** Paste the policy (EN or ZH) to see which detected SDKs and data categories it names, with excerpts, plus any statements about where data is stored.
- **Why this may matter.** Draft notes tying observations to COPPA, the DOJ Data Security Program, auto-renewal law, VPPA, UDAP and Apple's tracking rules. These are not legal conclusions.
- **Export.** JSON or print to PDF. The UI is in English and Simplified Chinese.

## Limits (also shown in the app)

- Static analysis only: the app isn't run and no traffic is captured. Packaged code isn't proof that it runs.
- iOS apps from the App Store have **FairPlay-encrypted** executables. For those, k1d can't read code strings or class names. It still reads frameworks, bundles, Info.plist, privacy manifests and entitlements, but SDKs linked statically into the encrypted executable can be missed. k1d does not decrypt apps.
- The SDK and infrastructure knowledge base (`site/kb/`) is an **unverified starter seed**.
- Certificates are read, not verified.

## Run locally

```bash
node tools/serve.mjs 8080
```

Then open http://localhost:8080/. The local server also serves the test fixtures at `/__fixtures__/` for manual testing. GitHub Pages does not.

## Tests

```bash
node --test tests/*.test.mjs
node scripts/check-claims.mjs
```

Synthetic fixtures live in `tests/fixtures/`:

- `k1d-demo.apk` and `k1d-demo.aab` are built by `tools/build-demo-apk.mjs` using Google's `aapt2` (binary and protobuf manifests). Their ground truth (package, version, permissions) comes from `aapt2`, and the certificate fingerprint from `openssl`.
- `k1d-demo.ipa` is built by `tools/build-demo-ipa.mjs`. It contains a binary Info.plist, arm64 Mach-O executables with load commands and string sections, a code signature whose CMS and certificate chain come from `openssl`, privacy manifests, frameworks, an App Store-encrypted framework, a provisioning profile and store metadata.
- The XAPK/APKM path is tested by wrapping the APK.

`check-claims` fails the build if the site contains verdict language ("violates", "compliant", 违法, 合规, …).

## Layout

```
site/            the web app served by GitHub Pages
  js/            zip, AXML + protobuf manifest, DEX, plist, Mach-O, code signature, certificate parsers;
                 Android + iOS analyzers; policy check; notes; UI
  kb/            SDK signatures (Android + iOS), infrastructure operators, permission/usage categories
tests/           node:test suites + synthetic fixtures + ground truth
tools/           fixture builders, zip writer, local static server
scripts/         banned-phrase check
```

k1d provides factual analysis, not legal advice.
