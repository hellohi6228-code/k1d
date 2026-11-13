# k1d — what's inside this app?

**Live:** https://hellohi6228-code.github.io/k1d/

k1d reads an app or installer **in your browser** and shows what's inside it. It maps what it finds to the US legal areas where China-linked apps have faced lawsuits and enforcement. Anyone can use it on a file they obtained lawfully: an app on their own device, or one their company publishes. The file is never uploaded, and there is no server.

## Supported formats (detected by content, not file extension)

| Platform | Formats |
|---|---|
| Android | `.apk`, `.aab`, `.xapk`, `.apks`, `.apkm` |
| iOS | `.ipa` |
| macOS | `.app` in a `.zip`, `.pkg` (metadata, scripts, signer), bare Mach-O; `.dmg` is recognized and you're asked to zip the `.app` |
| Windows | `.exe` / `.dll` / `.sys` (PE: version info, imports, manifest, Authenticode signer, embedded installer payloads), `.msi`, `.msix` / `.appx` / bundles |
| Linux | ELF binaries, `.deb` (gzip), `.rpm` (metadata) |
| HarmonyOS | `.hap`, `.hsp`, `.app` packs |
| Browser extensions | `.crx` (v2/v3), `.xpi`, extension `.zip` |
| WeChat mini-programs | `.wxapkg` (unencrypted) |
| Electron | `app.asar` (standalone, inside installers, macOS bundles and `.deb`) |
| Anything else | Generic scan for URLs and credentials, with the limit stated |

## What it reports

- **Risk areas (13).** Each area lists the signals found in the file, why the area may matter (with public cases and laws), and what to verify next. The areas:
  - data transfers to countries of concern (DSP, PADFA, state AG suits)
  - children and teens (COPPA, SCOPE, age-signal APIs)
  - biometrics (BIPA)
  - wiretap/pen-register SDK claims (CIPA, MHMDA)
  - location and health data
  - video viewing (VPPA)
  - subscriptions (ARL, ROSCA)
  - loot boxes and social casino
  - AI chatbots (SB 243)
  - data security, including hard-coded cloud keys
  - intrusive device access
  - disclosures vs. behavior
  - foreign-adversary-controlled apps (PAFACA)

  These are draft notes, not legal conclusions.
- **SDKs (94 in the knowledge base).** Includes China-origin ad, analytics and push SDKs, face/voice biometric SDKs, session replay, video players, AI model APIs (US and PRC), age-assurance APIs, and PC game services and anti-cheat. Each comes with evidence and a confidence level.
- **Data access.**
  - Android permissions.
  - iOS usage keys, with the app's stated reason.
  - Windows capability APIs (keyboard hooks, credential access, hardware IDs, …) and admin rights.
  - MSIX capabilities, HarmonyOS permissions, extension permissions, mini-program APIs and scopes.
- **Declared data (iOS/macOS).** Privacy manifests from the app and every SDK.
- **Endpoints.** Hosts on PRC clouds and `.cn` domains are flagged, as are cleartext connections.
- **Hard-coded credentials.** AWS, Alibaba Cloud, Tencent Cloud, private keys, GitHub, Slack, Stripe, FCM and OpenAI-style keys. Values are always masked.
- **Signing.** APK v1–v3, iOS/macOS code signing (Team ID, entitlements), Authenticode (signer chosen by serial number), MSIX, pkg.
- **Privacy-policy check (EN/ZH)** and **export** (JSON, print to PDF).

## Run locally

```bash
node tools/serve.mjs 8080
```

Then open http://localhost:8080/. The local server also serves the test fixtures at `/__fixtures__/`.

## Tests

```bash
node --test tests/*.test.mjs
node scripts/check-claims.mjs
```

- **Android:** ground truth comes from Google's `aapt2` (binary and protobuf manifests) and `openssl`.
- **iOS:** a synthetic IPA with an `openssl` CMS chain.
- **Other formats:** fixtures built by `tools/build-demo-formats.mjs` (signers from `openssl`). `IdleQuest.msi` is created by Windows Installer itself.
- **Real binaries:** `tests/real-binaries.test.mjs` checks real signed Windows executables against the thumbprints and version info that Windows reports. It is skipped where the files aren't present, for example in CI.

`check-claims` fails the build if the site contains verdict language ("violates", "compliant", 违法, 合规, …).

## Limits

- Static analysis only. Presence of code isn't proof it runs.
- Encrypted App Store executables and compressed installer payloads are only partly readable. The UI says so whenever this applies.
- The knowledge base is an **unverified starter seed**.
- Signatures are read, not verified.

k1d provides factual analysis, not legal advice.
