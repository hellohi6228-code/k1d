# k1d — static evidence about Android apps

k1d reads an Android app file (APK, XAPK or APKS) **in your browser** and reports:

- **Embedded SDKs**: matched by code package, native library, manifest key, config key and endpoint domain, with the evidence and a confidence level. SDKs with China-nexus indicators are flagged.
- **Permissions**: grouped by the personal-data category they unlock.
- **Hard-coded endpoints**: URLs found in DEX code, `resources.arsc`, assets and native `.so` libraries. Hosts on PRC-headquartered clouds or `.cn` domains are flagged.
- **Manifest and signing facts**: exported components, cleartext/backup/debuggable flags, meta-data, package queries, and the signing certificate (SHA-256 fingerprint, subject, issuer, validity) from the v2/v3 block or v1 PKCS#7.
- **Privacy-policy check**: paste the policy (EN or ZH) to see which detected SDKs and data categories it names, with excerpts, plus any statements about where data is stored.
- **Why this may matter**: draft notes that tie observations to COPPA, the DOJ Data Security Program, auto-renewal law, VPPA and UDAP. These are not legal conclusions.
- **Export**: JSON (including the authorization record) or print to PDF. UI in English and Simplified Chinese.

The file is never uploaded. The site is static, and there is no server.

## Use it

Open **https://hellohi6228-code.github.io/k1d/**, then drop in an APK or click **Try the synthetic demo APK**.

Run it locally (Node 18+):

```bash
node tools/serve.mjs 8080
```

Then open http://localhost:8080/.

## Tests

```bash
node --test tests/*.test.mjs
node scripts/check-claims.mjs
```

The tests run the analyzer on `site/demo/k1d-demo.apk`, a synthetic APK built by `tools/build-demo-apk.mjs`. The expected values (package, version, permissions, certificate fingerprint) come from Google's `aapt2` and from `openssl`, not from k1d itself. `check-claims` fails the build if the site contains verdict language ("violates", "compliant", 违法, 合规, …).

To rebuild the demo APK you need the Android SDK (build-tools + a platform) and openssl:

```bash
node tools/build-demo-apk.mjs
```

## What it does not do (yet)

- No dynamic analysis: nothing is run, and no traffic is captured. Presence of code or a URL is not proof that it is used.
- The SDK and infrastructure knowledge base (`site/kb/`) is an **unverified starter seed** built from public package names. It needs expert review before client use.
- Signatures are read, not verified.
- No `.aab` support (export a universal APK first) and no iOS.
- The authorization step is a local attestation. A static site cannot verify app ownership. Server-side ownership verification is part of the full platform design.

The full platform (accounts, ownership verification, a dynamic analysis sandbox, a rule engine and reviewed rule packs) has not been built yet.

## Layout

```
site/            the web app served by GitHub Pages
  js/            zip, AXML, DEX and certificate parsers; analyzer; policy check; notes; UI
  kb/            SDK signatures, infrastructure operators, permission categories (seed data)
  demo/          synthetic demo APK
tests/           node:test suite + ground truth fixture
tools/           demo APK builder, local static server
scripts/         banned-phrase check
```

k1d provides factual analysis, not legal advice.
