# k1d command line

The same analyzer as the website, run on your machine or in CI. Nothing is uploaded. Needs Node 20+; no dependencies.

```bash
node cli/k1d.mjs scan  app-release.apk --snapshot k1d-baseline.json      # free
node cli/k1d.mjs scan  app.apk --recording capture.pcap                  # free: app file + recording
node cli/k1d.mjs diff  old.apk new.apk                                   # free: what changed between builds
node cli/k1d.mjs check app-release.aab --baseline k1d-baseline.json      # Pro: release gate
```

`diff` and `check` accept app files or snapshot JSON files on either side.

## Release check (`k1d check`, Pro / Monitoring / Enterprise)

Compares the build with a baseline snapshot and exits:

| Exit code | Meaning |
|---|---|
| 0 | No blocking changes (or first run: baseline saved) |
| 1 | Blocking changes: the table lists them |
| 3 | License missing, expired or not covering this app |

Blocking by default: `new-cn-sdk`, `new-cn-host`, `new-secret`, `new-tracking-sdk`, `new-high-permission`, `consent-default`. Change with `--fail-on new-cn-sdk,new-secret`. Other change kinds (`new-sdk`, `new-host`, `new-cleartext-host`, `new-permission`, `risk-area`, `target-sdk`, removals) are reported but don't block unless listed.

`--update-baseline` writes the new snapshot when the check passes. In GitHub Actions the change table is added to the job summary.

The license key goes in `K1D_LICENSE` (or `--license`). Keys are verified offline with k1d's public key; no network call. Plans: https://hellohi6228-code.github.io/k1d/publishers.html

## GitHub Action

```yaml
- name: k1d release check
  uses: hellohi6228-code/k1d@main
  with:
    file: app/build/outputs/bundle/release/app-release.aab
    baseline: k1d-baseline.json
    license: ${{ secrets.K1D_LICENSE }}
```

## Evidence report (`k1d report`, Pro and up)

```bash
node cli/k1d.mjs report app.apk --recording capture.pcap --out report.html --json evidence.json
node cli/k1d.mjs report app.apk --out report.html --brand "Example LLP" --brand-note "Matter 2026-17"   # Enterprise: white-label
```

One self-contained bilingual (EN/ZH) HTML file: input files with SHA-256, analyzer and knowledge-base versions, every risk area with findings / why it may matter / not scanned, runtime hosts with before-consent markers, SDKs (with "connected in recording"), China-linked endpoints, permissions, credentials (masked), coverage and limits. Print to PDF for counsel. `--json` writes the full result next to it.

## Store watch (`k1d watch`, Monitoring and Enterprise)

```bash
node cli/k1d.mjs watch watchlist.json --state k1d-watch-state.json --snapshots snapshots/
```

`watchlist.json`: `{"apps": [{"app": "com.example.game", "iosId": 1234567890, "country": "us"}]}`. Reads the public Google Play listing and Apple's public lookup API (no app files are downloaded), compares with the last run, and marks each live version "checked by k1d" when a snapshot with that app ID and version exists. Exit code 1 when a new release went live without a check.

Run it daily from GitHub Actions:

```yaml
on:
  schedule: [{ cron: '0 13 * * *' }]
  workflow_dispatch:
jobs:
  watch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with: { repository: hellohi6228-code/k1d, path: k1d }
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: node k1d/cli/k1d.mjs watch watchlist.json --state k1d-watch-state.json --snapshots snapshots
        env: { K1D_LICENSE: '${{ secrets.K1D_LICENSE }}' }
      - run: git config user.name k1d && git config user.email k1d@users.noreply.github.com && git add k1d-watch-state.json && git commit -m "store watch" || true && git push
```

A failed run sends GitHub's usual failure email: that is the alert.

## Portfolio dashboard (`k1d portfolio`, Enterprise)

```bash
node cli/k1d.mjs portfolio snapshots/ --out dashboard.html --brand "Example Group"
```

One HTML page across every app's snapshots: latest version, SDK counts, China-nexus SDKs and hosts, risk areas with findings, and the changes since each app's previous check.

## Automated Android runtime test (k1d staff, Health Check and Monitoring)

```bash
node tools/runtime/run.mjs app.apks --out runs/game-2026-11-18 --idle 60 --explore 300
```

Needs the Android SDK and an emulator (default AVD `k1d_Pixel`). Installs the app, clears its data, records Wi-Fi traffic through the emulator's netsim, runs: idle launch → decline consent → answer an age question with 12 → accept consent → random play (Android monkey), with a screenshot and timestamp for each step, then writes `recording.pcap`, `timeline.json`, `screens/` and `report.html`.
