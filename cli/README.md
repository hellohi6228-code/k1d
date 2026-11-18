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
