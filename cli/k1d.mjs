#!/usr/bin/env node
// k1d command line. Same analyzer as the website, run locally; nothing is uploaded.
//
//   k1d scan  <app> [--recording <pcap|ndjson>] [--json <out.json>] [--snapshot <out.json>]
//   k1d diff  <old.apk|old.json> <new.apk|new.json> [--markdown]
//   k1d check <app> --baseline <baseline.json> [--fail-on a,b] [--update-baseline]   (Pro license)
//   k1d report <app> [--recording f] --out report.html [--brand "Firm"]             (Pro; --brand needs Enterprise)
//   k1d watch <watchlist.json> [--state watch-state.json] [--snapshots dir]          (Monitoring)
//   k1d portfolio <snapshot dir|files…> --out dashboard.html [--brand "Group"]        (Enterprise)
//   k1d license                                                                      (show the K1D_LICENSE in use)
//
// scan and diff are free. check and report need a Pro, Monitoring or Enterprise license key in
// K1D_LICENSE (or --license); watch needs Monitoring or Enterprise; portfolio needs Enterprise.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { renderReport } from './report.mjs';
import { storeVersions, compareWatch, watchMarkdown, loadSnapshots, portfolioHtml } from './monitor.mjs';
import { scanFile, snapshot, diffSnapshots, applyPolicy, changesMarkdown, loadSnapshotOrScan, DEFAULT_FAIL_ON } from './lib.mjs';
import { verifyLicense } from './license.mjs';

const argv = process.argv.slice(2);
const cmd = argv[0];
const flags = {};
const pos = [];
for (let i = 1; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith('--')) {
    const k = a.slice(2);
    const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    flags[k] = v;
  } else pos.push(a);
}
const out = (s) => process.stdout.write(`${s}\n`);
function sha256File(f) {
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(f, 'r');
  const buf = Buffer.allocUnsafe(8 * 1024 * 1024);
  let n;
  while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  fs.closeSync(fd);
  return h.digest('hex');
}
const fail = (msg, code = 2) => { process.stderr.write(`k1d: ${msg}\n`); process.exit(code); };
const PUBLISHERS = 'https://hellohi6228-code.github.io/k1d/publishers.html';

async function main() {
  if (cmd === 'scan') {
    if (!pos[0]) fail('usage: k1d scan <app> [--recording <file>] [--json out.json] [--snapshot out.json]');
    const r = await scanFile(pos[0], { recording: flags.recording || null });
    const s = snapshot(r, { file: pos[0] });
    if (flags.json) fs.writeFileSync(flags.json, JSON.stringify(r, null, 1));
    if (flags.snapshot) fs.writeFileSync(flags.snapshot, `${JSON.stringify(s, null, 1)}\n`);
    out(`${s.app.id ?? s.file} ${s.app.version ?? ''} (${s.app.platform})`);
    out(`  SDKs: ${s.sdks.length} (${s.sdks.filter((x) => x.cn).length} with China-nexus indicators)`);
    out(`  Endpoints: ${s.hosts.length} (${s.hosts.filter((x) => x.cn.length).length} China-linked)`);
    out(`  Permissions: ${s.permissions.length} · Credentials: ${s.secrets.length}`);
    out(`  App type: ${s.profile.category} · Likely audience: ${s.profile.audience}`);
    out(`  Risk areas with findings: ${Object.entries(s.risks).filter(([, v]) => v === 'signals').map(([k]) => k).join(', ') || 'none'}`);
    if (r.runtime) out(`  Recording: ${r.runtime.hostsMatchingApp} of ${r.runtime.hostsContacted} servers belong to this app; ${s.sdks.filter((x) => x.seenAtRuntime).length} SDKs seen connecting`);
    return;
  }
  if (cmd === 'diff') {
    if (pos.length < 2) fail('usage: k1d diff <old> <new> [--markdown]');
    const [a, b] = await Promise.all([loadSnapshotOrScan(pos[0]), loadSnapshotOrScan(pos[1])]);
    const changes = diffSnapshots(a, b);
    if (flags.markdown) out(changesMarkdown(a, b, changes, null));
    else if (!changes.length) out('No changes in SDKs, endpoints, permissions, credentials or consent defaults.');
    else for (const c of changes) out(`[${c.severity}] ${c.en}`);
    return;
  }
  if (cmd === 'check') {
    if (!pos[0] || !flags.baseline) fail('usage: k1d check <app> --baseline <baseline.json> [--fail-on a,b] [--update-baseline]');
    const b = await loadSnapshotOrScan(pos[0]);
    const lic = verifyLicense(flags.license || process.env.K1D_LICENSE, { appId: b.app.id });
    if (!lic.ok) fail(`${lic.reason}\n  k1d check is part of k1d Pro. Plans: ${PUBLISHERS}\n  (k1d scan and k1d diff stay free.)`, 3);
    const failOn = typeof flags['fail-on'] === 'string' ? flags['fail-on'].split(',').map((x) => x.trim()) : DEFAULT_FAIL_ON;
    let a = null;
    if (fs.existsSync(flags.baseline)) a = JSON.parse(fs.readFileSync(flags.baseline, 'utf8'));
    if (!a) {
      fs.writeFileSync(flags.baseline, `${JSON.stringify(b, null, 1)}\n`);
      out(`No baseline yet: saved ${flags.baseline} from this build. Commit it; later builds are compared with it.`);
      return;
    }
    const changes = diffSnapshots(a, b);
    const policy = applyPolicy(changes, failOn);
    const md = changesMarkdown(a, b, changes, policy);
    out(md);
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${md}\n`);
    if (policy.pass && flags['update-baseline']) fs.writeFileSync(flags.baseline, `${JSON.stringify(b, null, 1)}\n`);
    process.exit(policy.pass ? 0 : 1);
  }
  if (cmd === 'report') {
    if (!pos[0] || !flags.out) fail('usage: k1d report <app> [--recording <file>] --out report.html [--json evidence.json] [--brand "Firm name"] [--brand-note "Matter 123"]');
    const r = await scanFile(pos[0], { recording: flags.recording || null });
    const lic = verifyLicense(flags.license || process.env.K1D_LICENSE, { appId: r.app?.id ?? null });
    if (!lic.ok) fail(`${lic.reason}\n  k1d report is part of k1d Pro. Plans: ${PUBLISHERS}`, 3);
    if (flags.brand && lic.license.plan !== 'enterprise') fail('--brand (white-label reports) needs an Enterprise license.', 3);
    const files = [pos[0], flags.recording].filter((f) => typeof f === 'string').map((f) => ({ name: path.basename(f), size: fs.statSync(f).size, sha256: sha256File(f) }));
    fs.writeFileSync(flags.out, renderReport(r, { files, brand: typeof flags.brand === 'string' ? flags.brand : null, brandNote: typeof flags['brand-note'] === 'string' ? flags['brand-note'] : null }));
    if (flags.json) fs.writeFileSync(flags.json, JSON.stringify({ files, generatedAt: new Date().toISOString(), result: r }, null, 1));
    out(`Wrote ${flags.out}${flags.json ? ` and ${flags.json}` : ''}. Open it in a browser and Print → Save as PDF.`);
    return;
  }
  if (cmd === 'watch') {
    if (!pos[0]) fail('usage: k1d watch <watchlist.json> [--state watch-state.json] [--snapshots dir]');
    const list = JSON.parse(fs.readFileSync(pos[0], 'utf8')).apps;
    const lic = verifyLicense(flags.license || process.env.K1D_LICENSE);
    if (!lic.ok) fail(`${lic.reason}\n  k1d watch is part of k1d Monitoring. Plans: ${PUBLISHERS}`, 3);
    if (!['monitoring', 'enterprise'].includes(lic.license.plan)) fail('k1d watch needs a Monitoring or Enterprise license.', 3);
    const covered = (a) => lic.license.apps.includes('*') || lic.license.apps.includes(a);
    const notCovered = list.filter((e) => !covered(e.app)).map((e) => e.app);
    if (notCovered.length) fail(`The license does not cover: ${notCovered.join(', ')}`, 3);
    const current = [];
    for (const e of list) current.push(await storeVersions(e));
    const stateFile = typeof flags.state === 'string' ? flags.state : 'k1d-watch-state.json';
    const prev = fs.existsSync(stateFile) ? JSON.parse(fs.readFileSync(stateFile, 'utf8')) : {};
    const { rows, state } = compareWatch(current, prev, loadSnapshots(typeof flags.snapshots === 'string' ? flags.snapshots : null));
    fs.writeFileSync(stateFile, `${JSON.stringify(state, null, 1)}\n`);
    const md = watchMarkdown(rows, current.flatMap((c) => c.errors.map((e) => `${c.app}: ${e}`)));
    out(md);
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${md}\n`);
    process.exit(rows.some((r) => !r.checked && r.isNew) ? 1 : 0);
  }
  if (cmd === 'portfolio') {
    if (!pos.length || !flags.out) fail('usage: k1d portfolio <snapshot dir|files…> --out dashboard.html [--brand "Group"]');
    const lic = verifyLicense(flags.license || process.env.K1D_LICENSE);
    if (!lic.ok || lic.license.plan !== 'enterprise') fail(`${lic.ok ? 'k1d portfolio needs an Enterprise license.' : lic.reason}\n  Plans: ${PUBLISHERS}`, 3);
    const snaps = pos.flatMap((p) => loadSnapshots(p));
    fs.writeFileSync(flags.out, portfolioHtml(snaps, { brand: typeof flags.brand === 'string' ? flags.brand : null }));
    out(`Wrote ${flags.out} (${snaps.length} snapshots).`);
    return;
  }
  if (cmd === 'license') {
    const lic = verifyLicense(flags.license || process.env.K1D_LICENSE);
    if (!lic.ok) fail(lic.reason, 3);
    out(JSON.stringify(lic.license, null, 1));
    return;
  }
  out('k1d: scan | diff | check | report | watch | portfolio | license. See cli/README.md.');
  process.exit(cmd ? 2 : 0);
}

main().catch((err) => fail(err.message || String(err)));
