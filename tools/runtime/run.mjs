#!/usr/bin/env node
// Automated Android runtime test for a Health Check (k1d staff tool).
// Boots an Android emulator, installs the app, records Wi-Fi traffic through the emulator's netsim,
// runs scripted scenarios, then writes the recording, screenshots, a timeline and the evidence report.
//
//   node tools/runtime/run.mjs <app.apk|app.apks|app.xapk|split-folder> [--avd k1d_Pixel] [--out runs/<pkg>-<time>]
//        [--scenarios idle,consent-decline,age,consent-accept,explore] [--idle 60] [--explore 300]
//        [--taps "consent-accept=540,1512;consent-decline=300,1700"]   (tap positions for canvas-drawn UIs)
//
// Scenarios (in the order given):
//   idle            launch from a cleared state and touch nothing for --idle seconds
//   consent-decline tap a Decline / Reject / Disagree / 拒绝 button if one is shown
//   age             if an age or birth-year question is shown, answer 12 (a child under 13)
//   consent-accept  tap Accept / Agree / Continue / OK / 同意 if shown
//   explore         Android "monkey" random taps for --explore events (often shows ads)
// Every tap and phase is written to timeline.json with its time, so the report can say what the app
// sent before and after each step. Nothing is sent anywhere except the app's own traffic.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { openZip, bytesSource } from '../../site/js/zip.js';
import { scanFile } from '../../cli/lib.mjs';
import { renderReport } from '../../cli/report.mjs';
import { analyzeFlows, parseFlows } from '../../cli/decrypt.mjs';
import { loadKb } from '../../cli/lib.mjs';
import { startMitm, trustCaOnDevice, setProxy, deviceIds } from './mitm.mjs';

const SDK = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT || path.join(os.homedir(), 'AppData', 'Local', 'Android', 'Sdk');
const exe = (p) => (process.platform === 'win32' ? `${p}.exe` : p);
const ADB = path.join(SDK, 'platform-tools', exe('adb'));
const EMU = path.join(SDK, 'emulator', exe('emulator'));
const NETSIM = 'http://localhost:7681';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function adb(...args) {
  const r = spawnSync(ADB, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw r.error;
  return (r.stdout ?? '').trim();
}
const adbBuf = (...args) => spawnSync(ADB, args, { maxBuffer: 64 * 1024 * 1024 }).stdout;

// ---------------------------------------------------------------- UI helpers (uiautomator)
export function parseUiNodes(xml) {
  const nodes = [];
  for (const m of xml.matchAll(/<node ([^>]+?)\/?>/g)) {
    const a = Object.fromEntries([...m[1].matchAll(/([\w-]+)="([^"]*)"/g)].map((x) => [x[1], x[2]]));
    const b = a.bounds?.match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
    if (!b) continue;
    nodes.push({ text: a.text ?? '', desc: a['content-desc'] ?? '', cls: a.class ?? '', clickable: a.clickable === 'true', x: (Number(b[1]) + Number(b[3])) >> 1, y: (Number(b[2]) + Number(b[4])) >> 1 });
  }
  return nodes;
}

export const BUTTONS = {
  decline: /^(decline|reject( all)?|disagree|do not agree|don.?t agree|no,? thanks|not now|deny|拒绝|不同意|暂不)$/i,
  accept: /^(accept( all)?|agree|i agree|agree and continue|accept and continue|continue|ok|okay|got it|allow|同意|同意并继续|接受|确定|继续|好的)$/i,
  age: /\b(age|how old|birth|birthday|year of birth)\b|年龄|出生|生日/i,
};

export function findButton(nodes, re) {
  return nodes.find((n) => (re.test(n.text.trim()) || re.test(n.desc.trim())) && (n.clickable || /Button|TextView/.test(n.cls)));
}

function uiDump() {
  adb('shell', 'uiautomator', 'dump', '/sdcard/k1d-ui.xml');
  return parseUiNodes(adb('shell', 'cat', '/sdcard/k1d-ui.xml'));
}

// ---------------------------------------------------------------- APK inputs
async function apkFiles(input, workDir) {
  const st = fs.statSync(input);
  if (st.isDirectory()) return fs.readdirSync(input).filter((f) => f.endsWith('.apk')).map((f) => path.join(input, f));
  if (/\.(apks|xapk|apkm)$/i.test(input)) {
    const zip = await openZip(bytesSource(new Uint8Array(fs.readFileSync(input))));
    const dir = path.join(workDir, 'splits');
    fs.mkdirSync(dir, { recursive: true });
    const out = [];
    for (const e of zip.entries.filter((x) => x.name.endsWith('.apk'))) {
      const f = path.join(dir, path.basename(e.name));
      fs.writeFileSync(f, await zip.readEntry(e));
      out.push(f);
    }
    return out;
  }
  return [input];
}

// ---------------------------------------------------------------- emulator + netsim
async function ensureEmulator(avd) {
  if (!adb('devices').split('\n').slice(1).some((l) => /\tdevice$/.test(l))) {
    spawn(EMU, ['-avd', avd, '-no-boot-anim', '-gpu', 'auto'], { detached: true, stdio: 'ignore' }).unref();
  }
  adb('wait-for-device');
  for (let i = 0; i < 180; i++) {
    if (adb('shell', 'getprop', 'sys.boot_completed') === '1') break;
    await sleep(2000);
  }
  // Wi-Fi sometimes stays off after a reboot inside the guest.
  if (!/Wifi is enabled/i.test(adb('shell', 'cmd', 'wifi', 'status'))) adb('shell', 'svc', 'wifi', 'enable');
  adb('shell', 'cmd', 'wifi', 'connect-network', 'AndroidWifi', 'open');
  await sleep(4000);
}

async function netsimWifiCapture() {
  const list = await fetch(`${NETSIM}/v1/captures`).then((r) => r.json());
  const caps = list.captures ?? list;
  const wifi = caps.find((c) => /wifi/i.test(c.chip_kind ?? c.chipKind ?? '')) ?? caps[0];
  if (!wifi) throw new Error('netsim reports no capture-capable chip; is the emulator using netsim Wi-Fi?');
  return wifi.id;
}
// netsim's HTTP server rejects Node fetch's PATCH body ("Incorrect state"); curl's form-encoded body works.
const setCapture = async (id, on) => {
  const r = spawnSync('curl', ['-s', '-X', 'PATCH', `${NETSIM}/v1/captures/${id}`, '-d', on ? '1' : '0'], { encoding: 'utf8' });
  const ok = new RegExp(`"state": ${on ? 'true' : 'false'}`).test(r.stdout ?? '');
  if (!ok) throw new Error(`netsim did not switch capture ${on ? 'on' : 'off'}: ${(r.stdout || r.stderr || '').slice(0, 120)}`);
};

// ---------------------------------------------------------------- main run
export async function runScenarios(input, opts = {}) {
  const avd = opts.avd ?? (opts.decrypt ? 'k1d_Root' : 'k1d_Pixel');
  const scenarios = opts.scenarios ?? ['idle', 'consent-decline', 'age', 'consent-accept', 'explore'];
  const idle = opts.idle ?? 60;
  const explore = opts.explore ?? 300;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'k1d-run-'));
  const apks = await apkFiles(input, tmp);
  const base = apks.find((f) => /base\.apk$/i.test(f)) ?? apks[0];
  const appScan = await scanFile(base);
  const pkg = appScan.app.id;
  const outDir = opts.out ?? path.join('runs', `${pkg}-${new Date().toISOString().replace(/[:.]/g, '-')}`);
  fs.mkdirSync(path.join(outDir, 'screens'), { recursive: true });
  const timeline = [];
  const mark = (event, detail = '') => { timeline.push({ t: new Date().toISOString(), event, detail }); console.log(`${new Date().toISOString()}  ${event}${detail ? `  ${detail}` : ''}`); };
  let shots = 0;
  const shot = (name) => fs.writeFileSync(path.join(outDir, 'screens', `${String(++shots).padStart(2, '0')}-${name}.png`), adbBuf('exec-out', 'screencap', '-p'));

  mark('emulator', avd);
  await ensureEmulator(avd);
  const installed = adb('shell', 'dumpsys', 'package', pkg).match(/versionName=(\S+)/)?.[1];
  if (installed && installed === appScan.app.versionName && opts.reuseInstall !== false) mark('install', `already installed: ${pkg} ${installed}`);
  else {
    mark('install', apks.map((f) => path.basename(f)).join(', '));
    const inst = adb(apks.length > 1 ? 'install-multiple' : 'install', '-r', '-g', ...apks);
    if (!/Success/.test(inst)) throw new Error(`install failed: ${inst}`);
  }
  adb('shell', 'pm', 'clear', pkg);
  mark('app data cleared', pkg);

  // Decrypting mode: mitmproxy + its CA trusted by the system + emulator proxy setting.
  let mitm = null;
  let ids = null;
  const flowLog = path.join(outDir, 'flows.jsonl');
  if (opts.decrypt) {
    if (fs.existsSync(flowLog)) fs.unlinkSync(flowLog);
    mitm = await startMitm(flowLog);
    const caName = trustCaOnDevice(adb, mitm.ca);
    setProxy(adb, true);
    mark('decryption on', `mitmproxy CA ${caName} trusted by the system; proxy 10.0.2.2:8888`);
  }

  const capId = await netsimWifiCapture();
  await setCapture(capId, false);
  await setCapture(capId, true); // restart = fresh file
  mark('capture started', `netsim ${capId}`);
  await sleep(5000);
  mark('baseline end');

  const activity = adb('shell', 'cmd', 'package', 'resolve-activity', '--brief', '-c', 'android.intent.category.LAUNCHER', pkg).split('\n').pop();
  for (const sc of scenarios) {
    if (sc === 'idle') {
      mark('launch', activity);
      adb('shell', 'am', 'start', '-W', '-n', activity);
      for (const s of [5, 20, idle]) { await sleep((s - (s === 5 ? 0 : s === 20 ? 5 : 20)) * 1000); shot(`idle-${s}s`); }
      mark('idle end', `${idle}s without input`);
    } else if (opts.taps?.[sc]) {
      // Operator-given position, for UIs drawn on a game canvas that uiautomator cannot see.
      const [x, y] = opts.taps[sc];
      adb('shell', 'input', 'tap', String(x), String(y));
      mark(sc, `tapped at ${x},${y} (position given by operator)`);
      await sleep(4000); shot(sc);
    } else if (sc === 'consent-decline' || sc === 'consent-accept') {
      const re = sc === 'consent-decline' ? BUTTONS.decline : BUTTONS.accept;
      let done = false;
      for (let i = 0; i < 3 && !done; i++) {
        const b = findButton(uiDump(), re);
        if (b) { adb('shell', 'input', 'tap', String(b.x), String(b.y)); mark(sc, `tapped "${b.text || b.desc}"`); done = true; await sleep(4000); shot(sc); } else await sleep(3000);
      }
      if (!done) mark(sc, 'no matching button found (if the app draws its UI on a game canvas, pass --taps ' + sc + '=x,y from a screenshot)');
    } else if (sc === 'age') {
      const nodes = uiDump();
      const q = nodes.find((n) => BUTTONS.age.test(n.text) || BUTTONS.age.test(n.desc));
      const field = nodes.find((n) => /EditText/.test(n.cls));
      if (q && field) {
        adb('shell', 'input', 'tap', String(field.x), String(field.y));
        const year = /year|birth|出生/i.test(q.text) ? String(new Date().getUTCFullYear() - 12) : '12';
        adb('shell', 'input', 'text', year);
        mark('age answered', `"${q.text}" → ${year} (12 years old)`);
        const ok = findButton(uiDump(), BUTTONS.accept);
        if (ok) adb('shell', 'input', 'tap', String(ok.x), String(ok.y));
        await sleep(4000); shot('age');
      } else mark('age', 'no age question on screen');
    } else if (sc === 'explore') {
      mark('explore start', `${explore} random events`);
      adb('shell', 'monkey', '-p', pkg, '--throttle', '400', '--pct-syskeys', '0', '--pct-appswitch', '0', '-v', String(explore));
      shot('explore');
      mark('explore end');
    }
  }
  await sleep(10000);
  await setCapture(capId, false);
  if (mitm) {
    // Read identifiers after the run: the advertising ID only exists once an app has asked for it.
    ids = deviceIds(adb, pkg);
    mark('identifiers read', Object.entries(ids).filter(([, v]) => v).map(([k]) => k).join(', '));
    setProxy(adb, false); await sleep(1000); mitm.stop();
  }
  mark('capture stopped');
  const pcap = Buffer.from(await fetch(`${NETSIM}/v1/captures/${capId}`).then((r) => r.arrayBuffer()));
  const pcapFile = path.join(outDir, 'recording.pcap');
  fs.writeFileSync(pcapFile, pcap);
  fs.writeFileSync(path.join(outDir, 'timeline.json'), `${JSON.stringify(timeline, null, 1)}\n`);

  // Report: the consent tap (if any) is the consent moment.
  const result = await scanFile(base, { recording: pcapFile });
  const accept = timeline.find((e) => e.event === 'consent-accept' && e.detail.startsWith('tapped'));
  if (!fs.statSync(pcapFile).size || !fs.readFileSync(pcapFile).subarray(0, 4).equals(Buffer.from([0xd4, 0xc3, 0xb2, 0xa1])) && !fs.readFileSync(pcapFile).subarray(0, 4).equals(Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]))) throw new Error(`netsim returned no capture file: ${fs.readFileSync(pcapFile, 'utf8').slice(0, 120)}`);
  const t0 = result.traffic?.start ? result.traffic.start * 1000 : null;
  const consentAt = accept && t0 ? +((Date.parse(accept.t) - t0) / 1000).toFixed(1) : null;
  if (opts.decrypt && fs.existsSync(flowLog)) {
    const launch = timeline.find((e) => e.event === 'launch');
    result.decrypted = analyzeFlows(parseFlows(fs.readFileSync(flowLog, 'utf8')), { ids, sdkKb: loadKb().sdks, startMs: launch ? Date.parse(launch.t) : null, consentMs: accept ? Date.parse(accept.t) : null });
    fs.writeFileSync(path.join(outDir, 'decrypted-summary.json'), `${JSON.stringify(result.decrypted, null, 1)}\n`);
    mark('decrypted', `${result.decrypted.requests} requests to ${result.decrypted.hosts.length} hosts; ${result.decrypted.tlsFailed.length} hosts refused the proxy`);
  }
  const files = [base, pcapFile].map((f) => ({ name: path.basename(f), size: fs.statSync(f).size, sha256: sha256(f) }));
  fs.writeFileSync(path.join(outDir, 'report.html'), renderReport(result, { files, ctx: consentAt != null ? { consentAt } : {}, timeline }));
  mark('report written', path.join(outDir, 'report.html'));
  fs.writeFileSync(path.join(outDir, 'timeline.json'), `${JSON.stringify(timeline, null, 1)}\n`);
  return { outDir, pkg, consentAt, result };
}

function sha256(f) {
  return spawnSync(process.execPath, ['-e', `const c=require('crypto'),fs=require('fs');const h=c.createHash('sha256');h.update(fs.readFileSync(process.argv[1]));process.stdout.write(h.digest('hex'))`, f], { encoding: 'utf8', maxBuffer: 1 << 20 }).stdout;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const argv = process.argv.slice(2);
  const opt = (k, d) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
  const input = argv.find((a, i) => !a.startsWith('--') && !argv[i - 1]?.startsWith('--'));
  if (!input) { console.log('usage: run.mjs <app.apk|.apks|.xapk|folder> [--avd k1d_Pixel] [--out dir] [--scenarios idle,consent-decline,age,consent-accept,explore] [--idle 60] [--explore 300]'); process.exit(2); }
  runScenarios(input, {
    avd: opt('avd'), out: opt('out'), idle: Number(opt('idle', 60)), explore: Number(opt('explore', 300)),
    scenarios: opt('scenarios') ? opt('scenarios').split(',') : undefined,
    decrypt: argv.includes('--decrypt'),
    taps: opt('taps') ? Object.fromEntries(opt('taps').split(';').map((t) => { const [k, v] = t.split('='); return [k, v.split(',').map(Number)]; })) : undefined,
  }).then((r) => console.log(`\nDone: ${r.outDir}`)).catch((e) => { console.error(`runtime: ${e.message}`); process.exit(1); });
}
