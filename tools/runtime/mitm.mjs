// mitmproxy side of a decrypting runtime test: start mitmdump with the k1d add-on, make the rooted
// emulator trust mitmproxy's CA, route the emulator's HTTP(S) through it, and collect the device
// identifiers that the analysis looks for in requests.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const MITM_DIR = process.env.K1D_MITM_DIR || path.join(os.homedir(), '.k1d', 'tools', 'mitmproxy');
export const PROXY_PORT = 8888;

function mitmdumpPath() {
  const p = path.join(MITM_DIR, process.platform === 'win32' ? 'mitmdump.exe' : 'mitmdump');
  if (!fs.existsSync(p)) throw new Error(`mitmdump not found at ${p} (set K1D_MITM_DIR)`);
  return p;
}

function opensslPath() {
  for (const c of ['openssl', 'C:/Program Files/Git/mingw64/bin/openssl.exe', 'C:/Program Files/Git/usr/bin/openssl.exe']) {
    const r = spawnSync(c, ['version'], { encoding: 'utf8' });
    if (r.status === 0) return c;
  }
  throw new Error('openssl not found (needed to name the CA file the way Android expects)');
}

export async function startMitm(flowLog) {
  const proc = spawn(mitmdumpPath(), ['--listen-port', String(PROXY_PORT), '-s', path.join(here, 'k1d_flows.py'), '--set', `k1d_flowlog=${flowLog}`, '-q'], { stdio: ['ignore', 'ignore', 'pipe'] });
  let err = '';
  proc.stderr.on('data', (d) => { err += d; });
  const ca = path.join(os.homedir(), '.mitmproxy', 'mitmproxy-ca-cert.pem');
  for (let i = 0; i < 60 && !fs.existsSync(ca); i++) await sleep(500);
  await sleep(1500);
  if (proc.exitCode != null) throw new Error(`mitmdump exited: ${err.slice(0, 300)}`);
  if (!fs.existsSync(ca)) throw new Error('mitmproxy did not create its CA certificate');
  // mitmdump.exe is a launcher with a child process; kill the whole tree on Windows.
  const stop = () => {
    if (process.platform === 'win32') spawnSync('taskkill', ['/PID', String(proc.pid), '/T', '/F']);
    else try { proc.kill(); } catch { /* already gone */ }
  };
  return { proc, ca, stop };
}

// Android looks CAs up by OpenSSL's "subject_hash_old".
export function caFileName(caPem) {
  const r = spawnSync(opensslPath(), ['x509', '-inform', 'PEM', '-subject_hash_old', '-noout', '-in', caPem], { encoding: 'utf8' });
  const h = r.stdout.trim().split(/\s+/)[0];
  if (!/^[0-9a-f]{8}$/.test(h)) throw new Error(`openssl could not hash the CA: ${r.stderr}`);
  return `${h}.0`;
}

export function trustCaOnDevice(adb, caPem) {
  const root = adb('root');
  if (/cannot run as root|production builds/i.test(root)) throw new Error('This emulator image does not allow root. Use a "Google APIs" image (not "Google Play"), e.g. the k1d_Root AVD.');
  adb('wait-for-device');
  const name = caFileName(caPem);
  adb('push', caPem, `/data/local/tmp/${name}`);
  adb('push', path.join(here, 'inject-ca.sh'), '/data/local/tmp/k1d-inject-ca.sh');
  const out = adb('shell', 'sh', '/data/local/tmp/k1d-inject-ca.sh', `/data/local/tmp/${name}`);
  if (!/k1d CA installed/.test(out)) throw new Error(`CA injection failed: ${out.slice(0, 300)}`);
  return name;
}

export const setProxy = (adb, on) => adb('shell', 'settings', 'put', 'global', 'http_proxy', on ? `10.0.2.2:${PROXY_PORT}` : ':0');

// Identifiers the app can read on this emulator (needs root for the per-app Android ID and GAID files).
export function deviceIds(adb, pkg) {
  const ids = { model: adb('shell', 'getprop', 'ro.product.model') || null };
  const ad = adb('shell', 'cat', '/data/data/com.google.android.gms/shared_prefs/adid_settings.xml');
  ids.gaid = ad.match(/adid_key">([0-9a-fA-F-]{36})</)?.[1] ?? null;
  // Android 8+: each app signing key gets its own Android ID (SSAID). The settings file may be binary XML.
  let ssaid = adb('shell', 'abx2xml', '/data/system/users/0/settings_ssaid.xml', '-');
  if (!/<settings/.test(ssaid)) ssaid = adb('shell', 'cat', '/data/system/users/0/settings_ssaid.xml');
  const m = ssaid.match(new RegExp(`value="([0-9a-f]{16})"[^>]*package="${pkg.replace(/\./g, '\\.')}"`)) ?? ssaid.match(new RegExp(`package="${pkg.replace(/\./g, '\\.')}"[^>]*value="([0-9a-f]{16})"`));
  ids.androidId = m?.[1] ?? (adb('shell', 'settings', 'get', 'secure', 'android_id') || null);
  return ids;
}
