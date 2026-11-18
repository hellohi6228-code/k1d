// Create the k1d_Root emulator (Google APIs image: allows `adb root`, needed to trust mitmproxy's CA)
// from the existing k1d_Pixel configuration. Usage: node tools/runtime/make-root-avd.mjs [api=37.0]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const api = process.argv[2] ?? '37.0';
const avdRoot = path.join(os.homedir(), '.android', 'avd');
const src = path.join(avdRoot, 'k1d_Pixel.avd', 'config.ini');
const dir = path.join(avdRoot, 'k1d_Root.avd');
const sysdir = `system-images\\android-${api}\\google_apis\\x86_64\\`;
let c = fs.readFileSync(src, 'utf8');
const set = (k, v) => { c = new RegExp(`^${k.replace(/\./g, '\\.')}=.*$`, 'm').test(c) ? c.replace(new RegExp(`^${k.replace(/\./g, '\\.')}=.*$`, 'm'), () => `${k}=${v}`) : `${c.trimEnd()}\n${k}=${v}\n`; };
set('AvdId', 'k1d_Root');
set('avd.ini.displayname', 'k1d Root (Google APIs)');
set('PlayStore.enabled', 'false');
set('image.sysdir.1', sysdir);
set('tag.id', 'google_apis');
set('tag.display', 'Google APIs');
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'config.ini'), c);
fs.writeFileSync(path.join(avdRoot, 'k1d_Root.ini'), `avd.ini.encoding=UTF-8\npath=${dir}\npath.rel=avd\\k1d_Root.avd\ntarget=android-${api}\n`);
console.log(`Created ${dir} using ${sysdir}`);
