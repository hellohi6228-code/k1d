// Issue a k1d license key (k1d staff only). The private key never goes in the repo.
// Usage:
//   node tools/issue-license.mjs --org "Hungry Studio" --plan pro --apps com.block.juggle --exp 2027-11-30
// Private key: $K1D_SIGNING_KEY, or ~/.k1d/license-signing-key.pem
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { signLicense, verifyLicense } from '../cli/license.mjs';

const args = Object.fromEntries(process.argv.slice(2).join(' ').split(/\s*--/).filter(Boolean).map((p) => { const i = p.indexOf(' '); return i < 0 ? [p, true] : [p.slice(0, i), p.slice(i + 1).replace(/^"|"$/g, '')]; }));
for (const k of ['org', 'plan', 'apps', 'exp']) if (!args[k]) { console.error(`missing --${k}`); process.exit(2); }
if (!['pro', 'monitoring', 'enterprise'].includes(args.plan)) { console.error('--plan must be pro, monitoring or enterprise'); process.exit(2); }
if (!/^\d{4}-\d{2}-\d{2}$/.test(args.exp)) { console.error('--exp must be YYYY-MM-DD'); process.exit(2); }
const keyPath = process.env.K1D_SIGNING_KEY || path.join(os.homedir(), '.k1d', 'license-signing-key.pem');
const pem = fs.readFileSync(keyPath, 'utf8');
const payload = { v: 1, id: crypto.randomUUID(), org: args.org, plan: args.plan, apps: String(args.apps).split(',').map((s) => s.trim()), exp: args.exp, issued: new Date().toISOString().slice(0, 10) };
const key = signLicense(payload, pem);
const check = verifyLicense(key);
if (!check.ok) { console.error(`signed key does not verify with the public key in cli/license.mjs: ${check.reason}`); process.exit(1); }
console.log(JSON.stringify(payload, null, 1));
console.log(`\nK1D_LICENSE=${key}`);
