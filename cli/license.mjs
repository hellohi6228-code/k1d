// k1d Pro / Monitoring license keys: base64url(JSON payload) "." base64url(Ed25519 signature).
// Payload: { v: 1, id, org, plan: 'pro' | 'monitoring' | 'enterprise', apps: ['com.example.app'] | ['*'], exp: 'YYYY-MM-DD' }
// Keys are issued with tools/issue-license.mjs and the private key that stays with k1d.
// Verification is offline: no server, nothing sent anywhere.
import crypto from 'node:crypto';

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA0d6WKxSaV49h8r98s3oTeorwHuGLEmYllDzjVkxXddo=
-----END PUBLIC KEY-----
`;

const b64u = (buf) => Buffer.from(buf).toString('base64url');

export function signLicense(payload, privateKeyPem) {
  const body = b64u(JSON.stringify(payload));
  const sig = crypto.sign(null, Buffer.from(body), privateKeyPem);
  return `${body}.${b64u(sig)}`;
}

// Returns { ok: true, license } or { ok: false, reason }.
export function verifyLicense(key, { appId = null, today = new Date(), publicKeyPem = PUBLIC_KEY } = {}) {
  if (!key || typeof key !== 'string') return { ok: false, reason: 'No license key. Set K1D_LICENSE (see the publishers page).' };
  const [body, sig] = key.trim().split('.');
  if (!body || !sig) return { ok: false, reason: 'The license key is not in the expected format.' };
  let good = false;
  try { good = crypto.verify(null, Buffer.from(body), publicKeyPem, Buffer.from(sig, 'base64url')); } catch { good = false; }
  if (!good) return { ok: false, reason: 'The license key signature is not valid.' };
  let license;
  try { license = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { return { ok: false, reason: 'The license key payload is unreadable.' }; }
  if (license.exp && new Date(`${license.exp}T23:59:59Z`) < today) return { ok: false, reason: `The license expired on ${license.exp}.`, license };
  const apps = license.apps ?? [];
  if (appId && !apps.includes('*') && !apps.includes(appId)) return { ok: false, reason: `The license does not cover ${appId} (covers: ${apps.join(', ')}).`, license };
  return { ok: true, license };
}
