// Fails if any file served by the site contains verdict language (EN or ZH).
// k1d reports facts with evidence; it never says an app "violates", is "illegal", "compliant", "safe", etc.
// Usage: node scripts/check-claims.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_DIR = path.join(root, 'site');
const EXTENSIONS = new Set(['.html', '.js', '.json', '.css', '.txt', '.md']);

const BANNED = [
  { re: /\bviolat(e|es|ed|ing|ion|ions)\b/i, why: 'verdict: violates' },
  { re: /\billegal(ly)?\b/i, why: 'verdict: illegal' },
  { re: /\bunlawful(ly)?\b/i, why: 'verdict: unlawful' },
  { re: /\bnon-?compliant\b/i, why: 'verdict: non-compliant' },
  { re: /\bcompliant\b/i, why: 'verdict: compliant' },
  { re: /\bcompliance\b/i, why: 'promise of compliance (see docs/OPEN_QUESTIONS.md OQ-13)' },
  { re: /\bsafe\b/i, why: 'verdict: safe' },
  { re: /\bguarantee(s|d)?\b/i, why: 'promise of outcome' },
  { re: /违法/, why: 'verdict: 违法' },
  { re: /违规/, why: 'verdict: 违规' },
  { re: /合规/, why: 'verdict: 合规' },
  { re: /非法/, why: 'verdict: 非法' },
];

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (EXTENSIONS.has(path.extname(e.name))) yield p;
  }
}

let hits = 0;
for (const file of walk(SCAN_DIR)) {
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, i) => {
    for (const { re, why } of BANNED) {
      if (re.test(line)) {
        hits++;
        console.error(`${path.relative(root, file)}:${i + 1}: ${why}\n    ${line.trim().slice(0, 160)}`);
      }
    }
  });
}
if (hits) {
  console.error(`\n${hits} banned phrase(s) found.`);
  process.exit(1);
}
console.log('claims check: no banned phrases in site/');
