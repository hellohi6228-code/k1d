// Every script the website loads must parse as an ES module. Unit tests import only some of them,
// and a syntax error in a browser-only file (app.js, guides.js, publishers.js) takes the site down.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dir = path.join(root, 'site/js');

for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js'))) {
  test(`site/js/${f} parses as an ES module`, () => {
    const r = spawnSync(process.execPath, ['--input-type=module', '--check'], { input: fs.readFileSync(path.join(dir, f)), encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
  });
}

test('every page references only scripts that exist', () => {
  for (const page of fs.readdirSync(path.join(root, 'site')).filter((x) => x.endsWith('.html'))) {
    const html = fs.readFileSync(path.join(root, 'site', page), 'utf8');
    for (const [, src] of html.matchAll(/<script[^>]+src="([^"]+)"/g)) assert.ok(fs.existsSync(path.join(root, 'site', src)), `${page} → ${src}`);
  }
});
