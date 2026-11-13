// Tiny static server for local preview of site/ (same files GitHub Pages serves).
// Usage: node tools/serve.mjs [port]
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'site');
const fixtures = path.resolve(root, '..', 'tests', 'fixtures');
const port = Number(process.argv[2] || process.env.PORT || 8080);
const types = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.apk': 'application/vnd.android.package-archive', '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
};

http.createServer((req, res) => {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  // Dev-only: test fixtures for manual/browser testing. Not part of the published site.
  const base = urlPath.startsWith('/__fixtures__/') ? fixtures : root;
  const rel = urlPath.startsWith('/__fixtures__/') ? urlPath.slice('/__fixtures__'.length) : urlPath;
  let file = path.normalize(path.join(base, rel));
  if (!file.startsWith(base)) { res.writeHead(403).end(); return; }
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404).end('not found'); return; }
    res.writeHead(200, { 'content-type': types[path.extname(file)] || 'application/octet-stream', 'cache-control': 'no-store' });
    res.end(data);
  });
}).listen(port, () => console.log(`k1d preview: http://localhost:${port}/`));
