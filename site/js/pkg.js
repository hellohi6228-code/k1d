// macOS installer package (.pkg, xar archive): table of contents, signing certificate,
// Distribution metadata and file list. Payload (cpio, gzip/pbzx) is not unpacked.
import { parsePlist } from './plist.js';

const td8 = new TextDecoder('utf-8');

export function isXar(head) {
  return head.length >= 4 && head[0] === 0x78 && head[1] === 0x61 && head[2] === 0x72 && head[3] === 0x21;
}

async function inflateZlib(bytes) {
  const ds = new DecompressionStream('deflate');
  return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer());
}

function b64(s) {
  const bin = atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function readXar(source) {
  const h = await source.read(0, 28);
  const d = new DataView(h.buffer, h.byteOffset, h.byteLength);
  const headerSize = d.getUint16(4, false);
  const tocLen = Number(d.getBigUint64(8, false));
  const toc = td8.decode(await inflateZlib(await source.read(headerSize, tocLen)));
  const heap = headerSize + tocLen;
  const files = [];
  // flatten <file> elements (names joined by nesting depth)
  const stack = [];
  // xar <data>: <length> = archived (stored) size, <offset> into the heap, <encoding style>.
  const re = /<file\b[^>]*>|<\/file>|<name>([^<]*)<\/name>|<data>([\s\S]*?)<\/data>/g;
  let m;
  while ((m = re.exec(toc)) !== null) {
    if (m[0].startsWith('<file')) stack.push({ name: null, data: null });
    else if (m[0] === '</file>') {
      const f = stack.pop();
      if (f?.name) files.push({ path: [...stack.map((x) => x.name), f.name].join('/'), data: f.data });
    } else if (m[1] !== undefined && stack.length && !stack[stack.length - 1].name) stack[stack.length - 1].name = m[1];
    else if (m[2] !== undefined && stack.length) {
      const length = /<length>(\d+)<\/length>/.exec(m[2])?.[1];
      const offset = /<offset>(\d+)<\/offset>/.exec(m[2])?.[1];
      const encoding = /<encoding style="([^"]+)"/.exec(m[2])?.[1] ?? 'application/octet-stream';
      if (length && offset) stack[stack.length - 1].data = { offset: heap + Number(offset), size: Number(length), encoding };
    }
  }
  const certs = [...toc.matchAll(/<X509Certificate>([^<]+)<\/X509Certificate>/g)].map((x) => b64(x[1]));
  const readFile = async (f) => {
    const raw = await source.read(f.data.offset, f.data.size);
    if (/gzip/.test(f.data.encoding)) return new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer());
    if (/octet-stream/.test(f.data.encoding)) return raw;
    return null;
  };
  return { files, certs, readFile, toc };
}

export async function collectPkg(source, facts, ctx) {
  facts.platform = 'macos';
  const x = await readXar(source);
  if (x.certs[0] && !facts.cert) { facts.cert = { scheme: 'pkg', der: x.certs[0] }; facts.signatureSchemes.push('Installer package signature (xar)'); }
  if (!x.certs.length) facts.flags.unsigned = true;
  const dist = x.files.find((f) => f.path === 'Distribution' && f.data);
  const pkgInfos = x.files.filter((f) => /(^|\/)PackageInfo$/.test(f.path) && f.data);
  const rows = [];
  if (dist) {
    const t = td8.decode(await x.readFile(dist));
    const title = /<title>([^<]*)<\/title>/.exec(t)?.[1];
    if (title) rows.push(['Title', title]);
    const refs = [...t.matchAll(/<pkg-ref\b[^>]*id="([^"]+)"[^>]*version="([^"]+)"/g)].map((r) => `${r[1]} ${r[2]}`);
    if (refs.length) rows.push(['Packages', refs.join(', ')]);
    ctx.addUrls(t, 'Distribution');
  }
  let id = null;
  let version = null;
  for (const f of pkgInfos) {
    const t = td8.decode(await x.readFile(f));
    id = id ?? /identifier="([^"]+)"/.exec(t)?.[1];
    version = version ?? /<pkg-info\b[^>]*\bversion="([^"]+)"/.exec(t)?.[1];
    for (const b of t.matchAll(/<bundle\b[^>]*id="([^"]+)"[^>]*path="([^"]+)"/g)) rows.push(['Bundle', `${b[1]} (${b[2]})`]);
  }
  facts.app = { id, name: rows.find((r) => r[0] === 'Title')?.[1] ?? id, versionName: version, versionCode: null, minSdk: null, targetSdk: null };
  for (const f of x.files) facts.fileNames.add(f.path.split('/').pop());
  for (const f of x.files.filter((y) => /\.(plist|xml|json|sh|txt)$|(^|\/)(preinstall|postinstall)$/.test(y.path) && y.data && y.data.size < 2 * 1024 * 1024)) {
    try {
      const b = await x.readFile(f);
      if (!b) continue;
      const t = td8.decode(b);
      ctx.addUrls(t, f.path);
      ctx.scanText(t, f.path);
      if (/\.plist$/.test(f.path)) parsePlist(b);
    } catch { /* ignore */ }
  }
  facts.details.push({ title: { en: 'macOS installer package (.pkg)', zh: 'macOS 安装包（.pkg）' }, rows, lists: [{ title: 'Install scripts', items: x.files.filter((f) => /(preinstall|postinstall)$/.test(f.path)).map((f) => f.path) }, { title: 'Entries', items: x.files.map((f) => f.path).slice(0, 200) }] });
  facts.limits.push({ en: 'The .pkg payload (cpio, gzip or pbzx) is not unpacked. For full analysis, install on a test Mac and zip the installed .app, then analyze that.', zh: '.pkg 载荷（cpio，gzip 或 pbzx）未解包。如需完整分析，请在测试 Mac 上安装后将生成的 .app 压缩为 zip 再分析。' });
}
