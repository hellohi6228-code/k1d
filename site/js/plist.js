// Property-list parser: binary (bplist00) and XML. Works in browsers and Node.

const td8 = new TextDecoder('utf-8');
const td16be = new TextDecoder('utf-16be');

export function parsePlist(bytes) {
  if (!bytes || bytes.length < 8) throw new Error('PLIST_EMPTY');
  const magic = td8.decode(bytes.subarray(0, 8));
  if (magic === 'bplist00') return parseBinary(bytes);
  const text = td8.decode(bytes);
  if (text.includes('<plist') || text.trimStart().startsWith('<?xml')) return parseXml(text);
  throw new Error('PLIST_UNKNOWN_FORMAT');
}

// ---------------------------------------------------------------- binary
function readUInt(bytes, off, size) {
  let v = 0;
  for (let i = 0; i < size; i++) v = v * 256 + bytes[off + i];
  return v;
}

function parseBinary(bytes) {
  const t = bytes.length - 32;
  const offsetSize = bytes[t + 6];
  const refSize = bytes[t + 7];
  const numObjects = readUInt(bytes, t + 8, 8);
  const topObject = readUInt(bytes, t + 16, 8);
  const tableOffset = readUInt(bytes, t + 24, 8);
  const offsets = new Array(numObjects);
  for (let i = 0; i < numObjects; i++) offsets[i] = readUInt(bytes, tableOffset + i * offsetSize, offsetSize);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const cache = new Map();
  const depthLimit = 64;

  function lengthAndStart(off, info) {
    if (info !== 0xf) return [info, off + 1];
    const marker = bytes[off + 1];
    const size = 1 << (marker & 0xf);
    return [readUInt(bytes, off + 2, size), off + 2 + size];
  }

  function obj(ref, depth) {
    if (depth > depthLimit) throw new Error('PLIST_TOO_DEEP');
    if (cache.has(ref)) return cache.get(ref);
    const off = offsets[ref];
    const marker = bytes[off];
    const type = marker >> 4;
    const info = marker & 0xf;
    let v;
    switch (type) {
      case 0x0: v = info === 0x8 ? false : info === 0x9 ? true : null; break;
      case 0x1: {
        const size = 1 << info;
        if (size === 8) v = Number(dv.getBigInt64(off + 1));
        else v = readUInt(bytes, off + 1, size);
        break;
      }
      case 0x2: v = info === 2 ? dv.getFloat32(off + 1) : dv.getFloat64(off + 1); break;
      case 0x3: v = new Date((978307200 + dv.getFloat64(off + 1)) * 1000).toISOString(); break;
      case 0x4: { const [len, s] = lengthAndStart(off, info); v = bytes.slice(s, s + len); break; }
      case 0x5: { const [len, s] = lengthAndStart(off, info); v = td8.decode(bytes.subarray(s, s + len)); break; }
      case 0x6: { const [len, s] = lengthAndStart(off, info); v = td16be.decode(bytes.subarray(s, s + len * 2)); break; }
      case 0x8: v = { UID: readUInt(bytes, off + 1, info + 1) }; break;
      case 0xa: case 0xc: {
        const [len, s] = lengthAndStart(off, info);
        v = [];
        for (let i = 0; i < len; i++) v.push(obj(readUInt(bytes, s + i * refSize, refSize), depth + 1));
        break;
      }
      case 0xd: {
        const [len, s] = lengthAndStart(off, info);
        v = {};
        for (let i = 0; i < len; i++) {
          const k = obj(readUInt(bytes, s + i * refSize, refSize), depth + 1);
          v[String(k)] = obj(readUInt(bytes, s + (len + i) * refSize, refSize), depth + 1);
        }
        break;
      }
      default: v = null;
    }
    cache.set(ref, v);
    return v;
  }
  return obj(topObject, 0);
}

// ---------------------------------------------------------------- XML
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
function unescape(s) {
  return s.replace(/&(#x?[0-9a-fA-F]+|\w+);/g, (m, e) => {
    if (e[0] === '#') return String.fromCodePoint(e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
    return ENTITIES[e] ?? m;
  });
}

function parseXml(text) {
  const body = text.replace(/<\?xml[^>]*\?>/, '').replace(/<!DOCTYPE[^>]*>/i, '').replace(/<!--[\s\S]*?-->/g, '');
  const re = /<(\/?)([A-Za-z]+)[^>]*?(\/)?>|([^<]+)/g;
  const tokens = [];
  let m;
  while ((m = re.exec(body)) !== null) {
    if (m[4] !== undefined) { if (m[4].trim()) tokens.push({ text: m[4] }); continue; }
    tokens.push({ close: m[1] === '/', name: m[2], selfClose: Boolean(m[3]) });
  }
  let i = 0;
  function textUntilClose(name) {
    let s = '';
    while (i < tokens.length && !(tokens[i].close && tokens[i].name === name)) { if (tokens[i].text !== undefined) s += tokens[i].text; i++; }
    i++; // closing tag
    return unescape(s);
  }
  function value() {
    const tk = tokens[i++];
    if (!tk) return null;
    if (tk.name === 'plist') { const v = value(); i++; return v; }
    if (tk.selfClose) {
      if (tk.name === 'true') return true;
      if (tk.name === 'false') return false;
      if (tk.name === 'dict') return {};
      if (tk.name === 'array') return [];
      if (tk.name === 'string') return '';
      return null;
    }
    switch (tk.name) {
      case 'string': return textUntilClose('string');
      case 'integer': return Number(textUntilClose('integer').trim());
      case 'real': return Number(textUntilClose('real').trim());
      case 'date': return textUntilClose('date').trim();
      case 'data': return textUntilClose('data').replace(/\s+/g, '');
      case 'true': i++; return true;
      case 'false': i++; return false;
      case 'array': {
        const arr = [];
        while (i < tokens.length && !(tokens[i].close && tokens[i].name === 'array')) arr.push(value());
        i++;
        return arr;
      }
      case 'dict': {
        const d = {};
        while (i < tokens.length && !(tokens[i].close && tokens[i].name === 'dict')) {
          const k = tokens[i++];
          if (k.name !== 'key') continue;
          const key = k.selfClose ? '' : textUntilClose('key');
          d[key] = value();
        }
        i++;
        return d;
      }
      default: return null;
    }
  }
  return value();
}

// Pull an XML plist out of a CMS/PKCS#7 envelope (embedded.mobileprovision).
export function plistFromCms(bytes) {
  const latin = new TextDecoder('latin1').decode(bytes);
  const start = latin.indexOf('<?xml');
  const end = latin.indexOf('</plist>');
  if (start < 0 || end < 0) return null;
  return parseXml(td8.decode(bytes.subarray(start, end + 8)));
}
