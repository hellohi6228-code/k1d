// Android binary XML (AXML) parser for AndroidManifest.xml, plus the string pool
// parser reused for resources.arsc.

const RES_STRING_POOL_TYPE = 0x0001;
const RES_TABLE_TYPE = 0x0002;
const RES_XML_TYPE = 0x0003;
const RES_XML_START_ELEMENT = 0x0102;
const RES_XML_END_ELEMENT = 0x0103;
const RES_XML_RESOURCE_MAP = 0x0180;

// android.R.attr ids, used when attribute name strings are stripped/obfuscated.
const RES_IDS = {
  0x01010001: 'label',
  0x01010003: 'name',
  0x0101000f: 'debuggable',
  0x01010010: 'exported',
  0x01010024: 'value',
  0x01010025: 'resource',
  0x0101020c: 'minSdkVersion',
  0x0101021b: 'versionCode',
  0x0101021c: 'versionName',
  0x01010270: 'targetSdkVersion',
  0x01010280: 'allowBackup',
  0x010104ec: 'usesCleartextTraffic',
  0x01010527: 'networkSecurityConfig',
};

function view(u8) {
  return new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
}

export function parseStringPool(buf, off) {
  const d = view(buf);
  const headerSize = d.getUint16(off + 2, true);
  const chunkSize = d.getUint32(off + 4, true);
  const count = d.getUint32(off + 8, true);
  const flags = d.getUint32(off + 16, true);
  const stringsStart = d.getUint32(off + 20, true);
  const utf8 = (flags & 0x100) !== 0;
  const td8 = new TextDecoder('utf-8');
  const td16 = new TextDecoder('utf-16le');
  const strings = new Array(count);
  for (let i = 0; i < count; i++) {
    try {
      let p = off + stringsStart + d.getUint32(off + headerSize + i * 4, true);
      if (utf8) {
        p += buf[p] & 0x80 ? 2 : 1; // utf-16 length, unused
        let len = buf[p];
        if (len & 0x80) { len = ((len & 0x7f) << 8) | buf[p + 1]; p += 2; } else { p += 1; }
        strings[i] = td8.decode(buf.subarray(p, p + len));
      } else {
        let len = d.getUint16(p, true);
        if (len & 0x8000) { len = ((len & 0x7fff) << 16) | d.getUint16(p + 2, true); p += 4; } else { p += 2; }
        strings[i] = td16.decode(buf.subarray(p, p + len * 2));
      }
    } catch {
      strings[i] = '';
    }
  }
  return { strings, size: chunkSize };
}

function typedValue(strings, raw, type, data) {
  switch (type) {
    case 0x03: return strings[data] ?? '';
    case 0x10: return data | 0;
    case 0x11: return '0x' + data.toString(16);
    case 0x12: return data !== 0;
    case 0x01: return '@0x' + data.toString(16).padStart(8, '0');
    case 0x04: return new DataView(new Uint32Array([data]).buffer).getFloat32(0, true);
    default:
      if (raw !== 0xffffffff) return strings[raw] ?? '';
      return data;
  }
}

// Returns the root element as { tag, attrs, children }.
export function parseAXML(buf) {
  const d = view(buf);
  if (buf.length < 8 || d.getUint16(0, true) !== RES_XML_TYPE) throw new Error('NOT_BINARY_XML');
  let off = d.getUint16(2, true);
  const end = Math.min(d.getUint32(4, true), buf.length);
  let strings = [];
  const resMap = [];
  const root = { tag: '#root', attrs: {}, children: [] };
  const stack = [root];
  while (off + 8 <= end) {
    const type = d.getUint16(off, true);
    const hsize = d.getUint16(off + 2, true);
    const size = d.getUint32(off + 4, true);
    if (size < 8) break;
    if (type === RES_STRING_POOL_TYPE) {
      strings = parseStringPool(buf, off).strings;
    } else if (type === RES_XML_RESOURCE_MAP) {
      for (let i = 0; i < (size - hsize) / 4; i++) resMap.push(d.getUint32(off + hsize + i * 4, true));
    } else if (type === RES_XML_START_ELEMENT) {
      const ext = off + hsize;
      const nameIdx = d.getUint32(ext + 4, true);
      const attrStart = d.getUint16(ext + 8, true);
      const attrSize = d.getUint16(ext + 10, true);
      const attrCount = d.getUint16(ext + 12, true);
      const el = { tag: strings[nameIdx] ?? '', attrs: {}, children: [] };
      for (let a = 0; a < attrCount; a++) {
        const ao = ext + attrStart + a * attrSize;
        const nameI = d.getUint32(ao + 4, true);
        const raw = d.getUint32(ao + 8, true);
        const dtype = buf[ao + 15];
        const data = d.getUint32(ao + 16, true);
        let key = strings[nameI];
        if (!key || !/^[A-Za-z]/.test(key)) key = RES_IDS[resMap[nameI]] || `attr_${a}`;
        el.attrs[key] = typedValue(strings, raw, dtype, data);
      }
      stack[stack.length - 1].children.push(el);
      stack.push(el);
    } else if (type === RES_XML_END_ELEMENT) {
      if (stack.length > 1) stack.pop();
    }
    off += size;
  }
  return root.children[0] || null;
}

// ---------------------------------------------------------------------------
// Android App Bundle manifests are aapt2 protobuf XmlNode messages
// (frameworks/base/tools/aapt2/Resources.proto), not binary AXML.

function* protoFields(buf, start = 0, end = buf.length) {
  let p = start;
  const varint = () => {
    let v = 0;
    let mul = 1;
    let b;
    do { b = buf[p++]; v += (b & 0x7f) * mul; mul *= 128; } while (b & 0x80 && p < end);
    return v;
  };
  while (p < end) {
    const key = varint();
    const field = Math.floor(key / 8);
    const wire = key & 7;
    if (wire === 0) yield { field, wire, value: varint() };
    else if (wire === 2) { const len = varint(); yield { field, wire, start: p, end: p + len }; p += len; }
    else if (wire === 5) { yield { field, wire, start: p, end: p + 4 }; p += 4; }
    else if (wire === 1) { yield { field, wire, start: p, end: p + 8 }; p += 8; }
    else break;
  }
}

const tdp = new TextDecoder('utf-8');
const BOOL_ATTRS = new Set(['exported', 'debuggable', 'allowBackup', 'usesCleartextTraffic', 'enabled']);
const INT_ATTRS = new Set(['versionCode', 'minSdkVersion', 'targetSdkVersion']);

function protoItemValue(buf, s, e) {
  for (const f of protoFields(buf, s, e)) {
    if ((f.field === 2 || f.field === 3) && f.wire === 2) { // String / RawString { value = 1 }
      for (const g of protoFields(buf, f.start, f.end)) if (g.field === 1 && g.wire === 2) return tdp.decode(buf.subarray(g.start, g.end));
    }
    if (f.field === 7 && f.wire === 2) { // Primitive
      for (const g of protoFields(buf, f.start, f.end)) {
        if (g.field === 8 && g.wire === 0) return g.value !== 0;
        if ((g.field === 6 || g.field === 7) && g.wire === 0) return g.value;
      }
    }
    if (f.field === 1 && f.wire === 2) { // Reference { id = 2 }
      for (const g of protoFields(buf, f.start, f.end)) if (g.field === 2 && g.wire === 0) return '@0x' + g.value.toString(16).padStart(8, '0');
    }
  }
  return undefined;
}

function protoElement(buf, s, e) {
  const el = { tag: '', attrs: {}, children: [] };
  for (const f of protoFields(buf, s, e)) {
    if (f.field === 3 && f.wire === 2) el.tag = tdp.decode(buf.subarray(f.start, f.end));
    else if (f.field === 4 && f.wire === 2) {
      let name = '';
      let value;
      let resId = 0;
      let compiled;
      for (const g of protoFields(buf, f.start, f.end)) {
        if (g.field === 2 && g.wire === 2) name = tdp.decode(buf.subarray(g.start, g.end));
        else if (g.field === 3 && g.wire === 2) value = tdp.decode(buf.subarray(g.start, g.end));
        else if (g.field === 5 && g.wire === 0) resId = g.value;
        else if (g.field === 6 && g.wire === 2) compiled = protoItemValue(buf, g.start, g.end);
      }
      if (!name || !/^[A-Za-z]/.test(name)) name = RES_IDS[resId] || name || 'attr';
      let v = compiled !== undefined && (value === undefined || value === '') ? compiled : value;
      if (BOOL_ATTRS.has(name) && typeof v === 'string') v = v === 'true';
      if (INT_ATTRS.has(name) && typeof v === 'string' && /^-?\d+$/.test(v)) v = Number(v);
      el.attrs[name] = v ?? '';
    } else if (f.field === 5 && f.wire === 2) {
      const child = protoNode(buf, f.start, f.end);
      if (child) el.children.push(child);
    }
  }
  return el;
}

function protoNode(buf, s, e) {
  for (const f of protoFields(buf, s, e)) if (f.field === 1 && f.wire === 2) return protoElement(buf, f.start, f.end);
  return null; // text node
}

export function parseProtoXml(buf) {
  const root = protoNode(buf, 0, buf.length);
  if (!root || !root.tag) throw new Error('NOT_PROTO_XML');
  return root;
}

// Global string pool of resources.arsc (where hard-coded URLs in string resources live).
export function parseArscStrings(buf) {
  const d = view(buf);
  if (buf.length < 12 || d.getUint16(0, true) !== RES_TABLE_TYPE) return [];
  const off = d.getUint16(2, true);
  if (d.getUint16(off, true) !== RES_STRING_POOL_TYPE) return [];
  return parseStringPool(buf, off).strings;
}

function find(el, tag) {
  return el.children.filter((c) => c.tag === tag);
}

const COMPONENT_TAGS = ['activity', 'activity-alias', 'service', 'receiver', 'provider'];

// Turn the manifest tree into the facts we report on.
export function summarizeManifest(root) {
  if (!root || root.tag !== 'manifest') throw new Error('NO_MANIFEST_ROOT');
  const pkg = String(root.attrs.package ?? '');
  const sdk = find(root, 'uses-sdk')[0]?.attrs ?? {};
  const permissions = [
    ...find(root, 'uses-permission'),
    ...find(root, 'uses-permission-sdk-23'),
  ].map((e) => String(e.attrs.name ?? '')).filter(Boolean);

  const app = find(root, 'application')[0] ?? { attrs: {}, children: [] };
  const targetSdk = Number(sdk.targetSdkVersion ?? 0) || null;
  const components = [];
  const metaData = [];
  for (const child of app.children) {
    if (COMPONENT_TAGS.includes(child.tag)) {
      let name = String(child.attrs.name ?? '');
      if (name.startsWith('.')) name = pkg + name;
      else if (name && !name.includes('.')) name = pkg + '.' + name;
      const hasFilter = child.children.some((c) => c.tag === 'intent-filter');
      let exported = child.attrs.exported;
      if (exported === undefined) exported = child.tag === 'provider' ? (targetSdk !== null && targetSdk < 17) : hasFilter;
      components.push({ type: child.tag, name, exported: exported === true || exported === 'true', hasIntentFilter: hasFilter, permission: child.attrs.permission ? String(child.attrs.permission) : null });
    } else if (child.tag === 'meta-data') {
      metaData.push({ name: String(child.attrs.name ?? ''), value: child.attrs.value ?? child.attrs.resource ?? '' });
    }
  }
  const queries = find(root, 'queries')[0];
  const queriedPackages = queries
    ? find(queries, 'package').map((p) => String(p.attrs.name ?? '')).filter(Boolean)
    : [];

  return {
    package: pkg,
    versionCode: root.attrs.versionCode ?? null,
    versionName: root.attrs.versionName ?? null,
    minSdk: sdk.minSdkVersion ?? null,
    targetSdk,
    permissions: [...new Set(permissions)],
    application: {
      debuggable: app.attrs.debuggable === true,
      allowBackup: app.attrs.allowBackup === undefined ? null : app.attrs.allowBackup === true,
      usesCleartextTraffic: app.attrs.usesCleartextTraffic === undefined ? null : app.attrs.usesCleartextTraffic === true,
      networkSecurityConfig: app.attrs.networkSecurityConfig ?? null,
      appCategory: app.attrs.appCategory ?? null,
      isGame: app.attrs.isGame === true || app.attrs.isGame === 'true',
    },
    components,
    metaData,
    queriedPackages,
  };
}
