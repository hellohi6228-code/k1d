// Signing-certificate extraction: APK Signature Scheme v2/v3 block, with v1 (JAR/PKCS#7) fallback.

const BLOCK_IDS = {
  0x7109871a: 'v2',
  0xf05368c0: 'v3',
  0x1b93ad61: 'v3.1',
};

function u64(d, off) {
  return d.getUint32(off + 4, true) * 0x100000000 + d.getUint32(off, true);
}

// Returns { scheme, der } for the first signer's first certificate, or null.
export async function readSigningBlockCert(zip) {
  const cd = zip.cdOffset;
  if (cd < 32) return null;
  const footer = await zip.source.read(cd - 24, 24);
  const magic = new TextDecoder().decode(footer.subarray(8, 24));
  if (magic !== 'APK Sig Block 42') return null;
  const fd = new DataView(footer.buffer, footer.byteOffset, 24);
  const blockSize = u64(fd, 0);
  const start = cd - blockSize - 8;
  if (start < 0) return null;
  const block = await zip.source.read(start, blockSize + 8);
  const d = new DataView(block.buffer, block.byteOffset, block.byteLength);
  let p = 8;
  const end = block.length - 24;
  const found = {};
  while (p + 12 <= end) {
    const len = u64(d, p);
    const id = d.getUint32(p + 8, true);
    const valStart = p + 12;
    if (BLOCK_IDS[id]) found[BLOCK_IDS[id]] = valStart;
    p += 8 + len;
  }
  for (const scheme of ['v3.1', 'v3', 'v2']) {
    if (found[scheme] === undefined) continue;
    try {
      let q = found[scheme];
      q += 4; // signers sequence length
      q += 4; // first signer length
      q += 4; // signed data length
      const digestsLen = d.getUint32(q, true);
      q += 4 + digestsLen;
      q += 4; // certificates sequence length
      const certLen = d.getUint32(q, true);
      q += 4;
      return { scheme, der: block.slice(q, q + certLen), schemes: Object.keys(found) };
    } catch {
      /* fall through */
    }
  }
  return null;
}

// --- Minimal DER reader -------------------------------------------------------

function readTLV(buf, p) {
  const tag = buf[p];
  let len = buf[p + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p + 2 + i];
    hdr = 2 + n;
  }
  return { tag, start: p, contentStart: p + hdr, end: p + hdr + len };
}

function children(buf, tlv) {
  const out = [];
  let p = tlv.contentStart;
  while (p < tlv.end) {
    const c = readTLV(buf, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

// v1: PKCS#7 SignedData in META-INF/*.RSA|DSA|EC -> first certificate DER.
export function certFromPkcs7(buf) {
  const ci = readTLV(buf, 0);
  const [, explicit] = children(buf, ci);
  const signedData = children(buf, explicit)[0];
  for (const c of children(buf, signedData)) {
    if (c.tag === 0xa0) {
      const cert = children(buf, c)[0];
      return buf.slice(cert.start, cert.end);
    }
  }
  return null;
}

const OID_NAMES = { '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU' };

function decodeOid(bytes) {
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) {
    v = v * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}

function decodeName(buf, nameTlv) {
  const out = {};
  for (const rdn of children(buf, nameTlv)) {
    for (const atv of children(buf, rdn)) {
      const [oid, val] = children(buf, atv);
      const key = OID_NAMES[decodeOid(buf.subarray(oid.contentStart, oid.end))];
      if (!key) continue;
      const enc = val.tag === 0x1e ? 'utf-16be' : 'utf-8';
      out[key] = new TextDecoder(enc).decode(buf.subarray(val.contentStart, val.end));
    }
  }
  return out;
}

function decodeTime(buf, t) {
  const s = new TextDecoder().decode(buf.subarray(t.contentStart, t.end));
  if (t.tag === 0x17) { // UTCTime YYMMDDHHMMSSZ
    const yy = Number(s.slice(0, 2));
    return `${yy >= 50 ? 19 : 20}${s.slice(0, 2)}-${s.slice(2, 4)}-${s.slice(4, 6)}`;
  }
  return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}`;
}

export function describeCert(der) {
  try {
    const cert = readTLV(der, 0);
    const tbs = children(der, cert)[0];
    let fields = children(der, tbs);
    if (fields[0].tag === 0xa0) fields = fields.slice(1); // explicit version
    const [serial, , issuer, validity, subject] = fields;
    const [nb, na] = children(der, validity);
    return {
      subject: decodeName(der, subject),
      issuer: decodeName(der, issuer),
      notBefore: decodeTime(der, nb),
      notAfter: decodeTime(der, na),
      serialHex: Array.from(der.subarray(serial.contentStart, serial.end), (b) => b.toString(16).padStart(2, '0')).join(''),
    };
  } catch {
    return null;
  }
}

export async function sha256Hex(bytes) {
  const h = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(h), (b) => b.toString(16).padStart(2, '0')).join('');
}
