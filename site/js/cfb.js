// Minimal OLE Compound File (CFB) reader for .msi: stream directory, SummaryInformation
// property set, and the DigitalSignature (Authenticode PKCS#7) stream.

const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;

export function isCFB(head) {
  return head.length >= 8 && head[0] === 0xd0 && head[1] === 0xcf && head[2] === 0x11 && head[3] === 0xe0 && head[4] === 0xa1 && head[5] === 0xb1 && head[6] === 0x1a && head[7] === 0xe1;
}

export function readCFB(bytes) {
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const secSize = 1 << d.getUint16(30, true);
  const miniSize = 1 << d.getUint16(32, true);
  const nFat = d.getUint32(44, true);
  const dirStart = d.getUint32(48, true);
  const miniCutoff = d.getUint32(56, true);
  const miniFatStart = d.getUint32(60, true);
  const difatStart = d.getUint32(68, true);
  const secOff = (s) => (s + 1) * secSize;

  // FAT sector list from the header DIFAT (+ DIFAT chain)
  const fatSecs = [];
  for (let i = 0; i < 109 && fatSecs.length < nFat; i++) {
    const s = d.getUint32(76 + i * 4, true);
    if (s !== FREESECT) fatSecs.push(s);
  }
  let dif = difatStart;
  let guard = 0;
  while (dif !== ENDOFCHAIN && dif !== FREESECT && fatSecs.length < nFat && guard++ < 10000) {
    const o = secOff(dif);
    for (let i = 0; i < secSize / 4 - 1 && fatSecs.length < nFat; i++) {
      const s = d.getUint32(o + i * 4, true);
      if (s !== FREESECT) fatSecs.push(s);
    }
    dif = d.getUint32(o + secSize - 4, true);
  }
  const fat = [];
  for (const s of fatSecs) {
    const o = secOff(s);
    for (let i = 0; i < secSize / 4; i++) fat.push(o + i * 4 + 4 <= bytes.length ? d.getUint32(o + i * 4, true) : FREESECT);
  }
  const chain = (start) => {
    const out = [];
    let s = start;
    let g = 0;
    while (s !== ENDOFCHAIN && s < fat.length && g++ < 1e6) { out.push(s); s = fat[s]; }
    return out;
  };
  const readChain = (start, size) => {
    const secs = chain(start);
    const buf = new Uint8Array(secs.length * secSize);
    secs.forEach((s, i) => buf.set(bytes.subarray(secOff(s), secOff(s) + secSize), i * secSize));
    return size === undefined ? buf : buf.subarray(0, size);
  };

  // directory
  const dirBytes = readChain(dirStart);
  const dd = new DataView(dirBytes.buffer, dirBytes.byteOffset, dirBytes.byteLength);
  const entries = [];
  for (let o = 0; o + 128 <= dirBytes.length; o += 128) {
    const nameLen = dd.getUint16(o + 64, true);
    const type = dirBytes[o + 66];
    if (!type) continue;
    const name = new TextDecoder('utf-16le').decode(dirBytes.subarray(o, o + Math.max(0, nameLen - 2)));
    entries.push({ name, type, start: dd.getUint32(o + 116, true), size: dd.getUint32(o + 120, true) });
  }
  const root = entries.find((e) => e.type === 5);
  const miniStream = root ? readChain(root.start, root.size) : new Uint8Array(0);
  const miniFat = [];
  if (miniFatStart !== ENDOFCHAIN) {
    const mf = readChain(miniFatStart);
    const mv = new DataView(mf.buffer, mf.byteOffset, mf.byteLength);
    for (let i = 0; i + 4 <= mf.length; i += 4) miniFat.push(mv.getUint32(i, true));
  }
  const readStream = (e) => {
    if (e.size < miniCutoff) {
      const out = new Uint8Array(e.size);
      let s = e.start;
      let p = 0;
      let g = 0;
      while (s !== ENDOFCHAIN && p < e.size && g++ < 1e6) {
        const n = Math.min(miniSize, e.size - p);
        out.set(miniStream.subarray(s * miniSize, s * miniSize + n), p);
        p += n;
        s = miniFat[s];
      }
      return out;
    }
    return readChain(e.start, e.size);
  };
  return { entries: entries.filter((e) => e.type === 2), readStream };
}

// OLE property set (\u0005SummaryInformation): returns { title, subject, author, keywords, comments, revision, appName }.
export function parseSummaryInformation(b) {
  const d = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (b.length < 48) return null;
  const secOff = d.getUint32(44, true);
  const nProps = d.getUint32(secOff + 4, true);
  const names = { 2: 'title', 3: 'subject', 4: 'author', 5: 'keywords', 6: 'comments', 9: 'revision', 18: 'appName' };
  const out = {};
  for (let i = 0; i < nProps && i < 64; i++) {
    const id = d.getUint32(secOff + 8 + i * 8, true);
    const off = secOff + d.getUint32(secOff + 12 + i * 8, true);
    if (!names[id] || off + 8 > b.length) continue;
    const type = d.getUint32(off, true);
    if (type === 30) { // VT_LPSTR
      const len = d.getUint32(off + 4, true);
      out[names[id]] = new TextDecoder('utf-8').decode(b.subarray(off + 8, off + 8 + len)).replace(/\0+$/, '');
    }
  }
  return out;
}
