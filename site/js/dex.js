// DEX parser: extracts the string table and type descriptors (class names).

function readUleb128(buf, p) {
  let result = 0;
  let shift = 0;
  let b;
  do {
    b = buf[p++];
    result |= (b & 0x7f) << shift;
    shift += 7;
  } while (b & 0x80 && shift < 35);
  return [result >>> 0, p];
}

// Modified UTF-8 is close enough to UTF-8 for URL/class-name extraction.
const td = new TextDecoder('utf-8');

export function parseDex(buf) {
  if (buf.length < 0x70 || buf[0] !== 0x64 || buf[1] !== 0x65 || buf[2] !== 0x78 || buf[3] !== 0x0a) {
    throw new Error('NOT_DEX');
  }
  const d = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const stringIdsSize = d.getUint32(0x38, true);
  const stringIdsOff = d.getUint32(0x3c, true);
  const typeIdsSize = d.getUint32(0x40, true);
  const typeIdsOff = d.getUint32(0x44, true);

  const strings = new Array(stringIdsSize);
  for (let i = 0; i < stringIdsSize; i++) {
    const dataOff = d.getUint32(stringIdsOff + i * 4, true);
    let [, p] = readUleb128(buf, dataOff);
    let e = p;
    while (e < buf.length && buf[e] !== 0) e++;
    strings[i] = td.decode(buf.subarray(p, e));
  }

  const classes = [];
  for (let i = 0; i < typeIdsSize; i++) {
    const desc = strings[d.getUint32(typeIdsOff + i * 4, true)];
    if (desc && desc[0] === 'L' && desc.endsWith(';')) {
      classes.push(desc.slice(1, -1).replace(/\//g, '.'));
    }
  }
  return { strings, classes, version: td.decode(buf.subarray(4, 7)) };
}
