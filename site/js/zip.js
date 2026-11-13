// Minimal ZIP reader that reads lazily from a random-access source, so multi-GB APKs
// never have to be loaded into memory at once. Works in browsers and Node 18+.
// source: { size: number, read(offset, length): Promise<Uint8Array> }

const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_CDH = 0x02014b50;
const SIG_LFH = 0x04034b50;

function dv(u8) {
  return new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
}

function u64(view, off) {
  const lo = view.getUint32(off, true);
  const hi = view.getUint32(off + 4, true);
  return hi * 0x100000000 + lo;
}

export function fileSource(file) {
  return {
    size: file.size,
    async read(offset, length) {
      const buf = await file.slice(offset, offset + length).arrayBuffer();
      return new Uint8Array(buf);
    },
  };
}

export function bytesSource(u8) {
  return {
    size: u8.byteLength,
    async read(offset, length) {
      return u8.subarray(offset, offset + length);
    },
  };
}

export async function inflateRaw(bytes) {
  const ds = new DecompressionStream('deflate-raw');
  const stream = new Blob([bytes]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export async function openZip(source) {
  const tailLen = Math.min(source.size, 65535 + 22 + 20);
  const tailStart = source.size - tailLen;
  const tail = await source.read(tailStart, tailLen);
  const tv = dv(tail);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tv.getUint32(i, true) === SIG_EOCD) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('NOT_A_ZIP');

  let count = tv.getUint16(eocd + 10, true);
  let cdSize = tv.getUint32(eocd + 12, true);
  let cdOffset = tv.getUint32(eocd + 16, true);

  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc >= 0 && tv.getUint32(loc, true) === SIG_ZIP64_LOCATOR) {
      const z64Off = u64(tv, loc + 8);
      const z = dv(await source.read(z64Off, 56));
      if (z.getUint32(0, true) !== SIG_ZIP64_EOCD) throw new Error('BAD_ZIP64');
      count = u64(z, 32);
      cdSize = u64(z, 40);
      cdOffset = u64(z, 48);
    }
  }

  const cd = await source.read(cdOffset, cdSize);
  const cv = dv(cd);
  const entries = [];
  const decoder = new TextDecoder('utf-8');
  let p = 0;
  for (let i = 0; i < count && p + 46 <= cd.length; i++) {
    if (cv.getUint32(p, true) !== SIG_CDH) break;
    const method = cv.getUint16(p + 10, true);
    let compSize = cv.getUint32(p + 20, true);
    let size = cv.getUint32(p + 24, true);
    const nameLen = cv.getUint16(p + 28, true);
    const extraLen = cv.getUint16(p + 30, true);
    const commentLen = cv.getUint16(p + 32, true);
    let offset = cv.getUint32(p + 42, true);
    const name = decoder.decode(cd.subarray(p + 46, p + 46 + nameLen));
    // ZIP64 extended information extra field
    let e = p + 46 + nameLen;
    const eEnd = e + extraLen;
    while (e + 4 <= eEnd) {
      const id = cv.getUint16(e, true);
      const len = cv.getUint16(e + 2, true);
      if (id === 0x0001) {
        let q = e + 4;
        if (size === 0xffffffff) { size = u64(cv, q); q += 8; }
        if (compSize === 0xffffffff) { compSize = u64(cv, q); q += 8; }
        if (offset === 0xffffffff) { offset = u64(cv, q); q += 8; }
      }
      e += 4 + len;
    }
    entries.push({ name, method, compSize, size, offset });
    p += 46 + nameLen + extraLen + commentLen;
  }

  const byName = new Map(entries.map((en) => [en.name, en]));

  async function readEntry(entry) {
    if (typeof entry === 'string') entry = byName.get(entry);
    if (!entry) return null;
    const lfh = dv(await source.read(entry.offset, 30));
    if (lfh.getUint32(0, true) !== SIG_LFH) throw new Error('BAD_LOCAL_HEADER');
    const dataStart = entry.offset + 30 + lfh.getUint16(26, true) + lfh.getUint16(28, true);
    const raw = await source.read(dataStart, entry.compSize);
    if (entry.method === 0) return raw;
    if (entry.method === 8) return inflateRaw(raw);
    throw new Error('UNSUPPORTED_COMPRESSION_' + entry.method);
  }

  return { entries, byName, cdOffset, source, readEntry };
}
