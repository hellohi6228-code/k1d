// Minimal ZIP writer for building test fixtures (stored or deflated entries, optional
// APK Signing Block inserted before the central directory).
import zlib from 'node:zlib';

export function writeZip(entries, { beforeCentralDirectory = null } = {}) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const data = Buffer.from(e.data);
    const method = e.method ?? 8;
    const crc = zlib.crc32(data);
    const comp = method === 8 ? zlib.deflateRawSync(data) : data;
    const name = Buffer.from(e.name, 'utf8');
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0); lfh.writeUInt16LE(20, 4); lfh.writeUInt16LE(0x0800, 6); lfh.writeUInt16LE(method, 8);
    lfh.writeUInt16LE(0, 10); lfh.writeUInt16LE(0x5b21, 12); lfh.writeUInt32LE(crc, 14); lfh.writeUInt32LE(comp.length, 18);
    lfh.writeUInt32LE(data.length, 22); lfh.writeUInt16LE(name.length, 26); lfh.writeUInt16LE(0, 28);
    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0); cdh.writeUInt16LE(20, 4); cdh.writeUInt16LE(20, 6); cdh.writeUInt16LE(0x0800, 8);
    cdh.writeUInt16LE(method, 10); cdh.writeUInt16LE(0, 12); cdh.writeUInt16LE(0x5b21, 14); cdh.writeUInt32LE(crc, 16);
    cdh.writeUInt32LE(comp.length, 20); cdh.writeUInt32LE(data.length, 24); cdh.writeUInt16LE(name.length, 28);
    cdh.writeUInt32LE(offset, 42);
    central.push(cdh, name);
    parts.push(lfh, name, comp);
    offset += 30 + name.length + comp.length;
  }
  if (beforeCentralDirectory) {
    parts.push(beforeCentralDirectory);
    offset += beforeCentralDirectory.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cdBuf, eocd]);
}
