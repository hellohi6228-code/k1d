// Builds synthetic network captures for tests: classic pcap (Ethernet), pcapng (raw IP) and
// pcap with radiotap + 802.11 frames (the format the Android emulator's netsim writes).
// Usage: node tools/build-demo-pcap.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'tests', 'fixtures', 'formats');
const B = (s) => Buffer.from(s, 'latin1');
const be16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const be32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const ipBytes = (ip) => Buffer.from(ip.split('.').map(Number));
const FAKE_AWS_KEY = 'AKIA' + 'K1DDEMO0FAKE0KEY';
const DEVICE = '10.0.2.16';

function checksum(buf) {
  let s = 0;
  for (let i = 0; i < buf.length; i += 2) s += (buf[i] << 8) | (buf[i + 1] ?? 0);
  while (s >> 16) s = (s & 0xffff) + (s >> 16);
  return ~s & 0xffff;
}
function ipv4(src, dst, proto, payload) {
  const h = Buffer.alloc(20);
  h[0] = 0x45; h.writeUInt16BE(20 + payload.length, 2); h[8] = 64; h[9] = proto;
  ipBytes(src).copy(h, 12); ipBytes(dst).copy(h, 16);
  h.writeUInt16BE(checksum(h), 10);
  return Buffer.concat([h, payload]);
}
function tcp(sport, dport, flags, payload = Buffer.alloc(0), seq = 1000) {
  const h = Buffer.alloc(20);
  h.writeUInt16BE(sport, 0); h.writeUInt16BE(dport, 2); h.writeUInt32BE(seq, 4);
  h[12] = 5 << 4; h[13] = flags; h.writeUInt16BE(65535, 14);
  return Buffer.concat([h, payload]);
}
function udp(sport, dport, payload) {
  const h = Buffer.alloc(8);
  h.writeUInt16BE(sport, 0); h.writeUInt16BE(dport, 2); h.writeUInt16BE(8 + payload.length, 4);
  return Buffer.concat([h, payload]);
}
function dnsName(n) { return Buffer.concat([...n.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), B(l)])), Buffer.from([0])]); }
function dnsResponse(name, ip) {
  return Buffer.concat([be16(0x1234), be16(0x8180), be16(1), be16(1), be16(0), be16(0), dnsName(name), be16(1), be16(1),
    be16(0xc00c), be16(1), be16(1), be32(60), be16(4), ipBytes(ip)]);
}
function clientHello(sni) {
  const name = B(sni);
  const sniExt = Buffer.concat([be16(0), be16(name.length + 5), be16(name.length + 3), Buffer.from([0]), be16(name.length), name]);
  const alpn = Buffer.concat([be16(16), be16(5), be16(3), Buffer.from([2]), B('h2')]);
  const exts = Buffer.concat([sniExt, alpn]);
  const body = Buffer.concat([be16(0x0303), Buffer.alloc(32, 7), Buffer.from([0]), be16(2), be16(0x1301), Buffer.from([1, 0]), be16(exts.length), exts]);
  const hs = Buffer.concat([Buffer.from([1, 0, (body.length >> 8) & 0xff, body.length & 0xff]), body]);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), be16(hs.length), hs]);
}

// Packets: [time offset seconds, IP packet]
const packets = [
  [0.0, ipv4('10.0.2.3', DEVICE, 17, udp(53, 40001, dnsResponse('events.k1d-demo.cn', '203.0.113.10')))],
  [0.5, ipv4(DEVICE, '203.0.113.20', 6, tcp(50001, 443, 0x02))],
  [0.6, ipv4(DEVICE, '203.0.113.20', 6, tcp(50001, 443, 0x18, clientHello('analytics.us.tiktok.com')))],
  [0.7, ipv4('203.0.113.20', DEVICE, 6, tcp(443, 50001, 0x18, Buffer.alloc(3000, 1)))],
  [2.0, ipv4(DEVICE, '203.0.113.30', 6, tcp(50002, 80, 0x02))],
  [2.1, ipv4(DEVICE, '203.0.113.30', 6, tcp(50002, 80, 0x18, B(`POST /v1/track?gaid=00000000-1111-2222-3333-444444444444 HTTP/1.1\r\nHost: track.k1d-demo.example\r\nUser-Agent: IdleQuest/1.4.2\r\nContent-Type: application/json\r\n\r\n{"event":"launch","key":"${FAKE_AWS_KEY}"}`)))],
  [5.0, ipv4(DEVICE, '203.0.113.10', 17, udp(50003, 443, Buffer.alloc(1200, 0xc3)))],
  [9.0, ipv4(DEVICE, '203.0.113.40', 6, tcp(50004, 443, 0x02))],
  [9.1, ipv4(DEVICE, '203.0.113.40', 6, tcp(50004, 443, 0x18, clientHello('graph.facebook.com')))],
];
const T0 = 1794000000;

function ethernet(ip) {
  return Buffer.concat([Buffer.from([2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]), be16(0x0800), ip]);
}
function radiotap80211(ip, toDS) {
  const rt = Buffer.from([0, 0, 8, 0, 0, 0, 0, 0]); // radiotap v0, len 8, no fields
  const fc = Buffer.from([0x88, toDS ? 0x01 : 0x02]); // QoS data
  const hdr = Buffer.concat([fc, Buffer.alloc(2), Buffer.alloc(18, 0xbb), Buffer.alloc(2), Buffer.alloc(2)]); // dur, 3 addrs, seq, QoS
  const llc = Buffer.from([0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00]);
  return Buffer.concat([rt, hdr, llc, ip]);
}
function pcap(link, frames) {
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(0xa1b2c3d4, 0); gh.writeUInt16LE(2, 4); gh.writeUInt16LE(4, 6); gh.writeUInt32LE(65535, 16); gh.writeUInt32LE(link, 20);
  const recs = frames.map(([t, f]) => {
    const h = Buffer.alloc(16);
    h.writeUInt32LE(T0 + Math.floor(t), 0); h.writeUInt32LE(Math.round((t % 1) * 1e6), 4); h.writeUInt32LE(f.length, 8); h.writeUInt32LE(f.length, 12);
    return Buffer.concat([h, f]);
  });
  return Buffer.concat([gh, ...recs]);
}
function pcapng(link, frames) {
  const block = (type, body) => { const len = 12 + Math.ceil(body.length / 4) * 4; const b = Buffer.alloc(len); b.writeUInt32LE(type, 0); b.writeUInt32LE(len, 4); body.copy(b, 8); b.writeUInt32LE(len, len - 4); return b; };
  const shbBody = Buffer.alloc(16); shbBody.writeUInt32LE(0x1a2b3c4d, 0); shbBody.writeUInt16LE(1, 4); shbBody.writeBigInt64LE(-1n, 8);
  const shb = block(0x0a0d0d0a, shbBody);
  const idbBody = Buffer.alloc(8); idbBody.writeUInt16LE(link, 0); idbBody.writeUInt32LE(65535, 4);
  const idb = block(1, idbBody);
  const epbs = frames.map(([t, f]) => {
    const us = BigInt(T0) * 1000000n + BigInt(Math.round(t * 1e6));
    const hdr = Buffer.alloc(20);
    hdr.writeUInt32LE(0, 0); hdr.writeUInt32LE(Number(us >> 32n), 4); hdr.writeUInt32LE(Number(us & 0xffffffffn), 8); hdr.writeUInt32LE(f.length, 12); hdr.writeUInt32LE(f.length, 16);
    return block(6, Buffer.concat([hdr, f]));
  });
  return Buffer.concat([shb, idb, ...epbs]);
}

fs.writeFileSync(path.join(out, 'capture-ethernet.pcap'), pcap(1, packets.map(([t, ip]) => [t, ethernet(ip)])));
fs.writeFileSync(path.join(out, 'capture-raw.pcapng'), pcapng(101, packets));
fs.writeFileSync(path.join(out, 'capture-wifi.pcap'), pcap(127, packets.map(([t, ip]) => [t, radiotap80211(ip, ip[12] === 10)])));
console.log('Wrote capture-ethernet.pcap, capture-raw.pcapng, capture-wifi.pcap');
