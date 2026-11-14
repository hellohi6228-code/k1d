// Network capture (pcap / pcapng) analysis: who an app talked to, when, and how much.
// Link types: Ethernet, raw IP, Linux SLL/SLL2, 802.11, radiotap+802.11, BSD loopback.
// Decodes DNS, TLS ClientHello SNI, cleartext HTTP requests; QUIC flows are named via DNS.

const td = new TextDecoder('latin1');
const PCAP_MAGICS = new Set([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1]);

export function isPcap(head) {
  if (head.length < 4) return false;
  const le = new DataView(head.buffer, head.byteOffset, 4).getUint32(0, true);
  return PCAP_MAGICS.has(le) || le === 0x0a0d0d0a;
}

// ---------------------------------------------------------------- container readers
function* readPcap(b) {
  const d = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const m = d.getUint32(0, true);
  const le = m === 0xa1b2c3d4 || m === 0xa1b23c4d;
  const nano = m === 0xa1b23c4d || m === 0x4d3cb2a1;
  const link = d.getUint32(20, le) & 0xffff;
  let p = 24;
  while (p + 16 <= b.length) {
    const sec = d.getUint32(p, le);
    const frac = d.getUint32(p + 4, le);
    const incl = d.getUint32(p + 8, le);
    const orig = d.getUint32(p + 12, le);
    if (p + 16 + incl > b.length) break;
    yield { ts: sec + frac / (nano ? 1e9 : 1e6), link, data: b.subarray(p + 16, p + 16 + incl), orig };
    p += 16 + incl;
  }
}

function* readPcapng(b) {
  const d = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let le = true;
  let p = 0;
  const ifaces = [];
  while (p + 12 <= b.length) {
    let type = d.getUint32(p, le);
    if (type === 0x0a0d0d0a) {
      const bom = d.getUint32(p + 8, true);
      le = bom === 0x1a2b3c4d;
      type = 0x0a0d0d0a;
    }
    const len = d.getUint32(p + 4, le);
    if (len < 12 || p + len > b.length) break;
    if (type === 0x0a0d0d0a) ifaces.length = 0;
    else if (type === 1) { // IDB
      const link = d.getUint16(p + 8, le);
      let tsres = 1e-6;
      let o = p + 16;
      while (o + 4 <= p + len - 4) { // options
        const code = d.getUint16(o, le);
        const olen = d.getUint16(o + 2, le);
        if (code === 0) break;
        if (code === 9 && olen >= 1) { const v = b[o + 4]; tsres = v & 0x80 ? 2 ** -(v & 0x7f) : 10 ** -v; }
        o += 4 + Math.ceil(olen / 4) * 4;
      }
      ifaces.push({ link, tsres });
    } else if (type === 6) { // EPB
      const ifc = ifaces[d.getUint32(p + 8, le)] ?? { link: 1, tsres: 1e-6 };
      const ts = (d.getUint32(p + 12, le) * 2 ** 32 + d.getUint32(p + 16, le)) * ifc.tsres;
      const incl = d.getUint32(p + 20, le);
      yield { ts, link: ifc.link, data: b.subarray(p + 28, p + 28 + incl), orig: d.getUint32(p + 24, le) };
    } else if (type === 3) { // SPB
      const ifc = ifaces[0] ?? { link: 1 };
      yield { ts: 0, link: ifc.link, data: b.subarray(p + 12, p + len - 4), orig: d.getUint32(p + 8, le) };
    }
    p += len;
  }
}

// ---------------------------------------------------------------- link layer -> IP packet
function toIP(link, f) {
  const d = new DataView(f.buffer, f.byteOffset, f.byteLength);
  const ether = (off) => {
    let o = off;
    let et = d.getUint16(o, false);
    o += 2;
    while ((et === 0x8100 || et === 0x88a8) && o + 4 <= f.length) { et = d.getUint16(o + 2, false); o += 4; }
    return [et, o];
  };
  let et;
  let o;
  switch (link) {
    case 1: if (f.length < 14) return null; [et, o] = ether(12); break;
    case 101: case 228: case 229: case 12: case 14: return f.length ? { v: f[0] >> 4, off: 0 } : null;
    case 0: case 108: return f.length > 4 ? { v: f[4] >> 4, off: 4 } : null;
    case 113: if (f.length < 16) return null; et = d.getUint16(14, false); o = 16; break;
    case 276: if (f.length < 20) return null; et = d.getUint16(0, false); o = 20; break;
    case 127: case 105: {
      let h = 0;
      if (link === 127) { if (f.length < 4) return null; h = d.getUint16(2, true); }
      if (f.length < h + 24) return null;
      const fc = d.getUint16(h, true);
      if (((fc >> 2) & 3) !== 2 || fc & 0x4000) return null; // data frames only; skip protected
      const sub = (fc >> 4) & 0xf;
      if (sub & 0x4) return null; // null-data
      let hl = 24 + ((fc & 0x0300) === 0x0300 ? 6 : 0);
      if (sub & 0x8) { hl += 2; if (fc & 0x8000) hl += 4; }
      o = h + hl;
      if (f[o] !== 0xaa || f[o + 1] !== 0xaa || f[o + 2] !== 0x03) return null;
      et = d.getUint16(o + 6, false);
      o += 8;
      break;
    }
    default: return null;
  }
  if (et === 0x0800) return { v: 4, off: o };
  if (et === 0x86dd) return { v: 6, off: o };
  return null;
}

const ip4 = (b, o) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
function ip6(b, o) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(((b[o + i] << 8) | b[o + i + 1]).toString(16));
  return parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
}
export const isPrivateIP = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fe80:|fc|fd)/.test(ip);

// ---------------------------------------------------------------- DNS
function dnsName(b, o, base, depth = 0) {
  const labels = [];
  let p = o;
  let end = -1;
  while (p < b.length && depth < 20) {
    const len = b[p];
    if (len === 0) { p += 1; break; }
    if ((len & 0xc0) === 0xc0) {
      if (end < 0) end = p + 2;
      p = base + (((len & 0x3f) << 8) | b[p + 1]);
      depth++;
      continue;
    }
    labels.push(td.decode(b.subarray(p + 1, p + 1 + len)));
    p += 1 + len;
  }
  return [labels.join('.').toLowerCase(), end >= 0 ? end : p];
}

function parseDNS(b, o) {
  const d = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (o + 12 > b.length) return null;
  const flags = d.getUint16(o + 2, false);
  const qd = d.getUint16(o + 4, false);
  const an = d.getUint16(o + 6, false);
  let p = o + 12;
  const questions = [];
  for (let i = 0; i < qd && p < b.length; i++) {
    const [name, np] = dnsName(b, p, o);
    questions.push(name);
    p = np + 4;
  }
  const answers = [];
  for (let i = 0; i < an && p + 10 <= b.length; i++) {
    const [name, np] = dnsName(b, p, o);
    const type = d.getUint16(np, false);
    const rdlen = d.getUint16(np + 8, false);
    const rd = np + 10;
    if (type === 1 && rdlen === 4) answers.push({ name, ip: ip4(b, rd) });
    else if (type === 28 && rdlen === 16) answers.push({ name, ip: ip6(b, rd) });
    else if (type === 5) answers.push({ name, cname: dnsName(b, rd, o)[0] });
    p = rd + rdlen;
  }
  return { response: (flags & 0x8000) !== 0, questions, answers };
}

// ---------------------------------------------------------------- TLS / HTTP
function tlsSNI(buf) {
  // TLS record(s) -> handshake ClientHello -> server_name extension
  if (buf.length < 9 || buf[0] !== 0x16 || buf[5] !== 0x01) return null;
  let p = 9 + 2 + 32; // handshake header(4) after record header(5), version, random
  if (p >= buf.length) return null;
  p += 1 + buf[p]; // session id
  if (p + 2 > buf.length) return null;
  p += 2 + ((buf[p] << 8) | buf[p + 1]); // cipher suites
  if (p >= buf.length) return null;
  p += 1 + buf[p]; // compression
  if (p + 2 > buf.length) return null;
  const extEnd = Math.min(buf.length, p + 2 + ((buf[p] << 8) | buf[p + 1]));
  p += 2;
  let sni = null;
  let alpn = null;
  while (p + 4 <= extEnd) {
    const type = (buf[p] << 8) | buf[p + 1];
    const len = (buf[p + 2] << 8) | buf[p + 3];
    const e = p + 4;
    if (type === 0 && e + 5 <= buf.length) {
      const nl = (buf[e + 3] << 8) | buf[e + 4];
      sni = td.decode(buf.subarray(e + 5, e + 5 + nl)).toLowerCase();
    } else if (type === 16 && e + 3 <= buf.length) {
      const l = buf[e + 2];
      alpn = td.decode(buf.subarray(e + 3, e + 3 + l));
    }
    p = e + len;
  }
  return sni ? { sni, alpn } : null;
}

const HTTP_RE = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (\S+) HTTP\/1\.[01]\r\n/;
function httpRequest(buf) {
  const s = td.decode(buf.subarray(0, Math.min(buf.length, 16384)));
  const m = HTTP_RE.exec(s);
  if (!m) return null;
  const headEnd = s.indexOf('\r\n\r\n');
  const head = s.slice(0, headEnd < 0 ? s.length : headEnd);
  const headers = {};
  for (const line of head.split('\r\n').slice(1)) {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0, i).toLowerCase()] = line.slice(i + 1).trim();
  }
  const body = headEnd < 0 ? '' : s.slice(headEnd + 4, headEnd + 4 + 2048);
  return { method: m[1], path: m[2].slice(0, 500), host: (headers.host ?? '').toLowerCase(), userAgent: headers['user-agent'] ?? null, contentType: headers['content-type'] ?? null, body };
}

// ---------------------------------------------------------------- main
export function analyzePcap(bytes) {
  const d4 = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  const records = d4 === 0x0a0d0d0a ? readPcapng(bytes) : readPcap(bytes);
  const flows = new Map();
  const dnsByIp = new Map();
  const dnsQueries = new Map(); // name -> first ts
  const ipCount = new Map();
  let packets = 0;
  let parsed = 0;
  let start = Infinity;
  let end = 0;
  const links = new Set();

  for (const r of records) {
    packets++;
    links.add(r.link);
    if (r.ts) { start = Math.min(start, r.ts); end = Math.max(end, r.ts); }
    const ip = toIP(r.link, r.data);
    if (!ip) continue;
    const b = r.data;
    let o = ip.off;
    let proto;
    let src;
    let dst;
    let payloadEnd;
    if (ip.v === 4) {
      if (o + 20 > b.length) continue;
      const ihl = (b[o] & 0x0f) * 4;
      const total = (b[o + 2] << 8) | b[o + 3];
      const fragOff = ((b[o + 6] & 0x1f) << 8) | b[o + 7];
      if (fragOff) continue;
      proto = b[o + 9];
      src = ip4(b, o + 12);
      dst = ip4(b, o + 16);
      payloadEnd = Math.min(b.length, o + total);
      o += ihl;
    } else if (ip.v === 6) {
      if (o + 40 > b.length) continue;
      proto = b[o + 6];
      const plen = (b[o + 4] << 8) | b[o + 5];
      src = ip6(b, o + 8);
      dst = ip6(b, o + 24);
      payloadEnd = Math.min(b.length, o + 40 + plen);
      o += 40;
    } else continue;
    parsed++;
    ipCount.set(src, (ipCount.get(src) ?? 0) + 1);
    let sport;
    let dport;
    let payload;
    let syn = false;
    if (proto === 6) {
      if (o + 20 > payloadEnd) continue;
      sport = (b[o] << 8) | b[o + 1];
      dport = (b[o + 2] << 8) | b[o + 3];
      const doff = (b[o + 12] >> 4) * 4;
      syn = (b[o + 13] & 0x12) === 0x02;
      payload = b.subarray(o + doff, payloadEnd);
    } else if (proto === 17) {
      if (o + 8 > payloadEnd) continue;
      sport = (b[o] << 8) | b[o + 1];
      dport = (b[o + 2] << 8) | b[o + 3];
      payload = b.subarray(o + 8, payloadEnd);
      if (sport === 53 || dport === 53) {
        const dns = parseDNS(b, o + 8);
        if (dns) {
          for (const q of dns.questions) if (!dnsQueries.has(q)) dnsQueries.set(q, r.ts);
          if (dns.response) {
            const cname = new Map();
            for (const a of dns.answers) if (a.cname) cname.set(a.cname, a.name);
            for (const a of dns.answers) {
              if (!a.ip) continue;
              let n = a.name;
              while (cname.has(n) && n !== cname.get(n)) n = cname.get(n);
              const q = dns.questions[0] ?? n;
              if (!dnsByIp.has(a.ip)) dnsByIp.set(a.ip, q);
            }
          }
        }
        continue;
      }
    } else continue;

    const a = `${src}:${sport}`;
    const z = `${dst}:${dport}`;
    const key = `${proto}|${a < z ? a + '|' + z : z + '|' + a}`;
    let fl = flows.get(key);
    if (!fl) {
      // client = SYN sender, else the side with the higher (ephemeral) port
      const clientIsSrc = syn || (proto === 17 ? sport > dport : sport > dport);
      fl = { proto: proto === 6 ? 'tcp' : 'udp', client: clientIsSrc ? src : dst, cport: clientIsSrc ? sport : dport, server: clientIsSrc ? dst : src, sport: clientIsSrc ? dport : sport, first: r.ts, last: r.ts, up: 0, down: 0, packets: 0, clientBuf: [], clientBufLen: 0, sni: null, alpn: null, http: [] };
      flows.set(key, fl);
    }
    fl.last = r.ts;
    fl.packets++;
    const up = src === fl.client && sport === fl.cport;
    if (up) fl.up += payload.length; else fl.down += payload.length;
    if (up && payload.length && fl.clientBufLen < 16384) {
      fl.clientBuf.push(payload.slice());
      fl.clientBufLen += payload.length;
      if (!fl.sni && proto === 6) {
        const joined = new Uint8Array(fl.clientBufLen);
        let q = 0;
        for (const c of fl.clientBuf) { joined.set(c, q); q += c.length; }
        const t = tlsSNI(joined);
        if (t) { fl.sni = t.sni; fl.alpn = t.alpn; }
      }
      const h = proto === 6 ? httpRequest(payload) : null;
      if (h && fl.http.length < 50) fl.http.push({ ts: r.ts, ...h });
    }
  }

  // the capturing device: the private address that sent the most packets
  const device = [...ipCount].filter(([ip]) => isPrivateIP(ip)).sort((x, y) => y[1] - x[1])[0]?.[0] ?? null;
  const outFlows = [];
  for (const f of flows.values()) {
    if (isPrivateIP(f.server) && !(f.sport === 80 || f.sport === 443)) continue;
    const name = f.sni || f.http[0]?.host?.replace(/:\d+$/, '') || dnsByIp.get(f.server) || null;
    const protocol = f.proto === 'udp' ? (f.sport === 443 ? 'QUIC' : `UDP/${f.sport}`) : f.sni ? 'TLS' : f.http.length ? 'HTTP' : f.sport === 443 ? 'TLS?' : `TCP/${f.sport}`;
    outFlows.push({ host: name, ip: f.server, port: f.sport, protocol, alpn: f.alpn, first: f.first, last: f.last, up: f.up, down: f.down, packets: f.packets, http: f.http, fromDevice: f.client === device });
  }
  outFlows.sort((x, y) => x.first - y.first);
  return {
    packets, parsedPackets: parsed, links: [...links], start: Number.isFinite(start) ? start : null, end: end || null, device,
    flows: outFlows,
    dns: [...dnsQueries].map(([name, ts]) => ({ name, ts })).sort((x, y) => x.ts - y.ts),
  };
}

// Aggregate flows by host (DNS/SNI name, else IP).
export function hostsFromFlows(flows, dns = []) {
  const by = new Map();
  for (const f of flows) {
    const h = f.host ?? f.ip;
    if (!by.has(h)) by.set(h, { host: h, ips: new Set(), protocols: new Set(), first: f.first, last: f.last, up: 0, down: 0, flows: 0, http: [] });
    const x = by.get(h);
    x.ips.add(f.ip);
    x.protocols.add(f.protocol);
    x.first = Math.min(x.first, f.first);
    x.last = Math.max(x.last, f.last);
    x.up += f.up;
    x.down += f.down;
    x.flows++;
    for (const r of f.http) if (x.http.length < 20) x.http.push(r);
  }
  // names that were only resolved (DNS) without a captured connection
  for (const q of dns) if (!by.has(q.name)) by.set(q.name, { host: q.name, ips: new Set(), protocols: new Set(['DNS only']), first: q.ts, last: q.ts, up: 0, down: 0, flows: 0, http: [] });
  return [...by.values()].map((x) => ({ ...x, ips: [...x.ips], protocols: [...x.protocols] })).sort((a, b) => a.first - b.first);
}
