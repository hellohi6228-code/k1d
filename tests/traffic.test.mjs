// Network captures against fixtures from tools/build-demo-pcap.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../site/js/analyze.js';
import { bytesSource } from '../site/js/zip.js';
import { buildRisks } from '../site/js/risks.js';
import { isPcap, analyzePcap, hostsFromFlows, isPrivateIP } from '../site/js/pcap.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
const kb = { sdks: readJson('site/kb/sdks.json'), infra: readJson('site/kb/infra.json'), permissions: readJson('site/kb/permissions.json') };
const bytes = (name) => new Uint8Array(fs.readFileSync(path.join(root, 'tests/fixtures/formats', name)));
const scan = (name) => analyzeSource(bytesSource(bytes(name)), kb);
const FILES = ['capture-ethernet.pcap', 'capture-raw.pcapng', 'capture-wifi.pcap'];

test('pcap decoder: link types, SNI, ALPN, DNS-named QUIC, cleartext HTTP, byte counts', () => {
  for (const f of FILES) {
    const b = bytes(f);
    assert.ok(isPcap(b.subarray(0, 16)), f);
    const t = analyzePcap(b);
    assert.equal(t.packets, 9, f);
    assert.equal(t.parsedPackets, 9, `${f}: every frame decoded to IP`);
    assert.equal(t.device, '10.0.2.16', f);
    const by = Object.fromEntries(t.flows.map((x) => [x.host ?? x.ip, x]));
    assert.equal(by['analytics.us.tiktok.com'].protocol, 'TLS', f);
    assert.equal(by['analytics.us.tiktok.com'].alpn, 'h2', f);
    assert.equal(by['analytics.us.tiktok.com'].down, 3000, f);
    assert.equal(by['events.k1d-demo.cn'].protocol, 'QUIC', `${f}: QUIC named from the DNS answer`);
    assert.equal(by['track.k1d-demo.example'].http[0].method, 'POST', f);
    assert.match(by['track.k1d-demo.example'].http[0].path, /^\/v1\/track\?gaid=/);
    assert.ok(t.dns.some((d) => d.name === 'events.k1d-demo.cn'), f);
    const hosts = hostsFromFlows(t.flows, t.dns).map((h) => h.host);
    assert.deepEqual(hosts, ['analytics.us.tiktok.com', 'track.k1d-demo.example', 'events.k1d-demo.cn', 'graph.facebook.com'], `${f}: ordered by first contact`);
  }
  assert.ok(isPrivateIP('10.0.2.16') && isPrivateIP('192.168.1.2') && !isPrivateIP('203.0.113.10'));
  assert.ok(!isPcap(new Uint8Array([0x50, 0x4b, 3, 4])));
});

test('network capture through analyzeSource: SDKs from traffic, PRC host, masked credential in HTTP', async () => {
  const r = await scan('capture-wifi.pcap');
  assert.equal(r.platform, 'traffic');
  assert.ok(r.traffic);
  assert.equal(r.traffic.duration, 9.1);
  const sdk = Object.fromEntries(r.sdks.map((s) => [s.id, s]));
  for (const id of ['tiktok_sdk', 'meta_sdk']) {
    assert.ok(sdk[id], id);
    assert.ok(sdk[id].evidence.some((e) => e.type === 'traffic'), `${id}: evidence is runtime traffic`);
  }
  const cn = r.traffic.hosts.find((h) => h.host === 'events.k1d-demo.cn');
  assert.ok(cn.cnIndicators.length, '.cn host flagged');
  assert.equal(r.traffic.http.length, 1);
  assert.deepEqual(r.secrets.map((s) => s.type), ['aws_access_key']);
  assert.ok(r.secrets[0].value.includes('…'), 'masked');
  const ep = r.endpoints.find((e) => e.host === 'analytics.us.tiktok.com');
  assert.equal(ep.traffic.down, 3000);
});

test('traffic risk signals use the consent time', async () => {
  const r = await scan('capture-raw.pcapng');
  const area = (ctx, id) => buildRisks(r, { category: 'game', childDirected: false, ...ctx }, null).find((a) => a.id === id);
  const fd = area({ consentAt: 5 }, 'foreign_data');
  assert.equal(fd.status, 'signals');
  assert.ok(fd.signals.some((s) => /events\.k1d-demo\.cn/.test(s.en)), 'PRC host contacted at runtime');
  const wt = area({ consentAt: 5 }, 'wiretap');
  const pre = wt.signals.find((s) => /before the consent time/.test(s.en));
  assert.ok(pre, 'tracking hosts before consent');
  assert.match(pre.en, /analytics\.us\.tiktok\.com/);
  assert.doesNotMatch(pre.en, /graph\.facebook\.com/, 'contacted at 9s, after consent at 5s');
  const none = area({}, 'wiretap');
  assert.ok(!none.signals.some((s) => /before the consent time/.test(s.en)), 'no consent time, no before-consent claim');
});
