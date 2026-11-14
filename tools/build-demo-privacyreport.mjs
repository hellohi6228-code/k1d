// Builds a synthetic iPhone App Privacy Report export (NDJSON) for tests, following the record
// layout in Apple's "Inspecting app activity data". All apps and domains are made up.
// Usage: node tools/build-demo-privacyreport.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'tests', 'fixtures', 'formats', 'App_Privacy_Report_v4_demo.ndjson');
const ts = (h, m = 0) => `2026-11-10T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:00.000-05:00`;
const net = (bundleID, domain, hits, first, last, extra = {}) => ({ domain, firstTimeStamp: first, context: '', timeStamp: last, domainType: 2, initiatedType: 'AppInitiated', hits, type: 'networkActivity', domainOwner: '', bundleID, ...extra });
const access = (app, category, id, begin, end) => [
  { accessor: { identifier: app, identifierType: 'bundleID' }, category, identifier: id, kind: 'intervalBegin', timeStamp: begin, type: 'access' },
  { accessor: { identifier: app, identifierType: 'bundleID' }, category, identifier: id, kind: 'intervalEnd', timeStamp: end, type: 'access' },
];
const GAME = 'com.k1d.demo.idlequest';
const NOTES = 'com.k1d.demo.notes';
const records = [
  ...access(GAME, 'camera', 'A1', ts(9, 0), ts(9, 2)),
  ...access(GAME, 'location', 'A2', ts(9, 5), ts(9, 6)),
  ...access(NOTES, 'photos', 'A3', ts(10, 0), ts(10, 1)),
  net(GAME, 'analytics.us.tiktok.com', 42, ts(8, 0), ts(20, 0), { domainType: 1, domainOwner: 'TikTok Pte. Ltd.' }),
  net(GAME, 'graph.facebook.com', 17, ts(8, 1), ts(19, 0), { domainType: 1, domainOwner: 'Meta Platforms, Inc.' }),
  net(GAME, 'events.k1d-demo.cn', 9, ts(8, 2), ts(18, 0)),
  net(GAME, 'stats.k1d-demo-partner.com', 5, ts(8, 3), ts(18, 0), { domainOwner: 'Tencent Holdings Ltd.' }),
  net(GAME, 'api.k1d-demo.example', 120, ts(8, 0), ts(21, 0)),
  net(NOTES, 'sync.k1d-notes.example', 30, ts(7, 0), ts(22, 0)),
  net('com.apple.mobilesafari', 'news.k1d-demo.example', 3, ts(12, 0), ts(12, 5), { initiatedType: 'NonAppInitiated', context: 'news.k1d-demo.example' }),
];
fs.writeFileSync(out, records.map((r) => JSON.stringify(r)).join('\n') + '\n{"broken json\n');
console.log(`Wrote ${path.relative(root, out)} (${records.length} records + 1 malformed line)`);
