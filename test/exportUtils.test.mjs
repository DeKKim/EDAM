import { test } from 'node:test';
import assert from 'node:assert/strict';
import { exportCsv, exportJson, exportMarkdown } from '../src/engine/exportUtils.ts';

const scan = {
  id: 's',
  domain: 'x.com',
  timestamp: new Date(0).toISOString(),
  durationMs: 1500,
  assets: [
    { id: 'd', type: 'domain', value: 'x.com', metadata: {}, riskScore: 5, severity: 'low', riskReasons: ['name signal'], firstSeen: new Date(0).toISOString() },
    { id: 'svc', type: 'service', value: '1.1.1.1:3306', metadata: { port: 3306 }, riskScore: 10, severity: 'medium', riskReasons: ['db exposed'], firstSeen: new Date(0).toISOString() },
  ],
  relationships: [],
  stats: { totalAssets: 2, domains: 1, subdomains: 0, ips: 0, services: 1, buckets: 0, avgRisk: 8, maxRisk: 10, critical: 0, high: 0, medium: 1, low: 1 },
  logs: [],
  errors: [],
};

test('CSV export has the header and an escaped data row', () => {
  const csv = exportCsv(scan);
  assert.ok(csv.includes('Risk Score'));
  assert.ok(csv.includes('Recommended Check'));
  assert.ok(csv.includes('x.com'));
});

test('JSON export round-trips to the same scan', () => {
  const obj = JSON.parse(exportJson(scan));
  assert.equal(obj.domain, 'x.com');
  assert.equal(obj.assets.length, 2);
});

test('Markdown export includes the report title and a recommendation for the DB service', () => {
  const md = exportMarkdown(scan);
  assert.ok(md.includes('# External Asset Scan Report'));
  assert.ok(md.includes('x.com'));
  assert.match(md, /private network/i); // recommendation for the exposed database
});
