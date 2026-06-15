import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreAsset } from '../src/engine/riskEngine.ts';

const base = { riskScore: 0, severity: 'low', riskReasons: [], firstSeen: '' };
const sub = (value, metadata = {}) => ({ id: `subdomain:${value}`, type: 'subdomain', value, metadata, ...base });
const svc = (port, metadata = {}) => ({ id: `service:1.2.3.4:${port}`, type: 'service', value: `1.2.3.4:${port}`, metadata: { port, protocol: 'tcp', product: '', ...metadata }, ...base });
const noServices = new Map();

test('name keyword matches at a label boundary (developer -> dev)', () => {
  const r = scoreAsset(sub('developer.example.com'), noServices);
  assert.ok(r.reasons.some(x => /development environment/.test(x)));
});

test('name keyword does NOT match inside an unrelated word (digital !-> git)', () => {
  const r = scoreAsset(sub('digital.example.com'), noServices);
  assert.ok(!r.reasons.some(x => /version control/.test(x)), 'should not flag "git" inside "digital"');
});

test('name keyword does NOT match inside "gold" for "old"', () => {
  const r = scoreAsset(sub('gold.example.com'), noServices);
  assert.ok(!r.reasons.some(x => /unmaintained/.test(x)));
});

test('HTTP without HTTPS produces a cleartext finding', () => {
  const r = scoreAsset(sub('app.example.com', { http: true, https: false }), noServices);
  assert.ok(r.reasons.some(x => /without HTTPS/i.test(x)));
});

test('database service port is flagged and scored', () => {
  const r = scoreAsset(svc(3306), noServices);
  assert.ok(r.score >= 10);
  assert.ok(r.reasons.some(x => /MySQL/.test(x)));
});

test('exposed bucket is high severity', () => {
  const bucket = { id: 'bucket:b', type: 'bucket', value: 'b.s3.com', metadata: {}, ...base };
  const r = scoreAsset(bucket, noServices);
  assert.equal(r.severity, 'high');
});

test('a plain name with no signals stays low', () => {
  const r = scoreAsset(sub('www.example.com'), noServices);
  assert.equal(r.severity, 'low');
  assert.equal(r.score, 0);
});

test('multiple services on one IP add an attack-surface penalty', () => {
  const ip = { id: 'ip:1.2.3.4', type: 'ip', value: '1.2.3.4', metadata: { ports: [3306] }, ...base };
  const many = new Map([['1.2.3.4', 6]]);
  const r = scoreAsset(ip, many);
  assert.ok(r.reasons.some(x => /services exposed on single IP/.test(x)));
});
