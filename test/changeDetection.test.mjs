import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareScans } from '../src/engine/changeDetection.ts';

const asset = (id, riskScore = 0) => ({ id, type: 'subdomain', value: id, metadata: {}, riskScore, severity: 'low', riskReasons: [], firstSeen: '' });
const scan = (assets) => ({ id: 's', domain: 'x', timestamp: '', durationMs: 0, assets, relationships: [], stats: {}, logs: [], errors: [] });

test('compareScans detects added, removed and risk-changed assets', () => {
  const oldScan = scan([asset('a', 5), asset('b', 3)]);
  const newScan = scan([asset('a', 9), asset('c', 1)]);
  const r = compareScans(oldScan, newScan);

  assert.equal(r.summary.added, 1);    // c is new
  assert.equal(r.summary.removed, 1);  // b is gone
  assert.equal(r.summary.changed, 1);  // a: 5 -> 9
  assert.equal(r.newAssets[0].id, 'c');
  assert.equal(r.removedAssets[0].id, 'b');
  assert.deepEqual(
    { id: r.riskChanges[0].asset.id, from: r.riskChanges[0].oldScore, to: r.riskChanges[0].newScore },
    { id: 'a', from: 5, to: 9 }
  );
});

test('identical scans report no changes', () => {
  const s = scan([asset('a', 5)]);
  const r = compareScans(s, scan([asset('a', 5)]));
  assert.deepEqual(r.summary, { added: 0, removed: 0, changed: 0 });
});
