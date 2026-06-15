import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildGraph, severityColor, typeShape } from '../src/engine/graphBuilder.ts';

const a = (id, type, value) => ({ id, type, value, metadata: {}, riskScore: 0, severity: 'low', riskReasons: [], firstSeen: '' });

test('buildGraph maps assets to nodes and drops dangling edges', () => {
  const assets = [a('d', 'domain', 'x.com'), a('s', 'subdomain', 'a.x.com')];
  const rels = [
    { id: 'r1', sourceId: 'd', targetId: 's', type: 'parent_of' },
    { id: 'r2', sourceId: 'd', targetId: 'missing', type: 'parent_of' }, // dangling
  ];
  const g = buildGraph(assets, rels);

  assert.equal(g.nodes.length, 2);
  assert.equal(g.edges.length, 1, 'edge to a missing node should be dropped');
  assert.equal(g.edges[0].data.source, 'd');
});

test('buildGraph computes node degree', () => {
  const assets = [a('d', 'domain', 'x.com'), a('s', 'subdomain', 'a.x.com'), a('i', 'ip', '1.1.1.1')];
  const rels = [
    { id: 'r1', sourceId: 'd', targetId: 's', type: 'parent_of' },
    { id: 'r2', sourceId: 's', targetId: 'i', type: 'resolves_to' },
  ];
  const g = buildGraph(assets, rels);
  const sNode = g.nodes.find(n => n.data.id === 's');
  assert.equal(sNode.data.degree, 2); // one inbound, one outbound
});

test('severityColor returns a hex per severity; typeShape maps types', () => {
  for (const sev of ['low', 'medium', 'high', 'critical']) {
    assert.match(severityColor(sev), /^#[0-9a-f]{6}$/i);
  }
  assert.equal(typeShape('domain'), 'diamond');
  assert.equal(typeShape('ip'), 'ellipse');
});
