/**
 * Builds Cytoscape-compatible graph data from assets and relationships.
 */

import type { Asset, Relationship, GraphData, GraphNode, GraphEdge, Severity, AssetType } from '../types';

export function buildGraph(assets: Asset[], relationships: Relationship[]): GraphData {
  const assetIds = new Set(assets.map(a => a.id));

  const nodes: GraphNode[] = assets.map(a => ({
    data: {
      id: a.id,
      label: formatLabel(a),
      type: a.type,
      severity: a.severity,
      riskScore: a.riskScore,
      value: a.value,
      reasons: a.riskReasons,
      meta: a.metadata,
    },
  }));

  const edges: GraphEdge[] = relationships
    .filter(r => assetIds.has(r.sourceId) && assetIds.has(r.targetId))
    .map(r => ({
      data: {
        id: r.id,
        source: r.sourceId,
        target: r.targetId,
        label: r.type.replace(/_/g, ' '),
      },
    }));

  return { nodes, edges };
}

function formatLabel(a: Asset): string {
  switch (a.type) {
    case 'domain':
      return a.value;
    case 'subdomain': {
      // Show just the subdomain prefix
      const parts = a.value.split('.');
      return parts.length > 2 ? parts.slice(0, -2).join('.') : a.value;
    }
    case 'ip':
      return a.value;
    case 'service':
      return `${a.metadata.product || 'svc'}:${a.metadata.port}`;
    default:
      return a.value;
  }
}

/* ── Color helpers ── */

export function severityColor(sev: Severity): string {
  switch (sev) {
    case 'critical': return '#ef4444';
    case 'high':     return '#f97316';
    case 'medium':   return '#eab308';
    case 'low':      return '#22c55e';
  }
}

export function typeShape(type: AssetType): string {
  switch (type) {
    case 'domain':    return 'diamond';
    case 'subdomain': return 'round-rectangle';
    case 'ip':        return 'ellipse';
    case 'service':   return 'hexagon';
  }
}
