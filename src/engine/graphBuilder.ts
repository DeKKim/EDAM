/**
 * Builds Cytoscape-compatible graph data from assets and relationships.
 */

import type { Asset, Relationship, GraphData, GraphNode, GraphEdge, Severity, AssetType } from '../types';

export function buildGraph(assets: Asset[], relationships: Relationship[]): GraphData {
  const assetIds = new Set(assets.map(a => a.id));
  const degreeById = new Map<string, { inbound: number; outbound: number }>();

  for (const asset of assets) {
    degreeById.set(asset.id, { inbound: 0, outbound: 0 });
  }

  for (const rel of relationships) {
    if (!assetIds.has(rel.sourceId) || !assetIds.has(rel.targetId)) continue;
    const source = degreeById.get(rel.sourceId);
    const target = degreeById.get(rel.targetId);
    if (source) source.outbound += 1;
    if (target) target.inbound += 1;
  }

  const nodes: GraphNode[] = assets.map(a => ({
    data: {
      id: a.id,
      label: formatLabel(a),
      shortLabel: formatShortLabel(a),
      type: a.type,
      severity: a.severity,
      riskScore: a.riskScore,
      value: a.value,
      tier: assetTier(a.type),
      size: assetSize(a),
      degree: (degreeById.get(a.id)?.inbound || 0) + (degreeById.get(a.id)?.outbound || 0),
      inbound: degreeById.get(a.id)?.inbound || 0,
      outbound: degreeById.get(a.id)?.outbound || 0,
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
        relationType: r.type,
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
      return `${(a.metadata as any).product || 'svc'}:${(a.metadata as any).port}`;
    case 'bucket':
      return `🪣 ${a.value.split('.')[0]}`;
    default:
      return assertNever(a);
  }
}

function formatShortLabel(a: Asset): string {
  switch (a.type) {
    case 'domain':
      return a.value;
    case 'subdomain': {
      const parts = a.value.split('.');
      return parts.length > 2 ? parts.slice(0, -2).join('.') || a.value : a.value;
    }
    case 'ip':
      return a.value;
    case 'service':
      return `${(a.metadata as any).port}/${(a.metadata as any).protocol || 'tcp'}`;
    case 'bucket':
      return a.value.split('.')[0];
    default:
      return assertNever(a);
  }
}

function assetTier(type: AssetType): number {
  switch (type) {
    case 'domain':
      return 4;
    case 'subdomain':
      return 3;
    case 'ip':
      return 2;
    case 'service':
    case 'bucket':
      return 1;
  }
}

function assetSize(asset: Asset): number {
  const baseSize: Record<AssetType, number> = {
    domain: 82,
    subdomain: 60,
    ip: 52,
    service: 40,
    bucket: 44,
  };
  return baseSize[asset.type] + Math.min(22, Math.round(asset.riskScore / 8));
}

function assertNever(value: never): never {
  throw new Error(`Unhandled asset type: ${JSON.stringify(value)}`);
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
    case 'bucket':    return 'triangle';
  }
}
