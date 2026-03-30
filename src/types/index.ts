/* ── Core Asset Types ── */

export type AssetType = 'domain' | 'subdomain' | 'ip' | 'service';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type RelationType = 'resolves_to' | 'exposes' | 'cname_to' | 'parent_of';

export interface BaseAsset {
  id: string;
  value: string;
  riskScore: number;
  severity: Severity;
  riskReasons: string[];
  firstSeen: string;
}

export interface DomainMetadata {
  dnsRecordCount?: number;
  ips?: string[];
  cnames?: string[];
  http?: boolean;
  https?: boolean;
}

export interface IpMetadata {
  org?: string;
  isp?: string;
  os?: string;
  country?: string;
  city?: string;
  portCount?: number;
  ports?: number[];
}

export interface ServiceMetadata {
  port: number;
  protocol: string;
  product: string;
  version?: string;
  banner?: string;
}

export type Metadata =
  | DomainMetadata
  | IpMetadata
  | ServiceMetadata
  | Record<string, string | number | boolean | string[]>;

export interface DomainAsset extends BaseAsset {
  type: 'domain' | 'subdomain';
  metadata: DomainMetadata;
}

export interface IpAsset extends BaseAsset {
  type: 'ip';
  metadata: IpMetadata;
}

export interface ServiceAsset extends BaseAsset {
  type: 'service';
  metadata: ServiceMetadata;
}

export type Asset = DomainAsset | IpAsset | ServiceAsset;

export interface Relationship {
  id: string;
  sourceId: string;
  targetId: string;
  type: RelationType;
  metadata?: Record<string, string>;
}

export interface ScanStats {
  totalAssets: number;
  domains: number;
  subdomains: number;
  ips: number;
  services: number;
  avgRisk: number;
  maxRisk: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanResult {
  id: string;
  domain: string;
  timestamp: string;
  durationMs: number;
  assets: Asset[];
  relationships: Relationship[];
  stats: ScanStats;
  logs: string[];
  errors: string[];
}

export interface CompareResult {
  newAssets: Asset[];
  removedAssets: Asset[];
  riskChanges: { asset: Asset; oldScore: number; newScore: number }[];
  summary: { added: number; removed: number; changed: number };
}

/* ── Graph visualization ── */

export interface GraphNode {
  data: {
    id: string;
    label: string;
    type: AssetType;
    severity: Severity;
    riskScore: number;
    value: string;
    reasons: string[];
    meta: Metadata;
  };
}

export interface GraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label: string;
  };
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/* ── API connector types ── */

export interface DnsRecord {
  type: string;
  value: string;
  ttl?: number;
}

export interface ShodanService {
  port: number;
  protocol: string;
  product?: string;
  version?: string;
  banner?: string;
}

export interface ShodanHostResult {
  ip: string;
  ports: number[];
  services: ShodanService[];
  os?: string;
  org?: string;
  isp?: string;
  country?: string;
  city?: string;
}

export interface ScanConfig {
  domain: string;
  shodanKey: string;
  enableCT: boolean;
  enableShodan: boolean;
  enableActivePortScan?: boolean;
  activePortScanPorts?: number[];
  onProgress: (phase: string, pct: number, detail: string) => void;
  onLog: (msg: string) => void;
}
