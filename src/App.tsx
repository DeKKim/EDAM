import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import cytoscape from 'cytoscape';
import {
  Shield, Search, LayoutDashboard, Network, Table2, History,
  Download, ChevronRight, AlertTriangle, Globe, Server, Wifi,
  Play, Settings, Trash2, Eye, ArrowUpDown, X, RefreshCw,
  ChevronDown, ChevronUp, GitCompareArrows, Filter, Focus, Sparkles, Cloud,
} from 'lucide-react';
import type { ScanResult, Asset, Severity, AssetType, CompareResult, RelationType } from './types';
import { runScan } from './api/orchestrator';
import { buildGraph, severityColor, typeShape } from './engine/graphBuilder';
import { compareScans } from './engine/changeDetection';
import {
  saveToHistory, loadHistory, deleteFromHistory,
  exportCsv, exportJson, exportMarkdown, downloadFile,
} from './engine/exportUtils';

/* ── Helpers ── */
type View = 'scan' | 'dashboard' | 'graph' | 'risk' | 'history' | 'export';
type ScanMode = 'fast' | 'balanced' | 'deep';

// Use environment variables for API keys
const SHODAN_API_KEY = import.meta.env.VITE_SHODAN_API_KEY || '';
const CENSYS_ID = import.meta.env.VITE_CENSYS_API_ID || '';
const CENSYS_SECRET = import.meta.env.VITE_CENSYS_API_SECRET || '';
const GREYHAT_KEY = import.meta.env.VITE_GREYHAT_API_KEY || '';

const SEV_COLORS: Record<Severity, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
};

const SEV_TEXT: Record<Severity, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
};

const TYPE_ICONS: Record<AssetType, typeof Globe> = {
  domain: Globe,
  subdomain: ChevronRight,
  ip: Server,
  service: Wifi,
  bucket: Cloud,
};

const RELATION_COLORS: Record<RelationType, string> = {
  parent_of: '#38bdf8',
  resolves_to: '#22c55e',
  exposes: '#f97316',
  cname_to: '#a78bfa',
  discovered_bucket: '#f59e0b',
};

/** Mirrors the geometric shapes Cytoscape draws per asset type, for the graph legend. */
function NodeShape({ type, className = 'h-4 w-4' }: { type: AssetType; className?: string }) {
  const props = { fill: '#0f172a', stroke: '#94a3b8', strokeWidth: 1.6 };
  const shape = (() => {
    switch (type) {
      case 'domain': return <polygon points="10,2 18,10 10,18 2,10" {...props} />;
      case 'subdomain': return <rect x="2.5" y="5" width="15" height="10" rx="3" {...props} />;
      case 'ip': return <circle cx="10" cy="10" r="7.5" {...props} />;
      case 'service': return <polygon points="6,3 14,3 18.5,10 14,17 6,17 1.5,10" {...props} />;
      case 'bucket': return <polygon points="10,3 18,17 2,17" {...props} />;
    }
  })();
  return <svg viewBox="0 0 20 20" className={className}>{shape}</svg>;
}

function Badge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-bold text-white ${SEV_COLORS[severity]}`}>
      {severity.toUpperCase()}
    </span>
  );
}

type ExposurePath = {
  assets: Asset[];
  score: number;
  severity: Severity;
};

type InfrastructureHub = {
  ip: Asset;
  children: Asset[];
  services: Asset[];
  risk: number;
};

type MappingSummary = {
  domain: string;
  discoveredNames: number;
  resolvedIps: number;
  exposedServices: number;
  buckets: number;
  exposurePaths: number;
  topHub?: InfrastructureHub;
  topRisk?: Asset;
};

type GraphLayout = 'breadthfirst' | 'infrastructure';
type FindingCategory =
  | 'Remote Access'
  | 'Data Service'
  | 'Web Exposure'
  | 'Cloud Storage'
  | 'Sensitive Name'
  | 'Shared Host'
  | 'Mail/DNS'
  | 'Inventory';

const SCAN_MODE_CONFIG: Record<ScanMode, { label: string; maxSubdomains: number; shodanLimit: number; description: string }> = {
  fast: {
    label: 'Fast Demo',
    maxSubdomains: 60,
    shodanLimit: 0,
    description: 'Quick passive map for presentation or first look.',
  },
  balanced: {
    label: 'Balanced',
    maxSubdomains: 120,
    shodanLimit: 35,
    description: 'Default coverage with controlled enrichment time.',
  },
  deep: {
    label: 'Deep Review',
    maxSubdomains: 200,
    shodanLimit: 75,
    description: 'Broader mapping with deep active port validation.',
  },
};

const FINDING_COLORS: Record<FindingCategory, string> = {
  'Remote Access': 'text-red-400',
  'Data Service': 'text-orange-400',
  'Web Exposure': 'text-cyan-400',
  'Cloud Storage': 'text-amber-400',
  'Sensitive Name': 'text-purple-400',
  'Shared Host': 'text-blue-400',
  'Mail/DNS': 'text-emerald-400',
  Inventory: 'text-slate-400',
};

function buildExposurePaths(scan: ScanResult): ExposurePath[] {
  const assetById = new Map(scan.assets.map(asset => [asset.id, asset]));
  const outgoing = new Map<string, string[]>();

  for (const rel of scan.relationships) {
    if (!outgoing.has(rel.sourceId)) outgoing.set(rel.sourceId, []);
    outgoing.get(rel.sourceId)!.push(rel.targetId);
  }

  const roots = scan.assets.filter(asset => asset.type === 'domain');
  const paths: ExposurePath[] = [];

  const walk = (assetId: string, path: Asset[], visited: Set<string>) => {
    const asset = assetById.get(assetId);
    if (!asset || visited.has(assetId)) return;

    const nextPath = [...path, asset];
    const nextVisited = new Set(visited);
    nextVisited.add(assetId);

    if (asset.type === 'service' || asset.type === 'bucket') {
      paths.push({ assets: nextPath, score: asset.riskScore, severity: asset.severity });
    }

    for (const childId of outgoing.get(assetId) || []) {
      walk(childId, nextPath, nextVisited);
    }
  };

  roots.forEach(root => walk(root.id, [], new Set()));

  return paths
    .sort((a, b) => b.score - a.score || b.assets.length - a.assets.length)
    .slice(0, 6);
}

function findInfrastructureHubs(scan: ScanResult): InfrastructureHub[] {
  const assetById = new Map(scan.assets.map(asset => [asset.id, asset]));

  return scan.assets
    .filter(asset => asset.type === 'ip')
    .map(ip => {
      const linkedRels = scan.relationships.filter(rel => rel.sourceId === ip.id || rel.targetId === ip.id);
      const linkedAssets = linkedRels
        .map(rel => assetById.get(rel.sourceId === ip.id ? rel.targetId : rel.sourceId))
        .filter((asset): asset is Asset => Boolean(asset));

      const children = linkedAssets.filter(asset => asset.type === 'subdomain' || asset.type === 'domain');
      const services = linkedAssets.filter(asset => asset.type === 'service');
      const risk = Math.max(ip.riskScore, ...linkedAssets.map(asset => asset.riskScore), 0);

      return { ip, children, services, risk };
    })
    .filter(hub => hub.children.length + hub.services.length >= 3)
    .sort((a, b) => b.risk - a.risk || (b.children.length + b.services.length) - (a.children.length + a.services.length))
    .slice(0, 5);
}

function buildMappingSummary(scan: ScanResult, exposurePaths: ExposurePath[], hubs: InfrastructureHub[]): MappingSummary {
  const topRisk = [...scan.assets].sort((a, b) => b.riskScore - a.riskScore)[0];

  return {
    domain: scan.domain,
    discoveredNames: scan.assets.filter(asset => asset.type === 'domain' || asset.type === 'subdomain').length,
    resolvedIps: scan.assets.filter(asset => asset.type === 'ip').length,
    exposedServices: scan.assets.filter(asset => asset.type === 'service').length,
    buckets: scan.assets.filter(asset => asset.type === 'bucket').length,
    exposurePaths: exposurePaths.length,
    topHub: hubs[0],
    topRisk,
  };
}

function buildInfrastructurePositions(assets: Asset[], relationships: { sourceId: string; targetId: string }[]) {
  const assetById = new Map(assets.map(asset => [asset.id, asset]));
  const byType: Record<AssetType, Asset[]> = {
    domain: [], subdomain: [], ip: [], service: [], bucket: [],
  };
  for (const asset of assets) byType[asset.type].push(asset);

  // Map each name/service to the IP it hangs off, so we can align them in rows.
  const ipByName = new Map<string, string>();
  const ipByService = new Map<string, string>();
  const linkCount = new Map<string, number>();
  for (const rel of relationships) {
    linkCount.set(rel.sourceId, (linkCount.get(rel.sourceId) || 0) + 1);
    linkCount.set(rel.targetId, (linkCount.get(rel.targetId) || 0) + 1);

    const source = assetById.get(rel.sourceId);
    const target = assetById.get(rel.targetId);
    if (!source || !target) continue;

    if ((source.type === 'domain' || source.type === 'subdomain') && target.type === 'ip') ipByName.set(source.id, target.id);
    if (source.type === 'ip' && (target.type === 'domain' || target.type === 'subdomain')) ipByName.set(target.id, source.id);
    if (source.type === 'ip' && target.type === 'service') ipByService.set(target.id, source.id);
    if (source.type === 'service' && target.type === 'ip') ipByService.set(source.id, target.id);
  }

  // Busiest / riskiest IP anchors first so the densest part of the map sits in the middle.
  const sortedIps = [...byType.ip].sort((a, b) =>
    (linkCount.get(b.id) || 0) - (linkCount.get(a.id) || 0) || b.riskScore - a.riskScore
  );

  const groupBy = (items: Asset[], lookup: Map<string, string>) => {
    const grouped = new Map<string, Asset[]>();
    const loose: Asset[] = [];
    for (const item of items) {
      const ipId = lookup.get(item.id);
      if (!ipId) { loose.push(item); continue; }
      if (!grouped.has(ipId)) grouped.set(ipId, []);
      grouped.get(ipId)!.push(item);
    }
    return { grouped, loose };
  };

  const { grouped: namesByIp, loose: looseNames } = groupBy(byType.subdomain, ipByName);
  const { grouped: svcByIp, loose: looseServices } = groupBy(byType.service, ipByService);

  const positions: Record<string, { x: number; y: number }> = {};
  const domainX = -620, bucketX = -430, nameX = -240, ipX = 150, svcX = 540;
  const rowStep = 46, blockGap = 42;

  // Give every IP a vertical block tall enough for the larger of its name / service column,
  // then stack the blocks so no rows overlap.
  let cursor = 0;
  const blocks = sortedIps.map(ip => {
    const names = namesByIp.get(ip.id) || [];
    const services = svcByIp.get(ip.id) || [];
    const rows = Math.max(names.length, services.length, 1);
    const height = rows * rowStep;
    const block = { ip, names, services, top: cursor, height };
    cursor += height + blockGap;
    return block;
  });
  const shift = Math.max(0, cursor - blockGap) / 2;

  const placeGroup = (items: Asset[], x: number, blockTop: number, blockHeight: number) => {
    if (items.length === 0) return;
    const groupHeight = (items.length - 1) * rowStep;
    const start = blockTop + (blockHeight - groupHeight) / 2;
    items.forEach((asset, index) => { positions[asset.id] = { x, y: start + index * rowStep }; });
  };

  for (const block of blocks) {
    const top = block.top - shift;
    positions[block.ip.id] = { x: ipX, y: top + block.height / 2 };
    placeGroup(block.names, nameX, top, block.height);
    placeGroup(block.services, svcX, top, block.height);
  }

  const placeColumn = (items: Asset[], x: number, startY: number) => {
    const offset = ((items.length - 1) * 92) / 2;
    items.forEach((asset, index) => { positions[asset.id] = { x, y: startY + index * 92 - offset }; });
  };

  // Domain(s) and buckets sit on the left; buckets link straight to the domain.
  placeColumn(byType.domain, domainX, 0);
  placeColumn(byType.bucket, bucketX, 0);

  // Names / services with no resolved IP go in a parking lane below the anchored blocks.
  const parkY = shift + 120;
  placeColumn(looseNames, nameX, parkY);
  placeColumn(looseServices, svcX, parkY);

  return positions;
}

function summarizeExposure(asset: Asset): string {
  if (asset.type === 'domain' || asset.type === 'subdomain') {
    const http = 'http' in asset.metadata && asset.metadata.http;
    const https = 'https' in asset.metadata && asset.metadata.https;
    const ips = 'ips' in asset.metadata && Array.isArray(asset.metadata.ips) ? asset.metadata.ips.length : 0;
    if (http || https) return `${https ? 'HTTPS' : ''}${http ? `${https ? ' + ' : ''}HTTP` : ''}${ips ? `, ${ips} IPs` : ''}`;
    return ips ? `${ips} resolved IPs` : 'Discovered name';
  }

  if (asset.type === 'ip') {
    const ports = Array.isArray(asset.metadata.ports) ? asset.metadata.ports : [];
    return ports.length ? `${ports.length} open ports: ${ports.slice(0, 6).join(', ')}${ports.length > 6 ? '...' : ''}` : 'Resolved host';
  }

  if (asset.type === 'service') {
    return `${asset.metadata.protocol}/${asset.metadata.port} ${asset.metadata.product || 'service'}`;
  }

  return asset.type === 'bucket' && asset.metadata.provider ? `${asset.metadata.provider} bucket` : 'Cloud bucket';
}

function summarizeEvidence(asset: Asset): string {
  if (asset.riskReasons.length > 0) return asset.riskReasons.slice(0, 3).join(' | ');
  if (asset.type === 'ip' && asset.metadata.org) return `Observed organization: ${asset.metadata.org}`;
  if (asset.type === 'service' && asset.metadata.banner) return asset.metadata.banner;
  return 'No specific risk signal beyond asset exposure.';
}

function recommendAction(asset: Asset): string {
  const reasons = asset.riskReasons.join(' ').toLowerCase();

  if (asset.type === 'service') {
    const port = asset.metadata.port;
    const product = `${asset.metadata.product || ''} ${asset.metadata.banner || ''}`.toLowerCase();

    if ([1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017].includes(port)) {
      return 'Database/cache exposure: restrict to private networks or VPN, enforce auth, and verify no public data access.';
    }
    if ([23].includes(port)) {
      return 'Disable Telnet and replace with SSH over restricted source IPs.';
    }
    if ([3389, 5900, 5901].includes(port)) {
      return 'Remote desktop exposure: require VPN/MFA, restrict source IPs, and review brute-force protections.';
    }
    if ([445, 139, 135].includes(port)) {
      return 'Windows sharing/RPC exposure: block from internet and confirm firewall segmentation.';
    }
    if ([21, 110, 143].includes(port)) {
      return 'Cleartext protocol exposure: migrate to encrypted alternative and check credential leakage risk.';
    }
    if ([25, 465, 587, 993, 995].includes(port)) {
      return 'Mail service exposure: verify SPF/DKIM/DMARC, relay restrictions, and TLS configuration.';
    }
    if ([80, 81, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090].includes(port)) {
      if (/jenkins|grafana|kibana|prometheus|phpmyadmin|adminer|tomcat|weblogic|jira|confluence|nexus|artifactory/.test(product)) {
        return 'Admin/devops web app exposed: require SSO/MFA, patch it, and restrict access by network.';
      }
      return 'Web service exposure: confirm owner, enforce HTTPS, review auth, headers, and default pages.';
    }
    if (port === 22) {
      return 'SSH exposure: restrict source IPs, disable password login, and enforce key/MFA policy.';
    }
    return 'Service exposure: confirm business owner, expected internet access, patch level, and access controls.';
  }

  if (asset.type === 'bucket') {
    return 'Cloud bucket exposure: disable public listing/write, review object sensitivity, and enable access logging.';
  }

  if (asset.type === 'ip') {
    const ports = Array.isArray(asset.metadata.ports) ? asset.metadata.ports : [];
    if (ports.some(port => [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017].includes(port))) {
      return 'Host exposes data services: move behind private network and verify firewall rules.';
    }
    if (ports.some(port => [22, 23, 3389, 5900, 5901].includes(port))) {
      return 'Host exposes remote administration: require VPN/MFA and source-IP restrictions.';
    }
    if (ports.some(port => [135, 139, 445].includes(port))) {
      return 'Host exposes Windows sharing/RPC: block internet access immediately unless explicitly required.';
    }
    if (ports.length > 5) {
      return 'Host has broad exposure: reduce open services and split public/private roles.';
    }
    return ports.length ? 'Host has open services: validate each port owner and firewall policy.' : 'Resolved host: verify ownership and whether it should remain externally visible.';
  }

  if (asset.type === 'domain' || asset.type === 'subdomain') {
    if (reasons.includes('http available without https')) {
      return 'Enable HTTPS redirect, HSTS, and remove cleartext-only HTTP exposure.';
    }
    if (/dev|test|stag|uat|qa|demo|beta|preview/.test(asset.value)) {
      return 'Non-production name exposed: restrict by VPN/IP allowlist or remove public DNS if not needed.';
    }
    if (/admin|portal|login|sso|auth|vpn/.test(asset.value)) {
      return 'Access portal exposed: verify MFA, SSO policy, lockout controls, and source restrictions.';
    }
    if (/jenkins|git|jira|grafana|kibana|prometheus|nexus|artifactory|sonar|phpmyadmin/.test(asset.value)) {
      return 'Devops/admin tool name exposed: confirm patching, MFA, and network restrictions.';
    }
    if (/internal|old|legacy|backup|debug|db|ftp/.test(asset.value)) {
      return 'Sensitive naming pattern: validate owner, remove stale DNS, or restrict exposure.';
    }
    if (reasons.includes('cname chain')) {
      return 'CNAME observed: verify third-party/cloud target ownership and dangling DNS risk.';
    }
    if (asset.metadata.http || asset.metadata.https) {
      return 'Reachable web asset: confirm owner, TLS posture, authentication, and expected exposure.';
    }
  }

  return 'Inventory item: confirm ownership, business purpose, and expected external visibility.';
}

function primaryFindingCategory(asset: Asset): FindingCategory {
  const reasons = asset.riskReasons.join(' ').toLowerCase();
  const value = asset.value.toLowerCase();

  if (asset.type === 'bucket') return 'Cloud Storage';

  if (asset.type === 'service') {
    const port = asset.metadata.port;
    if ([22, 23, 3389, 5900, 5901].includes(port)) return 'Remote Access';
    if ([1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017].includes(port)) return 'Data Service';
    if ([25, 53, 110, 143, 465, 587, 993, 995].includes(port)) return 'Mail/DNS';
    if ([80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090].includes(port)) return 'Web Exposure';
  }

  if (asset.type === 'ip') {
    const ports = Array.isArray(asset.metadata.ports) ? asset.metadata.ports : [];
    if (ports.some(port => [22, 23, 3389, 5900, 5901].includes(port))) return 'Remote Access';
    if (ports.some(port => [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017].includes(port))) return 'Data Service';
    if (ports.length > 5 || reasons.includes('attack surface')) return 'Shared Host';
    if (ports.some(port => [25, 53, 110, 143, 465, 587, 993, 995].includes(port))) return 'Mail/DNS';
  }

  if (
    /dev|test|stag|uat|qa|demo|beta|preview|admin|portal|login|sso|auth|vpn|internal|legacy|backup|debug|jenkins|git|jira|grafana|kibana|prometheus|nexus|artifactory|sonar|phpmyadmin/.test(value) ||
    reasons.includes('subdomain contains')
  ) {
    return 'Sensitive Name';
  }

  if (reasons.includes('http') || asset.metadata && 'http' in asset.metadata && (asset.metadata.http || asset.metadata.https)) {
    return 'Web Exposure';
  }

  return 'Inventory';
}

function buildFindingCategories(assets: Asset[]) {
  const counts = new Map<FindingCategory, { category: FindingCategory; count: number; maxRisk: number; examples: Asset[] }>();

  for (const asset of assets) {
    const category = primaryFindingCategory(asset);
    const current = counts.get(category) || { category, count: 0, maxRisk: 0, examples: [] };
    current.count += 1;
    current.maxRisk = Math.max(current.maxRisk, asset.riskScore);
    if (asset.riskScore > 0 && current.examples.length < 3) current.examples.push(asset);
    counts.set(category, current);
  }

  return Array.from(counts.values())
    .filter(item => item.category !== 'Inventory' || item.maxRisk > 0)
    .sort((a, b) => b.maxRisk - a.maxRisk || b.count - a.count);
}

function buildExecutiveSummary(scan: ScanResult): string {
  const categories = buildFindingCategories(scan.assets).filter(item => item.category !== 'Inventory');
  const topCategory = categories[0];
  const topAsset = [...scan.assets].sort((a, b) => b.riskScore - a.riskScore)[0];
  const highRisk = scan.stats.critical + scan.stats.high;
  const exposed = scan.stats.services + scan.stats.buckets;

  if (!topAsset) {
    return `EDAM did not identify assets for ${scan.domain}.`;
  }

  const focus = topCategory
    ? `Main finding category: ${topCategory.category.toLowerCase()} (${topCategory.count} assets).`
    : 'No major risk category dominated this scan.';

  return `EDAM mapped ${scan.stats.totalAssets} assets for ${scan.domain}, including ${scan.stats.subdomains} subdomains, ${scan.stats.ips} IPs, and ${exposed} exposed endpoints. ${highRisk} assets are high or critical risk. ${focus} Highest observed risk is ${topAsset.riskScore} on ${topAsset.value}.`;
}

/* ══════════════════════════════════════════════════════════════
   MAIN APP
   ══════════════════════════════════════════════════════════════ */

export default function App() {
  const [view, setView] = useState<View>('scan');
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState({ phase: '', pct: 0, detail: '' });
  const [logs, setLogs] = useState<string[]>([]);
  const [domain, setDomain] = useState('');
  const [enableCT, setEnableCT] = useState(true);
  const [enableShodan, setEnableShodan] = useState(true);
  const [enableCensys, setEnableCensys] = useState(true);
  const [enableGreyHat, setEnableGreyHat] = useState(true);
  const [enableActivePortScan, setEnableActivePortScan] = useState(false);
  const [deepScan, setDeepScan] = useState(false);
  const [scanMode, setScanMode] = useState<ScanMode>('balanced');
  useEffect(() => { setHistory(loadHistory()); }, []);

  const applyScanMode = (mode: ScanMode) => {
    setScanMode(mode);
    if (mode === 'fast') {
      setEnableCT(true);
      setEnableShodan(false);
      setEnableCensys(false);
      setEnableGreyHat(false);
      setEnableActivePortScan(false);
      setDeepScan(false);
    } else if (mode === 'balanced') {
      setEnableCT(true);
      setEnableShodan(true);
      setEnableCensys(true);
      setEnableGreyHat(true);
      setEnableActivePortScan(false);
      setDeepScan(false);
    } else {
      setEnableCT(true);
      setEnableShodan(true);
      setEnableCensys(true);
      setEnableGreyHat(true);
      setEnableActivePortScan(true);
      setDeepScan(true);
    }
  };

  const startScan = useCallback(async () => {
    const d = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!d) return;
    setScanning(true);
    setLogs([]);
    setProgress({ phase: 'init', pct: 0, detail: 'Initializing...' });
    setScan(null);

    try {
      const result = await runScan({
        domain: d,
        shodanKey: SHODAN_API_KEY || '',
        censysId: CENSYS_ID,
        censysSecret: CENSYS_SECRET,
        greyhatKey: GREYHAT_KEY,
        enableCT,
        enableShodan: enableShodan && !!SHODAN_API_KEY,
        enableCensys: enableCensys && !!CENSYS_ID && !!CENSYS_SECRET,
        enableGreyHat: enableGreyHat && !!GREYHAT_KEY,
        enableActivePortScan,
        deepScan,
        maxSubdomains: SCAN_MODE_CONFIG[scanMode].maxSubdomains,
        shodanLimit: enableShodan ? SCAN_MODE_CONFIG[scanMode].shodanLimit : 0,
        onProgress: (phase, pct, detail) => setProgress({ phase, pct, detail }),
        onLog: (msg) => setLogs(prev => [...prev, msg]),
      });
      setScan(result);
      saveToHistory(result);
      setHistory(loadHistory());
      setView('dashboard');
    } catch (err) {
      setLogs(prev => [...prev, `[ERROR] Scan failed: ${err}`]);
    } finally {
      setScanning(false);
    }
  }, [
    domain,
    enableCT,
    enableShodan,
    enableCensys,
    enableGreyHat,
    enableActivePortScan,
    deepScan,
    scanMode,
  ]);

  const loadScan = (s: ScanResult) => { setScan(s); setView('dashboard'); };
  const deleteScan = (id: string) => { deleteFromHistory(id); setHistory(loadHistory()); };

  const navItems: { id: View; label: string; icon: typeof Shield; needsScan: boolean }[] = [
    { id: 'scan', label: 'New Scan', icon: Search, needsScan: false },
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, needsScan: true },
    { id: 'graph', label: 'Asset Graph', icon: Network, needsScan: true },
    { id: 'risk', label: 'Risk Table', icon: Table2, needsScan: true },
    { id: 'history', label: 'History', icon: History, needsScan: false },
    { id: 'export', label: 'Export', icon: Download, needsScan: true },
  ];

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden">
      {/* ── Sidebar ── */}
      <aside className="w-56 bg-slate-900 border-r border-slate-800 flex flex-col">
        <div className="p-4 border-b border-slate-800 flex items-center gap-2">
          <Shield className="w-6 h-6 text-cyan-400" />
          <span className="font-bold text-lg tracking-tight">EDAM</span>
        </div>
        <nav className="flex-1 p-2 space-y-1">
          {navItems.map(item => {
            const disabled = item.needsScan && !scan;
            const active = view === item.id;
            return (
              <button
                key={item.id}
                onClick={() => !disabled && setView(item.id)}
                disabled={disabled}
                className={`w-full flex items-center gap-2 px-3 py-2 rounded text-sm transition-colors
                  ${active ? 'bg-cyan-600/20 text-cyan-400' : ''}
                  ${disabled ? 'opacity-30 cursor-not-allowed' : 'hover:bg-slate-800 cursor-pointer'}`}
              >
                <item.icon className="w-4 h-4" />
                {item.label}
              </button>
            );
          })}
        </nav>
        {scan && (
          <div className="p-3 border-t border-slate-800 text-xs text-slate-500">
            Last: {scan.domain}<br />
            {scan.stats.totalAssets} assets found
          </div>
        )}
      </aside>

      {/* ── Main Content ── */}
      <main className="flex-1 overflow-y-auto">
        {view === 'scan' && (
          <ScanView
            domain={domain} setDomain={setDomain}
            enableCT={enableCT} setEnableCT={setEnableCT}
            enableShodan={enableShodan} setEnableShodan={setEnableShodan}
            enableCensys={enableCensys} setEnableCensys={setEnableCensys}
            enableGreyHat={enableGreyHat} setEnableGreyHat={setEnableGreyHat}
            enableActivePortScan={enableActivePortScan} setEnableActivePortScan={setEnableActivePortScan}
            deepScan={deepScan} setDeepScan={setDeepScan}
            scanMode={scanMode} setScanMode={applyScanMode}
            shodanStatus={SHODAN_API_KEY ? 'valid' : 'invalid'}
            censysStatus={CENSYS_ID && CENSYS_SECRET ? 'valid' : 'invalid'}
            greyhatStatus={GREYHAT_KEY ? 'valid' : 'invalid'}
            scanning={scanning} progress={progress} logs={logs}
            onStart={startScan}
          />
        )}
        {view === 'dashboard' && scan && <DashboardView scan={scan} />}
        {view === 'graph' && scan && <GraphView scan={scan} />}
        {view === 'risk' && scan && <RiskTableView scan={scan} />}
        {view === 'history' && (
          <HistoryView
            history={history}
            currentScan={scan}
            onLoad={loadScan}
            onDelete={deleteScan}
          />
        )}
        {view === 'export' && scan && <ExportView scan={scan} />}
      </main>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   SCAN VIEW
   ══════════════════════════════════════════════════════════════ */

function ScanView(props: {
  domain: string; setDomain: (v: string) => void;
  enableCT: boolean; setEnableCT: (v: boolean) => void;
  enableShodan: boolean; setEnableShodan: (v: boolean) => void;
  enableCensys: boolean; setEnableCensys: (v: boolean) => void;
  enableGreyHat: boolean; setEnableGreyHat: (v: boolean) => void;
  enableActivePortScan: boolean; setEnableActivePortScan: (v: boolean) => void;
  deepScan: boolean; setDeepScan: (v: boolean) => void;
  scanMode: ScanMode; setScanMode: (v: ScanMode) => void;
  shodanStatus: 'checking' | 'valid' | 'invalid';
  censysStatus: 'checking' | 'valid' | 'invalid';
  greyhatStatus: 'checking' | 'valid' | 'invalid';
  scanning: boolean;
  progress: { phase: string; pct: number; detail: string };
  logs: string[];
  onStart: () => void;
}) {
  const logRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [props.logs]);

  return (
    <div className="p-6 max-w-3xl mx-auto">
      <h1 className="text-2xl font-bold mb-6 flex items-center gap-2">
        <Search className="w-6 h-6 text-cyan-400" /> New Scan
      </h1>

      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 space-y-4">
        {/* Domain input */}
        <div>
          <label className="block text-sm font-medium text-slate-400 mb-1">Target Domain</label>
          <input
            type="text"
            placeholder="example.com"
            value={props.domain}
            onChange={e => props.setDomain(e.target.value)}
            disabled={props.scanning}
            className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            onKeyDown={e => e.key === 'Enter' && !props.scanning && props.onStart()}
          />
        </div>

        {/* Settings */}
        <div className="flex items-center gap-2 text-sm text-slate-400">
          <Settings className="w-4 h-4" /> Configuration
        </div>

        <div>
          <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">Scan Mode</div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
            {(Object.keys(SCAN_MODE_CONFIG) as ScanMode[]).map(mode => {
              const cfg = SCAN_MODE_CONFIG[mode];
              const active = props.scanMode === mode;
              return (
                <button
                  key={mode}
                  type="button"
                  onClick={() => props.setScanMode(mode)}
                  disabled={props.scanning}
                  className={`rounded-lg border p-3 text-left transition-colors ${
                    active
                      ? 'border-cyan-500/70 bg-cyan-500/10'
                      : 'border-slate-800 bg-slate-950/50 hover:bg-slate-800/70'
                  } ${props.scanning ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}`}
                >
                  <div className="text-sm font-semibold text-slate-100">{cfg.label}</div>
                  <div className="mt-1 text-xs text-slate-500">{cfg.description}</div>
                  <div className="mt-2 text-[11px] text-slate-400">
                    up to {cfg.maxSubdomains} names, {cfg.shodanLimit || 'no'} Shodan IPs
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={props.enableCT} onChange={e => props.setEnableCT(e.target.checked)} className="accent-cyan-500" />
            Certificate Transparency (crt.sh)
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={props.enableCensys} onChange={e => props.setEnableCensys(e.target.checked)} className="accent-cyan-500" />
            Censys Enrichment
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={props.enableShodan} onChange={e => props.setEnableShodan(e.target.checked)} className="accent-cyan-500" />
            Shodan Enrichment
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={props.enableGreyHat} onChange={e => props.setEnableGreyHat(e.target.checked)} className="accent-cyan-500" />
            Cloud Bucket Discovery (GreyHat)
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={props.enableActivePortScan}
              onChange={e => props.setEnableActivePortScan(e.target.checked)}
              className="accent-cyan-500"
            />
            Active Port Check (local backend)
          </label>
          <label className={`flex items-center gap-2 text-sm ${props.enableActivePortScan ? 'cursor-pointer' : 'opacity-50 cursor-not-allowed'}`}>
            <input
              type="checkbox"
              checked={props.deepScan}
              onChange={e => props.setDeepScan(e.target.checked)}
              disabled={!props.enableActivePortScan}
              className="accent-cyan-500"
            />
            Deep Port Scan (Top 1000 Ports)
          </label>
        </div>

        {props.enableActivePortScan && (
          <div className="bg-slate-800/50 border border-cyan-900/30 rounded p-3 flex items-center justify-between animate-in fade-in slide-in-from-top-1">
            <span className="text-sm text-cyan-400 font-medium flex items-center gap-2">
              <Wifi className="w-4 h-4" />
              {props.deepScan ? 'Deep Port Scan Active (Top 1000 Ports)' : 'Standard Port Scan Active (Critical Ports)'}
            </span>
            <span className="text-[10px] text-slate-500 italic">
              {props.deepScan ? 'Thorough local port analysis' : 'Faster local exposure check'}
            </span>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border-t border-slate-800 pt-4">
          {props.enableShodan && (
            <div className="text-sm">
              <p className="text-slate-400 mb-1">Shodan Status</p>
              <p className={props.shodanStatus === 'valid' ? 'text-emerald-400 text-xs font-semibold' : 'text-red-400 text-xs font-semibold'}>
                {props.shodanStatus === 'valid' ? 'API Key: Ready' : 'API Key: Missing'}
              </p>
            </div>
          )}
          {props.enableCensys && (
            <div className="text-sm">
              <p className="text-slate-400 mb-1">Censys Status</p>
              <p className={props.censysStatus === 'valid' ? 'text-emerald-400 text-xs font-semibold' : 'text-red-400 text-xs font-semibold'}>
                {props.censysStatus === 'valid' ? 'API Key: Ready' : 'API Key: Missing'}
              </p>
            </div>
          )}
          {props.enableGreyHat && (
            <div className="text-sm">
              <p className="text-slate-400 mb-1">GreyHat Status</p>
              <p className={props.greyhatStatus === 'valid' ? 'text-emerald-400 text-xs font-semibold' : 'text-red-400 text-xs font-semibold'}>
                {props.greyhatStatus === 'valid' ? 'API Key: Ready' : 'API Key: Missing'}
              </p>
            </div>
          )}
        </div>

        {/* Start button */}
        <button
          onClick={props.onStart}
          disabled={props.scanning || !props.domain.trim()}
          className="w-full flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded transition-colors cursor-pointer"
        >
          {props.scanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {props.scanning ? 'Scanning...' : 'Start Scan'}
        </button>

        {/* Progress */}
        {props.scanning && (
          <div className="space-y-2">
            <div className="flex justify-between text-xs text-slate-400">
              <span>{props.progress.detail}</span>
              <span>{props.progress.pct}%</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300 rounded-full"
                style={{ width: `${props.progress.pct}%` }}
              />
            </div>
          </div>
        )}

        {/* Logs */}
        {props.logs.length > 0 && (
          <div>
            <p className="text-sm font-medium text-slate-400 mb-1">Scan Log</p>
            <div ref={logRef} className="bg-slate-950 border border-slate-800 rounded p-3 h-64 overflow-y-auto font-mono text-xs text-slate-400 space-y-0.5">
              {props.logs.map((l, i) => (
                <div key={i} className={l.includes('ERROR') ? 'text-red-400' : l.includes('Phase') ? 'text-cyan-400 font-semibold' : ''}>
                  {l}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="mt-6 bg-slate-900/50 border border-slate-800 rounded-lg p-4 text-sm text-slate-400">
        <h3 className="font-semibold text-slate-300 mb-2">How it works:</h3>
        <ol className="list-decimal list-inside space-y-1">
          <li><strong>Discovery</strong> — Queries passive sources; Censys runs only when API keys are configured</li>
          <li><strong>Cloud Recon</strong> — GreyHatWarfare bucket discovery runs only when an API key is configured</li>
          <li><strong>DNS Resolution</strong> — Resolves records via Google DoH</li>
          <li><strong>HTTP/HTTPS Probing</strong> — Checks web server availability</li>
          <li><strong>Shodan Enrichment</strong> — Adds open ports and services when an API key is configured</li>
          <li><strong>Active Port Check</strong> — Optional local TCP scan for live exposure validation</li>
          <li><strong>Risk Scoring</strong> — Heuristic analysis for attack surface rating</li>
        </ol>
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   DASHBOARD VIEW
   ══════════════════════════════════════════════════════════════ */

function DashboardView({ scan }: { scan: ScanResult }) {
  const s = scan.stats;
  const findingCategories = buildFindingCategories(scan.assets).filter(item => item.category !== 'Inventory');
  const executiveSummary = buildExecutiveSummary(scan);
  const cards = [
    { label: 'Total Assets', value: s.totalAssets, color: 'text-cyan-400' },
    { label: 'Subdomains', value: s.subdomains, color: 'text-blue-400' },
    { label: 'IP Addresses', value: s.ips, color: 'text-purple-400' },
    { label: 'Services', value: s.services, color: 'text-teal-400' },
    { label: 'Buckets', value: s.buckets, color: 'text-amber-400' },
    { label: 'Max Risk', value: s.maxRisk, color: 'text-red-400' },
    { label: 'Avg Risk', value: s.avgRisk, color: 'text-orange-400' },
  ];

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-2 flex items-center gap-2">
        <LayoutDashboard className="w-6 h-6 text-cyan-400" /> Dashboard
      </h1>
      <p className="text-slate-400 text-sm mb-6">
        Scan of <strong className="text-white">{scan.domain}</strong> — {new Date(scan.timestamp).toLocaleString()} — {(scan.durationMs / 1000).toFixed(1)}s
      </p>

      <div className="mb-6 rounded-lg border border-cyan-900/40 bg-cyan-950/20 p-5">
        <h2 className="mb-2 flex items-center gap-2 text-lg font-semibold text-cyan-300">
          <Sparkles className="h-5 w-5" /> Scan Summary
        </h2>
        <p className="text-sm leading-6 text-slate-300">{executiveSummary}</p>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-7 gap-4 mb-8">
        {cards.map(c => (
          <div key={c.label} className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <p className="text-xs text-slate-500 uppercase tracking-wider">{c.label}</p>
            <p className={`text-2xl font-bold mt-1 ${c.color}`}>{c.value}</p>
          </div>
        ))}
      </div>

      <div className="mb-8 rounded-lg border border-slate-800 bg-slate-900 p-5">
        <h3 className="mb-4 font-semibold">Finding Categories</h3>
        {findingCategories.length === 0 ? (
          <p className="text-sm text-slate-500">No categorized risk findings were identified.</p>
        ) : (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
            {findingCategories.map(item => (
              <div key={item.category} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className={`font-semibold ${FINDING_COLORS[item.category]}`}>{item.category}</span>
                  <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-300">{item.count}</span>
                </div>
                <div className="mt-2 text-xs text-slate-500">Max risk: {item.maxRisk}</div>
                {item.examples.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {item.examples.map(asset => (
                      <div key={asset.id} className="truncate text-xs text-slate-400">{asset.value}</div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Risk distribution and Services */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
          <h3 className="font-semibold mb-4">Risk Distribution</h3>
          {(['critical', 'high', 'medium', 'low'] as Severity[]).map(sev => {
            const count = s[sev];
            const pct = s.totalAssets > 0 ? (count / s.totalAssets) * 100 : 0;
            return (
              <div key={sev} className="mb-3">
                <div className="flex justify-between text-sm mb-1">
                  <span className={SEV_TEXT[sev]} style={{ textTransform: 'capitalize' }}>{sev}</span>
                  <span className="text-slate-400">{count} ({pct.toFixed(0)}%)</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-2">
                  <div className={`h-full rounded-full ${SEV_COLORS[sev]}`} style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Discovered Services */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <Wifi className="w-4 h-4 text-teal-400" /> Open Ports
          </h3>
          <div className="space-y-2 max-h-64 overflow-y-auto pr-2 custom-scrollbar">
            {scan.assets.filter(a => a.type === 'service').length === 0 ? (
              <p className="text-xs text-slate-500 italic">No open ports detected.</p>
            ) : (
              scan.assets
                .filter(a => a.type === 'service')
                .sort((a, b) => (a.metadata as any).port - (b.metadata as any).port)
                .map(a => (
                  <div key={a.id} className="flex items-center justify-between text-sm bg-slate-800/30 p-2 rounded border border-slate-800/50">
                    <div className="flex flex-col">
                      <span className="font-mono text-cyan-400 font-bold">Port {(a.metadata as any).port}</span>
                      <span className="text-[10px] text-slate-500 uppercase">{(a.metadata as any).protocol || 'tcp'} / {(a.metadata as any).product || 'unknown'}</span>
                    </div>
                    <div className="text-right">
                      <div className="text-[10px] text-slate-400 truncate max-w-[120px]">
                        {a.value.split(':')[0]}
                      </div>
                    </div>
                  </div>
                ))
            )}
          </div>
        </div>

        {/* Top risks */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
          <h3 className="font-semibold mb-4">Top Risk Assets</h3>
          <div className="space-y-2">
            {[...scan.assets].sort((a, b) => b.riskScore - a.riskScore).slice(0, 8).map(a => (
              <div key={a.id} className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2 truncate">
                  {(() => { const I = TYPE_ICONS[a.type]; return <I className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />; })()}
                  <span className="truncate">{a.value}</span>
                </div>
                <div className="flex items-center gap-2 ml-2 flex-shrink-0">
                  <span className={`font-mono text-xs ${SEV_TEXT[a.severity]}`}>{a.riskScore}</span>
                  <Badge severity={a.severity} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Errors */}
      {scan.errors.length > 0 && (
        <div className="mt-6 bg-red-950/30 border border-red-900 rounded-lg p-4">
          <h3 className="font-semibold text-red-400 flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4" /> Scan Errors
          </h3>
          <ul className="text-sm text-red-300 space-y-1">
            {scan.errors.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </div>
      )}

      <p className="mt-4 text-xs text-slate-500 max-w-3xl">
        Note: Service discovery and higher risk scores rely on Shodan enrichment. For large CDNs and cloud providers
        (such as Google), Shodan often exposes limited host data, so results are heuristic and not exhaustive.
      </p>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   GRAPH VIEW  (Cytoscape)
   ══════════════════════════════════════════════════════════════ */

function GraphView({ scan }: { scan: ScanResult }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const viewportRef = useRef<{ zoom: number; pan: { x: number; y: number } } | null>(null);
  const prevLayoutRef = useRef<GraphLayout | null>(null);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [pathIds, setPathIds] = useState<string[] | null>(null);
  const [typeFilters, setTypeFilters] = useState<Record<AssetType, boolean>>({
    domain: true, subdomain: true, ip: true, service: true, bucket: true,
  });
  const [sevFilters, setSevFilters] = useState<Record<Severity, boolean>>({
    critical: true, high: true, medium: true, low: true,
  });
  const [layout, setLayout] = useState<GraphLayout>('breadthfirst');
  const [searchTerm, setSearchTerm] = useState('');

  const toggleType = (t: AssetType) => setTypeFilters(p => ({ ...p, [t]: !p[t] }));
  const toggleSev = (s: Severity) => setSevFilters(p => ({ ...p, [s]: !p[s] }));

  const filteredAssets = useMemo(
    () => scan.assets.filter(a => typeFilters[a.type] && sevFilters[a.severity]),
    [scan.assets, typeFilters, sevFilters]
  );
  const visibleIds = useMemo(() => new Set(filteredAssets.map(a => a.id)), [filteredAssets]);
  const filteredRels = useMemo(
    () => scan.relationships.filter(r => visibleIds.has(r.sourceId) && visibleIds.has(r.targetId)),
    [scan.relationships, visibleIds]
  );
  const graph = useMemo(() => buildGraph(filteredAssets, filteredRels), [filteredAssets, filteredRels]);
  const infrastructurePositions = useMemo(
    () => buildInfrastructurePositions(filteredAssets, filteredRels),
    [filteredAssets, filteredRels]
  );
  const selectedStillVisible = selected && visibleIds.has(selected.id)
    ? selected
    : null;

  const stats = {
    assets: filteredAssets.length,
    edges: filteredRels.length,
    highRisk: filteredAssets.filter(a => a.severity === 'critical' || a.severity === 'high').length,
    internetFacing: filteredAssets.filter(a => a.type === 'service' || a.type === 'bucket').length,
  };

  const topRiskAssets = useMemo(
    () => [...filteredAssets].sort((a, b) => b.riskScore - a.riskScore).slice(0, 6),
    [filteredAssets]
  );

  const relationSummary = useMemo(
    () => (Object.keys(RELATION_COLORS) as RelationType[])
      .map(type => ({
        type,
        count: filteredRels.filter(rel => rel.type === type).length,
      }))
      .filter(item => item.count > 0),
    [filteredRels]
  );
  const scopedScan = useMemo(
    () => ({ ...scan, assets: filteredAssets, relationships: filteredRels }),
    [scan, filteredAssets, filteredRels]
  );
  const exposurePaths = useMemo(() => buildExposurePaths(scopedScan), [scopedScan]);
  const infrastructureHubs = useMemo(() => findInfrastructureHubs(scopedScan), [scopedScan]);
  const mappingSummary = useMemo(
    () => buildMappingSummary(scopedScan, exposurePaths, infrastructureHubs),
    [scopedScan, exposurePaths, infrastructureHubs]
  );
  const searchMatches = searchTerm.trim()
    ? filteredAssets
        .filter(asset => asset.value.toLowerCase().includes(searchTerm.trim().toLowerCase()))
        .slice(0, 8)
    : [];

  const zoomBy = (factor: number) => {
    const cy = cyRef.current;
    if (!cy) return;

    const extent = cy.extent();
    const center = {
      x: (extent.x1 + extent.x2) / 2,
      y: (extent.y1 + extent.y2) / 2,
    };

    cy.animate({
      zoom: {
        level: Math.max(cy.minZoom(), Math.min(cy.maxZoom(), cy.zoom() * factor)),
        position: center,
      },
      duration: 120,
    });
  };

  // Highlighting is driven by the effect below; these handlers set state and zoom the viewport.
  const focusAsset = (assetId: string) => {
    const asset = scan.assets.find(a => a.id === assetId) || null;
    setSelected(asset);
    setPathIds(null);

    const cy = cyRef.current;
    if (!cy) return;
    const node = cy.getElementById(assetId);
    if (node.nonempty()) cy.animate({ fit: { eles: node.closedNeighborhood(), padding: 80 }, duration: 220 });
  };

  const focusPath = (assetIds: string[]) => {
    const endpoint = scan.assets.find(a => a.id === assetIds[assetIds.length - 1]) || null;
    setSelected(endpoint);
    setPathIds(assetIds);

    const cy = cyRef.current;
    if (!cy) return;
    let nodes = cy.collection();
    for (const id of assetIds) {
      const n = cy.getElementById(id);
      if (n.nonempty()) nodes = nodes.union(n);
    }
    if (nodes.nonempty()) cy.animate({ fit: { eles: nodes, padding: 90 }, duration: 240 });
  };

  const clearFocus = () => {
    setSelected(null);
    setPathIds(null);
  };

  useEffect(() => {
    if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null; }
    if (!containerRef.current) return;

    // Preserve the user's zoom/pan across filter toggles (same layout); refit on layout change.
    const savedViewport = viewportRef.current;
    const layoutChanged = prevLayoutRef.current !== layout;
    prevLayoutRef.current = layout;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [
        ...graph.nodes.map(n => ({
          group: 'nodes' as const,
          data: n.data,
          ...(layout === 'infrastructure' ? { position: infrastructurePositions[n.data.id] } : {}),
        })),
        ...graph.edges.map(e => ({ group: 'edges' as const, data: e.data })),
      ],
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(shortLabel)',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': 'mapData(size, 40, 104, 9, 15)',
            'font-weight': 700,
            color: '#e2e8f0',
            'text-wrap': 'wrap',
            'text-max-width': '96px',
            'text-outline-color': '#020617',
            'text-outline-width': 2,
            width: 'data(size)',
            height: 'data(size)',
            'border-width': 3,
            'border-color': '#475569',
            'background-color': '#0f172a',
            'background-opacity': 0.92,
            'overlay-padding': '8px',
            'transition-property': 'opacity, border-color, width, height',
            'transition-duration': 180,
          },
        },
        ...(['critical', 'high', 'medium', 'low'] as Severity[]).map(sev => ({
          selector: `node[severity="${sev}"]`,
          style: {
            'border-color': severityColor(sev),
            'border-opacity': 1,
            'background-fill': 'radial-gradient',
            'background-gradient-stop-colors': [severityColor(sev), '#0f172a'],
            'background-gradient-stop-positions': [0, 100],
          } as cytoscape.Css.Node,
        })),
        ...(['domain', 'subdomain', 'ip', 'service', 'bucket'] as AssetType[]).map(t => ({
          selector: `node[type="${t}"]`,
          style: { shape: typeShape(t) } as cytoscape.Css.Node,
        })),
        {
          selector: 'node[type="domain"]',
          style: {
            'font-size': '15px',
            'border-width': 5,
            'text-max-width': '130px',
            'background-color': '#082f49',
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node[type="service"]',
          style: {
            'font-size': '9px',
            'text-max-width': '68px',
            'background-color': '#111827',
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node[type="bucket"]',
          style: {
            'background-color': '#1f2937',
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node[degree >= 4]',
          style: {
            'border-style': 'double',
            'border-width': 5,
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node[type="ip"][degree >= 4]',
          style: {
            'background-color': '#172554',
          } as cytoscape.Css.Node,
        },
        {
          selector: 'edge',
          style: {
            width: 2.2,
            'line-color': '#475569',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'taxi',
            'taxi-direction': layout === 'infrastructure' ? 'rightward' : 'downward',
            'taxi-turn': 28,
            opacity: 0.6,
          },
        },
        ...((Object.keys(RELATION_COLORS) as RelationType[]).map(type => ({
          selector: `edge[relationType="${type}"]`,
          style: {
            'line-color': RELATION_COLORS[type],
            'target-arrow-color': RELATION_COLORS[type],
          } as cytoscape.Css.Edge,
        }))),
        {
          selector: 'edge[relationType="cname_to"]',
          style: {
            'line-style': 'dashed',
          } as cytoscape.Css.Edge,
        },
        {
          selector: '.faded',
          style: {
            opacity: 0.12,
          },
        },
        {
          selector: 'edge.related',
          style: {
            width: 3.5,
            opacity: 0.95,
          } as cytoscape.Css.Edge,
        },
        {
          selector: 'node.related',
          style: {
            opacity: 1,
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node.focused',
          style: {
            'border-width': 6,
            'border-color': '#f8fafc',
            'text-outline-color': '#020617',
          } as cytoscape.Css.Node,
        },
        {
          selector: ':selected',
          style: {
            'overlay-color': '#22d3ee',
            'overlay-opacity': 0.12,
          } as cytoscape.Css.Node,
        },
      ],
      layout: {
        name: layout === 'infrastructure' ? 'preset' : layout,
        fit: false,
        ...(layout === 'infrastructure'
          ? {
              padding: 70,
            }
          : {}),
        ...(layout === 'breadthfirst'
          ? {
              directed: true,
              spacingFactor: 1.45,
              padding: 36,
              roots: filteredAssets.filter(a => a.type === 'domain').map(a => a.id),
            }
          : {}),
      } as cytoscape.LayoutOptions,
      minZoom: 0.06,
      maxZoom: 6,
      wheelSensitivity: 0.55,
    });

    cy.on('tap', 'node', (evt) => {
      const d = evt.target.data();
      const asset = scan.assets.find(a => a.id === d.id);
      if (asset) {
        setSelected(asset);
        setPathIds(null);
      }
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelected(null);
        setPathIds(null);
      }
    });

    // Pointer affordance on hover.
    cy.on('mouseover', 'node', () => { if (containerRef.current) containerRef.current.style.cursor = 'pointer'; });
    cy.on('mouseout', 'node', () => { if (containerRef.current) containerRef.current.style.cursor = 'default'; });

    let viewportReady = false;
    cy.on('layoutstop', () => {
      if (!layoutChanged && savedViewport) {
        cy.zoom(savedViewport.zoom);
        cy.pan(savedViewport.pan);
      } else {
        cy.fit(undefined, 50);
      }
      viewportReady = true;
    });
    cy.on('viewport', () => {
      if (viewportReady) viewportRef.current = { zoom: cy.zoom(), pan: { ...cy.pan() } };
    });

    cyRef.current = cy;

    return () => { cy.destroy(); if (cyRef.current === cy) cyRef.current = null; };
  }, [graph, filteredAssets, infrastructurePositions, layout, scan]);

  useEffect(() => {
    if (!selectedStillVisible && selected) { setSelected(null); setPathIds(null); }
  }, [selected, selectedStillVisible]);

  // Single source of truth for fade/highlight: an exposure path if one is focused, else the selected node's neighborhood.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      cy.elements().removeClass('faded related focused');

      if (pathIds && pathIds.length > 0) {
        let nodes = cy.collection();
        for (const id of pathIds) {
          const n = cy.getElementById(id);
          if (n.nonempty()) nodes = nodes.union(n);
        }
        if (nodes.empty()) return;
        const eles = nodes.union(nodes.edgesWith(nodes));
        cy.elements().not(eles).addClass('faded');
        eles.addClass('related');
        nodes.last().addClass('focused');
        return;
      }

      if (selectedStillVisible) {
        const node = cy.getElementById(selectedStillVisible.id);
        if (!node.nonempty()) return;
        const neighborhood = node.closedNeighborhood();
        cy.elements().not(neighborhood).addClass('faded');
        neighborhood.addClass('related');
        node.addClass('focused');
      }
    });
  }, [selectedStillVisible, pathIds, graph]);

  const infoAsset = selectedStillVisible || topRiskAssets[0] || null;

  return (
    <div className="flex h-full min-h-0 flex-col bg-slate-950">
      <div className="border-b border-slate-800 bg-slate-950/80 px-4 py-4 backdrop-blur">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="flex items-center gap-2 text-2xl font-bold text-slate-100">
              <Network className="h-6 w-6 text-cyan-400" /> Asset Graph
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Asset relationship map with exposure paths, shared infrastructure, and risk-aware nodes for {scan.domain}.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
            <div className="rounded-xl border border-slate-800 bg-slate-900 px-3 py-2">
              <div className="text-xs uppercase tracking-wide text-slate-500">Visible Assets</div>
              <div className="mt-1 text-xl font-semibold text-white">{stats.assets}</div>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900 px-3 py-2">
              <div className="text-xs uppercase tracking-wide text-slate-500">Connections</div>
              <div className="mt-1 text-xl font-semibold text-white">{stats.edges}</div>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900 px-3 py-2">
              <div className="text-xs uppercase tracking-wide text-slate-500">High Risk</div>
              <div className="mt-1 text-xl font-semibold text-orange-400">{stats.highRisk}</div>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900 px-3 py-2">
              <div className="text-xs uppercase tracking-wide text-slate-500">Exposed Endpoints</div>
              <div className="mt-1 text-xl font-semibold text-cyan-400">{stats.internetFacing}</div>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="flex items-center gap-1 rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-xs font-medium text-slate-400">
            <Filter className="h-3.5 w-3.5" /> Asset Types
          </span>
          {(['domain', 'subdomain', 'ip', 'service', 'bucket'] as AssetType[]).map(t => (
            <label key={t} className="flex cursor-pointer items-center gap-2 rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-xs text-slate-300">
              <input type="checkbox" checked={typeFilters[t]} onChange={() => toggleType(t)} className="accent-cyan-500" />
              <span className="capitalize">{t}</span>
            </label>
          ))}
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-2">
          <span className="rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-xs font-medium text-slate-400">
            Severity
          </span>
          {(['critical', 'high', 'medium', 'low'] as Severity[]).map(s => (
            <label key={s} className="flex cursor-pointer items-center gap-2 rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-xs">
              <input type="checkbox" checked={sevFilters[s]} onChange={() => toggleSev(s)} className="accent-cyan-500" />
              <span className={`${SEV_TEXT[s]} capitalize`}>{s}</span>
            </label>
          ))}
          <select
            value={layout}
            onChange={e => setLayout(e.target.value as GraphLayout)}
            className="ml-auto rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200"
          >
            <option value="breadthfirst">Hierarchy Map</option>
            <option value="infrastructure">IP Map</option>
          </select>
          <input
            type="text"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            placeholder="Find asset..."
            className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          <button
            onClick={() => cyRef.current?.fit(undefined, 40)}
            className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 transition-colors hover:bg-slate-800"
          >
            Fit View
          </button>
          <button
            onClick={() => zoomBy(1.35)}
            className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-800"
            title="Zoom in"
          >
            +
          </button>
          <button
            onClick={() => zoomBy(0.74)}
            className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-800"
            title="Zoom out"
          >
            -
              </button>
          <button
            onClick={clearFocus}
            className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 transition-colors hover:bg-slate-800"
          >
            Reset Focus
          </button>
        </div>
      </div>

      <div className="flex flex-1 min-h-0">
        <div className="relative flex-1 border-r border-slate-800 bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.08),_transparent_30%),linear-gradient(to_bottom,_#020617,_#020617)]">
          <div
            ref={containerRef}
            className="h-full w-full"
          />
          <div className="pointer-events-none absolute left-4 top-4 rounded-lg border border-slate-800 bg-slate-950/80 px-3 py-2 text-xs text-slate-400 backdrop-blur">
            Map flow: domain and subdomains connect into IP anchors, then out to services or buckets. Double borders mark shared infrastructure hubs.
          </div>
          <div className="pointer-events-none absolute bottom-4 left-4 max-w-xl rounded-lg border border-slate-800 bg-slate-950/85 p-3 text-xs text-slate-300 shadow-xl backdrop-blur">
            <div className="mb-2 font-semibold text-slate-100">Mapping Summary</div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-3">
              <span>{mappingSummary.discoveredNames} names</span>
              <span>{mappingSummary.resolvedIps} IPs</span>
              <span>{mappingSummary.exposedServices} services</span>
              <span>{mappingSummary.buckets} buckets</span>
              <span>{mappingSummary.exposurePaths} exposure paths</span>
              <span>{mappingSummary.topHub ? `${mappingSummary.topHub.children.length + mappingSummary.topHub.services.length} hub links` : 'no hubs'}</span>
            </div>
          </div>
          <div className="absolute right-4 top-4 flex flex-col gap-2">
            <button
              onClick={() => zoomBy(1.35)}
              className="h-9 w-9 rounded-lg border border-slate-700 bg-slate-950/85 text-base font-semibold text-slate-100 shadow-lg backdrop-blur transition-colors hover:bg-slate-800"
              title="Zoom in"
            >
              +
            </button>
            <button
              onClick={() => zoomBy(0.74)}
              className="h-9 w-9 rounded-lg border border-slate-700 bg-slate-950/85 text-base font-semibold text-slate-100 shadow-lg backdrop-blur transition-colors hover:bg-slate-800"
              title="Zoom out"
            >
              -
            </button>
            <button
              onClick={() => cyRef.current?.fit(undefined, 40)}
              className="h-9 rounded-lg border border-slate-700 bg-slate-950/85 px-2 text-xs font-semibold text-slate-100 shadow-lg backdrop-blur transition-colors hover:bg-slate-800"
              title="Fit all nodes"
            >
              Fit
            </button>
          </div>
        </div>

        <aside className="w-96 overflow-y-auto bg-slate-900">
          <div className="border-b border-slate-800 p-4">
            <div className="flex items-center gap-2 text-sm font-medium text-cyan-300">
              <Sparkles className="h-4 w-4" />
              Analysis Panel
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Keep the graph visually light and move detailed inspection here.
            </p>
          </div>

          <div className="space-y-5 p-4">
            <section>
              <h3 className="mb-3 text-sm font-semibold text-slate-200">Mapping Overview</h3>
              <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                <p className="text-sm leading-6 text-slate-300">
                  <span className="font-semibold text-cyan-300">{mappingSummary.domain}</span> maps to{' '}
                  <span className="font-semibold text-white">{mappingSummary.discoveredNames}</span> discovered names,{' '}
                  <span className="font-semibold text-white">{mappingSummary.resolvedIps}</span> resolved IPs, and{' '}
                  <span className="font-semibold text-white">{mappingSummary.exposedServices + mappingSummary.buckets}</span> exposed endpoints.
                </p>
                <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-2">
                    <div className="text-slate-500">Top Hub</div>
                    <div className="mt-1 truncate font-mono text-cyan-300">
                      {mappingSummary.topHub?.ip.value || 'None visible'}
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-2">
                    <div className="text-slate-500">Top Risk</div>
                    <div className={`mt-1 truncate font-semibold ${mappingSummary.topRisk ? SEV_TEXT[mappingSummary.topRisk.severity] : 'text-slate-400'}`}>
                      {mappingSummary.topRisk ? `${mappingSummary.topRisk.riskScore} ${mappingSummary.topRisk.type}` : 'None'}
                    </div>
                  </div>
                </div>
              </div>
            </section>

            {searchMatches.length > 0 && (
              <section>
                <h3 className="mb-3 text-sm font-semibold text-slate-200">Search Results</h3>
                <div className="space-y-2">
                  {searchMatches.map(asset => {
                    const Icon = TYPE_ICONS[asset.type];
                    return (
                      <button
                        key={asset.id}
                        onClick={() => focusAsset(asset.id)}
                        className="flex w-full items-center justify-between rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2 text-left transition-colors hover:bg-slate-800/70"
                      >
                        <div className="flex min-w-0 items-center gap-2">
                          <Icon className="h-4 w-4 flex-shrink-0 text-slate-500" />
                          <span className="truncate text-sm text-slate-200">{asset.value}</span>
                        </div>
                        <span className={`ml-3 text-xs font-semibold ${SEV_TEXT[asset.severity]}`}>{asset.riskScore}</span>
                      </button>
                    );
                  })}
                </div>
              </section>
            )}

            <section>
              <h3 className="mb-3 text-sm font-semibold text-slate-200">Exposure Paths</h3>
              <div className="space-y-2">
                {exposurePaths.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-800 bg-slate-950/50 p-3 text-sm text-slate-500">
                    No complete exposure paths under the current filters.
                  </div>
                ) : (
                  exposurePaths.map((path, index) => {
                    const endpoint = path.assets[path.assets.length - 1];
                    return (
                      <button
                        key={`${endpoint.id}-${index}`}
                        onClick={() => focusPath(path.assets.map(asset => asset.id))}
                        className="w-full rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-left transition-colors hover:bg-slate-800/70"
                      >
                        <div className="mb-2 flex items-center justify-between gap-3">
                          <span className="text-xs uppercase tracking-wide text-slate-500">Path {index + 1}</span>
                          <span className={`text-sm font-semibold ${SEV_TEXT[path.severity]}`}>{path.score}</span>
                        </div>
                        <div className="text-xs leading-5 text-slate-300">
                          {path.assets.map(asset => asset.value).join(' -> ')}
                        </div>
                      </button>
                    );
                  })
                )}
              </div>
            </section>

            <section>
              <h3 className="mb-3 text-sm font-semibold text-slate-200">Shared Infrastructure</h3>
              <div className="space-y-2">
                {infrastructureHubs.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-800 bg-slate-950/50 p-3 text-sm text-slate-500">
                    No high-connectivity IP hubs visible.
                  </div>
                ) : (
                  infrastructureHubs.map(hub => (
                    <button
                      key={hub.ip.id}
                      onClick={() => focusAsset(hub.ip.id)}
                      className="w-full rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-left transition-colors hover:bg-slate-800/70"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="truncate font-mono text-sm text-cyan-300">{hub.ip.value}</span>
                        <span className="text-xs text-slate-500">risk {hub.risk}</span>
                      </div>
                      <div className="mt-2 text-xs text-slate-400">
                        {hub.children.length} names, {hub.services.length} services connected
                      </div>
                    </button>
                  ))
                )}
              </div>
            </section>

            <section>
              <div className="mb-3 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-200">
                  {selectedStillVisible ? 'Selected Asset' : 'Priority Asset'}
                </h3>
                {selectedStillVisible && (
                  <button onClick={clearFocus} className="text-slate-500 transition-colors hover:text-white">
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>

              {infoAsset ? (
                <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-xs uppercase tracking-wide text-slate-500">{infoAsset.type}</div>
                      <h4 className="mt-1 truncate text-base font-semibold text-white">{infoAsset.value}</h4>
                    </div>
                    <Badge severity={infoAsset.severity} />
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
                    <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Risk Score</div>
                      <div className={`mt-1 text-2xl font-bold ${SEV_TEXT[infoAsset.severity]}`}>{infoAsset.riskScore}</div>
                    </div>
                    <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Observed</div>
                      <div className="mt-1 text-sm font-medium text-slate-200">
                        {new Date(infoAsset.firstSeen).toLocaleDateString()}
                      </div>
                    </div>
                  </div>

                  {infoAsset.riskReasons.length > 0 && (
                    <div className="mt-4">
                      <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">Why It Matters</div>
                      <div className="space-y-2">
                        {infoAsset.riskReasons.slice(0, 4).map((reason, index) => (
                          <div key={index} className="flex items-start gap-2 rounded-xl border border-slate-800 bg-slate-900/60 p-2.5 text-xs text-slate-300">
                            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-amber-400" />
                            <span>{reason}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {Object.keys(infoAsset.metadata).length > 0 && (
                    <div className="mt-4">
                      <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">Metadata</div>
                      <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-300">
                        {Object.entries(infoAsset.metadata).map(([key, value]) => (
                          <div key={key} className="mb-1 last:mb-0">
                            <span className="text-cyan-400">{key}</span>: {Array.isArray(value) ? value.join(', ') : String(value)}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-950/50 p-4 text-sm text-slate-500">
                  No assets match the current filters.
                </div>
              )}
            </section>

            <section>
              <h3 className="mb-3 text-sm font-semibold text-slate-200">Highest Risk Nodes</h3>
              <div className="space-y-2">
                {topRiskAssets.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-800 bg-slate-950/50 p-3 text-sm text-slate-500">
                    Nothing visible under the current filters.
                  </div>
                ) : (
                  topRiskAssets.map(asset => {
                    const Icon = TYPE_ICONS[asset.type];
                    const active = selectedStillVisible?.id === asset.id;
                    return (
                      <button
                        key={asset.id}
                        onClick={() => focusAsset(asset.id)}
                        className={`flex w-full items-center justify-between rounded-xl border px-3 py-2 text-left transition-colors ${
                          active
                            ? 'border-cyan-500/60 bg-cyan-500/10'
                            : 'border-slate-800 bg-slate-950/60 hover:bg-slate-800/70'
                        }`}
                      >
                        <div className="flex min-w-0 items-center gap-2">
                          <Icon className="h-4 w-4 flex-shrink-0 text-slate-500" />
                          <div className="min-w-0">
                            <div className="truncate text-sm text-slate-200">{asset.value}</div>
                            <div className="text-xs capitalize text-slate-500">{asset.type}</div>
                          </div>
                        </div>
                        <div className={`ml-3 text-sm font-semibold ${SEV_TEXT[asset.severity]}`}>{asset.riskScore}</div>
                      </button>
                    );
                  })
                )}
              </div>
            </section>

            <section>
              <h3 className="mb-3 text-sm font-semibold text-slate-200">Map Legend</h3>
              <div className="space-y-3 rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                <div>
                  <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">Node Shapes</div>
                  <div className="grid grid-cols-2 gap-2 text-xs text-slate-300">
                    {(['domain', 'subdomain', 'ip', 'service', 'bucket'] as AssetType[]).map(t => (
                      <div key={t} className="flex items-center gap-2">
                        <NodeShape type={t} className="h-4 w-4 flex-shrink-0" />
                        <span className="capitalize">{t}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">Severity (node border)</div>
                  <div className="flex flex-wrap gap-3 text-xs">
                    {(['critical', 'high', 'medium', 'low'] as Severity[]).map(s => (
                      <div key={s} className="flex items-center gap-1.5">
                        <span className="inline-block h-3 w-3 rounded-full" style={{ backgroundColor: severityColor(s) }} />
                        <span className={`${SEV_TEXT[s]} capitalize`}>{s}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <p className="text-xs leading-5 text-slate-500">
                  Node size grows with risk. Double-bordered nodes are shared-infrastructure hubs (4+ connections).
                </p>
              </div>
            </section>

            <section>
              <h3 className="mb-3 text-sm font-semibold text-slate-200">Relationship Legend</h3>
              <div className="space-y-2">
                {relationSummary.map(item => (
                  <div key={item.type} className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm">
                    <div className="flex items-center gap-2">
                      <span
                        className="inline-block h-2.5 w-8 rounded-full"
                        style={{ backgroundColor: RELATION_COLORS[item.type] }}
                      />
                      <span className="text-slate-300">{item.type.replace(/_/g, ' ')}</span>
                    </div>
                    <span className="font-mono text-slate-500">{item.count}</span>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </aside>
      </div>

      <div className="flex flex-wrap items-center gap-4 border-t border-slate-800 bg-slate-900 px-4 py-3 text-xs text-slate-500">
        <span className="font-medium text-slate-400">Visual Rules</span>
        <span>Severity drives border color.</span>
        <span>Node size reflects risk and hierarchy.</span>
        <span>Services and buckets represent exposed endpoints.</span>
        <span className="flex items-center gap-1 text-slate-400">
          <Focus className="h-3.5 w-3.5" /> Focus mode isolates connected assets.
        </span>
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   RISK TABLE VIEW
   ══════════════════════════════════════════════════════════════ */

function RiskTableView({ scan }: { scan: ScanResult }) {
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<'risk' | 'value' | 'type'>('risk');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [typeFilter, setTypeFilter] = useState<AssetType | 'all'>('all');
  const [sevFilter, setSevFilter] = useState<Severity | 'all'>('all');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleSort = (col: 'risk' | 'value' | 'type') => {
    if (sortBy === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortBy(col); setSortDir(col === 'risk' ? 'desc' : 'asc'); }
  };

  const toggleExpand = (id: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const filtered = scan.assets
    .filter(a => {
      if (typeFilter !== 'all' && a.type !== typeFilter) return false;
      if (sevFilter !== 'all' && a.severity !== sevFilter) return false;
      if (search && !a.value.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    })
    .sort((a, b) => {
      let cmp = 0;
      if (sortBy === 'risk') cmp = a.riskScore - b.riskScore;
      else if (sortBy === 'value') cmp = a.value.localeCompare(b.value);
      else cmp = a.type.localeCompare(b.type);
      return sortDir === 'asc' ? cmp : -cmp;
    });
  const actionable = filtered.filter(a => a.severity === 'critical' || a.severity === 'high' || a.type === 'service' || a.type === 'bucket');
  const exposed = filtered.filter(a => a.type === 'service' || a.type === 'bucket' || (a.type === 'ip' && Array.isArray(a.metadata.ports) && a.metadata.ports.length > 0));

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6 flex items-center gap-2">
        <Table2 className="w-6 h-6 text-cyan-400" /> Risk Assessment Table
      </h1>

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
          <div className="text-xs uppercase tracking-wide text-slate-500">Actionable</div>
          <div className="mt-1 text-2xl font-semibold text-orange-400">{actionable.length}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
          <div className="text-xs uppercase tracking-wide text-slate-500">Exposed</div>
          <div className="mt-1 text-2xl font-semibold text-cyan-400">{exposed.length}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
          <div className="text-xs uppercase tracking-wide text-slate-500">High/Critical</div>
          <div className="mt-1 text-2xl font-semibold text-red-400">
            {filtered.filter(a => a.severity === 'critical' || a.severity === 'high').length}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
          <div className="text-xs uppercase tracking-wide text-slate-500">Max Risk</div>
          <div className="mt-1 text-2xl font-semibold text-white">{Math.max(0, ...filtered.map(a => a.riskScore))}</div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-4">
        <input
          type="text"
          placeholder="Search assets..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm flex-1 min-w-48 focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value as AssetType | 'all')}
          className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm"
        >
          <option value="all">All Types</option>
          <option value="domain">Domain</option>
          <option value="subdomain">Subdomain</option>
          <option value="ip">IP</option>
          <option value="service">Service</option>
          <option value="bucket">Bucket</option>
        </select>
        <select
          value={sevFilter}
          onChange={e => setSevFilter(e.target.value as Severity | 'all')}
          className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <p className="text-sm text-slate-500 mb-3">{filtered.length} of {scan.assets.length} assets. Expand a row for raw metadata.</p>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
        <table className="min-w-[1280px] w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/50">
              <th className="w-8 px-3 py-2" />
              <th className="text-left px-3 py-2 cursor-pointer hover:text-cyan-400" onClick={() => toggleSort('value')}>
                <span className="flex items-center gap-1">Asset <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th className="text-left px-3 py-2 cursor-pointer hover:text-cyan-400" onClick={() => toggleSort('type')}>
                <span className="flex items-center gap-1">Type <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th className="text-left px-3 py-2 cursor-pointer hover:text-cyan-400" onClick={() => toggleSort('risk')}>
                <span className="flex items-center gap-1">Risk <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th className="text-left px-3 py-2">Severity</th>
              <th className="text-left px-3 py-2">Category</th>
              <th className="text-left px-3 py-2">Exposure</th>
              <th className="text-left px-3 py-2">Evidence</th>
              <th className="text-left px-3 py-2">Recommended Check</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(a => (
              <AssetRow key={a.id} asset={a} expanded={expanded.has(a.id)} onToggle={() => toggleExpand(a.id)} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AssetRow({ asset, expanded, onToggle }: { asset: Asset; expanded: boolean; onToggle: () => void }) {
  const Icon = TYPE_ICONS[asset.type];
  const actionable = asset.severity === 'critical' || asset.severity === 'high' || asset.type === 'service' || asset.type === 'bucket';
  const category = primaryFindingCategory(asset);
  return (
    <>
      <tr
        className="border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer"
        onClick={onToggle}
      >
        <td className="px-3 py-2 text-slate-500">
          {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </td>
        <td className="px-3 py-2 flex items-center gap-2">
          <Icon className="w-4 h-4 text-slate-500" />
          <span className="truncate max-w-xs">{asset.value}</span>
        </td>
        <td className="px-3 py-2 text-slate-400" style={{ textTransform: 'capitalize' }}>{asset.type}</td>
        <td className="px-3 py-2">
          <span className={`font-mono font-bold ${SEV_TEXT[asset.severity]}`}>{asset.riskScore}</span>
        </td>
        <td className="px-3 py-2"><Badge severity={asset.severity} /></td>
        <td className={`px-3 py-2 font-medium ${FINDING_COLORS[category]}`}>{category}</td>
        <td className="px-3 py-2 text-slate-300">{summarizeExposure(asset)}</td>
        <td className="max-w-md px-3 py-2 text-slate-400">
          <span className="line-clamp-2">{summarizeEvidence(asset)}</span>
        </td>
        <td className="max-w-sm px-3 py-2 text-slate-300">
          <span className={actionable ? 'text-amber-300' : 'text-slate-400'}>{recommendAction(asset)}</span>
        </td>
      </tr>
      {expanded && (
        <tr className="bg-slate-900/50">
          <td />
          <td colSpan={8} className="px-3 py-3">
            <div className="space-y-2 text-xs">
              {asset.riskReasons.length > 0 && (
                <div>
                  <p className="text-slate-400 font-medium mb-1">Risk Reasons:</p>
                  {asset.riskReasons.map((r, i) => (
                    <div key={i} className="flex items-start gap-1 text-slate-300 ml-2">
                      <AlertTriangle className="w-3 h-3 text-amber-400 mt-0.5 flex-shrink-0" /> {r}
                    </div>
                  ))}
                </div>
              )}
              {Object.keys(asset.metadata).length > 0 && (
                <div>
                  <p className="text-slate-400 font-medium mb-1">Metadata:</p>
                  <div className="flex flex-wrap gap-2 ml-2">
                    {Object.entries(asset.metadata).map(([k, v]) => (
                      <span key={k} className="bg-slate-800 rounded px-2 py-0.5">
                        <span className="text-cyan-400">{k}:</span> {Array.isArray(v) ? v.join(', ') : String(v)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

/* ══════════════════════════════════════════════════════════════
   HISTORY VIEW  (with Comparison)
   ══════════════════════════════════════════════════════════════ */

function HistoryView(props: {
  history: ScanResult[];
  currentScan: ScanResult | null;
  onLoad: (s: ScanResult) => void;
  onDelete: (id: string) => void;
}) {
  const [compareResult, setCompareResult] = useState<CompareResult | null>(null);
  const [compareId, setCompareId] = useState<string | null>(null);

  const handleCompare = (oldScan: ScanResult) => {
    if (!props.currentScan || props.currentScan.id === oldScan.id) return;
    setCompareResult(compareScans(oldScan, props.currentScan));
    setCompareId(oldScan.id);
  };

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6 flex items-center gap-2">
        <History className="w-6 h-6 text-cyan-400" /> Scan History
      </h1>

      {props.history.length === 0 ? (
        <p className="text-slate-500">No scans yet. Run a scan first.</p>
      ) : (
        <div className="space-y-3">
          {props.history.map(s => (
            <div key={s.id} className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex items-center justify-between">
              <div>
                <p className="font-semibold">{s.domain}</p>
                <p className="text-xs text-slate-500">
                  {new Date(s.timestamp).toLocaleString()} — {s.stats.totalAssets} assets — Max risk: {s.stats.maxRisk}
                </p>
              </div>
              <div className="flex gap-2">
                {props.currentScan && props.currentScan.id !== s.id && (
                  <button
                    onClick={() => handleCompare(s)}
                    className="flex items-center gap-1 px-2 py-1 bg-purple-600/20 text-purple-400 rounded text-xs hover:bg-purple-600/30 cursor-pointer"
                  >
                    <GitCompareArrows className="w-3 h-3" /> Compare
                  </button>
                )}
                <button
                  onClick={() => props.onLoad(s)}
                  className="flex items-center gap-1 px-2 py-1 bg-cyan-600/20 text-cyan-400 rounded text-xs hover:bg-cyan-600/30 cursor-pointer"
                >
                  <Eye className="w-3 h-3" /> Load
                </button>
                <button
                  onClick={() => props.onDelete(s.id)}
                  className="flex items-center gap-1 px-2 py-1 bg-red-600/20 text-red-400 rounded text-xs hover:bg-red-600/30 cursor-pointer"
                >
                  <Trash2 className="w-3 h-3" /> Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Comparison results */}
      {compareResult && (
        <div className="mt-8 bg-slate-900 border border-purple-800/50 rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-purple-400 flex items-center gap-2">
              <GitCompareArrows className="w-4 h-4" /> Comparison Results
            </h3>
            <button onClick={() => { setCompareResult(null); setCompareId(null); }} className="text-slate-500 hover:text-white cursor-pointer">
              <X className="w-4 h-4" />
            </button>
          </div>

          <p className="text-xs text-slate-500 mb-4">
            Comparing scan {compareId?.slice(0, 12)} → current scan
          </p>

          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="bg-green-950/30 border border-green-900/50 rounded p-3 text-center">
              <p className="text-2xl font-bold text-green-400">{compareResult.summary.added}</p>
              <p className="text-xs text-green-500">New Assets</p>
            </div>
            <div className="bg-red-950/30 border border-red-900/50 rounded p-3 text-center">
              <p className="text-2xl font-bold text-red-400">{compareResult.summary.removed}</p>
              <p className="text-xs text-red-500">Removed Assets</p>
            </div>
            <div className="bg-yellow-950/30 border border-yellow-900/50 rounded p-3 text-center">
              <p className="text-2xl font-bold text-yellow-400">{compareResult.summary.changed}</p>
              <p className="text-xs text-yellow-500">Risk Changes</p>
            </div>
          </div>

          {compareResult.newAssets.length > 0 && (
            <div className="mb-3">
              <p className="text-sm font-medium text-green-400 mb-1">New Assets:</p>
              {compareResult.newAssets.map(a => (
                <div key={a.id} className="text-xs text-slate-400 ml-2">+ {a.value} ({a.type}, risk: {a.riskScore})</div>
              ))}
            </div>
          )}
          {compareResult.removedAssets.length > 0 && (
            <div className="mb-3">
              <p className="text-sm font-medium text-red-400 mb-1">Removed Assets:</p>
              {compareResult.removedAssets.map(a => (
                <div key={a.id} className="text-xs text-slate-400 ml-2">- {a.value} ({a.type})</div>
              ))}
            </div>
          )}
          {compareResult.riskChanges.length > 0 && (
            <div>
              <p className="text-sm font-medium text-yellow-400 mb-1">Risk Score Changes:</p>
              {compareResult.riskChanges.map(c => (
                <div key={c.asset.id} className="text-xs text-slate-400 ml-2">
                  {c.asset.value}: {c.oldScore} → {c.newScore} ({c.newScore > c.oldScore ? '↑' : '↓'})
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   EXPORT VIEW
   ══════════════════════════════════════════════════════════════ */

function ExportView({ scan }: { scan: ScanResult }) {
  const [preview, setPreview] = useState('');
  const [format, setFormat] = useState<'csv' | 'json' | 'md'>('csv');

  const generate = (f: 'csv' | 'json' | 'md') => {
    setFormat(f);
    if (f === 'csv') setPreview(exportCsv(scan));
    else if (f === 'json') setPreview(exportJson(scan));
    else setPreview(exportMarkdown(scan));
  };

  useEffect(() => {
    generate(format);
    // Regenerate only when the scan changes; format-specific buttons call generate directly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan.id]);

  const handleDownload = () => {
    const name = `edam-${scan.domain}-${new Date(scan.timestamp).toISOString().slice(0, 10)}`;
    if (format === 'csv') downloadFile(preview, `${name}.csv`, 'text/csv');
    else if (format === 'json') downloadFile(preview, `${name}.json`, 'application/json');
    else downloadFile(preview, `${name}.md`, 'text/markdown');
  };

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6 flex items-center gap-2">
        <Download className="w-6 h-6 text-cyan-400" /> Export
      </h1>

      <div className="flex gap-3 mb-4">
        {[
          { id: 'csv' as const, label: 'CSV' },
          { id: 'json' as const, label: 'JSON' },
          { id: 'md' as const, label: 'Markdown Report' },
        ].map(f => (
          <button
            key={f.id}
            onClick={() => generate(f.id)}
            className={`px-4 py-2 rounded text-sm font-medium transition-colors cursor-pointer
              ${format === f.id && preview ? 'bg-cyan-600 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'}`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {preview && (
        <>
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 mb-4 max-h-96 overflow-auto">
            <pre className="text-xs font-mono text-slate-400 whitespace-pre-wrap">{preview.slice(0, 5000)}{preview.length > 5000 ? '\n\n... (truncated preview)' : ''}</pre>
          </div>
          <button
            onClick={handleDownload}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded font-medium cursor-pointer"
          >
            <Download className="w-4 h-4" /> Download {format.toUpperCase()}
          </button>
        </>
      )}
    </div>
  );
}
