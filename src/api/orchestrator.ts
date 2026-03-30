/**
 * Scan orchestrator — coordinates discovery, DNS, Shodan, HTTP probing,
 * risk scoring, and graph assembly into a single ScanResult.
 */

import type {
  Asset,
  Relationship,
  ScanConfig,
  ScanResult,
  ScanStats,
  DomainAsset,
  IpAsset,
  ServiceAsset,
} from '../types';
import {
  discoverSubdomainsCrtSh,
  discoverSubdomainsHackerTarget,
  discoverSubdomainsCertSpotter,
  discoverSubdomainsSonar,
  discoverSubdomainsBufferOver,
  resolveDns,
  shodanLookup,
  probeHttp,
} from './connectors';
import { scoreAsset } from '../engine/riskEngine';

const MAX_SUBS = 200;
const delay = (ms: number) => new Promise(r => setTimeout(r, ms));
const DEFAULT_ACTIVE_PORTS = [
  21, 22, 23, 25, 53, 80, 81, 88, 110, 135, 139, 143, 443, 445, 465, 587, 993, 995,
  1433, 1521, 3306, 3389, 5432, 5900, 6379, 7001, 8000, 8080, 8081, 8443, 8888, 9200, 27017
];

function uid(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export async function runScan(cfg: ScanConfig): Promise<ScanResult> {
  const t0 = Date.now();
  const assets: Asset[] = [];
  const rels: Relationship[] = [];
  const logs: string[] = [];
  const errors: string[] = [];
  const now = new Date().toISOString();

  const log = (msg: string) => {
    const entry = `[${new Date().toLocaleTimeString()}] ${msg}`;
    logs.push(entry);
    cfg.onLog(entry);
  };

  const progress = (phase: string, pct: number, detail: string) =>
    cfg.onProgress(phase, pct, detail);

  const domain = cfg.domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');

  // ── Root domain asset
  const rootId = `domain:${domain}`;
  const rootAsset: DomainAsset = {
    id: rootId,
    type: 'domain',
    value: domain,
    metadata: {},
    riskScore: 0,
    severity: 'low',
    riskReasons: [],
    firstSeen: now,
  };
  assets.push(rootAsset);
  const assetById = new Map<string, Asset>();
  assetById.set(rootId, rootAsset);
  log(`Starting scan for ${domain}`);

  // ── Phase 1: Subdomain Discovery ──
  progress('discovery', 5, 'Querying Certificate Transparency logs...');
  log('Phase 1: Subdomain discovery');

  const subSet = new Set<string>([domain]);

  if (cfg.enableCT) {
    log('Querying passive sources (crt.sh / CertSpotter / Sonar / BufferOver / HackerTarget)...');

    try {
      const r = await discoverSubdomainsCrtSh(domain);
      log(`crt.sh returned ${r.length} subdomains`);
      for (const s of r) subSet.add(s);
    } catch (err) {
      log(`crt.sh unavailable (${String(err)}), continuing`);
    }

    await delay(3000);

    {
      const r = await discoverSubdomainsCertSpotter(domain);
      log(`CertSpotter returned ${r.length} subdomains`);
      for (const s of r) subSet.add(s);
    }

    await delay(2000);

    {
      const r = await discoverSubdomainsSonar(domain);
      log(`Sonar returned ${r.length} subdomains`);
      for (const s of r) subSet.add(s);
    }

    await delay(2000);

    {
      const r = await discoverSubdomainsBufferOver(domain);
      log(`BufferOver returned ${r.length} subdomains`);
      for (const s of r) subSet.add(s);
    }

    await delay(2000);

    {
      const r = await discoverSubdomainsHackerTarget(domain);
      log(`HackerTarget returned ${r.length} subdomains`);
      for (const s of r) subSet.add(s);
    }
  }

  let subdomains = Array.from(subSet);

  // Cap subdomains
  if (subdomains.length > MAX_SUBS) {
    log(`Capping subdomains from ${subdomains.length} to ${MAX_SUBS}`);
    subdomains = subdomains.slice(0, MAX_SUBS);
  }

  log(`Total subdomains to resolve: ${subdomains.length}`);
  progress('discovery', 15, `Found ${subdomains.length} subdomains`);

  // Create subdomain assets
  for (const sub of subdomains) {
    if (sub === domain) continue;
    const subId = `subdomain:${sub}`;
    const subAsset: DomainAsset = {
      id: subId,
      type: 'subdomain',
      value: sub,
      metadata: {},
      riskScore: 0,
      severity: 'low',
      riskReasons: [],
      firstSeen: now,
    };
    assets.push(subAsset);
    assetById.set(subId, subAsset);
    rels.push({
      id: `rel:${uid()}`,
      sourceId: rootId,
      targetId: subId,
      type: 'parent_of',
    });
  }

  // ── Phase 2: DNS Resolution ──
  progress('dns', 20, 'Resolving DNS records...');
  log('Phase 2: DNS resolution');

  const ipMap = new Map<string, string>(); // ip -> asset id

  for (let i = 0; i < subdomains.length; i++) {
    const sub = subdomains[i];
    const pct = 20 + Math.round((i / subdomains.length) * 25);
    progress('dns', pct, `Resolving ${sub} (${i + 1}/${subdomains.length})`);

    try {
      const records = await resolveDns(sub);
      const subId = sub === domain ? rootId : `subdomain:${sub}`;

      // Store DNS records in metadata
      const aRecords: string[] = [];
      const cnameRecords: string[] = [];

      for (const rec of records) {
        if (rec.type === 'A' || rec.type === 'AAAA') {
          aRecords.push(rec.value);

          // Create IP asset if new
          if (!ipMap.has(rec.value)) {
            const ipId = `ip:${rec.value}`;
            ipMap.set(rec.value, ipId);
            const ipAsset: IpAsset = {
              id: ipId,
              type: 'ip',
              value: rec.value,
              metadata: {},
              riskScore: 0,
              severity: 'low',
              riskReasons: [],
              firstSeen: now,
            };
            assets.push(ipAsset);
            assetById.set(ipId, ipAsset);
          }

          // Relationship: subdomain -> resolves_to -> IP
          rels.push({
            id: `rel:${uid()}`,
            sourceId: subId,
            targetId: ipMap.get(rec.value)!,
            type: 'resolves_to',
          });
        }

        if (rec.type === 'CNAME') {
          cnameRecords.push(rec.value);
        }
      }

      // Update metadata
      const asset = assetById.get(subId) as DomainAsset | undefined;
      if (asset) {
        if (aRecords.length) asset.metadata.ips = aRecords;
        if (cnameRecords.length) asset.metadata.cnames = cnameRecords;
        asset.metadata.dnsRecordCount = records.length;
      }

      if (records.length > 0) {
        log(`  ${sub}: ${records.map(r => `${r.type}=${r.value}`).join(', ')}`);
      } else {
        log(`  ${sub}: no DNS records found`);
      }
    } catch (err) {
      log(`  ${sub}: DNS resolution failed — ${err}`);
      errors.push(`DNS resolution failed for ${sub}: ${err}`);
    }

    await delay(150); // Rate limit
  }

  log(`Discovered ${ipMap.size} unique IP addresses`);

  // ── Phase 3: HTTP/HTTPS Probing ──
  progress('http', 48, 'Probing HTTP/HTTPS...');
  log('Phase 3: HTTP/HTTPS probing');

  for (let i = 0; i < subdomains.length; i++) {
    const sub = subdomains[i];
    const pct = 48 + Math.round((i / subdomains.length) * 12);
    progress('http', pct, `Probing ${sub}`);

    try {
      const probe = await probeHttp(sub);
      const subId = sub === domain ? rootId : `subdomain:${sub}`;
      const asset = assetById.get(subId) as DomainAsset | undefined;
      if (asset) {
        asset.metadata.http = probe.http;
        asset.metadata.https = probe.https;
      }
      if (probe.http || probe.https) {
        log(`  ${sub}: HTTP=${probe.http} HTTPS=${probe.https}`);
      }
    } catch {
      // skip
    }
  }

  // ── Phase 4: Shodan Enrichment ──
  if (cfg.enableShodan && cfg.shodanKey) {
    progress('shodan', 62, 'Querying Shodan API...');
    log('Phase 4: Shodan enrichment');

    const ips = Array.from(ipMap.keys());
    for (let i = 0; i < ips.length; i++) {
      const ip = ips[i];
      const pct = 62 + Math.round((i / ips.length) * 20);
      progress('shodan', pct, `Shodan lookup: ${ip} (${i + 1}/${ips.length})`);

      try {
        const result = await shodanLookup(ip, cfg.shodanKey);
        if (result) {
          // Update IP asset metadata
          const ipAssetId = ipMap.get(ip);
          const ipAsset = ipAssetId ? (assetById.get(ipAssetId) as IpAsset | undefined) : undefined;
          if (ipAsset) {
            if (result.org) ipAsset.metadata.org = result.org;
            if (result.isp) ipAsset.metadata.isp = result.isp;
            if (result.os) ipAsset.metadata.os = result.os;
            if (result.country) ipAsset.metadata.country = result.country;
            if (result.city) ipAsset.metadata.city = result.city;
            ipAsset.metadata.portCount = result.ports.length;
            ipAsset.metadata.ports = result.ports;
          }

          // Create service assets
          for (const svc of result.services) {
            const svcId = `service:${ip}:${svc.port}`;
            if (!assetById.has(svcId)) {
              const svcAsset: ServiceAsset = {
                id: svcId,
                type: 'service',
                value: `${ip}:${svc.port}`,
                metadata: {
                  port: svc.port,
                  protocol: svc.protocol,
                  product: svc.product || 'unknown',
                  ...(svc.version ? { version: svc.version } : {}),
                  ...(svc.banner ? { banner: svc.banner } : {}),
                },
                riskScore: 0,
                severity: 'low',
                riskReasons: [],
                firstSeen: now,
              };
              assets.push(svcAsset);
              assetById.set(svcId, svcAsset);

              rels.push({
                id: `rel:${uid()}`,
                sourceId: ipMap.get(ip)!,
                targetId: svcId,
                type: 'exposes',
              });
            }
          }

          log(`  ${ip}: ${result.ports.length} ports — [${result.ports.join(', ')}]${result.org ? ` (${result.org})` : ''}`);
        } else {
          log(`  ${ip}: no Shodan data`);
        }
      } catch (err) {
        log(`  ${ip}: Shodan error — ${err}`);
        errors.push(`Shodan lookup failed for ${ip}: ${err}`);
      }

      await delay(1100); // Shodan rate limit: 1 req/sec
    }
  } else {
    log('Phase 4: Shodan enrichment skipped (disabled or no API key)');
    progress('shodan', 82, 'Shodan skipped');
  }

  // ── Phase 4b: Active port scan (local backend) ──
  if (cfg.enableActivePortScan) {
    const ips = Array.from(ipMap.keys());
    const ports = (cfg.activePortScanPorts && cfg.activePortScanPorts.length > 0)
      ? cfg.activePortScanPorts
      : DEFAULT_ACTIVE_PORTS;

    if (ips.length > 0 && ports.length > 0) {
      progress('ports', 82, `Active port check: ${ips.length} IPs × ${ports.length} ports...`);
      log(`Phase 4b: Active port check (local backend) — scanning ${ips.length} IPs...`);
      try {
        const res = await fetch('/api/port-scan', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            ips,
            ports,
            timeoutMs: 1200, // Increased timeout
            concurrency: 120,
          }),
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(`HTTP ${res.status}: ${errData.error || 'Backend unreachable'}`);
        }
        
        const data = (await res.json()) as { openByIp?: Record<string, number[]> };
        const openByIp = data.openByIp || {};

        let openCount = 0;
        let ipsWithOpenPorts = 0;

        for (const [ip, openPorts] of Object.entries(openByIp)) {
          const ipAssetId = ipMap.get(ip);
          if (!ipAssetId) continue;

          // Update IP asset metadata with combined results
          const ipAsset = assetById.get(ipAssetId) as IpAsset | undefined;
          if (ipAsset) {
            const combinedPorts = Array.from(new Set([...(ipAsset.metadata.ports || []), ...openPorts]));
            ipAsset.metadata.ports = combinedPorts.sort((a, b) => a - b);
            ipAsset.metadata.portCount = combinedPorts.length;
          }

          if (openPorts.length > 0) {
            ipsWithOpenPorts++;
            log(`  ${ip}: ${openPorts.length} active ports detected — [${openPorts.join(', ')}]`);
          }

          for (const port of openPorts) {
            openCount++;
            const svcId = `service:${ip}:${port}`;
            if (!assetById.has(svcId)) {
              const svcAsset: ServiceAsset = {
                id: svcId,
                type: 'service',
                value: `${ip}:${port}`,
                metadata: {
                  port,
                  protocol: 'tcp',
                  product: 'unknown',
                },
                riskScore: 0,
                severity: 'low',
                riskReasons: [],
                firstSeen: now,
              };
              assets.push(svcAsset);
              assetById.set(svcId, svcAsset);

              // Add relationship only if we added the asset
              rels.push({
                id: `rel:${uid()}`,
                sourceId: ipAssetId,
                targetId: svcId,
                type: 'exposes',
              });
            }
          }
        }

        log(`Active port check complete: ${openCount} services on ${ipsWithOpenPorts} IPs`);
      } catch (err) {
        log(`Active port check failed — ${err}`);
        errors.push(`Active port check failed: ${err}`);
      }
    }
  }

  // ── Phase 5: Risk Scoring ──
  progress('scoring', 85, 'Computing risk scores...');
  log('Phase 5: Heuristic risk scoring');

  // Collect services per IP for multi-service penalty
  const servicesPerIp = new Map<string, number>();
  for (const a of assets) {
    if (a.type === 'service') {
      const val = a.value;
      const lastColon = val.lastIndexOf(':');
      const ip = lastColon !== -1 ? val.substring(0, lastColon) : val;
      servicesPerIp.set(ip, (servicesPerIp.get(ip) || 0) + 1);
    }
  }

  for (const asset of assets) {
    const result = scoreAsset(asset, servicesPerIp);
    asset.riskScore = result.score;
    asset.severity = result.severity;
    asset.riskReasons = result.reasons;
  }

  // Root domain risk = scaled max child risk
  const childScores = assets.filter(a => a.id !== rootId).map(a => a.riskScore);
  if (childScores.length > 0) {
    const maxChild = Math.max(...childScores);
    const rootAsset = assets.find(a => a.id === rootId)!;
    rootAsset.riskScore = Math.min(100, Math.round(maxChild * 0.8));
    rootAsset.severity =
      rootAsset.riskScore >= 20 ? 'critical' :
      rootAsset.riskScore >= 12 ? 'high' :
      rootAsset.riskScore >= 6 ? 'medium' : 'low';
    rootAsset.riskReasons = [`Aggregate risk from ${assets.length - 1} child assets (max child score: ${maxChild})`];
  }

  log(`Risk scoring complete. Max risk: ${Math.max(...assets.map(a => a.riskScore))}`);

  // ── Finalize ──
  progress('done', 100, 'Scan complete!');
  log(`Scan completed in ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  const stats = computeStats(assets);

  return {
    id: `scan-${uid()}`,
    domain,
    timestamp: now,
    durationMs: Date.now() - t0,
    assets,
    relationships: rels,
    stats,
    logs,
    errors,
  };
}

function computeStats(assets: Asset[]): ScanStats {
  const byType = { domains: 0, subdomains: 0, ips: 0, services: 0 };
  let totalRisk = 0;
  let maxRisk = 0;
  const bySev = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const a of assets) {
    if (a.type === 'domain') byType.domains++;
    else if (a.type === 'subdomain') byType.subdomains++;
    else if (a.type === 'ip') byType.ips++;
    else if (a.type === 'service') byType.services++;

    totalRisk += a.riskScore;
    if (a.riskScore > maxRisk) maxRisk = a.riskScore;
    bySev[a.severity]++;
  }

  return {
    totalAssets: assets.length,
    ...byType,
    avgRisk: assets.length > 0 ? Math.round(totalRisk / assets.length) : 0,
    maxRisk,
    ...bySev,
  };
}
