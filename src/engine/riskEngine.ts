/**
 * Heuristic Risk Scoring Engine
 * NO CVE database. NO vulnerability scanning.
 * Pure rule-based scoring based on exposed services, naming, and configuration.
 */

import type { Asset, Severity } from '../types';

/* ── Port Risk Rules ── */
const PORT_RISKS: Record<number, { score: number; reason: string }> = {
  21:    { score: 8,  reason: 'FTP (21) exposed — cleartext file transfer' },
  22:    { score: 6,  reason: 'SSH (22) exposed — remote access service' },
  23:    { score: 10, reason: 'Telnet (23) exposed — unencrypted remote access' },
  25:    { score: 4,  reason: 'SMTP (25) exposed — mail server' },
  53:    { score: 3,  reason: 'DNS (53) exposed — DNS service' },
  110:   { score: 6,  reason: 'POP3 (110) exposed — cleartext email' },
  135:   { score: 8,  reason: 'MSRPC (135) exposed — Windows RPC' },
  139:   { score: 8,  reason: 'NetBIOS (139) exposed — Windows file sharing' },
  143:   { score: 5,  reason: 'IMAP (143) exposed — cleartext email' },
  445:   { score: 10, reason: 'SMB (445) exposed — high-risk file sharing' },
  1433:  { score: 10, reason: 'MSSQL (1433) exposed — database service' },
  1521:  { score: 10, reason: 'Oracle DB (1521) exposed — database service' },
  3306:  { score: 10, reason: 'MySQL (3306) exposed — database service' },
  3389:  { score: 10, reason: 'RDP (3389) exposed — remote desktop' },
  5432:  { score: 10, reason: 'PostgreSQL (5432) exposed — database service' },
  5900:  { score: 8,  reason: 'VNC (5900) exposed — remote desktop' },
  6379:  { score: 10, reason: 'Redis (6379) exposed — in-memory database' },
  8080:  { score: 3,  reason: 'HTTP-Alt (8080) exposed — alternative web server' },
  8443:  { score: 2,  reason: 'HTTPS-Alt (8443) exposed — alternative secure web' },
  9200:  { score: 10, reason: 'Elasticsearch (9200) exposed — search engine' },
  9929:  { score: 5,  reason: 'Nping Echo (9929) — likely network testing tool' },
  11211: { score: 10, reason: 'Memcached (11211) exposed — cache service' },
  27017: { score: 10, reason: 'MongoDB (27017) exposed — NoSQL database' },
  31337: { score: 7,  reason: 'Elite (31337) — common port for backdoors or legacy tools' },
};

const WEB_ADMIN_PORTS = new Set([81, 8080, 8081, 8000, 8008, 8443, 8888, 9000, 9090]);
const REMOTE_ACCESS_PORTS = new Set([22, 23, 3389, 5900, 5901]);
const DATABASE_PORTS = new Set([1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017]);
const WINDOWS_EXPOSURE_PORTS = new Set([135, 139, 445]);

/* ── Subdomain Name Risk Patterns ── */
const NAME_RISKS: Array<{ pattern: RegExp; score: number; reason: string }> = [
  { pattern: /dev/i,           score: 4, reason: 'Subdomain contains "dev" — likely development environment' },
  { pattern: /test/i,          score: 4, reason: 'Subdomain contains "test" — likely test environment' },
  { pattern: /stag/i,          score: 4, reason: 'Subdomain contains "stag" — likely staging environment' },
  { pattern: /admin/i,         score: 4, reason: 'Subdomain contains "admin" — administrative interface' },
  { pattern: /api/i,           score: 3, reason: 'Subdomain contains "api" — API endpoint' },
  { pattern: /vpn/i,           score: 4, reason: 'Subdomain contains "vpn" — VPN gateway' },
  { pattern: /mail/i,          score: 3, reason: 'Subdomain contains "mail" — email service' },
  { pattern: /ftp/i,           score: 5, reason: 'Subdomain contains "ftp" — file transfer service' },
  { pattern: /db/i,            score: 5, reason: 'Subdomain contains "db" — possible database access' },
  { pattern: /debug/i,         score: 6, reason: 'Subdomain contains "debug" — debug interface exposed' },
  { pattern: /backup/i,        score: 5, reason: 'Subdomain contains "backup" — backup system' },
  { pattern: /jira/i,          score: 3, reason: 'Subdomain contains "jira" — project tracker' },
  { pattern: /jenkins/i,       score: 5, reason: 'Subdomain contains "jenkins" — CI/CD pipeline' },
  { pattern: /git/i,           score: 4, reason: 'Subdomain contains "git" — version control' },
  { pattern: /phpmyadmin/i,    score: 6, reason: 'Subdomain contains "phpmyadmin" — database manager' },
  { pattern: /internal/i,      score: 5, reason: 'Subdomain contains "internal" — internal service exposed' },
  { pattern: /old/i,           score: 3, reason: 'Subdomain contains "old" — potentially unmaintained' },
  { pattern: /legacy/i,        score: 4, reason: 'Subdomain contains "legacy" — legacy system' },
  { pattern: /uat/i,           score: 4, reason: 'Subdomain contains "uat" — user acceptance testing environment' },
  { pattern: /qa/i,            score: 4, reason: 'Subdomain contains "qa" — quality assurance environment' },
  { pattern: /demo/i,          score: 3, reason: 'Subdomain contains "demo" — demonstration environment' },
  { pattern: /beta/i,          score: 3, reason: 'Subdomain contains "beta" — pre-production service' },
  { pattern: /preview/i,       score: 3, reason: 'Subdomain contains "preview" — pre-release service' },
  { pattern: /portal/i,        score: 3, reason: 'Subdomain contains "portal" — user or admin portal' },
  { pattern: /sso/i,           score: 4, reason: 'Subdomain contains "sso" — identity service' },
  { pattern: /auth/i,          score: 4, reason: 'Subdomain contains "auth" — authentication service' },
  { pattern: /login/i,         score: 4, reason: 'Subdomain contains "login" — authentication endpoint' },
  { pattern: /grafana/i,       score: 5, reason: 'Subdomain contains "grafana" — monitoring dashboard' },
  { pattern: /kibana/i,        score: 5, reason: 'Subdomain contains "kibana" — log analytics dashboard' },
  { pattern: /prometheus/i,    score: 5, reason: 'Subdomain contains "prometheus" — monitoring endpoint' },
  { pattern: /sonar/i,         score: 4, reason: 'Subdomain contains "sonar" — code quality or scanner portal' },
  { pattern: /nexus/i,         score: 5, reason: 'Subdomain contains "nexus" — artifact repository' },
  { pattern: /artifactory/i,   score: 5, reason: 'Subdomain contains "artifactory" — artifact repository' },
];

/* ── Scoring Function ── */

export interface RiskResult {
  score: number;
  severity: Severity;
  reasons: string[];
}

export function scoreAsset(
  asset: Asset,
  servicesPerIp: Map<string, number>
): RiskResult {
  let score = 0;
  const reasons: string[] = [];

  // ── Subdomain / Domain name analysis
  if (asset.type === 'subdomain' || asset.type === 'domain') {
    for (const rule of NAME_RISKS) {
      if (rule.pattern.test(asset.value)) {
        score += rule.score;
        reasons.push(rule.reason);
      }
    }

    // HTTP without HTTPS
    if (asset.metadata.http === true && asset.metadata.https !== true) {
      score += 6;
      reasons.push('HTTP available without HTTPS — data transmitted in cleartext');
    }

    if (asset.metadata.http === true && asset.metadata.https === true) {
      score += 1;
      reasons.push('Web service is externally reachable over HTTP and HTTPS');
    }

    if (asset.metadata.cnames && asset.metadata.cnames.length > 0) {
      score += 1;
      reasons.push(`CNAME chain observed — verify third-party or cloud ownership (${asset.metadata.cnames.slice(0, 2).join(', ')})`);
    }
  }

  // ── IP address analysis
  if (asset.type === 'ip') {
    const svcCount = servicesPerIp.get(asset.value) || 0;
    if (svcCount > 5) {
      score += 5;
      reasons.push(`${svcCount} services exposed on single IP — large attack surface`);
    } else if (svcCount > 2) {
      score += 3;
      reasons.push(`${svcCount} services exposed on single IP — moderate attack surface`);
    }

    const ports = Array.isArray(asset.metadata.ports) ? asset.metadata.ports : [];
    const databasePorts = ports.filter(port => DATABASE_PORTS.has(port));
    const remotePorts = ports.filter(port => REMOTE_ACCESS_PORTS.has(port));
    const windowsPorts = ports.filter(port => WINDOWS_EXPOSURE_PORTS.has(port));

    if (databasePorts.length > 0) {
      score += 8;
      reasons.push(`Database/cache ports exposed on IP — ${databasePorts.join(', ')}`);
    }
    if (remotePorts.length > 0) {
      score += 6;
      reasons.push(`Remote administration ports exposed on IP — ${remotePorts.join(', ')}`);
    }
    if (windowsPorts.length > 0) {
      score += 6;
      reasons.push(`Windows file sharing/RPC ports exposed on IP — ${windowsPorts.join(', ')}`);
    }
  }

  // ── Service / Port analysis
  if (asset.type === 'service') {
    const port = Number(asset.metadata.port);
    if (PORT_RISKS[port]) {
      score += PORT_RISKS[port].score;
      reasons.push(PORT_RISKS[port].reason);
    }

    if (WEB_ADMIN_PORTS.has(port)) {
      score += 3;
      reasons.push(`Management or alternate web port exposed (${port}) — verify authentication and access control`);
    }

    const product = `${asset.metadata.product || ''} ${asset.metadata.banner || ''}`.toLowerCase();
    if (/jenkins|grafana|kibana|prometheus|phpmyadmin|adminer|tomcat|weblogic|jira|confluence|nexus|artifactory/.test(product)) {
      score += 7;
      reasons.push('Sensitive admin/devops product fingerprint observed in service metadata');
    }
    if (/default|example|welcome|test page|index of/i.test(product)) {
      score += 3;
      reasons.push('Default or directory-style web content indicator observed');
    }
  }

  // ── Bucket analysis
  if (asset.type === 'bucket') {
    score += 12;
    reasons.push('Exposed cloud storage bucket — potential sensitive data leak');
  }

  // Cap at 100
  score = Math.min(100, score);

  const severity: Severity =
    score >= 20 ? 'critical' :
    score >= 12 ? 'high' :
    score >= 6  ? 'medium' :
    'low';

  return { score, severity, reasons };
}
