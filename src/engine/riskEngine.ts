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
  11211: { score: 10, reason: 'Memcached (11211) exposed — cache service' },
  27017: { score: 10, reason: 'MongoDB (27017) exposed — NoSQL database' },
};

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
  }

  // ── Service / Port analysis
  if (asset.type === 'service') {
    const port = Number(asset.metadata.port);
    if (PORT_RISKS[port]) {
      score += PORT_RISKS[port].score;
      reasons.push(PORT_RISKS[port].reason);
    }
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
