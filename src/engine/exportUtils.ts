/**
 * Export utilities — CSV, JSON, Markdown report generation.
 * Also handles scan history persistence in localStorage.
 */

import type { Asset, ScanResult } from '../types';

const HISTORY_KEY = 'edam_scan_history';
const MAX_HISTORY = 15;

/* ── History ── */

export function saveToHistory(scan: ScanResult): void {
  const history = loadHistory();
  history.unshift(scan);
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 5)));
    } catch {
      // If storage is unavailable, avoid breaking the scan workflow.
    }
  }
}

export function loadHistory(): ScanResult[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function deleteFromHistory(scanId: string): void {
  try {
    const history = loadHistory().filter(s => s.id !== scanId);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch {
    // If we can't update history, fail silently to avoid breaking the UI
  }
}

/* ── CSV Export ── */

function csvCell(value: unknown): string {
  const text = Array.isArray(value) ? value.join('; ') : String(value ?? '');
  return `"${text.replace(/"/g, '""')}"`;
}

function markdownCell(value: unknown): string {
  return String(value ?? '-').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function recommendAction(asset: Asset): string {
  if (asset.type === 'bucket') return 'Review bucket policy, public access, sensitive objects, and access logging.';
  if (asset.type === 'service') {
    const port = asset.metadata.port;
    if ([1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017].includes(port)) return 'Restrict database/cache service to private network or VPN.';
    if ([22, 23, 3389, 5900, 5901].includes(port)) return 'Restrict remote administration with VPN/MFA/source allowlist.';
    if ([135, 139, 445].includes(port)) return 'Block Windows sharing/RPC exposure from the internet.';
    if ([80, 81, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090].includes(port)) return 'Review web authentication, HTTPS, headers, and default pages.';
    return 'Confirm service owner, business need, patch level, and access controls.';
  }
  if (asset.type === 'ip') return 'Review exposed ports and firewall policy for this host.';
  if (asset.riskReasons.some(reason => /http available without https/i.test(reason))) return 'Enable HTTPS redirect and remove cleartext-only exposure.';
  if (/dev|test|stag|uat|qa|demo|beta|preview|internal|legacy|backup|debug|admin|login|sso|auth|vpn/i.test(asset.value)) {
    return 'Validate owner and restrict or remove public exposure if not required.';
  }
  return 'Confirm ownership, purpose, and expected external visibility.';
}

export function exportCsv(scan: ScanResult): string {
  const headers = ['ID', 'Type', 'Value', 'Risk Score', 'Severity', 'Risk Reasons', 'Recommended Check', 'First Seen'];
  const rows = scan.assets.map(a => [
    csvCell(a.id),
    csvCell(a.type),
    csvCell(a.value),
    a.riskScore.toString(),
    csvCell(a.severity),
    csvCell(a.riskReasons),
    csvCell(recommendAction(a)),
    csvCell(a.firstSeen),
  ]);
  return [headers.map(csvCell).join(','), ...rows.map(r => r.join(','))].join('\n');
}

/* ── JSON Export ── */

export function exportJson(scan: ScanResult): string {
  return JSON.stringify(scan, null, 2);
}

/* ── Markdown Report ── */

export function exportMarkdown(scan: ScanResult): string {
  const s = scan.stats;
  let md = `# External Asset Scan Report\n\n`;
  md += `**Domain:** ${scan.domain}\n`;
  md += `**Date:** ${new Date(scan.timestamp).toLocaleString()}\n`;
  md += `**Duration:** ${(scan.durationMs / 1000).toFixed(1)}s\n\n`;

  md += `## Summary\n\n`;
  md += `| Metric | Value |\n|--------|-------|\n`;
  md += `| Total Assets | ${s.totalAssets} |\n`;
  md += `| Domains | ${s.domains} |\n`;
  md += `| Subdomains | ${s.subdomains} |\n`;
  md += `| IP Addresses | ${s.ips} |\n`;
  md += `| Services | ${s.services} |\n`;
  md += `| Buckets | ${s.buckets} |\n`;
  md += `| Relationships | ${scan.relationships.length} |\n`;
  md += `| Avg Risk Score | ${s.avgRisk} |\n`;
  md += `| Max Risk Score | ${s.maxRisk} |\n`;
  md += `| Critical | ${s.critical} |\n`;
  md += `| High | ${s.high} |\n`;
  md += `| Medium | ${s.medium} |\n`;
  md += `| Low | ${s.low} |\n\n`;

  md += `## Assets by Risk\n\n`;
  md += `| Asset | Type | Risk | Severity | Reasons | Recommended Check |\n`;
  md += `|-------|------|------|----------|---------|-------------------|\n`;

  const sorted = [...scan.assets].sort((a, b) => b.riskScore - a.riskScore);
  for (const a of sorted) {
    md += `| ${markdownCell(a.value)} | ${a.type} | ${a.riskScore} | ${a.severity} | ${markdownCell(a.riskReasons.join('; ') || '-')} | ${markdownCell(recommendAction(a))} |\n`;
  }

  if (scan.errors.length > 0) {
    md += `\n## Errors\n\n`;
    for (const e of scan.errors) {
      md += `- ${e}\n`;
    }
  }

  md += `\n---\n*Generated by EDAM — External Digital Asset Mapper*\n`;
  return md;
}

/* ── Download helper ── */

export function downloadFile(content: string, filename: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
