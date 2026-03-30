/**
 * Real API connectors for external asset discovery.
 * - crt.sh (Certificate Transparency) via CORS proxy
 * - Google DNS-over-HTTPS (direct, CORS enabled)
 * - Shodan API (direct, CORS enabled)
 * - HTTP/HTTPS probing via HEAD requests
 */

import type { DnsRecord, ShodanHostResult, ShodanService } from '../types';

/* ── Helpers ── */

const CORS_PROXIES: Array<(url: string) => string> = [
  (url) => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
  (url) => `https://corsproxy.io/?${encodeURIComponent(url)}`,
];

function withTimeout(ms: number): AbortSignal {
  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), ms);
  return ctrl.signal;
}

async function fetchJson<T>(url: string, timeout = 12000): Promise<T> {
  const res = await fetch(url, { signal: withTimeout(timeout) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

async function fetchJsonViaCorsProxy<T>(url: string, timeout = 20000): Promise<T> {
  let lastErr: unknown = null;
  for (const wrap of CORS_PROXIES) {
    try {
      return await fetchJson<T>(wrap(url), timeout);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr ?? new Error('CORS proxy failed');
}

async function fetchTextViaCorsProxy(url: string, timeout = 20000): Promise<string> {
  let lastErr: unknown = null;
  for (const wrap of CORS_PROXIES) {
    try {
      const res = await fetch(wrap(url), { signal: withTimeout(timeout) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr ?? new Error('CORS proxy failed');
}

const delay = (ms: number) => new Promise(r => setTimeout(r, ms));

function normalizeHostname(raw: string): string | null {
  const n = raw.trim().toLowerCase().replace(/\.$/, '').replace(/^\*\./, '');
  if (!n) return null;
  if (n.includes(' ') || n.includes('\t') || n.includes('/')) return null;
  return n;
}

/* ── 1. Certificate Transparency (crt.sh) ── */

interface CrtEntry {
  name_value: string;
  common_name?: string;
}

export async function discoverSubdomainsCrtSh(domain: string): Promise<string[]> {
  const url = `https://crt.sh/?q=%25.${domain}&output=json`;
  const entries = await fetchJsonViaCorsProxy<CrtEntry[]>(url, 25000);

  const subs = new Set<string>();
  for (const e of entries) {
    const names = e.name_value.split('\n');
    for (const raw of names) {
      const n = normalizeHostname(raw);
      if (n && n.endsWith(domain)) subs.add(n);
    }
  }
  return Array.from(subs);
}

/* ── 1b. HackerTarget ── */

export async function discoverSubdomainsHackerTarget(domain: string): Promise<string[]> {
  const url = `https://api.hackertarget.com/hostsearch/?q=${domain}`;
  try {
    const text = await fetchTextViaCorsProxy(url, 20000);
    if (text.startsWith('error') || text.toLowerCase().includes('api count exceeded')) return [];

    const subs = new Set<string>();
    for (const line of text.split('\n')) {
      const host = normalizeHostname(line.split(',')[0] || '');
      if (host && host.endsWith(domain)) subs.add(host);
    }
    return Array.from(subs);
  } catch {
    return [];
  }
}

/* ── 1c. CertSpotter (passive CT aggregation) ── */

type CertSpotterIssuance = {
  dns_names?: string[];
};

export async function discoverSubdomainsCertSpotter(domain: string): Promise<string[]> {
  // Public endpoint; may paginate, but first page is usually enough for demos.
  const url =
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
    `&include_subdomains=true&expand=dns_names`;

  try {
    const issuances = await fetchJsonViaCorsProxy<CertSpotterIssuance[]>(url, 25000);
    const subs = new Set<string>();
    for (const iss of issuances) {
      for (const raw of iss.dns_names || []) {
        const n = normalizeHostname(raw);
        if (n && n.endsWith(domain)) subs.add(n);
      }
    }
    return Array.from(subs);
  } catch {
    return [];
  }
}

/* ── 1d. Sonar (Omnisint) ── */

export async function discoverSubdomainsSonar(domain: string): Promise<string[]> {
  const url = `https://sonar.omnisint.io/subdomains/${encodeURIComponent(domain)}`;
  try {
    const subsRaw = await fetchJsonViaCorsProxy<string[]>(url, 20000);
    const subs = new Set<string>();
    for (const raw of subsRaw || []) {
      const n = normalizeHostname(raw);
      if (n && n.endsWith(domain)) subs.add(n);
    }
    return Array.from(subs);
  } catch {
    return [];
  }
}

/* ── 1e. BufferOver DNS ── */

type BufferOverResponse = {
  FDNS_A?: string[];
  RDNS?: string[];
};

export async function discoverSubdomainsBufferOver(domain: string): Promise<string[]> {
  const url = `https://dns.bufferover.run/dns?q=.${encodeURIComponent(domain)}`;
  try {
    const data = await fetchJsonViaCorsProxy<BufferOverResponse>(url, 20000);
    const subs = new Set<string>();

    const pullHost = (row: string) => normalizeHostname(row.split(',')[0] || '');
    for (const row of data.FDNS_A || []) {
      const host = pullHost(row);
      if (host && host.endsWith(domain)) subs.add(host);
    }
    for (const row of data.RDNS || []) {
      // RDNS entries often look like "1.2.3.4,hostname"
      const host = normalizeHostname(row.split(',')[1] || '');
      if (host && host.endsWith(domain)) subs.add(host);
    }

    return Array.from(subs);
  } catch {
    return [];
  }
}

/* ── 2. DNS Resolution (Google DoH) ── */

interface GoogleDnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface GoogleDnsResponse {
  Answer?: GoogleDnsAnswer[];
  Status: number;
}

const DNS_TYPE_MAP: Record<number, string> = {
  1: 'A',
  5: 'CNAME',
  28: 'AAAA',
};

export async function resolveDns(
  hostname: string,
  types: string[] = ['A', 'AAAA', 'CNAME']
): Promise<DnsRecord[]> {
  const records: DnsRecord[] = [];

  for (const t of types) {
    try {
      const url = `https://dns.google/resolve?name=${encodeURIComponent(
        hostname
      )}&type=${t}`;
      const data = await fetchJson<GoogleDnsResponse>(url, 8000);

      if (data.Answer) {
        for (const ans of data.Answer) {
          records.push({
            type: DNS_TYPE_MAP[ans.type] || t,
            value: ans.data.replace(/\.$/, ''),
            ttl: ans.TTL,
          });
        }
      }
    } catch {
      // skip failed type
    }
    await delay(100);
  }

  return records;
}

/* ── 3. Shodan API ── */

const PORT_NAMES: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
  993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
  3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
  6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
  27017: 'MongoDB', 9200: 'Elasticsearch', 11211: 'Memcached',
};

interface ShodanHostResponse {
  ip_str: string;
  ports: number[];
  os?: string;
  org?: string;
  isp?: string;
  country_code?: string;
  city?: string;
  data?: Array<{
    port: number;
    transport: string;
    product?: string;
    version?: string;
    data?: string;
  }>;
}

export async function shodanLookup(
  ip: string,
  apiKey: string
): Promise<ShodanHostResult | null> {
  if (!apiKey) return null;

  try {
    const url = `https://api.shodan.io/shodan/host/${ip}?key=${apiKey}&minify=true`;
    const data = await fetchJson<ShodanHostResponse>(url, 15000);

    const services: ShodanService[] = (data.data || []).map(s => ({
      port: s.port,
      protocol: s.transport || 'tcp',
      product: s.product || PORT_NAMES[s.port] || 'unknown',
      version: s.version,
      banner: s.data?.substring(0, 200),
    }));

    // Also add ports that don't have service details
    for (const p of data.ports || []) {
      if (!services.find(s => s.port === p)) {
        services.push({
          port: p,
          protocol: 'tcp',
          product: PORT_NAMES[p] || 'unknown',
        });
      }
    }

    return {
      ip: data.ip_str,
      ports: data.ports || [],
      services,
      os: data.os || undefined,
      org: data.org || undefined,
      isp: data.isp || undefined,
      country: data.country_code || undefined,
      city: data.city || undefined,
    };
  } catch {
    return null;
  }
}

// No explicit validation helper here; the frontend simply checks for presence of a key.

/* ── 4. HTTP/HTTPS Probing ── */

export async function probeHttp(hostname: string): Promise<{
  http: boolean;
  https: boolean;
}> {
  const check = async (proto: string): Promise<boolean> => {
    try {
      const res = await fetch(`${proto}://${hostname}`, {
        method: 'HEAD',
        mode: 'no-cors',
        signal: withTimeout(5000),
      });
      // no-cors gives opaque response, status 0 means it connected
      return res.type === 'opaque' || res.ok;
    } catch {
      return false;
    }
  };

  const [http, https] = await Promise.all([check('http'), check('https')]);
  return { http, https };
}
