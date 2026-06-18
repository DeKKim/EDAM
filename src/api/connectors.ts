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

function normalizeHostname(raw: string): string | null {
  const n = raw.trim().toLowerCase().replace(/\.$/, '').replace(/^\*\./, '');
  if (!n) return null;
  if (n.includes(' ') || n.includes('\t') || n.includes('/')) return null;
  return n;
}

export function hostnameBelongsToDomain(hostname: string, domain: string): boolean {
  const host = normalizeHostname(hostname);
  const base = normalizeHostname(domain);
  return Boolean(host && base && (host === base || host.endsWith(`.${base}`)));
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
      if (n && hostnameBelongsToDomain(n, domain)) subs.add(n);
    }
  }
  return Array.from(subs);
}

// Backward-compatible alias for older orchestrator naming.
export const discoverSubdomainsCT = discoverSubdomainsCrtSh;

/* ── 1b. HackerTarget ── */

export async function discoverSubdomainsHackerTarget(domain: string): Promise<string[]> {
  const url = `https://api.hackertarget.com/hostsearch/?q=${domain}`;
  try {
    const text = await fetchTextViaCorsProxy(url, 20000);
    if (text.startsWith('error') || text.toLowerCase().includes('api count exceeded')) return [];

    const subs = new Set<string>();
    for (const line of text.split('\n')) {
      const host = normalizeHostname(line.split(',')[0] || '');
      if (host && hostnameBelongsToDomain(host, domain)) subs.add(host);
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
        if (n && hostnameBelongsToDomain(n, domain)) subs.add(n);
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
      if (n && hostnameBelongsToDomain(n, domain)) subs.add(n);
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
      if (host && hostnameBelongsToDomain(host, domain)) subs.add(host);
    }
    for (const row of data.RDNS || []) {
      // RDNS entries often look like "1.2.3.4,hostname"
      const host = normalizeHostname(row.split(',')[1] || '');
      if (host && hostnameBelongsToDomain(host, domain)) subs.add(host);
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
  const results = await Promise.all(types.map(async (t) => {
    try {
      const url = `https://dns.google/resolve?name=${encodeURIComponent(
        hostname
      )}&type=${t}`;
      const data = await fetchJson<GoogleDnsResponse>(url, 4500);

      const records: DnsRecord[] = [];
      if (data.Answer) {
        for (const ans of data.Answer) {
          records.push({
            type: DNS_TYPE_MAP[ans.type] || t,
            value: ans.data.replace(/\.$/, ''),
            ttl: ans.TTL,
          });
        }
      }
      return records;
    } catch {
      return [];
    }
  }));

  return results.flat();
}

/* ── 3. Shodan API ── */

const PORT_NAMES: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 69: 'TFTP',
  80: 'HTTP', 81: 'HTTP-Alt', 88: 'Kerberos', 110: 'POP3', 111: 'RPCBind',
  135: 'MSRPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP',
  161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
  514: 'Syslog', 515: 'LPD', 548: 'AFP', 587: 'Submission', 631: 'IPP',
  636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL',
  1521: 'Oracle', 2049: 'NFS', 3128: 'Squid', 3306: 'MySQL', 3389: 'RDP',
  4000: 'Teradata', 5000: 'Flask/UPnP', 5432: 'PostgreSQL', 5900: 'VNC',
  5901: 'VNC-1', 5984: 'CouchDB', 6379: 'Redis', 7001: 'WebLogic',
  8000: 'HTTP-Alt', 8008: 'HTTP-Alt', 8080: 'HTTP-Alt', 8081: 'HTTP-Alt',
  8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9000: 'SonarQube', 9200: 'Elasticsearch',
  9929: 'Nping-Echo', 11211: 'Memcached', 27017: 'MongoDB', 31337: 'Elite/Tcpwrapped'
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

/* ── 3b. Censys Search API (Subdomain Discovery) ── */

interface CensysSearchResponse {
  result?: {
    hits?: Array<{
      names?: string[];
    }>;
  };
}

export async function discoverSubdomainsCensys(
  domain: string,
  apiId: string,
  apiSecret: string
): Promise<string[]> {
  if (!apiId || !apiSecret) return [];

  // Censys requires Basic Auth: b64(id:secret)
  const auth = btoa(`${apiId}:${apiSecret}`);
  const url = `https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.names:${domain}`;

  try {
    const res = await fetch(url, {
      headers: { 'Authorization': `Basic ${auth}` },
      signal: withTimeout(20000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as CensysSearchResponse;

    const subs = new Set<string>();
    for (const hit of data.result?.hits || []) {
      for (const raw of hit.names || []) {
        const n = normalizeHostname(raw);
        if (n && hostnameBelongsToDomain(n, domain)) subs.add(n);
      }
    }
    return Array.from(subs);
  } catch {
    return [];
  }
}

/* ── 3c. GreyHatWarfare (Cloud Bucket Discovery) ── */

interface GreyHatResponse {
  buckets?: Array<{
    id: number;
    name: string;
    type: string;
    provider: string;
  }>;
}

export async function discoverBucketsGreyHat(
  domain: string,
  apiKey: string
): Promise<string[]> {
  if (!apiKey) return [];

  const url = `https://v1.greyhatwarfare.com/api/v1/buckets/search?keywords=${domain}&key=${apiKey}`;

  try {
    const data = await fetchJson<GreyHatResponse>(url, 15000);
    const buckets = new Set<string>();
    for (const b of data.buckets || []) {
      buckets.add(`${b.name}.${b.provider}.com`); // e.g., backup-corp.s3.com
    }
    return Array.from(buckets);
  } catch {
    return [];
  }
}

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
        signal: withTimeout(2500),
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
