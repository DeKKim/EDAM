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
  BucketAsset,
} from '../types';
import * as connectors from './connectors';
import { scoreAsset } from '../engine/riskEngine';

const DEFAULT_MAX_SUBS = 120;
const DEFAULT_SHODAN_LIMIT = 35;
const delay = (ms: number) => new Promise(r => setTimeout(r, ms));

async function runWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;

  async function runner() {
    while (next < items.length) {
      const index = next++;
      results[index] = await worker(items[index], index);
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, Math.max(1, items.length)) }, runner));
  return results;
}

type SubdomainDiscoveryFn = (domain: string) => Promise<string[]>;
type CensysDiscoveryFn = (domain: string, apiId: string, apiSecret: string) => Promise<string[]>;
type BucketDiscoveryFn = (domain: string, apiKey: string) => Promise<string[]>;

const discoverSubdomainsCrtSh =
  ((connectors as Record<string, unknown>).discoverSubdomainsCrtSh ??
    (connectors as Record<string, unknown>).discoverSubdomainsCT) as SubdomainDiscoveryFn;
const discoverSubdomainsHackerTarget =
  ((connectors as Record<string, unknown>).discoverSubdomainsHackerTarget ??
    (async () => [])) as SubdomainDiscoveryFn;
const discoverSubdomainsCertSpotter =
  ((connectors as Record<string, unknown>).discoverSubdomainsCertSpotter ??
    (async () => [])) as SubdomainDiscoveryFn;
const discoverSubdomainsSonar =
  ((connectors as Record<string, unknown>).discoverSubdomainsSonar ??
    (async () => [])) as SubdomainDiscoveryFn;
const discoverSubdomainsBufferOver =
  ((connectors as Record<string, unknown>).discoverSubdomainsBufferOver ??
    (async () => [])) as SubdomainDiscoveryFn;
const discoverSubdomainsCensys =
  ((connectors as Record<string, unknown>).discoverSubdomainsCensys ??
    (async () => [])) as CensysDiscoveryFn;
const discoverBucketsGreyHat =
  ((connectors as Record<string, unknown>).discoverBucketsGreyHat ??
    (async () => [])) as BucketDiscoveryFn;
const resolveDns = connectors.resolveDns;
const shodanLookup = connectors.shodanLookup;
const probeHttp = connectors.probeHttp;
const DEFAULT_ACTIVE_PORTS = [
  21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 135, 137, 138, 139, 143, 161, 389, 443, 445, 465, 514, 515, 548, 587, 631, 636, 993, 995, 1080,
  1433, 1521, 2049, 3128, 3306, 3389, 4000, 5000, 5432, 5900, 5901, 5984, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 9929, 11211, 27017, 31337
];

const DEEP_PORTS = [
  1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70,
  79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139,
  143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
  340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512,
  513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636,
  646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783,
  787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992,
  993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026,
  1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042,
  1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058,
  1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074,
  1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
  1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108,
  1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137,
  1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175,
  1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244,
  1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334,
  1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580,
  1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755,
  1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947,
  1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
  2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046,
  2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135,
  2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2201, 2232, 2251, 2260, 2301, 2302, 2323, 2366,
  2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605,
  2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2900, 2909,
  2910, 2920, 2967, 2968, 2998, 3000, 3001, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052,
  3071, 3077, 3127, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322,
  3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3481, 3500,
  3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814,
  3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3984,
  3985, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129,
  4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900,
  4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087,
  5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5400,
  5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678,
  5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900,
  5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5962, 5987,
  5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100,
  6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580,
  6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969,
  7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443,
  7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000,
  8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083,
  8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200,
  8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652,
  8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050,
  9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290,
  9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9917,
  9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024,
  10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110,
  11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13724, 13782, 13783, 14000, 14238, 14441,
  14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113,
  16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842,
  20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214,
  27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769,
  32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783,
  32784, 32785, 33354, 33899, 34571, 34572, 34573, 35000, 36963, 37008, 37103, 38037, 38292, 40193,
  40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156,
  49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49400, 49999, 50000, 50001, 50002, 50003,
  50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54321,
  54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58000, 58001, 58002, 58080, 59000,
  59001, 59623, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389
];


const COMMON_SERVICES: Record<number, string> = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 81: 'http-alt', 88: 'kerberos',
  110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 389: 'ldap',
  443: 'https', 445: 'microsoft-ds', 465: 'smtps', 514: 'syslog', 515: 'printer', 548: 'afp', 587: 'submission',
  631: 'ipp', 636: 'ldaps', 993: 'imaps', 995: 'pop3s', 1080: 'socks', 1433: 'ms-sql-s', 1521: 'oracle',
  2049: 'nfs', 3128: 'squid-http', 3306: 'mysql', 3389: 'ms-wbt-server', 4000: 'teradata-or-no-ip',
  5000: 'upnp-or-flask', 5432: 'postgresql', 5900: 'vnc', 5901: 'vnc-1', 5984: 'couchdb', 6379: 'redis',
  7001: 'weblogic', 8000: 'http-alt', 8008: 'http-alt', 8080: 'http-proxy', 8081: 'blackice-icecap',
  8443: 'https-alt', 8888: 'sun-answerbook', 9000: 'cslistener', 9200: 'elasticsearch', 9929: 'nping-echo',
  11211: 'memcached', 27017: 'mongodb', 31337: 'Elite/tcpwrapped'
};

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
  progress('discovery', 5, 'Querying passive sources in parallel...');
  log('Phase 1: Subdomain discovery');

  const subSet = new Set<string>([domain]);

  const discoveryTasks: Array<{ name: string; fn: () => Promise<string[]> }> = [];

  if (cfg.enableCT) {
    discoveryTasks.push(
      { name: 'crt.sh', fn: () => discoverSubdomainsCrtSh(domain) },
      { name: 'CertSpotter', fn: () => discoverSubdomainsCertSpotter(domain) },
      { name: 'Sonar', fn: () => discoverSubdomainsSonar(domain) },
      { name: 'BufferOver', fn: () => discoverSubdomainsBufferOver(domain) },
      { name: 'HackerTarget', fn: () => discoverSubdomainsHackerTarget(domain) }
    );
  }

  if (cfg.enableCensys && cfg.censysId && cfg.censysSecret) {
    discoveryTasks.push({
      name: 'Censys',
      fn: () => discoverSubdomainsCensys(domain, cfg.censysId!, cfg.censysSecret!)
    });
  }

  // Run discovery tasks in parallel
  if (discoveryTasks.length > 0) {
    log(`Querying ${discoveryTasks.length} passive sources in parallel...`);
    const results = await Promise.allSettled(discoveryTasks.map(t => t.fn()));
    
    results.forEach((res, idx) => {
      const taskName = discoveryTasks[idx].name;
      if (res.status === 'fulfilled') {
        log(`${taskName} returned ${res.value.length} subdomains`);
        res.value.forEach(s => subSet.add(s));
      } else {
        log(`${taskName} failed: ${res.reason}`);
      }
    });
  }

  if (cfg.enableGreyHat && cfg.greyhatKey) {
    log('Querying GreyHatWarfare (Cloud Buckets)...');
    try {
      const buckets = await discoverBucketsGreyHat(domain, cfg.greyhatKey);
      log(`GreyHatWarfare found ${buckets.length} potential buckets`);
      for (const b of buckets) {
        const bucketId = `bucket:${b}`;
        if (!assetById.has(bucketId)) {
          const bucketAsset: BucketAsset = {
            id: bucketId,
            type: 'bucket',
            value: b,
            metadata: { provider: b.includes('s3') ? 'Amazon S3' : 'Cloud' },
            riskScore: 0,
            severity: 'low',
            riskReasons: [],
            firstSeen: now,
          };
          assets.push(bucketAsset);
          assetById.set(bucketId, bucketAsset);
          rels.push({
            id: `rel:${uid()}`,
            sourceId: rootId,
            targetId: bucketId,
            type: 'discovered_bucket',
          });
        }
      }
    } catch (err) {
      log(`GreyHat error: ${err}`);
    }
  }

  let subdomains = Array.from(subSet);

  // Cap subdomains
  const maxSubdomains = Math.max(20, Math.min(300, cfg.maxSubdomains || DEFAULT_MAX_SUBS));
  if (subdomains.length > maxSubdomains) {
    log(`Capping subdomains from ${subdomains.length} to ${maxSubdomains}`);
    subdomains = subdomains.slice(0, maxSubdomains);
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

  await runWithConcurrency(subdomains, 16, async (sub, i) => {
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
  });

  log(`Discovered ${ipMap.size} unique IP addresses`);

  // ── Phase 3: HTTP/HTTPS Probing ──
  progress('http', 48, 'Probing HTTP/HTTPS...');
  log('Phase 3: HTTP/HTTPS probing');

  await runWithConcurrency(subdomains, 24, async (sub, i) => {
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
  });

  // ── Phase 4: Shodan Enrichment ──
  if (cfg.enableShodan && cfg.shodanKey) {
    progress('shodan', 62, 'Querying Shodan API...');
    log('Phase 4: Shodan enrichment');

    const shodanLimit = Math.max(0, Math.min(120, cfg.shodanLimit ?? DEFAULT_SHODAN_LIMIT));
    const ips = Array.from(ipMap.keys()).slice(0, shodanLimit);
    if (ipMap.size > ips.length) {
      log(`Shodan speed cap: enriching first ${ips.length} of ${ipMap.size} IPs`);
    }
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

      await delay(250);
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
      : cfg.deepScan
        ? DEEP_PORTS
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
            timeoutMs: 2000,
            concurrency: 100,
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
                  product: COMMON_SERVICES[port] || 'unknown',
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
  const byType = { domains: 0, subdomains: 0, ips: 0, services: 0, buckets: 0 };
  let totalRisk = 0;
  let maxRisk = 0;
  const bySev = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const a of assets) {
    if (a.type === 'domain') byType.domains++;
    else if (a.type === 'subdomain') byType.subdomains++;
    else if (a.type === 'ip') byType.ips++;
    else if (a.type === 'service') byType.services++;
    else if (a.type === 'bucket') byType.buckets++;

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
