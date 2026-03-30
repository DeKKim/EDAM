import { useState, useEffect, useRef, useCallback } from 'react';
import cytoscape from 'cytoscape';
import {
  Shield, Search, LayoutDashboard, Network, Table2, History,
  Download, ChevronRight, AlertTriangle, Globe, Server, Wifi,
  Play, Settings, Trash2, Eye, ArrowUpDown, X, RefreshCw,
  ChevronDown, ChevronUp, GitCompareArrows,
} from 'lucide-react';
import type { ScanResult, Asset, Severity, AssetType, CompareResult } from './types';
import { runScan } from './api/orchestrator';
import { buildGraph, severityColor, typeShape } from './engine/graphBuilder';
import { compareScans } from './engine/changeDetection';
import {
  saveToHistory, loadHistory, deleteFromHistory,
  exportCsv, exportJson, exportMarkdown, downloadFile,
} from './engine/exportUtils';

/* ── Helpers ── */
type View = 'scan' | 'dashboard' | 'graph' | 'risk' | 'history' | 'export';

// Use environment variable for the API key
const SHODAN_API_KEY = import.meta.env.VITE_SHODAN_API_KEY || '';

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
};

function Badge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-bold text-white ${SEV_COLORS[severity]}`}>
      {severity.toUpperCase()}
    </span>
  );
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
  const [enableActivePortScan, setEnableActivePortScan] = useState(false);
  useEffect(() => { setHistory(loadHistory()); }, []);

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
        enableCT,
        enableShodan: enableShodan && !!SHODAN_API_KEY,
        enableActivePortScan,
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
  }, [domain, enableCT, enableShodan, enableActivePortScan]);

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
            enableActivePortScan={enableActivePortScan} setEnableActivePortScan={setEnableActivePortScan}
            shodanStatus={SHODAN_API_KEY ? 'valid' : 'invalid'}
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
  enableActivePortScan: boolean; setEnableActivePortScan: (v: boolean) => void;
  shodanStatus: 'checking' | 'valid' | 'invalid';
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

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={props.enableCT} onChange={e => props.setEnableCT(e.target.checked)} className="accent-cyan-500" />
            Certificate Transparency (crt.sh)
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={props.enableShodan} onChange={e => props.setEnableShodan(e.target.checked)} className="accent-cyan-500" />
            Shodan Enrichment
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
        </div>

        {props.enableShodan && (
          <div className="text-sm">
            <p className="text-slate-400 mb-1">Shodan API Key</p>
            {props.shodanStatus === 'valid' && (
              <p className="text-emerald-400 text-xs font-semibold">Shodan API key: Valid</p>
            )}
            {props.shodanStatus === 'checking' && (
              <p className="text-slate-400 text-xs font-semibold">Shodan API key: Checking…</p>
            )}
            {props.shodanStatus === 'invalid' && (
              <p className="text-red-400 text-xs font-semibold">Shodan API key: Invalid / Missing</p>
            )}
          </div>
        )}

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

      {/* Info box */}
      <div className="mt-6 bg-slate-900/50 border border-slate-800 rounded-lg p-4 text-sm text-slate-400">
        <h3 className="font-semibold text-slate-300 mb-2">How it works:</h3>
        <ol className="list-decimal list-inside space-y-1">
          <li><strong>Subdomain Discovery</strong> — Queries Certificate Transparency logs (crt.sh) and HackerTarget</li>
          <li><strong>DNS Resolution</strong> — Resolves A, AAAA, CNAME records via Google DNS-over-HTTPS</li>
          <li><strong>HTTP/HTTPS Probing</strong> — Checks web server availability</li>
          <li><strong>Shodan Enrichment</strong> — Discovers open ports and services (optional, needs API key)</li>
          <li><strong>Risk Scoring</strong> — Heuristic analysis based on exposed services, naming patterns, and configuration</li>
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
  const cards = [
    { label: 'Total Assets', value: s.totalAssets, color: 'text-cyan-400' },
    { label: 'Subdomains', value: s.subdomains, color: 'text-blue-400' },
    { label: 'IP Addresses', value: s.ips, color: 'text-purple-400' },
    { label: 'Services', value: s.services, color: 'text-teal-400' },
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

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
        {cards.map(c => (
          <div key={c.label} className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <p className="text-xs text-slate-500 uppercase tracking-wider">{c.label}</p>
            <p className={`text-2xl font-bold mt-1 ${c.color}`}>{c.value}</p>
          </div>
        ))}
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
  const [selected, setSelected] = useState<Asset | null>(null);
  const [typeFilters, setTypeFilters] = useState<Record<AssetType, boolean>>({
    domain: true, subdomain: true, ip: true, service: true,
  });
  const [sevFilters, setSevFilters] = useState<Record<Severity, boolean>>({
    critical: true, high: true, medium: true, low: true,
  });
  const [layout, setLayout] = useState('concentric');

  const toggleType = (t: AssetType) => setTypeFilters(p => ({ ...p, [t]: !p[t] }));
  const toggleSev = (s: Severity) => setSevFilters(p => ({ ...p, [s]: !p[s] }));

  useEffect(() => {
    if (!containerRef.current) return;

    // Filter assets
    const filteredAssets = scan.assets.filter(a => typeFilters[a.type] && sevFilters[a.severity]);
    const ids = new Set(filteredAssets.map(a => a.id));
    const filteredRels = scan.relationships.filter(r => ids.has(r.sourceId) && ids.has(r.targetId));
    const graph = buildGraph(filteredAssets, filteredRels);

    if (cyRef.current) cyRef.current.destroy();

    const cy = cytoscape({
      container: containerRef.current,
      elements: [
        ...graph.nodes.map(n => ({ group: 'nodes' as const, data: n.data })),
        ...graph.edges.map(e => ({ group: 'edges' as const, data: e.data })),
      ],
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '10px',
            color: '#94a3b8',
            'text-margin-y': 6,
            width: 30,
            height: 30,
            'border-width': 2,
            'border-color': '#475569',
            'background-color': '#334155',
          },
        },
        ...(['critical', 'high', 'medium', 'low'] as Severity[]).map(sev => ({
          selector: `node[severity="${sev}"]`,
          style: {
            'background-color': severityColor(sev),
            'border-color': severityColor(sev),
          } as cytoscape.Css.Node,
        })),
        ...(['domain', 'subdomain', 'ip', 'service'] as AssetType[]).map(t => ({
          selector: `node[type="${t}"]`,
          style: { shape: typeShape(t) } as cytoscape.Css.Node,
        })),
        {
          selector: 'node[type="domain"]',
          style: { width: 50, height: 50, 'font-size': '12px', 'font-weight': 'bold' } as cytoscape.Css.Node,
        },
        {
          selector: 'edge',
          style: {
            width: 1.5,
            'line-color': '#475569',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': '8px',
            color: '#64748b',
            'text-rotation': 'autorotate',
          },
        },
        {
          selector: ':selected',
          style: {
            'border-width': 3,
            'border-color': '#06b6d4',
            'background-color': '#0891b2',
          } as cytoscape.Css.Node,
        },
      ],
      layout: {
        name: layout,
        ...(layout === 'cose'
          ? {
              nodeRepulsion: () => 8000,
              idealEdgeLength: () => 80,
              animate: false,
            }
          : {}),
        ...(layout === 'breadthfirst'
          ? {
              directed: true,
              spacingFactor: 1.2,
              roots: scan.assets.filter(a => a.type === 'domain').map(a => a.id),
            }
          : {}),
        ...(layout === 'concentric'
          ? {
              concentric: (node: cytoscape.NodeSingular) => {
                const type = node.data('type') as AssetType;
                if (type === 'domain') return 3;
                if (type === 'subdomain') return 2;
                if (type === 'ip') return 1;
                return 0;
              },
              levelWidth: () => 1,
              minNodeSpacing: 40,
            }
          : {}),
      } as cytoscape.LayoutOptions,
      minZoom: 0.2,
      maxZoom: 4,
    });

    cy.on('tap', 'node', (evt) => {
      const d = evt.target.data();
      const asset = scan.assets.find(a => a.id === d.id);
      if (asset) setSelected(asset);
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) setSelected(null);
    });

    cyRef.current = cy;

    return () => { cy.destroy(); };
  }, [scan, typeFilters, sevFilters, layout]);

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="p-3 bg-slate-900 border-b border-slate-800 flex flex-wrap items-center gap-4 text-sm">
        <span className="text-slate-400 font-medium">Filter:</span>
        {(['domain', 'subdomain', 'ip', 'service'] as AssetType[]).map(t => (
          <label key={t} className="flex items-center gap-1 cursor-pointer">
            <input type="checkbox" checked={typeFilters[t]} onChange={() => toggleType(t)} className="accent-cyan-500" />
            <span style={{ textTransform: 'capitalize' }}>{t}</span>
          </label>
        ))}
        <span className="text-slate-700">|</span>
        {(['critical', 'high', 'medium', 'low'] as Severity[]).map(s => (
          <label key={s} className="flex items-center gap-1 cursor-pointer">
            <input type="checkbox" checked={sevFilters[s]} onChange={() => toggleSev(s)} className="accent-cyan-500" />
            <span className={SEV_TEXT[s]} style={{ textTransform: 'capitalize' }}>{s}</span>
          </label>
        ))}
        <span className="text-slate-700">|</span>
        <select
          value={layout}
          onChange={e => setLayout(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs"
        >
          <option value="cose">Force-directed</option>
          <option value="breadthfirst">Hierarchical</option>
          <option value="concentric">Concentric</option>
          <option value="circle">Circle</option>
        </select>
        <button
          onClick={() => cyRef.current?.fit(undefined, 30)}
          className="px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs hover:bg-slate-700 cursor-pointer"
        >
          Fit
        </button>
      </div>

      <div className="flex flex-1 min-h-0">
        {/* Graph canvas */}
        <div ref={containerRef} className="flex-1 bg-slate-950" />

        {/* Detail panel */}
        {selected && (
          <div className="w-72 bg-slate-900 border-l border-slate-800 p-4 overflow-y-auto">
            <div className="flex justify-between items-start mb-3">
              <h3 className="font-semibold truncate">{selected.value}</h3>
              <button onClick={() => setSelected(null)} className="text-slate-500 hover:text-white cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Type:</span>
                <span style={{ textTransform: 'capitalize' }}>{selected.type}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Risk:</span>
                <span className={`font-bold ${SEV_TEXT[selected.severity]}`}>{selected.riskScore}</span>
                <Badge severity={selected.severity} />
              </div>

              {selected.riskReasons.length > 0 && (
                <div>
                  <p className="text-slate-400 mb-1">Risk Reasons:</p>
                  <ul className="space-y-1">
                    {selected.riskReasons.map((r, i) => (
                      <li key={i} className="flex items-start gap-1 text-xs text-slate-300">
                        <AlertTriangle className="w-3 h-3 text-amber-400 mt-0.5 flex-shrink-0" />
                        {r}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {Object.keys(selected.metadata).length > 0 && (
                <div>
                  <p className="text-slate-400 mb-1">Metadata:</p>
                  <div className="bg-slate-950 rounded p-2 text-xs font-mono space-y-0.5">
                    {Object.entries(selected.metadata).map(([k, v]) => (
                      <div key={k}>
                        <span className="text-cyan-400">{k}:</span>{' '}
                        <span className="text-slate-300">{Array.isArray(v) ? v.join(', ') : String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="px-3 py-2 bg-slate-900 border-t border-slate-800 flex items-center gap-4 text-xs text-slate-500">
        <span className="font-medium">Legend:</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 bg-green-500 rounded-full inline-block" /> Low</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 bg-yellow-500 rounded-full inline-block" /> Medium</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 bg-orange-500 rounded-full inline-block" /> High</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 bg-red-500 rounded-full inline-block" /> Critical</span>
        <span className="text-slate-700">|</span>
        <span>◇ Domain</span>
        <span>▢ Subdomain</span>
        <span>○ IP</span>
        <span>⬡ Service</span>
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

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6 flex items-center gap-2">
        <Table2 className="w-6 h-6 text-cyan-400" /> Risk Assessment Table
      </h1>

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

      <p className="text-sm text-slate-500 mb-3">{filtered.length} of {scan.assets.length} assets</p>

      {/* Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
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
      </tr>
      {expanded && (
        <tr className="bg-slate-900/50">
          <td />
          <td colSpan={4} className="px-3 py-3">
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
