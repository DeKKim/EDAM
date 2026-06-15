# EDAM — Architecture

This document describes the architecture of EDAM (External Discovery and Asset
Mapper): its components, the scan pipeline, the data model, and how it is
deployed. Diagrams use [Mermaid](https://mermaid.js.org/) and render directly on
GitHub and in most Markdown viewers.

## 1. Technology stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend UI | React 18 + TypeScript | Views, state, workflow orchestration |
| Build / dev | Vite 6 | Dev server, HMR, production bundle |
| Styling | Tailwind CSS 4 | Utility-first styling |
| Visualization | Cytoscape.js | Interactive node-link asset graph |
| Icons | lucide-react | UI iconography |
| Backend | Node.js + Express | Active TCP port checks (`net.Socket`) |
| Presentation server | Node.js `http` (zero deps) | Serves the built app without `npm install` |
| Tests | Node.js built-in test runner | Unit tests for engine logic |

## 2. Component view

```mermaid
graph TD
  subgraph Browser["Browser (React + TypeScript)"]
    UI["App.tsx — views & state\n(Scan, Dashboard, Graph, Risk Table, History, Export)"]
    ORCH["api/orchestrator.ts\nscan pipeline coordinator"]
    CONN["api/connectors.ts\nexternal API connectors"]
    RISK["engine/riskEngine.ts\nheuristic scoring"]
    GRAPH["engine/graphBuilder.ts\nCytoscape graph model"]
    CHG["engine/changeDetection.ts\nscan diffing"]
    EXP["engine/exportUtils.ts\nCSV / JSON / Markdown + history"]
  end

  subgraph Backend["Local backend (Node + Express)"]
    API["/api/health\n/api/port-scan"]
    SOCK["net.Socket TCP checks"]
  end

  subgraph External["External data sources"]
    CT["crt.sh / CertSpotter / Sonar / BufferOver / HackerTarget"]
    DNS["Google DNS-over-HTTPS"]
    SHODAN["Shodan API"]
    CENSYS["Censys API"]
    GHW["GreyHatWarfare API"]
  end

  UI --> ORCH
  ORCH --> CONN
  ORCH --> RISK
  UI --> GRAPH
  UI --> CHG
  UI --> EXP
  CONN --> CT
  CONN --> DNS
  CONN --> SHODAN
  CONN --> CENSYS
  CONN --> GHW
  ORCH -->|POST /api/port-scan| API
  API --> SOCK
```

The browser does all discovery, scoring and rendering. The backend exists for a
single reason: browsers cannot open raw TCP sockets, so active port validation
is delegated to a small local service.

## 3. Scan pipeline (sequence)

```mermaid
sequenceDiagram
  actor User
  participant UI as App (UI)
  participant O as orchestrator
  participant C as connectors
  participant B as backend
  participant R as riskEngine

  User->>UI: enter domain, pick scan mode, start
  UI->>O: runScan(config)
  O->>C: passive discovery (crt.sh, CertSpotter, Sonar, BufferOver, HackerTarget) [parallel]
  C-->>O: subdomains
  opt Censys key configured
    O->>C: Censys discovery
  end
  opt GreyHatWarfare key configured
    O->>C: bucket discovery
  end
  O->>C: DNS resolution (A/AAAA/CNAME) [concurrency 16]
  C-->>O: IP addresses, CNAMEs
  O->>C: HTTP/HTTPS probing [concurrency 24]
  opt Shodan key configured
    O->>C: Shodan enrichment (ports, banners, org)
  end
  opt active port scan enabled
    O->>B: POST /api/port-scan {ips, ports}
    B-->>O: openByIp
  end
  O->>R: scoreAsset() for every asset
  R-->>O: score, severity, reasons
  O-->>UI: ScanResult (assets, relationships, stats, logs)
  UI->>UI: build graph, render dashboard, save to history
```

## 4. Data model

Assets and relationships form a directed graph.

```mermaid
graph LR
  D[domain] -->|parent_of| S[subdomain]
  D -->|discovered_bucket| K[bucket]
  S -->|resolves_to| I[ip]
  I -->|exposes| SV[service]
```

- **Asset types:** `domain`, `subdomain`, `ip`, `service`, `bucket`
- **Relationship types:** `parent_of`, `resolves_to`, `exposes`, `discovered_bucket`

Type definitions live in [`src/types/index.ts`](../src/types/index.ts).

## 5. Deployment views

### Development mode (`npm start`)

```mermaid
graph LR
  Dev[Developer] -->|http://localhost:5173| Vite[Vite dev server]
  Vite -->|/api proxy| Express[Express backend :8787]
  Vite -->|HMR| Browser
```

Vite serves the frontend with hot-module reload and proxies `/api/*` to the
Express backend on port 8787 (configured in `vite.config.ts`).

### Presentation mode (`npm run presentation`)

```mermaid
graph LR
  User[Presenter] -->|http://localhost:5173| Pres[presentation.mjs\nzero-dependency Node server]
  Pres -->|serves| Dist[dist/ static build]
  Pres -->|/api/port-scan, /api/health| Net[net.Socket]
```

The presentation server serves the pre-built `dist/` folder and implements the
same two API endpoints, so the project runs on another machine with only
Node.js installed — no `npm install` required. Build `dist/` first with
`npm run build`.

## 6. Key design decisions

- **Browser-first architecture.** Maximizing what runs client-side keeps the
  backend tiny and the app portable. The backend's only job is the one thing the
  browser cannot do (raw TCP).
- **Pluggable connectors.** Each source is an independent function returning a
  normalized list; failures are isolated with `Promise.allSettled`, so one dead
  source never fails a scan.
- **Transparent, rule-based scoring.** Every risk score traces back to
  human-readable reasons and a recommended check (see `riskEngine.ts`), rather
  than an opaque model — important for an analyst-facing, explainable tool.
- **Two graph layouts for two questions.** The hierarchy map shows how a domain
  expands into names, IPs and services; the IP map anchors names and services
  around their host IP to expose shared infrastructure.
- **Separation of pure logic from UI.** Scoring, diffing, and graph building are
  framework-agnostic modules under `src/engine/`, which makes them unit-testable
  in isolation (see `test/`).
