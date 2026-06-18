# EDAM

**External Discovery and Asset Mapper**

EDAM is a bachelor project focused on external attack surface mapping. It is a full-stack web application that discovers internet-facing assets related to a target domain, enriches them with external intelligence, applies heuristic risk scoring, and presents the results through dashboards, tables, historical comparison, exports, and an interactive graph.

## Quick Start

On Windows, run the project from the repository root by double-clicking:

```text
start-edam.bat
```

The launcher checks that Node.js/npm are available, prints the installed versions, installs dependencies when `node_modules` is missing, repairs common Windows optional-dependency issues, and starts both the frontend and backend.

Open the app at:

- frontend: `http://127.0.0.1:5173`
- backend health check: `http://127.0.0.1:8787/api/health`

From Git Bash, WSL, Linux, or macOS, use:

```bash
./start-edam.sh
```

Manual startup is also supported:

```bash
npm install
npm start
```

## Abstract

Organizations often expose more external infrastructure than they intentionally track. Public-facing domains, subdomains, IP addresses, services, and cloud storage assets can accumulate over time through infrastructure growth, misconfiguration, shadow IT, and legacy systems. This creates visibility gaps that directly affect attack surface management.

EDAM was built to address that problem by combining passive OSINT discovery, DNS resolution, HTTP/HTTPS probing, external host enrichment, optional active TCP validation, and rule-based risk scoring into a single interface. The goal is not vulnerability exploitation or CVE-level assessment. The goal is to help a researcher or analyst identify what is exposed, how those assets relate to each other, and which assets deserve closer investigation first.

## Problem Statement

Many organizations do not maintain a complete and continuously updated inventory of their internet-facing assets. External services may appear through:

- forgotten subdomains
- cloud buckets and storage endpoints
- legacy services
- development or testing environments
- multiple services exposed on a single host
- assets visible in third-party intelligence sources but not in internal inventories

Traditional security assessment workflows often require switching between many separate tools and data sources. This makes asset mapping fragmented, time-consuming, and harder to interpret as a whole.

## Project Objectives

The main objectives of EDAM are:

- discover external assets related to a target domain
- combine multiple passive OSINT and enrichment sources into one workflow
- validate infrastructure through DNS and network probing
- represent discovered assets as a relationship graph
- estimate relative risk through a transparent heuristic model
- provide a usable interface for exploration, comparison, and reporting

## Methodology

EDAM follows a multi-phase pipeline:

1. Passive subdomain discovery from multiple OSINT sources
2. Optional additional discovery through Censys
3. Optional cloud bucket discovery through GreyHatWarfare
4. DNS resolution of discovered names using Google DNS-over-HTTPS
5. HTTP and HTTPS reachability probing
6. Optional Shodan enrichment for host and service metadata
7. Optional active TCP port verification using a local backend
8. Heuristic risk scoring of discovered assets
9. Visualization, historical comparison, and export

This approach intentionally combines passive and active methods:

- passive methods maximize breadth without directly touching the target infrastructure heavily
- active methods validate live exposure where passive intelligence may be incomplete

## Tool Selection Justification

The project was initially framed around comparing major OSINT and ASM-related tools. The final implementation uses a practical subset chosen for complementary coverage.

### Shodan

Shodan is included for host and service enrichment. It is useful for:

- open port visibility
- basic service and banner information
- organization and ISP metadata
- public host context

Shodan is valuable for exposed-service context, but its coverage is not universal. EDAM therefore treats it as enrichment rather than a single source of truth.

### Censys

Censys is included to improve passive discovery, especially through certificate-related host visibility. It complements Shodan by contributing a different view of internet-exposed assets and certificate-linked names.

### GreyHatWarfare

GreyHatWarfare was included to extend the project beyond classical host discovery into cloud asset exposure and possible shadow IT. This supports one of the more current ASM concerns: public buckets and storage-related exposure.


## System Overview

EDAM is implemented as a full-stack application.

### Frontend

- React 18
- TypeScript
- Vite
- Tailwind CSS
- Cytoscape.js
- Lucide React

The frontend controls the scan workflow, stores local history, renders dashboards and graph views, and exports reports.

### Backend

- Node.js
- Express
- native `net.Socket`

The backend exists specifically to perform active TCP port checks that are not possible directly from the browser.

### Development Proxy

The Vite development server proxies `/api` requests to the Express backend at `http://127.0.0.1:8787`. Both development servers bind to localhost by default.

## Tools and APIs Used

This section lists the project stack and every external source or API currently used by EDAM.

### Frontend Technologies

- React 18
- TypeScript
- Vite
- Tailwind CSS
- Cytoscape.js
- Lucide React

### Backend Technologies

- Node.js
- Express
- native `net.Socket` for TCP connection checks
- `cors` middleware

### External APIs and Data Sources

- `crt.sh`
  Purpose: certificate transparency subdomain discovery
- `CertSpotter`
  Purpose: certificate-based hostname discovery
- `Sonar / Omnisint`
  Purpose: passive subdomain discovery
- `BufferOver`
  Purpose: passive DNS-style hostname discovery
- `HackerTarget`
  Purpose: host search and subdomain discovery
- `Google DNS-over-HTTPS`
  Purpose: resolve `A`, `AAAA`, and `CNAME` records
- `Shodan API`
  Purpose: host enrichment, port visibility, service metadata, org and ISP context
- `Censys Search API`
  Purpose: additional passive discovery from certificate-linked host data
- `GreyHatWarfare API`
  Purpose: possible exposed cloud bucket discovery

### Internal Local API

- `GET /api/health`
  Purpose: backend health check
- `POST /api/port-scan`
  Purpose: active TCP port validation for discovered IP addresses

### Browser and Local Platform Features

- browser `fetch`
- browser `localStorage`
- Vite proxying for frontend-to-backend communication

## Implemented Features

- Passive subdomain discovery from `crt.sh`, `CertSpotter`, `Sonar`, `BufferOver`, and `HackerTarget`
- Optional additional discovery through `Censys`
- Optional cloud bucket discovery through `GreyHatWarfare`
- DNS resolution using Google DNS-over-HTTPS
- HTTP/HTTPS probing
- Shodan host and service enrichment
- Local active TCP port checking
- Heuristic risk scoring
- Interactive Cytoscape-based asset graph with two layouts (hierarchy and IP map)
- Risk table with filtering and sorting
- Local scan history with scan comparison
- CSV, JSON, and Markdown export
- Automated unit test suite for the scoring, graph, diffing, and export logic

## Asset and Relationship Model

EDAM represents the attack surface as a graph.

### Asset Types

- `domain`
- `subdomain`
- `ip`
- `service`
- `bucket`

### Relationship Types

- `parent_of`
- `resolves_to`
- `exposes`
- `discovered_bucket`

This model allows the project to show how a root domain expands into child names, infrastructure endpoints, and exposed services.

## Discovery and Enrichment Sources

### Passive Subdomain Discovery

The passive discovery stage queries these sources in parallel:

- `crt.sh`
- `CertSpotter`
- `Sonar`
- `BufferOver`
- `HackerTarget`

Results are normalized, deduplicated, and capped before further processing.

### DNS Resolution

EDAM resolves these record types:

- `A`
- `AAAA`
- `CNAME`

Resolution is performed through Google DNS-over-HTTPS.

### HTTP and HTTPS Probing

Each resolved domain or subdomain is checked for HTTP and HTTPS availability. This gives basic visibility into whether a web service appears reachable.

### Shodan Enrichment

When a valid API key is configured, Shodan contributes:

- observed ports
- protocol
- product
- version
- short banner snippet
- organization
- ISP
- country and city
- operating system when available

### Censys Discovery

When configured, Censys contributes additional candidate hostnames related to the target domain by querying certificate-related host data.

### GreyHatWarfare Bucket Discovery

When configured, GreyHatWarfare is used to search for possible cloud buckets associated with the target domain.

### Active Port Verification

The local backend can test:

- a curated list of important ports
- or a deeper top-ports list when deep scanning is enabled

This is useful when passive services are missing or incomplete.

## Complete Scan Pipeline

To make the workflow explicit, a full scan can involve all of the following tools and APIs:

1. `crt.sh`
2. `CertSpotter`
3. `Sonar`
4. `BufferOver`
5. `HackerTarget`
6. `Censys`
7. `GreyHatWarfare`
8. `Google DNS-over-HTTPS`
9. browser HTTP/HTTPS probing
10. `Shodan`
11. local backend `POST /api/port-scan`
12. internal heuristic risk engine
13. Cytoscape graph rendering
14. local history and export utilities

## Risk Assessment Model

EDAM uses a rule-based heuristic risk engine. It does not use CVEs, exploit validation, or authenticated scanning.

The model was designed for prioritization rather than definitive vulnerability claims.

### Risk Signals

Risk is increased by signals such as:

- subdomain names containing indicators like `dev`, `test`, `admin`, `vpn`, `internal`, `jenkins`, `phpmyadmin`, or `legacy`
- non-production and access-control naming patterns such as `uat`, `qa`, `demo`, `beta`, `preview`, `login`, `sso`, `auth`, and `portal`
- exposed DevOps and monitoring names such as `grafana`, `kibana`, `prometheus`, `nexus`, `artifactory`, and `sonar`
- HTTP availability without HTTPS
- externally reachable web services
- CNAME chains that may indicate third-party/cloud ownership or dangling DNS review needs
- multiple services exposed on the same IP
- high-risk service ports such as `23`, `445`, `1433`, `3306`, `3389`, `5432`, `6379`, `9200`, `11211`, and `27017`
- grouped IP-level exposure for database/cache ports, remote administration ports, and Windows sharing/RPC ports
- alternate management web ports such as `8080`, `8081`, `8443`, `8888`, `9000`, and `9090`
- sensitive service fingerprints from banners or product metadata
- exposed cloud buckets

### Severity Thresholds

- `low`: score `< 6`
- `medium`: score `6-11`
- `high`: score `12-19`
- `critical`: score `20+`

The root domain receives an aggregate score based on the highest-risk discovered child assets.

## Visualization and User Interface

### Dashboard

The dashboard provides:

- presentation-friendly scan summary
- total asset counts
- per-type counts
- finding category breakdown
- average and maximum risk
- risk distribution
- discovered services
- highest-risk assets
- scan error visibility

### Asset Graph

The graph view is designed as an analyst-facing relationship map and includes:

- focused layout controls with a hierarchy map and an IP map
- risk-weighted node sizing
- severity-colored node borders
- relation-colored edges
- type-based node shapes
- filter controls
- focus mode for selected neighborhoods
- a persistent analysis panel
- asset search and quick focus
- exposure paths from root domain to exposed services or buckets
- shared-infrastructure hub detection for IPs connected to multiple names or services
- double-border hub styling for high-connectivity nodes
- mapping summary overlay for presentation-friendly explanation
- faster wheel zoom with dedicated zoom-in, zoom-out, and fit controls

### Risk Table

The risk table offers a triage-oriented textual view of discovered assets and supports filtering and sorting. It includes actionable counts, exposed endpoint counts, high-risk totals, finding categories, exposure summaries, primary evidence, and recommended follow-up checks.

Recommendations are generated from the same evidence used for scoring. Examples include restricting exposed databases to private networks, requiring VPN/MFA for remote administration, disabling Telnet, blocking Windows file sharing from the internet, reviewing public bucket policy, enforcing HTTPS, and validating CNAME ownership.

The table is horizontally scrollable so the evidence and recommendation columns remain readable instead of being compressed on smaller screens.

### Scan Modes

EDAM includes three scan presets:

- `Fast Demo`: quick passive mapping for presentation and first-look scans
- `Balanced`: default coverage with controlled enrichment time
- `Deep Review`: broader discovery, enrichment, and deep active port validation

The presets adjust subdomain caps, Shodan enrichment limits, and optional active validation defaults while still allowing manual configuration.

### History and Comparison

Scan history is stored locally in the browser and can be used to compare:

- newly discovered assets
- removed assets
- changed risk scores

### Export

EDAM can export reports in:

- CSV
- JSON
- Markdown

CSV and Markdown exports include risk reasons and recommended checks. Markdown reports include bucket counts and relationship counts in the summary.

## Case Study Use

The project is suitable for case-study style evaluation against a real organization or public test target, as long as the user is authorized to assess that target.

A typical case study can examine:

- number of discovered external assets
- discovered services and infrastructure relationships
- potentially risky naming patterns
- exposed buckets or storage endpoints
- overall heuristic risk distribution
- changes across multiple scans over time

For demonstrations, use an owned lab domain, an explicitly authorized target, or a public test target that clearly allows scanning. Do not use third-party organizations as demo targets unless you have permission.

## Limitations

EDAM has several intentional limitations:

- it is not a vulnerability scanner
- results depend on third-party source coverage and availability
- browser-side passive discovery relies on public endpoints and some CORS proxy usage
- Shodan, Censys, and GreyHatWarfare require valid API keys for full functionality
- HTTP probing only checks basic reachability
- active TCP checks only validate connect success, not protocol correctness or exploitability
- heuristic scores are useful for triage, but not a substitute for manual analysis
- large result sets are capped for performance and UI clarity

## Future Work

Possible future improvements include:

- broader ASM coverage for cloud-native assets
- more accurate shadow IT detection
- improved source validation and connector health monitoring
- richer risk models with weighted confidence scoring
- more advanced visualization modes such as heat maps or grouped infrastructure views
- automated screenshotting or report snapshots for web assets
- integration of additional passive DNS or certificate sources
- more formal case-study benchmarking across multiple targets

## Repository Structure

```text
.
├── server/
│   ├── presentation.mjs
│   └── server.mjs
├── start-presentation.sh
├── start-edam.bat
├── start-edam.sh
├── src/
│   ├── api/
│   │   ├── connectors.ts
│   │   └── orchestrator.ts
│   ├── engine/
│   │   ├── changeDetection.ts
│   │   ├── exportUtils.ts
│   │   ├── graphBuilder.ts
│   │   └── riskEngine.ts
│   ├── types/
│   │   └── index.ts
│   ├── App.tsx
│   ├── index.css
│   └── main.tsx
├── test/
│   ├── changeDetection.test.mjs
│   ├── connectors.test.mjs
│   ├── exportUtils.test.mjs
│   ├── graphBuilder.test.mjs
│   └── riskEngine.test.mjs
├── docs/
│   ├── ARCHITECTURE.md
│   └── USER_GUIDE.md
├── test-api-connectors.mjs
├── CONTRIBUTING.md
├── .env.local.example
├── LICENSE
├── package.json
└── vite.config.ts
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — component, sequence, and deployment diagrams; data model; design decisions
- [User Guide](docs/USER_GUIDE.md) — step-by-step walkthrough of every view
- [Contributing](CONTRIBUTING.md) — setup, project layout, conventions, and checks
- [License](LICENSE) — MIT

## Setup and Running

### Requirements

- Node.js 20+ recommended
- npm 9+ recommended

Check local tool versions with:

```bash
npm run version:check
```

This prints the active Node.js, npm, Vite, and TypeScript versions used by the local environment.

### Start with the Windows launcher

Double-click this file from the project root:

```text
start-edam.bat
```

The launcher:

- checks that npm is available
- prints Node.js and npm versions
- installs dependencies when `node_modules` is missing
- repairs common Windows optional dependency issues
- starts both the Vite frontend and Express backend

After it starts, open:

- app: `http://127.0.0.1:5173`
- backend health check: `http://127.0.0.1:8787/api/health`

Keep the terminal window open while using the application.

### Start from a shell

```bash
./start-edam.sh
```

This is the same workflow for Git Bash, WSL, Linux, and macOS.

### Manual startup

```bash
npm install
npm start
```

`npm start` runs the frontend and backend together through `npm run dev`.

### Optional API Keys

Create a `.env` file in the project root when you want Shodan, Censys, or GreyHatWarfare enrichment:

```env
VITE_SHODAN_API_KEY=
VITE_CENSYS_API_ID=
VITE_CENSYS_API_SECRET=
VITE_GREYHAT_API_KEY=
```

If a key is missing, the related enrichment phase is skipped.

### How to Use

1. Start EDAM and open `http://127.0.0.1:5173`.
2. Enter a domain you are authorized to assess.
3. Choose a scan mode:
   - `Fast Demo` for quick passive mapping
   - `Balanced` for the default workflow
   - `Deep Review` for broader mapping and active port validation
4. Enable or disable optional sources such as Shodan, Censys, GreyHatWarfare, and active port checking.
5. Click `Start Scan` and follow the live progress log.
6. Use `Dashboard` for summary metrics, `Asset Graph` for relationships, `Risk Table` for triage, `History` for comparison, and `Export` for CSV/JSON/Markdown output.

### Quality Checks

Run unit tests:

```bash
npm test
```

Type-check the project:

```bash
npx tsc --noEmit
```

Build production assets:

```bash
npm run build
```

Run the full local verification sequence:

```bash
npm run verify
```

The pure logic in `src/engine/` (risk scoring, graph building, scan diffing, and export) is covered by unit tests under `test/`, run with Node.js's built-in test runner.

### Optional Static Server

For a built static copy, run:

```bash
npm run build
npm run presentation
```

This serves the existing `dist/` build and the same local API endpoints at `http://127.0.0.1:5173`.

Preview through Vite is also available with `npm run preview`.

## Troubleshooting

| Symptom | Likely cause and fix |
|---------|----------------------|
| Passive discovery returns few/no subdomains | Public OSINT sources or CORS proxies are rate-limited or temporarily down. Retry, or run a different target; sources fail soft and the scan still completes. |
| "Shodan/Censys/GreyHatWarfare skipped" in the log | No API key configured. Add the key(s) to `.env` (see `.env.local.example`). All keys are optional. |
| Active port check fails / "Backend unreachable" | The local backend isn't running. Use `npm start` (starts both), and confirm `http://127.0.0.1:8787/api/health` returns `{ "ok": true }`. |
| HTTP probe shows `false` for sites that load in a browser | Probing uses `no-cors` HEAD requests and only confirms reachability; some hosts block it. This is expected and noted in the limitations. |
| `npm run build` fails with an `@rolldown/binding-*` or native binding "Cannot find module" error | Platform-specific optional dependency mismatch (e.g. copying `node_modules` between OSes). Delete `node_modules` and `package-lock.json`, then `npm install` on the target machine. |
| Presentation mode shows "Missing dist/index.html" | You must run `npm run build` once before using presentation mode. |

## Local Backend API

### `GET /api/health`

Returns a basic health response for the local backend.

### `POST /api/port-scan`

Example request:

```json
{
  "ips": ["45.33.32.156"],
  "ports": [22, 80, 443],
  "timeoutMs": 2000,
  "concurrency": 100
}
```

Example response:

```json
{
  "ips": 1,
  "ports": 3,
  "timeoutMs": 2000,
  "concurrency": 100,
  "openByIp": {
    "45.33.32.156": [22, 80]
  }
}
```

### Status and error codes

| Endpoint | Status | Meaning |
|----------|--------|---------|
| `GET /api/health` | `200` | Backend is up — `{ "ok": true }` |
| `POST /api/port-scan` | `200` | Scan completed; body contains `openByIp` |
| `POST /api/port-scan` | `400` | Missing/invalid input — `{ "error": "ips and ports are required" }` |
| unsupported method or path | `405` | Method not allowed (presentation server) |

Request fields are validated and clamped on the server: IPs must be valid IPv4/IPv6
literals (max 200 per request), ports must be `1–65535`, `timeoutMs` is clamped to
`150–5000`, and `concurrency` to `1–400`.

## Ethics and Legal Use

EDAM should only be used on systems, domains, and organizations for which the user has authorization.

The project is intended for research, learning, defensive asset inventory, and attack surface analysis. It must not be used for unauthorized reconnaissance or intrusive security testing.
