# EDAM — Presentation Brief

A complete, fact-grounded description of the project, organized so it can be
turned directly into presentation slides. Everything here reflects what is
actually implemented in the codebase. Items you must personalize (your own
process, timeline, supervisor meetings) are marked **[fill in]**.

> The project text is in English; the talking points map one-to-one to the
> grading rubric (1.1, 1.2, 2, 3, 5). Deliver the talk in Georgian or English as
> you prefer.

---

## 0. One-line pitch

**EDAM (External Discovery and Asset Mapper)** — a full-stack web application
that takes a single domain and maps its external attack surface: it discovers
subdomains, IPs, services, and cloud buckets, enriches them with public
intelligence, scores them with a transparent heuristic risk model, and presents
the result as an interactive relationship graph, dashboard, triage table, and
exportable report.

It answers four questions about any domain:
1. What names/subdomains exist?
2. What IPs and services do they expose?
3. Which assets are risky and why?
4. How are all these assets connected?

It is **not** a vulnerability scanner — it is an attack-surface *mapping and
prioritization* tool.

---

## Suggested slide outline (12–14 slides)

1. Title — EDAM: External Discovery and Asset Mapper + your name/supervisor
2. Problem — organizations lose track of what they expose to the internet
3. Goal & scope — what EDAM does and explicitly does not do
4. Methodology — the passive→active scan pipeline (one diagram)
5. System architecture — frontend / backend / external sources (component diagram)
6. Data model — domain → subdomain → IP → service (+ buckets)
7. Risk scoring — heuristic, transparent, explainable
8. Live demo — run a scan, walk the dashboard, graph, risk table
9. Visualization — the asset graph (two layouts, exposure paths, hubs)
10. Engineering quality — TypeScript, modular engine, unit tests
11. Documentation — README, architecture (UML), user guide, API docs
12. Limitations — honest boundaries of the tool
13. Results / case study — numbers from a real scan **[fill in your target]**
14. Conclusion & future work

---

## 1.1 Code quality and architecture

**Talking points**
- **Full-stack TypeScript + React 18 + Vite 8**, styled with Tailwind CSS 4,
  graph rendered with Cytoscape.js, icons with lucide-react.
- **Clear layered architecture** with separation of concerns:
  - `src/api/connectors.ts` — one isolated function per external data source.
  - `src/api/orchestrator.ts` — coordinates the whole scan pipeline.
  - `src/engine/` — **pure, framework-free logic**: `riskEngine.ts` (scoring),
    `graphBuilder.ts` (graph model), `changeDetection.ts` (scan diffing),
    `exportUtils.ts` (CSV/JSON/Markdown + history).
  - `src/types/index.ts` — a single shared, strongly-typed domain model.
  - `src/App.tsx` — React views and UI state.
  - `server/` — Express backend + a zero-dependency presentation server.
- **Design patterns / principles:** orchestrator/pipeline pattern, strict
  separation of pure logic from UI (so logic is unit-testable), pluggable
  connector functions, a typed discriminated-union asset model.
- **Best practices:** strict typing (`tsc --noEmit` passes clean), consistent
  naming conventions (camelCase / PascalCase / SCREAMING_SNAKE_CASE), bounded
  concurrency for network calls, soft-failing connectors so one dead source
  never breaks a scan.
- **Maintainability:** small focused modules, docstrings/comments on non-obvious
  logic, a documented project structure.

**Evidence to show:** the folder tree, the `types/index.ts` model, the
`orchestrator.ts` pipeline, and a clean `npx tsc --noEmit`.

---

## 1.2 Functionality and stability

**Implemented functionality (all working):**
- Passive subdomain discovery from **five** sources in parallel: crt.sh,
  CertSpotter, Sonar/Omnisint, BufferOver, HackerTarget.
- Optional Censys discovery and GreyHatWarfare cloud-bucket discovery (when keys
  are configured).
- DNS resolution (A/AAAA/CNAME) via Google DNS-over-HTTPS.
- HTTP/HTTPS reachability probing.
- Shodan enrichment (ports, banners, org/ISP, geo) with rate limiting.
- Active TCP port validation via the local backend (`net.Socket`).
- Heuristic risk scoring with human-readable reasons.
- Interactive asset graph, dashboard, risk table, history + comparison, exports.
- Three scan presets: **Fast Demo / Balanced / Deep Review**.

**Stability & robustness:**
- `Promise.allSettled` for parallel discovery — partial failures don't abort.
- Every connector wraps network calls in try/catch and returns empty on failure.
- Bounded concurrency (DNS 16, HTTP 24) and a Shodan rate-limit delay.
- Backend input validation: IP/port validity, list caps, clamped timeout and
  concurrency; clear `400` responses for invalid scan requests and `405`
  responses for unsupported methods in presentation mode.
- Result-set caps for performance and UI clarity.

**Edge cases handled (and unit-tested):** empty inputs to the layout/diff/export
functions, keyword matching at word boundaries (e.g. "git" is **not** falsely
matched inside "digital"), dangling graph edges dropped, localStorage quota
fallback for history.

**Testing:** an automated unit-test suite (`npm test`, Node's built-in runner)
covering the risk engine, graph builder, scan diffing, and export logic — all
passing. Plus manual scenario testing against authorized or demo targets.

---

## 2. Problem solving

**Talking points**
- **Problem clearly framed:** organizations expose more external infrastructure
  than they track — forgotten subdomains, dev/test environments, legacy hosts,
  multiple services per host, cloud buckets. Traditional workflows scatter this
  across many separate tools.
- **Solution fits the problem:** unify passive OSINT, DNS, HTTP probing,
  enrichment, optional active validation, scoring, and visualization in one
  interface.
- **Alternatives considered and justified:** the project was framed around
  comparing OSINT/ASM tools and converged on a practical, complementary subset —
  Shodan (service/host enrichment), Censys (certificate-linked discovery),
  GreyHatWarfare (cloud exposure) — each chosen for a distinct coverage gap, and
  treated as enrichment rather than a single source of truth.
- **Methodology is deliberate:** combine *passive* methods (breadth without heavy
  direct contact) with *optional active* validation (confirm live exposure). The
  backend exists for exactly one reason — browsers cannot open raw TCP sockets.
- **Efficient implementation:** parallelism where safe, rate limiting where
  required, caps where needed for UI/performance.
- **Expected results achieved:** for a target domain, EDAM produces a structured,
  navigable map of the external surface with prioritized risk.

---

## 3. Documentation

**What exists (show these files):**
- **`README.md`** — abstract, problem statement, objectives, methodology, tool
  justification, full stack, implemented features, asset model, scan pipeline,
  risk model, setup/run, testing, troubleshooting, API reference, ethics.
- **`docs/ARCHITECTURE.md`** — technology stack table, **UML/system diagrams**
  (component, sequence, deployment) in Mermaid, the data model, and design-
  decision rationale.
- **`docs/USER_GUIDE.md`** — step-by-step walkthrough of every view (scan,
  dashboard, graph, risk table, history/compare, export) and how to read risk.
- **`CONTRIBUTING.md`** — setup, project layout, scripts, coding conventions,
  testing, PR checklist.
- **`LICENSE`** — MIT, with an authorized-use note.
- **API documentation** — `GET /api/health` and `POST /api/port-scan` with
  request/response examples and a **status/error-code table** in the README.
- **Code documentation** — module-level docstrings and inline comments.

**[fill in]** Add **screenshots** to the user guide (placeholders are marked in
`docs/USER_GUIDE.md`) — capture the scan form, dashboard, graph, and risk table.

---

## 5. Independent / individual work

**Factual, project-based points (true and demonstrable):**
- Solo full-stack build: frontend, backend, scan engine, scoring, visualization,
  and documentation.
- **Version control with Git** throughout the project.
- **Additional initiatives / improvements beyond the base plan:**
  - extracted pure logic into testable engine modules and added a **unit-test
    suite** with Node's built-in runner (no extra dependencies),
  - hardened the risk engine (word-boundary keyword matching to cut false
    positives),
  - improved the graph (two layouts, exposure-path highlighting, shared-
    infrastructure hub detection, a visual legend, viewport preservation),
  - added full project documentation (architecture with UML diagrams, user
    guide, contributing guide, license, troubleshooting),
  - built a **zero-dependency presentation server** so the project runs on any
    machine with only Node.js installed.

**[fill in] — these are about your process; substantiate them yourself:**
- self-organization and time management, milestones met on schedule,
- regular progress and proactive communication with your supervisor,
- a richer commit history with meaningful messages (commit the recent
  improvements as discrete steps: e.g. "add unit tests", "improve graph layout",
  "add architecture + user docs").

---

## Live demo script (≈3 minutes)

1. Open the app → **New Scan**. Enter a known domain (e.g. your target **[fill in]**),
   pick **Balanced**, start the scan. Narrate the live progress/log.
2. **Dashboard** — point out total assets, severity distribution, top services,
   highest-risk assets.
3. **Asset Graph** — switch between **Hierarchy Map** and **IP Map**; click a
   high-risk node to focus its neighborhood; click an exposure path to highlight
   the chain; mention shape = type, border = severity, size = risk.
4. **Risk Table** — sort by risk, expand a row to show evidence + recommended
   check.
5. **Export** — generate the Markdown report.
6. Mention **History/Compare** for tracking the surface over time.

---

## Key facts sheet (for quick reference on slides)

- **Stack:** React 18, TypeScript, Vite 8, Tailwind CSS 4, Cytoscape.js,
  Node.js, Express.
- **External sources:** crt.sh, CertSpotter, Sonar, BufferOver, HackerTarget,
  Google DoH, Shodan, Censys, GreyHatWarfare.
- **Asset types:** domain, subdomain, ip, service, bucket.
- **Relationships:** parent_of, resolves_to, exposes, discovered_bucket.
- **Severity bands:** low `<6`, medium `6–11`, high `12–19`, critical `20+`.
- **Backend API:** `GET /api/health`, `POST /api/port-scan` (validated, clamped).
- **Tests:** automated unit tests, `npm test`, all passing.
- **Scan modes:** Fast Demo, Balanced, Deep Review.

---

## Limitations (be honest — it strengthens credibility)

- Not a vulnerability scanner; no CVE detection or exploitation.
- Results depend on third-party source availability and coverage.
- Shodan/Censys/GreyHatWarfare need API keys for full functionality (optional).
- HTTP probing confirms reachability only; TCP checks confirm connection only.
- Risk scores are heuristic — for prioritization, not definitive assessment.
- Large result sets are capped for performance.
- `VITE_*` API keys are embedded in the client build — fine for a local demo,
  but for public deployment they should be proxied through the backend.

---

## Future work

- Proxy enrichment APIs through the backend (keys stay server-side).
- Confidence-weighted scoring (passive-inferred vs. actively-confirmed).
- Broader cloud-native and shadow-IT coverage.
- Connector health monitoring and source-coverage reporting.
- Automated screenshots/snapshots of discovered web assets.
