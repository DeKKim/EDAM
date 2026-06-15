# EDAM — User Guide

A step-by-step guide to running a scan and interpreting the results.

> **Authorization:** Only scan domains and organizations you are authorized to
> assess. EDAM is for research, learning, and defensive asset inventory.

> _Tip: add a screenshot under each step (`docs/img/...`) when preparing the
> thesis; the headings below map one-to-one to the app's views._

## 1. Start a scan

1. Open the app (`http://localhost:5173`).
2. In **New Scan**, enter a target domain (e.g. `example.com`).
3. Choose a **scan mode**:
   - **Fast Demo** — quick passive map (no Shodan), good for a first look or live demo.
   - **Balanced** — default coverage with controlled enrichment time.
   - **Deep Review** — broader discovery + deep active port validation.
4. Optionally toggle data sources (CT discovery, Shodan, Censys, GreyHatWarfare,
   active port scan). Sources without a configured API key are skipped automatically.
5. Click **Start Scan**. Live progress and a log stream are shown while the
   pipeline runs.

## 2. Dashboard

After a scan you land on the **Dashboard**:
- total and per-type asset counts,
- finding-category breakdown,
- average and maximum risk,
- severity distribution (critical / high / medium / low),
- discovered services and highest-risk assets,
- any scan errors.

Use this for the executive summary of the surface.

## 3. Asset Graph

Open **Asset Graph** for the interactive node-link relationship map.

- **Hierarchy Map** shows `domain → subdomain → IP → service` top-down.
- **IP Map** anchors names and services around their host IP (best for spotting
  shared infrastructure).
- Node **shape** = asset type, **border color** = severity, **size** = risk.
  Double-bordered nodes are shared-infrastructure hubs.
- Click a node to focus its neighborhood; click an **exposure path** in the side
  panel to highlight the full chain from domain to exposed endpoint.
- Filter by type/severity, search, zoom, and "Reset Focus".

The **Analysis Panel** on the right shows the mapping overview, exposure paths,
shared-infrastructure hubs, the selected asset's evidence, the highest-risk
nodes, and the legends.

## 4. Risk Table

**Risk Table** is the triage view: a sortable, filterable table of every asset
with severity, finding category, exposure summary, primary evidence, and a
recommended follow-up check. Expand any row for raw metadata and full risk
reasons. Use this view for large surfaces where you need precise detail.

## 5. History & Comparison

Scans are stored locally in the browser. In **History** you can re-load a past
scan or **Compare** it to the current one to see newly discovered assets, removed
assets, and changed risk scores over time.

## 6. Export

**Export** produces a report in **CSV**, **JSON**, or **Markdown**. CSV and
Markdown include risk reasons and recommended checks; the Markdown report is a
ready-to-read summary suitable for a case study appendix.

## 7. Interpreting risk

Risk scores are **heuristic** and meant for prioritization, not definitive
vulnerability assessment. Every score is explained by the listed reasons (e.g.
"Database/cache ports exposed", "HTTP available without HTTPS", "Subdomain
contains 'admin'"). Severity bands:

| Severity | Score |
|----------|-------|
| Low | `< 6` |
| Medium | `6–11` |
| High | `12–19` |
| Critical | `20+` |
