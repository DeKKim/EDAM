# Contributing to EDAM

Thanks for your interest in improving EDAM. This guide covers local setup, the
project layout, coding conventions, and how to run the checks before submitting
a change.

## Prerequisites

- Node.js 20+ (the test runner uses Node's built-in TypeScript support; Node 22+
  recommended)
- npm 9+

## Setup

```bash
npm install
cp .env.local.example .env   # fill in any API keys you have (all optional)
npm start                    # frontend on :5173, backend on :8787
```

## Project layout

```
src/
  api/         external API connectors + scan orchestrator
  engine/      pure logic: risk scoring, graph building, diffing, export
  types/       shared TypeScript types
  App.tsx      React views and state
server/        Express backend + zero-dependency presentation server
test/          unit tests (Node built-in test runner)
docs/          architecture and user documentation
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the component, sequence,
and deployment diagrams.

## Available scripts

| Command | Description |
|---------|-------------|
| `npm start` / `npm run dev` | Run frontend + backend in development |
| `npm run build` | Production build into `dist/` |
| `npm run preview` | Preview the production build |
| `npm run presentation` | Serve `dist/` with the zero-dependency server |
| `npm test` | Run the unit test suite |
| `npx tsc --noEmit` | Type-check the whole project |

## Coding conventions

- **TypeScript everywhere** in `src/`; keep `tsc --noEmit` clean.
- **Keep pure logic in `src/engine/`** and free of React/DOM imports so it stays
  unit-testable. UI concerns belong in `App.tsx`.
- **Naming:** `camelCase` for variables/functions, `PascalCase` for types and
  React components, `SCREAMING_SNAKE_CASE` for module-level constants.
- **Connectors** should fail soft: catch errors and return an empty result rather
  than throwing, so one dead source never breaks a scan.
- Match the comment density and style of the surrounding code.

## Testing

Unit tests live in `test/` as `*.test.mjs` and import the TypeScript engine
modules directly. Add or update tests for any change to scoring, graph building,
diffing, or export logic.

```bash
npm test
```

## Before opening a pull request

1. `npm test` passes.
2. `npx tsc --noEmit` is clean.
3. `npm run build` succeeds.
4. The change is described clearly, and new behavior is covered by a test.

## Security and ethics

EDAM must only be used against assets you are authorized to assess. Do not commit
real API keys — `.env` is gitignored; use `.env.local.example` as the template.
