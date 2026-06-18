#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if ! command -v npm >/dev/null 2>&1; then
  echo "Node.js and npm are required to run EDAM."
  echo "Install Node.js LTS from https://nodejs.org/ and run this script again."
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "Installing dependencies..."
  npm install --include=optional
fi

rolldown_binding=""
case "$(uname -s):$(uname -m)" in
  Linux:x86_64|Linux:amd64)
    rolldown_binding="node_modules/@rolldown/binding-linux-x64-gnu"
    ;;
  Linux:aarch64|Linux:arm64)
    rolldown_binding="node_modules/@rolldown/binding-linux-arm64-gnu"
    ;;
  Darwin:x86_64|Darwin:amd64)
    rolldown_binding="node_modules/@rolldown/binding-darwin-x64"
    ;;
  Darwin:aarch64|Darwin:arm64)
    rolldown_binding="node_modules/@rolldown/binding-darwin-arm64"
    ;;
esac

if [ -n "$rolldown_binding" ] && [ ! -d "$rolldown_binding" ]; then
  echo "Repairing Vite native dependencies..."
  npm install --include=optional
fi

if [ -n "$rolldown_binding" ] && [ ! -d "$rolldown_binding" ]; then
  echo "Required native dependency is still missing:"
  echo "$rolldown_binding"
  echo
  echo "Delete node_modules and package-lock.json, then run this script again."
  exit 1
fi

echo "Starting EDAM..."
echo
echo "Version check:"
node --version
npm --version
echo
echo "Frontend: http://127.0.0.1:5173"
echo "Backend:  http://127.0.0.1:8787"
npm run dev
