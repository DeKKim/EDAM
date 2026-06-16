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
  npm install
fi

echo "Starting EDAM..."
echo
echo "Version check:"
node --version
npm --version
echo
echo "Frontend: http://localhost:5173"
echo "Backend:  http://localhost:8787"
npm run dev
