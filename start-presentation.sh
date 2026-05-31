#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is required to run the EDAM presentation build."
  echo "Install Node.js LTS from https://nodejs.org/ and run this script again."
  exit 1
fi

if [ ! -f dist/index.html ]; then
  echo "Missing dist/index.html."
  echo "Before the presentation, run this once on your own computer:"
  echo "npm install"
  echo "npm run build"
  echo
  echo "Then copy this whole folder to the USB or presentation computer."
  exit 1
fi

echo "Starting EDAM presentation mode..."
echo "Open: http://localhost:5173"
node server/presentation.mjs
