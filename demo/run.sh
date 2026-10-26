#!/usr/bin/env bash
# Rebuild the demo from scratch: install, bundle, SBOMs, audit, vexproof.
set -euo pipefail
cd "$(dirname "$0")"
npm install --no-audit
npm install --no-audit -D esbuild @cyclonedx/cyclonedx-esbuild @cyclonedx/cyclonedx-npm
node build.mjs
npx cyclonedx-esbuild --output-reproducible --spec-version 1.6 -o dist/bom.bundle.json dist/meta.json
npx cyclonedx-npm --omit dev --output-format JSON --spec-version 1.6 --output-file bom.lockfile.json
npm audit --omit dev --json > out/audit.json || true
node ../src/cli.js --lockfile bom.lockfile.json --bundle dist/bom.bundle.json --findings out/audit.json \
  --modules dist/meta.json --out out/vex.cdx.json --openvex out/vex.openvex.json
