#!/usr/bin/env bash
# Runs the real Trivy and Grype on a demo app, with and without vexproof's VEX, and checks that each scanner
# hides exactly the findings the VEX settles and still shows every other one.
#
#   interop/live.sh                     vexproof from this checkout (packed with npm pack)
#   interop/live.sh vexproof@0.13.0     the published package
#
# Needs Node 20+, npm, trivy and grype on PATH, and network access for npm, OSV and the scanners' databases.
# The app is demo/ plus two dependencies it never imports (minimist, @xmldom/xmldom), so the free tier has
# package-level statements to check, one of them on a scoped package. Set VEXPROOF_LICENSE to also check
# lodash's module-level statement. KEEP=1 keeps the working folder.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
spec="${1:-}"
for t in node npm trivy grype; do command -v "$t" >/dev/null || { echo "live.sh: $t is not on PATH" >&2; exit 2; }; done
work="$(mktemp -d)"
if [ "${KEEP:-}" = 1 ]; then echo "Working in $work"; else trap 'rm -rf "$work"' EXIT; fi

trivy_v="$(trivy --version 2>/dev/null | awk '/^Version:/{print $2; exit}')"
grype_v="$(grype version 2>/dev/null | awk '/^Version:/{print $2; exit}')"
echo "Trivy ${trivy_v:-?}, Grype ${grype_v:-?}, Node $(node --version)"

# 1. The vexproof under test, installed the way a user installs it.
mkdir -p "$work/vx"
if [ -z "$spec" ]; then spec="$work/vx/$(cd "$work/vx" && npm pack --silent "$repo" | tail -1)"; fi
(cd "$work/vx" && npm init -y >/dev/null && npm install --no-audit --no-fund --silent "$spec")
vexproof="$work/vx/node_modules/.bin/vexproof"
echo "vexproof $("$vexproof" --version) from $spec"

# 2. The app: build it and write its lockfile SBOM.
app="$work/app"; mkdir -p "$app"
cp -R "$repo/demo/src" "$repo/demo/build.mjs" "$repo/demo/package.json" "$app/"
cd "$app"
node -e 'const f="package.json",p=JSON.parse(require("fs").readFileSync(f));Object.assign(p.dependencies,{"minimist":"1.2.5","@xmldom/xmldom":"0.7.5"});require("fs").writeFileSync(f,JSON.stringify(p,null,2))'
npm install --no-audit --no-fund --silent
node build.mjs
npx --no-install cyclonedx-npm --omit dev --output-format JSON --spec-version 1.6 --output-file bom.lockfile.json 2>/dev/null

# 3. What each scanner reports without VEX.
trivy fs --quiet --scanners vuln --format json --output trivy.fs.json .
trivy sbom --quiet --format json --output trivy.sbom.json bom.lockfile.json
grype -q sbom:bom.lockfile.json -o json --file grype.sbom.json
grype -q dir:. -o json --file grype.dir.json

# 4. VEX from OSV (what the Action does by default) and from each scanner's own report.
vx() { "$vexproof" --lockfile bom.lockfile.json --modules dist/meta.json --quiet "$@" >/dev/null; }
vx --out vex.osv.cdx.json --openvex vex.osv.openvex.json
vx --out vex.osv17.cdx.json --spec-version 1.7
vx --out vex.osv.pp.cdx.json --openvex vex.osv.pp.openvex.json --openvex-package-products
vx --findings trivy.fs.json --out vex.trivy.cdx.json --openvex vex.trivy.openvex.json
vx --findings grype.sbom.json --out vex.grype.cdx.json --openvex vex.grype.openvex.json --openvex-package-products

# 5. The same scans with the VEX applied, each checked against the CycloneDX VEX from the same run.
failed=0; ran=0
check() { ran=$((ran + 1)); node "$here/live-check.mjs" "$@" || failed=$((failed + 1)); }
newer() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }  # $1 >= $2

trivy fs --quiet --scanners vuln --format json --output t1.json --vex vex.osv.openvex.json .
check --scanner trivy --label "Trivy fs, OpenVEX" --baseline trivy.fs.json --with t1.json --vex vex.osv.cdx.json
trivy sbom --quiet --format json --output t2.json --vex vex.osv.openvex.json bom.lockfile.json
check --scanner trivy --label "Trivy sbom, OpenVEX" --baseline trivy.sbom.json --with t2.json --vex vex.osv.cdx.json
trivy sbom --quiet --format json --output t3.json --vex vex.osv.cdx.json bom.lockfile.json
check --scanner trivy --label "Trivy sbom, CycloneDX 1.6" --baseline trivy.sbom.json --with t3.json --vex vex.osv.cdx.json
if newer "${trivy_v:-0}" 0.71.0; then
  trivy sbom --quiet --format json --output t4.json --vex vex.osv17.cdx.json bom.lockfile.json
  check --scanner trivy --label "Trivy sbom, CycloneDX 1.7" --baseline trivy.sbom.json --with t4.json --vex vex.osv17.cdx.json
else
  echo "SKIP  Trivy sbom, CycloneDX 1.7                     Trivy reads CycloneDX 1.7 from 0.71.0"
fi
trivy fs --quiet --scanners vuln --format json --output t5.json --vex vex.trivy.openvex.json .
check --scanner trivy --label "Trivy fs, OpenVEX from Trivy's findings" --baseline trivy.fs.json --with t5.json --vex vex.trivy.cdx.json

grype -q sbom:bom.lockfile.json -o json --file g1.json --vex vex.osv.pp.openvex.json
check --scanner grype --label "Grype sbom, OpenVEX" --baseline grype.sbom.json --with g1.json --vex vex.osv.pp.cdx.json
grype -q dir:. -o json --file g2.json --vex vex.osv.pp.openvex.json
check --scanner grype --label "Grype dir, OpenVEX" --baseline grype.dir.json --with g2.json --vex vex.osv.pp.cdx.json
grype -q sbom:bom.lockfile.json -o json --file g3.json --vex vex.grype.openvex.json
check --scanner grype --label "Grype sbom, OpenVEX from Grype's findings" --baseline grype.sbom.json --with g3.json --vex vex.grype.cdx.json

echo
if [ "$failed" = 0 ]; then echo "All $ran checks passed."; else echo "$failed of $ran checks failed."; exit 1; fi
