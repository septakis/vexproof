#!/usr/bin/env bash
# Applies vexproof's VEX files with the same library code Trivy and Grype use:
#   openvex/go-vex (Document.Matches) and cyclonedx-go (ParseBOMLink), plus Trivy's PkgIdentifier.Match rule.
# Usage: interop/run.sh <dir containing bom.lockfile.json, vex.trivy.openvex.json, vex.grype.openvex.json, vex.trivy.cdx.json>
# Needs git and Go ≥1.24. Clones the three libraries, keeps only the matching code, builds offline.
set -euo pipefail
target="$(cd "${1:?usage: run.sh <dir>}" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"; work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
git clone -q --depth 1 https://github.com/openvex/go-vex "$work/go-vex"
git clone -q --depth 1 https://github.com/CycloneDX/cyclonedx-go "$work/cyclonedx-go"
git clone -q --depth 1 https://github.com/package-url/packageurl-go "$work/packageurl-go"
mkdir -p "$work/check/vexlib" "$work/check/bomlink"
cp "$work"/go-vex/pkg/vex/{compat,component,justification,product,statement,status,vex,vulnerability}.go "$work/check/vexlib/"
# product.go's only non-stdlib import is an in-toto helper that matching never calls
python3 - "$work/check/vexlib/product.go" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
s=s.replace('\tintoto "github.com/in-toto/attestation/go/v1"\n','')
a=s.index('// ToInToto returns'); b=s.index('\n}\n',a)+3; open(p,'w').write(s[:a]+s[b:])
PY
cp "$work/cyclonedx-go/link.go" "$work/check/bomlink/"
python3 - "$work/check/bomlink/link.go" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read().replace('package cyclonedx','package bomlink',1)
a=s.index('func NewBOMLink('); b=s.index('\n}\n',a)+3; open(p,'w').write(s[:a]+s[b:])
PY
cp "$here/main.go" "$work/check/"
sed -i 's/^go .*/go 1.24/' "$work/packageurl-go/go.mod"
cat > "$work/check/go.mod" <<MOD
module gocheck
go 1.24
require github.com/package-url/packageurl-go v0.1.7
replace github.com/package-url/packageurl-go => ../packageurl-go
MOD
(cd "$work/check" && GOPROXY=off GOFLAGS=-mod=mod GOTOOLCHAIN=local go build -o check . && ./check "$target")
