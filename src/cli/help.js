// SPDX-License-Identifier: MIT
// The help pages. Each fits in 80 columns, and `vexproof --help` on one screen; each command has its own page.
import { VERSION } from '../index.js';

const HELP = {
  overview: `vexproof ${VERSION}: build-proven VEX for npm

Usage:
  vexproof --lockfile <sbom> --bundle <sbom> [options]   write VEX
           (or --modules <file> / --deploy <dir> in place of --bundle)
  vexproof review --vex <file> --id <advisory> ...       record a decision
  vexproof rules derive --lockfile <sbom> --findings <file>
  vexproof dependabot --vex <file> --lockfile <sbom>     (Pro) apply to alerts
  vexproof rollup --vex <file>... --product <purl>       (Pro) one VEX per org
  vexproof verify <file> [--key <pub.pem>]               check a signature

Common options:
  --findings <file>   scanner or audit JSON (default: query OSV)
  --product <purl>    product identifier in the VEX
  --out <file>        CycloneDX VEX (default vex.cdx.json)
  --openvex <file>    also write OpenVEX
  --fail-on <mode>    in_triage | new: exit 1 when the gate trips
  --csaf <file>       (Pro) also write CSAF 2.0 VEX; needs --csaf-namespace
  --sign <key.pem>    (Pro) sign every file written
  --license <key>     Pro license key or file (or VEXPROOF_LICENSE)

More: vexproof --help all (every option), vexproof <command> --help
      (review, rules derive, dependabot, rollup, verify, keygen),
      https://vexproof.dev/docs/`,

  all: `vexproof ${VERSION}

  vexproof --lockfile <sbom> [options]
           (--bundle <sbom> | --modules <file> | --deploy <dir>)

What ships (at least one):
  --bundle <file>         CycloneDX SBOM of the bundle; optional with --modules
  --modules <file>        vexproof-modules.json (vexproof/vite or /webpack),
                          esbuild or bun build metafile, Angular stats.json,
                          or webpack stats JSON. Repeatable.
  --deploy <dir>          deployment folder: its node_modules files and the
                          source maps of its bundled code. Repeatable (Next.js:
                          .next/standalone and .next/static; Nuxt: .output)
  --maps <dir>            extra source map folder (default: the build's .next)
  --root <dir>            the folder the build ran in: node_modules and the
                          build output are looked for there (default: cwd)

Findings:
  --findings <file>       npm, pnpm, yarn or bun audit, osv-scanner, Trivy,
                          Grype or Snyk JSON, or [{purl, ids}] (default:
                          query OSV)
  --enrich-aliases        look up GHSA/CVE aliases on OSV (automatic when
                          querying OSV)

Output:
  --product <purl>        product identifier used in the VEX
  --out <file>            CycloneDX VEX (default vex.cdx.json)
  --spec-version <v>      CycloneDX 1.6 (default) or 1.7. Trivy reads 1.7 from
                          0.71, Dependency-Track from 4.14
  --openvex <file>        also write OpenVEX (Trivy applies it to a scan of the
                          lockfile SBOM)
  --openvex-package-products
                          add package-as-product statements, which Grype needs
                          for directory and SBOM scans and Trivy for directory
                          scans (trivy fs); use that file only for this app
  --browser-only          the VEX covers the browser bundle only (required when
                          the app also has a server build; name that artifact
                          with --product)
  SOURCE_DATE_EPOCH       env var: pin every timestamp written (seconds since
                          1970)

CSAF (Pro; the document a supplier hands to customers and regulators):
  --csaf <file>           also write CSAF 2.0 VEX (profile csaf_vex)
  --csaf-namespace <url>  the publisher's namespace URL. Required with --csaf
  --csaf-publisher <name> publisher name (default: the license holder)
  --csaf-id <id>          tracking id (default <PRODUCT>-<VERSION>-VEX)
  --csaf-status <s>       draft | interim | final (default final)
  --csaf-tlp <label>      WHITE | GREEN | AMBER | RED (default WHITE)
  --csaf-url <url>        canonical URL of the document (its "self" reference)
  --csaf-previous <file>  the previous revision: carries its history forward
                          and bumps the version

Gates and reviews:
  --fail-on <mode>        in_triage | new: exit 1 when the gate trips ("new"
                          needs --baseline; a finding reviewed exploitable
                          trips both)
  --baseline <vex>        (Pro) previous release's VEX; reviews carry forward
                          while their evidence is unchanged
  --review-max-age <d>    reviews older than this many days need re-confirming
                          (default 365)

Pro:
  --license <token|file>  or VEXPROOF_LICENSE, or ./.vexproof-license
  --rules <file>          extra module rules, e.g. from \`vexproof rules derive\`
  --accept-derived        let derived rules settle findings, not only suggest
  --report <file.html>    audit-ready evidence report
  --sign <key.pem>        sign every file written (Ed25519 or ECDSA P-256 key,
                          see vexproof keygen): JSF signature inside the
                          CycloneDX VEX, <file>.sig beside OpenVEX and CSAF
  --signer <name>         name recorded with the signature (default: the key's
                          fingerprint)
  --quiet                 no Pro hints`,

  review: `vexproof review: record a human decision in a VEX file

  vexproof review --vex <file> --id <advisory> --state <state> --detail <text>
                  --by <name> [--justification <j>] [--package <purl>]
                  [--same-cause]

  --same-cause            also apply the decision to open findings on the same
                          vulnerable files

With --baseline, Pro carries the decision into later releases.`,

  dependabot: `vexproof dependabot (Pro): apply a VEX to Dependabot npm alerts

  vexproof dependabot --vex <file> --lockfile <sbom> [--repo owner/name]
                      [--manifest <path>] [--link <url>] [--dry-run]

Dismisses the alerts the VEX settles (with the reason and a link as the
comment) and reopens ones it dismissed earlier that it no longer settles.
Alerts dismissed by people are never changed. --vex, --lockfile and
--manifest repeat.

  --manifest <path>       manifest file or folder whose alerts to change, from
                          the repository root (. is the root; default: the
                          current folder)
  --repo owner/name       default: GITHUB_REPOSITORY, then the git remote
  --link <url>            what the dismissal comment links to (default: this
                          Actions run)
  --token <token>         a token that can write Dependabot alerts (or
                          VEXPROOF_DEPENDABOT_TOKEN, GH_TOKEN, GITHUB_TOKEN)
  --dry-run               print what would change
  --license <token|file>  or VEXPROOF_LICENSE, or ./.vexproof-license`,

  rules: `vexproof rules derive: write module rules from each advisory's fix

  vexproof rules derive --lockfile <sbom> --findings <file> [--modules <file>]
                        [--out <file>]

The rules list the files that changed between the installed version and the
first fixed release, from the npm registry. With --modules, only packages that
ship get rules. Default output: vexproof-rules.derived.json.`,

  rollup: `vexproof rollup (Pro): one CycloneDX VEX for an organization

  vexproof rollup --vex <file> [--vex <file>...] --product <purl>
                  [--out <file>] [--sign <key.pem>] [--signer <name>]

Combines the VEX files vexproof wrote for each application into one document
about the product that contains them all. Every statement keeps its evidence
and names its application (vexproof:application). Settled statements come
first, then open ones; verdicts that differ between applications on the same
package version are listed on standard error.

  --vex <file>            an application's CycloneDX VEX. Repeat for each
  --product <purl>        what the rollup speaks for, e.g. pkg:generic/acme@2026
  --out <file>            default vex.rollup.cdx.json
  --sign <key.pem>        sign the rollup (JSF signature inside the document)
  --signer <name>         name recorded with the signature
  --license <token|file>  or VEXPROOF_LICENSE, or ./.vexproof-license`,

  verify: `vexproof verify: check a signature vexproof wrote. Needs no license.

  vexproof verify <file> [--key <public.pem>]

A CycloneDX VEX carries its signature inside (JSF, the schema's "signature");
OpenVEX and CSAF have a detached <file>.sig beside them. Without --key the
public key embedded in the signature is used and printed, so you can compare
it with the one the publisher gave you; with --key the two must match.
Exit 0 when the signature checks, 1 when it does not, 2 on unreadable input.`,

  keygen: `vexproof keygen: make a signing key pair for --sign. Needs no license.

  vexproof keygen [--out <prefix>] [--type ed25519|p256]

Writes <prefix>.pem (the private key: keep it with your release secrets) and
<prefix>.pub.pem (the public key: publish it where customers can find it).
Default prefix vexproof-signing; nothing is overwritten. Any Ed25519 or ECDSA
P-256 key in PEM form works too, for example from openssl.`,
};

/** The page for a command ("vex" is the main command's overview; "all" every main-command option). */
export function helpPage(command, words) {
  if (command === 'vex') {
    return words[0] === 'all' ? HELP.all : HELP.overview;
  }

  return HELP[command === 'rules-derive' ? 'rules' : command] ?? HELP.overview;
}
