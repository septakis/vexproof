# The vexproof 1.0 contract

This is the public API of vexproof. Everything listed here is stable for the whole 1.x line: a change that
removes or renames any of it, or changes its meaning, is a 2.0. Additions (a new flag, a new property) can
land in a minor release. Anything *not* listed here, including the exact wording of messages on standard error,
may change in any release.

`test/contract.test.js` checks this file against the code: every flag the CLI reads, every property it writes
and every exit code it uses must be listed here, and nothing listed here may be missing from the code.

## Commands

| Command | Does |
|---|---|
| `vexproof` | Writes a CycloneDX VEX (and optionally OpenVEX) from a lockfile SBOM and what shipped. |
| `vexproof review` | Records a human decision on one statement in a VEX file, in place. |
| `vexproof rules derive` | Writes a module-rules file from each finding's fix, using the npm registry. |
| `vexproof dependabot` | (Pro) Applies a VEX to the repository's Dependabot npm alerts. |

`--help` on its own prints a one-screen overview; `--help all` lists every option of the main command, and
`<command> --help` the options of that command. `--version` prints the version and nothing else.

## Options of `vexproof`

What ships (at least one is required):

| Option | Meaning |
|---|---|
| `--lockfile <file>` | CycloneDX JSON SBOM of every package installed for production. Required. |
| `--bundle <file>` | CycloneDX SBOM of the bundle. Optional when `--modules` or `--deploy` is given. |
| `--modules <file>` | A module map (see Inputs). Repeatable, or comma-separated. |
| `--deploy <dir>` | A deployment folder: its package files and the source maps of its bundled code. Repeatable. |
| `--maps <dir>` | Extra folder to find source maps in for `--deploy`. Default `.next` when present. |
| `--root <dir>` | Where `node_modules` and the build output live. Default: the current directory. |

Findings:

| Option | Meaning |
|---|---|
| `--findings <file>` | Scanner or audit output (see Inputs). Without it, vexproof queries OSV. |
| `--enrich-aliases` | Look up GHSA and CVE aliases on OSV for a findings file. Automatic when querying OSV. |

Output:

| Option | Meaning |
|---|---|
| `--product <purl>` | Package URL of the app, used as the VEX product. Default: the lockfile SBOM's component, else `pkg:generic/app`. |
| `--out <file>` | CycloneDX VEX output. Default `vex.cdx.json`. |
| `--spec-version <v>` | CycloneDX version of the VEX: `1.6` (default) or `1.7`. |
| `--openvex <file>` | Also write OpenVEX 0.2.0. |
| `--openvex-package-products` | Add package-as-product statements to the OpenVEX file. |
| `--browser-only` | The VEX covers the browser bundle only; sets the `vexproof:scope` property. |

Gates and reviews:

| Option | Meaning |
|---|---|
| `--fail-on <mode>` | `in_triage` or `new`. Exit 1 when the gate trips; the VEX is still written. `new` needs `--baseline`. |
| `--baseline <file>` | (Pro) The previous release's CycloneDX VEX. Reviews carry forward while their evidence is unchanged. |
| `--review-max-age <days>` | Reviews older than this need re-confirming. Default 365; `0` turns it off. |

Pro:

| Option | Meaning |
|---|---|
| `--license <token\|file>` | License token, or a path to a file holding it. |
| `--rules <file>` | Extra module rules, such as the output of `rules derive`. |
| `--accept-derived` | Let derived rules settle findings instead of only suggesting. |
| `--report <file>` | Write the HTML evidence report. |
| `--quiet` | Hide the Pro hints. |

## Options of `vexproof review`

| Option | Meaning |
|---|---|
| `--vex <file>` | The CycloneDX VEX to update. Required. |
| `--id <advisory>` | Advisory id or alias. Required. |
| `--state <state>` | One of the CycloneDX analysis states. Required. |
| `--justification <j>` | One of the CycloneDX justifications. Required with `not_affected`. |
| `--detail <text>` | Why. Required. |
| `--by <name>` | Who decided. Required. |
| `--package <purl>` | Picks the package when the advisory appears on several. |
| `--same-cause` | Also apply the decision to open findings whose vulnerable files overlap. |

## Options of `vexproof rules derive`

| Option | Meaning |
|---|---|
| `--lockfile <file>` | Lockfile SBOM, for versions. Required. |
| `--findings <file>` | Any supported findings file. Required. |
| `--modules <file>` | Derive only for packages that ship. |
| `--out <file>` | Default `vexproof-rules.derived.json`. |

## Options of `vexproof dependabot` (Pro)

| Option | Meaning |
|---|---|
| `--vex <file>` | The VEX to apply. Repeatable. Required. |
| `--lockfile <file>` | The lockfile SBOM the VEX was made from. Repeatable. Required. |
| `--repo <owner/name>` | Default: `GITHUB_REPOSITORY`, then the git remote. |
| `--manifest <path>` | Manifest file or folder whose alerts to change. Default: the current folder. Repeatable. |
| `--link <url>` | What the dismissal comment links to. Default: the current Actions run. |
| `--token <token>` | A token that can write Dependabot alerts. |
| `--dry-run` | Print what would change and change nothing. |

## Environment

| Variable | Meaning |
|---|---|
| `VEXPROOF_LICENSE` | License token, or a path to a file holding it. A `.vexproof-license` file in the current directory is read when neither `--license` nor the variable is set. |
| `VEXPROOF_QUIET` | `1` is the same as `--quiet`. |
| `VEXPROOF_DEPENDABOT_TOKEN` | Token for `vexproof dependabot`. `GH_TOKEN` and `GITHUB_TOKEN` are read after it. |
| `SOURCE_DATE_EPOCH` | Seconds since 1970. Pins every timestamp vexproof writes. A value that is not whole seconds is an error. |

vexproof reads the usual CI variables (`GITHUB_*`, `CI_PROJECT_PATH`, `CI_SERVER_HOST`, `BITBUCKET_REPO_FULL_NAME`)
to identify the repository and the run. It never sets any.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. The VEX was written (or, for other commands, the change was made). |
| 1 | The `--fail-on` gate tripped. The VEX was still written. |
| 2 | vexproof stopped: a missing or unknown option, an unreadable or unrecognised input, an incomplete module map, or a lookup that failed after retries. Nothing was written. |

The summary goes to standard output; diagnostics, warnings and hints go to standard error.

## Inputs

Findings: `npm audit --json`, `pnpm audit --json`, `yarn audit --json` (Yarn 1), `yarn npm audit --json --recursive`
(Yarn 2+), `bun audit --json`, `osv-scanner --format json`, Trivy JSON, Grype JSON, Snyk JSON, or the internal
`[{purl, ids}]` shape.

Module maps: `vexproof-modules.json` from the `vexproof/vite`, `vexproof/rollup`, `vexproof/webpack` and
`vexproof/rspack` plugins; esbuild and Bun build metafiles; Angular CLI `stats.json`; webpack stats JSON.
Anything else fails with exit 2 and a message naming these.

SBOMs: CycloneDX JSON, 1.4 or later.

## Network

With `--findings` and without `--enrich-aliases`, a run makes no network requests. Otherwise vexproof calls
`api.osv.dev` (package names, versions and advisory ids). `rules derive` downloads packages from
`registry.npmjs.org`. `vexproof dependabot` calls the GitHub API of the repository's host. The license check
never makes a network request. There is no telemetry.

Every request times out after 30 seconds; 429 and 5xx responses are retried up to three times with backoff.
A lookup that still fails stops the run with exit 2.

## Output

### CycloneDX VEX

A CycloneDX BOM (`specVersion` 1.6 or 1.7) with `metadata.timestamp`, `metadata.tools`, `metadata.component`
(the product) and `metadata.properties`, and a `vulnerabilities` array. Settled statements come first and open
ones last; within each group the order is by advisory and package. `serialNumber` is a UUID derived from the
document's content, so the same input gives the same serial number.

Document properties (`metadata.properties`):

| Name | Value |
|---|---|
| `vexproof:bundleSbomSerial` | Serial number of the bundle SBOM, or `null`. |
| `vexproof:lockfileSbomSerial` | Serial number of the lockfile SBOM, or `null`. |
| `vexproof:bundleComponentCount` | Components in the bundle SBOM. |
| `vexproof:lockfileComponentCount` | Components in the lockfile SBOM. |
| `vexproof:input:<role>:sha256` | SHA-256 of each input file, by role (`lockfile-sbom`, `bundle-sbom`, `module-map`, `findings-<format>`, `rules`, `baseline-vex`, …). |
| `vexproof:licensee` | The organization a valid Pro license names. Absent without one. |
| `vexproof:scope` | `browser-bundle` when `--browser-only` is set. Absent otherwise. |

Each vulnerability has `id`, `source` (for GHSA, CVE and Snyk ids), `references` (aliases), `analysis`
(`state`, `justification`, `response`, `detail`, `firstIssued`, `lastUpdated`), `affects` (BOM-Links into the
lockfile SBOM when it has a serial number, else the package's purl) and `properties`:

| Name | Value |
|---|---|
| `vexproof:package` | The package's purl. |
| `vexproof:origin` | `auto` or `reviewed`. |
| `vexproof:level` | `package` or `module`. |
| `vexproof:reviewed-by`, `vexproof:reviewed-at` | From `vexproof review`. |
| `vexproof:rule-source`, `vexproof:rule-origin` | Which rules file settled the finding, and whether it was derived. |
| `vexproof:surviving-files` | The vulnerable files that shipped, when the finding stays open at module level. |
| `vexproof:copies-checked` | Every installed copy of the package that was checked. |
| `vexproof:vulnerable-files`, `vexproof:importers`, `vexproof:evidence-files`, `vexproof:evidence-files-digest` | The evidence fingerprint a review is carried forward on. |
| `vexproof:carried-from` | The purl and review time a carried-forward review came from. |
| `vexproof:alias-of` | On an alias entry, the id of the primary entry. |

### OpenVEX

An OpenVEX 0.2.0 document whose `@id` is derived from its content, with one statement per finding, in the same
order as the CycloneDX file. The product is the app's purl with the package as a subcomponent; with
`--openvex-package-products`, the package is also listed as a product.

## Files vexproof reads without being told

`.vexproof-license` in the current directory, and `.git/config` (to identify the repository for an open-source
license and for `vexproof dependabot`). Nothing else.
