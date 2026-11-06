# Changelog

All notable changes to vexproof. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and vexproof uses [Semantic Versioning](https://semver.org/): the CLI contract and the VEX output shape are the
public API, so a breaking change to either is a major release.

## [Unreleased]

## [1.0.0-beta.3] - 2026-11-05

### Added
- **CSAF 2.0 VEX** (Pro): `--csaf <file>` writes the document a supplier hands to customers, procurement portals
  and regulators, alongside the CycloneDX and OpenVEX files. One entry per advisory, the release as the product,
  each package as a component of it. `--csaf-namespace` is required; `--csaf-publisher`, `--csaf-id`,
  `--csaf-status`, `--csaf-tlp`, `--csaf-url` and `--csaf-previous` (revision history) are optional. Every document
  passes the CSAF 2.0 schema and all mandatory tests of BSI's validator, which now runs in `npm test`.
- **Signed VEX** (Pro): `--sign <key.pem>` signs every file written. The CycloneDX VEX carries a JSON Signature
  Format signature (the schema's `signature`, over the RFC 8785 canonical form); OpenVEX and CSAF get a detached
  `<file>.sig`. Ed25519 or ECDSA P-256 keys; `vexproof keygen` makes a pair. `vexproof verify <file> [--key]`
  checks a signature and needs no license, so customers can verify what they receive.
- **Rollup** (Pro): `vexproof rollup --vex a.cdx.json --vex b.cdx.json --product <purl>` writes one CycloneDX VEX
  for an organization from each application's VEX. Statements keep their evidence and name their application;
  verdicts that differ between applications on the same package version are listed.
- Licenses issued before this release already carry `csaf`, `signing` and `rollup`, so every key unlocks them.

## [1.0.0-beta.2] - 2026-11-05

### Changed
- The license signing key was rotated before any license was issued. Keys are verified against the public key
  in this release; 1.0.0-beta.1 carries the retired key and accepts no license.

## [1.0.0-beta.1] - 2026-11-05

First beta of 1.0. The CLI contract and the output shape are frozen as written in `docs/CONTRACT.md`;
what changes before 1.0.0 is copy and fixes.

### Added
- The same inputs now write the same files: statements come in a fixed order and each file's serial number is
  derived from its content. `SOURCE_DATE_EPOCH` pins every timestamp, so a VEX file committed next to its SBOM
  only changes when a verdict does.
- `vexproof --help` fits on one screen; `vexproof --help all` lists every option, and each command has its own
  page (`vexproof review --help`, `vexproof dependabot --help`, `vexproof rules derive --help`).
- Lookups on OSV and the npm registry time out after 30 seconds and retry 429 and 5xx responses with backoff. A
  lookup that keeps failing stops the run with exit 2 and no VEX file, and says how to run without it.
- Tests run on every supported Node LTS line in CI, and a tagged release is published to npm with provenance.

### Changed
- `package.json` names the license as `MIT AND LicenseRef-vexproof-Pro` instead of `SEE LICENSE IN LICENSE`.
- Node 22 or later is required; Node 20 reached end of life in April 2026.

## [0.13.0] - 2026-10-30

### Added
- `vexproof dependabot` (Pro): applies a VEX to the repository's Dependabot npm alerts, dismissing those it
  settles and reopening ones it dismissed earlier that it no longer settles. Alerts dismissed by people are
  never changed.
- `npm run revoke-license`: a revocation list ships with each release (`src/pro/revoked.json`).
- `interop/live.sh`: runs the real Trivy and Grype on the demo app, with and without the VEX, and checks
  that each hides exactly the findings the VEX settles.
- Each CycloneDX VEX entry names its source (`GITHUB` for GHSA, `NVD` for CVE), which Dependency-Track 4.x
  needs before it applies the entry.

## [0.12.0] - 2026-10-24

First published version: CycloneDX 1.6/1.7 and OpenVEX 0.2.0 output from a lockfile SBOM and a bundle SBOM or
module map; findings from npm, pnpm, yarn and bun audit, osv-scanner, Trivy, Grype and Snyk, or from OSV
directly; Vite, Rollup, webpack, Rspack, esbuild, bun and Angular inputs; `--deploy` for server-rendered apps;
`vexproof review` and `vexproof rules derive`; Pro module-level analysis, baselines and the evidence report.

[Unreleased]: https://github.com/septakis/vexproof/compare/v1.0.0-beta.3...HEAD
[1.0.0-beta.3]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.3
[1.0.0-beta.2]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.2
[1.0.0-beta.1]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.1
[0.13.0]: https://www.npmjs.com/package/vexproof/v/0.13.0
[0.12.0]: https://www.npmjs.com/package/vexproof/v/0.12.0
