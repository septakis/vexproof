# Changelog

All notable changes to vexproof. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and vexproof uses [Semantic Versioning](https://semver.org/): the CLI contract and the VEX output shape are the
public API, so a breaking change to either is a major release.

## [Unreleased]

### Fixed
Two more ways a run could report `not_affected` for code that ships. Both come from a package store that keeps
packages in a dot folder of `node_modules`, where vexproof took the dot folder for the package:
- Yarn with `nodeLinker: pnpm` installs to `node_modules/.store/<name>-npm-<version>-<hash>/package/`, and
  bundlers name modules by that path. Every package in such a build counted as absent. They are read now, by
  the name in their `package.json`; a store folder whose package can't be named stops the run.
- Nitro (Nuxt) deploys a package the server needs in two versions under
  `.output/server/node_modules/.nitro/<name>@<version>/` and links one of them from the top level. `--deploy`
  does not follow links, so such a package counted as absent unless a source map also named it. Each folder
  is now read as that package at that version.

- A file in the build output counted as the project's own if any file in the project folder matched it byte
  for byte, including another build's output: a prebuilt bundle copied into the output could pass with the
  packages inside it unseen. Only files git tracks count now; outside a git checkout none do.
- Angular's webpack-based builder (`@angular-devkit/build-angular:browser`) writes its module list per chunk,
  and its stats file was refused as unrecognised. It is read now. A chunk with no modules, such as the
  `scripts` bundle that builder joins from raw files, is not vouched for by the stats: turn on source maps for
  it (`--source-map`) and vexproof reads the map.
- Rspack 2.0 names some members of a concatenated module after the concatenation, and the plugin's output was
  refused as incomplete. Those members are read by their real path. When a plugin-written file is refused
  for leaving modules out, the message no longer says to use the plugin.
- SvelteKit 3 on Vite 8: a web worker's chunk was recorded under Vite's default `dist` folder, where SvelteKit
  never writes, so the output check failed. The plugin now moves the record to where the main build emits
  the file.
- `--deploy` refused any app that deploys one of its own files as it is (`public/sw.js`). A file git tracks
  is now accepted; what it loads by name is checked like any other deployed file.
- `--deploy` on Vite 8: Rolldown's runtime chunk and Vite's preload helper have no source map, because no
  source file is behind them, and stopped the run. They are recognised by shape and content.

### Changed
- The webpack plugin also lists the bundler's runtime modules, so that a chunk holding only the runtime can be
  told from one whose contents are unknown.
- Finding copies of installed files no longer hashes all of `node_modules`: files are compared by size first.
  `--deploy` runs that took one to two minutes for this reason take well under one.
- The package count in "contents taken from …" counts each package version once. It used to count a version
  once per place it was found, so a deployment could show a third more packages than it has. The
  `vexproof:bundleComponentCount` property in the VEX changes with it.
- Shipped code under any other dot folder of `node_modules` (`.cache`, `.prisma`) is no longer listed as a
  package of that name, and a line says that it counts for none.

## [1.0.0-beta.7] - 2026-11-11

### Fixed
Four ways a run could report `not_affected` for code that ships, found by running vexproof on twelve
open-source apps:
- The check that every `.js` file in the build output is recorded was skipped, silently, when the output
  folder wasn't found: running from a repository root with `--modules apps/web/vexproof-modules.json` was
  enough. A recorded output folder that isn't there now stops the run.
- That check ran only for the Vite plugin's module map. It now runs for webpack and Rspack stats, esbuild and
  Bun metafiles and Angular stats too, so a file copied into the output (copy-webpack-plugin, Angular
  `assets`) or built by a second bundler is seen. The webpack plugin now records the output folder, the
  emitted files and child compilations (workers); a map from an older plugin is refused, so rebuild.
- A workspace package bundled from source (`../packages/ui/src/…`, not under `node_modules`) counted as
  absent. Shipped files outside `node_modules` are now given to the nearest `package.json` above them.
- A deployment passed as "includes the server" if any file mentioned a Node module, which browser code that
  also runs under Node does behind a test (`if (IS_NODE) require("fs")`). Only loads that are not behind a
  test count now. A static SvelteKit site therefore needs `--browser-only`.

Three things that made `--deploy` refuse a Next.js 16 (Turbopack) app in a pnpm workspace, found on ZITADEL's
login app:
- Run from the app's own folder, vexproof found none of the packages: a workspace installs them beside the
  lockfile and links them into the app, and it did not look there. It now also reads `node_modules` in the
  parent folders, up to the one with the lockfile. Packages found there are named with a `../` path.
- Run from the workspace root, the server source maps were not found without `--maps`. The default is now
  the `.next` folder that each `--deploy` folder sits in, not only `.next` under the root.
- Two kinds of source-map entry could not be traced to a package: the stand-in Next.js generates for a client
  component (`<file>/__nextjs-internal-proxy.cjs`), now counted as that file, and a file that a package's own
  source map names under a `node_modules` folder it never published (@formatjs), now traced to that package.

### Changed
- An output file the module map doesn't record no longer always stops the run. It is accounted for on its
  own when it has a source map beside it, is an unmodified copy of an installed or project file, was copied
  by webpack from a recorded origin, or holds no functions; a package it imports by name counts as shipped.
  This lets apps with a PWA service worker, `?url` imports, or files copied from `public/` through.
  Anything else is still refused, now with the reason for each file and a count of those not listed.
- `uncoveredOutputs` is gone from `src/modules.js`; `strayOutputs` and `accountFor` in `src/coverage.js`
  replace it.

## [1.0.0-beta.6] - 2026-11-11

### Changed
- The two-line Pro hint printed for free runs no longer quotes a price (the pricing page does) and says how to
  silence it (`--quiet` or `VEXPROOF_QUIET=1`).

### Fixed
- The README's GitHub Action examples used `septakis/vexproof@v0`, a tag that does not exist. They now name this
  release's tag.

## [1.0.0-beta.5] - 2026-11-06

### Fixed
- 1.0.0-beta.4 reported itself as 1.0.0-beta.3, in `--version` and in the `metadata.tools` entry of every file it
  wrote, because the version was a constant that the release did not bump. The version now comes from
  package.json, and a test checks `--version` and the VEX metadata against it.

## [1.0.0-beta.4] - 2026-11-06

### Fixed
- The GitHub Action's `action.yml` did not parse: a shell string in the signing step held a line break. Any
  workflow with `uses: septakis/vexproof@v1.0.0-beta.3` failed at "Set up job". A test now checks the file.

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

[Unreleased]: https://github.com/septakis/vexproof/compare/v1.0.0-beta.7...HEAD
[1.0.0-beta.7]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.7
[1.0.0-beta.6]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.6
[1.0.0-beta.5]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.5
[1.0.0-beta.4]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.4
[1.0.0-beta.3]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.3
[1.0.0-beta.2]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.2
[1.0.0-beta.1]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.1
[0.13.0]: https://www.npmjs.com/package/vexproof/v/0.13.0
[0.12.0]: https://www.npmjs.com/package/vexproof/v/0.12.0
