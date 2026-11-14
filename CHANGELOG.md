# Changelog

All notable changes to vexproof. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and vexproof uses [Semantic Versioning](https://semver.org/): the CLI contract and the VEX output shape are the
public API, so a breaking change to either is a major release.

## [Unreleased]

A code audit of 1.0.0-beta.9 (five independent reviews, each finding reproduced) found about twenty more ways to
get `not_affected` for code that ships, and a test suite that missed most of the CLI's decisions about what
shipped. This release closes them, and adds a test for each route and each refusal. Upgrade from any earlier
version.

### Fixed
Package names and SBOMs:
- npm package names are compared without regard to case. cyclonedx-npm writes `pkg:npm/jsonstream` for
  `JSONStream`, as the purl spec says, while module maps keep the published name, so a shipped `JSONStream`
  was called absent. The content check, the inline source map check and the Dependabot sync match names the
  same way.
- A bundle SBOM component listed by name and version without a purl counts as shipped.
- A bundle SBOM that names none of the lockfile's npm packages (an empty file, one that lists only the app,
  another project's) settles nothing. Before, any component at all made it usable.

Module maps (`--modules`):
- A package file vendored into `public/` and checked out with CRLF line endings is still that package's file.
  And a git-tracked file accepted as the project's own no longer explains away its strings in the content
  check, which let a patched copy of a package pass unseen.
- Externals count as shipped: webpack's (also `externals: { react: 'React' }`, which reads a global), esbuild's
  `--external`, and Rollup's in the Vite plugin, also for iife and umd output.
- A nested package whose `package.json` can't be parsed (a UTF-8 byte order mark, which Node accepts) was filed
  under the package around it. It keeps its own name now; every `package.json` is read with the BOM removed.
- A folder in the build output that is a link (a symlink or junction) is checked like any other, and one that
  can't be read stops the run. Output files are found whatever the case of their extension (`app.JS`).
- A file outside the module map that is accounted for by its source map keeps the packages it loads by name.
- A concatenated module named `x.js + 21 modules` holds 22; a list of 21 was taken as complete.

Deployments (`--deploy`):
- A deployed package that loads another from the project's own `node_modules` was missed when the load was
  written as esbuild's `__require("x")`, as `createRequire(…)("x")`, or behind a `try`. All three count now.
- Deployed code that loads a file from outside the deployment folders (a generated client beside the build)
  stops the run: what that file holds is not checked.
- TypeScript files that Node runs as they are (type stripping) are read like JavaScript.
- The server half of React Router, Astro, Angular SSR and SvelteKit builds is refused without its browser
  half, as Next.js and Nuxt builds were.
- A source map whose every source is made up accounts for nothing, unless it carries the file's debug id
  (Turbopack's maps do). Turbopack's runtime counts as `next`.
- A map found elsewhere by name must sit in folders named like all of the file's own, up to the deployment
  folder, and agree with the file's name and debug id where it gives them: `app/[locale]/about/page.js` took
  `app/about/page.js.map` before.
- A map written on Windows (`C:\build\node_modules\x\index.js`) names the same package on Linux.
- SvelteKit's generated files (`generated/root.svelte`) are found under `.svelte-kit` after an adapter
  copied the build.

Module rules (Pro) and `rules derive`:
- A `--rules` file no longer drops a package's full-build guards (`monoliths`, `monolithDirs`), and every rule
  must list its files: a rule with none settled every build.
- `rules derive` looks for the fix outside every range an advisory gives, not only the one for the installed
  release line, names every JavaScript file the fix changed (also under `spec/` or `docs/`), ignores a file
  that only had its version number changed, and refuses a fix that changed the package's dependencies.
- Advisory ranges are read with a space after an operator (`>= 1.0.0`), as hyphen ranges, and with
  prereleases compared as semver says. A `bun audit` finding is never dropped for a range misread.

Dependabot (Pro):
- With several `--manifest` scopes, each needs its own `--vex`, in the same order: one application's VEX
  dismissed another application's alerts before. An alert on a workspace's root lockfile is judged only by a
  VEX for the root package.

## [1.0.0-beta.9] - 2026-11-13

A soundness audit of 1.0.0-beta.8 (two independent reviews of the code, and runs over real package-manager
layouts) found 29 ways to get `not_affected` for code that ships. This release closes most of them and adds a
check that does not depend on finding each one first. Upgrade from any earlier version.

A review of the published 1.0.0-beta.8 package found one more, and a gate that could switch itself off;
both are closed here too.

### Changed
- **An option vexproof does not have stops the run** (exit 2) and names the one that was probably meant.
  Until now it was skipped in silence, so `--failon in_triage`, or `--fail-on=in_triage`, left a build with
  no gate. `--name=value` is now read like `--name value`; an option without its value, a value on a flag
  that takes none, and a word that is not a command stop the run as well. `-h` and `-v` work.
- **`--fail-on` is checked before any work.** A mistyped mode, or `--fail-on new` without `--baseline`, stops
  the run (exit 2) with nothing written; it used to write the VEX first, or exit 0. When no license covers
  `--baseline` (an expired key, for one), the gate still does not run and the build still passes, as the Pro
  terms promise, but the one line that said so is now a warning at the start and the end of the output and an
  annotation on the GitHub Actions run.
- **The GitHub Action runs the release its tag names**, not npm's `latest`: pinning the Action now pins the
  code that runs. `version:` still overrides it.
- `vexproof verify` without `--key` says on standard error that the signer was not checked.
- `vexproof rules derive` checks every package it downloads against the checksum the registry lists for it.
- On Node.js older than 22 the CLI says so and stops, instead of failing somewhere else.

### Added
- TypeScript types for `vexproof`, `vexproof/vite`, `vexproof/rollup`, `vexproof/webpack` and
  `vexproof/rspack`; `vexproof/package.json` can be imported.
- **Content check.** Before a package is called absent, vexproof looks for the package's own string literals
  in the JavaScript and HTML that ship. A minifier keeps what a string says. If some are there, and no file
  the build's records name holds them too, the finding stays open and a line says which string was found
  where. The check can only keep a finding open. It needs `node_modules` installed and looks only at packages
  that have a finding.

### Fixed
Package names:
- A package installed under another name (`"tiny": "npm:ms@2.1.3"`, an npm `overrides` entry, a git
  dependency) was named after its folder, so the real package looked absent: npm, Yarn 1 and Yarn's
  node-modules linker. The name now comes from the `package.json` in the folder, which also settles
  `require('Lodash')` on a file system that ignores case. A shipped folder that can't be read, under a name the
  lockfile SBOM doesn't have, stops the run.
- A finding on a package that is not an npm package (`pkg:pypi/…` from osv-scanner) was marked not affected
  from a JavaScript build. It is left open.

Module maps (`--modules`):
- A webpack or Rspack config that exports an array runs one compiler per configuration, and each one's
  `VexproofPlugin` wrote the same `vexproof-modules.json`: the last replaced the rest, and a package only an
  earlier configuration shipped was called not affected. The plugin now writes every configuration of the run
  into the one file, each with its output folder, and vexproof checks them all. Child compilations inside a
  configuration of such a run (and of `webpack --json` for an array) are read as well.
- The Vite plugin kept the records of chunks from earlier rebuilds of a `--watch` run. Records of files that
  are gone are dropped.
- A package the output loads by name when it runs (esbuild `--external`, a webpack external, a library or SSR
  build) counted as absent. The recorded output files are now read for such loads, and the package counts
  as shipped.
- Angular's default builder records the `scripts` bundle under a made-up input name. An output made only of
  such inputs is no longer vouched for by the stats: it needs a source map (`--source-map`).
- A Vite worker imported with `?worker&inline` and built without `worker.plugins` sits in the main chunk as
  a string, where the output check could not see it. The plugin now names workers that no build of its own
  recorded, and the map is refused.
- webpack stats with grouped modules (`stats: { all: true }`, `groupModulesByPath`) were neither read nor
  refused. They are read. The bundler's runtime in the output now counts as the bundler's package.
- An esbuild or Angular metafile read from a folder that holds none of the project's source files it names
  is refused: that is not where the build ran.
- An output file the map doesn't record was accepted for having any source map beside it. The map must now
  name at least one source that is a file here or in an installed package.
- A file webpack says it copied is taken at its word only when it came from an installed package.

Deployments (`--deploy`):
- With `--bundle` and `--deploy` (or `--modules`) together, only the bundle SBOM decided the verdicts. A
  package either one names now ships. The GitHub Action passes both.
- A source map that is not beside its file was found by file name alone, first match wins; every route of a
  webpack-built Next.js app is `route.js`. A map must now sit in folders of the same names, and a map inside
  a deployed package is never taken for a bundle's.
- A source that names no file was dropped. It is now placed when it is written from the project folder
  (`webpack://_N_E/./packages/ui/…`), as a Windows path (`C:/…`), or copied from an installed package's own
  source map (`webpack://Lib/./src/x.js`, a URL). What still can't be placed is counted, and a line says so.
- Runtime loads written as `__require("x")` (esbuild's ESM output), `createRequire(…)("x")`, `"punycode/"`,
  a hashed Next.js alias, or a relative path into `node_modules` outside the deployment were not seen.
- A `--deploy` folder that does not exist was skipped without a word. So was the browser half of a build:
  `.next/standalone` without `.next/static`, `.output/server` without `.output/public`. Both stop the run.
- A folder linked into the deployment was not read. Links are followed.
- `--deploy build --deploy node_modules`, the README's own example, was refused.

Files accepted without a source map, on both routes:
- "The project's own file" compared against the working tree, so a tracked file the build had overwritten
  passed. It is compared against what git has. An accepted file is now filed under its path, so a vendored
  package's file is given to that package.
- A copy is credited to every installed file it matches, not the first: two packages can hold the same file.
  `.node` and `.wasm` files in a deployment are matched too.
- "Glue" was a file without the word `function` and with at most two arrows, which a class or an object
  with methods passes. It is now decided by parsing.

Stale and incomplete records:
- A module map from an earlier build vouched for whatever was on disk under the same file names. For webpack,
  Rspack and esbuild the size the bundler recorded for each file must now be the file's size; for the Vite
  plugin a recorded file written more than two minutes after the map stops the run, and the plugin removes
  the map an earlier build left when a new one starts. Angular's builder rewrites its files after writing
  the stats and is not held to the sizes.
- A metafile input with no `bytesInOutput` counted as dropped. Only a stated `0` does.
- webpack stats that list no runtime modules vouched for any chunk with no modules listed. Such a chunk is now
  looked at like an unrecorded file. The plugin lists runtime modules; raw stats need `runtimeModules: true`.
- A source map that names a bundle (a minifier run over a bundler's output) is followed through that bundle's
  own map when it has one. A file with two `sourceMappingURL` lines accounts for nothing. Nor does a map
  with no sources, unless the file only wires modules together, as the many small chunks Turbopack writes
  do: functions that call methods of their own parameters with literals, and compute nothing.

More places a package's code was missed:
- A deployed package that loads another from outside the deployment (hoisted above it): the loaded package
  now counts as shipped, and a line names it.
- A copy of one package published inside another's build (`node_modules/ui-kit/dist/node_modules/tslib/…`)
  counted for the inner package only. It counts for both.
- A module a webpack DLL build names `delegated ./node_modules/x/y.js from dll-reference …` is read as that file.
- Vite's own helpers in the output (`vite/preload-helper.js`) count as the `vite` package, and webpack's or
  Rspack's runtime as theirs. Advisories on code a bundler puts in its output exist.
- Compiled files in a build's output (`.wasm`, `.node`) that are exact copies of installed files name their
  package on the module-map route too.
- Code under `node_modules/.vite`, where Vite keeps dependencies it bundled ahead of time, stops the run.

Files with no source map, or with one that says nothing:
- "Glue" is decided by parsing alone: a file of translated strings may say "function", and a function with
  an empty body is not code.
- A file a build tool writes from its own template is recognised by what it is. Workbox's generated service
  worker has a source map that names a temp file, gone by the time vexproof runs; it is accepted as a loader
  plus settings, and `workbox-build` counts as shipped.
- A file the bundler says it copied, minified on the way, from a path that names no package
  (`base/worker/workerMain.js`) is given to the installed files that end in that path when most of their
  strings are in the copy. Before, such files were accepted without being given to any package.
- A relative source that climbs too far (`../../../../src/routes/+page.svelte`, as SvelteKit writes them) is
  found by what follows the dots.
- A folder inside a package that is no package itself (a test fixture) gives its files to that package.
- With `--browser-only`, a package the deployed files load by name and the deployment does not hold counts
  as shipped; the run no longer stops.

File-level rules (Pro):
- File names are compared without regard to case (`lodash/Template` on Windows and macOS).
- A package whose original sources a source map leads to (`src/parse.ts`), or that inlines source maps in
  its files, is taken whole in a deployment, like one that publishes `.map` files.

### Changed
- webpack multi-compiler stats (`children` with their own `outputPath`) are read instead of refused.
- The server check also looks at the application's own dependencies, from `package.json` and from the
  lockfile SBOM's dependency graph, for a server of its own (Express, Fastify, Koa, NestJS, Hono, Electron
  and others). In a deployment, only bundled code that loads a Node module makes it a server; a script of
  your own that does (`public/healthcheck.js`) does not.
- The VEX records a digest of the deployment's files (`vexproof:input:deployment:sha256`) where it had `-`.
- Runs take longer: the content check reads the shipped files and the installed files of absent packages.
- With a full SBOM (not `--omit dev`), findings on `vite` or `webpack` stay open for an app whose output
  holds their helper or runtime code.

### Known limits
- A source map lists what has mappings, not what is in the file: a build step that drops a dependency from
  the map (a plugin returning an empty map, a second-stage bundle with no map of its own) hides it from
  `--deploy`. The content check is the only guard, and it finds nothing for a package with no prose strings.
- For an esbuild metafile the output folder is taken from the recorded outputs; a sibling folder is searched
  by the content check only.
- A server that is in the lockfile but in neither `package.json` nor the SBOM's dependency graph is not seen.
- Helper code that Rollup or Babel inlines is not attributed to them.

## [1.0.0-beta.8] - 2026-11-12

### Fixed
Three ways a run could report `not_affected` for code that ships. Upgrade from any earlier version.
- Yarn with `nodeLinker: pnpm` installs to `node_modules/.store/<name>-npm-<version>-<hash>/package/`, and
  bundlers name modules by that path. vexproof took `.store` for the package, so every package in such a
  build counted as absent. They are read now, by the name in their `package.json`; a store folder whose
  package can't be named stops the run.
- Nitro (Nuxt) deploys a package the server needs in two versions under
  `.output/server/node_modules/.nitro/<name>@<version>/` and links one of them from the top level. `--deploy`
  does not follow links, so such a package counted as absent unless a source map also named it. Each folder
  is now read as that package at that version.
- A file in the build output counted as the project's own if any file in the project folder matched it byte
  for byte, including another build's output: a prebuilt bundle copied into the output could pass with the
  packages inside it unseen. Only files git tracks count now; outside a git checkout none do. This one came
  in with 1.0.0-beta.7.

Builds that 1.0.0-beta.7 refused, found on four open-source apps:
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

[Unreleased]: https://github.com/septakis/vexproof/compare/v1.0.0-beta.9...HEAD
[1.0.0-beta.9]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.9
[1.0.0-beta.8]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.8
[1.0.0-beta.7]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.7
[1.0.0-beta.6]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.6
[1.0.0-beta.5]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.5
[1.0.0-beta.4]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.4
[1.0.0-beta.3]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.3
[1.0.0-beta.2]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.2
[1.0.0-beta.1]: https://github.com/septakis/vexproof/releases/tag/v1.0.0-beta.1
[0.13.0]: https://www.npmjs.com/package/vexproof/v/0.13.0
[0.12.0]: https://www.npmjs.com/package/vexproof/v/0.12.0
