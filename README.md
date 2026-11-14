# vexproof

Your scanner reports vulnerabilities in everything your lockfile lists. vexproof checks which of
them actually ship, and writes the answer as VEX, CycloneDX and OpenVEX: machine-readable "not
affected" statements, with evidence, that your scanner, your customers and your auditor accept.

Keep the scanner you have. vexproof reads its output and writes VEX it applies.
Runs in your own CI, and your code never leaves it. Without a findings file, vexproof looks up
advisories by sending the package names and versions in your lockfile to OSV, and `rules derive`
downloads public packages from the npm registry.

Full guides and reference: [vexproof.dev/docs](https://vexproof.dev/docs/) (source in [septakis/vexproof-site](https://github.com/septakis/vexproof-site)).

## Free and Pro

| | Free (MIT) | Pro |
|---|---|---|
| **Package not in bundle** → `not_affected` | ✓ | ✓ |
| CycloneDX 1.6 VEX with SHA-256 of every input, and OpenVEX 0.2.0 | ✓ | ✓ |
| Reads `npm audit`, `osv-scanner`, Trivy, Grype or Snyk output, or queries OSV | ✓ | ✓ |
| GitHub Action | ✓ | ✓ |
| `vexproof review`: record a human decision in the VEX | ✓ | ✓ |
| CI gate: `--fail-on in_triage` | ✓ | ✓ |
| Preview of how many open findings Pro would settle | ✓ | |
| **Vulnerable files not in bundle** → `not_affected` (`--modules`) | | ✓ |
| **Audit report**: printable HTML with evidence, reviewer names, input hashes (`--report`) | | ✓ |
| **Baselines**: reviewed decisions carry into the next release; `--fail-on new` only fails on new risk (`--baseline`) | | ✓ |
| **Dependabot**: dismiss the GitHub alerts a VEX settles, and reopen them if it stops (`vexproof dependabot`) | | ✓ |
| **CSAF 2.0 VEX** for customers, procurement and regulators (`--csaf`) | | ✓ |
| **Signed VEX**: prove who produced a document; anyone can verify it (`--sign`, `vexproof verify`) | | ✓ |
| **Rollup**: one VEX for the whole organization from each application's (`vexproof rollup`) | | ✓ |
| Email support, with a response within a few business days (paid licenses) | | ✓ |

`vexproof verify` and `vexproof keygen` need no license: a customer verifies a signed VEX with the free tool.

On a fresh Angular 20 app with `lodash-es` (one function used), `moment` and `dompurify`
(installed, never imported), `npm audit` reports 26 advisories. Free settles 21. Pro settles the
other 5, because none of the files holding the vulnerable lodash code survived the build.

## Pipeline

```
lockfile SBOM   npm:    npx @cyclonedx/cyclonedx-npm --omit dev -o bom.lockfile.json
                pnpm:   pnpm sbom --sbom-format cyclonedx --sbom-type application --prod --out bom.lockfile.json
                Yarn 1: npx @cyclonedx/cyclonedx-npm --omit dev -o bom.lockfile.json
                Yarn 4: yarn dlx -q @cyclonedx/yarn-plugin-cyclonedx --prod --output-file bom.lockfile.json
                Bun:    npx @cyclonedx/cyclonedx-npm --omit dev -o bom.lockfile.json
                        (isolated linker: add --ignore-npm-errors; the SBOM then also lists dev tooling, which is harmless)
findings        npm audit --json · pnpm audit --json · yarn audit --json · yarn npm audit --json --recursive
                bun audit --json · or any scanner below · or omit to query OSV
module map      Vite 7/8, Rollup:  plugins: [vexproof()]  from 'vexproof/vite'  → vexproof-modules.json
                server-rendered:   --deploy <deployment folder> (with source maps on)
                webpack, Rspack:   plugins: [new VexproofPlugin()]  from 'vexproof/webpack'
                Angular 17+:       ng build --stats-json        → stats.json or browser-stats.json in the output folder
                esbuild:           metafile: true               → meta.json
                bun build:         --metafile=meta.json
bundle SBOM     optional: with --modules, vexproof lists the bundle's packages from the module map
```

### Bundler setup

```js
// vite.config.js (Vite 7 with Rollup, Vite 8 with Rolldown) or rollup.config.js ('vexproof/rollup')
import vexproof from 'vexproof/vite';
export default {
  plugins: [vexproof()],
  worker: { plugins: () => [vexproof()] },   // if you ship web workers
};

// webpack.config.js or rspack.config.js
const { VexproofPlugin } = require('vexproof/webpack');
module.exports = { plugins: [new VexproofPlugin()] };
```

Every build that ships code needs the plugin, including web workers and nested `build()` calls. You
don't have to get this right by inspection. Whatever wrote the module map (a vexproof plugin, an
esbuild metafile, Angular or webpack stats), vexproof finds the build's output folder and checks every
`.js` file in it. On Gitea that caught two bundles made by nested builds (`e2e-gitea/`). A Vite worker
imported with `?worker&inline` is no file of its own; the plugin names it instead, and the run stops.

A file the module map doesn't record is accounted for on its own, and counted as shipped where it
holds a package's code:

- it is an unmodified copy of installed files (a package file imported with `?url`, or copied by a
  plugin), or webpack recorded that it was copied from an installed package: those files shipped;
- it has a source map beside it (a service worker written by workbox) that names at least one source
  that is a file here or in an installed package: the map's sources shipped;
- it is an unmodified copy of a file as git has it in your project (from `public/`), or holds no
  code at all. An untracked file doesn't count: it may be another build's output.
  A package such a file imports by name counts as shipped.

A package the recorded output loads by name when it runs (an esbuild `--external`, a webpack external)
counts as shipped too: the product uses it, wherever it is loaded from.

**Content check.** Module maps and source maps are records, and records can be incomplete. So before a
package is called absent, vexproof looks for the package's own string literals in the JavaScript and
HTML that ship; a minifier keeps what a string says. If some are there, and no file the records name
holds them too, the finding stays open and a line says which string was found where. The check can
only keep a finding open, needs `node_modules` installed, and looks only at packages with a finding.

Packages are named by the `package.json` in their folder, not by the folder: `"tiny": "npm:ms@2"` ships
`ms`. So run vexproof where `node_modules` is installed. Without it, a shipped folder whose name the
lockfile SBOM doesn't have stops the run, since it may be another package under an alias.

Any other file stops the run, named with the reason. So does a module map that describes another
build: webpack, Rspack and esbuild record each output file's size, and the file on disk must have it;
for the Vite plugin, an output written more than two minutes after the map does it. Run vexproof on a
build before other tools change its files. So does an output folder that can't be found:
run vexproof from the folder the build ran in, or pass `--root`. In a monorepo that is the app's
folder, not the repository root.

vexproof also refuses a webpack or Rspack stats file that leaves modules out (a size limit, grouped or
filtered children, or a concatenated module whose members aren't listed). `rspack build --json` does
exactly that, whatever the config says, which is why the plugin exists.

Without --bundle, the bundle's packages come from the module map, with versions from each package's
installed `package.json` (--root) or, when it lists one version, the lockfile SBOM. The CycloneDX
webpack plugin fails on Rspack, so this is the Rspack path.

### Run

```
vexproof --lockfile bom.lockfile.json --bundle bom.bundle.json \
          --findings audit.json --modules dist/app/stats.json \
          --product pkg:npm/my-app@1.4.0 --out vex.cdx.json [--spec-version 1.7] \
          [--baseline previous.vex.cdx.json --fail-on new --report report.html]
```

`--findings` accepts `npm audit --json`, `pnpm audit --json`, `yarn audit --json` (Yarn 1),
`yarn npm audit --json --recursive` (Yarn 2+; without `--recursive` it skips transitive packages),
`bun audit --json`, `osv-scanner --format json`, `trivy … --format json`,
`grype … -o json`, `snyk test --json`, or `[{purl, ids}]`. Without it, vexproof queries OSV directly
(and looks up GHSA ↔ CVE aliases there; `--enrich-aliases` does the same for a findings file).

The same inputs write the same files: statements come in a fixed order, and each file's serial number
is derived from its content. Only the timestamps change from run to run. Set `SOURCE_DATE_EPOCH`
(seconds since 1970, the [reproducible-builds](https://reproducible-builds.org/specs/source-date-epoch/)
convention) to pin them, for example to the commit time with
`SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)`, and a VEX file committed next to its SBOM only
changes when a verdict does.

## Works with your scanner

Scanners disagree on IDs: Trivy reports npm issues by CVE, npm audit and Grype by GHSA. vexproof
carries both on every statement (from OSV and its own rules), so one VEX file matches either.

| Scanner | Give it | Command | Notes |
|---|---|---|---|
| Trivy, any target | `--openvex vex.openvex.json` | `trivy fs . --vex vex.openvex.json` | Product = the app PURL, subcomponent = the package. The app PURL must be what Trivy sees as the project root (default: the lockfile SBOM's own component). |
| Trivy, SBOM scan | `--out vex.cdx.json` | `trivy sbom bom.lockfile.json --vex vex.cdx.json` | `affects` are BOM-Links into that exact lockfile SBOM (serial + version). Trivy keeps one CycloneDX statement per ID, so prefer OpenVEX when two packages share an advisory. |
| Grype, SBOM or directory scan | `--openvex vex.openvex.json --openvex-package-products` | `grype sbom:bom.lockfile.json --vex vex.openvex.json` | Grype only matches the package's own PURL as the product on these scans, so the flag adds that form. Use that file only for this app. |
| Dependency-Track | `--out vex.cdx.json` | upload after the lockfile SBOM has been analysed ([below](#dependency-track)) | Each entry names its source (`GITHUB` for GHSA, `NVD` for CVE), which Dependency-Track 4.x needs. Applies to every component with the finding. |
| Anchore, other CycloneDX tools | `--out vex.cdx.json` | upload beside the lockfile SBOM | CycloneDX 1.6, or 1.7 with `--spec-version 1.7`, validated against the official schema. |

`interop/live.sh` runs the real Trivy and Grype on the demo app, with and without vexproof's VEX, and
checks that each one hides exactly the findings the VEX settles and still shows every other one: Trivy on
`fs` and `sbom` scans with OpenVEX, CycloneDX 1.6 and 1.7; Grype on SBOM and directory scans; VEX made from
OSV and from each scanner's own report. Run it before each release, or with `vexproof@<version>` against a
published package. It needs `trivy`, `grype` and network access. `interop/run.sh <dir>` checks the same files
without the scanners: it applies them with the matching code Trivy and Grype use (`openvex/go-vex`,
`cyclonedx-go`'s BOM-Link parser, Trivy's package-match rule) and prints what each would filter.

### Dependency-Track

Dependency-Track applies a VEX only to findings it already has, so upload the lockfile SBOM, wait for
its analysis to finish, then upload the VEX. The API key needs `BOM_UPLOAD`, `VULNERABILITY_ANALYSIS`
and, to create the project, `PROJECT_CREATION_UPLOAD`.

```bash
DT=https://dtrack.example.com; KEY="$DT_API_KEY"; NAME=my-app; VERSION=1.4.0
token=$(curl -sf -H "X-Api-Key: $KEY" -F autoCreate=true -F projectName=$NAME -F projectVersion=$VERSION \
  -F bom=@bom.lockfile.json "$DT/api/v1/bom" | jq -r .token)
while curl -sf -H "X-Api-Key: $KEY" "$DT/api/v1/event/token/$token" | jq -e .processing >/dev/null; do sleep 5; done
curl -sf -H "X-Api-Key: $KEY" -F projectName=$NAME -F projectVersion=$VERSION -F vex=@vex.cdx.json "$DT/api/v1/vex"
```

Each statement shows up as an analysis with its state, justification and vexproof's reasoning as the
details, commented "CycloneDX VEX". Two things to know:

- Dependency-Track 4.x skips any VEX entry without a source. vexproof names one on every GHSA (`GITHUB`, which
  is also where Dependency-Track's OSV mirror files GHSA advisories) and CVE (`NVD`) entry.
- Dependency-Track applies a BOM-Link statement to every component in the project that has the finding, not
  only the one linked. When two copies of a package get different verdicts on one advisory, vexproof writes
  the open statement last, so the copy that ships is never suppressed. Both end up open; review them there.

## GitHub Action

```yaml
- uses: septakis/vexproof@v1.0.0-beta.8      # after your build and SBOM steps
  with:
    lockfile: bom.lockfile.json
    bundle: dist/bom.bundle.json
    modules: dist/app/stats.json
    findings: trivy.json          # or omit to query OSV
    openvex: vex.openvex.json
    fail-on: in_triage
    license: ${{ secrets.VEXPROOF_LICENSE }}
```

## Dependabot (Pro)

Dependabot reads no VEX, so alerts for code that never shipped stay open in your repository. `vexproof dependabot`
applies the VEX to them through GitHub's API. Without a license that includes `dependabot`, it says so, changes
nothing and exits 0, `--dry-run` included:

```
vexproof dependabot --vex vex.cdx.json --lockfile bom.lockfile.json --dry-run
```

- It **dismisses** an open npm alert when the VEX settles it (`not_affected` or `false_positive`) for every
  installed version of that package inside the alert's vulnerable range. The comment starts with `vexproof:` and
  says why, with a link to the run, within GitHub's 280 characters. A version the VEX says nothing about keeps the
  alert open.
- It **reopens** an alert it dismissed earlier when a later VEX no longer settles it, for example after a new
  import brings the vulnerable code into the build.
- It **never touches** an alert a person dismissed, an alert with a dismissal request waiting for approval, or one
  on a development dependency.
- `--manifest` picks the lockfiles whose alerts to change (a file or a folder, repeatable; default the current
  folder, which is the repository root in CI). `--repo owner/name` defaults to `GITHUB_REPOSITORY`, then the git
  origin. A VEX written with `--browser-only` is refused, because a server may run packages the browser bundle
  leaves out.
- It needs a token that can **write** Dependabot alerts: a fine-grained token or GitHub App token with
  "Dependabot alerts" read and write, from `--token`, `VEXPROOF_DEPENDABOT_TOKEN`, `GH_TOKEN` or `GITHUB_TOKEN`. The
  workflow's own `GITHUB_TOKEN` can read alerts (`permissions: vulnerability-alerts: read`) but not change them, so
  it only works with `--dry-run`.
- In Actions, only a run of the repository's default branch changes alerts, because that is the branch they
  describe. Other runs preview.

The Action does this after it writes the VEX, including when `fail-on` stops the job:

```yaml
- uses: septakis/vexproof@v1.0.0-beta.8
  with:
    lockfile: bom.lockfile.json
    bundle: dist/bom.bundle.json
    dependabot: true
    dependabot-token: ${{ secrets.DEPENDABOT_ALERTS_TOKEN }}
    license: ${{ secrets.VEXPROOF_LICENSE }}
```

## Demo: vulnerable code your imports never mention

`demo/` is a dashboard that uses recharts and never imports lodash. recharts' `Treemap` does, and
the shipped bundle contains `omit.js` and `_baseUnset.js`. An import-only analysis calls all three
lodash advisories safe; vexproof settles one and keeps the two whose code ships open. See
`demo/README.md`.

## What each verdict means

- **Package not in bundle.** The package name appears in the lockfile SBOM and nowhere in the
  bundle SBOM. Justification `code_not_present`, level `package`.
- **Vulnerable files not in bundle (Pro).** The package is bundled, but the bundler's own module
  graph shows that none of the files containing the vulnerable code survived, and no full
  build of the package did either. Justification `code_not_present`, level `module`; the
  surviving file list and the rule's source are attached as evidence.
- **Open (`in_triage`).** Anything vexproof can't prove. With `--modules`, the VEX and report
  say why, e.g. `vulnerable file(s) bundled: template.js`.

When a package ships more than once (pnpm stores and npm nested installs both do this), vexproof reads
each copy's version from its installed `package.json`, or from the store path (pnpm `.pnpm/`, Bun
`.bun/`, Yarn's cache zip under Plug'n'Play or its `.store/` folder, Nitro's `.nitro/`), and checks a finding
only against the files of the copy at the vulnerable version. A vulnerable file shipping from a fixed
copy doesn't block the verdict; one shipping from the vulnerable copy always does. The VEX statement and
the report name the copy that was checked.

Module-level claims are deliberately narrow. vexproof makes no claim when:
- several copies ship and any copy's version can't be read,
- no shipped copy is at the vulnerable version, or the bundle SBOM disagrees with the copies,
- the module map and bundle SBOM disagree,
- a full build (`lodash.js`, `lodash.default.js`, `fp/`…) is bundled, or
- there is no rule for that advisory.

Rules live in `src/pro/rules/module-rules.json`. Each lists the files holding the vulnerable code, the
advisory it came from, and what it affects. They currently cover the five current lodash and
lodash-es advisories. Every rule is checked against the package source before it ships.

### Derived rules (Pro)

For packages without a hand-checked rule, vexproof can derive one from the fix itself:

```
vexproof rules derive --lockfile bom.lockfile.json --findings audit.json \
  --modules vexproof-modules.json --out vexproof-rules.derived.json
vexproof … --rules vexproof-rules.derived.json [--accept-derived]
```

For each finding it downloads the installed version and the first fixed release from the npm registry,
and takes every runtime file that changed between them. If none of those files shipped, the fix
touched no code you ship. It diffs the installed version against the fix, not the last vulnerable
release: advisory ranges can be wider than the real fix (lodash-es fixed GHSA-xxjr-mmjv-4gpg's code
in 4.17.22, a release inside its range), and the narrower diff then shows only unrelated files.

A derived rule is weaker than a hand-checked one: a fix can change a caller while the vulnerable
code sits in a file it didn't touch. So derived rules only suggest a verdict, as `in_triage` with
the reasoning, until the run passes `--accept-derived` or someone records a review. Accepted
statements carry `vexproof:rule-origin`. Hand-checked rules always win over derived ones.

How they measure, run on real data:
- On the 10 lodash and lodash-es advisories with hand-checked rules, every derived rule contains the
  file with the vulnerable code. On the Angular, recharts and Gitea builds they never cleared a
  finding the hand-checked rules keep open.
- They are coarser. A fixed release that bundles several fixes yields a rule covering all of them,
  so derived rules settled 4 fewer findings than the hand-checked ones on those builds.
- Across 841 advisories in 80 popular frontend packages, 796 got a rule. Most fixes rewrite the
  package's main file, which ships, so they settle little. The narrow ones cluster in framework
  server and compiler code (Next.js, Svelte), which the next section is about.

### Apps that also run on a server

For apps with server-side rendering (Next.js, Nuxt, SvelteKit, Remix, Angular SSR and similar), point
vexproof at what you deploy:

```
vexproof --lockfile bom.lockfile.json --findings audit.json \
  --deploy .next/standalone --deploy .next/static        # Next.js, output: 'standalone'
vexproof … --deploy .output                               # Nuxt / Nitro
vexproof … --deploy build --deploy node_modules           # anything that runs with its node_modules
                                                          # (after npm prune --omit=dev)
```

A deployment folder is evidence the same way a browser bundle is: a file that isn't deployed can't run.
vexproof reads the files copied into it (the framework's traced `node_modules`), and the source maps of
its bundled code, which name the files bundled in. Turn source maps on for the build (Next.js:
`productionBrowserSourceMaps` and `experimental.serverSourceMaps`; Nuxt:
`sourcemap: { server: true, client: 'hidden' }`; Vite: `build.sourcemap: 'hidden'`). Maps that live outside
the deployment are found in `.next`, or in folders given with `--maps`, by matching the folders they sit
in, not the file name alone.

It refuses a deployment it can't account for:
- a `--deploy` folder that doesn't exist, or the server half of a build without the browser half
  (`.next/standalone` without `.next/static`, `.output/server` without `.output/public`);
- a bundled file with no source map, unless it is an exact copy of an installed file (Next's polyfills),
  a file of yours as git has it (`public/sw.js`), a helper chunk the bundler writes itself, or glue with
  no code of its own (manifests, Next's `server.js`);
- bundled code that loads a lockfile package at runtime when that package isn't in the deployment
  (imports are parsed, so examples in comments don't count);
- a source-map source under `node_modules` that can't be traced to an installed package.

A source that names no file is placed when it is written from the project folder (`webpack://_N_E/./…`)
or copied from an installed package's own source map; what is left is counted and reported. A source map
lists what has mappings, not everything in the file, so a build step that drops a dependency from the
map hides it here: the content check above is the guard for that.

A package that publishes its own source maps is taken whole: bundler maps point through them at its
original sources (esbuild followed fast-equals' maps to `src/comparator.ts`), so its file-level rules
can't be checked. Several `--modules` and `--deploy` folders combine into one module map.

`e2e-server/` has a Next.js 16 and a Nuxt 4 app. Next.js: 9 of 17 findings settle (build-only
`postcss` and `@babel/traverse` aren't deployed; lodash's vulnerable files aren't bundled); js-yaml,
marked and semver stay open, because the server runs them. Nuxt: 4 of 11.

Without a server deployment, vexproof refuses to run when the module map records a skipped server
build or the lockfile includes one of these frameworks. `--browser-only` writes VEX for the browser
bundle alone (`vexproof:scope` = `browser-bundle`); give that artifact its own identifier with `--product`.

## Recording decisions

```
vexproof review --vex vex.cdx.json --id GHSA-f23m-r3pf-42rh \
  --state not_affected --justification code_not_reachable --same-cause \
  --detail "omit() only receives a fixed key list from src/main.js" --by "Jane Doe"
```

`--same-cause` applies the decision to every open finding on the same vulnerable files too
(GHSA-xxjr-mmjv-4gpg and GHSA-f23m-r3pf-42rh are both `_baseUnset.js`).

Next release, pass that file as `--baseline` (Pro). A review carries forward for as long as the
evidence it rests on holds, whatever the version number does. Every open statement records:

- the shipped files holding the vulnerable code, each with a content hash
  (`vexproof:vulnerable-files`, `vexproof:evidence-files`), and
- the code outside the package that imports them, found by walking the bundler's import graph back
  through the package's own files (`vexproof:importers`).

If both match, the decision carries, with the reviewer, date and reasoning kept and a note naming the
version it was made for. If either changes, the finding goes back to the reviewer with the
difference: `needs re-confirming: new importer: src/filters.js`, or `vulnerable files changed:
_baseUnset.js`. Decisions resting on things vexproof can't see (`protected_at_perimeter`,
`requires_configuration` and similar) stay tied to the exact version. Reviews older than 365 days
need re-confirming (`--review-max-age <days>`; `0` turns it off).

`--fail-on new` then fails only on findings that are open and weren't open or validly reviewed
before, including a package that used to be absent and is now bundled, and a review that needs
re-confirming. `e2e-reviews/` walks through all three cases on a real build.

Import graphs come from the esbuild metafile, the Vite plugin, and the webpack plugin (which now
includes each module's `reasons`). A module map without them falls back to version matching.

## How the code is licensed

vexproof is one npm package under two licenses.

- **Everything outside `src/pro/` is MIT** ([`LICENSE`](LICENSE)): the CLI, the bundler plugins, the
  readers for scanner output, package-level analysis, both VEX writers, `vexproof review` and
  `vexproof rules derive`. A copy with `src/pro/` deleted still runs all of it.
- **`src/pro/` is vexproof Pro** ([`src/pro/LICENSE.md`](src/pro/LICENSE.md)): module-level analysis
  and the rules that ship with it, baselines, the report, and the key check. You can read it,
  install it and pass on unmodified copies. Using the Pro features needs a license key, and the
  files can't be changed and redistributed or copied into other software. It is source-available,
  not open source.

Every source file says which it is in an `SPDX-License-Identifier` line, and a test fails if one
is in the wrong place. Without a key, vexproof uses the Pro files only to check for a key, to read
the rules that ship with it, and to count the findings Pro would settle. What vexproof writes for you (VEX, reports, rules) is yours
under either license and stays valid after a key expires.

`package.json` says `MIT AND LicenseRef-vexproof-Pro`, an SPDX expression for the two parts. A
license scanner that only allows MIT will ask about the second one.

"vexproof" and "Septakis" are trademarks of Septakis LLC. The MIT License covers the code, not the
names: a fork can use the code but needs its own name.

## License keys

A license key is a signed token, verified locally. Provide it with `--license <token|file>`,
`VEXPROOF_LICENSE`, or a `.vexproof-license` file.

- License checks make no network calls.
- A missing, invalid, expired or revoked license never fails a build; vexproof drops to free
  features and says so once.
- 14-day grace period after expiry.
- A license can be revoked before it expires. Each release carries a list of revoked license ids
  (`src/pro/revoked.json`), so a revocation applies once a user is on a version that includes it.
- `--quiet` or `VEXPROOF_QUIET=1` hides the free-tier hint.

Pro is $1,200 per organization per year, with no seats. A paid license includes email support, with
a response within a few business days.

### Open-source projects

Pro is free for open-source projects: public repositories under an OSI-approved license. An
open-source license names its repositories (`github.com/owner/repo`) and unlocks Pro only when
vexproof runs in one of them. The repository comes from `GITHUB_REPOSITORY`, GitLab's
`CI_PROJECT_PATH` or Bitbucket's `BITBUCKET_REPO_FULL_NAME`, else the `origin` remote in the
nearest `.git/config`. Elsewhere the license runs free features and says which repositories it
covers. Still no network calls. Help for open-source licenses is through GitHub issues.

### Issuing licenses (maintainer)

```
npm run keygen                      # once: .keys/license-private.pem + src/pro/license-key.js
npm run issue-license -- --org "Acme GmbH" --exp 2027-09-30
npm run issue-license -- --plan oss --org vitejs --repos github.com/vitejs/vite --exp 2027-09-30
```

Keep `.keys/` offline and backed up. Re-keying invalidates every license already issued. The
key in this repo was generated for testing; run `npm run keygen -- --force` before your first
real release.

### Revoking a license (maintainer)

```
npm run revoke-license -- --token <token|file>    # takes the id from the license itself
npm run revoke-license -- --id <license id> [--note "text"]
npm run revoke-license -- --list
```

This adds the license id to `src/pro/revoked.json`. It takes effect in the next version you
publish: runs on that version or later treat the license as invalid and use free features. The
GitHub Action runs the latest version by default, so it picks up a revocation on the next run. A
project that installs vexproof as a dependency gets it when it updates; a copy pinned to an older
version keeps accepting the license until it expires. The list, notes included, is public in the
npm package, so keep customer names out of notes.

## Tests

`npm test` runs 156 tests, including schema validation of both output formats. Most fixtures are
real builds, slimmed down:

- two Angular 20 apps, one using only `capitalize` and one also using `template` and `omit`,
- a webpack app importing `lodash/trim` per-method,
- a webpack app importing all of `lodash`,
- the recharts demo built with esbuild, webpack, Rspack, Rollup, Vite 7 and Vite 8; every bundler
  reports the same shipped lodash files,
- a lodash-es app on Vite 7 and 8 (the same 21 files as the Angular/esbuild build),
- the recharts demo installed with Yarn 1, Yarn 4 (node-modules and Plug'n'Play) and Bun (hoisted and
  isolated), with each one's real audit output; all reach npm's verdicts,
- Trivy's own npm integration golden file, and Gitea's real `pnpm audit` output,
- derived rules for the real lodash and lodash-es fixes, checked against the hand-checked rules,
- the import graph of a small lodash-es app before and after new code starts calling `omit()`,
- small deployments on disk for each rule of the deployment reader (found on real Next.js and Nuxt builds).

## Package managers

| | Install layouts tested | Findings | Copy versions from |
|---|---|---|---|
| npm | hoisted, nested | `npm audit --json` | `package.json` |
| pnpm | isolated store | `pnpm audit --json` | `package.json`, `.pnpm/` path |
| Yarn 1 | hoisted | `yarn audit --json` | `package.json` |
| Yarn 4 | node-modules, Plug'n'Play, pnpm | `yarn npm audit --json --recursive` | `package.json`, cache zip name, `.store/` path |
| Bun | hoisted, isolated | `bun audit --json` | `package.json`, `.bun/` path |

Under Plug'n'Play, Vite sees packages inside Yarn's zip cache and through `__virtual__` paths; vexproof
folds both onto one copy per package version. With `nodeLinker: pnpm`, packages sit in
`node_modules/.store/<name>-npm-<version>-<hash>/package/`; the folder name doesn't always spell the package
name, so vexproof takes it from the `package.json` inside and stops if it can't. `bun audit` gives no installed version, so vexproof
takes every version of the package in the lockfile SBOM and keeps the ones inside the advisory's range.

`e2e-gitea/` is a full run on Gitea's Vite 8 frontend.

`e2e-angular/` and `e2e-webpack/` hold the full outputs, including a sample `report.html`. Every
VEX there validates against the CycloneDX 1.6 JSON schema.

## Limits

- Hand-checked module rules cover lodash and lodash-es; derived rules cover the rest, less precisely.
  Single-file packages like DOMPurify or moment can only be settled at package level.
- For apps that also run on a server, vexproof needs the deployment (`--deploy`), with source maps on.
- `npm audit` and `bun audit` don't report installed versions; vexproof takes every version of the
  package in the lockfile SBOM that falls inside each advisory's range.
