# Server-rendered apps: Next.js 16 and Nuxt 4

Two small apps with the same shape: a server route that renders markdown with `marked` and reads YAML
with `js-yaml`, a client component using `lodash/debounce`, and tooling listed under `dependencies` that
only runs at build time or by hand (`@babel/traverse` in a codegen script; for Next.js also `postcss` with a
config file and `semver` in `next.config.mjs`).

vexproof reads what each app deploys: files the framework copied into its output, and the source maps of
its bundled code. Anything not in the deployment can't run in production.

## Next.js 16 (Turbopack, `output: 'standalone'`)

```
next build
vexproof --lockfile bom.lockfile.json --findings audit.json \
         --deploy .next/standalone --deploy .next/static
17 finding(s) → 9 not_affected (3 at module level), 8 in_triage
```

| Package | Findings | Verdict | Why |
|---|---|---|---|
| lodash 4.17.21 | 3 | not_affected, module | debounce's files ship; `template.js` and `_baseUnset.js` don't, in the browser or on the server |
| postcss 8.4.30 | 5 | not_affected, package | used by `postcss.config.mjs` at build time; not in the deployment |
| @babel/traverse 7.22.0 | 1 | not_affected, package | only used by `scripts/codegen.mjs` |
| js-yaml 4.1.0 | 5 | in_triage | loaded by the server at runtime (an external, copied into `standalone/node_modules`) |
| marked 4.0.9 | 2 | in_triage | bundled into the server chunk |
| semver 7.5.1 | 1 | in_triage | imported by `next.config.mjs`, which Next traces into the standalone output, so it is deployed |

`next.config.mjs` turns on `productionBrowserSourceMaps` and `experimental.serverSourceMaps`. The
standalone folder doesn't copy the server maps; vexproof finds them in `.next`.

Before this, vexproof refused to run on a Next.js app, or with `--browser-only` would have spoken for the
browser bundle alone, where js-yaml, marked and semver are indeed absent. The server runs all three.

## Nuxt 4 (Nitro, node-server preset)

```
nuxt build
vexproof --lockfile bom.lockfile.json --findings audit.json --deploy .output
11 finding(s) → 4 not_affected (3 at module level), 7 in_triage
```

Nitro copies individual files of the packages the server loads into `.output/server/node_modules`
(only lodash's debounce files, for example), so file-level evidence holds there too.
`nuxt.config.ts` sets `sourcemap: { server: true, client: 'hidden' }`.

## Checks that make this safe

- A bundled file without a source map is refused, unless it is an exact copy of an installed file (Next's
  polyfills) or glue code with no functions of its own (manifests, Next's `server.js`).
- Bundled code that loads a lockfile package at runtime is checked: the package must be inside the
  deployment. Imports are parsed, so examples in comments don't count.
- A package that publishes its own source maps is taken whole: bundler maps then point at its original
  sources, not the files that shipped (esbuild followed fast-equals' maps to `src/comparator.ts`).
- Source-map sources were checked against the bundlers' own module lists on the recharts demo: Vite 8 and
  webpack agree file for file, esbuild once fast-equals is traced back through its maps.
