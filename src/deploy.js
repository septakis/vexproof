// SPDX-License-Identifier: MIT
// What a deployment contains: the module map for code that runs on a server (and, with source maps, in a browser).
//
//   vexproof --deploy .next/standalone --deploy .next/static …      (Next.js, output: 'standalone')
//   vexproof --deploy .output …                                     (Nuxt / Nitro)
//
// Evidence, per file in the deployment folders:
//   node_modules/**      files copied into the deployment (traced by the framework): shipped, as they are
//   other .js/.mjs/.cjs  bundled code: its source map's `sources` name the files bundled into it
//
// A file that isn't in the deployment can't be loaded, so absence here is proof in the same sense as for a
// browser bundle. vexproof refuses to read a deployment it can't fully account for:
//   - a bundled file with no source map, unless it is an exact copy of an installed file, or data only
//     (a framework manifest: an assignment of a JSON-like literal, no functions)
//   - bundled code that loads a lockfile package at runtime (require/import of a bare name) when that package
//     isn't in the deployment: it would run from somewhere vexproof didn't look
// Packages that ship their own source maps get "whole" treatment: bundler maps then point through them to
// the package's original sources, so file-level claims can't be checked against the files that shipped.
import { readdirSync, readFileSync, statSync, existsSync, realpathSync } from 'node:fs';
import { join, dirname, resolve, relative, basename, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { builtinModules } from 'node:module';
import { parse } from 'acorn';
import { splitNodeModulesPath } from './modules.js';

const JS = /\.(m|c)?js$/;
const posix = (p) => p.split(sep).join('/');
const BUILTINS = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);

// Symbolic links to folders are not followed: a link into the deployment is walked at its real path anyway, and a
// link out of it is not part of the deployment (runtime loads through it are caught by the runtime check).
function walk(dir, out = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.isFile()) out.push(p);
    else if (e.isSymbolicLink()) { try { if (statSync(p).isFile()) out.push(p); } catch { /* dangling */ } }
  }
  return out;
}

const LOCKFILES = ['pnpm-lock.yaml', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'bun.lock', 'bun.lockb'];

/**
 * Folders whose node_modules can hold this project's packages: the root and, when the root is an app inside a
 * workspace, its parents up to the folder with the lockfile. Workspaces install packages there and link them
 * into each app's own node_modules, and links to folders are not walked. Bundlers also write source paths
 * against the workspace root. A root with its own lockfile, or with none above it, stands alone.
 */
export function installBases(root) {
  const start = resolve(root);
  const hasLock = (d) => LOCKFILES.some((f) => existsSync(join(d, f)));
  if (hasLock(start)) return [start];
  const up = [];
  for (let d = dirname(start); d !== dirname(d); d = dirname(d)) {
    up.push(d);
    if (hasLock(d)) return [start, ...up];
  }
  return [start];
}

/** Source map for a bundled file: its sourceMappingURL (inline, next to it, or elsewhere by name), or file.map. */
export function findMap(file, code, mapIndex) {
  const m = /\/[/*][#@]\s*sourceMappingURL=([^\s*]+)\s*(?:\*\/\s*)?$/.exec(code.slice(-4096));
  if (m && m[1].startsWith('data:')) {
    const b64 = /;base64,(.*)$/.exec(m[1]);
    return { map: JSON.parse(b64 ? Buffer.from(b64[1], 'base64').toString('utf8') : decodeURIComponent(m[1].split(',')[1])), at: file };
  }
  const candidates = [];
  if (m) { const u = decodeURIComponent(m[1].split('?')[0]); candidates.push(resolve(dirname(file), u), ...(mapIndex.get(basename(u)) ?? [])); }
  candidates.push(`${file}.map`, ...(mapIndex.get(`${basename(file)}.map`) ?? []));
  for (const c of candidates) if (existsSync(c)) return { map: JSON.parse(readFileSync(c, 'utf8')), at: c };
  return null;
}

/**
 * Every original file a source map names, as a path relative to the project root. `bases` are the folders
 * packages may be installed under (installBases); a package found under a parent gets a `../` path.
 */
export function mapSources(map, mapFile, root, bases = [root]) {
  const out = [];
  const visit = (m) => {
    for (const sec of m.sections ?? []) visit(sec.map);
    for (const s0 of m.sources ?? []) {
      if (!s0) continue;
      let s = s0;
      try { s = decodeURIComponent(s0); } catch { /* keep as is */ }
      // Next.js (Turbopack) names the generated stand-in for a client component after the file it stands for:
      // `<file>/__nextjs-internal-proxy.cjs { server => "…" }`. Count it as that file. That only ever adds a
      // file to what shipped, so it can't turn a finding into "not present".
      s = s.replace(/\/__nextjs-internal-proxy\.[cm]?js(?: \{[^]*)?$/, '');
      s = s.split('?')[0].replace(/^webpack:\/\/[^/]*\//, '').replace(/^turbopack:\/\/\/?(\[project\]\/)?/, '').replace(/^file:\/\//, '').replace(/^\[project\]\//, '');
      if (/^[a-z]+:/i.test(s)) continue; // other virtual sources (e.g. vite's "\0" helpers already stripped above)
      let abs = s.startsWith('/') ? s : resolve(dirname(mapFile), m.sourceRoot ?? '', s);
      const literal = posix(relative(root, abs)); // where the source points as written, before any search below
      // Some bundlers write sources against their own project root (Turbopack's "[project]" is the workspace
      // root, which may be a parent folder). If that doesn't land on a file, find the package under this root.
      const nm = s.indexOf('node_modules/');
      if (!existsSync(abs) && nm >= 0) {
        const parts = s.split('/');
        search: for (let i = 0; i < parts.length; i++) {
          const tail = parts.slice(i).join('/');
          if (!tail.includes('node_modules/')) break;
          for (const b of bases) { const cand = resolve(b, tail); if (existsSync(cand)) { abs = cand; break search; } }
        }
        if (!existsSync(abs)) {
          // not installed here: still counts as shipped. Place it under the base that holds its top folder
          // (node_modules/.pnpm, or the package's own), so it reads the same as its installed neighbours.
          const rel = s.slice(nm);
          const top = rel.split('/').slice(0, 2).join('/');
          abs = resolve(bases.find((b) => existsSync(resolve(b, top))) ?? root, rel);
        }
      }
      out.push({ path: posix(relative(root, abs)), exists: existsSync(abs), literal });
    }
  };
  visit(map);
  return out;
}

/**
 * Sources that point through a package's own published source maps name that package's original files
 * (src/*.ts), which may not be installed, and sometimes lose the package's folder on the way
 * (fast-equals: node_modules/src/comparator.ts). Index what each installed package's maps point to, so such a
 * source can be traced back to the package that shipped it.
 *
 * A source is indexed twice: where vexproof would look for it, and where the package's map literally points.
 * A bundler that chains through the package's map writes the literal path, and the two differ when that path
 * runs through a node_modules folder that was never published (@formatjs's maps name files under its build
 * tool's `node_modules/.aspect_rules_js/`).
 */
function packageMapIndex(root, bases) {
  const index = new Map();
  for (const f of bases.flatMap((b) => walk(resolve(b, 'node_modules')))) {
    if (!f.endsWith('.map')) continue;
    const owner = splitNodeModulesPath(posix(relative(root, f)));
    if (!owner) continue;
    let m;
    try { m = JSON.parse(readFileSync(f, 'utf8')); } catch { continue; }
    for (const src of mapSources(m, f, root, bases)) for (const key of [src.path, src.literal]) if (!index.has(key)) index.set(key, owner);
  }
  return index;
}

// Unmapped files that can't be carrying a package's code: framework manifests (data assignments) and launchers
// like Next.js's standalone server.js. Package code defines functions; these define none beyond a couple of
// inline callbacks. Their runtime imports are still checked.
export const isGlue = (code) => !/\bfunction\b/.test(code) && (code.match(/=>/g) ?? []).length <= 2;

/**
 * Module specifiers a bundled file loads at runtime: static and dynamic imports, re-exports, and require()
 * calls with a string argument. Parsed, not pattern-matched, so examples in comments and strings don't count.
 * Returns null when the file doesn't parse (the caller then errs on the safe side).
 */
export function loadedSpecifiers(code) {
  let ast = null;
  for (const sourceType of ['module', 'script']) {
    try { ast = parse(code, { ecmaVersion: 'latest', sourceType, allowHashBang: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowImportExportEverywhere: true }); break; } catch { /* try the other */ }
  }
  if (!ast) return null;
  const specs = new Set();
  const lit = (n) => (n?.type === 'Literal' && typeof n.value === 'string' ? n.value : n?.type === 'TemplateLiteral' && n.expressions.length === 0 ? n.quasis[0].value.cooked : null);
  // Loads that run whenever the code around them runs, as opposed to ones behind a test (if, ?:, &&, ||, ??, try,
  // case). Code meant for browsers that can also run under Node guards its Node loads that way
  // (`if (ENVIRONMENT_IS_NODE) fs = require("fs")`); a server just loads what it needs.
  specs.unguarded = new Set();
  const guards = (n, k) => ((n.type === 'IfStatement' || n.type === 'ConditionalExpression') && k !== 'test')
    || (n.type === 'LogicalExpression' && k === 'right') || (n.type === 'TryStatement' && k === 'block') || (n.type === 'SwitchCase' && k === 'consequent');
  const stack = [[ast, false]];
  while (stack.length) {
    const [n, guarded] = stack.pop();
    if (!n || typeof n.type !== 'string') continue;
    let spec = null;
    if ((n.type === 'ImportDeclaration' || n.type === 'ExportAllDeclaration' || n.type === 'ExportNamedDeclaration') && n.source) spec = n.source.value;
    else if (n.type === 'ImportExpression' && lit(n.source)) spec = lit(n.source);
    else if (n.type === 'CallExpression' && n.callee.type === 'Identifier' && n.callee.name === 'require' && lit(n.arguments[0])) spec = lit(n.arguments[0]);
    if (spec !== null) { specs.add(spec); if (!guarded) specs.unguarded.add(spec); }
    for (const k in n) {
      const v = n[k];
      if (k === 'type' || k === 'start' || k === 'end') continue;
      const g = guarded || guards(n, k);
      if (Array.isArray(v)) for (const c of v) { if (c && typeof c.type === 'string') stack.push([c, g]); }
      else if (v && typeof v.type === 'string') stack.push([v, g]);
    }
  }
  return specs;
}

const packageOf = (spec) => (spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]);
const isBare = (spec) => !/^[./]/.test(spec) && !/^[a-z]+:/i.test(spec);

/**
 * Code that loads Node's own modules runs on a server. Only loads that aren't behind a test count: browser code
 * that can also run under Node (emscripten glue, isomorphic libraries) mentions `require("fs")` too, guarded.
 */
export const usesNodeBuiltins = (specs) => [...(specs.unguarded ?? specs)].some((s) => BUILTINS.has(s) || BUILTINS.has(packageOf(s)));

/** Bare package names loaded at runtime (Node's own modules excluded). */
export function runtimeImports(specs) {
  const names = new Set();
  for (const s of specs) if (isBare(s) && !BUILTINS.has(s) && !BUILTINS.has(packageOf(s))) names.add(packageOf(s));
  return names;
}

/**
 * Where to look for source maps when --maps isn't given. Next.js keeps server maps in `.next`, outside the
 * standalone folder it deploys; in a monorepo that `.next` is the app's (apps/web/.next), not the root's.
 */
export function defaultMapDirs(dirs, root = process.cwd()) {
  const out = new Set();
  if (existsSync(resolve(root, '.next'))) out.add('.next');
  for (const d of dirs) {
    const parts = String(d).split(/[\\/]/);
    const i = parts.indexOf('.next');
    if (i < 0) continue;
    const dir = parts.slice(0, i + 1).join('/');
    if (existsSync(resolve(root, dir))) out.add(dir);
  }
  return [...out];
}

/**
 * Read deployment folders. Returns a module map ({ format, packages, graph: null, whole }) plus what
 * couldn't be accounted for ({ unmapped: [files], missingRuntime: [{ name, from }] }).
 * `lockNames` (Set of npm package names in the lockfile SBOM) limits the runtime-import check to real dependencies.
 */
export function readDeployment(dirs, { root = process.cwd(), mapDirs = [], lockNames = null } = {}) {
  const packages = new Map(), whole = new Set(), own = new Set();
  const bases = installBases(root);
  const add = (rel) => {
    const s = splitNodeModulesPath(rel);
    if (!s) { if (!/(^|\/)node_modules\//.test(rel)) own.add(rel); return; }
    if (!packages.has(s.name)) packages.set(s.name, { roots: new Set(), files: new Set(), byRoot: new Map() });
    const e = packages.get(s.name);
    e.roots.add(s.root); e.files.add(s.file);
    if (!e.byRoot.has(s.root)) e.byRoot.set(s.root, new Set());
    e.byRoot.get(s.root).add(s.file);
  };
  const files = dirs.flatMap((d) => walk(resolve(root, d)));
  const mapIndex = new Map();
  for (const f of [...files, ...mapDirs.flatMap((d) => walk(resolve(root, d)))]) if (f.endsWith('.map')) {
    if (!mapIndex.has(basename(f))) mapIndex.set(basename(f), []);
    mapIndex.get(basename(f)).push(f);
  }
  // packages present in the deployment, by the name code requires them by. Frameworks link externals under
  // hashed names (Next.js: .next/node_modules/js-yaml-77b6… -> node_modules/js-yaml); follow the link to the
  // real package, and note whether it lands inside the deployment.
  const absDirs = dirs.map((d) => { try { return realpathSync(resolve(root, d)); } catch { return resolve(root, d); } });
  const inside = (p) => absDirs.some((d) => p === d || p.startsWith(d + sep));
  const deployed = new Map(); // name as required -> { name: real package name, inside }
  const scan = (p) => { try { return readdirSync(p, { withFileTypes: true }); } catch { return []; } };
  const record = (dir, entryName) => {
    let real = null, name = entryName;
    try { real = realpathSync(dir); name = JSON.parse(readFileSync(join(real, 'package.json'), 'utf8')).name ?? entryName; } catch { /* not a package */ }
    deployed.set(entryName, { name, inside: real ? inside(real) : false });
  };
  const findNodeModules = (p) => { for (const e of scan(p)) {
    const q = join(p, e.name);
    if (e.name === 'node_modules') {
      for (const x of scan(q)) {
        if (x.name.startsWith('.')) continue;
        if (x.name.startsWith('@')) for (const y of scan(join(q, x.name))) record(join(q, x.name, y.name), `${x.name}/${y.name}`);
        else record(join(q, x.name), x.name);
      }
    } else if (e.isDirectory()) findNodeModules(q);
  } };
  for (const d of dirs) findNodeModules(resolve(root, d));

  // installed files by content, to recognise unmapped copies of package files (polyfills, runtimes)
  let byHash = null;
  const installedCopy = (code) => {
    if (!byHash) {
      byHash = new Map();
      for (const f of bases.flatMap((b) => walk(resolve(b, 'node_modules')))) if (JS.test(f)) {
        try { byHash.set(createHash('sha256').update(readFileSync(f)).digest('hex'), posix(relative(root, f))); } catch { /* unreadable */ }
      }
    }
    return byHash.get(createHash('sha256').update(code).digest('hex'));
  };

  const unmapped = [], missingRuntime = [], unparsed = [], unattributed = [];
  let pkgMaps = null;
  let mapped = 0, copied = 0, serverCode = 0;
  for (const f of files) {
    if (!JS.test(f) && !f.endsWith('.json') && !f.endsWith('.node')) continue;
    const rel = posix(relative(root, f));
    if (/(^|\/)node_modules\//.test(rel)) { if (!f.endsWith('.map')) { add(rel); copied++; } continue; }
    if (!JS.test(f)) continue;
    const code = readFileSync(f, 'utf8');
    const specs = loadedSpecifiers(code);
    if (!specs) { unparsed.push(rel); continue; }
    if (usesNodeBuiltins(specs)) serverCode++;
    for (const spec of runtimeImports(specs)) {
      const d = deployed.get(spec);
      const name = d?.name ?? spec;
      if (lockNames && !lockNames.has(name)) continue; // not installed, so it can't hold a finding
      if (!d?.inside) missingRuntime.push({ name, from: rel });
    }
    const found = findMap(f, code, mapIndex);
    if (found) {
      mapped++;
      for (const src of mapSources(found.map, found.at, root, bases)) {
        if (src.exists) { add(src.path); continue; }
        // not a real file: a source reached through a package's own map, or a bundler's virtual module
        const s0 = splitNodeModulesPath(src.path);
        if (s0 && existsSync(resolve(root, s0.root))) { add(src.path); whole.add(s0.name); continue; }
        pkgMaps ??= packageMapIndex(root, bases);
        const owner = pkgMaps.get(src.path) ?? pkgMaps.get(src.literal);
        if (owner) { add(`${owner.root}/${owner.file}`); whole.add(owner.name); continue; }
        if (/(^|\/)node_modules\//.test(src.path)) unattributed.push(`${src.path} (in ${rel})`);
        // else: bundler runtime or virtual module (webpack/bootstrap, \0commonjsHelpers, [turbopack]/runtime…)
      }
      continue;
    }
    const copy = installedCopy(code);
    if (copy) { add(copy); continue; }
    if (isGlue(code)) continue;
    unmapped.push(rel);
  }

  // packages that publish source maps: bundler maps chain through them to files that didn't ship
  for (const name of packages.keys()) {
    for (const root0 of packages.get(name).roots) {
      const dir = resolve(root, root0);
      if (existsSync(dir) && walk(dir).some((f) => f.endsWith('.map'))) whole.add(name);
    }
  }
  return {
    format: `deployment (${dirs.join(', ')}; ${copied} deployed package files, ${mapped} bundled files with source maps)`,
    packages, graph: null, whole, own, unmapped: [...unmapped, ...unparsed], unattributed, missingRuntime,
    hasServer: copied > 0 || serverCode > 0, // a server's own files, or code that loads Node's modules unguarded
  };
}

/** One module map from several (browser + server, several deployments). The import graph survives only if all have one. */
export function mergeModuleMaps(maps) {
  if (maps.length === 1) return maps[0];
  const packages = new Map(), whole = new Set(), own = new Set();
  for (const m of maps) {
    for (const n of m.whole ?? []) whole.add(n);
    for (const p of m.own ?? []) own.add(p);
    for (const [name, e] of m.packages) {
      if (!packages.has(name)) packages.set(name, { roots: new Set(), files: new Set(), byRoot: new Map() });
      const t = packages.get(name);
      for (const r of e.roots) t.roots.add(r);
      for (const f of e.files) t.files.add(f);
      for (const [r, fs] of e.byRoot ?? []) { if (!t.byRoot.has(r)) t.byRoot.set(r, new Set()); for (const f of fs) t.byRoot.get(r).add(f); }
    }
  }
  let graph = null;
  if (maps.every((m) => m.graph)) {
    graph = { importers: new Map(), shipped: new Set() };
    for (const m of maps) {
      for (const k of m.graph.shipped) graph.shipped.add(k);
      for (const [k, v] of m.graph.importers) { if (!graph.importers.has(k)) graph.importers.set(k, new Set()); for (const x of v) graph.importers.get(k).add(x); }
    }
  }
  return { format: maps.map((m) => m.format).join(' + '), packages, graph, whole, own };
}
