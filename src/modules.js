// SPDX-License-Identifier: MIT
// Which files of each npm package survived into the shipped output.
import { readFileSync } from 'node:fs';
import { join, posix } from 'node:path';
// Sources: esbuild metafile (esbuild, Bun, Angular 17+ `ng build --stats-json`)
//          webpack or Rspack stats JSON (`webpack --json=stats.json`)
//          vexproof-modules.json from the vexproof/vite plugin (Vite 7/8, Rollup)

const UNNAMED = '.store/';
const storeNames = new Map(); // Yarn store folder -> the package in it, once attachVersions has read its package.json

/** Packages in Yarn's store whose name could not be read: nothing can be said about them, so a run must stop. */
export const unnamedStorePackages = (moduleMap) => [...moduleMap.packages].filter(([n]) => n.startsWith(UNNAMED)).flatMap(([, e]) => [...e.roots]);

/**
 * "@a-b-c-npm-1.0.0-<hash>" is @a/b-c or @a-b/c, so the name comes from the package.json inside; the folder
 * name is used only when that can't be read and leaves no doubt.
 */
function nameFromYarnStore(folder) {
  const m = /^(.+)-npm-\d[^/]*-[0-9a-f]{10}$/.exec(folder);
  if (!m) return undefined;
  if (!m[1].startsWith('@')) return m[1];
  const parts = m[1].split('-');
  return parts.length === 2 ? parts.join('/') : undefined;
}

function nameStorePackages(moduleMap, cwd, read) {
  for (const [key, entry] of [...moduleMap.packages]) {
    if (!key.startsWith(UNNAMED)) continue;
    const folder = key.slice(UNNAMED.length);
    let name;
    for (const root of entry.roots) { try { name = read(join(cwd, root, 'package.json')).name; } catch { /* not installed here */ } if (name) break; }
    name ??= nameFromYarnStore(folder);
    if (typeof name !== 'string' || !name || name.startsWith('.')) continue;
    storeNames.set(folder, name);
    moduleMap.packages.delete(key);
    if (!moduleMap.packages.has(name)) moduleMap.packages.set(name, { roots: new Set(), files: new Set(), byRoot: new Map() });
    const to = moduleMap.packages.get(name);
    for (const r of entry.roots) to.roots.add(r);
    for (const f of entry.files) to.files.add(f);
    for (const [r, fs] of entry.byRoot ?? []) { if (!to.byRoot.has(r)) to.byRoot.set(r, new Set()); for (const f of fs) to.byRoot.get(r).add(f); }
    if (moduleMap.whole?.delete(key)) moduleMap.whole.add(name);
  }
}

/** "./node_modules/a/node_modules/@s/pkg/lib/x.js" ->{ name:"@s/pkg", root:"node_modules/a/node_modules/@s/pkg", file:"lib/x.js" } */
export function splitNodeModulesPath(p) {
  // drop webpack loader prefixes ("babel-loader!./x") and query strings first, then the leading "./"
  const path = String(p).replace(/\\/g, '/').replace(/^.*!/, '').replace(/\?.*$/, '').replace(/^\.\//, '');
  const idx = path.lastIndexOf('node_modules/');
  if (idx < 0) return null;
  const rest = path.slice(idx + 'node_modules/'.length).split('/');
  // Two stores keep packages in a dot folder, where the folder after node_modules is not the package:
  //   Nitro  .nitro/<name>@<version>/<file>                              each version a server needs (Nuxt)
  //   Yarn   .store/<name>-<protocol>-<version>-<hash>/package/<file>    nodeLinker: pnpm
  const before = path.slice(0, idx) + 'node_modules/';
  if (rest[0] === '.nitro') {
    const n = rest[1]?.startsWith('@') ? 2 : 1;
    const at = (rest[n] ?? '').lastIndexOf('@');
    const file = rest.slice(n + 1).join('/');
    if (at > 0 && file) return { name: [...rest.slice(1, n), rest[n].slice(0, at)].join('/'), root: before + rest.slice(0, n + 1).join('/'), file };
  }
  if (rest[0] === '.store' && rest[1] && rest[2] === 'package') {
    // the folder doesn't spell the name unambiguously; until attachVersions reads it, the folder stands in for it
    const file = rest.slice(3).join('/');
    return file ? { name: storeNames.get(rest[1]) ?? `${UNNAMED}${rest[1]}`, root: before + rest.slice(0, 3).join('/'), file } : null;
  }
  const nameParts = rest[0]?.startsWith('@') ? rest.slice(0, 2) : rest.slice(0, 1);
  if (!nameParts.length || nameParts.some((s) => !s)) return null;
  const name = nameParts.join('/');
  const file = rest.slice(nameParts.length).join('/');
  let root = path.slice(0, idx) + 'node_modules/' + name;
  // Yarn Plug'n'Play serves packages from zip archives in a cache that is often outside the project
  // (~/.yarn/berry/cache), sometimes via .yarn/__virtual__/ paths. Key the copy by its archive name:
  // stable across machines, no home directory in the evidence, and virtual paths collapse onto one copy.
  const zip = /([^/]+\.zip)\/node_modules\/$/.exec(path.slice(0, idx + 'node_modules/'.length));
  if (zip) root = `yarn-cache/${zip[1]}/node_modules/${name}`;
  return file ? { name, root, file } : null;
}

export function detectModuleFormat(json) {
  if (json && json.vexproof === 1 && typeof json.outputs === 'object') return 'vite-modules';
  if (json && typeof json.outputs === 'object' && typeof json.inputs === 'object') return 'esbuild-metafile';
  if (json && Array.isArray(json.modules)) return 'webpack-stats';
  if (json && Array.isArray(json.children) && json.children.some((c) => Array.isArray(c.modules))) return 'webpack-stats';
  if (json && Array.isArray(json.chunks) && json.chunks.some((c) => Array.isArray(c.modules))) return 'webpack-stats'; // Angular's webpack-based builder
  throw new Error('Unrecognised module map (expected vexproof-modules.json, an esbuild or bun build metafile, Angular stats.json, or webpack stats JSON)');
}

/** Record one shipped file of an installed package in a module map's `packages`. Paths outside node_modules are skipped. */
export function addToMap(map, path) {
  const s = splitNodeModulesPath(path);
  if (!s) return;
  if (!map.has(s.name)) map.set(s.name, { roots: new Set(), files: new Set(), byRoot: new Map() });
  const e = map.get(s.name);
  e.roots.add(s.root);
  e.files.add(s.file);
  if (!e.byRoot.has(s.root)) e.byRoot.set(s.root, new Set());
  e.byRoot.get(s.root).add(s.file);
}
const add = addToMap;

/** A shipped module that is not in node_modules: the app's own source, or a workspace package bundled from source. */
const outsideNodeModules = (path) => !/(^|\/)node_modules\//.test(String(path).replace(/\\/g, '/'));

/**
 * Package stores name each copy's folder or archive after its version:
 *   pnpm  node_modules/.pnpm/<name>@<version>[_peers|(peers)]/node_modules/<name>   (scope "/" → "+")
 *   Bun   node_modules/.bun/<name>@<version>[+hash]/node_modules/<name>              (scope "/" → "+")
 *   Yarn  yarn-cache/<name>-npm-<version>-<hash>-<key>.zip/node_modules/<name>       (scope "/" → "-")
 *   Yarn  node_modules/.store/<name>-npm-<version>-<hash>/package                    (nodeLinker: pnpm)
 *   Nitro node_modules/.nitro/<name>@<version>
 * The version is returned only when the name in the path matches the package.
 */
export function versionFromStorePath(root, name) {
  let m = /(?:^|\/)\.(?:pnpm|bun)\/((?:@[^/@]+\+)?[^/@]+)@([^/_(+]+)/.exec(root);
  if (m && m[1].replace('+', '/') === name) return m[2];
  m = /(?:^|\/)([^/]+)-npm-(.+?)-[0-9a-f]{10}-[0-9a-z]{1,8}\.zip\//.exec(root);
  if (m && m[1] === name.replace('/', '-')) return m[2];
  m = /(?:^|\/)\.nitro\/((?:@[^/@]+\/)?[^/@]+)@([^/]+)$/.exec(root);
  if (m && m[1] === name) return m[2];
  m = /(?:^|\/)\.store\/([^/]+)-npm-(\d[^/]*)-[0-9a-f]{10}\/package$/.exec(root);
  if (m && m[1] === name.replace('/', '-')) return m[2];
  return undefined;
}
export const versionFromPnpmPath = versionFromStorePath; // v0.6 name

/**
 * Version of every shipped copy, from its installed package.json (under cwd) or, failing that, pnpm's
 * store path. Copies with no readable version stay undefined, and file-level rules then make no claim.
 */
export function attachVersions(moduleMap, { cwd = process.cwd(), readJson } = {}) {
  const read = readJson ?? ((p) => JSON.parse(readFileSync(p, 'utf8')));
  nameStorePackages(moduleMap, cwd, read);
  for (const [name, entry] of moduleMap.packages) {
    entry.versionByRoot = new Map();
    for (const root of entry.roots) {
      let version;
      try { version = read(join(cwd, root, 'package.json')).version; } catch { /* not installed here */ }
      version ??= versionFromStorePath(root, name);
      entry.versionByRoot.set(root, version);
    }
  }
  return moduleMap;
}

/** The same file as bundlers name it in different places: no loader prefix, query, "./" or concatenation suffix. */
export const moduleKey = (p) => String(p).replace(/\\/g, '/').replace(/^.*!/, '').replace(/\?.*$/, '').replace(/^\.\//, '').replace(/ \+ \d+ modules?$/, '');

/**
 * Who imports whom, when the module map records it: Map<key, Set<key of an importer>>, plus the keys that
 * shipped code. null when the file has no import data (older plugin output, slimmed or hand-made maps).
 */
function graphFrom(edges, shipped) {
  if (!edges.length) return null;
  const importers = new Map();
  for (const [from, to] of edges) {
    const t = moduleKey(to), f = moduleKey(from);
    if (!importers.has(t)) importers.set(t, new Set());
    importers.get(t).add(f);
  }
  return { importers, shipped: new Set([...shipped].map(moduleKey)) };
}

function fromEsbuild(meta) {
  const map = new Map(), shipped = new Set(), edges = [], own = new Set();
  for (const out of Object.values(meta.outputs ?? {})) {
    for (const [path, info] of Object.entries(out.inputs ?? {})) {
      if ((info?.bytesInOutput ?? 0) > 0) { add(map, path); shipped.add(path); if (outsideNodeModules(path)) own.add(moduleKey(path)); }
    }
  }
  for (const [path, info] of Object.entries(meta.inputs ?? {})) for (const i of info?.imports ?? []) if (!i.external) edges.push([path, i.path]);
  return { map, graph: graphFrom(edges, shipped), own };
}

const CONCATENATED = / \+ (\d+) modules?$/;

/**
 * Rspack 2.0 names some members of a concatenated module after the concatenation itself
 * ("./a/index.js + 15 modules" for a/Trans.js): inside the root's member list, and again as orphan entries of
 * their own. The member's real file is in nameForCondition. Such an entry has the label and no members, and is
 * either inside a member list (concatenations don't nest) or an orphan in no chunk. A root whose members were
 * left out is neither, so it is still caught.
 */
const mislabelled = (m, nested) => CONCATENATED.test(m.name ?? '') && !(m.modules?.length) && typeof m.nameForCondition === 'string'
  && (nested || Boolean(m.orphan && !(m.chunks?.length)));

/** Module lists of a stats file: its own, per chunk (Angular's webpack-based builder keeps them only there), and the same for child compilations. */
function moduleLists(stats) {
  const lists = [];
  const take = (s, where) => {
    if (Array.isArray(s.modules)) lists.push({ modules: s.modules, where });
    for (const c of s.chunks ?? []) if (Array.isArray(c.modules)) lists.push({ modules: c.modules, where: `${where}, chunk ${c.names?.[0] ?? c.id}`, filtered: c.filteredModules });
  };
  take(stats, 'modules');
  for (const c of stats.children ?? []) take(c, 'child');
  return lists;
}

/**
 * Stats JSON can silently leave modules out: a size limit (filteredModules), grouped or filtered children
 * (filteredChildren), or a concatenated module ("./x.js + 190 modules") whose members are not listed. Any of
 * these would make shipped code look absent, so such a file is refused rather than trusted.
 */
export function webpackStatsGaps(stats) {
  const gaps = [];
  const check = (mods, where, nested) => {
    for (const m of mods ?? []) {
      // the bundler's own runtime (chunk loading, module registry) never comes from node_modules
      if ((m.filteredChildren ?? 0) > 0 && m.type !== 'runtime modules') gaps.push(`${where}: ${m.filteredChildren} modules filtered out of "${m.name ?? m.type}"`);
      const n = CONCATENATED.exec(m.name ?? '');
      if (n && !mislabelled(m, nested)) {
        const listed = (m.modules ?? []).filter((x) => x.name).length;
        if (listed < Number(n[1])) gaps.push(`"${m.name}" lists ${listed} of its ${n[1]} concatenated modules`);
      }
      check(m.modules, where, true);
    }
  };
  if ((stats.filteredModules ?? 0) > 0) gaps.push(`${stats.filteredModules} modules filtered out (modulesSpace limit)`);
  for (const c of stats.children ?? []) if ((c.filteredModules ?? 0) > 0) gaps.push(`${c.filteredModules} modules filtered out of a child compilation`);
  for (const l of moduleLists(stats)) {
    if ((l.filtered ?? 0) > 0) gaps.push(`${l.filtered} modules filtered out of ${l.where}`);
    check(l.modules, l.where, false);
  }
  return gaps;
}

function fromWebpack(stats) {
  const gaps = webpackStatsGaps(stats);
  if (gaps.length) {
    throw new Error(
      `This stats file leaves modules out, so shipped code could look absent: ${gaps.slice(0, 3).join('; ')}. ` +
      (stats.vexproofBundler
        ? `It was written by the VexproofPlugin under ${stats.vexproofBundler}, so this is the bundler's doing: try a newer release of it.`
        : `Use the VexproofPlugin from 'vexproof/webpack' (required for Rspack, whose --json flag ignores stats options), ` +
          `or set stats { modules, nestedModules, orphanModules: true, modulesSpace: Infinity, nestedModulesSpace: Infinity }.`)
    );
  }
  const lists = moduleLists(stats);
  const map = new Map(), shipped = new Set(), edges = [], own = new Set();

  // The project folder as the bundler saw it: what a relative module name leaves off its absolute path.
  let context;
  const findContext = (mods) => {
    for (const m of mods ?? []) {
      const name = String(m.name ?? ''), abs = typeof m.nameForCondition === 'string' ? m.nameForCondition.replace(/\\/g, '/') : '';
      if (name.startsWith('./') && !CONCATENATED.test(name) && abs.endsWith(name.slice(1))) return abs.slice(0, abs.length - name.length + 1);
      const below = findContext(m.modules);
      if (below) return below;
    }
    return null;
  };
  const realName = (m) => {
    const abs = m.nameForCondition.replace(/\\/g, '/');
    if (context === undefined) { context = null; for (const l of lists) { context = findContext(l.modules); if (context) break; } }
    if (!context) return abs;
    const rel = posix.relative(context, abs);
    return rel.startsWith('.') ? rel : `./${rel}`;
  };

  const visit = (mods, parentIncluded) => {
    for (const m of mods ?? []) {
      const included = parentIncluded || (Array.isArray(m.chunks) && m.chunks.length > 0);
      if (!included || m.orphan && !parentIncluded) { visit(m.modules, false); continue; }
      // concatenated roots are named "./x.js + 12 modules"; their members arrive via m.modules
      const name = parentIncluded && mislabelled(m, true) ? realName(m) : String(m.name ?? m.identifier ?? '').replace(CONCATENATED, '');
      add(map, name);
      shipped.add(name);
      if (name && outsideNodeModules(name)) own.add(moduleKey(name));
      for (const r of m.reasons ?? []) if (r.moduleName) edges.push([r.moduleName, name]);
      visit(m.modules, true);
    }
  };
  for (const l of lists) visit(l.modules, false);
  return { map, graph: graphFrom(edges, shipped), own };
}

/** Map<packageName, { roots:Set<string>, files:Set<string> }> */
export function readModuleMap(json) {
  const fmt = detectModuleFormat(json);
  const { map, graph, own } = fmt === 'webpack-stats' ? fromWebpack(json) : fromEsbuild(json); // the Vite plugin writes the metafile shape
  const label = fmt === 'vite-modules' ? `vite-modules (${json.bundler ?? 'unknown bundler'})` : fmt === 'webpack-stats' && json.vexproofBundler ? `webpack-stats (${json.vexproofBundler})` : fmt;
  return { format: label, packages: map, graph, own };
}

/**
 * A minimal bundle SBOM built from the module map, for bundlers the CycloneDX plugins don't support
 * (Rspack) or to skip that plugin entirely. Versions come from each package's installed package.json
 * under `cwd`, or from the lockfile SBOM when it lists exactly one version; otherwise none is claimed.
 */
export function bundleSbomFromModules(moduleMap, { lockfileSbom = null, cwd = process.cwd(), readJson } = {}) {
  const read = readJson ?? ((p) => JSON.parse(readFileSync(p, 'utf8')));
  const lockVersions = new Map();
  for (const c of flatten(lockfileSbom?.components)) {
    const m = /^pkg:npm\/(.+)@([^@?#]+)/.exec(c.purl ?? '');
    if (!m) continue;
    const name = decodeURIComponent(m[1]);
    if (!lockVersions.has(name)) lockVersions.set(name, new Set());
    lockVersions.get(name).add(m[2]);
  }
  const unnamed = unnamedStorePackages(moduleMap);
  if (unnamed.length) throw new Error(`Can't tell which package is in ${unnamed[0]}${unnamed.length > 1 ? ` (and ${unnamed.length - 1} more)` : ''}: its package.json could not be read`);
  const components = [], seen = new Set();
  for (const [name, entry] of moduleMap.packages) {
    // a dot folder in node_modules that is not a package store (.cache, .prisma): no npm package is named like that
    if (name.startsWith('.')) continue;
    for (const root of entry.roots) {
      let version = entry.versionByRoot?.get(root);
      if (!version) try { version = read(join(cwd, root, 'package.json')).version; } catch { /* not installed here */ }
      version ??= versionFromStorePath(root, name);
      if (!version && lockVersions.get(name)?.size === 1) version = [...lockVersions.get(name)][0];
      const enc = name.startsWith('@') ? `%40${name.slice(1)}` : name;
      const purl = `pkg:npm/${enc}${version ? '@' + version : ''}`;
      if (seen.has(purl)) continue; // one copy linked from two places, or two copies of one version
      seen.add(purl);
      components.push({ type: 'library', name, ...(version ? { version } : {}), purl });
    }
  }
  return { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, metadata: { tools: { components: [{ type: 'application', name: 'vexproof', description: `derived from ${moduleMap.format}` }] } }, components };
}

function flatten(list, out = []) {
  for (const c of list ?? []) { out.push(c); flatten(c.components, out); }
  return out;
}
