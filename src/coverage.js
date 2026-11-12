// SPDX-License-Identifier: MIT
// Is every JavaScript file the build wrote accounted for?
//
// A module map lists the files a bundler put into its chunks. A build output usually holds more than chunks:
// files copied in by a plugin or from public/, package files imported by URL, a service worker another tool
// wrote, a worker from a build that had no plugin. A package that ships only in such a file would look absent,
// and "not affected" would be wrong. So for every module-map format vexproof finds the output folder, lists
// the JavaScript in it that the map does not record, and accounts for each such file on its own:
//
//   glue      empty, or no functions and no package imports: nothing of a package can be in it
//   mapped    it has a source map: the map's sources are what it contains
//   copy      byte-identical to an installed package file: that file shipped
//   own       byte-identical to a file git tracks in the project (public/sw.js): the project's own code
//
// Anything else is refused, with the reason for each file. Finding no output folder at all is refused too:
// a check that can't run must not pass.
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve, relative, dirname, isAbsolute, sep } from 'node:path';
import { detectModuleFormat, splitNodeModulesPath } from './modules.js';
import { mapSources, findMap, loadedSpecifiers, runtimeImports, isGlue, installBases } from './deploy.js';
import { copyFinder } from './copies.js';

const JS = /\.(m|c)?js$/;
const posix = (p) => p.split(sep).join('/');

/** The build output can't be located or isn't described: the caller refuses with this message. */
export class CoverageError extends Error {}

const WHERE = 'Run vexproof from the folder the build ran in, or pass --root, so the build output can be checked.';

/** JavaScript files under a folder. Links to folders are not followed. */
function jsFiles(dir, recurse, out = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) { if (recurse) jsFiles(p, true, out); } else if (JS.test(e.name)) out.push(p);
  }
  return out;
}

/** The folder every path shares, as posix segments; '.' when they share none. */
function commonDir(paths) {
  let parts = null;
  for (const p of paths) {
    const d = p.split('/').slice(0, -1);
    if (!parts) { parts = d; continue; }
    let i = 0;
    while (i < parts.length && i < d.length && parts[i] === d[i]) i++;
    parts = parts.slice(0, i);
  }
  return parts?.length ? parts.join('/') : '.';
}

/**
 * Where a module map says the build wrote JavaScript, and which files there it records.
 * `file` is the module map's own path (Angular writes its stats into the output folder, with names relative
 * to it). Returns { dirs: [{ abs, recurse }], isCovered(abs) }; throws CoverageError when the output can't be found.
 */
export function recordedOutputs(json, { root = process.cwd(), file = null } = {}) {
  const fmt = detectModuleFormat(json);
  const here = resolve(root);

  if (fmt === 'vite-modules') {
    const keys = Object.keys(json.outputs ?? {});
    if (!Array.isArray(json.outDirs) || !json.outDirs.length) {
      throw new CoverageError('this module map does not record where the build wrote its files (it was written by an older vexproof plugin). Rebuild with the current plugin.');
    }
    const covered = new Set(keys.map((k) => resolve(here, k)));
    const dirs = [];
    for (const d of json.outDirs) {
      const abs = resolve(here, d);
      if (existsSync(abs)) { dirs.push({ abs, recurse: d !== '.' }); continue; }
      // a folder the build recorded chunks in must be here; one it wrote nothing to (a skipped pass) need not be
      if (keys.some((k) => d === '.' || k.startsWith(`${d}/`))) {
        throw new CoverageError(`the module map records build output in "${d}", but ${posix(abs)} does not exist. ${WHERE}`);
      }
    }
    return { dirs, isCovered: (abs) => covered.has(abs) };
  }

  if (fmt === 'esbuild-metafile') {
    const keys = Object.keys(json.outputs ?? {}).filter((k) => JS.test(k)).map((k) => k.replace(/\\/g, '/'));
    if (!keys.length) return { dirs: [], isCovered: () => true };
    const found = (base) => keys.some((k) => existsSync(resolve(base, k)));
    if (found(here)) {
      const covered = new Set(keys.map((k) => resolve(here, k)));
      const top = commonDir(keys);
      // outputs written straight into the project folder: check the folders that hold them, without descending
      const dirs = top === '.'
        ? [...new Set(keys.map((k) => dirname(resolve(here, k))))].map((abs) => ({ abs, recurse: abs !== here }))
        : [{ abs: resolve(here, top), recurse: true }];
      return { dirs, isCovered: (abs) => covered.has(abs) };
    }
    const beside = file ? dirname(resolve(file)) : null;
    if (beside && found(beside)) {
      const covered = new Set(keys.map((k) => resolve(beside, k)));
      return { dirs: [{ abs: beside, recurse: true }], isCovered: (abs) => covered.has(abs) };
    }
    if (beside) {
      // Angular with localize: one stats file, and a copy of every output in a folder per locale
      let subs = [];
      try { subs = readdirSync(beside, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name); } catch { /* unreadable */ }
      if (subs.some((s) => found(join(beside, s)))) {
        const names = new Set(keys);
        return {
          dirs: [{ abs: beside, recurse: true }],
          isCovered: (abs) => { const rel = posix(relative(beside, abs)); return names.has(rel) || names.has(rel.split('/').slice(1).join('/')); },
        };
      }
    }
    throw new CoverageError(`none of the ${keys.length} JavaScript files this module map lists as build output were found under ${posix(here)}${beside ? ` or beside the module map` : ''}. ${WHERE}`);
  }

  // webpack or Rspack stats
  const out = json.vexproofOutDir != null ? resolve(here, json.vexproofOutDir)
    : typeof json.outputPath === 'string' ? (isAbsolute(json.outputPath) ? json.outputPath : resolve(here, json.outputPath)) : null;
  if (!out || !Array.isArray(json.assets)) {
    throw new CoverageError(json.vexproofBundler
      ? 'this module map does not record where the build wrote its files or which files it emitted (it was written by an older VexproofPlugin). Rebuild with the current plugin.'
      : "this stats file does not say where the build wrote its files or which files it emitted (no outputPath or assets), so vexproof cannot check that every shipped file is accounted for. Use the VexproofPlugin from 'vexproof/webpack', or keep outputPath and assets in the stats.");
  }
  if (!existsSync(out)) throw new CoverageError(`the module map records build output in ${posix(out)}, which does not exist. ${WHERE}`);
  const covered = new Set(), copiedFrom = new Map();
  const take = (s, dir) => {
    // Chunks that have modules listed. One with none is raw files a plugin joined together (the `scripts` of
    // Angular's webpack-based builder): the stats say nothing about what is in it. That can only be told apart
    // from a chunk holding just the bundler's runtime when the stats list runtime modules too.
    const full = new Set();
    let listsRuntime = false;
    const walk = (mods) => { for (const m of mods ?? []) { for (const c of m.chunks ?? []) full.add(String(c)); if (m.moduleType === 'runtime') listsRuntime = true; walk(m.modules); } };
    walk(s.modules);
    for (const c of s.chunks ?? []) { if (c.modules?.length) full.add(String(c.id)); walk(c.modules); }
    for (const a of s.assets ?? []) {
      const abs = resolve(dir, String(a.name).split('?')[0]);
      // a file emitted for a chunk, or for a module of a chunk (asset modules), has its modules in the stats;
      // one that a plugin copied in belongs to no chunk
      if ((a.chunks ?? []).some((c) => !listsRuntime || full.has(String(c))) || (a.auxiliaryChunks?.length ?? 0) > 0) covered.add(abs);
      // copy-webpack-plugin says where it took a file from. The copy is often minified on the way, so it would
      // not match the installed file byte for byte; the bundler's own record of its origin stands instead.
      else if (a.info?.copied && typeof a.info.sourceFilename === 'string') copiedFrom.set(abs, a.info.sourceFilename.replace(/\\/g, '/'));
    }
  };
  take(json, out);
  for (const c of json.children ?? []) take(c, typeof c.outputPath === 'string' && isAbsolute(c.outputPath) ? c.outputPath : out);
  return { dirs: [{ abs: out, recurse: true }], isCovered: (abs) => covered.has(abs), copiedFrom };
}

/**
 * JavaScript files in the recorded output folders that the module map does not record: `stray` (absolute
 * paths, to be accounted for one by one) and `copied` ([{ file, from }], files whose origin the bundler recorded).
 */
export function strayOutputs(json, opts = {}) {
  const { dirs, isCovered, copiedFrom = new Map() } = recordedOutputs(json, opts);
  const seen = new Set(), copied = [];
  for (const d of dirs) for (const f of jsFiles(d.abs, d.recurse)) {
    if (isCovered(f)) continue;
    if (copiedFrom.has(f)) copied.push({ file: f, from: copiedFrom.get(f) }); else seen.add(f);
  }
  return { stray: [...seen].sort(), copied, dirs: dirs.map((d) => d.abs) };
}

/**
 * Account for the output files a module map does not record. Returns
 *   { accounted: [{ file, kind, adds, whole, loads }], unknown: [{ file, why }] }
 * with `file` relative to root, `adds` the shipped paths the file stands for (relative to root, as a module
 * map names them), `whole` the packages whose files can't be told apart through it, and `loads` the packages
 * it imports by name at runtime.
 */
export function accountFor(stray, { root = process.cwd(), outDirs = [] } = {}) {
  const here = resolve(root);
  const bases = installBases(here);
  const copies = copyFinder({ root: here, bases, outDirs });
  const accounted = [], unknown = [];
  for (const abs of stray) {
    const file = posix(relative(here, abs));
    let buf;
    try { buf = readFileSync(abs); } catch { unknown.push({ file, why: 'could not be read' }); continue; }
    const code = buf.toString('utf8');
    const specs = buf.length ? loadedSpecifiers(code) : new Set();
    // A file that ships as it is and imports a package by name gets that package from somewhere vexproof can't
    // see (an import map, a loader, another bundle). The caller counts such a package as shipped, whole.
    const loads = specs ? [...runtimeImports(specs)] : [];

    if (buf.length === 0 || (specs && isGlue(code))) { accounted.push({ file, kind: 'glue', adds: [], whole: [], loads }); continue; }
    let found = null;
    try { found = findMap(abs, code, new Map()); } catch { /* unreadable map: treated as none */ }
    if (found) {
      const adds = [], whole = [], lost = [];
      for (const src of mapSources(found.map, found.at, here, bases)) {
        const pkg = splitNodeModulesPath(src.path);
        if (pkg) { adds.push(src.path); if (!src.exists) whole.push(pkg.name); } else if (/(^|\/)node_modules\//.test(src.path)) lost.push(src.path); else if (src.exists) adds.push(src.path);
      }
      if (lost.length) unknown.push({ file, why: `its source map names ${lost[0]}, which cannot be traced to a package` });
      else accounted.push({ file, kind: 'mapped', adds, whole, loads: [] }); // a bundle: what it loads by name is its bundler's business
      continue;
    }
    if (!specs) { unknown.push({ file, why: 'it has no source map and could not be parsed, so what it loads is unknown' }); continue; }
    const installed = copies.installed(buf);
    if (installed) { accounted.push({ file, kind: 'copy', adds: [posix(relative(here, installed))], whole: [], loads }); continue; }
    const mine = copies.project(buf);
    if (mine) { accounted.push({ file, kind: 'own', adds: [], whole: [], loads }); continue; }
    unknown.push({ file, why: 'no bundler recorded it, it has no source map, and it is not an unmodified copy of an installed or project file' });
  }
  return { accounted, unknown };
}

/**
 * Workspace packages bundled from source. A bundler names their files by real path (../packages/ui/src/x.ts),
 * not under node_modules, so by path alone they look like the app's own code and the package looks absent.
 * Each shipped file outside node_modules is given to the nearest package.json above it; packages other than
 * the project's own are added to the module map. Returns the names added.
 */
export function addWorkspacePackages(moduleMap, root = process.cwd()) {
  const here = resolve(root);
  const owners = new Map();
  const owner = (dir) => {
    if (owners.has(dir)) return owners.get(dir);
    let found = null;
    const pj = join(dir, 'package.json');
    if (existsSync(pj)) { try { const name = JSON.parse(readFileSync(pj, 'utf8')).name; if (typeof name === 'string' && name) found = { dir, name }; } catch { /* not a package */ } }
    if (!found) { const up = dirname(dir); found = up === dir ? null : owner(up); }
    owners.set(dir, found);
    return found;
  };
  const added = new Set();
  for (const p of moduleMap.own ?? []) {
    const abs = resolve(here, p);
    if (!existsSync(abs)) continue; // a bundler's virtual module
    const o = owner(dirname(abs));
    if (!o || o.dir === here) continue;
    const pkgRoot = posix(relative(here, o.dir)), file = posix(relative(o.dir, abs));
    if (!moduleMap.packages.has(o.name)) moduleMap.packages.set(o.name, { roots: new Set(), files: new Set(), byRoot: new Map() });
    const e = moduleMap.packages.get(o.name);
    e.roots.add(pkgRoot); e.files.add(file);
    if (!e.byRoot.has(pkgRoot)) e.byRoot.set(pkgRoot, new Set());
    e.byRoot.get(pkgRoot).add(file);
    added.add(o.name);
  }
  return [...added].sort();
}
