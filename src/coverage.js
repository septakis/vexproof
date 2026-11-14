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
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, resolve, relative, dirname, isAbsolute, sep } from 'node:path';
import { detectModuleFormat, splitNodeModulesPath, ungroupStats } from './modules.js';
import { mapSources, withChainedSources, findMap, loadedSpecifiers, runtimeImports, isGlue, isLoaderStub, generatedBy, installBases } from './deploy.js';
import { copyFinder } from './copies.js';
import { literalsOf } from './content-check.js';
import { listFiles, UnreadableFolder } from './walk.js';
import { readPackageJson } from './package-json.js';

// any case: a server serves app.JS as JavaScript too
const JS = /\.(m|c)?js$/i;
const posix = (p) => p.split(sep).join('/');

// a plugin's virtual module, as esbuild names it: "<namespace>:<path>" (two letters or more, so not a Windows drive)
const NAMESPACED = /^[a-z][a-z0-9+.-]+:/i;

/** The build output can't be located or isn't described: the caller refuses with this message. */
export class CoverageError extends Error {}

const WHERE = 'Run vexproof from the folder the build ran in, or pass --root, so the build output can be checked.';
// A module map describes the files of one build. Signs that the files on disk are from another:
const STALE_AFTER_MS = 120_000;
const stale = (n) => `${n} output file(s) on disk are not the ones this module map describes:`;
const REBUILD = 'Rebuild, and run vexproof on that build before anything else changes its output.';
/** Recorded outputs whose size on disk is not the size the bundler recorded: [{ file, recorded, disk }]. */
function wrongSizes(pairs) {
  const out = [];
  for (const [abs, recorded] of pairs) {
    if (typeof recorded !== 'number') continue;
    let disk; try { disk = statSync(abs).size; } catch { continue; } // not there: not shipped
    if (disk !== recorded) out.push({ file: abs, recorded, disk });
  }
  return out;
}
const sizeError = (wrong, here) => new CoverageError(`${stale(wrong.length)} ${posix(relative(here, wrong[0].file))} is ${wrong[0].disk} bytes, and the bundler wrote ${wrong[0].recorded}. ${REBUILD}`);

/** JavaScript files under an output folder, linked folders included (see listFiles). An unreadable folder is refused. */
function jsFiles(dir, recurse) {
  try {
    return listFiles(dir, { recurse, strict: true }).filter((p) => JS.test(p));
  } catch (e) {
    if (e instanceof UnreadableFolder) throw new CoverageError(`${posix(e.message)}, so the files in it can't be checked.`);
    throw e;
  }
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
    if (Array.isArray(json.unrecordedWorkers) && json.unrecordedWorkers.length) {
      const w = json.unrecordedWorkers;
      throw new CoverageError(`${w.length} web worker(s) were bundled without the vexproof plugin, so what they hold is not recorded: ${w.slice(0, 4).join(', ')}${w.length > 4 ? ', …' : ''}. ` +
        'Add the plugin to that build too (worker: { plugins: () => [vexproof()] } in the Vite config) and rebuild.');
    }
    if (!Array.isArray(json.outDirs) || !json.outDirs.length) {
      throw new CoverageError('this module map does not record where the build wrote its files (it was written by an older vexproof plugin). Rebuild with the current plugin.');
    }
    const covered = new Set(keys.map((k) => resolve(here, k)));
    // The plugin writes the map when the build closes, after the output. A recorded file that is newer than
    // the map by more than a pause was written by a later build that this map knows nothing about.
    if (file) {
      let mapTime = null;
      try { mapTime = statSync(resolve(file)).mtimeMs; } catch { /* read from elsewhere */ }
      const newer = mapTime === null ? [] : [...covered].filter((p) => { try { return statSync(p).mtimeMs - mapTime > STALE_AFTER_MS; } catch { return false; } });
      if (newer.length) throw new CoverageError(`${stale(newer.length)} ${posix(relative(here, newer[0]))} was written after the module map. ${REBUILD}`);
    }
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
    const all = Object.keys(json.outputs ?? {}).filter((k) => JS.test(k));
    const keys = all.map((k) => k.replace(/\\/g, '/'));
    if (!keys.length) return { dirs: [], isCovered: () => true };
    const found = (base) => keys.some((k) => existsSync(resolve(base, k)));
    // An output whose every input is a plugin's virtual module ("angular:script/global:scripts.js", the files
    // Angular joins from its `scripts` option) is recorded without saying what is in it: not vouched for.
    const shippedInputs = (k) => Object.entries(json.outputs[k]?.inputs ?? {}).filter(([, i]) => (i?.bytesInOutput ?? 0) > 0).map(([p]) => p.replace(/\\/g, '/'));
    const vouched = new Set(all.filter((k) => { const ins = shippedInputs(k); return !ins.length || ins.some((p) => !NAMESPACED.test(p)); }).map((k) => k.replace(/\\/g, '/')));
    // The inputs are named from the folder the build ran in. If none of the project's own is there, this is not it.
    const own = [...new Set(all.flatMap(shippedInputs))].filter((p) => !NAMESPACED.test(p) && !/(^|\/)node_modules\//.test(p) && !p.startsWith('<'));
    if (own.length && !own.some((p) => existsSync(resolve(here, p)))) {
      throw new CoverageError(`none of the ${own.length} source files of the project that this module map names (${own[0]}, …) are under ${posix(here)}. ${WHERE}`);
    }
    if (found(here)) {
      // esbuild records each output's size, and nothing changes the file afterwards. (Angular's builder does:
      // its outputs are found beside the stats file, below, and are not held to their recorded size.)
      const wrong = wrongSizes(all.map((k) => [resolve(here, k), json.outputs[k]?.bytes]));
      if (wrong.length) throw sizeError(wrong, here);
      const covered = new Set([...vouched].map((k) => resolve(here, k)));
      const top = commonDir(keys);
      // outputs written straight into the project folder: check the folders that hold them, without descending
      const dirs = top === '.'
        ? [...new Set(keys.map((k) => dirname(resolve(here, k))))].map((abs) => ({ abs, recurse: abs !== here }))
        : [{ abs: resolve(here, top), recurse: true }];
      return { dirs, isCovered: (abs) => covered.has(abs) };
    }
    const beside = file ? dirname(resolve(file)) : null;
    if (beside && found(beside)) {
      const covered = new Set([...vouched].map((k) => resolve(beside, k)));
      return { dirs: [{ abs: beside, recurse: true }], isCovered: (abs) => covered.has(abs) };
    }
    if (beside) {
      // Angular with localize: one stats file, and a copy of every output in a folder per locale
      let subs = [];
      try { subs = readdirSync(beside, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name); } catch { /* unreadable */ }
      if (subs.some((s) => found(join(beside, s)))) {
        const names = vouched;
        return {
          dirs: [{ abs: beside, recurse: true }],
          isCovered: (abs) => { const rel = posix(relative(beside, abs)); return names.has(rel) || names.has(rel.split('/').slice(1).join('/')); },
        };
      }
    }
    throw new CoverageError(`none of the ${keys.length} JavaScript files this module map lists as build output were found under ${posix(here)}${beside ? ` or beside the module map` : ''}. ${WHERE}`);
  }

  // webpack or Rspack stats
  ungroupStats(json);
  const out = json.vexproofOutDir != null ? resolve(here, json.vexproofOutDir)
    : typeof json.outputPath === 'string' ? (isAbsolute(json.outputPath) ? json.outputPath : resolve(here, json.outputPath)) : null;
  // several configurations in one run (webpack's multi-compiler): the stats have no output of their own, each child has
  const kids = (json.children ?? []).filter((c) => c && typeof c.outputPath === 'string' && Array.isArray(c.assets));
  const multi = (!out || !Array.isArray(json.assets)) && kids.length > 0 && kids.length === (json.children ?? []).length;
  if (!multi && (!out || !Array.isArray(json.assets))) {
    throw new CoverageError(json.vexproofBundler
      ? 'this module map does not record where the build wrote its files or which files it emitted (it was written by an older VexproofPlugin). Rebuild with the current plugin.'
      : "this stats file does not say where the build wrote its files or which files it emitted (no outputPath or assets), so vexproof cannot check that every shipped file is accounted for. Use the VexproofPlugin from 'vexproof/webpack', or keep outputPath and assets in the stats.");
  }
  const outOf = (c) => (isAbsolute(c.outputPath) ? c.outputPath : resolve(here, c.outputPath));
  for (const o of multi ? kids.map(outOf) : [out]) if (!existsSync(o)) throw new CoverageError(`the module map records build output in ${posix(o)}, which does not exist. ${WHERE}`);
  const covered = new Set(), copiedFrom = new Map(), hints = new Map(), sized = [];
  const checkSizes = () => { const wrong = wrongSizes(sized); if (wrong.length) throw sizeError(wrong, here); };
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
      // Without runtime modules in the stats, a chunk with none listed is not vouched for either: it is looked
      // at like any other unrecorded file (the plugin lists them; raw stats need `runtimeModules: true`).
      if ((a.chunks ?? []).some((c) => full.has(String(c))) || (a.auxiliaryChunks?.length ?? 0) > 0) { covered.add(abs); if (JS.test(abs)) sized.push([abs, a.size]); }
      // copy-webpack-plugin says where it took a file from. The copy is often minified on the way, so it would
      // not match the installed file byte for byte; the bundler's own record of its origin stands instead.
      // That holds for a file taken from an installed package. One copied from anywhere else is looked at
      // like any other unrecorded file: it may be another build's output.
      else if (a.info?.copied && typeof a.info.sourceFilename === 'string' && /(^|[\\/])node_modules[\\/]/.test(a.info.sourceFilename)) copiedFrom.set(abs, a.info.sourceFilename.replace(/\\/g, '/'));
      // a path that names no package ("base/worker/workerMain.js", counted from the copied folder) is only a
      // hint: accountFor looks for the installed file it ends in and checks the copy against it
      else if (a.info?.copied && typeof a.info.sourceFilename === 'string') hints.set(abs, a.info.sourceFilename.replace(/\\/g, '/'));
    }
  };
  if (multi) {
    // each configuration, and the child compilations it ran (worker-loader), which write into its folder
    const below = (s, dir) => { for (const c of s.children ?? []) if (c && typeof c === 'object') { const d = typeof c.outputPath === 'string' && isAbsolute(c.outputPath) ? c.outputPath : dir; take(c, d); below(c, d); } };
    for (const c of kids) { take(c, outOf(c)); below(c, outOf(c)); }
    checkSizes();
    return { dirs: [...new Set(kids.map(outOf))].map((abs) => ({ abs, recurse: true })), isCovered: (abs) => covered.has(abs), copiedFrom, hints };
  }
  take(json, out);
  for (const c of json.children ?? []) take(c, typeof c.outputPath === 'string' && isAbsolute(c.outputPath) ? c.outputPath : out);
  // webpack and Rspack record each emitted file's size; Angular's webpack-based builder leaves them as written too
  checkSizes();
  return { dirs: [{ abs: out, recurse: true }], isCovered: (abs) => covered.has(abs), copiedFrom, hints };
}

/**
 * JavaScript files in the recorded output folders that the module map does not record: `stray` (absolute
 * paths, to be accounted for one by one) and `copied` ([{ file, from }], files whose origin the bundler recorded).
 */
export function strayOutputs(json, opts = {}) {
  const { dirs, isCovered, copiedFrom = new Map(), hints = new Map() } = recordedOutputs(json, opts);
  const seen = new Set(), copied = [], recorded = new Set();
  for (const d of dirs) for (const f of jsFiles(d.abs, d.recurse)) {
    if (isCovered(f)) { recorded.add(f); continue; }
    if (copiedFrom.has(f)) copied.push({ file: f, from: copiedFrom.get(f) }); else seen.add(f);
  }
  return { stray: [...seen].sort(), copied, dirs: dirs.map((d) => d.abs), recorded: [...recorded].sort(), hints };
}

/**
 * Whether `code` reads like a minified copy of the installed file at `path`: most of the string literals of the
 * original are in it. A file with too few strings to tell by is not vouched for this way.
 */
function derivesFrom(code, path) {
  let original;
  try { original = readFileSync(path, 'utf8'); } catch { return false; }
  // every string, not only the sentences: a grammar or a table of names has no prose, and many strings; a
  // file of translations has them in any script (those are compared as written, where nothing is escaped)
  const strings = [...literalsOf(original)];
  if (strings.length < 8) for (const m of original.matchAll(/"([^"\\\n]{4,160})"|'([^'\\\n]{4,160})'/g)) strings.push(m[1] ?? m[2]);
  if (new Set(strings).size < 8) return false;
  return strings.filter((s) => code.includes(s)).length >= Math.ceil(strings.length * 0.7);
}

/**
 * Compiled code in the output folders (.wasm, .node) that is an exact copy of installed files: the installed
 * files' paths, relative to root. A bundler copies such a file as it is, under a hashed name. One that matches
 * nothing is left alone: it may be the project's own.
 */
export function binaryCopies(outDirs, { root = process.cwd() } = {}) {
  const here = resolve(root);
  const files = outDirs.flatMap((d) => listFiles(resolve(d), { enter: (name) => name !== 'node_modules' })).filter((p) => /\.(wasm|node)$/i.test(p));
  if (!files.length) return [];
  const copies = copyFinder({ root: here, bases: installBases(here), outDirs });
  const out = new Set();
  for (const f of files) {
    let buf; try { buf = readFileSync(f); } catch { continue; }
    for (const c of copies.installedAll(buf)) out.add(posix(relative(here, c)));
  }
  return [...out];
}

/**
 * Packages that recorded output files load by name when they run (an esbuild `--external`, a webpack external, a
 * library build): code the product uses and the module map does not list. Only loads that are not behind a
 * test count; code written for browsers and Node guards its Node-only loads.
 */
export function runtimeLoads(files) {
  const names = new Set();
  for (const f of files) {
    let specs = null;
    try { specs = loadedSpecifiers(readFileSync(f, 'utf8')); } catch { /* unreadable */ }
    for (const n of runtimeImports(specs?.unguarded ?? [])) names.add(n);
  }
  return names;
}

/**
 * Account for the output files a module map does not record. Returns
 *   { accounted: [{ file, kind, adds, whole, loads }], unknown: [{ file, why }] }
 * with `file` relative to root, `adds` the shipped paths the file stands for (relative to root, as a module
 * map names them), `whole` the packages whose files can't be told apart through it, and `loads` the packages
 * it imports by name at runtime.
 */
export function accountFor(stray, { root = process.cwd(), outDirs = [], hints = new Map() } = {}) {
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

    if (buf.length === 0) { accounted.push({ file, kind: 'glue', adds: [], whole: [], loads }); continue; }
    // An exact copy of installed files says most, so it is asked first; every file it matches ships (two
    // packages can hold the same file).
    const same = copies.installedAll(buf);
    if (same.length) { accounted.push({ file, kind: 'copy', adds: same.map((p) => posix(relative(here, p))), whole: [], loads }); continue; }
    // A file the bundler says it copied, minified on the way so that no bytes match, from a path that names no
    // package. Installed files that end in that path are where it may have come from; one counts when most of
    // what its strings say is in the copy too. Every such file ships.
    const hint = hints.get(abs);
    if (hint) {
      const from = copies.installedEndingWith(hint).filter((p) => derivesFrom(code, p));
      if (from.length) { accounted.push({ file, kind: 'copy', adds: from.map((p) => posix(relative(here, p))), whole: [], loads }); continue; }
    }
    if (specs && (isGlue(code) || isLoaderStub(code))) { accounted.push({ file, kind: 'glue', adds: [], whole: [], loads }); continue; }
    // a file a build tool wrote from a template of its own (Workbox's service worker): that tool's code is in
    // it, so the tool counts as shipped, the way a package the file loads by name does
    const tools = generatedBy(code);
    if (tools) { accounted.push({ file, kind: 'generated', adds: [], whole: [], loads: [...loads, ...tools] }); continue; }
    let found = null, noMap = 'it has no source map';
    try { found = findMap(abs, code, new Map()); } catch { noMap = 'its source map could not be read'; }
    if (found) {
      // A map accounts for a file only through sources that can be placed: an installed package's file, or a
      // file of the project that is there. One that names nothing placeable says nothing about the file.
      const adds = [], whole = [], lost = [];
      let unplaced = 0;
      for (const src of withChainedSources(mapSources(found.map, found.at, here, bases), here, bases)) {
        const pkg = splitNodeModulesPath(src.path);
        if (pkg) { adds.push(src.path); if (!src.exists) whole.push(pkg.name); } else if (/(^|\/)node_modules\//.test(src.path)) lost.push(src.path); else if (src.exists) adds.push(src.path); else unplaced++;
      }
      if (lost.length) { unknown.push({ file, why: `its source map names ${lost[0]}, which cannot be traced to a package` }); continue; }
      // a bundle: what it loads by name outside a test (a webpack external, a worker's `import`) is used by the
      // product, the same rule as for the recorded outputs (runtimeLoads)
      if (adds.length) { accounted.push({ file, kind: 'mapped', adds, whole, loads: [...runtimeImports(specs?.unguarded ?? [])] }); continue; }
      noMap = unplaced ? `its source map names ${unplaced} source(s), none of which is a file here or in an installed package` : 'its source map names no sources';
    }
    if (!specs) { unknown.push({ file, why: `${noMap} and it could not be parsed, so what it loads is unknown` }); continue; }
    // filed under its own path, so that a vendored package's file is given to that package
    const mine = copies.project(buf);
    if (mine) { accounted.push({ file, kind: 'own', adds: [posix(relative(here, mine))], whole: [], loads }); continue; }
    unknown.push({ file, why: `no bundler recorded it, ${noMap}, and it is not an unmodified copy of an installed file or of a file git tracks` });
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
    const r = readPackageJson(dir);
    // a package.json that is there and can't be read belongs to a package whose name is unknown: stop, rather
    // than give its files to a package further up
    if (r.error) throw new Error(`${pj} could not be read (${r.error.message}), so the workspace package it belongs to can't be named`);
    if (typeof r.pkg?.name === 'string' && r.pkg.name) found = { dir, name: r.pkg.name };
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
