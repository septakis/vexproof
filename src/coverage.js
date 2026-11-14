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
import {
  mapSources, withChainedSources, findMap, loadedSpecifiers, runtimeImports, isGlue, isLoaderStub, generatedBy, installBases,
} from './deploy.js';
import { copyFinder } from './copies.js';
import { literalsOf } from './content-check.js';
import { listFiles, UnreadableFolder } from './walk.js';
import { readPackageJson } from './package-json.js';

// any case: a server serves app.JS as JavaScript too
const JS = /\.(m|c)?js$/i;
const posix = (path) => path.split(sep).join('/');

// a plugin's virtual module, as esbuild names it: "<namespace>:<path>" (two letters or more, so not a Windows drive)
const NAMESPACED = /^[a-z][a-z0-9+.-]+:/i;

/** The build output can't be located or isn't described: the caller refuses with this message. */
export class CoverageError extends Error {}

const WHERE = 'Run vexproof from the folder the build ran in, or pass --root, so the build output can be checked.';
// A module map describes the files of one build. Signs that the files on disk are from another:
const STALE_AFTER_MS = 120_000;
const stale = (count) => `${count} output file(s) on disk are not the ones this module map describes:`;
const REBUILD = 'Rebuild, and run vexproof on that build before anything else changes its output.';
/** Recorded outputs whose size on disk is not the size the bundler recorded: [{ file, recorded, disk }]. */
function wrongSizes(pairs) {
  const wrong = [];
  for (const [abs, recorded] of pairs) {
    if (typeof recorded !== 'number') continue;

    let disk;
    try {
      disk = statSync(abs).size;
    } catch {
      continue; // not there: not shipped
    }
    if (disk !== recorded) wrong.push({ file: abs, recorded, disk });
  }

  return wrong;
}
const sizeError = (wrong, here) => {
  const first = wrong[0];

  return new CoverageError(
    `${stale(wrong.length)} ${posix(relative(here, first.file))} is ${first.disk} bytes, ` +
    `and the bundler wrote ${first.recorded}. ${REBUILD}`
  );
};

/** JavaScript files under an output folder, linked folders included (see listFiles). An unreadable folder is refused. */
function jsFiles(dir, recurse) {
  try {
    return listFiles(dir, { recurse, strict: true }).filter((path) => JS.test(path));
  } catch (error) {
    if (error instanceof UnreadableFolder) {
      throw new CoverageError(`${posix(error.message)}, so the files in it can't be checked.`);
    }

    throw error;
  }
}

/** The folder every path shares, as posix segments; '.' when they share none. */
function commonDir(paths) {
  let parts = null;
  for (const path of paths) {
    const folders = path.split('/').slice(0, -1);
    if (!parts) {
      parts = folders;
      continue;
    }

    let shared = 0;
    while (shared < parts.length && shared < folders.length && parts[shared] === folders[shared]) shared++;
    parts = parts.slice(0, shared);
  }

  return parts?.length ? parts.join('/') : '.';
}

/**
 * Where a module map says the build wrote JavaScript, and which files there it records.
 * `file` is the module map's own path (Angular writes its stats into the output folder, with names relative
 * to it). Returns { dirs: [{ abs, recurse }], isCovered(abs) }, and for webpack stats also copiedFrom (output file →
 * the installed file the bundler says it copied) and hints (output file → a path it was copied from); throws
 * CoverageError when the output can't be found.
 */
export function recordedOutputs(json, { root = process.cwd(), file = null } = {}) {
  const format = detectModuleFormat(json);
  const here = resolve(root);

  if (format === 'vite-modules') {
    const keys = Object.keys(json.outputs ?? {});
    if (Array.isArray(json.unrecordedWorkers) && json.unrecordedWorkers.length) {
      const workers = json.unrecordedWorkers;
      throw new CoverageError(
        `${workers.length} web worker(s) were bundled without the vexproof plugin, so what they hold is not recorded: ` +
        `${workers.slice(0, 4).join(', ')}${workers.length > 4 ? ', …' : ''}. ` +
        'Add the plugin to that build too (worker: { plugins: () => [vexproof()] } in the Vite config) and rebuild.'
      );
    }
    if (!Array.isArray(json.outDirs) || !json.outDirs.length) {
      throw new CoverageError(
        'this module map does not record where the build wrote its files (it was written by an older vexproof plugin). ' +
        'Rebuild with the current plugin.'
      );
    }

    const covered = new Set(keys.map((key) => resolve(here, key)));
    // The plugin writes the map when the build closes, after the output. A recorded file that is newer than
    // the map by more than a pause was written by a later build that this map knows nothing about.
    if (file) {
      let mapTime = null;
      try {
        mapTime = statSync(resolve(file)).mtimeMs;
      } catch {
        /* read from elsewhere */
      }

      const newer = mapTime === null ? [] : [...covered].filter((path) => {
        try {
          return statSync(path).mtimeMs - mapTime > STALE_AFTER_MS;
        } catch {
          return false;
        }
      });
      if (newer.length) {
        throw new CoverageError(`${stale(newer.length)} ${posix(relative(here, newer[0]))} was written after the module map. ${REBUILD}`);
      }
    }

    // the plugin records each file's size when the build is done (a map from an older plugin has none to check)
    const wrong = wrongSizes(keys.map((key) => [resolve(here, key), json.outputs[key]?.bytes]));
    if (wrong.length) {
      throw sizeError(wrong, here);
    }

    const dirs = [];
    for (const recordedDir of json.outDirs) {
      const abs = resolve(here, recordedDir);
      if (existsSync(abs)) {
        dirs.push({ abs, recurse: recordedDir !== '.' });
        continue;
      }

      // a folder the build recorded chunks in must be here; one it wrote nothing to (a skipped pass) need not be
      if (keys.some((key) => recordedDir === '.' || key.startsWith(`${recordedDir}/`))) {
        throw new CoverageError(`the module map records build output in "${recordedDir}", but ${posix(abs)} does not exist. ${WHERE}`);
      }
    }

    return { dirs, isCovered: (abs) => covered.has(abs) };
  }

  if (format === 'esbuild-metafile') {
    const all = Object.keys(json.outputs ?? {}).filter((key) => JS.test(key));
    const keys = all.map((key) => key.replace(/\\/g, '/'));
    if (!keys.length) {
      return { dirs: [], isCovered: () => true };
    }

    const found = (base) => keys.some((key) => existsSync(resolve(base, key)));
    // An output whose every input is a plugin's virtual module ("angular:script/global:scripts.js", the files
    // Angular joins from its `scripts` option) is recorded without saying what is in it: not vouched for.
    const shippedInputs = (key) => Object.entries(json.outputs[key]?.inputs ?? {})
      .filter(([, input]) => (input?.bytesInOutput ?? 0) > 0)
      .map(([inputPath]) => inputPath.replace(/\\/g, '/'));
    const isVouched = (key) => {
      const inputs = shippedInputs(key);

      return !inputs.length || inputs.some((inputPath) => !NAMESPACED.test(inputPath));
    };
    const vouched = new Set(all.filter(isVouched).map((key) => key.replace(/\\/g, '/')));
    // The inputs are named from the folder the build ran in. If none of the project's own is there, this is not it.
    const own = [...new Set(all.flatMap(shippedInputs))]
      .filter((inputPath) => !NAMESPACED.test(inputPath) && !/(^|\/)node_modules\//.test(inputPath) && !inputPath.startsWith('<'));
    if (own.length && !own.some((inputPath) => existsSync(resolve(here, inputPath)))) {
      throw new CoverageError(
        `none of the ${own.length} source files of the project that this module map names (${own[0]}, …) are under ${posix(here)}. ${WHERE}`
      );
    }

    if (found(here)) {
      // esbuild records each output's size, and nothing changes the file afterwards. (Angular's builder does:
      // its outputs are found beside the stats file, below, and are not held to their recorded size.)
      const wrong = wrongSizes(all.map((key) => [resolve(here, key), json.outputs[key]?.bytes]));
      if (wrong.length) {
        throw sizeError(wrong, here);
      }

      const covered = new Set([...vouched].map((key) => resolve(here, key)));
      const top = commonDir(keys);
      // outputs written straight into the project folder: check the folders that hold them, without descending
      const dirs = top === '.'
        ? [...new Set(keys.map((key) => dirname(resolve(here, key))))].map((abs) => ({ abs, recurse: abs !== here }))
        : [{ abs: resolve(here, top), recurse: true }];

      return { dirs, isCovered: (abs) => covered.has(abs) };
    }

    const beside = file ? dirname(resolve(file)) : null;
    if (beside && found(beside)) {
      const covered = new Set([...vouched].map((key) => resolve(beside, key)));

      return { dirs: [{ abs: beside, recurse: true }], isCovered: (abs) => covered.has(abs) };
    }

    if (beside) {
      // Angular with localize: one stats file, and a copy of every output in a folder per locale
      let subfolders = [];
      try {
        subfolders = readdirSync(beside, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name);
      } catch {
        /* unreadable */
      }
      if (subfolders.some((subfolder) => found(join(beside, subfolder)))) {
        const names = vouched;

        return {
          dirs: [{ abs: beside, recurse: true }],
          isCovered: (abs) => {
            const relativePath = posix(relative(beside, abs));

            return names.has(relativePath) || names.has(relativePath.split('/').slice(1).join('/'));
          },
        };
      }
    }

    throw new CoverageError(
      `none of the ${keys.length} JavaScript files this module map lists as build output were found under ${posix(here)}` +
      `${beside ? ` or beside the module map` : ''}. ${WHERE}`
    );
  }

  // webpack or Rspack stats
  ungroupStats(json);
  let outDir = null;
  if (json.vexproofOutDir != null) {
    outDir = resolve(here, json.vexproofOutDir);
  } else if (typeof json.outputPath === 'string') {
    outDir = isAbsolute(json.outputPath) ? json.outputPath : resolve(here, json.outputPath);
  }

  // several configurations in one run (webpack's multi-compiler): the stats have no output of their own, each child has
  const configurations = (json.children ?? [])
    .filter((child) => child && typeof child.outputPath === 'string' && Array.isArray(child.assets));
  const multiCompiler = (!outDir || !Array.isArray(json.assets))
    && configurations.length > 0
    && configurations.length === (json.children ?? []).length;
  if (!multiCompiler && (!outDir || !Array.isArray(json.assets))) {
    throw new CoverageError(json.vexproofBundler
      ? 'this module map does not record where the build wrote its files or which files it emitted ' +
        '(it was written by an older VexproofPlugin). Rebuild with the current plugin.'
      : 'this stats file does not say where the build wrote its files or which files it emitted (no outputPath or assets), ' +
        'so vexproof cannot check that every shipped file is accounted for. ' +
        "Use the VexproofPlugin from 'vexproof/webpack', or keep outputPath and assets in the stats.");
  }

  const outOf = (child) => (isAbsolute(child.outputPath) ? child.outputPath : resolve(here, child.outputPath));
  for (const outputFolder of multiCompiler ? configurations.map(outOf) : [outDir]) {
    if (!existsSync(outputFolder)) {
      throw new CoverageError(`the module map records build output in ${posix(outputFolder)}, which does not exist. ${WHERE}`);
    }
  }

  const covered = new Set();
  const copiedFrom = new Map();
  const hints = new Map();
  const sized = [];
  const checkSizes = () => {
    const wrong = wrongSizes(sized);
    if (wrong.length) {
      throw sizeError(wrong, here);
    }
  };
  const take = (compilation, dir) => {
    // Chunks that have modules listed. One with none is raw files a plugin joined together (the `scripts` of
    // Angular's webpack-based builder): the stats say nothing about what is in it. That can only be told apart
    // from a chunk holding just the bundler's runtime when the stats list runtime modules too: then the runtime
    // modules name their chunk, which is in `full` like any other.
    const full = new Set();
    const walk = (modules) => {
      for (const module of modules ?? []) {
        for (const chunk of module.chunks ?? []) full.add(String(chunk));
        walk(module.modules);
      }
    };
    walk(compilation.modules);
    for (const chunk of compilation.chunks ?? []) {
      if (chunk.modules?.length) full.add(String(chunk.id));
      walk(chunk.modules);
    }

    for (const asset of compilation.assets ?? []) {
      const abs = resolve(dir, String(asset.name).split('?')[0]);
      // a file emitted for a chunk, or for a module of a chunk (asset modules), has its modules in the stats;
      // one that a plugin copied in belongs to no chunk
      // Without runtime modules in the stats, a chunk with none listed is not vouched for either: it is looked
      // at like any other unrecorded file (the plugin lists them; raw stats need `runtimeModules: true`).
      if ((asset.chunks ?? []).some((chunk) => full.has(String(chunk))) || (asset.auxiliaryChunks?.length ?? 0) > 0) {
        covered.add(abs);
        if (JS.test(abs)) sized.push([abs, asset.size]);
      }
      // copy-webpack-plugin says where it took a file from. The copy is often minified on the way, so it would
      // not match the installed file byte for byte; the bundler's own record of its origin stands instead.
      // That holds for a file taken from an installed package. One copied from anywhere else is looked at
      // like any other unrecorded file: it may be another build's output.
      else if (
        asset.info?.copied
        && typeof asset.info.sourceFilename === 'string'
        && /(^|[\\/])node_modules[\\/]/.test(asset.info.sourceFilename)
      ) {
        copiedFrom.set(abs, asset.info.sourceFilename.replace(/\\/g, '/'));
      }
      // a path that names no package ("base/worker/workerMain.js", counted from the copied folder) is only a
      // hint: accountFor looks for the installed file it ends in and checks the copy against it
      else if (asset.info?.copied && typeof asset.info.sourceFilename === 'string') {
        hints.set(abs, asset.info.sourceFilename.replace(/\\/g, '/'));
      }
    }
  };

  if (multiCompiler) {
    // each configuration, and the child compilations it ran (worker-loader), which write into its folder
    const below = (compilation, dir) => {
      for (const child of compilation.children ?? []) {
        if (child && typeof child === 'object') {
          const childDir = typeof child.outputPath === 'string' && isAbsolute(child.outputPath) ? child.outputPath : dir;
          take(child, childDir);
          below(child, childDir);
        }
      }
    };
    for (const configuration of configurations) {
      take(configuration, outOf(configuration));
      below(configuration, outOf(configuration));
    }
    checkSizes();

    return {
      dirs: [...new Set(configurations.map(outOf))].map((abs) => ({ abs, recurse: true })),
      isCovered: (abs) => covered.has(abs),
      copiedFrom,
      hints,
    };
  }

  take(json, outDir);
  for (const child of json.children ?? []) {
    take(child, typeof child.outputPath === 'string' && isAbsolute(child.outputPath) ? child.outputPath : outDir);
  }
  // webpack and Rspack record each emitted file's size; Angular's webpack-based builder leaves them as written too
  checkSizes();

  return { dirs: [{ abs: outDir, recurse: true }], isCovered: (abs) => covered.has(abs), copiedFrom, hints };
}

/**
 * The JavaScript files in the recorded output folders, sorted out: { stray, copied, dirs, recorded, hints }.
 * `stray` are the ones the module map does not record (absolute paths, to be accounted for one by one), `copied`
 * ([{ file, from }]) the ones whose origin the bundler recorded, `dirs` the output folders, `recorded` the files the
 * map does record, and `hints` the copied-from paths that name no package (see accountFor).
 */
export function strayOutputs(json, options = {}) {
  const { dirs, isCovered, copiedFrom = new Map(), hints = new Map() } = recordedOutputs(json, options);
  const seen = new Set();
  const copied = [];
  const recorded = new Set();
  for (const dir of dirs) {
    for (const file of jsFiles(dir.abs, dir.recurse)) {
      if (isCovered(file)) {
        recorded.add(file);
        continue;
      }

      if (copiedFrom.has(file)) {
        copied.push({ file, from: copiedFrom.get(file) });
      } else {
        seen.add(file);
      }
    }
  }

  return { stray: [...seen].sort(), copied, dirs: dirs.map((dir) => dir.abs), recorded: [...recorded].sort(), hints };
}

/**
 * Whether `code` reads like a minified copy of the installed file at `path`: most of the string literals of the
 * original are in it. A file with too few strings to tell by is not vouched for this way.
 */
function derivesFrom(code, path) {
  let original;
  try {
    original = readFileSync(path, 'utf8');
  } catch {
    return false;
  }

  // every string, not only the sentences: a grammar or a table of names has no prose, and many strings; a
  // file of translations has them in any script (those are compared as written, where nothing is escaped)
  const strings = [...literalsOf(original)];
  if (strings.length < 8) {
    for (const match of original.matchAll(/"([^"\\\n]{4,160})"|'([^'\\\n]{4,160})'/g)) strings.push(match[1] ?? match[2]);
  }
  if (new Set(strings).size < 8) {
    return false;
  }

  return strings.filter((string) => code.includes(string)).length >= Math.ceil(strings.length * 0.7);
}

/**
 * Compiled code in the output folders (.wasm, .node) that is an exact copy of installed files: the installed
 * files' paths, relative to root. A bundler copies such a file as it is, under a hashed name. One that matches
 * nothing is left alone: it may be the project's own.
 */
export function binaryCopies(outDirs, { root = process.cwd() } = {}) {
  const here = resolve(root);
  const files = outDirs
    .flatMap((outDir) => listFiles(resolve(outDir), { enter: (name) => name !== 'node_modules' }))
    .filter((path) => /\.(wasm|node)$/i.test(path));
  if (!files.length) {
    return [];
  }

  const copies = copyFinder({ root: here, bases: installBases(here), outDirs });
  const installed = new Set();
  for (const file of files) {
    let buffer;
    try {
      buffer = readFileSync(file);
    } catch {
      continue;
    }
    for (const copy of copies.installedAll(buffer)) installed.add(posix(relative(here, copy)));
  }

  return [...installed];
}

/**
 * Packages that recorded output files load by name when they run (an esbuild `--external`, a webpack external, a
 * library build): code the product uses and the module map does not list. Only loads that are not behind a
 * test count; code written for browsers and Node guards its Node-only loads.
 */
export function runtimeLoads(files) {
  const names = new Set();
  for (const file of files) {
    let specifiers = null;
    try {
      specifiers = loadedSpecifiers(readFileSync(file, 'utf8'));
    } catch {
      /* unreadable */
    }
    for (const name of runtimeImports(specifiers?.unguarded ?? [])) names.add(name);
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
  const accounted = [];
  const unknown = [];
  for (const abs of stray) {
    const file = posix(relative(here, abs));
    let buffer;
    try {
      buffer = readFileSync(abs);
    } catch {
      unknown.push({ file, why: 'could not be read' });
      continue;
    }

    const code = buffer.toString('utf8');
    const specifiers = buffer.length ? loadedSpecifiers(code) : new Set();
    // A file that ships as it is and imports a package by name gets that package from somewhere vexproof can't
    // see (an import map, a loader, another bundle). The caller counts such a package as shipped, whole.
    const loads = specifiers ? [...runtimeImports(specifiers)] : [];

    if (buffer.length === 0) {
      accounted.push({ file, kind: 'glue', adds: [], whole: [], loads });
      continue;
    }

    // An exact copy of installed files says most, so it is asked first; every file it matches ships (two
    // packages can hold the same file).
    const same = copies.installedAll(buffer);
    if (same.length) {
      accounted.push({ file, kind: 'copy', adds: same.map((path) => posix(relative(here, path))), whole: [], loads });
      continue;
    }

    // A file the bundler says it copied, minified on the way so that no bytes match, from a path that names no
    // package. Installed files that end in that path are where it may have come from; one counts when most of
    // what its strings say is in the copy too. Every such file ships.
    const hint = hints.get(abs);
    if (hint) {
      const from = copies.installedEndingWith(hint).filter((path) => derivesFrom(code, path));
      if (from.length) {
        accounted.push({ file, kind: 'copy', adds: from.map((path) => posix(relative(here, path))), whole: [], loads });
        continue;
      }
    }

    if (specifiers && (isGlue(code) || isLoaderStub(code))) {
      accounted.push({ file, kind: 'glue', adds: [], whole: [], loads });
      continue;
    }

    // a file a build tool wrote from a template of its own (Workbox's service worker): that tool's code is in
    // it, so the tool counts as shipped, the way a package the file loads by name does
    const tools = generatedBy(code);
    if (tools) {
      accounted.push({ file, kind: 'generated', adds: [], whole: [], loads: [...loads, ...tools] });
      continue;
    }

    let found = null;
    let noMap = 'it has no source map';
    try {
      found = findMap(abs, code, new Map());
    } catch {
      noMap = 'its source map could not be read';
    }
    if (found) {
      // A map accounts for a file only through sources that can be placed: an installed package's file, or a
      // file of the project that is there. One that names nothing placeable says nothing about the file.
      const adds = [];
      const whole = [];
      const lost = [];
      let unplaced = 0;
      for (const source of withChainedSources(mapSources(found.map, found.at, here, bases), here, bases)) {
        const pkg = splitNodeModulesPath(source.path);
        if (pkg) {
          adds.push(source.path);
          if (!source.exists) whole.push(pkg.name);
        } else if (/(^|\/)node_modules\//.test(source.path)) {
          lost.push(source.path);
        } else if (source.exists) {
          adds.push(source.path);
        } else {
          unplaced++;
        }
      }

      if (lost.length) {
        unknown.push({ file, why: `its source map names ${lost[0]}, which cannot be traced to a package` });
        continue;
      }

      // a bundle: what it loads by name outside a test (a webpack external, a worker's `import`) is used by the
      // product, the same rule as for the recorded outputs (runtimeLoads)
      if (adds.length) {
        accounted.push({ file, kind: 'mapped', adds, whole, loads: [...runtimeImports(specifiers?.unguarded ?? [])] });
        continue;
      }

      noMap = unplaced
        ? `its source map names ${unplaced} source(s), none of which is a file here or in an installed package`
        : 'its source map names no sources';
    }

    if (!specifiers) {
      unknown.push({ file, why: `${noMap} and it could not be parsed, so what it loads is unknown` });
      continue;
    }

    // filed under its own path, so that a vendored package's file is given to that package
    const mine = copies.project(buffer);
    if (mine) {
      accounted.push({ file, kind: 'own', adds: [posix(relative(here, mine))], whole: [], loads });
      continue;
    }

    unknown.push({
      file,
      why: `no bundler recorded it, ${noMap}, and it is not an unmodified copy of an installed file or of a file git tracks`,
    });
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
    if (owners.has(dir)) {
      return owners.get(dir);
    }

    let found = null;
    const packageJsonPath = join(dir, 'package.json');
    const result = readPackageJson(dir);
    // a package.json that is there and can't be read belongs to a package whose name is unknown: stop, rather
    // than give its files to a package further up
    if (result.error) {
      throw new Error(
        `${packageJsonPath} could not be read (${result.error.message}), so the workspace package it belongs to can't be named`
      );
    }
    if (typeof result.pkg?.name === 'string' && result.pkg.name) found = { dir, name: result.pkg.name };
    if (!found) {
      const parent = dirname(dir);
      found = parent === dir ? null : owner(parent);
    }
    owners.set(dir, found);

    return found;
  };

  const added = new Set();
  for (const ownPath of moduleMap.own ?? []) {
    const abs = resolve(here, ownPath);
    if (!existsSync(abs)) continue; // a bundler's virtual module

    const ownerPackage = owner(dirname(abs));
    if (!ownerPackage || ownerPackage.dir === here) continue;

    const pkgRoot = posix(relative(here, ownerPackage.dir));
    const file = posix(relative(ownerPackage.dir, abs));
    if (!moduleMap.packages.has(ownerPackage.name)) {
      moduleMap.packages.set(ownerPackage.name, { roots: new Set(), files: new Set(), byRoot: new Map() });
    }
    const entry = moduleMap.packages.get(ownerPackage.name);
    entry.roots.add(pkgRoot);
    entry.files.add(file);
    if (!entry.byRoot.has(pkgRoot)) entry.byRoot.set(pkgRoot, new Set());
    entry.byRoot.get(pkgRoot).add(file);
    added.add(ownerPackage.name);
  }

  return [...added].sort();
}
