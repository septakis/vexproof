// SPDX-License-Identifier: MIT
// Which files of each npm package survived into the shipped output.
import { existsSync } from 'node:fs';
import { join, posix, dirname } from 'node:path';
import { builtinModules } from 'node:module';
import { readPackageJson } from './package-json.js';
import { npmName } from './names.js';
// Sources: esbuild metafile (esbuild, Bun, Angular 17+ `ng build --stats-json`)
//          webpack or Rspack stats JSON (`webpack --json=stats.json`)
//          vexproof-modules.json from the vexproof/vite plugin (Vite 7/8, Rollup)

const UNNAMED = '.store/';

/**
 * The installed package.json at path `path`, read as Node reads it (see package-json.js). Throws an error whose
 * `code` is ENOENT when there is none, and the read or parse error when there is one that can't be read: the
 * two mean different things below. Tests replace it through the `readJson` option.
 */
const readInstalled = (path) => {
  const result = readPackageJson(dirname(path));
  if (result.pkg) {
    return result.pkg;
  }

  throw result.missing ? Object.assign(new Error(`no ${path}`), { code: 'ENOENT' }) : result.error;
};
const isMissing = (error) => error?.code === 'ENOENT' || error?.code === 'ENOTDIR';
const storeNames = new Map(); // Yarn store folder -> the package in it, once attachVersions has read its package.json

/** Packages in Yarn's store whose name could not be read: nothing can be said about them, so a run must stop. */
export const unnamedStorePackages = (moduleMap) => [...moduleMap.packages]
  .filter(([name]) => name.startsWith(UNNAMED))
  .flatMap(([, entry]) => [...entry.roots]);

/**
 * "@a-b-c-npm-1.0.0-<hash>" is @a/b-c or @a-b/c, so the name comes from the package.json inside; the folder
 * name is used only when that can't be read and leaves no doubt.
 */
function nameFromYarnStore(folder) {
  const match = /^(.+)-npm-\d[^/]*-[0-9a-f]{10}$/.exec(folder);
  if (!match) {
    return undefined;
  }
  if (!match[1].startsWith('@')) {
    return match[1];
  }

  const parts = match[1].split('-');

  return parts.length === 2 ? parts.join('/') : undefined;
}

function nameStorePackages(moduleMap, cwd, read) {
  for (const [key, entry] of [...moduleMap.packages]) {
    if (!key.startsWith(UNNAMED)) continue;

    const folder = key.slice(UNNAMED.length);
    let name;
    for (const root of entry.roots) {
      try {
        name = read(join(cwd, root, 'package.json')).name;
      } catch {
        /* not installed here */
      }
      if (name) break;
    }
    name ??= nameFromYarnStore(folder);
    if (typeof name !== 'string' || !name || name.startsWith('.')) continue;

    storeNames.set(folder, name);
    moduleMap.packages.delete(key);
    if (!moduleMap.packages.has(name)) moduleMap.packages.set(name, { roots: new Set(), files: new Set(), byRoot: new Map() });
    const target = moduleMap.packages.get(name);
    for (const root of entry.roots) target.roots.add(root);
    for (const file of entry.files) target.files.add(file);
    for (const [root, files] of entry.byRoot ?? []) {
      if (!target.byRoot.has(root)) target.byRoot.set(root, new Set());
      for (const file of files) target.byRoot.get(root).add(file);
    }
    if (moduleMap.whole?.delete(key)) moduleMap.whole.add(name);
  }
}

/**
 * A folder under node_modules is named by whoever installed it, not by the package in it: an alias
 * ("tiny": "npm:ms@2.1.3"), an override, a git dependency, or `require('Lodash')` on a file system that ignores
 * case. The package.json inside names the package. Every shipped folder that can be read is filed under that
 * name; `moduleMap.rootNames` keeps what was renamed, and `moduleMap.unverified` lists the folders that could
 * not be read and whose path does not spell name and version the way a package store's does.
 */
function nameFromPackageJson(moduleMap, cwd, read) {
  moduleMap.rootNames = new Map();
  moduleMap.unverified = [];

  for (const [key, entry] of [...moduleMap.packages]) {
    if (key.startsWith('.')) continue; // an unnamed store folder, or a dot folder that is no package

    for (const root of [...entry.roots]) {
      let pkg = null;
      let unreadable = false;
      try {
        pkg = read(join(cwd, root, 'package.json'));
      } catch (error) {
        unreadable = !isMissing(error);
      }

      if (unreadable) {
        // The folder has a package.json that can't be read: it is a package, and its name is unknown. Its files
        // stay under the folder's name, which the CLI accepts only when the lockfile has a package of that
        // name; filing them under the package around it would make this one look absent.
        moduleMap.unverified.push({ name: key, root });
        continue;
      }

      if (!pkg && existsSync(join(cwd, root))) {
        // The folder is there and is no package: a fixture inside another package's tests
        // (resolve/test/shadowed_core/node_modules/util). Its files belong to the package that holds it.
        let dir = root;
        let holder = null;
        for (let level = 0; level < 8 && !holder; level++) {
          const parent = dir.slice(0, dir.lastIndexOf('/'));
          if (!parent || parent === dir || !parent.includes('node_modules/')) break;

          dir = parent;
          try {
            const parentPkg = read(join(cwd, dir, 'package.json'));
            if (typeof parentPkg.name === 'string' && parentPkg.name) holder = { name: parentPkg.name, root: dir };
          } catch {
            /* keep climbing */
          }
        }

        if (holder) {
          const files = entry.byRoot?.get(root) ?? entry.files;
          const prefix = root.slice(holder.root.length + 1);
          if (!moduleMap.packages.has(holder.name)) {
            moduleMap.packages.set(holder.name, { roots: new Set(), files: new Set(), byRoot: new Map() });
          }
          const target = moduleMap.packages.get(holder.name);
          target.roots.add(holder.root);
          if (!target.byRoot.has(holder.root)) target.byRoot.set(holder.root, new Set());
          for (const file of files) {
            target.files.add(`${prefix}/${file}`);
            target.byRoot.get(holder.root).add(`${prefix}/${file}`);
          }
          entry.roots.delete(root);
          entry.byRoot?.delete(root);
          continue;
        }
      }

      if (!pkg) {
        // a package counted by name alone (a runtime load, the bundler's runtime) has no folder to read
        const files = entry.byRoot?.get(root);
        const byName = files?.size === 1 && files.has('package.json');
        if (!byName && versionFromStorePath(root, key) === undefined) moduleMap.unverified.push({ name: key, root });
        continue;
      }

      const name = pkg.name;
      if (typeof name !== 'string' || !name || name === key || name.startsWith('.')) continue;

      moduleMap.rootNames.set(root, name);
      if (!moduleMap.packages.has(name)) moduleMap.packages.set(name, { roots: new Set(), files: new Set(), byRoot: new Map() });
      const target = moduleMap.packages.get(name);
      const files = entry.byRoot?.get(root) ?? entry.files;
      target.roots.add(root);
      target.byRoot.set(root, new Set([...(target.byRoot.get(root) ?? []), ...files]));
      for (const file of files) target.files.add(file);
      entry.roots.delete(root);
      entry.byRoot?.delete(root);
      if (moduleMap.whole?.has(key)) moduleMap.whole.add(name);
    }

    if (!entry.roots.size) {
      moduleMap.packages.delete(key);
      moduleMap.whole?.delete(key);
    } else if (entry.byRoot?.size) {
      entry.files = new Set([...entry.byRoot.values()].flatMap((rootFiles) => [...rootFiles]));
    }
  }
}

/** splitNodeModulesPath, with the package named as attachVersions found it in the folder's package.json. */
export function splitShipped(moduleMap, path) {
  const split = splitNodeModulesPath(path);
  const name = split && moduleMap?.rootNames?.get(split.root);

  return name ? { ...split, name } : split;
}

/** "./node_modules/a/node_modules/@s/pkg/lib/x.js" -> { name:"@s/pkg", root:"node_modules/a/node_modules/@s/pkg", file:"lib/x.js" } */
export function splitNodeModulesPath(rawPath) {
  // drop webpack loader prefixes ("babel-loader!./x") and query strings first, then the leading "./"
  const path = String(rawPath).replace(/\\/g, '/').replace(/^.*!/, '').replace(/\?.*$/, '').replace(/^\.\//, '');
  const nodeModulesAt = path.lastIndexOf('node_modules/');
  if (nodeModulesAt < 0) {
    return null;
  }

  const rest = path.slice(nodeModulesAt + 'node_modules/'.length).split('/');
  // Two stores keep packages in a dot folder, where the folder after node_modules is not the package:
  //   Nitro  .nitro/<name>@<version>/<file>                              each version a server needs (Nuxt)
  //   Yarn   .store/<name>-<protocol>-<version>-<hash>/package/<file>    nodeLinker: pnpm
  const before = path.slice(0, nodeModulesAt) + 'node_modules/';
  if (rest[0] === '.nitro') {
    const versionedAt = rest[1]?.startsWith('@') ? 2 : 1;
    const atSign = (rest[versionedAt] ?? '').lastIndexOf('@');
    const file = rest.slice(versionedAt + 1).join('/');
    if (atSign > 0 && file) {
      return {
        name: [...rest.slice(1, versionedAt), rest[versionedAt].slice(0, atSign)].join('/'),
        root: before + rest.slice(0, versionedAt + 1).join('/'),
        file,
      };
    }
  }

  if (rest[0] === '.store' && rest[1] && rest[2] === 'package') {
    // the folder doesn't spell the name unambiguously; until attachVersions reads it, the folder stands in for it
    const file = rest.slice(3).join('/');

    return file
      ? { name: storeNames.get(rest[1]) ?? `${UNNAMED}${rest[1]}`, root: before + rest.slice(0, 3).join('/'), file }
      : null;
  }

  const nameParts = rest[0]?.startsWith('@') ? rest.slice(0, 2) : rest.slice(0, 1);
  if (!nameParts.length || nameParts.some((part) => !part)) {
    return null;
  }

  const name = nameParts.join('/');
  const file = rest.slice(nameParts.length).join('/');
  let root = path.slice(0, nodeModulesAt) + 'node_modules/' + name;
  // Yarn Plug'n'Play serves packages from zip archives in a cache that is often outside the project
  // (~/.yarn/berry/cache), sometimes via .yarn/__virtual__/ paths. Key the copy by its archive name:
  // stable across machines, no home directory in the evidence, and virtual paths collapse onto one copy.
  const zip = /([^/]+\.zip)\/node_modules\/$/.exec(path.slice(0, nodeModulesAt + 'node_modules/'.length));
  if (zip) root = `yarn-cache/${zip[1]}/node_modules/${name}`;

  return file ? { name, root, file } : null;
}

export function detectModuleFormat(json) {
  if (json && json.vexproof === 1 && typeof json.outputs === 'object') {
    return 'vite-modules';
  }
  if (json && typeof json.outputs === 'object' && typeof json.inputs === 'object') {
    return 'esbuild-metafile';
  }
  if (json && Array.isArray(json.modules)) {
    return 'webpack-stats';
  }
  if (json && Array.isArray(json.children) && json.children.some((child) => Array.isArray(child.modules))) {
    return 'webpack-stats';
  }
  if (json && Array.isArray(json.chunks) && json.chunks.some((chunk) => Array.isArray(chunk.modules))) {
    return 'webpack-stats'; // Angular's webpack-based builder
  }

  throw new Error(
    'Unrecognised module map (expected vexproof-modules.json, an esbuild or bun build metafile, Angular stats.json, or webpack stats JSON)'
  );
}

/** Record one shipped file of an installed package in a module map's `packages`. Paths outside node_modules are skipped. */
export function addToMap(map, path) {
  const split = splitNodeModulesPath(path);
  if (!split) {
    return;
  }

  const put = ({ name, root, file }) => {
    if (!map.has(name)) map.set(name, { roots: new Set(), files: new Set(), byRoot: new Map() });
    const entry = map.get(name);
    entry.roots.add(root);
    entry.files.add(file);
    if (!entry.byRoot.has(root)) entry.byRoot.set(root, new Set());
    entry.byRoot.get(root).add(file);
  };
  put(split);

  // "node_modules/ui-kit/dist/node_modules/tslib/x.js": a copy of tslib that ui-kit publishes inside its own
  // build (a preserveModules build does this). The file is tslib's code and it is ui-kit's file: both ship.
  // An installed nested dependency (node_modules/a/node_modules/b) sits directly under the outer package and
  // is b's alone.
  const outer = splitNodeModulesPath(split.root.slice(0, split.root.lastIndexOf('node_modules/')).replace(/\/$/, ''));
  if (outer && !outer.name.startsWith('.')) {
    put({ ...outer, file: `${outer.file}/${split.root.slice(split.root.lastIndexOf('node_modules/'))}/${split.file}` });
  }
}
const add = addToMap;

const BUILTIN = new Set([...builtinModules, ...builtinModules.map((moduleName) => `node:${moduleName}`)]);
/**
 * The npm package a bare import specifier names ("lodash/omit" is lodash, "@a/b/c" is @a/b), or null for a
 * relative or absolute path, a URL, a subpath import (#x) or a Node built-in.
 */
export function packageOfSpecifier(specifier) {
  const text = String(specifier ?? '');
  if (!text || /^[./\\#]/.test(text) || /^[a-z][a-z0-9+.-]*:/i.test(text)) {
    return null; // paths, URLs, node:fs
  }

  const parts = text.split('/');
  const name = text.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  if (BUILTIN.has(name)) {
    return null;
  }

  return /^(@[^/@\s]+\/)?[^/@\s]+$/.test(name) ? name : null;
}

/**
 * A package the output loads when it runs instead of bundling (an esbuild --external, a Rollup `external`, a
 * webpack external, also one read from a global as in `externals: { react: 'React' }`): the product uses it,
 * so it ships, whole. Which of its files run is recorded nowhere.
 */
function addExternal(map, whole, specifier) {
  const name = packageOfSpecifier(specifier);
  if (!name) {
    return;
  }

  add(map, `node_modules/${name}/package.json`);
  whole.add(name);
}

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
  let match = /(?:^|\/)\.(?:pnpm|bun)\/((?:@[^/@]+\+)?[^/@]+)@([^/_(+]+)/.exec(root);
  if (match && match[1].replace('+', '/') === name) {
    return match[2];
  }

  match = /(?:^|\/)([^/]+)-npm-(.+?)-[0-9a-f]{10}-[0-9a-z]{1,8}\.zip\//.exec(root);
  if (match && match[1] === name.replace('/', '-')) {
    return match[2];
  }

  match = /(?:^|\/)\.nitro\/((?:@[^/@]+\/)?[^/@]+)@([^/]+)$/.exec(root);
  if (match && match[1] === name) {
    return match[2];
  }

  match = /(?:^|\/)\.store\/([^/]+)-npm-(\d[^/]*)-[0-9a-f]{10}\/package$/.exec(root);
  if (match && match[1] === name.replace('/', '-')) {
    return match[2];
  }

  return undefined;
}

/**
 * Version of every shipped copy, from its installed package.json (under cwd) or, failing that, pnpm's
 * store path. Copies with no readable version stay undefined, and file-level rules then make no claim.
 */
export function attachVersions(moduleMap, { cwd = process.cwd(), readJson } = {}) {
  const read = readJson ?? readInstalled;
  nameStorePackages(moduleMap, cwd, read);
  nameFromPackageJson(moduleMap, cwd, read);

  for (const [name, entry] of moduleMap.packages) {
    entry.versionByRoot = new Map();
    for (const root of entry.roots) {
      let version;
      try {
        version = read(join(cwd, root, 'package.json')).version;
      } catch {
        /* not installed here */
      }
      version ??= versionFromStorePath(root, name);
      entry.versionByRoot.set(root, version);
    }
  }

  return moduleMap;
}

/** The same file as bundlers name it in different places: no loader prefix, query, "./" or concatenation suffix. */
export const moduleKey = (path) => String(path)
  .replace(/\\/g, '/')
  .replace(/^.*!/, '')
  .replace(/\?.*$/, '')
  .replace(/^\.\//, '')
  .replace(/ \+ \d+ modules?$/, '');

/**
 * Who imports whom, when the module map records it: Map<key, Set<key of an importer>>, plus the keys that
 * shipped code. null when the file has no import data (older plugin output, slimmed or hand-made maps).
 */
function graphFrom(edges, shipped) {
  if (!edges.length) {
    return null;
  }

  const importers = new Map();
  for (const [from, to] of edges) {
    const importedKey = moduleKey(to);
    const importerKey = moduleKey(from);
    if (!importers.has(importedKey)) importers.set(importedKey, new Set());
    importers.get(importedKey).add(importerKey);
  }

  return { importers, shipped: new Set([...shipped].map(moduleKey)) };
}

function fromEsbuild(metafile) {
  const map = new Map();
  const shipped = new Set();
  const edges = [];
  const own = new Set();
  const whole = new Set();

  for (const output of Object.values(metafile.outputs ?? {})) {
    for (const [path, info] of Object.entries(output.inputs ?? {})) {
      // an input listed with no byte count is in the output for all the file says: only a stated 0 is "dropped"
      const bytes = typeof info?.bytesInOutput === 'number' ? info.bytesInOutput : 1;
      if (bytes <= 0) continue;

      add(map, path);
      shipped.add(path);
      if (outsideNodeModules(path)) own.add(moduleKey(path));
      // Vite's own helpers (vite/preload-helper.js, vite/modulepreload-polyfill.js) are Vite's code in the
      // output, under a made-up id: the package counts by name.
      if (/^\0?vite\/[\w.-]+$/.test(path)) {
        add(map, 'node_modules/vite/package.json');
        whole.add('vite');
      }
    }
    for (const imported of output.imports ?? []) if (imported?.external) addExternal(map, whole, imported.path);
  }

  for (const [path, info] of Object.entries(metafile.inputs ?? {})) {
    for (const imported of info?.imports ?? []) {
      if (imported.external) addExternal(map, whole, imported.path);
      else edges.push([path, imported.path]);
    }
  }

  return { map, graph: graphFrom(edges, shipped), own, whole };
}

const CONCATENATED = / \+ (\d+) modules?$/;
// how webpack and Rspack name an external module: external "React", external var "React", external commonjs "fs"
const EXTERNAL = /^external (?:[\w-]+ )?"/;

/**
 * Rspack 2.0 names some members of a concatenated module after the concatenation itself
 * ("./a/index.js + 15 modules" for a/Trans.js): inside the root's member list, and again as orphan entries of
 * their own. The member's real file is in nameForCondition. Such an entry has the label and no members, and is
 * either inside a member list (concatenations don't nest) or an orphan in no chunk. A root whose members were
 * left out is neither, so it is still caught.
 */
const mislabelled = (module, nested) => CONCATENATED.test(module.name ?? '')
  && !(module.modules?.length)
  && typeof module.nameForCondition === 'string'
  && (nested || Boolean(module.orphan && !(module.chunks?.length)));

/**
 * webpack groups modules when asked to (stats.all, groupModulesByPath): a list then holds entries like
 * { type: "modules by path", children: [...] } with the modules inside. Put the modules back in the list, in
 * place; the emptied group stays, so that a group that left children out is still seen as a gap.
 */
export function ungroupStats(stats) {
  const isGroup = (item) => item && typeof item === 'object'
    && item.type !== undefined && item.type !== 'module' && Array.isArray(item.children);

  const flat = (items) => {
    if (!Array.isArray(items) || !items.some(isGroup)) {
      for (const item of items ?? []) if (item && Array.isArray(item.modules)) item.modules = flat(item.modules);

      return items;
    }

    const flattened = [];
    for (const item of items) {
      if (isGroup(item)) {
        const children = item.children;
        item.children = [];
        flattened.push(item, ...flat(children));
      } else {
        if (item && Array.isArray(item.modules)) item.modules = flat(item.modules);
        flattened.push(item);
      }
    }

    return flattened;
  };

  const take = (compilation) => {
    if (!compilation || typeof compilation !== 'object') {
      return;
    }

    if (Array.isArray(compilation.modules)) compilation.modules = flat(compilation.modules);
    for (const chunk of compilation.chunks ?? []) {
      if (chunk && Array.isArray(chunk.modules)) chunk.modules = flat(chunk.modules);
    }
  };

  // child compilations, and the configurations of a multi-compiler run with child compilations of their own
  const all = (compilation) => {
    take(compilation);
    for (const child of compilation?.children ?? []) {
      if (child && typeof child === 'object' && child.type === undefined) all(child);
    }
  };

  all(stats);

  return stats;
}

/** Module lists of a stats file: its own, per chunk (Angular's webpack-based builder keeps them only there), and the same for child compilations. */
function moduleLists(stats) {
  const lists = [];
  const take = (compilation, where) => {
    if (Array.isArray(compilation.modules)) lists.push({ modules: compilation.modules, where });
    for (const chunk of compilation.chunks ?? []) {
      if (Array.isArray(chunk.modules)) {
        lists.push({ modules: chunk.modules, where: `${where}, chunk ${chunk.names?.[0] ?? chunk.id}`, filtered: chunk.filteredModules });
      }
    }
  };
  take(stats, 'modules');

  const below = (compilation) => {
    for (const child of compilation.children ?? []) {
      if (child && typeof child === 'object') {
        take(child, 'child');
        below(child);
      }
    }
  };
  below(stats);

  return lists;
}

/**
 * Stats JSON can silently leave modules out: a size limit (filteredModules), grouped or filtered children
 * (filteredChildren), or a concatenated module ("./x.js + 190 modules") whose members are not listed. Any of
 * these would make shipped code look absent, so such a file is refused rather than trusted.
 */
export function webpackStatsGaps(stats) {
  const gaps = [];
  const check = (modules, where, nested) => {
    for (const module of modules ?? []) {
      // the bundler's own runtime (chunk loading, module registry) never comes from node_modules
      if ((module.filteredChildren ?? 0) > 0 && module.type !== 'runtime modules') {
        gaps.push(`${where}: ${module.filteredChildren} modules filtered out of "${module.name ?? module.type}"`);
      }
      // an external whose stats name no request leaves the package it stands for unknown (stats without reasons)
      if (EXTERNAL.test(String(module.name ?? '')) && !(module.reasons ?? []).some((reason) => reason.userRequest)) {
        gaps.push(`"${module.name}" does not say which package it stands for (keep reasons in the stats)`);
      }

      const concatenation = CONCATENATED.exec(module.name ?? '');
      if (concatenation && !mislabelled(module, nested)) {
        const listed = (module.modules ?? []).filter((member) => member.name).length;
        // "./x.js + 21 modules" is x.js and 21 more: its list holds all 22
        const total = Number(concatenation[1]) + 1;
        if (listed < total) gaps.push(`"${module.name}" lists ${listed} of its ${total} concatenated modules`);
      }

      check(module.modules, where, true);
    }
  };

  if ((stats.filteredModules ?? 0) > 0) gaps.push(`${stats.filteredModules} modules filtered out (modulesSpace limit)`);

  const below = (compilation) => {
    for (const child of compilation.children ?? []) {
      if (child && typeof child === 'object') {
        if ((child.filteredModules ?? 0) > 0) gaps.push(`${child.filteredModules} modules filtered out of a child compilation`);
        below(child);
      }
    }
  };
  below(stats);

  for (const list of moduleLists(stats)) {
    if ((list.filtered ?? 0) > 0) gaps.push(`${list.filtered} modules filtered out of ${list.where}`);
    check(list.modules, list.where, false);
  }

  return gaps;
}

function fromWebpack(stats) {
  ungroupStats(stats);
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
  const map = new Map();
  const shipped = new Set();
  const edges = [];
  const own = new Set();

  // The project folder as the bundler saw it: what a relative module name leaves off its absolute path.
  let context;
  const findContext = (modules) => {
    for (const module of modules ?? []) {
      const name = String(module.name ?? '');
      const absolutePath = typeof module.nameForCondition === 'string' ? module.nameForCondition.replace(/\\/g, '/') : '';
      if (name.startsWith('./') && !CONCATENATED.test(name) && absolutePath.endsWith(name.slice(1))) {
        return absolutePath.slice(0, absolutePath.length - name.length + 1);
      }

      const below = findContext(module.modules);
      if (below) {
        return below;
      }
    }

    return null;
  };
  const realName = (module) => {
    const absolutePath = module.nameForCondition.replace(/\\/g, '/');
    if (context === undefined) {
      context = null;
      for (const list of lists) {
        context = findContext(list.modules);
        if (context) break;
      }
    }
    if (!context) {
      return absolutePath;
    }

    const relativePath = posix.relative(context, absolutePath);

    return relativePath.startsWith('.') ? relativePath : `./${relativePath}`;
  };

  const whole = new Set();
  const visit = (modules, parentIncluded) => {
    for (const module of modules ?? []) {
      const included = parentIncluded || (Array.isArray(module.chunks) && module.chunks.length > 0);
      if (!included || (module.orphan && !parentIncluded)) {
        visit(module.modules, false);
        continue;
      }

      // An external (external "React") is code the output gets at runtime, from a require() or from a global.
      // The package is what the importing code asked for: each reason's userRequest.
      if (EXTERNAL.test(String(module.name ?? module.identifier ?? ''))) {
        for (const reason of module.reasons ?? []) addExternal(map, whole, reason.userRequest);
        continue;
      }

      // concatenated roots are named "./x.js + 12 modules"; their members arrive via module.modules
      // "delegated ./node_modules/lodash/lodash.js from dll-reference vendor": the module, as a DLL build names it
      const name = parentIncluded && mislabelled(module, true)
        ? realName(module)
        : String(module.name ?? module.identifier ?? '').replace(CONCATENATED, '').replace(/^delegated (.+) from dll-reference \S+$/, '$1');
      add(map, name);
      shipped.add(name);
      if (name && outsideNodeModules(name)) own.add(moduleKey(name));
      for (const reason of module.reasons ?? []) if (reason.moduleName) edges.push([reason.moduleName, name]);
      visit(module.modules, true);
    }
  };
  for (const list of lists) visit(list.modules, false);

  // The bundler's runtime (chunk loading, the module registry, the public path) is the bundler's own code in
  // the output. No file of the bundler's package stands for it in the stats, so the package counts by name.
  const hasRuntime = (modules) => (modules ?? []).some((module) => module && (
    module.moduleType === 'runtime'
    || /^webpack\/runtime\//.test(String(module.name ?? ''))
    || hasRuntime(module.modules)
  ));
  if (lists.some((list) => hasRuntime(list.modules))) {
    const bundlerPackage = /^rspack/i.test(String(stats.vexproofBundler ?? '')) ? '@rspack/core' : 'webpack';
    add(map, `node_modules/${bundlerPackage}/package.json`);
    whole.add(bundlerPackage);
  }

  return { map, graph: graphFrom(edges, shipped), own, whole };
}

/**
 * { format, packages: Map<packageName, { roots:Set<string>, files:Set<string> }>, graph, own, whole }, with
 * `whole` only when a package ships whole.
 */
export function readModuleMap(json) {
  const format = detectModuleFormat(json);
  const { map, graph, own, whole } = format === 'webpack-stats'
    ? fromWebpack(json)
    : fromEsbuild(json); // the Vite plugin writes the metafile shape

  let label = format;
  if (format === 'vite-modules') {
    label = `vite-modules (${json.bundler ?? 'unknown bundler'})`;
  } else if (format === 'webpack-stats' && json.vexproofBundler) {
    label = `webpack-stats (${json.vexproofBundler})`;
  }

  return { format: label, packages: map, graph, own, ...(whole?.size ? { whole } : {}) };
}

/**
 * A minimal bundle SBOM built from the module map, for bundlers the CycloneDX plugins don't support
 * (Rspack) or to skip that plugin entirely. Versions come from each package's installed package.json
 * under `cwd`, or from the lockfile SBOM when it lists exactly one version; otherwise none is claimed.
 */
export function bundleSbomFromModules(moduleMap, { lockfileSbom = null, cwd = process.cwd(), readJson } = {}) {
  const read = readJson ?? readInstalled;
  const lockVersions = new Map(); // npmName → versions in the lockfile SBOM
  for (const component of flatten(lockfileSbom?.components)) {
    const match = /^pkg:npm\/(.+)@([^@?#]+)/.exec(component.purl ?? '');
    if (!match) continue;

    let name;
    try {
      name = npmName(decodeURIComponent(match[1]));
    } catch {
      continue;
    }
    if (!lockVersions.has(name)) lockVersions.set(name, new Set());
    lockVersions.get(name).add(match[2]);
  }

  const unnamed = unnamedStorePackages(moduleMap);
  if (unnamed.length) {
    throw new Error(
      `Can't tell which package is in ${unnamed[0]}${unnamed.length > 1 ? ` (and ${unnamed.length - 1} more)` : ''}: ` +
      'its package.json could not be read'
    );
  }

  const components = [];
  const seen = new Set();
  for (const [name, entry] of moduleMap.packages) {
    // a dot folder in node_modules that is not a package store (.cache, .prisma): no npm package is named like that
    if (name.startsWith('.')) continue;

    for (const root of entry.roots) {
      let version = entry.versionByRoot?.get(root);
      if (!version) {
        try {
          version = read(join(cwd, root, 'package.json')).version;
        } catch {
          /* not installed here */
        }
      }
      version ??= versionFromStorePath(root, name);
      const lockedVersions = lockVersions.get(npmName(name));
      if (!version && lockedVersions?.size === 1) version = [...lockedVersions][0];

      const encodedName = name.startsWith('@') ? `%40${name.slice(1)}` : name;
      const purl = `pkg:npm/${encodedName}${version ? '@' + version : ''}`;
      if (seen.has(purl)) continue; // one copy linked from two places, or two copies of one version

      seen.add(purl);
      components.push({ type: 'library', name, ...(version ? { version } : {}), purl });
    }
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: { tools: { components: [{ type: 'application', name: 'vexproof', description: `derived from ${moduleMap.format}` }] } },
    components,
  };
}

function flatten(list, out = []) {
  for (const component of list ?? []) {
    out.push(component);
    flatten(component.components, out);
  }

  return out;
}
