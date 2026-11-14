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
import { readdirSync, readFileSync, statSync, existsSync, realpathSync, openSync, readSync, closeSync, fstatSync } from 'node:fs';
import { join, dirname, resolve, relative, basename, sep } from 'node:path';
// A namespace import: stripTypeScriptTypes is in Node 22.13 and later only, and a named import of an export that
// isn't there would stop this module, and the CLI, from loading at all on an earlier Node 22.
import * as nodeModule from 'node:module';

const { builtinModules } = nodeModule;
import { createHash } from 'node:crypto';
import { parse } from 'acorn';
import { splitNodeModulesPath, addToMap } from './modules.js';
import { npmName } from './names.js';
import { readPackageJson } from './package-json.js';
import { listFiles } from './walk.js';
import { copyFinder } from './copies.js';

const JS = /\.(m|c)?js$/;
// TypeScript that Node 22.18+ and 24 run as it is (type stripping); declaration files hold no code
const TS = /\.(m|c)?ts$/i;
const DTS = /\.d\.(m|c)?ts$/i;
const isTs = (file) => TS.test(file) && !DTS.test(file);
// a source of Turbopack's own runtime, as its maps name them
const TURBOPACK_RUNTIME = /^turbopack:\/\/\/\[turbopack\]\//;
/** The debug id written at the end of a bundled file (Turbopack, esbuild, Sentry), lower case, or null. */
const debugIdOf = (code) => /\/\/[#@]\s*debugId=([0-9a-f-]{32,36})/i.exec(code.slice(-4096))?.[1]?.toLowerCase() ?? null;
/** Whether a file and a map carry the same debug id: then the map was written for this file. */
const sameDebugId = (code, map) => {
  const debugId = debugIdOf(code);

  return Boolean(debugId) && typeof map?.debugId === 'string' && map.debugId.toLowerCase() === debugId;
};
const posix = (path) => path.split(sep).join('/');
const BUILTINS = new Set([...builtinModules, ...builtinModules.map((moduleName) => `node:${moduleName}`)]);

// Symbolic links to folders are not followed: a link into the deployment is walked at its real path anyway, and a
// link out of it is not part of the deployment (runtime loads through it are caught by the runtime check).
function walk(dir, out = [], followed = null) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }

  for (const entry of entries) {
    const entryPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(entryPath, out, followed);
    } else if (entry.isFile()) {
      out.push(entryPath);
    } else if (entry.isSymbolicLink()) {
      try {
        const stats = statSync(entryPath);
        if (stats.isFile()) {
          out.push(entryPath);
        } else if (stats.isDirectory() && followed) {
          // with `followed` (a Set), linked folders are walked too, each real folder once
          const real = realpathSync(entryPath);
          if (!followed.has(real)) {
            followed.add(real);
            walk(entryPath, out, followed);
          }
        }
      } catch {
        /* dangling */
      }
    }
  }

  return out;
}

/**
 * The half of a framework's build that was not given: a Next.js standalone folder without `.next/static`, a
 * Nitro `.output/server` without `.output/public`. The browser half ships too, and holds other packages.
 */
export function missingHalves(dirs, root = process.cwd()) {
  const absoluteDirs = dirs.map((dir) => resolve(root, dir));
  const given = (path) => absoluteDirs.some((dir) => path === dir || path.startsWith(dir + sep) || dir.startsWith(path + sep));
  const has = (dir, tail, depth) => {
    const subfolderHas = (entry) => entry.isDirectory() && entry.name !== 'node_modules' && has(join(dir, entry.name), tail, depth - 1);

    return existsSync(join(dir, tail)) || (depth > 0 && readdirSafe(dir).some(subfolderHas));
  };

  const out = [];
  for (const dir of absoluteDirs) {
    const posixDir = posix(dir);
    const standaloneAt = posixDir.lastIndexOf('/.next/standalone');
    if (standaloneAt >= 0 && /\/\.next\/standalone(\/|$)/.test(posixDir.slice(standaloneAt))) {
      const staticDir = resolve(posixDir.slice(0, standaloneAt), '.next/static');
      if (existsSync(staticDir) && !given(staticDir) && !has(dir, '.next/static', 2)) {
        out.push(posix(relative(root, staticDir)));
      }
    }

    // A server half beside a browser half: Nitro's .output/server and public, React Router's build/server and
    // client, Astro's dist/server and client, Angular SSR's server and browser, SvelteKit's output/server and
    // client. A sibling of those names that holds JavaScript ships too.
    if (basename(dir).toLowerCase() === 'server') {
      for (const half of ['public', 'client', 'browser', 'static']) {
        const other = resolve(dir, '..', half);
        if (existsSync(other) && !given(other) && listFiles(other).some((file) => JS.test(file))) {
          out.push(posix(relative(root, other)));
        }
      }
    }
  }

  return [...new Set(out)];
}
const readdirSafe = (dir) => {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
};

const LOCKFILES = ['pnpm-lock.yaml', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'bun.lock', 'bun.lockb'];

/**
 * Folders whose node_modules can hold this project's packages: the root and, when the root is an app inside a
 * workspace, its parents up to the folder with the lockfile. Workspaces install packages there and link them
 * into each app's own node_modules, and links to folders are not walked. Bundlers also write source paths
 * against the workspace root. A root with its own lockfile, or with none above it, stands alone.
 */
export function installBases(root) {
  const start = resolve(root);
  const hasLock = (dir) => LOCKFILES.some((lockfile) => existsSync(join(dir, lockfile)));
  if (hasLock(start)) {
    return [start];
  }

  const parents = [];
  for (let dir = dirname(start); dir !== dirname(dir); dir = dirname(dir)) {
    parents.push(dir);
    if (hasLock(dir)) {
      return [start, ...parents];
    }
  }

  return [start];
}

/**
 * Source map for a bundled file: its sourceMappingURL (inline, next to it, or elsewhere by name), or file.map.
 * `base` is the deployment folder the file is in: a map found elsewhere by name must then sit in folders named
 * like every folder between `base` and the file.
 */
export function findMap(file, code, mapIndex, { base = null } = {}) {
  const tail = code.slice(-4096);
  const urlMatch = /\/[/*][#@]\s*sourceMappingURL=([^\s*]+)\s*(?:\*\/\s*)?$/.exec(tail);
  const parseMap = (text, where) => {
    try {
      return JSON.parse(text);
    } catch (error) {
      throw new Error(`the source map ${where} could not be read: ${error.message}`);
    }
  };

  if (urlMatch && urlMatch[1].startsWith('data:')) {
    const base64Match = /;base64,(.*)$/.exec(urlMatch[1]);
    const body = base64Match
      ? Buffer.from(base64Match[1], 'base64').toString('utf8')
      : decodeURIComponent(urlMatch[1].slice(urlMatch[1].indexOf(',') + 1));

    return { map: parseMap(body, `inline in ${file}`), at: file };
  }

  const read = (candidate) => ({ map: parseMap(readFileSync(candidate, 'utf8'), candidate), at: candidate });
  // A map found elsewhere by its name must be this file's: the generated file it names, and the debug id
  // that Turbopack, esbuild and Sentry write into both, must agree where they are written.
  const debugId = debugIdOf(code);
  const describes = ({ map }) => (typeof map.file !== 'string' || !map.file || basename(map.file) === basename(file))
    && (!debugId || typeof map.debugId !== 'string' || map.debugId.toLowerCase() === debugId);

  const beside = [];
  const names = new Set([`${basename(file)}.map`]);
  if (urlMatch) {
    const mapUrl = decodeURIComponent(urlMatch[1].split('?')[0]);
    beside.push(resolve(dirname(file), mapUrl));
    names.add(basename(mapUrl));
  }
  beside.push(`${file}.map`);
  for (const candidate of beside) {
    if (existsSync(candidate)) {
      return read(candidate);
    }
  }

  // Not beside the file (Next.js keeps server maps in .next, outside the folder it deploys). A map of the same
  // name is this file's only if it sits in folders of the same names, all the way up to the deployment folder:
  // every route of an app is "route.js", and app/about and app/[locale]/about share "about". Among several,
  // the ones that match furthest up; if more than one is left, all of them are read, since the file is one of
  // them and reading too many can only add to what counts as shipped.
  const all = [...new Set([...names].flatMap((name) => mapIndex.get(name) ?? []))]
    .filter((candidate) => existsSync(candidate))
    .map(read)
    .filter(describes);
  const scored = all.map((candidateMap) => ({ candidateMap, shared: sharedTail(file, candidateMap.at) }));
  const need = base ? relative(base, dirname(file)).split(/[\\/]/).filter(Boolean).length : 1;

  // A file at the top of the deployment folder has no folders to match: there, a map elsewhere is accepted only
  // when the file names it and nothing else has that name (a flat --maps folder).
  const usable = scored.filter((score) => (need > 0 && score.shared >= need) || (need === 0 && urlMatch && all.length === 1));
  if (!usable.length) {
    return null;
  }

  const best = Math.max(...usable.map((score) => score.shared));
  const [first, ...more] = usable.filter((score) => score.shared === best).map((score) => score.candidateMap);

  return { ...first, more };
}

/**
 * A map can name a file that is itself a bundle: a minifier run over a bundler's output writes a map whose only
 * source is that output. If the named file has a map of its own beside it, that map says what is in it, so its
 * sources are taken too (a few levels deep). One with no map is taken as the project's own code, which the
 * content check then has to catch.
 */
export function withChainedSources(sources, root, bases) {
  const out = [];
  const seen = new Set();
  const visit = (list, depth) => {
    for (const source of list) {
      out.push(source);
      if (!source.exists || depth >= 3 || !JS.test(source.path) || /(^|\/)node_modules\//.test(source.path)) {
        continue;
      }

      const absolutePath = resolve(root, source.path);
      const mapFile = `${absolutePath}.map`;
      if (seen.has(absolutePath) || !existsSync(mapFile)) {
        continue;
      }
      seen.add(absolutePath);

      let map;
      try {
        map = JSON.parse(readFileSync(mapFile, 'utf8'));
      } catch {
        continue;
      }
      visit(mapSources(map, mapFile, root, bases), depth + 1);
    }
  };

  visit(sources, 0);

  return out;
}

/** How many folders two files' paths share, counted from the files upward. */
function sharedTail(firstFile, secondFile) {
  const firstFolders = dirname(firstFile).split(/[\\/]/).reverse();
  const secondFolders = dirname(secondFile).split(/[\\/]/).reverse();

  let shared = 0;
  while (shared < firstFolders.length && shared < secondFolders.length && firstFolders[shared] === secondFolders[shared]) {
    shared++;
  }

  return shared;
}

const SCHEME = /^[a-z][a-z0-9+.-]+:/i; // two letters or more, so not a Windows drive

/**
 * A source as the map's author wrote it, made comparable: joined to a `sourceRoot` that is a URL, and without
 * "./" segments. A bundler that reads a package's own source map copies these strings into its own map
 * ("webpack://Lib/./src/x.js", "https://raw.githubusercontent.com/…/src/x.ts"), so the same string in an
 * installed package's map says whose code it is.
 */
function rawSource(map, source) {
  let raw = source.split('?')[0];
  if (!SCHEME.test(raw) && typeof map.sourceRoot === 'string' && SCHEME.test(map.sourceRoot)) {
    raw = map.sourceRoot.replace(/\/?$/, '/') + raw;
  }

  return raw.replace(/\/(\.\/)+/g, '/');
}

/**
 * Every original file a source map names, as a path relative to the project root. `bases` are the folders
 * packages may be installed under (installBases); a package found under a parent gets a `../` path.
 */
export function mapSources(map, mapFile, root, bases = [root]) {
  const out = [];
  const visit = (currentMap) => {
    for (const section of currentMap.sections ?? []) {
      visit(section.map);
    }

    for (const originalSource of currentMap.sources ?? []) {
      if (!originalSource) {
        continue;
      }

      let source = originalSource;
      try {
        source = decodeURIComponent(originalSource);
      } catch {
        /* keep as is */
      }

      // a map written on Windows names sources with backslashes; on Linux they are not separators unless made so
      source = source.replace(/\\/g, '/');

      // Next.js (Turbopack) names the generated stand-in for a client component after the file it stands for:
      // `<file>/__nextjs-internal-proxy.cjs { server => "…" }`. Count it as that file. That only ever adds a
      // file to what shipped, so it can't turn a finding into "not present".
      source = source.replace(/\/__nextjs-internal-proxy\.[cm]?js(?: \{[^]*)?$/, '');

      const before = source.split('?')[0];
      source = before
        .replace(/^webpack:\/\/[^/]*\//, '')
        .replace(/^turbopack:\/\/\/?(\[project\]\/)?/, '')
        .replace(/^file:\/\/\/?(?=[a-z]:)/i, '')
        .replace(/^file:\/\//, '')
        .replace(/^\[project\]\//, '');

      // webpack and Turbopack name sources from the project folder, not from the folder the map is in
      const fromProject = source !== before && !/^file:/.test(before);
      const drive = /^[a-z]:[\\/]/i.test(source); // a Windows path, not a URL scheme
      const raw = rawSource(currentMap, before);

      // a URL, or a bundler's own scheme: no file here. Whose it is can only be told from the string itself.
      if (!drive && SCHEME.test(source)) {
        out.push({ path: source, exists: false, literal: source, raw });
        continue;
      }

      let absolutePath = source.startsWith('/') || drive
        ? resolve(source)
        : resolve(dirname(mapFile), currentMap.sourceRoot ?? '', source);
      if (fromProject && !existsSync(absolutePath)) {
        for (const base of bases) {
          const candidate = resolve(base, source);
          if (existsSync(candidate)) {
            absolutePath = candidate;
            break;
          }
        }
      }

      // A relative source that climbs too far ("../../../../src/routes/+page.svelte" from a map only three
      // folders deep, as SvelteKit writes them) still names a file of the project: found by what follows the dots.
      // SvelteKit writes its maps in .svelte-kit/output and an adapter copies the files elsewhere, so the files
      // it generates for the app (generated/root.svelte) are found under .svelte-kit too.
      if (!existsSync(absolutePath) && /^(\.\.\/)+[^.]/.test(source) && !source.includes('node_modules/')) {
        const tail = source.replace(/^(\.\.\/)+/, '');
        search: for (const base of bases) {
          for (const candidate of [resolve(base, tail), resolve(base, '.svelte-kit', tail)]) {
            if (existsSync(candidate)) {
              absolutePath = candidate;
              break search;
            }
          }
        }
      }

      // where the source points as written (found in the project, or past SvelteKit's extra dots), before the
      // search for a package under the install bases below
      const literal = posix(relative(root, absolutePath));

      // Some bundlers write sources against their own project root (Turbopack's "[project]" is the workspace
      // root, which may be a parent folder). If that doesn't land on a file, find the package under this root:
      // shorter and shorter tails of the path, down to the one that starts at its first node_modules and no
      // further. A shorter one would drop a nesting level: a/node_modules/b is not the top-level b, and can be
      // another version of it.
      const nodeModulesAt = source.indexOf('node_modules/');
      if (!existsSync(absolutePath) && nodeModulesAt >= 0) {
        const parts = source.split('/');
        const firstNodeModules = parts.indexOf('node_modules');
        search: for (let partIndex = 0; partIndex <= firstNodeModules; partIndex++) {
          const tail = parts.slice(partIndex).join('/');

          for (const base of bases) {
            const candidate = resolve(base, tail);
            if (existsSync(candidate)) {
              absolutePath = candidate;
              break search;
            }
          }
        }

        if (!existsSync(absolutePath)) {
          // not installed here: still counts as shipped. Place it under the base that holds its top folder
          // (node_modules/.pnpm, or the package's own), so it reads the same as its installed neighbours.
          const relativePath = source.slice(nodeModulesAt);
          const topFolder = relativePath.split('/').slice(0, 2).join('/');
          absolutePath = resolve(bases.find((base) => existsSync(resolve(base, topFolder))) ?? root, relativePath);
        }
      }

      out.push({ path: posix(relative(root, absolutePath)), exists: existsSync(absolutePath), literal, raw });
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
  // every package that names a source, not the first: two packages can publish maps that point at the same
  // place ("../../../src/index.ts"), and crediting both can only add to what counts as shipped
  const index = new Map();
  index.raw = new Map(); // sources written as URLs or in a bundler's scheme, as they stand
  const put = (map, key, owner) => {
    if (!map.has(key)) {
      map.set(key, []);
    }
    if (!map.get(key).some((existing) => existing.root === owner.root)) {
      map.get(key).push(owner);
    }
  };

  for (const file of bases.flatMap((base) => walk(resolve(base, 'node_modules')))) {
    if (!file.endsWith('.map')) {
      continue;
    }

    const owner = splitNodeModulesPath(posix(relative(root, file)));
    if (!owner) {
      continue;
    }

    let map;
    try {
      map = JSON.parse(readFileSync(file, 'utf8'));
    } catch {
      continue;
    }

    for (const source of mapSources(map, file, root, bases)) {
      put(index, source.path, owner);
      put(index, source.literal, owner);
      if (source.raw && SCHEME.test(source.raw)) {
        put(index.raw, source.raw, owner);
      }
    }
  }

  return index;
}

// The snippet that registers a file's debug id (Turbopack and Sentry both write one at the top of each file):
// a function, but the same few lines everywhere and nobody's package.
function withoutDebugId(code) {
  const start = /^\s*;?\s*!function\(\)\{try\s*\{/.exec(code);
  if (!start) {
    return code;
  }

  const close = /\}catch\(\w+\)\{\}\}\(\);?/.exec(code.slice(start[0].length, start[0].length + 700));
  if (!close) {
    return code;
  }

  const body = code.slice(start[0].length, start[0].length + close.index);
  // only the snippet: it names _debugIds, and holds no function, load or import of its own
  if (!body.includes('_debugIds') || /\bfunction\b|=>|\brequire\b|\bimport\b/.test(body)) {
    return code;
  }

  return code.slice(start[0].length + close.index + close[0].length);
}

/**
 * A chunk that only wires modules together: Turbopack writes many (a re-export, a list of chunks to load, an
 * external handed to require), with a source map that names no source, since no source file is in them. It is
 * a list of functions that do nothing but call methods of their own parameters with literals, `require("x")`,
 * `import("x")` or `Promise.all`. Anything that computes (an operator, a branch, a loop, a variable, `new`, a
 * call of anything else) is code, and a file with code is not one of these.
 */
export function isLoaderStub(code) {
  // in a browser the list is handed over as `(globalThis.TURBOPACK || (globalThis.TURBOPACK = [])).push([<this script>, …])`
  const body = withoutDebugId(code).replace(
    /^\s*\(globalThis\.(TURBOPACK\w*)\|\|\(globalThis\.\1=\[\]\)\)\.push\(\["object"==typeof document\?document\.currentScript:void 0,/,
    'module.exports.push(['
  );

  let ast;
  try {
    ast = parse(body, { ecmaVersion: 'latest', sourceType: 'script', allowReturnOutsideFunction: true });
  } catch {
    return false;
  }

  const ALLOWED_TYPES = new Set([
    'Program', 'ExpressionStatement', 'AssignmentExpression', 'ArrayExpression', 'Literal', 'ArrowFunctionExpression', 'FunctionExpression',
    'CallExpression', 'MemberExpression', 'Identifier', 'BlockStatement', 'ReturnStatement', 'ImportExpression', 'EmptyStatement',
    'VariableDeclaration', 'TryStatement', 'CatchClause', 'AwaitExpression', 'SequenceExpression', 'UnaryExpression', 'BinaryExpression',
    // settings handed to what was loaded: `new e.CacheFirst({ cacheName: "fonts", plugins: [new e.ExpirationPlugin({ maxEntries: 50 })] })`
    'NewExpression', 'ObjectExpression', 'Property']);
  const FREE_NAMES = new Set(['module', 'exports', 'require', 'Promise', 'undefined', 'self', 'define', 'importScripts']);
  const walkNode = (node, params) => {
    if (!ALLOWED_TYPES.has(node.type)) {
      return false;
    }

    if (node.type === 'Identifier') {
      return params.has(node.name) || FREE_NAMES.has(node.name);
    }

    if (node.type === 'MemberExpression') {
      return !node.computed ? walkNode(node.object, params) : walkNode(node.object, params) && walkNode(node.property, params);
    }

    if (node.type === 'AssignmentExpression') {
      return node.operator === '=' && node.left.type === 'MemberExpression' && walkNode(node.left, params) && walkNode(node.right, params);
    }

    // "/_next/static/media/a.svg" + (globalThis.NEXT_CLIENT_ASSET_SUFFIX || ""): the address of a static file
    if (node.type === 'BinaryExpression') {
      const right = node.right;

      return node.operator === '+' && node.left.type === 'Literal' && typeof node.left.value === 'string'
        && right.type === 'LogicalExpression' && right.operator === '||'
        && right.right.type === 'Literal' && right.right.value === '' && right.left.type === 'MemberExpression' && !right.left.computed
        && right.left.object.type === 'Identifier' && right.left.object.name === 'globalThis' && /^[A-Z_]+$/.test(right.left.property.name);
    }

    if (node.type === 'Property') {
      return !node.computed && node.kind === 'init' && !node.method && walkNode(node.value, params);
    }

    // `!0`, `!1`: how a minifier writes true and false
    if (node.type === 'UnaryExpression') {
      return node.operator === '!' && node.argument.type === 'Literal' && typeof node.argument.value === 'number';
    }

    // `try { var d = await a.y("x"); a.n(d), c() } catch (e) { c(e) }`: an external loaded as an ES module
    if (node.type === 'CatchClause') {
      if (node.param && node.param.type !== 'Identifier') {
        return false;
      }

      return walkNode(node.body, node.param ? new Set([...params, node.param.name]) : params);
    }

    // `var d = a.i(857764)`: a module fetched from the registry, to hand on. The name is then one of the function's own.
    if (node.type === 'VariableDeclaration') {
      for (const declarator of node.declarations) {
        if (declarator.id.type !== 'Identifier' || !declarator.init || !walkNode(declarator.init, params)) {
          return false;
        }
        params.add(declarator.id.name);
      }

      return true;
    }

    let inner = params;
    if (node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression') {
      if (node.params.some((param) => param.type !== 'Identifier')) {
        return false;
      }
      inner = new Set([...params, ...node.params.map((param) => param.name)]);
    }

    for (const key in node) {
      if (key === 'type' || key === 'params' || key === 'id') {
        continue;
      }

      const value = node[key];
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child.type === 'string' && !walkNode(child, inner)) {
            return false;
          }
        }
      } else if (value && typeof value.type === 'string' && !walkNode(value, inner)) {
        return false;
      }
    }

    return true;
  };

  return walkNode(ast, new Set());
}

// Unmapped files that can't be carrying a package's code: framework manifests (data assignments) and launchers
// like Next.js's standalone server.js. Package code defines functions; these define none beyond a couple of
// inline callbacks. Their runtime imports are still checked.
export function isGlue(code) {
  code = withoutDebugId(code);

  // Decided by parsing, not by looking for the word: a file of translated strings can say "function", and code
  // can be written without it (a class, a method in an object, a getter).
  let ast = null;
  for (const sourceType of ['module', 'script']) {
    try {
      ast = parse(code, {
        ecmaVersion: 'latest',
        sourceType,
        allowHashBang: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
      });
      break;
    } catch {
      /* try the other */
    }
  }
  if (!ast) {
    return false;
  }

  // a function with nothing in it does nothing (a placeholder component: `function e(e){}`)
  const isEmpty = (node) => node.body?.type === 'BlockStatement' && node.body.body.length === 0;
  let arrows = 0;
  const stack = [ast];
  while (stack.length) {
    const node = stack.pop();
    if (/^(ClassDeclaration|ClassExpression)$/.test(node.type)) {
      return false;
    }
    if (/^(FunctionExpression|FunctionDeclaration)$/.test(node.type) && !isEmpty(node)) {
      return false;
    }
    // up to two small arrows, as manifests and loaders have (`()=>import("./x.js")`)
    if (node.type === 'ArrowFunctionExpression' && !isEmpty(node) && ++arrows > 2) {
      return false;
    }

    for (const key in node) {
      const value = node[key];
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child.type === 'string') {
            stack.push(child);
          }
        }
      } else if (value && typeof value.type === 'string') {
        stack.push(value);
      }
    }
  }

  return true;
}

const RUNTIME_ALIASES = [
  'Object.create',
  'Object.defineProperty',
  'Object.getOwnPropertyDescriptor',
  'Object.getOwnPropertyNames',
  'Object.getPrototypeOf',
  'Object.prototype.hasOwnProperty',
];

/**
 * A file a build tool writes from a template of its own, recognised by what it is: the packages whose code it
 * holds, or null. Its source map, if it has one, names a temporary file that is gone by the time anyone looks.
 *
 * Workbox's generated service worker (workbox-build, behind vite-plugin-pwa and others in `generateSW` mode):
 * the small loader that gives a worker `define` (from @surma/rollup-plugin-off-main-thread), then one `define`
 * call that hands settings to the Workbox library, which is a file of its own beside it. Past the loader, the
 * file may only wire things together.
 */
export function generatedBy(code) {
  if (!code.startsWith('if(!self.define){')) {
    return null;
  }

  const defineAt = code.indexOf('}define([');
  if (defineAt < 0 || defineAt > 1500 || !/register its module/.test(code.slice(0, defineAt))) {
    return null;
  }

  return isLoaderStub(code.slice(defineAt + 1)) ? ['workbox-build', '@surma/rollup-plugin-off-main-thread'] : null;
}

/**
 * Chunks a bundler writes for itself. They get no source map, because no source file is behind them:
 *   - Rolldown's runtime, the helpers that define modules and convert between module formats, which Vite 8
 *     splits into a chunk of its own: one `var` statement of Object.* aliases and functions, then an export list;
 *   - Vite's preload helper, which loads a lazy chunk's CSS and dependencies ahead of it.
 * Recognised narrowly, by shape and content, because a file taken for one of these is taken to hold no package
 * code. Anything that doesn't fit stays an unmapped file, and is refused.
 */
export function isBundlerRuntime(code, specs) {
  // small, and loads nothing
  if (code.length > 4096 || !specs || specs.size) {
    return false;
  }
  if (code.includes('modulepreload') && code.includes('Unable to preload CSS for') && code.includes('vite:preloadError')) {
    return true;
  }

  let ast;
  try {
    ast = parse(code, { ecmaVersion: 'latest', sourceType: 'module' });
  } catch {
    return false;
  }

  const [declaration, exportList] = ast.body;
  if (ast.body.length !== 2 || declaration.type !== 'VariableDeclaration' || exportList.type !== 'ExportNamedDeclaration'
    || exportList.source || exportList.declaration) {
    return false;
  }

  const aliases = new Set();
  for (const declarator of declaration.declarations) {
    const init = declarator.init;
    if (init?.type === 'MemberExpression') {
      aliases.add(code.slice(init.start, init.end));
    } else if (init?.type !== 'ArrowFunctionExpression' && init?.type !== 'FunctionExpression') {
      return false;
    }
  }

  return aliases.size === RUNTIME_ALIASES.length && RUNTIME_ALIASES.every((alias) => aliases.has(alias));
}

// require("x") as bundlers leave it in their output: esbuild's __require in ESM output, webpack's
// __non_webpack_require__, module.require, and createRequire(import.meta.url)("x").
const REQUIRE = /^(_*require\d*|__non_webpack_require__|nodeRequire)$/;
const isRequire = (callee) => (callee.type === 'Identifier' && REQUIRE.test(callee.name))
  || (callee.type === 'MemberExpression' && !callee.computed && callee.property.name === 'require'
    && callee.object.type === 'Identifier' && callee.object.name === 'module')
  || (callee.type === 'CallExpression' && ((callee.callee.type === 'Identifier' && callee.callee.name === 'createRequire')
    || (callee.callee.type === 'MemberExpression' && !callee.callee.computed && callee.callee.property.name === 'createRequire')));

/**
 * Module specifiers a bundled file loads at runtime: static and dynamic imports, re-exports, and require()
 * calls with a string argument. Parsed, not pattern-matched, so examples in comments and strings don't count.
 * Returns null when the file doesn't parse (the caller then errs on the safe side).
 */
export function loadedSpecifiers(code) {
  let ast = null;
  for (const sourceType of ['module', 'script']) {
    try {
      ast = parse(code, {
        ecmaVersion: 'latest',
        sourceType,
        allowHashBang: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        allowImportExportEverywhere: true,
      });
      break;
    } catch {
      /* try the other */
    }
  }
  if (!ast) {
    return null;
  }

  const specs = new Set();
  const literalString = (node) => {
    if (node?.type === 'Literal' && typeof node.value === 'string') {
      return node.value;
    }
    if (node?.type === 'TemplateLiteral' && node.expressions.length === 0) {
      return node.quasis[0].value.cooked;
    }

    return null;
  };

  // Loads that run whenever the code around them runs, as opposed to ones behind a test (if, ?:, &&, ||, ??, try,
  // case). Code meant for browsers that can also run under Node guards its Node loads that way
  // (`if (ENVIRONMENT_IS_NODE) fs = require("fs")`); a server just loads what it needs.
  specs.unguarded = new Set();
  const guards = (node, key) => ((node.type === 'IfStatement' || node.type === 'ConditionalExpression') && key !== 'test')
    || (node.type === 'LogicalExpression' && key === 'right')
    || (node.type === 'TryStatement' && key === 'block')
    || (node.type === 'SwitchCase' && key === 'consequent');

  const stack = [[ast, false]];
  while (stack.length) {
    const [node, guarded] = stack.pop();
    if (!node || typeof node.type !== 'string') {
      continue;
    }

    let spec = null;
    if ((node.type === 'ImportDeclaration' || node.type === 'ExportAllDeclaration' || node.type === 'ExportNamedDeclaration')
      && node.source) {
      spec = node.source.value;
    } else if (node.type === 'ImportExpression' && literalString(node.source)) {
      spec = literalString(node.source);
    } else if (node.type === 'CallExpression' && isRequire(node.callee) && literalString(node.arguments[0])) {
      spec = literalString(node.arguments[0]);
    }
    if (spec !== null) {
      specs.add(spec);
      if (!guarded) {
        specs.unguarded.add(spec);
      }
    }

    for (const key in node) {
      const value = node[key];
      if (key === 'type' || key === 'start' || key === 'end') {
        continue;
      }

      const childGuarded = guarded || guards(node, key);
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child.type === 'string') {
            stack.push([child, childGuarded]);
          }
        }
      } else if (value && typeof value.type === 'string') {
        stack.push([value, childGuarded]);
      }
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
export const usesNodeBuiltins = (specs) => [...(specs.unguarded ?? specs)]
  .some((spec) => BUILTINS.has(spec) || BUILTINS.has(packageOf(spec)));

/** Bare package names loaded at runtime (Node's own modules excluded). */
export function runtimeImports(specs) {
  const names = new Set();
  for (const spec of specs) {
    if (!isBare(spec)) {
      continue;
    }
    // "punycode/" is how code asks for the installed package of a name Node also has built in
    if (!spec.endsWith('/') && (BUILTINS.has(spec) || BUILTINS.has(packageOf(spec)))) {
      continue;
    }

    names.add(packageOf(spec));
  }

  return names;
}

/**
 * Where to look for source maps when --maps isn't given. Next.js keeps server maps in `.next`, outside the
 * standalone folder it deploys; in a monorepo that `.next` is the app's (apps/web/.next), not the root's.
 */
export function defaultMapDirs(dirs, root = process.cwd()) {
  const out = new Set();
  if (existsSync(resolve(root, '.next'))) {
    out.add('.next');
  }

  for (const deployDir of dirs) {
    const parts = String(deployDir).split(/[\\/]/);
    const nextIndex = parts.indexOf('.next');
    if (nextIndex < 0) {
      continue;
    }

    const dir = parts.slice(0, nextIndex + 1).join('/');
    if (existsSync(resolve(root, dir))) {
      out.add(dir);
    }
  }

  return [...out];
}

/**
 * Read deployment folders. Returns a module map ({ format, packages, graph: null, whole, own }) plus what the
 * caller must check or say:
 *   unmapped           bundled files whose contents are unknown (no source map, one naming only made-up sources,
 *                      or code that can't be parsed)
 *   unattributed       map sources under node_modules that trace to no installed package
 *   missingRuntime     [{ name, from }]: packages deployed code loads that the deployment does not hold
 *   escapes            [{ target, from }]: files outside the deployment that deployed code loads
 *   loadedFromOutside  [{ name, from }]: packages deployed packages load from the project's node_modules
 *   unplaced           [{ source, file }]: map sources that are no file and no package's (modules the bundler made up)
 *   selfVouched        project files that vouch for a deployed file only by being its git-tracked original
 *   missingDirs, missingHalves, hasServer
 * `lockNames` (Set of npm package names in the lockfile SBOM) limits the runtime-import check to real dependencies.
 */
export function readDeployment(dirs, { root = process.cwd(), mapDirs = [], lockNames = null } = {}) {
  const packages = new Map();
  const whole = new Set();
  const own = new Set();
  const bases = installBases(root);
  // project files that vouch for a deployed file only by being its git-tracked original (see the CLI's content check)
  const selfVouched = new Set();
  const add = (relativePath) => {
    if (splitNodeModulesPath(relativePath)) {
      addToMap(packages, relativePath);
    } else if (!/(^|\/)node_modules\//.test(relativePath)) {
      own.add(relativePath);
    }
  };

  const lexDirs = dirs.map((dir) => resolve(root, dir));
  const mapsRead = new Set(); // the source map files the deployment's files were read with
  // a folder linked into the deployment is part of it wherever it really lives, so links are followed here
  const files = dirs.flatMap((dir) => walk(resolve(root, dir), [], new Set()));
  const mapIndex = new Map();
  // a map inside a deployed package describes that package's file, never a bundle of the app's
  for (const file of [...files, ...mapDirs.flatMap((dir) => walk(resolve(root, dir)))]) {
    if (file.endsWith('.map') && !/[\\/]node_modules[\\/]/.test(file)) {
      if (!mapIndex.has(basename(file))) {
        mapIndex.set(basename(file), []);
      }
      mapIndex.get(basename(file)).push(file);
    }
  }

  // packages present in the deployment, by the name code requires them by. Frameworks link externals under
  // hashed names (Next.js: .next/node_modules/js-yaml-77b6… -> node_modules/js-yaml); follow the link to the
  // real package, and note whether it lands inside the deployment.
  const absoluteDirs = dirs.map((dir) => {
    try {
      return realpathSync(resolve(root, dir));
    } catch {
      return resolve(root, dir);
    }
  });
  const inside = (path) => absoluteDirs.some((dir) => path === dir || path.startsWith(dir + sep));
  const deployed = new Map(); // name as required -> { name: real package name, inside }
  const scan = (dir) => {
    try {
      return readdirSync(dir, { withFileTypes: true });
    } catch {
      return [];
    }
  };
  const record = (dir, entryName) => {
    let real = null;
    let name = entryName;
    try {
      real = realpathSync(dir);
      name = readPackageJson(real).pkg?.name ?? entryName;
    } catch {
      /* not a package */
    }

    deployed.set(entryName, { name, inside: real ? inside(real) : false });
  };
  const packagesIn = (nodeModulesDir, inStore = false) => {
    for (const entry of scan(nodeModulesDir)) {
      // a deployed pnpm or Bun store: its packages are in the deployment, and code inside the store loads them
      // by name (createRequire(<a path in the store>)("undici")), though no top-level folder has that name
      if ((entry.name === '.pnpm' || entry.name === '.bun') && !inStore) {
        for (const storeEntry of scan(join(nodeModulesDir, entry.name))) {
          packagesIn(join(nodeModulesDir, entry.name, storeEntry.name, 'node_modules'), true);
        }
        continue;
      }

      // Yarn's pnpm linker: node_modules/.store/<name>-npm-<version>-<hash>/package, named by its package.json
      if (entry.name === '.store' && !inStore) {
        for (const storeEntry of scan(join(nodeModulesDir, entry.name))) {
          const dir = join(nodeModulesDir, entry.name, storeEntry.name, 'package');
          const packageName = readPackageJson(dir).pkg?.name;
          if (typeof packageName === 'string' && packageName && !deployed.has(packageName)) {
            record(dir, packageName);
          }
        }
        continue;
      }

      if (entry.name.startsWith('.')) {
        continue;
      }
      // what a top-level folder says stands
      if (inStore && deployed.has(entry.name)) {
        continue;
      }

      if (entry.name.startsWith('@')) {
        for (const scopedEntry of scan(join(nodeModulesDir, entry.name))) {
          record(join(nodeModulesDir, entry.name, scopedEntry.name), `${entry.name}/${scopedEntry.name}`);
        }
      } else {
        record(join(nodeModulesDir, entry.name), entry.name);
      }
    }
  };
  const findNodeModules = (dir) => {
    for (const entry of scan(dir)) {
      const entryPath = join(dir, entry.name);
      if (entry.name === 'node_modules') {
        packagesIn(entryPath);
      } else if (entry.isDirectory()) {
        findNodeModules(entryPath);
      }
    }
  };

  for (const deployDir of dirs) {
    const dir = resolve(root, deployDir);
    // --deploy node_modules: the folder itself holds the packages
    if (basename(dir) === 'node_modules') {
      packagesIn(dir);
    }
    findNodeModules(dir);
  }

  // byte-identical copies of installed package files (polyfills, runtimes), and of files the project tracks
  const copies = copyFinder({ root, bases, outDirs: absoluteDirs });

  const unmapped = [];
  const missingRuntime = [];
  const unparsed = [];
  const unattributed = [];
  const escapes = [];
  const unplaced = new Map(); // a source that is no file and no known virtual module -> a file whose map names it
  let packageMaps = null;
  let mapped = 0;
  let copied = 0;
  let serverCode = 0;
  for (const file of files) {
    if (!JS.test(file) && !file.endsWith('.json') && !file.endsWith('.node') && !isTs(file)) {
      continue;
    }

    const relativePath = posix(relative(root, file));
    if (/(^|\/)node_modules\//.test(relativePath)) {
      add(relativePath);
      copied++;
      continue;
    }
    if (!JS.test(file) && !isTs(file)) {
      continue;
    }

    const buffer = readFileSync(file);
    // TypeScript is read with its types stripped, as Node runs it; a Node too old to strip them can't tell
    let code = buffer.toString('utf8');
    if (isTs(file)) {
      try {
        // on a Node without type stripping this throws too, and the file is then one that can't be read
        code = nodeModule.stripTypeScriptTypes(code);
      } catch {
        unparsed.push(relativePath);
        continue;
      }
    }

    const specs = loadedSpecifiers(code);
    if (!specs) {
      unparsed.push(relativePath);
      continue;
    }

    const loadsNode = usesNodeBuiltins(specs);
    for (const spec of runtimeImports(specs)) {
      const deployedPackage = deployed.get(spec);
      let name = deployedPackage?.name ?? spec;
      if (lockNames && !lockNames.has(name)) {
        // Next.js loads an external under a hashed alias (js-yaml-77b6df11dc860fde); without its link, the name says whose it is
        const bare = name.replace(/-[0-9a-f]{16}$/, '');
        // not installed, so it can't hold a finding
        if (bare === name || !lockNames.has(bare)) {
          continue;
        }
        name = bare;
      }
      if (!deployedPackage?.inside) {
        missingRuntime.push({ name, from: relativePath });
      }
    }

    // A relative or absolute load that leaves the deployment: for an installed package it is a runtime load of
    // that package. For any other code that is there (a generated client beside the build), it is code that runs
    // and is in no deployment folder, so nothing it holds or loads can be checked. A target that isn't there
    // is left alone: where the server runs, it may be something else, and nothing here can say what.
    for (const spec of specs) {
      if (!/^\.{1,2}\//.test(spec) && !/^\/|^[a-z]:[\\/]/i.test(spec)) {
        continue;
      }

      const target = /^\.{1,2}\//.test(spec) ? resolve(dirname(file), spec) : resolve(spec);
      if (lexDirs.some((dir) => target === dir || target.startsWith(dir + sep))) {
        continue;
      }

      const targetPackage = splitNodeModulesPath(posix(relative(root, target)));
      if (targetPackage) {
        if (!lockNames || lockNames.has(targetPackage.name)) {
          missingRuntime.push({ name: targetPackage.name, from: relativePath });
        }
        continue;
      }

      const targetFile = ['', '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '/index.js', '/index.mjs']
        .map((suffix) => target + suffix)
        .find((candidate) => {
          try {
            return statSync(candidate).isFile();
          } catch {
            return false;
          }
        });
      if (targetFile && !targetFile.endsWith('.json')) {
        escapes.push({ target: posix(relative(root, targetFile)), from: relativePath });
      }
    }

    const deployBase = lexDirs.find((dir) => file === dir || file.startsWith(dir + sep)) ?? null;
    const found = findMap(file, code, mapIndex, { base: deployBase });
    // One map per file: of two files joined, each with its own, only the last would be read. And a map that
    // names no source at all says nothing about a file that holds code.
    // (counted as lines of their own: a bundle can hold the words in a string, as the TypeScript compiler's does)
    const several = (code.match(/^\s*\/\/[#@]\s*sourceMappingURL=/gm) ?? []).length > 1;
    let sources = [];
    if (found && !several) {
      for (const readMap of [found, ...(found.more ?? [])]) {
        if (readMap.at !== file) {
          mapsRead.add(readMap.at); // a map file, not one inlined in the code: the digest covers it too
        }
      }
      const foundSources = [found, ...(found.more ?? [])].flatMap((readMap) => mapSources(readMap.map, readMap.at, root, bases));
      sources = withChainedSources(foundSources, root, bases);
    }

    if (found && !several && (sources.length || isGlue(code) || isLoaderStub(code))) {
      mapped++;
      // The server's code is code a bundler made, so it has a map. A script of the project's own that loads a
      // Node module (public/healthcheck.js) does not make a folder of browser files a server.
      if (loadsNode) {
        serverCode++;
      }

      let madeUp = 0;
      for (const source of sources) {
        if (source.exists) {
          add(source.path);
          // A package file that is not JavaScript (src/parse.ts) is an original the package publishes beside
          // what it runs: the bundler's map was led there by the package's own, inline or not. The files that
          // ran are then not the ones named, so file-level rules can't be checked for it.
          const installedPackage = splitNodeModulesPath(source.path);
          if (installedPackage && !/\.(m|c)?js$|\.json$|\.node$/.test(source.path)) {
            whole.add(installedPackage.name);
          }
          continue;
        }

        // not a real file: a source reached through a package's own map, or a bundler's virtual module
        const claimedPackage = splitNodeModulesPath(source.path);
        if (claimedPackage && existsSync(resolve(root, claimedPackage.root))) {
          add(source.path);
          whole.add(claimedPackage.name);
          continue;
        }

        packageMaps ??= packageMapIndex(root, bases);
        const owners = packageMaps.get(source.path) ?? packageMaps.get(source.literal) ?? packageMaps.raw.get(source.raw);
        if (owners) {
          for (const owner of owners) {
            add(`${owner.root}/${owner.file}`);
            whole.add(owner.name);
          }
          continue;
        }

        if (/(^|\/)node_modules\//.test(source.path)) {
          unattributed.push(`${source.path} (in ${relativePath})`);
          continue;
        }

        // Turbopack's own runtime (turbopack:///[turbopack]/…) is the bundler's code, which ships inside next: it
        // counts as that package, the way webpack's runtime counts as webpack
        if (TURBOPACK_RUNTIME.test(source.raw)) {
          if (!lockNames || lockNames.has('next')) {
            add('node_modules/next/package.json');
            whole.add('next');
          }
          continue;
        }

        // What is left names no file and no installed package's map names it: a module the bundler made up
        // (a CSS module's stand-in, a generated font module, a virtual: import). Counted, so the run can say so.
        unplaced.set(source.raw, relativePath);
        madeUp++;
      }

      // A map whose every source is made up says nothing about what is in the file (coverage.js holds the same
      // for module maps): it may be another build's map. It stands only when it is provably this file's, by the
      // debug id both carry; the bundler that wrote both lists every module of the file in it. A file with no
      // code of its own, or the bundler's runtime, needs nothing more either.
      const ownMap = sameDebugId(code, found.map);
      if (sources.length && madeUp === sources.length && !ownMap
        && !isGlue(code) && !isLoaderStub(code) && !isBundlerRuntime(code, specs)) {
        mapped--;
        if (loadsNode) {
          serverCode--;
        }
        unmapped.push(relativePath);
      }
      continue;
    }

    // every installed file it is a copy of: two packages can hold the same file, and both then ship
    const same = copies.installedAll(buffer);
    if (same.length) {
      for (const copy of same) {
        add(posix(relative(root, copy)));
      }
      continue;
    }

    if (isGlue(code) || isBundlerRuntime(code, specs) || isLoaderStub(code)) {
      continue;
    }

    // a file a build tool wrote from its own template: that tool's code is in it
    const tools = generatedBy(code);
    if (tools) {
      for (const tool of tools) {
        if (!lockNames || lockNames.has(tool)) {
          add(`node_modules/${tool}/package.json`);
          whole.add(tool);
        }
      }
      continue;
    }

    // A file of the project's own, deployed as it is (public/sw.js): what it loads by name was checked above.
    // It is filed under its own path, so that a vendored package's file is given to that package.
    const mine = copies.project(buffer);
    if (mine) {
      const projectPath = posix(relative(root, mine));
      own.add(projectPath);
      selfVouched.add(projectPath);
      continue;
    }

    unmapped.push(relativePath);
  }

  // compiled code outside node_modules (a .node addon or .wasm file a bundler copied): whose it is, if it is a copy
  for (const file of files) {
    if (!/\.(node|wasm)$/.test(file) || /[\\/]node_modules[\\/]/.test(file)) {
      continue;
    }

    let buffer;
    try {
      buffer = readFileSync(file);
    } catch {
      continue;
    }

    for (const copy of copies.installedAll(buffer)) {
      add(posix(relative(root, copy)));
    }
  }

  // A deployed package can load another that the deployment does not hold: Node then finds it further up, in
  // the project's own node_modules, when the server runs from there. Such a package is used by the product,
  // so it counts as shipped. Looked for cheaply first (a load-shaped string in the text), then by parsing. A
  // load behind a test (`try { require("optional") } catch {}`) counts too: the lockfile says the package is
  // installed, so the load succeeds, as it does for bundled code above.
  const outside = new Map(); // name -> a deployed file that loads it
  if (lockNames) {
    const realDirs = new Map();
    const held = new Map();
    const realDir = (dir) => {
      if (!realDirs.has(dir)) {
        try {
          realDirs.set(dir, realpathSync(dir));
        } catch {
          realDirs.set(dir, dir);
        }
      }

      return realDirs.get(dir);
    };
    const holds = (dir, name) => {
      for (let folder = dir; inside(folder); folder = dirname(folder)) {
        const cacheKey = `${folder}\0${name}`;
        if (!held.has(cacheKey)) {
          held.set(cacheKey, existsSync(join(folder, 'node_modules', name)));
        }
        if (held.get(cacheKey)) {
          return true;
        }
        if (dirname(folder) === folder) {
          break;
        }
      }

      return false;
    };

    // require("x") and its bundled spellings (__require, nodeRequire), import/from "x", and a call on a call,
    // createRequire(import.meta.url)("x"); loadedSpecifiers then says which of these really are loads
    const LOADS = /(?:require\d*|import|from)\s*\(?\s*["']([^"'./][^"']*)["']|\)\s*\(\s*["']([^"'./][^"']*)["']/gi;
    for (const file of files) {
      if (!JS.test(file) || !/[\\/]node_modules[\\/]/.test(file)) {
        continue;
      }

      let text;
      try {
        if (statSync(file).size > 4 * 1024 * 1024) {
          continue;
        }
        text = readFileSync(file, 'utf8');
      } catch {
        continue;
      }

      const selfName = splitNodeModulesPath(posix(relative(root, file)))?.name;
      const dir = realDir(dirname(file));
      const absent = new Set();
      for (const load of text.matchAll(LOADS)) {
        const name = packageOf(load[1] ?? load[2]);
        if (name !== selfName && lockNames.has(name) && !outside.has(name) && !holds(dir, name)) {
          absent.add(name);
        }
      }
      if (!absent.size) {
        continue;
      }

      // a file that doesn't parse can't be told apart: what it seems to load counts
      const specs = loadedSpecifiers(text);
      for (const name of specs ? runtimeImports(specs) : absent) {
        if (absent.has(name)) {
          outside.set(name, posix(relative(root, file)));
        }
      }
    }

    for (const name of outside.keys()) {
      add(`node_modules/${name}/package.json`);
      whole.add(name);
    }
  }

  // packages that publish source maps: bundler maps chain through them to files that didn't ship
  for (const name of packages.keys()) {
    for (const packageRoot of packages.get(name).roots) {
      const dir = resolve(root, packageRoot);
      if (existsSync(dir) && walk(dir).some((file) => file.endsWith('.map'))) {
        whole.add(name);
      }
    }
  }

  return {
    format: `deployment (${dirs.join(', ')}; ${copied} deployed package files, ${mapped} bundled files with source maps)`,
    packages,
    graph: null,
    whole,
    own,
    selfVouched: [...selfVouched],
    unmapped: [...unmapped, ...unparsed],
    unattributed,
    missingRuntime,
    escapes,
    unplaced: [...unplaced].map(([source, file]) => ({ source, file })),
    missingDirs: dirs.filter((dir) => !existsSync(resolve(root, dir))),
    loadedFromOutside: [...outside].map(([name, from]) => ({ name, from })),
    missingHalves: missingHalves(dirs, root),
    mapsRead: [...mapsRead],
    hasServer: copied > 0 || serverCode > 0, // a server's own files, or code that loads Node's modules unguarded
  };
}

/**
 * One sha256 for everything the deployment folders hold that vexproof reads as code, and for the source maps it
 * read them with (`mapsRead`, from readDeployment; they can be in a --maps folder): each file's path and
 * content, in path order. Other maps, and files under no code extension, are left out. Two deployments with
 * the same digest got the same verdicts from the same evidence.
 */
export function deploymentDigest(dirs, root = process.cwd(), { mapsRead = [] } = {}) {
  const hash = createHash('sha256');
  const byPath = (first, second) => {
    if (first[0] < second[0]) {
      return -1;
    }

    return first[0] > second[0] ? 1 : 0;
  };
  const codeFiles = dirs.flatMap((dir) => walk(resolve(root, dir), [], new Set()))
    .filter((file) => JS.test(file) || /\.(json|node|wasm)$/.test(file));
  const files = [...new Set([...codeFiles, ...mapsRead.map((file) => resolve(root, file))])]
    .map((file) => [posix(relative(root, file)), file])
    .sort(byPath);

  for (const [relativePath, file] of files) {
    let buffer;
    try {
      buffer = readFileSync(file);
    } catch {
      continue;
    }

    hash.update(`${relativePath}\0${buffer.length}\0`).update(buffer);
  }

  return hash.digest('hex');
}

/**
 * Of the named packages, those with a source map inlined in one of their files. A bundler follows such a map to
 * the package's original sources just as it follows a .map file, so the package is taken whole. Looked for only
 * in the packages asked about (those with a finding): every file's end has to be read.
 */
export function inlineMapPackages(moduleMap, names, root = process.cwd()) {
  const out = [];
  const tail = Buffer.alloc(160);
  const endsInBase64 = (file) => {
    let descriptor;
    try {
      descriptor = openSync(file, 'r');
      const size = fstatSync(descriptor).size;
      const bytesRead = readSync(descriptor, tail, 0, Math.min(160, size), Math.max(0, size - 160));

      return /[A-Za-z0-9+/]{120,}={0,2}\s*$/.test(tail.toString('latin1', 0, bytesRead));
    } catch {
      return false;
    } finally {
      if (descriptor !== undefined) {
        try {
          closeSync(descriptor);
        } catch {
          /* closed */
        }
      }
    }
  };
  const holdsInlineMap = (dir) => walk(dir).some((file) => JS.test(file)
    && !/[\\/]node_modules[\\/]/.test(file.slice(dir.length))
    && endsInBase64(file));

  // `names` come from findings, whose purls may spell a name in lower case (see names.js); the map keeps the
  // published spelling, which is what is returned
  const keyOf = new Map([...moduleMap.packages.keys()].map((key) => [npmName(key), key]));
  for (const asked of names) {
    const name = keyOf.get(npmName(asked));
    const entry = name && moduleMap.packages.get(name);
    if (!entry || moduleMap.whole?.has(name)) {
      continue;
    }

    const dirs = [...entry.roots].map((packageRoot) => resolve(root, packageRoot)).filter((dir) => existsSync(dir));
    if (dirs.some((dir) => holdsInlineMap(dir))) {
      out.push(name);
    }
  }

  return out;
}

/** One module map from several (browser + server, several deployments). The import graph survives only if all have one. */
export function mergeModuleMaps(maps) {
  if (maps.length === 1) {
    return maps[0];
  }

  const packages = new Map();
  const whole = new Set();
  const own = new Set();
  for (const moduleMap of maps) {
    for (const wholeName of moduleMap.whole ?? []) {
      whole.add(wholeName);
    }
    for (const ownPath of moduleMap.own ?? []) {
      own.add(ownPath);
    }
    for (const [name, entry] of moduleMap.packages) {
      if (!packages.has(name)) {
        packages.set(name, { roots: new Set(), files: new Set(), byRoot: new Map() });
      }

      const merged = packages.get(name);
      for (const packageRoot of entry.roots) {
        merged.roots.add(packageRoot);
      }
      for (const file of entry.files) {
        merged.files.add(file);
      }
      for (const [packageRoot, rootFiles] of entry.byRoot ?? []) {
        if (!merged.byRoot.has(packageRoot)) {
          merged.byRoot.set(packageRoot, new Set());
        }
        for (const file of rootFiles) {
          merged.byRoot.get(packageRoot).add(file);
        }
      }
    }
  }

  let graph = null;
  if (maps.every((moduleMap) => moduleMap.graph)) {
    graph = { importers: new Map(), shipped: new Set() };
    for (const moduleMap of maps) {
      for (const shippedModule of moduleMap.graph.shipped) {
        graph.shipped.add(shippedModule);
      }
      for (const [imported, importers] of moduleMap.graph.importers) {
        if (!graph.importers.has(imported)) {
          graph.importers.set(imported, new Set());
        }
        for (const importer of importers) {
          graph.importers.get(imported).add(importer);
        }
      }
    }
  }

  return { format: maps.map((moduleMap) => moduleMap.format).join(' + '), packages, graph, whole, own };
}
