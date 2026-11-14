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
import { builtinModules, stripTypeScriptTypes } from 'node:module';
import { createHash } from 'node:crypto';
import { parse } from 'acorn';
import { splitNodeModulesPath, addToMap } from './modules.js';
import { npmName } from './names.js';
import { readPackageJson } from './package-json.js';
import { listFiles } from './walk.js';
import { copyFinder } from './copies.js';

const JS = /\.(m|c)?js$/;
// TypeScript that Node 22.18+ and 24 run as it is (type stripping); declaration files hold no code
const TS = /\.(m|c)?ts$/i, DTS = /\.d\.(m|c)?ts$/i;
const isTs = (f) => TS.test(f) && !DTS.test(f);
// a source of Turbopack's own runtime, as its maps name them
const TURBOPACK_RUNTIME = /^turbopack:\/\/\/\[turbopack\]\//;
/** The debug id written at the end of a bundled file (Turbopack, esbuild, Sentry), lower case, or null. */
const debugIdOf = (code) => /\/\/[#@]\s*debugId=([0-9a-f-]{32,36})/i.exec(code.slice(-4096))?.[1]?.toLowerCase() ?? null;
/** Whether a file and a map carry the same debug id: then the map was written for this file. */
const sameDebugId = (code, map) => { const id = debugIdOf(code); return Boolean(id) && typeof map?.debugId === 'string' && map.debugId.toLowerCase() === id; };
const posix = (p) => p.split(sep).join('/');
const BUILTINS = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);

// Symbolic links to folders are not followed: a link into the deployment is walked at its real path anyway, and a
// link out of it is not part of the deployment (runtime loads through it are caught by the runtime check).
function walk(dir, out = [], followed = null) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out, followed);
    else if (e.isFile()) out.push(p);
    else if (e.isSymbolicLink()) {
      try {
        const st = statSync(p);
        if (st.isFile()) out.push(p);
        // with `followed` (a Set), linked folders are walked too, each real folder once
        else if (st.isDirectory() && followed) { const real = realpathSync(p); if (!followed.has(real)) { followed.add(real); walk(p, out, followed); } }
      } catch { /* dangling */ }
    }
  }
  return out;
}

/**
 * The half of a framework's build that was not given: a Next.js standalone folder without `.next/static`, a
 * Nitro `.output/server` without `.output/public`. The browser half ships too, and holds other packages.
 */
export function missingHalves(dirs, root = process.cwd()) {
  const abs = dirs.map((d) => resolve(root, d));
  const given = (p) => abs.some((d) => p === d || p.startsWith(d + sep) || d.startsWith(p + sep));
  const has = (d, tail, depth) => existsSync(join(d, tail)) || (depth > 0 && readdirSafe(d).some((e) => e.isDirectory() && e.name !== 'node_modules' && has(join(d, e.name), tail, depth - 1)));
  const out = [];
  for (const d of abs) {
    const p = posix(d);
    const next = p.lastIndexOf('/.next/standalone');
    if (next >= 0 && /\/\.next\/standalone(\/|$)/.test(p.slice(next))) {
      const fixed = resolve(p.slice(0, next), '.next/static');
      if (existsSync(fixed) && !given(fixed) && !has(d, '.next/static', 2)) out.push(posix(relative(root, fixed)));
    }
    // A server half beside a browser half: Nitro's .output/server and public, React Router's build/server and
    // client, Astro's dist/server and client, Angular SSR's server and browser, SvelteKit's output/server and
    // client. A sibling of those names that holds JavaScript ships too.
    if (basename(d).toLowerCase() === 'server') {
      for (const half of ['public', 'client', 'browser', 'static']) {
        const other = resolve(d, '..', half);
        if (existsSync(other) && !given(other) && listFiles(other).some((f) => JS.test(f))) out.push(posix(relative(root, other)));
      }
    }
  }
  return [...new Set(out)];
}
const readdirSafe = (d) => { try { return readdirSync(d, { withFileTypes: true }); } catch { return []; } };

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

/**
 * Source map for a bundled file: its sourceMappingURL (inline, next to it, or elsewhere by name), or file.map.
 * `base` is the deployment folder the file is in: a map found elsewhere by name must then sit in folders named
 * like every folder between `base` and the file.
 */
export function findMap(file, code, mapIndex, { base = null } = {}) {
  const tail = code.slice(-4096);
  const m = /\/[/*][#@]\s*sourceMappingURL=([^\s*]+)\s*(?:\*\/\s*)?$/.exec(tail);
  const parse = (text, where) => { try { return JSON.parse(text); } catch (e) { throw new Error(`the source map ${where} could not be read: ${e.message}`); } };
  if (m && m[1].startsWith('data:')) {
    const b64 = /;base64,(.*)$/.exec(m[1]);
    const body = b64 ? Buffer.from(b64[1], 'base64').toString('utf8') : decodeURIComponent(m[1].slice(m[1].indexOf(',') + 1));
    return { map: parse(body, `inline in ${file}`), at: file };
  }
  const read = (c) => ({ map: parse(readFileSync(c, 'utf8'), c), at: c });
  // A map found elsewhere by its name must be this file's: the generated file it names, and the debug id
  // that Turbopack, esbuild and Sentry write into both, must agree where they are written.
  const debugId = debugIdOf(code);
  const describes = ({ map }) => (typeof map.file !== 'string' || !map.file || basename(map.file) === basename(file))
    && (!debugId || typeof map.debugId !== 'string' || map.debugId.toLowerCase() === debugId);
  const beside = [], names = new Set([`${basename(file)}.map`]);
  if (m) { const u = decodeURIComponent(m[1].split('?')[0]); beside.push(resolve(dirname(file), u)); names.add(basename(u)); }
  beside.push(`${file}.map`);
  for (const c of beside) if (existsSync(c)) return read(c);
  // Not beside the file (Next.js keeps server maps in .next, outside the folder it deploys). A map of the same
  // name is this file's only if it sits in folders of the same names, all the way up to the deployment folder:
  // every route of an app is "route.js", and app/about and app/[locale]/about share "about". Among several,
  // the ones that match furthest up; if more than one is left, all of them are read, since the file is one of
  // them and reading too many can only add to what counts as shipped.
  const all = [...new Set([...names].flatMap((n) => mapIndex.get(n) ?? []))].filter((c) => existsSync(c)).map(read).filter(describes);
  const scored = all.map((x) => ({ x, n: sharedTail(file, x.at) }));
  const need = base ? relative(base, dirname(file)).split(/[\\/]/).filter(Boolean).length : 1;
  // A file at the top of the deployment folder has no folders to match: there, a map elsewhere is accepted only
  // when the file names it and nothing else has that name (a flat --maps folder).
  const usable = scored.filter((s) => (need > 0 && s.n >= need) || (need === 0 && m && all.length === 1));
  if (!usable.length) return null;
  const best = Math.max(...usable.map((s) => s.n));
  const [first, ...more] = usable.filter((s) => s.n === best).map((s) => s.x);
  return { ...first, more };
}

/**
 * A map can name a file that is itself a bundle: a minifier run over a bundler's output writes a map whose only
 * source is that output. If the named file has a map of its own beside it, that map says what is in it, so its
 * sources are taken too (a few levels deep). One with no map is taken as the project's own code, which the
 * content check then has to catch.
 */
export function withChainedSources(sources, root, bases) {
  const out = [], seen = new Set();
  const visit = (list, depth) => {
    for (const src of list) {
      out.push(src);
      if (!src.exists || depth >= 3 || !JS.test(src.path) || /(^|\/)node_modules\//.test(src.path)) continue;
      const abs = resolve(root, src.path), map = `${abs}.map`;
      if (seen.has(abs) || !existsSync(map)) continue;
      seen.add(abs);
      let m; try { m = JSON.parse(readFileSync(map, 'utf8')); } catch { continue; }
      visit(mapSources(m, map, root, bases), depth + 1);
    }
  };
  visit(sources, 0);
  return out;
}

/** How many folders two files' paths share, counted from the files upward. */
function sharedTail(a, b) {
  const x = dirname(a).split(/[\\/]/).reverse(), y = dirname(b).split(/[\\/]/).reverse();
  let n = 0;
  while (n < x.length && n < y.length && x[n] === y[n]) n++;
  return n;
}

/**
 * Every original file a source map names, as a path relative to the project root. `bases` are the folders
 * packages may be installed under (installBases); a package found under a parent gets a `../` path.
 */
const SCHEME = /^[a-z][a-z0-9+.-]+:/i; // two letters or more, so not a Windows drive

/**
 * A source as the map's author wrote it, made comparable: joined to a `sourceRoot` that is a URL, and without
 * "./" segments. A bundler that reads a package's own source map copies these strings into its own map
 * ("webpack://Lib/./src/x.js", "https://raw.githubusercontent.com/…/src/x.ts"), so the same string in an
 * installed package's map says whose code it is.
 */
function rawSource(m, s) {
  let r = s.split('?')[0];
  if (!SCHEME.test(r) && typeof m.sourceRoot === 'string' && SCHEME.test(m.sourceRoot)) r = m.sourceRoot.replace(/\/?$/, '/') + r;
  return r.replace(/\/(\.\/)+/g, '/');
}

export function mapSources(map, mapFile, root, bases = [root]) {
  const out = [];
  const visit = (m) => {
    for (const sec of m.sections ?? []) visit(sec.map);
    for (const s0 of m.sources ?? []) {
      if (!s0) continue;
      let s = s0;
      try { s = decodeURIComponent(s0); } catch { /* keep as is */ }
      // a map written on Windows names sources with backslashes; on Linux they are not separators unless made so
      s = s.replace(/\\/g, '/');
      // Next.js (Turbopack) names the generated stand-in for a client component after the file it stands for:
      // `<file>/__nextjs-internal-proxy.cjs { server => "…" }`. Count it as that file. That only ever adds a
      // file to what shipped, so it can't turn a finding into "not present".
      s = s.replace(/\/__nextjs-internal-proxy\.[cm]?js(?: \{[^]*)?$/, '');
      const before = s.split('?')[0];
      s = before.replace(/^webpack:\/\/[^/]*\//, '').replace(/^turbopack:\/\/\/?(\[project\]\/)?/, '').replace(/^file:\/\/\/?(?=[a-z]:)/i, '').replace(/^file:\/\//, '').replace(/^\[project\]\//, '');
      // webpack and Turbopack name sources from the project folder, not from the folder the map is in
      const fromProject = s !== before && !/^file:/.test(before);
      const drive = /^[a-z]:[\\/]/i.test(s); // a Windows path, not a URL scheme
      const raw = rawSource(m, before);
      // a URL, or a bundler's own scheme: no file here. Whose it is can only be told from the string itself.
      if (!drive && SCHEME.test(s)) { out.push({ path: s, exists: false, literal: s, raw }); continue; }
      let abs = s.startsWith('/') || drive ? resolve(s) : resolve(dirname(mapFile), m.sourceRoot ?? '', s);
      if (fromProject && !existsSync(abs)) for (const b of bases) { const cand = resolve(b, s); if (existsSync(cand)) { abs = cand; break; } }
      // A relative source that climbs too far ("../../../../src/routes/+page.svelte" from a map only three
      // folders deep, as SvelteKit writes them) still names a file of the project: found by what follows the dots.
      // SvelteKit writes its maps in .svelte-kit/output and an adapter copies the files elsewhere, so the files
      // it generates for the app (generated/root.svelte) are found under .svelte-kit too.
      if (!existsSync(abs) && /^(\.\.\/)+[^.]/.test(s) && !s.includes('node_modules/')) {
        const tail = s.replace(/^(\.\.\/)+/, '');
        search: for (const b of bases) {
          for (const cand of [resolve(b, tail), resolve(b, '.svelte-kit', tail)]) if (existsSync(cand)) { abs = cand; break search; }
        }
      }
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
      out.push({ path: posix(relative(root, abs)), exists: existsSync(abs), literal, raw });
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
  const put = (map, key, owner) => { if (!map.has(key)) map.set(key, []); if (!map.get(key).some((o) => o.root === owner.root)) map.get(key).push(owner); };
  for (const f of bases.flatMap((b) => walk(resolve(b, 'node_modules')))) {
    if (!f.endsWith('.map')) continue;
    const owner = splitNodeModulesPath(posix(relative(root, f)));
    if (!owner) continue;
    let m;
    try { m = JSON.parse(readFileSync(f, 'utf8')); } catch { continue; }
    for (const src of mapSources(m, f, root, bases)) {
      put(index, src.path, owner);
      put(index, src.literal, owner);
      if (src.raw && SCHEME.test(src.raw)) put(index.raw, src.raw, owner);
    }
  }
  return index;
}

// Unmapped files that can't be carrying a package's code: framework manifests (data assignments) and launchers
// like Next.js's standalone server.js. Package code defines functions; these define none beyond a couple of
// inline callbacks. Their runtime imports are still checked.
// The snippet that registers a file's debug id (Turbopack and Sentry both write one at the top of each file):
// a function, but the same few lines everywhere and nobody's package.
function withoutDebugId(code) {
  const start = /^\s*;?\s*!function\(\)\{try\s*\{/.exec(code);
  if (!start) return code;
  const close = /\}catch\(\w+\)\{\}\}\(\);?/.exec(code.slice(start[0].length, start[0].length + 700));
  if (!close) return code;
  const body = code.slice(start[0].length, start[0].length + close.index);
  // only the snippet: it names _debugIds, and holds no function, load or import of its own
  if (!body.includes('_debugIds') || /\bfunction\b|=>|\brequire\b|\bimport\b/.test(body)) return code;
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
  const body = withoutDebugId(code).replace(/^\s*\(globalThis\.(TURBOPACK\w*)\|\|\(globalThis\.\1=\[\]\)\)\.push\(\["object"==typeof document\?document\.currentScript:void 0,/, 'module.exports.push([');
  let ast;
  try { ast = parse(body, { ecmaVersion: 'latest', sourceType: 'script', allowReturnOutsideFunction: true }); } catch { return false; }
  const OK = new Set(['Program', 'ExpressionStatement', 'AssignmentExpression', 'ArrayExpression', 'Literal', 'ArrowFunctionExpression', 'FunctionExpression',
    'CallExpression', 'MemberExpression', 'Identifier', 'BlockStatement', 'ReturnStatement', 'ImportExpression', 'EmptyStatement', 'VariableDeclaration',
    'TryStatement', 'CatchClause', 'AwaitExpression', 'SequenceExpression', 'UnaryExpression', 'BinaryExpression',
    // settings handed to what was loaded: `new e.CacheFirst({ cacheName: "fonts", plugins: [new e.ExpirationPlugin({ maxEntries: 50 })] })`
    'NewExpression', 'ObjectExpression', 'Property']);
  const FREE = new Set(['module', 'exports', 'require', 'Promise', 'undefined', 'self', 'define', 'importScripts']);
  const walk = (n, params) => {
    if (!OK.has(n.type)) return false;
    if (n.type === 'Identifier') return params.has(n.name) || FREE.has(n.name);
    if (n.type === 'MemberExpression') return !n.computed ? walk(n.object, params) : walk(n.object, params) && walk(n.property, params);
    if (n.type === 'AssignmentExpression') return n.operator === '=' && n.left.type === 'MemberExpression' && walk(n.left, params) && walk(n.right, params);
    // "/_next/static/media/a.svg" + (globalThis.NEXT_CLIENT_ASSET_SUFFIX || ""): the address of a static file
    if (n.type === 'BinaryExpression') {
      const r = n.right;
      return n.operator === '+' && n.left.type === 'Literal' && typeof n.left.value === 'string' && r.type === 'LogicalExpression' && r.operator === '||'
        && r.right.type === 'Literal' && r.right.value === '' && r.left.type === 'MemberExpression' && !r.left.computed
        && r.left.object.type === 'Identifier' && r.left.object.name === 'globalThis' && /^[A-Z_]+$/.test(r.left.property.name);
    }
    if (n.type === 'Property') return !n.computed && n.kind === 'init' && !n.method && walk(n.value, params);
    // `!0`, `!1`: how a minifier writes true and false
    if (n.type === 'UnaryExpression') return n.operator === '!' && n.argument.type === 'Literal' && typeof n.argument.value === 'number';
    // `try { var d = await a.y("x"); a.n(d), c() } catch (e) { c(e) }`: an external loaded as an ES module
    if (n.type === 'CatchClause') {
      if (n.param && n.param.type !== 'Identifier') return false;
      return walk(n.body, n.param ? new Set([...params, n.param.name]) : params);
    }
    // `var d = a.i(857764)`: a module fetched from the registry, to hand on. The name is then one of the function's own.
    if (n.type === 'VariableDeclaration') {
      for (const d of n.declarations) { if (d.id.type !== 'Identifier' || !d.init || !walk(d.init, params)) return false; params.add(d.id.name); }
      return true;
    }
    let inner = params;
    if (n.type === 'ArrowFunctionExpression' || n.type === 'FunctionExpression') {
      if (n.params.some((p) => p.type !== 'Identifier')) return false;
      inner = new Set([...params, ...n.params.map((p) => p.name)]);
    }
    for (const k in n) {
      if (k === 'type' || k === 'params' || k === 'id') continue;
      const v = n[k];
      if (Array.isArray(v)) { for (const c of v) if (c && typeof c.type === 'string' && !walk(c, inner)) return false; } else if (v && typeof v.type === 'string' && !walk(v, inner)) return false;
    }
    return true;
  };
  return walk(ast, new Set());
}

export function isGlue(code) {
  code = withoutDebugId(code);
  // Decided by parsing, not by looking for the word: a file of translated strings can say "function", and code
  // can be written without it (a class, a method in an object, a getter).
  let ast = null;
  for (const sourceType of ['module', 'script']) {
    try { ast = parse(code, { ecmaVersion: 'latest', sourceType, allowHashBang: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true }); break; } catch { /* try the other */ }
  }
  if (!ast) return false;
  // a function with nothing in it does nothing (a placeholder component: `function e(e){}`)
  const empty = (n) => n.body?.type === 'BlockStatement' && n.body.body.length === 0;
  let arrows = 0;
  const stack = [ast];
  while (stack.length) {
    const n = stack.pop();
    if (/^(ClassDeclaration|ClassExpression)$/.test(n.type)) return false;
    if (/^(FunctionExpression|FunctionDeclaration)$/.test(n.type) && !empty(n)) return false;
    // up to two small arrows, as manifests and loaders have (`()=>import("./x.js")`)
    if (n.type === 'ArrowFunctionExpression' && !empty(n) && ++arrows > 2) return false;
    for (const k in n) {
      const v = n[k];
      if (Array.isArray(v)) { for (const c of v) if (c && typeof c.type === 'string') stack.push(c); } else if (v && typeof v.type === 'string') stack.push(v);
    }
  }
  return true;
}

const RUNTIME_ALIASES = ['Object.create', 'Object.defineProperty', 'Object.getOwnPropertyDescriptor', 'Object.getOwnPropertyNames', 'Object.getPrototypeOf', 'Object.prototype.hasOwnProperty'];

/**
 * Chunks a bundler writes for itself. They get no source map, because no source file is behind them:
 *   - Rolldown's runtime, the helpers that define modules and convert between module formats, which Vite 8
 *     splits into a chunk of its own: one `var` statement of Object.* aliases and functions, then an export list;
 *   - Vite's preload helper, which loads a lazy chunk's CSS and dependencies ahead of it.
 * Recognised narrowly, by shape and content, because a file taken for one of these is taken to hold no package
 * code. Anything that doesn't fit stays an unmapped file, and is refused.
 */
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
  if (!code.startsWith('if(!self.define){')) return null;
  const at = code.indexOf('}define([');
  if (at < 0 || at > 1500 || !/register its module/.test(code.slice(0, at))) return null;
  return isLoaderStub(code.slice(at + 1)) ? ['workbox-build', '@surma/rollup-plugin-off-main-thread'] : null;
}

export function isBundlerRuntime(code, specs) {
  if (code.length > 4096 || !specs || specs.size) return false; // small, and loads nothing
  if (code.includes('modulepreload') && code.includes('Unable to preload CSS for') && code.includes('vite:preloadError')) return true;
  let ast;
  try { ast = parse(code, { ecmaVersion: 'latest', sourceType: 'module' }); } catch { return false; }
  const [decl, exp] = ast.body;
  if (ast.body.length !== 2 || decl.type !== 'VariableDeclaration' || exp.type !== 'ExportNamedDeclaration' || exp.source || exp.declaration) return false;
  const aliases = new Set();
  for (const d of decl.declarations) {
    const init = d.init;
    if (init?.type === 'MemberExpression') aliases.add(code.slice(init.start, init.end));
    else if (init?.type !== 'ArrowFunctionExpression' && init?.type !== 'FunctionExpression') return false;
  }
  return aliases.size === RUNTIME_ALIASES.length && RUNTIME_ALIASES.every((a) => aliases.has(a));
}

/**
 * Module specifiers a bundled file loads at runtime: static and dynamic imports, re-exports, and require()
 * calls with a string argument. Parsed, not pattern-matched, so examples in comments and strings don't count.
 * Returns null when the file doesn't parse (the caller then errs on the safe side).
 */
// require("x") as bundlers leave it in their output: esbuild's __require in ESM output, webpack's
// __non_webpack_require__, module.require, and createRequire(import.meta.url)("x").
const REQUIRE = /^(_*require\d*|__non_webpack_require__|nodeRequire)$/;
const isRequire = (c) => (c.type === 'Identifier' && REQUIRE.test(c.name))
  || (c.type === 'MemberExpression' && !c.computed && c.property.name === 'require' && c.object.type === 'Identifier' && c.object.name === 'module')
  || (c.type === 'CallExpression' && ((c.callee.type === 'Identifier' && c.callee.name === 'createRequire')
    || (c.callee.type === 'MemberExpression' && !c.callee.computed && c.callee.property.name === 'createRequire')));

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
    else if (n.type === 'CallExpression' && isRequire(n.callee) && lit(n.arguments[0])) spec = lit(n.arguments[0]);
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
  for (const s of specs) {
    if (!isBare(s)) continue;
    // "punycode/" is how code asks for the installed package of a name Node also has built in
    if (!s.endsWith('/') && (BUILTINS.has(s) || BUILTINS.has(packageOf(s)))) continue;
    names.add(packageOf(s));
  }
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
  // project files that vouch for a deployed file only by being its git-tracked original (see the CLI's content check)
  const selfVouched = new Set();
  const add = (rel) => {
    if (splitNodeModulesPath(rel)) addToMap(packages, rel);
    else if (!/(^|\/)node_modules\//.test(rel)) own.add(rel);
  };
  const lexDirs = dirs.map((d) => resolve(root, d));
  // a folder linked into the deployment is part of it wherever it really lives, so links are followed here
  const files = dirs.flatMap((d) => walk(resolve(root, d), [], new Set()));
  const mapIndex = new Map();
  // a map inside a deployed package describes that package's file, never a bundle of the app's
  for (const f of [...files, ...mapDirs.flatMap((d) => walk(resolve(root, d)))]) if (f.endsWith('.map') && !/[\\/]node_modules[\\/]/.test(f)) {
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
    try { real = realpathSync(dir); name = readPackageJson(real).pkg?.name ?? entryName; } catch { /* not a package */ }
    deployed.set(entryName, { name, inside: real ? inside(real) : false });
  };
  const packagesIn = (q, inStore = false) => {
    for (const x of scan(q)) {
      // a deployed pnpm or Bun store: its packages are in the deployment, and code inside the store loads them
      // by name (createRequire(<a path in the store>)("undici")), though no top-level folder has that name
      if ((x.name === '.pnpm' || x.name === '.bun') && !inStore) { for (const s of scan(join(q, x.name))) packagesIn(join(q, x.name, s.name, 'node_modules'), true); continue; }
      // Yarn's pnpm linker: node_modules/.store/<name>-npm-<version>-<hash>/package, named by its package.json
      if (x.name === '.store' && !inStore) {
        for (const s of scan(join(q, x.name))) {
          const dir = join(q, x.name, s.name, 'package'), n = readPackageJson(dir).pkg?.name;
          if (typeof n === 'string' && n && !deployed.has(n)) record(dir, n);
        }
        continue;
      }
      if (x.name.startsWith('.')) continue;
      if (inStore && deployed.has(x.name)) continue; // what a top-level folder says stands
      if (x.name.startsWith('@')) for (const y of scan(join(q, x.name))) record(join(q, x.name, y.name), `${x.name}/${y.name}`);
      else record(join(q, x.name), x.name);
    }
  };
  const findNodeModules = (p) => { for (const e of scan(p)) {
    const q = join(p, e.name);
    if (e.name === 'node_modules') packagesIn(q);
    else if (e.isDirectory()) findNodeModules(q);
  } };
  for (const d of dirs) {
    const p = resolve(root, d);
    if (basename(p) === 'node_modules') packagesIn(p); // --deploy node_modules: the folder itself holds the packages
    findNodeModules(p);
  }

  // byte-identical copies of installed package files (polyfills, runtimes), and of files the project tracks
  const copies = copyFinder({ root, bases, outDirs: absDirs });

  const unmapped = [], missingRuntime = [], unparsed = [], unattributed = [], escapes = [];
  const unplaced = new Map(); // a source that is no file and no known virtual module -> a file whose map names it
  let pkgMaps = null;
  let mapped = 0, copied = 0, serverCode = 0;
  for (const f of files) {
    if (!JS.test(f) && !f.endsWith('.json') && !f.endsWith('.node') && !isTs(f)) continue;
    const rel = posix(relative(root, f));
    if (/(^|\/)node_modules\//.test(rel)) { if (!f.endsWith('.map')) { add(rel); copied++; } continue; }
    if (!JS.test(f) && !isTs(f)) continue;
    const buf = readFileSync(f);
    // TypeScript is read with its types stripped, as Node runs it; a Node too old to strip them can't tell
    let code = buf.toString('utf8');
    if (isTs(f)) {
      try { code = stripTypeScriptTypes(code); } catch { unparsed.push(rel); continue; }
    }
    const specs = loadedSpecifiers(code);
    if (!specs) { unparsed.push(rel); continue; }
    const loadsNode = usesNodeBuiltins(specs);
    for (const spec of runtimeImports(specs)) {
      const d = deployed.get(spec);
      let name = d?.name ?? spec;
      if (lockNames && !lockNames.has(name)) {
        // Next.js loads an external under a hashed alias (js-yaml-77b6df11dc860fde); without its link, the name says whose it is
        const bare = name.replace(/-[0-9a-f]{16}$/, '');
        if (bare === name || !lockNames.has(bare)) continue; // not installed, so it can't hold a finding
        name = bare;
      }
      if (!d?.inside) missingRuntime.push({ name, from: rel });
    }
    // A relative or absolute load that leaves the deployment: for an installed package it is a runtime load of
    // that package. For any other code that is there (a generated client beside the build), it is code that runs
    // and is in no deployment folder, so nothing it holds or loads can be checked. A target that isn't there
    // is left alone: where the server runs, it may be something else, and nothing here can say what.
    for (const spec of specs) {
      if (!/^\.{1,2}\//.test(spec) && !/^\/|^[a-z]:[\\/]/i.test(spec)) continue;
      const target = /^\.{1,2}\//.test(spec) ? resolve(dirname(f), spec) : resolve(spec);
      if (lexDirs.some((d) => target === d || target.startsWith(d + sep))) continue;
      const s = splitNodeModulesPath(posix(relative(root, target)));
      if (s) { if (!lockNames || lockNames.has(s.name)) missingRuntime.push({ name: s.name, from: rel }); continue; }
      const code0 = ['', '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '/index.js', '/index.mjs'].map((x) => target + x).find((p) => { try { return statSync(p).isFile(); } catch { return false; } });
      if (code0 && !code0.endsWith('.json')) escapes.push({ target: posix(relative(root, code0)), from: rel });
    }
    const found = findMap(f, code, mapIndex, { base: lexDirs.find((d) => f === d || f.startsWith(d + sep)) ?? null });
    // One map per file: of two files joined, each with its own, only the last would be read. And a map that
    // names no source at all says nothing about a file that holds code.
    // (counted as lines of their own: a bundle can hold the words in a string, as the TypeScript compiler's does)
    const several = (code.match(/^\s*\/\/[#@]\s*sourceMappingURL=/gm) ?? []).length > 1;
    const sources = found && !several ? withChainedSources([found, ...(found.more ?? [])].flatMap((x) => mapSources(x.map, x.at, root, bases)), root, bases) : [];
    if (found && !several && (sources.length || isGlue(code) || isLoaderStub(code))) {
      mapped++;
      // The server's code is code a bundler made, so it has a map. A script of the project's own that loads a
      // Node module (public/healthcheck.js) does not make a folder of browser files a server.
      if (loadsNode) serverCode++;
      let madeUp = 0;
      for (const src of sources) {
        if (src.exists) {
          add(src.path);
          // A package file that is not JavaScript (src/parse.ts) is an original the package publishes beside
          // what it runs: the bundler's map was led there by the package's own, inline or not. The files that
          // ran are then not the ones named, so file-level rules can't be checked for it.
          const p = splitNodeModulesPath(src.path);
          if (p && !/\.(m|c)?js$|\.json$|\.node$/.test(src.path)) whole.add(p.name);
          continue;
        }
        // not a real file: a source reached through a package's own map, or a bundler's virtual module
        const s0 = splitNodeModulesPath(src.path);
        if (s0 && existsSync(resolve(root, s0.root))) { add(src.path); whole.add(s0.name); continue; }
        pkgMaps ??= packageMapIndex(root, bases);
        const owners = pkgMaps.get(src.path) ?? pkgMaps.get(src.literal) ?? pkgMaps.raw.get(src.raw);
        if (owners) { for (const o of owners) { add(`${o.root}/${o.file}`); whole.add(o.name); } continue; }
        if (/(^|\/)node_modules\//.test(src.path)) { unattributed.push(`${src.path} (in ${rel})`); continue; }
        // Turbopack's own runtime (turbopack:///[turbopack]/…) is the bundler's code, which ships inside next: it
        // counts as that package, the way webpack's runtime counts as webpack
        if (TURBOPACK_RUNTIME.test(src.raw ?? '')) {
          if (!lockNames || lockNames.has('next')) { add('node_modules/next/package.json'); whole.add('next'); }
          continue;
        }
        // What is left names no file and no installed package's map names it: a module the bundler made up
        // (a CSS module's stand-in, a generated font module, a virtual: import). Counted, so the run can say so.
        unplaced.set(src.raw ?? src.literal, rel);
        madeUp++;
      }
      // A map whose every source is made up says nothing about what is in the file (coverage.js holds the same
      // for module maps): it may be another build's map. It stands only when it is provably this file's, by the
      // debug id both carry; the bundler that wrote both lists every module of the file in it. A file with no
      // code of its own, or the bundler's runtime, needs nothing more either.
      const ownMap = Boolean(found) && sameDebugId(code, found.map);
      if (sources.length && madeUp === sources.length && !ownMap && !isGlue(code) && !isLoaderStub(code) && !isBundlerRuntime(code, specs)) {
        mapped--;
        if (loadsNode) serverCode--;
        unmapped.push(rel);
      }
      continue;
    }
    // every installed file it is a copy of: two packages can hold the same file, and both then ship
    const same = copies.installedAll(buf);
    if (same.length) { for (const c of same) add(posix(relative(root, c))); continue; }
    if (isGlue(code) || isBundlerRuntime(code, specs) || isLoaderStub(code)) continue;
    // a file a build tool wrote from its own template: that tool's code is in it
    const tools = generatedBy(code);
    if (tools) { for (const n of tools) if (!lockNames || lockNames.has(n)) { add(`node_modules/${n}/package.json`); whole.add(n); } continue; }
    // A file of the project's own, deployed as it is (public/sw.js): what it loads by name was checked above.
    // It is filed under its own path, so that a vendored package's file is given to that package.
    const mine = copies.project(buf);
    if (mine) { const p = posix(relative(root, mine)); own.add(p); selfVouched.add(p); continue; }
    unmapped.push(rel);
  }
  // compiled code outside node_modules (a .node addon or .wasm file a bundler copied): whose it is, if it is a copy
  for (const f of files) {
    if (!/\.(node|wasm)$/.test(f) || /[\\/]node_modules[\\/]/.test(f)) continue;
    let buf; try { buf = readFileSync(f); } catch { continue; }
    for (const c of copies.installedAll(buf)) add(posix(relative(root, c)));
  }

  // A deployed package can load another that the deployment does not hold: Node then finds it further up, in
  // the project's own node_modules, when the server runs from there. Such a package is used by the product,
  // so it counts as shipped. Looked for cheaply first (a load-shaped string in the text), then by parsing. A
  // load behind a test (`try { require("optional") } catch {}`) counts too: the lockfile says the package is
  // installed, so the load succeeds, as it does for bundled code above.
  const outside = new Map(); // name -> a deployed file that loads it
  if (lockNames) {
    const realDirs = new Map(), held = new Map();
    const realDir = (d) => { if (!realDirs.has(d)) { try { realDirs.set(d, realpathSync(d)); } catch { realDirs.set(d, d); } } return realDirs.get(d); };
    const holds = (dir, name) => {
      for (let d = dir; inside(d); d = dirname(d)) {
        const k = `${d}\0${name}`;
        if (!held.has(k)) held.set(k, existsSync(join(d, 'node_modules', name)));
        if (held.get(k)) return true;
        if (dirname(d) === d) break;
      }
      return false;
    };
    // require("x") and its bundled spellings (__require, nodeRequire), import/from "x", and a call on a call,
    // createRequire(import.meta.url)("x"); loadedSpecifiers then says which of these really are loads
    const LOADS = /(?:require\d*|import|from)\s*\(?\s*["']([^"'./][^"']*)["']|\)\s*\(\s*["']([^"'./][^"']*)["']/gi;
    for (const f of files) {
      if (!JS.test(f) || !/[\\/]node_modules[\\/]/.test(f)) continue;
      let text;
      try { if (statSync(f).size > 4 * 1024 * 1024) continue; text = readFileSync(f, 'utf8'); } catch { continue; }
      const self = splitNodeModulesPath(posix(relative(root, f)))?.name;
      const dir = realDir(dirname(f));
      const absent = new Set();
      for (const m of text.matchAll(LOADS)) {
        const name = packageOf(m[1] ?? m[2]);
        if (name !== self && lockNames.has(name) && !outside.has(name) && !holds(dir, name)) absent.add(name);
      }
      if (!absent.size) continue;
      // a file that doesn't parse can't be told apart: what it seems to load counts
      const specs = loadedSpecifiers(text);
      for (const name of specs ? runtimeImports(specs) : absent) if (absent.has(name)) outside.set(name, posix(relative(root, f)));
    }
    for (const name of outside.keys()) { add(`node_modules/${name}/package.json`); whole.add(name); }
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
    packages, graph: null, whole, own, selfVouched: [...selfVouched], unmapped: [...unmapped, ...unparsed], unattributed, missingRuntime, escapes,
    unplaced: [...unplaced].map(([source, file]) => ({ source, file })),
    missingDirs: dirs.filter((d) => !existsSync(resolve(root, d))),
    loadedFromOutside: [...outside].map(([name, from]) => ({ name, from })),
    missingHalves: missingHalves(dirs, root),
    hasServer: copied > 0 || serverCode > 0, // a server's own files, or code that loads Node's modules unguarded
  };
}

/**
 * One sha256 for everything the deployment folders hold that vexproof reads as code: each file's path and
 * content, in path order (source maps and files under no code extension are left out). Two deployments with
 * the same digest got the same verdicts from the same evidence.
 */
export function deploymentDigest(dirs, root = process.cwd()) {
  const h = createHash('sha256');
  const files = [...new Set(dirs.flatMap((d) => walk(resolve(root, d), [], new Set())))]
    .filter((f) => JS.test(f) || /\.(json|node|wasm)$/.test(f))
    .map((f) => [posix(relative(root, f)), f]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  for (const [rel, f] of files) {
    let buf; try { buf = readFileSync(f); } catch { continue; }
    h.update(`${rel}\0${buf.length}\0`).update(buf);
  }
  return h.digest('hex');
}

/**
 * Of the named packages, those with a source map inlined in one of their files. A bundler follows such a map to
 * the package's original sources just as it follows a .map file, so the package is taken whole. Looked for only
 * in the packages asked about (those with a finding): every file's end has to be read.
 */
export function inlineMapPackages(moduleMap, names, root = process.cwd()) {
  const out = [];
  const tail = Buffer.alloc(160);
  const endsInBase64 = (f) => {
    let fd;
    try {
      fd = openSync(f, 'r');
      const size = fstatSync(fd).size;
      const n = readSync(fd, tail, 0, Math.min(160, size), Math.max(0, size - 160));
      return /[A-Za-z0-9+/]{120,}={0,2}\s*$/.test(tail.toString('latin1', 0, n));
    } catch { return false; } finally { if (fd !== undefined) try { closeSync(fd); } catch { /* closed */ } }
  };
  // `names` come from findings, whose purls may spell a name in lower case (see names.js); the map keeps the
  // published spelling, which is what is returned
  const keyOf = new Map([...moduleMap.packages.keys()].map((k) => [npmName(k), k]));
  for (const asked of names) {
    const name = keyOf.get(npmName(asked));
    const entry = name && moduleMap.packages.get(name);
    if (!entry || moduleMap.whole?.has(name)) continue;
    const dirs = [...entry.roots].map((r) => resolve(root, r)).filter((d) => existsSync(d));
    if (dirs.some((d) => walk(d).some((f) => JS.test(f) && !/[\\/]node_modules[\\/]/.test(f.slice(d.length)) && endsInBase64(f)))) out.push(name);
  }
  return out;
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
