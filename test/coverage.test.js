// SPDX-License-Identifier: MIT
// Every JavaScript file a build wrote must be accounted for, whichever tool wrote the module map, and a check
// that cannot run must refuse. Each case builds a small project on disk; the shapes were found on real apps
// (Actual Budget, Argo CD, Excalidraw, immich, Jaeger UI, Open WebUI, paperless-ngx).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { strayOutputs, accountFor, addWorkspacePackages, CoverageError } from '../src/coverage.js';
import { readModuleMap } from '../src/modules.js';
import { readDeployment, loadedSpecifiers, usesNodeBuiltins } from '../src/deploy.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const put = (root, files) => { for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(root, p)), { recursive: true }); writeFileSync(join(root, p), c); } };
const project = (files = {}) => {
  const root = mkdtempSync(join(tmpdir(), 'vxp-cov-'));
  put(root, { 'package-lock.json': '{}', 'package.json': '{"name":"app","version":"1.0.0"}', ...files });
  return root;
};
const rel = (root, files) => files.map((f) => relative(root, f).split(sep).join('/'));
const map = (sources) => JSON.stringify({ version: 3, sources, mappings: '' });

test('Vite plugin map: a recorded output folder that is not here is a refusal, not a pass', () => {
  const mm = { vexproof: 1, outDirs: ['dist', 'ssr-out'], outputs: { 'dist/a.js': { inputs: {} } } };
  const root = project({ 'dist/a.js': '' });
  assert.deepEqual(strayOutputs(mm, { root }).stray, []); // ssr-out holds no recorded chunk, so it may be missing
  // the same map read from another folder, as when vexproof runs at the repository root
  assert.throws(() => strayOutputs(mm, { root: project() }), (e) => e instanceof CoverageError && /"dist".*does not exist/.test(e.message));
  assert.throws(() => strayOutputs({ vexproof: 1, outputs: mm.outputs }, { root }), /older vexproof plugin/);
});

test('esbuild metafile: the folder its outputs share is checked, and files there that it does not list are found', () => {
  const meta = { inputs: {}, outputs: { 'dist/web/main.js': { inputs: {} }, 'dist/web/chunks/c.js': { inputs: {} }, 'dist/web/main.css': {} } };
  const root = project({ 'dist/web/main.js': '', 'dist/web/chunks/c.js': '', 'dist/web/extra/copied.js': '', 'src/own.js': '' });
  assert.deepEqual(rel(root, strayOutputs(meta, { root }).stray), ['dist/web/extra/copied.js']);
  assert.throws(() => strayOutputs(meta, { root: project() }), (e) => e instanceof CoverageError && /were found/.test(e.message));
});

test('Angular stats: outputs are named relative to the stats file, with one copy per locale when localized', () => {
  const stats = { inputs: {}, outputs: { 'main.js': { inputs: {} }, 'polyfills.js': { inputs: {} } } };
  const one = project({ 'out/browser-stats.json': '{}', 'out/main.js': '', 'out/polyfills.js': '', 'out/assets/pdf.worker.mjs': '' });
  assert.deepEqual(rel(one, strayOutputs(stats, { root: one, file: join(one, 'out/browser-stats.json') }).stray), ['out/assets/pdf.worker.mjs']);
  const many = project({ 'out/browser-stats.json': '{}', 'out/en/main.js': '', 'out/en/polyfills.js': '', 'out/de/main.js': '', 'out/de/polyfills.js': '', 'out/de/assets/x.js': '' });
  assert.deepEqual(rel(many, strayOutputs(stats, { root: many, file: join(many, 'out/browser-stats.json') }).stray), ['out/de/assets/x.js']);
});

test('webpack stats: files of chunks and of child compilations are recorded; a copied file names its origin', () => {
  const stats = {
    modules: [], vexproofBundler: 'webpack 5', vexproofOutDir: 'dist',
    assets: [
      { name: 'main.js', chunks: [1] },
      { name: 'editor.worker.js', chunks: [] }, // listed by the parent without a chunk, and by its child with one
      { name: 'assets/swagger.js', chunks: [], info: { copied: true, sourceFilename: 'node_modules/swagger-ui-dist/swagger-ui-bundle.js' } },
    ],
    children: [{ modules: [], assets: [{ name: 'editor.worker.js', chunks: ['w'] }] }],
  };
  const root = project({ 'dist/main.js': '', 'dist/editor.worker.js': '', 'dist/assets/swagger.js': 'minified', 'dist/stray.js': '' });
  const r = strayOutputs(stats, { root });
  assert.deepEqual(rel(root, r.stray), ['dist/stray.js']);
  assert.deepEqual(r.copied.map((c) => c.from), ['node_modules/swagger-ui-dist/swagger-ui-bundle.js']);
  assert.throws(() => strayOutputs({ modules: [] }, { root }), /no outputPath or assets/);
  assert.throws(() => strayOutputs({ modules: [], vexproofBundler: 'rspack 2' }, { root }), /older VexproofPlugin/);
  assert.throws(() => strayOutputs(stats, { root: project() }), /does not exist/);
});

test('a file the module map does not record is accounted for on its own, or named with the reason', () => {
  const worker = 'export function work(){ return 1 }', migrate = 'export function up(){ return 2 }', uses = 'import { v4 } from "uuid"; export function id(){ return v4() }';
  const root = project({
    'node_modules/pdfjs-dist/package.json': '{"name":"pdfjs-dist","version":"4.0.0"}',
    'node_modules/pdfjs-dist/build/pdf.worker.mjs': worker,
    'node_modules/workbox-core/package.json': '{"name":"workbox-core","version":"7.0.0"}',
    'node_modules/workbox-core/core.js': 'export const v = 1',
    'node_modules/.cache/build/migrate.js': migrate, // a build tool's cache: inside node_modules, but no package
    'public/migrate.js': migrate,
    'public/uses.js': uses,
    'src/sw.ts': 'x',
    'dist/assets/pdf.worker-abc.mjs': worker,
    'dist/migrate.js': migrate,
    'dist/uses.js': uses,
    'dist/empty.js': '',
    'dist/manifest.js': 'self.__MANIFEST = {"a":1};',
    'dist/sw.js': 'function s(){}\n//# sourceMappingURL=sw.js.map',
    'dist/sw.js.map': map(['../node_modules/workbox-core/core.js', '../node_modules/ghost/src/x.ts', '../src/sw.ts']),
    'dist/mystery.js': 'function who(){ return 3 }',
  });
  const stray = ['assets/pdf.worker-abc.mjs', 'migrate.js', 'uses.js', 'empty.js', 'manifest.js', 'sw.js', 'mystery.js'].map((f) => join(root, 'dist', f));
  const { accounted, unknown } = accountFor(stray, { root, outDirs: [join(root, 'dist')] });
  const by = Object.fromEntries(accounted.map((a) => [a.file, a]));
  assert.deepEqual([by['dist/assets/pdf.worker-abc.mjs'].kind, by['dist/assets/pdf.worker-abc.mjs'].adds], ['copy', ['node_modules/pdfjs-dist/build/pdf.worker.mjs']]);
  assert.equal(by['dist/migrate.js'].kind, 'own');
  assert.deepEqual([by['dist/uses.js'].kind, by['dist/uses.js'].loads], ['own', ['uuid']]);
  assert.deepEqual([by['dist/empty.js'].kind, by['dist/manifest.js'].kind], ['glue', 'glue']);
  assert.equal(by['dist/sw.js'].kind, 'mapped');
  assert.deepEqual(by['dist/sw.js'].adds, ['node_modules/workbox-core/core.js', 'node_modules/ghost/src/x.ts', 'src/sw.ts']);
  assert.deepEqual(by['dist/sw.js'].whole, ['ghost']); // named by the map, not installed: present, but no file of it can be checked
  assert.deepEqual(unknown.map((u) => u.file), ['dist/mystery.js']);
  assert.match(unknown[0].why, /no bundler recorded it/);
});

test('a workspace package bundled from source counts as shipped', () => {
  const ws = mkdtempSync(join(tmpdir(), 'vxp-ws-'));
  put(ws, {
    'package-lock.json': '{}',
    'packages/ui/package.json': '{"name":"@acme/ui","version":"2.0.0"}',
    'packages/ui/src/button.ts': 'x',
    'apps/web/package.json': '{"name":"web"}',
    'apps/web/src/main.ts': 'x',
  });
  const root = join(ws, 'apps/web');
  const mm = readModuleMap({ vexproof: 1, outDirs: ['dist'], outputs: { 'dist/a.js': { inputs: {
    'src/main.ts': { bytesInOutput: 5 }, '../../packages/ui/src/button.ts': { bytesInOutput: 9 }, 'vite/preload-helper.js': { bytesInOutput: 3 },
  } } } });
  assert.ok(!mm.packages.has('@acme/ui'));
  assert.deepEqual(addWorkspacePackages(mm, root), ['@acme/ui']); // not the app itself, and not a bundler's virtual module
  assert.deepEqual([[...mm.packages.get('@acme/ui').roots], [...mm.packages.get('@acme/ui').files]], [['../../packages/ui'], ['src/button.ts']]);
});

test('server check: a Node module loaded behind a test does not make a folder a server', () => {
  const uses = (code) => usesNodeBuiltins(loadedSpecifiers(code));
  assert.ok(uses('import http from "node:http"'));
  assert.ok(uses('(() => { var m = { 1: (module) => { module.exports = require("http") } } })()')); // a bundled server
  for (const guarded of ['if (IS_NODE) { var fs = require("fs") }', 'var c = isNode ? require("crypto") : null', 'var p = typeof process !== "undefined" && require("path")', 'try { x = require("fs") } catch (e) {}']) assert.ok(!uses(guarded), guarded);
  const client = project({ 'out/glue.js': 'function g(){ if (IS_NODE) { var fs = require("fs") } }\n//# sourceMappingURL=glue.js.map', 'out/glue.js.map': map([]) });
  assert.equal(readDeployment(['out'], { root: client }).hasServer, false);
  const server = project({ 'out/server.mjs': 'import "node:http"; function s(){}\n//# sourceMappingURL=server.mjs.map', 'out/server.mjs.map': map([]) });
  assert.equal(readDeployment(['out'], { root: server }).hasServer, true);
});

test('CLI: a copied package file counts as shipped; the same map read from another folder is refused', () => {
  const left = 'module.exports = function left(){ return 1 }';
  const root = project({
    'node_modules/left/package.json': '{"name":"left","version":"1.0.0"}',
    'node_modules/left/index.js': left,
    'dist/a.js': '',
    'dist/vendor/left.js': left, // copied into the output, never a chunk
    'vexproof-modules.json': JSON.stringify({ vexproof: 1, bundler: 'vite 8', outDirs: ['dist'], inputs: {}, outputs: { 'dist/a.js': { inputs: { 'src/a.js': { bytesInOutput: 1 } } } } }),
    'bom.json': JSON.stringify({ serialNumber: 'urn:uuid:11111111-2222-3333-4444-555555555555', version: 1, components: ['left@1.0.0', 'right@1.0.0'].map((c) => ({ purl: `pkg:npm/${c}`, 'bom-ref': c })) }),
    'findings.json': JSON.stringify([{ purl: 'pkg:npm/left@1.0.0', ids: ['GHSA-aaaa-bbbb-cccc'] }, { purl: 'pkg:npm/right@1.0.0', ids: ['GHSA-dddd-eeee-ffff'] }]),
  });
  const run = (cwd, modules) => spawnSync(process.execPath, [CLI, '--lockfile', join(root, 'bom.json'), '--findings', join(root, 'findings.json'), '--modules', modules, '--out', join(root, 'vex.json'), '--quiet'], { cwd, encoding: 'utf8' });
  const here = run(root, 'vexproof-modules.json');
  assert.equal(here.status, 0, here.stderr);
  assert.match(here.stderr, /1 output file\(s\) outside the module map accounted for: 1 copied from installed packages/);
  assert.match(here.stdout, /in_triage\s+GHSA-aaaa-bbbb-cccc/);    // left ships, in the copied file only
  assert.match(here.stdout, /not_affected\s+GHSA-dddd-eeee-ffff/); // right is nowhere in the output
  const elsewhere = run(project(), join(root, 'vexproof-modules.json'));
  assert.equal(elsewhere.status, 2);
  assert.match(elsewhere.stderr, /records build output in "dist", but .* does not exist/);
  put(root, { 'dist/mystery.js': 'function who(){ return 3 }' });
  const unknown = run(root, 'vexproof-modules.json');
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /dist\/mystery\.js: no bundler recorded it/);
});
