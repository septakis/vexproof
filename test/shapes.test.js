// SPDX-License-Identifier: MIT
// Build shapes that 1.0.0-beta.7 refused on real apps: Harbor (Angular's webpack-based builder), Headlamp
// (Rspack 2.0), immich (SvelteKit 3 on Vite 8). Each case is the smallest input with the same shape.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, relative, sep } from 'node:path';
import vexproof from '../src/vite.js';
import { readModuleMap, webpackStatsGaps } from '../src/modules.js';
import { strayOutputs } from '../src/coverage.js';
import { isBundlerRuntime, loadedSpecifiers, readDeployment } from '../src/deploy.js';

const files = (mm, name) => [...(mm.packages.get(name)?.files ?? [])].sort();
const project = (list = {}) => {
  const root = mkdtempSync(join(tmpdir(), 'vxp-shape-'));
  for (const [p, c] of Object.entries({ 'package-lock.json': '{}', ...list })) { mkdirSync(dirname(join(root, p)), { recursive: true }); writeFileSync(join(root, p), c); }
  return root;
};
const rel = (root, list) => list.map((f) => relative(root, f).split(sep).join('/'));

test("Angular's webpack-based builder: the stats list modules per chunk, not at the top", () => {
  const stats = { outputPath: '/x/dist', assets: [], chunks: [
    { id: 1, names: ['main'], modules: [
      { name: './node_modules/a/index.js', chunks: [1] },
      { name: './node_modules/b/x.js + 1 modules', chunks: [1], modules: [{ name: './node_modules/b/x.js' }, { name: './node_modules/b/y.js' }] },
    ] },
    { id: 'scripts', names: ['scripts'], modules: [] },
  ] };
  const mm = readModuleMap(stats);
  assert.match(mm.format, /^webpack-stats/);
  assert.deepEqual([files(mm, 'a'), files(mm, 'b')], [['index.js'], ['x.js', 'y.js']]);
  // a per-chunk list is checked for gaps like any other
  assert.equal(webpackStatsGaps({ chunks: [{ id: 1, names: ['main'], filteredModules: 2, modules: [] }] }).length, 1);
  assert.throws(() => readModuleMap({ chunks: [{ id: 1, modules: [{ name: './node_modules/b/x.js + 3 modules', chunks: [1], modules: [] }] }] }), /lists 0 of its 3/);
});

test('webpack stats: a chunk with no modules is not vouched for, once the stats list runtime modules', () => {
  const root = project({ 'dist/main.js': '', 'dist/runtime.js': '', 'dist/scripts.js': '' });
  const stats = (runtimeListed) => ({
    outputPath: join(root, 'dist'),
    assets: [{ name: 'main.js', chunks: [1] }, { name: 'runtime.js', chunks: [2] }, { name: 'scripts.js', chunks: ['scripts'] }],
    chunks: [
      { id: 1, modules: [{ name: './node_modules/a/index.js', chunks: [1], moduleType: 'javascript/auto' }] },
      { id: 2, modules: runtimeListed ? [{ name: 'webpack/runtime/chunk loaded', chunks: [2], moduleType: 'runtime' }] : [] },
      { id: 'scripts', modules: [] }, // files joined by a plugin (Angular's `scripts`): the stats don't say what is in them
    ],
  });
  assert.deepEqual(rel(root, strayOutputs(stats(true), { root }).stray), ['dist/scripts.js']);
  // without runtime modules in the stats, an empty chunk can't be told from one that holds only the runtime
  assert.deepEqual(strayOutputs(stats(false), { root }).stray, []);
});

test('Rspack 2.0: a member named after its concatenation is read by its real path', () => {
  const at = (p) => `C:\\proj\\node_modules\\${p}`;
  const label = './node_modules/i18n/dist/index.js + 2 modules';
  const stats = { vexproofBundler: 'rspack 2.0.0', modules: [
    { name: label, nameForCondition: at('i18n\\dist\\index.js'), chunks: ['1'], orphan: false, modules: [
      { name: './node_modules/i18n/dist/index.js', nameForCondition: at('i18n\\dist\\index.js') },
      { name: label, nameForCondition: at('i18n\\dist\\Trans.js') },
      { name: label, nameForCondition: at('helper\\lib\\h.js') },
    ] },
    { name: label, nameForCondition: at('i18n\\dist\\Trans.js'), chunks: [], orphan: true }, // the same member again, as an entry of its own
  ] };
  assert.deepEqual(webpackStatsGaps(stats), []);
  const mm = readModuleMap(stats);
  assert.deepEqual([files(mm, 'i18n'), files(mm, 'helper')], [['dist/Trans.js', 'dist/index.js'], ['lib/h.js']]);
  assert.deepEqual([...mm.packages.get('i18n').roots], ['node_modules/i18n']);
  // a concatenation that is in a chunk and lists no members is still a gap, and the message doesn't say "use the plugin" to someone who did
  assert.throws(() => readModuleMap({ vexproofBundler: 'rspack 2.0.0', modules: [{ name: label, nameForCondition: at('i18n\\dist\\index.js'), chunks: ['1'], orphan: false }] }),
    (e) => /lists 0 of its 2/.test(e.message) && /written by the VexproofPlugin/.test(e.message) && !/Use the VexproofPlugin/.test(e.message));
});

test("Vite 8: the bundler's own helper chunks have no source map and hold no package code", () => {
  const runtime = 'var e=Object.create,t=Object.defineProperty,n=Object.getOwnPropertyDescriptor,r=Object.getOwnPropertyNames,i=Object.getPrototypeOf,a=Object.prototype.hasOwnProperty,o=(e,t)=>()=>(t||e((t={exports:{}}).exports,t),t.exports);export{o as t};';
  const preload = 'var i=function(e){let n=document.createElement(`link`);n.rel=`modulepreload`;n.onerror=()=>{throw Error(`Unable to preload CSS for ${e}`)};return n};export{i as t};';
  const is = (code) => isBundlerRuntime(code, loadedSpecifiers(code));
  assert.ok(is(runtime) && is(preload));
  assert.ok(!is(runtime.replace('export{', 'function leftPad(){}export{'))); // anything besides the helpers
  assert.ok(!is(runtime.replace('a=Object.prototype.hasOwnProperty,', '')));  // not the whole set of helpers
  assert.ok(!is(`import x from "pkg";${runtime}`));
  assert.ok(!is('function pkg(){ return 1 }'));
  const root = project({ 'out/rt.js': runtime, 'out/preload.js': preload, 'out/other.js': 'function pkg(){ return 1 }' });
  assert.deepEqual(readDeployment(['out'], { root }).unmapped, ['out/other.js']);
});

test('Vite plugin: a worker chunk recorded under a guessed folder moves to where the main build emits it', () => {
  const root = mkdtempSync(join(tmpdir(), 'vxp-shape-'));
  const ctx = { meta: { viteVersion: '8.0.0', rolldownVersion: '1.0.0' } };
  const worker = vexproof({ root, output: 'mm.json' }), main = vexproof({ root, output: 'mm.json' });
  worker.configResolved({ root, build: { outDir: 'dist' } }); // the worker's build sees Vite's default folder
  main.configResolved({ root, build: { outDir: '.svelte-kit/output/client' } });
  for (const p of [worker, main]) p.buildStart.call(ctx);
  worker.generateBundle.call(ctx, {}, { 'workers/hash-abc.js': { type: 'chunk', fileName: 'workers/hash-abc.js', modules: { [join(root, 'node_modules/noble/sha.js')]: { renderedLength: 9 } } } });
  main.generateBundle.call(ctx, { dir: join(root, '.svelte-kit/output/client') }, {
    'entry.js': { type: 'chunk', fileName: 'entry.js', modules: { [join(root, 'src/app.js')]: { renderedLength: 3 } } },
    'workers/hash-abc.js': { type: 'asset', fileName: 'workers/hash-abc.js', source: '' }, // the finished worker, handed over as a file
    'logo.svg': { type: 'asset', fileName: 'logo.svg', source: '' },
  });
  main.closeBundle();
  const out = JSON.parse(readFileSync(join(root, 'mm.json'), 'utf8'));
  assert.deepEqual(Object.keys(out.outputs).sort(), ['.svelte-kit/output/client/entry.js', '.svelte-kit/output/client/workers/hash-abc.js']);
  assert.deepEqual(files(readModuleMap(out), 'noble'), ['sha.js']);
});
