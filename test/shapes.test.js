// SPDX-License-Identifier: MIT
// Build shapes that 1.0.0-beta.7 refused on real apps: Harbor (Angular's webpack-based builder), Headlamp
// (Rspack 2.0), immich (SvelteKit 3 on Vite 8). Each case is the smallest input with the same shape.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, relative, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import vexproof from '../src/vite.js';
import { readModuleMap, webpackStatsGaps, attachVersions, bundleSbomFromModules, unnamedStorePackages, splitNodeModulesPath } from '../src/modules.js';
import { triage } from '../src/index.js';
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

// Two stores keep packages in a dot folder of node_modules, where the folder after node_modules is not the package.

test('Nitro: each version under node_modules/.nitro/<name>@<version> is that package, at that version', () => {
  const pkg = (name, version) => JSON.stringify({ name, version });
  const root = project({
    '.output/server/index.mjs': 'import "node:http";',
    '.output/server/node_modules/devalue/package.json': pkg('devalue', '5.8.1'), // Nitro links one version at the top
    '.output/server/node_modules/devalue/index.js': 'export const a = () => 1;',
    '.output/server/node_modules/.nitro/devalue@5.8.1/package.json': pkg('devalue', '5.8.1'),
    '.output/server/node_modules/.nitro/devalue@5.8.1/index.js': 'export const a = () => 1;',
    '.output/server/node_modules/.nitro/devalue@5.6.4/package.json': pkg('devalue', '5.6.4'),
    '.output/server/node_modules/.nitro/devalue@5.6.4/src/parse.js': 'export const b = () => 2;',
    '.output/server/node_modules/.nitro/@vue/shared@3.5.30/package.json': pkg('@vue/shared', '3.5.30'),
    '.output/server/node_modules/.nitro/@vue/shared@3.5.30/dist/shared.cjs.js': 'exports.c = () => 3;',
    '.output/server/node_modules/.cache/tool/x.js': 'export const d = () => 4;', // a tool folder, not a package
  });
  const mm = attachVersions(readDeployment(['.output'], { root }), { cwd: root });
  assert.ok(!mm.packages.has('.nitro'));
  const devalue = mm.packages.get('devalue');
  assert.deepEqual([...new Set(devalue.versionByRoot.values())].sort(), ['5.6.4', '5.8.1']);
  assert.deepEqual([...devalue.byRoot.get('.output/server/node_modules/.nitro/devalue@5.6.4')].sort(), ['package.json', 'src/parse.js']);
  assert.equal(mm.packages.get('@vue/shared').versionByRoot.get('.output/server/node_modules/.nitro/@vue/shared@3.5.30'), '3.5.30');
  // each version once, and no component for a dot folder
  const sbom = bundleSbomFromModules(mm, { cwd: root });
  assert.deepEqual(sbom.components.map((c) => c.purl).sort(), ['pkg:npm/%40vue/shared@3.5.30', 'pkg:npm/devalue@5.6.4', 'pkg:npm/devalue@5.8.1']);
  // the version is also read from the folder name, when the package.json isn't there
  assert.deepEqual(splitNodeModulesPath('out/node_modules/.nitro/@vue/shared@3.5.30/dist/x.js'), { name: '@vue/shared', root: 'out/node_modules/.nitro/@vue/shared@3.5.30', file: 'dist/x.js' });
  const bare = attachVersions(readModuleMap({ inputs: {}, outputs: { 'o.js': { inputs: { 'out/node_modules/.nitro/devalue@5.6.4/index.js': { bytesInOutput: 9 } } } } }), { cwd: root });
  assert.equal(bare.packages.get('devalue').versionByRoot.get('out/node_modules/.nitro/devalue@5.6.4'), '5.6.4');
  // a finding for the second version names it
  const lock = { components: [{ purl: 'pkg:npm/devalue@5.6.4' }, { purl: 'pkg:npm/devalue@5.8.1' }] };
  const [r] = triage({ lockfileSbom: lock, bundleSbom: sbom, findings: [{ purl: 'pkg:npm/devalue@5.6.4', id: 'GHSA-xxxx-xxxx-xxxx' }], moduleMap: mm });
  assert.equal(r.state, 'in_triage');
  assert.match(r.detail, /5\.6\.4/);
});

test("Yarn's pnpm linker: node_modules/.store/<folder>/package is the package its package.json names", () => {
  const meta = (...folders) => ({ inputs: {}, outputs: { 'dist/app.js': { inputs: Object.fromEntries(folders.map((f) => [`node_modules/.store/${f}/package/index.js`, { bytesInOutput: 9 }])) } } });
  const notInstalled = () => { throw new Error('ENOENT'); };

  // not installed where vexproof runs: an unscoped folder name leaves no doubt, a scoped one with more dashes does
  const mm = attachVersions(readModuleMap(meta('ms-npm-2.1.3-81ff3cfac1', '@a-b-npm-1.0.0-0000000001', '@a-b-c-npm-1.0.0-0000000002')), { readJson: notInstalled });
  assert.equal(mm.packages.get('ms').versionByRoot.get('node_modules/.store/ms-npm-2.1.3-81ff3cfac1/package'), '2.1.3');
  assert.deepEqual(files(mm, '@a/b'), ['index.js']);
  assert.deepEqual(unnamedStorePackages(mm), ['node_modules/.store/@a-b-c-npm-1.0.0-0000000002/package']);
  assert.throws(() => bundleSbomFromModules(mm, { readJson: notInstalled }), /Can't tell which package/);

  // installed: the package.json decides, also where the folder name says nothing
  const installed = { '@a-b-c-npm-1.0.0-0000000003': { name: '@a-b/c', version: '1.0.0' }, 'x-patch-1a2b3c4d5e-0000000004': { name: 'x', version: '3.1.0' } };
  const readJson = (p) => { const hit = Object.entries(installed).find(([f]) => p.split(sep).join('/').includes(`/.store/${f}/package/`)); if (!hit) throw new Error('ENOENT'); return hit[1]; };
  const named = attachVersions(readModuleMap(meta(...Object.keys(installed))), { readJson });
  assert.deepEqual(unnamedStorePackages(named), []);
  assert.deepEqual(bundleSbomFromModules(named, { readJson }).components.map((c) => c.purl).sort(), ['pkg:npm/%40a-b/c@1.0.0', 'pkg:npm/x@3.1.0']);
  // once named, the same folder reads as that package everywhere
  assert.equal(splitNodeModulesPath('node_modules/.store/@a-b-c-npm-1.0.0-0000000003/package/lib/y.js').name, '@a-b/c');
});

test("Yarn's pnpm linker, through the CLI: a bundled package is found, and one that can't be named stops the run", () => {
  const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
  const folder = '@my-org-pkg-npm-1.0.0-0000000005';
  const root = project({
    'dist/app.js': 'console.log(1);',
    'meta.json': JSON.stringify({ inputs: {}, outputs: { 'dist/app.js': { inputs: { [`node_modules/.store/${folder}/package/index.js`]: { bytesInOutput: 9 }, 'app.js': { bytesInOutput: 5 } } } } }),
    'bom.json': JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [{ type: 'library', name: 'pkg', group: '@my-org', version: '1.0.0', purl: 'pkg:npm/%40my-org/pkg@1.0.0' }, { type: 'library', name: 'other', version: '2.0.0', purl: 'pkg:npm/other@2.0.0' }] }),
    'findings.json': JSON.stringify([{ purl: 'pkg:npm/%40my-org/pkg@1.0.0', id: 'GHSA-xxxx-xxxx-xxxx' }]),
  });
  const run = () => spawnSync('node', [CLI, '--lockfile', 'bom.json', '--findings', 'findings.json', '--modules', 'meta.json', '--out', 'vex.json'], { cwd: root, encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: '' } });
  const refused = run();
  assert.equal(refused.status, 2);
  assert.match(refused.stderr + refused.stdout, /can't be named/);
  assert.ok((refused.stderr + refused.stdout).includes(`node_modules/.store/${folder}/package`));
  mkdirSync(join(root, `node_modules/.store/${folder}/package`), { recursive: true });
  writeFileSync(join(root, `node_modules/.store/${folder}/package/package.json`), JSON.stringify({ name: '@my-org/pkg', version: '1.0.0' }));
  const ok = run();
  assert.equal(ok.status, 0, ok.stderr);
  const [v] = JSON.parse(readFileSync(join(root, 'vex.json'), 'utf8')).vulnerabilities;
  assert.equal(v.analysis.state, 'in_triage');
});
