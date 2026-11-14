// SPDX-License-Identifier: MIT
// Build shapes that 1.0.0-beta.7 refused on real apps: Harbor (Angular's webpack-based builder), Headlamp
// (Rspack 2.0), immich (SvelteKit 3 on Vite 8). Each case is the smallest input with the same shape.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join, dirname, relative, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import vexproof from '../src/vite.js';
import {
  readModuleMap, webpackStatsGaps, attachVersions, bundleSbomFromModules, unnamedStorePackages, splitNodeModulesPath,
} from '../src/modules.js';
import { triage } from '../src/index.js';
import { strayOutputs } from '../src/coverage.js';
import { isBundlerRuntime, loadedSpecifiers, readDeployment } from '../src/deploy.js';
import { temporaryFolder, temporaryFolderForFile } from './lib/temporary.js';

const files = (moduleMap, name) => [...(moduleMap.packages.get(name)?.files ?? [])].sort();
const project = (list = {}) => {
  const root = temporaryFolderForFile('vxp-shape-');
  for (const [filePath, content] of Object.entries({ 'package-lock.json': '{}', ...list })) {
    mkdirSync(dirname(join(root, filePath)), { recursive: true });
    writeFileSync(join(root, filePath), content);
  }

  return root;
};
const relativePaths = (root, list) => list.map((file) => relative(root, file).split(sep).join('/'));

test("Angular's webpack-based builder: the stats list modules per chunk, not at the top", () => {
  const stats = { outputPath: '/x/dist', assets: [], chunks: [
    { id: 1, names: ['main'], modules: [
      { name: './node_modules/a/index.js', chunks: [1] },
      { name: './node_modules/b/x.js + 1 modules', chunks: [1], modules: [{ name: './node_modules/b/x.js' }, { name: './node_modules/b/y.js' }] },
    ] },
    { id: 'scripts', names: ['scripts'], modules: [] },
  ] };

  const moduleMap = readModuleMap(stats);

  assert.match(moduleMap.format, /^webpack-stats/);
  assert.deepEqual([files(moduleMap, 'a'), files(moduleMap, 'b')], [['index.js'], ['x.js', 'y.js']]);

  // a per-chunk list is checked for gaps like any other
  assert.equal(webpackStatsGaps({ chunks: [{ id: 1, names: ['main'], filteredModules: 2, modules: [] }] }).length, 1);
  assert.throws(
    () => readModuleMap({ chunks: [{ id: 1, modules: [{ name: './node_modules/b/x.js + 3 modules', chunks: [1], modules: [] }] }] }),
    /lists 0 of its 4/,
  );
});

test('webpack stats: a chunk with no modules listed is not vouched for', () => {
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

  assert.deepEqual(relativePaths(root, strayOutputs(stats(true), { root }).stray), ['dist/scripts.js']);

  // without runtime modules in the stats, an empty chunk can't be told from one that holds only the runtime:
  // neither is vouched for, and each is looked at like any other unrecorded file
  assert.deepEqual(relativePaths(root, strayOutputs(stats(false), { root }).stray), ['dist/runtime.js', 'dist/scripts.js']);
});

test('Rspack 2.0: a member named after its concatenation is read by its real path', () => {
  const at = (packagePath) => `C:\\proj\\node_modules\\${packagePath}`;
  const label = './node_modules/i18n/dist/index.js + 2 modules';
  const stats = { vexproofBundler: 'rspack 2.0.0', modules: [
    { name: label, nameForCondition: at('i18n\\dist\\index.js'), chunks: ['1'], orphan: false, modules: [
      { name: './node_modules/i18n/dist/index.js', nameForCondition: at('i18n\\dist\\index.js') },
      { name: label, nameForCondition: at('i18n\\dist\\Trans.js') },
      { name: label, nameForCondition: at('helper\\lib\\h.js') },
    ] },
    // the same member again, as an entry of its own
    { name: label, nameForCondition: at('i18n\\dist\\Trans.js'), chunks: [], orphan: true },
  ] };

  assert.deepEqual(webpackStatsGaps(stats), []);

  const moduleMap = readModuleMap(stats);

  assert.deepEqual([files(moduleMap, 'i18n'), files(moduleMap, 'helper')], [['dist/Trans.js', 'dist/index.js'], ['lib/h.js']]);
  assert.deepEqual([...moduleMap.packages.get('i18n').roots], ['node_modules/i18n']);

  // a concatenation that is in a chunk and lists no members is still a gap, and the message doesn't say "use the plugin" to someone who did
  const unlisted = {
    vexproofBundler: 'rspack 2.0.0',
    modules: [{ name: label, nameForCondition: at('i18n\\dist\\index.js'), chunks: ['1'], orphan: false }],
  };

  assert.throws(
    () => readModuleMap(unlisted),
    (error) => /lists 0 of its 3/.test(error.message)
      && /written by the VexproofPlugin/.test(error.message)
      && !/Use the VexproofPlugin/.test(error.message),
  );
});

test("Vite 8: the bundler's own helper chunks have no source map and hold no package code", () => {
  const runtime = 'var e=Object.create,t=Object.defineProperty,n=Object.getOwnPropertyDescriptor,r=Object.getOwnPropertyNames,i=Object.getPrototypeOf,a=Object.prototype.hasOwnProperty,o=(e,t)=>()=>(t||e((t={exports:{}}).exports,t),t.exports);export{o as t};';
  const preload = 'var i=function(e){let n=document.createElement(`link`);n.rel=`modulepreload`;n.onerror=()=>{window.dispatchEvent(new Event(`vite:preloadError`));throw Error(`Unable to preload CSS for ${e}`)};return n};export{i as t};';
  const isRuntime = (code) => isBundlerRuntime(code, loadedSpecifiers(code));

  assert.ok(isRuntime(runtime) && isRuntime(preload));
  assert.ok(!isRuntime(runtime.replace('export{', 'function leftPad(){}export{'))); // anything besides the helpers
  assert.ok(!isRuntime(runtime.replace('a=Object.prototype.hasOwnProperty,', '')));  // not the whole set of helpers
  assert.ok(!isRuntime(`import x from "pkg";${runtime}`));
  assert.ok(!isRuntime('function pkg(){ return 1 }'));

  const root = project({ 'out/rt.js': runtime, 'out/preload.js': preload, 'out/other.js': 'function pkg(){ return 1 }' });

  assert.deepEqual(readDeployment(['out'], { root }).unmapped, ['out/other.js']);
});

test('Vite plugin: a worker chunk recorded under a guessed folder moves to where the main build emits it', (testContext) => {
  const root = temporaryFolder(testContext, 'vxp-shape-');
  const context = { meta: { viteVersion: '8.0.0', rolldownVersion: '1.0.0' } };
  const worker = vexproof({ root, output: 'mm.json' });
  const main = vexproof({ root, output: 'mm.json' });
  // the worker's build sees Vite's default folder, and Vite tells its plugins it is a worker build
  worker.configResolved({ root, isWorker: true, build: { outDir: 'dist' } });
  main.configResolved({ root, build: { outDir: '.svelte-kit/output/client' } });
  for (const plugin of [worker, main]) {
    plugin.buildStart.call(context);
  }

  worker.generateBundle.call(context, {}, {
    'workers/hash-abc.js': {
      type: 'chunk', fileName: 'workers/hash-abc.js', modules: { [join(root, 'node_modules/noble/sha.js')]: { renderedLength: 9 } },
    },
  });
  main.generateBundle.call(context, { dir: join(root, '.svelte-kit/output/client') }, {
    'entry.js': { type: 'chunk', fileName: 'entry.js', modules: { [join(root, 'src/app.js')]: { renderedLength: 3 } } },
    'workers/hash-abc.js': { type: 'asset', fileName: 'workers/hash-abc.js', source: '' }, // the finished worker, handed over as a file
    'logo.svg': { type: 'asset', fileName: 'logo.svg', source: '' },
  });
  main.closeBundle();

  const writtenMap = JSON.parse(readFileSync(join(root, 'mm.json'), 'utf8'));
  assert.deepEqual(
    Object.keys(writtenMap.outputs).sort(),
    ['.svelte-kit/output/client/entry.js', '.svelte-kit/output/client/workers/hash-abc.js'],
  );
  assert.deepEqual(files(readModuleMap(writtenMap), 'noble'), ['sha.js']);
});

// Two stores keep packages in a dot folder of node_modules, where the folder after node_modules is not the package.

test('Nitro: each version under node_modules/.nitro/<name>@<version> is that package, at that version', () => {
  const packageJson = (name, version) => JSON.stringify({ name, version });
  const root = project({
    '.output/server/index.mjs': 'import "node:http";',
    '.output/server/node_modules/devalue/package.json': packageJson('devalue', '5.8.1'), // Nitro links one version at the top
    '.output/server/node_modules/devalue/index.js': 'export const a = () => 1;',
    '.output/server/node_modules/.nitro/devalue@5.8.1/package.json': packageJson('devalue', '5.8.1'),
    '.output/server/node_modules/.nitro/devalue@5.8.1/index.js': 'export const a = () => 1;',
    '.output/server/node_modules/.nitro/devalue@5.6.4/package.json': packageJson('devalue', '5.6.4'),
    '.output/server/node_modules/.nitro/devalue@5.6.4/src/parse.js': 'export const b = () => 2;',
    '.output/server/node_modules/.nitro/@vue/shared@3.5.30/package.json': packageJson('@vue/shared', '3.5.30'),
    '.output/server/node_modules/.nitro/@vue/shared@3.5.30/dist/shared.cjs.js': 'exports.c = () => 3;',
    '.output/server/node_modules/.cache/tool/x.js': 'export const d = () => 4;', // a tool folder, not a package
  });

  const moduleMap = attachVersions(readDeployment(['.output'], { root }), { cwd: root });

  assert.ok(!moduleMap.packages.has('.nitro'));
  const devalue = moduleMap.packages.get('devalue');
  assert.deepEqual([...new Set(devalue.versionByRoot.values())].sort(), ['5.6.4', '5.8.1']);
  assert.deepEqual(
    [...devalue.byRoot.get('.output/server/node_modules/.nitro/devalue@5.6.4')].sort(),
    ['package.json', 'src/parse.js'],
  );
  assert.equal(
    moduleMap.packages.get('@vue/shared').versionByRoot.get('.output/server/node_modules/.nitro/@vue/shared@3.5.30'),
    '3.5.30',
  );

  // each version once, and no component for a dot folder
  const sbom = bundleSbomFromModules(moduleMap, { cwd: root });

  assert.deepEqual(
    sbom.components.map((component) => component.purl).sort(),
    ['pkg:npm/%40vue/shared@3.5.30', 'pkg:npm/devalue@5.6.4', 'pkg:npm/devalue@5.8.1'],
  );

  // the version is also read from the folder name, when the package.json isn't there
  assert.deepEqual(
    splitNodeModulesPath('out/node_modules/.nitro/@vue/shared@3.5.30/dist/x.js'),
    { name: '@vue/shared', root: 'out/node_modules/.nitro/@vue/shared@3.5.30', file: 'dist/x.js' },
  );

  const bareMeta = { inputs: {}, outputs: { 'o.js': { inputs: { 'out/node_modules/.nitro/devalue@5.6.4/index.js': { bytesInOutput: 9 } } } } };

  const bare = attachVersions(readModuleMap(bareMeta), { cwd: root });

  assert.equal(bare.packages.get('devalue').versionByRoot.get('out/node_modules/.nitro/devalue@5.6.4'), '5.6.4');

  // a finding for the second version names it
  const lock = { components: [{ purl: 'pkg:npm/devalue@5.6.4' }, { purl: 'pkg:npm/devalue@5.8.1' }] };
  const findings = [{ purl: 'pkg:npm/devalue@5.6.4', id: 'GHSA-xxxx-xxxx-xxxx' }];

  const [result] = triage({ lockfileSbom: lock, bundleSbom: sbom, findings, moduleMap });

  assert.equal(result.state, 'in_triage');
  assert.match(result.detail, /5\.6\.4/);
});

test("Yarn's pnpm linker: node_modules/.store/<folder>/package is the package its package.json names", () => {
  const meta = (...folders) => ({
    inputs: {},
    outputs: {
      'dist/app.js': {
        inputs: Object.fromEntries(folders.map((folder) => [`node_modules/.store/${folder}/package/index.js`, { bytesInOutput: 9 }])),
      },
    },
  });
  const missing = () => Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); // as a missing package.json reads
  const notInstalled = () => {
    throw missing();
  };

  // not installed where vexproof runs: an unscoped folder name leaves no doubt, a scoped one with more dashes does
  const storeFolders = meta('ms-npm-2.1.3-81ff3cfac1', '@a-b-npm-1.0.0-0000000001', '@a-b-c-npm-1.0.0-0000000002');

  const moduleMap = attachVersions(readModuleMap(storeFolders), { readJson: notInstalled });

  assert.equal(moduleMap.packages.get('ms').versionByRoot.get('node_modules/.store/ms-npm-2.1.3-81ff3cfac1/package'), '2.1.3');
  assert.deepEqual(files(moduleMap, '@a/b'), ['index.js']);
  assert.deepEqual(unnamedStorePackages(moduleMap), ['node_modules/.store/@a-b-c-npm-1.0.0-0000000002/package']);
  assert.throws(() => bundleSbomFromModules(moduleMap, { readJson: notInstalled }), /Can't tell which package/);

  // installed: the package.json decides, also where the folder name says nothing
  const installed = {
    '@a-b-c-npm-1.0.0-0000000003': { name: '@a-b/c', version: '1.0.0' },
    'x-patch-1a2b3c4d5e-0000000004': { name: 'x', version: '3.1.0' },
  };
  const readJson = (filePath) => {
    const hit = Object.entries(installed).find(([folder]) => filePath.split(sep).join('/').includes(`/.store/${folder}/package/`));
    if (!hit) {
      throw missing();
    }

    return hit[1];
  };

  const named = attachVersions(readModuleMap(meta(...Object.keys(installed))), { readJson });

  assert.deepEqual(unnamedStorePackages(named), []);
  assert.deepEqual(
    bundleSbomFromModules(named, { readJson }).components.map((component) => component.purl).sort(),
    ['pkg:npm/%40a-b/c@1.0.0', 'pkg:npm/x@3.1.0'],
  );
  // once named, the same folder reads as that package everywhere
  assert.equal(splitNodeModulesPath('node_modules/.store/@a-b-c-npm-1.0.0-0000000003/package/lib/y.js').name, '@a-b/c');
});

test("Yarn's pnpm linker, through the CLI: a bundled package is found, and one that can't be named stops the run", () => {
  const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
  const folder = '@my-org-pkg-npm-1.0.0-0000000005';
  const root = project({
    'dist/app.js': 'console.log(1);',
    'app.js': 'console.log(1);',
    'meta.json': JSON.stringify({ inputs: {}, outputs: { 'dist/app.js': { inputs: {
      [`node_modules/.store/${folder}/package/index.js`]: { bytesInOutput: 9 },
      'app.js': { bytesInOutput: 5 },
    } } } }),
    'bom.json': JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [
      { type: 'library', name: 'pkg', group: '@my-org', version: '1.0.0', purl: 'pkg:npm/%40my-org/pkg@1.0.0' },
      { type: 'library', name: 'other', version: '2.0.0', purl: 'pkg:npm/other@2.0.0' },
    ] }),
    'findings.json': JSON.stringify([{ purl: 'pkg:npm/%40my-org/pkg@1.0.0', id: 'GHSA-xxxx-xxxx-xxxx' }]),
  });
  const args = ['--lockfile', 'bom.json', '--findings', 'findings.json', '--modules', 'meta.json', '--out', 'vex.json'];
  const run = () => spawnSync(process.execPath, [CLI, ...args], {
    cwd: root, encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: '' },
  });

  const refused = run();

  assert.equal(refused.status, 2);
  assert.match(refused.stderr + refused.stdout, /can't be named/);
  assert.ok((refused.stderr + refused.stdout).includes(`node_modules/.store/${folder}/package`));

  mkdirSync(join(root, `node_modules/.store/${folder}/package`), { recursive: true });
  writeFileSync(
    join(root, `node_modules/.store/${folder}/package/package.json`),
    JSON.stringify({ name: '@my-org/pkg', version: '1.0.0' }),
  );

  const accepted = run();

  assert.equal(accepted.status, 0, accepted.stderr);
  const [vulnerability] = JSON.parse(readFileSync(join(root, 'vex.json'), 'utf8')).vulnerabilities;
  assert.equal(vulnerability.analysis.state, 'in_triage');
});
