// SPDX-License-Identifier: MIT
// Ways 1.0.0-beta.8 could say not_affected for code that ships, found by a soundness audit (two independent
// reviews and a run over real package-manager layouts). Each case is the smallest input with the same shape.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname, relative, sep } from 'node:path';
import vexproof from '../src/vite.js';
import { readModuleMap, attachVersions, bundleSbomFromModules, ungroupStats } from '../src/modules.js';
import { strayOutputs, accountFor, runtimeLoads, CoverageError } from '../src/coverage.js';
import { readDeployment, loadedSpecifiers, runtimeImports, isGlue, findMap, missingHalves } from '../src/deploy.js';
import { copyFinder } from '../src/copies.js';
import { findPackageText, contentCheck, markersOf } from '../src/content-check.js';
import { triage } from '../src/index.js';
import { temporaryFolder, temporaryFolderForFile } from './lib/temporary.js';

const project = (list = {}) => {
  const root = temporaryFolderForFile('vxp-audit-');
  for (const [filePath, content] of Object.entries({ 'package-lock.json': '{}', ...list })) {
    mkdirSync(dirname(join(root, filePath)), { recursive: true });
    writeFileSync(join(root, filePath), content);
  }

  return root;
};
const packageJson = (name, version = '1.0.0') => JSON.stringify({ name, version });
const sourceMap = (sources, extra = {}) => JSON.stringify({ version: 3, sources, names: [], mappings: '', ...extra });
const meta = (inputs, outputPath = 'dist/app.js') => ({
  inputs: {},
  outputs: { [outputPath]: { inputs: Object.fromEntries(inputs.map((input) => [input, { bytesInOutput: 9 }])) } },
});
const relativePaths = (root, list) => list.map((file) => relative(root, file).split(sep).join('/')).sort();
const names = (moduleMap) => [...moduleMap.packages.keys()].sort();

test('a folder under node_modules is named by the package.json in it: aliases, and names that differ only in case', () => {
  const root = project({
    'node_modules/tiny/package.json': packageJson('ms', '2.1.3'),
    'node_modules/tiny/index.js': '',
    'node_modules/Lodash/package.json': packageJson('lodash', '4.17.20'),
  });
  const inputs = ['node_modules/tiny/index.js', 'node_modules/Lodash/template.js', 'node_modules/gone/index.js'];

  const moduleMap = attachVersions(readModuleMap(meta(inputs)), { cwd: root });

  assert.deepEqual(names(moduleMap), ['gone', 'lodash', 'ms']);
  assert.equal(moduleMap.packages.get('ms').versionByRoot.get('node_modules/tiny'), '2.1.3');
  assert.deepEqual(
    bundleSbomFromModules(moduleMap, { cwd: root }).components.map((component) => component.purl).sort(),
    ['pkg:npm/gone', 'pkg:npm/lodash@4.17.20', 'pkg:npm/ms@2.1.3'],
  );
  // a folder that can't be read is known by its folder name only, and says so
  assert.deepEqual(moduleMap.unverified, [{ name: 'gone', root: 'node_modules/gone' }]);

  // a pnpm store path spells name and version itself
  const store = attachVersions(readModuleMap(meta(['node_modules/.pnpm/ms@2.1.3/node_modules/ms/index.js'])), { cwd: root });

  assert.deepEqual(store.unverified, []);
});

test('content check: strings of an absent package found in the shipped files keep its findings open', () => {
  const message = 'val is not a non-empty string or a valid number';
  const shared = 'Cannot call a class as a function here';
  const root = project({
    'node_modules/ms/package.json': packageJson('ms', '2.1.3'),
    'node_modules/ms/index.js': `module.exports = () => { throw new Error("${message}"); }; var x = "${shared}";`,
    'node_modules/helper/package.json': packageJson('helper'),
    'node_modules/helper/index.js': `exports.h = "${shared}";`,
    'dist/app.js': `var a="${message}",b="${shared}";`,
  });

  assert.deepEqual([...markersOf(`a("${message}"); b("short"); c("abcdefghijklmnopqrstuvwxyz0123456789");`)], [message]);

  const options = { root, bases: [root], shippedDirs: [join(root, 'dist')] };

  const found = findPackageText(['ms', 'not-installed'], options).get('ms');

  assert.deepEqual(found.hits.map((hit) => hit.text).sort(), [shared, message].sort());

  // a string that a recorded file outside the package also holds is accounted for by that file
  const explained = findPackageText(['ms'], { ...options, recorded: () => [join(root, 'node_modules/helper/index.js')] }).get('ms');

  assert.deepEqual(explained.hits.map((hit) => hit.text), [message]);

  // the package's own file, recorded under another name, explains nothing away
  const ownFile = findPackageText(['ms'], { ...options, recorded: () => [join(root, 'node_modules/ms/index.js')] }).get('ms');

  assert.equal(ownFile.hits.length, 2);

  const results = [
    { key: 'npm/ms', state: 'not_affected', level: 'package', origin: 'auto', justification: 'code_not_present' },
    { key: 'npm/absent', state: 'not_affected', level: 'package', origin: 'auto' },
  ];

  const checked = contentCheck(results, options);

  assert.deepEqual(
    [results[0].state, results[1].state, checked.kept.map((kept) => kept.name), checked.uncheckable],
    ['in_triage', 'not_affected', ['ms'], ['absent']],
  );
});

test('runtime loads: the forms bundlers leave in their output, and a package the output loads counts as shipped', () => {
  const loads = (code) => [...runtimeImports(loadedSpecifiers(code).unguarded)].sort();

  assert.deepEqual(
    loads('import a from "lodash/template.js"; const b = __require("ms"); const c = createRequire(import.meta.url)("qs");'),
    ['lodash', 'ms', 'qs'],
  );
  assert.deepEqual(loads('const p = require("punycode/"); const q = require("punycode"); if (isNode) require("ws");'), ['punycode']);

  const root = project({ 'dist/server.js': 'var l = require("lodash/template"); module.exports = l;', 'dist/empty.js': '' });

  const loaded = runtimeLoads([join(root, 'dist/server.js'), join(root, 'dist/empty.js')]);

  assert.deepEqual([...loaded], ['lodash']);
});

test('webpack stats: grouped module lists are read, the runtime counts as the bundler, several configurations are found', () => {
  const stats = { outputPath: '/x/dist', assets: [], modules: [
    {
      type: 'modules by path',
      children: [
        { type: 'module', name: './node_modules/lodash/template.js', chunks: [1] },
        { type: 'modules by path', children: [{ type: 'module', name: './node_modules/lodash/_root.js', chunks: [1] }] },
      ],
    },
    { type: 'module', name: 'webpack/runtime/publicPath', moduleType: 'runtime', chunks: [1] },
  ] };

  const moduleMap = readModuleMap(stats);

  assert.deepEqual([...moduleMap.packages.get('lodash').files].sort(), ['_root.js', 'template.js']);
  assert.ok(moduleMap.packages.has('webpack') && moduleMap.whole.has('webpack'));
  assert.equal(ungroupStats({ modules: [{ type: 'module', name: './a.js' }] }).modules.length, 1);

  const root = project({ 'out-a/a.js': '', 'out-b/b.js': '', 'out-b/stray.js': 'function x(){}' });
  const multi = { children: [
    { outputPath: join(root, 'out-a'), assets: [{ name: 'a.js', chunks: [1] }], modules: [{ name: './node_modules/a/index.js', chunks: [1] }] },
    { outputPath: join(root, 'out-b'), assets: [{ name: 'b.js', chunks: [1] }], modules: [{ name: './node_modules/b/index.js', chunks: [1] }] },
  ] };

  assert.deepEqual(relativePaths(root, strayOutputs(multi, { root }).stray), ['out-b/stray.js']);

  // a file webpack says it copied is taken at its word only when it came from an installed package
  const copied = {
    outputPath: join(root, 'out-b'),
    assets: [{ name: 'b.js', chunks: [1] }, { name: 'stray.js', info: { copied: true, sourceFilename: 'prebuilt/stray.js' } }],
    modules: [{ name: './node_modules/b/index.js', chunks: [1] }],
  };

  assert.deepEqual(relativePaths(root, strayOutputs(copied, { root }).stray), ['out-b/stray.js']);
});

test('esbuild metafile: an output made only of virtual inputs is not vouched for, and a map read from the wrong folder stops', () => {
  const root = project({ 'src/main.ts': '', 'dist/main.js': '', 'dist/scripts.js': '/*! jQuery */' });
  const json = { inputs: {}, outputs: {
    'dist/main.js': { inputs: { 'src/main.ts': { bytesInOutput: 5 }, 'angular:polyfills:x': { bytesInOutput: 2 } } },
    'dist/scripts.js': { inputs: { 'angular:script/global:scripts.js': { bytesInOutput: 90 } } },
  } };

  const coverage = strayOutputs(json, { root });

  assert.deepEqual([relativePaths(root, coverage.stray), relativePaths(root, coverage.recorded)], [['dist/scripts.js'], ['dist/main.js']]);

  const elsewhere = project({ 'dist/main.js': '', 'dist/scripts.js': '' });

  assert.throws(
    () => strayOutputs(json, { root: elsewhere }),
    (error) => error instanceof CoverageError && /source files of the project/.test(error.message),
  );
});

test('Vite plugin: a worker bundled without the plugin is named, and the map is then refused', (testContext) => {
  const root = temporaryFolder(testContext, 'vxp-audit-');
  const context = (ids) => ({ meta: { viteVersion: '7.0.0', rollupVersion: '4.0.0' }, getModuleIds: () => ids, getModuleInfo: () => null });
  const build = (output, withWorkerPlugin) => {
    const main = vexproof({ root, output });
    main.configResolved({ root, build: { outDir: 'dist' } });

    if (withWorkerPlugin) {
      const worker = vexproof({ root, output });
      worker.configResolved({ root, build: { outDir: 'dist' } });
      const workerContext = context([join(root, 'src/worker.js')]);
      worker.buildStart.call(workerContext);
      worker.generateBundle.call(workerContext, { dir: join(root, 'dist') }, {
        'assets/worker.js': {
          type: 'chunk', fileName: 'assets/worker.js', isEntry: true, facadeModuleId: join(root, 'src/worker.js'),
          modules: { [join(root, 'node_modules/mitt/index.js')]: { renderedLength: 4 } },
        },
      });
    }

    const mainContext = context([join(root, 'src/main.js'), `${join(root, 'src/worker.js')}?worker&inline`]);
    main.buildStart.call(mainContext);
    main.generateBundle.call(mainContext, { dir: join(root, 'dist') }, {
      'assets/index.js': {
        type: 'chunk', fileName: 'assets/index.js', isEntry: true, facadeModuleId: join(root, 'src/main.js'),
        modules: { [join(root, 'src/main.js')]: { renderedLength: 4 } },
      },
    });
    main.closeBundle();

    return JSON.parse(readFileSync(join(root, output), 'utf8'));
  };
  mkdirSync(join(root, 'dist/assets'), { recursive: true });
  writeFileSync(join(root, 'dist/assets/index.js'), '');

  const without = build('without.json', false);

  assert.deepEqual(without.unrecordedWorkers, ['src/worker.js']);
  assert.throws(() => strayOutputs(without, { root }), (error) => error instanceof CoverageError && /web worker/.test(error.message));

  const withPlugin = build('with.json', true);

  assert.deepEqual(withPlugin.unrecordedWorkers, []);
});

test('--deploy: a source map elsewhere is matched by its folders, and a deployed package\'s own map is never a bundle\'s', () => {
  const route = 'function h(){}\n//# sourceMappingURL=route.js.map';
  const root = project({
    'node_modules/safe/index.js': '', 'node_modules/vuln/index.js': '',
    '.next/server/app/alpha/route.js.map': sourceMap(['webpack://_N_E/./node_modules/safe/index.js']),
    '.next/server/app/beta/route.js.map': sourceMap(['webpack://_N_E/./node_modules/vuln/index.js']),
    '.next/standalone/.next/server/app/alpha/route.js': route,
    '.next/standalone/.next/server/app/beta/route.js': route,
    'out/server/index.js': 'function bundled(){ return 1 }',
    'out/server/node_modules/safe/dist/index.js.map': sourceMap(['../src/index.ts']),
  });

  const deployment = readDeployment(['.next/standalone'], { root, mapDirs: ['.next'] });

  assert.deepEqual([...deployment.packages.keys()].sort(), ['safe', 'vuln']);
  assert.deepEqual(readDeployment(['out'], { root }).unmapped, ['out/server/index.js']);

  // a map with the same name in a folder of another name is not this file's
  const index = new Map([['route.js.map', [
    join(root, '.next/server/app/alpha/route.js.map'),
    join(root, '.next/server/app/beta/route.js.map'),
  ]]]);

  const found = findMap(join(root, '.next/standalone/.next/server/app/beta/route.js'), route, index);

  assert.equal(found.at, join(root, '.next/server/app/beta/route.js.map'));
  assert.equal(findMap(join(root, 'elsewhere/gamma/route.js'), 'function h(){}', index), null);
});

test('--deploy: sources written as drive paths, from the project folder, or copied from a package\'s own map are placed', () => {
  const root = project({
    'node_modules/vuln/index.js': '', 'node_modules/safe/index.js': '',
    'packages/ui/package.json': packageJson('@acme/ui'), 'packages/ui/src/button.js': '',
    'node_modules/weblib/package.json': packageJson('weblib'), 'node_modules/weblib/dist/weblib.js': '',
    'node_modules/weblib/dist/weblib.js.map': sourceMap(['webpack://WebLib/./src/index.js']),
    'node_modules/rootlib/package.json': packageJson('rootlib'), 'node_modules/rootlib/dist/rootlib.js': '',
    'node_modules/rootlib/dist/rootlib.js.map': sourceMap(['src/index.ts'], { sourceRoot: 'https://example.test/rootlib/v1/' }),
  });
  put(root, 'out/a.js', 'function a(){}');
  put(root, 'out/a.js.map', sourceMap([join(root, 'node_modules/vuln/index.js').replace(/\\/g, '/')]));
  put(root, 'out/server/b.js', 'function b(){}');
  put(root, 'out/server/b.js.map', sourceMap(['webpack://_N_E/./packages/ui/src/button.js', 'turbopack:///[project]/node_modules/safe/index.js']));
  put(root, 'out/c.js', 'function c(){}');
  put(root, 'out/c.js.map', sourceMap([
    'webpack://WebLib/src/index.js', 'https://example.test/rootlib/v1/src/index.ts', 'webpack://app/webpack/bootstrap',
  ]));

  const deployment = readDeployment(['out'], { root });

  assert.deepEqual([...deployment.packages.keys()].sort(), ['rootlib', 'safe', 'vuln', 'weblib']);
  assert.ok(deployment.own.has('packages/ui/src/button.js'));
  assert.ok(deployment.whole.has('weblib') && deployment.whole.has('rootlib'));
  // what names no file and no package's map is counted, not dropped without a word
  assert.deepEqual(deployment.unplaced.map((unplaced) => unplaced.source), ['webpack://app/webpack/bootstrap']);
});

test('--deploy: a missing folder, the other half of a framework build, and a relative load that leaves the deployment', () => {
  const root = project({
    '.next/standalone/server.js': 'require("node:http");', '.next/static/chunks/a.js': '',
    '.output/server/index.mjs': 'import "node:http";', '.output/public/a.js': '',
    'node_modules/vuln/package.json': packageJson('vuln'), 'node_modules/vuln/index.js': '',
    'out/server.mjs': 'import v from "../node_modules/vuln/index.js"; import "node:http"; v();',
  });

  assert.deepEqual(readDeployment(['.next/standalone', '.next/statik'], { root }).missingDirs, ['.next/statik']);

  assert.deepEqual(missingHalves(['.next/standalone'], root), ['.next/static']);
  assert.deepEqual(missingHalves(['.next/standalone', '.next/static'], root), []);
  assert.deepEqual(missingHalves(['.output/server'], root), ['.output/public']);
  assert.deepEqual(missingHalves(['.output'], root), []);

  const deployment = readDeployment(['out'], { root, lockNames: new Set(['vuln']) });

  assert.deepEqual(deployment.missingRuntime, [{ name: 'vuln', from: 'out/server.mjs' }]);
});

test('copies: every installed file a copy matches, and a tracked file as git has it, not as the build left it', () => {
  const lib = 'var jq = function(){ return 42 };';
  const root = project({
    'node_modules/jq-lib/dist/jq.js': lib,
    'node_modules/admin-kit/vendor/jq.js': lib,
    'public/sw.js': 'self.skipWaiting();\n',
    'dist/jq.js': lib,
  });

  const copies = copyFinder({ root, bases: [root], outDirs: [join(root, 'dist')] });

  assert.deepEqual(
    relativePaths(root, copies.installedAll(Buffer.from(lib))),
    ['node_modules/admin-kit/vendor/jq.js', 'node_modules/jq-lib/dist/jq.js'],
  );

  const account = accountFor([join(root, 'dist/jq.js')], { root, outDirs: [join(root, 'dist')] });

  assert.deepEqual(account.accounted[0].adds.sort(), ['node_modules/admin-kit/vendor/jq.js', 'node_modules/jq-lib/dist/jq.js']);

  const git = (...args) => spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  for (const args of [['init', '-q'], ['add', 'public/sw.js']]) {
    const result = git(...args);
    assert.equal(result.status, 0, `git ${args.join(' ')}: ${result.error?.message ?? result.stderr}`);
  }

  const fresh = copyFinder({ root, bases: [root], outDirs: [join(root, 'dist')] });

  assert.equal(relativePaths(root, [fresh.project(Buffer.from('self.skipWaiting();\n'))])[0], 'public/sw.js');
  assert.equal(relativePaths(root, [fresh.project(Buffer.from('self.skipWaiting();\r\n'))])[0], 'public/sw.js'); // checked out with CRLF

  // the build overwrites the tracked file with a bundle: the bundle is not what git has
  const bundle = 'class Parser { parse(i) { return eval(i) } }';
  writeFileSync(join(root, 'public/sw.js'), bundle);

  assert.equal(copyFinder({ root, bases: [root], outDirs: [] }).project(Buffer.from(bundle)), undefined);
});

test('glue is a file with no code in it: a class or a method is code, with or without the word function', () => {
  assert.ok(isGlue('self.__BUILD_MANIFEST={"/":["static/chunks/a.js"]};'));
  assert.ok(isGlue('const path = require("path"); process.chdir(__dirname);'));
  assert.ok(!isGlue('class P{parse(i){return eval(i)}}globalThis.P=P;'));
  assert.ok(!isGlue('globalThis.V={parse(i){return eval(i)}};'));
  assert.ok(!isGlue('this is not javascript {'));
});

test('a finding on a package that is not an npm package is left open: a JavaScript build says nothing about it', () => {
  const lock = { components: [{ purl: 'pkg:pypi/django@3.2.0' }, { purl: 'pkg:npm/lodash@4.17.21' }, { purl: 'pkg:npm/left-pad@1.3.0' }] };
  const bundle = { components: [{ purl: 'pkg:npm/lodash@4.17.21' }] };
  const findings = [{ purl: 'pkg:pypi/django@3.2.0', id: 'GHSA-xxxx-xxxx-xxx1' }, { purl: 'pkg:npm/left-pad@1.3.0', id: 'GHSA-xxxx-xxxx-xxx2' }];

  const results = triage({ lockfileSbom: lock, bundleSbom: bundle, findings });

  assert.deepEqual(results.map((result) => result.state), ['in_triage', 'not_affected']);
  assert.match(results[0].detail, /not an npm package/);
});

function put(root, filePath, content) {
  mkdirSync(dirname(join(root, filePath)), { recursive: true });
  writeFileSync(join(root, filePath), content);
}
