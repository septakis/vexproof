// SPDX-License-Identifier: MIT
// The narrower cases from the same audit as audit.test.js: defaults that leaned toward "absent", module names
// a bundler decorates, stale module maps, loads from outside a deployment, and packages that ship their sources.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, existsSync, utimesSync, symlinkSync } from 'node:fs';
import { join, dirname, relative, sep } from 'node:path';
import vexproof from '../src/vite.js';
import { readModuleMap, attachVersions } from '../src/modules.js';
import { strayOutputs, accountFor, binaryCopies, CoverageError } from '../src/coverage.js';
import {
  readDeployment, withChainedSources, mapSources, inlineMapPackages, deploymentDigest, isGlue, isLoaderStub, generatedBy,
} from '../src/deploy.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { temporaryFolderForFile } from './lib/temporary.js';

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
const relativePaths = (root, list) => list.map((file) => relative(root, file).split(sep).join('/')).sort();
const files = (moduleMap, name) => [...(moduleMap.packages.get(name)?.files ?? [])].sort();

test('module names: an input with no byte count ships, a DLL-delegated module is its file, Vite\'s helpers are Vite', () => {
  const moduleMap = readModuleMap({ inputs: {}, outputs: { 'dist/a.js': { inputs: {
    'node_modules/lodash/template.js': {},                       // no bytesInOutput: not "dropped"
    'node_modules/lodash/unused.js': { bytesInOutput: 0 },       // dropped, and says so
    'vite/preload-helper.js': { bytesInOutput: 300 },
  } } } });

  assert.deepEqual(files(moduleMap, 'lodash'), ['template.js']);
  // Vite's helper ships as a file of vite named after it, so module rules can tell it from Vite's own files
  assert.deepEqual(files(moduleMap, 'vite'), ['preload-helper.js']);
  assert.equal(moduleMap.whole, undefined);

  const dll = readModuleMap({ modules: [{ name: 'delegated ./node_modules/lodash/lodash.js from dll-reference vendor_lib', chunks: [1] }] });

  assert.deepEqual(files(dll, 'lodash'), ['lodash.js']);
});

test('a copy of one package published inside another\'s build is both packages\' code; a nested install is one package\'s', () => {
  const moduleMap = readModuleMap({ inputs: {}, outputs: { 'dist/a.js': { inputs: {
    'node_modules/ui-kit/dist/node_modules/tslib/tslib.es6.js': { bytesInOutput: 9 },
    'node_modules/a/node_modules/b/index.js': { bytesInOutput: 9 },
    'node_modules/.pnpm/c@1.0.0/node_modules/c/index.js': { bytesInOutput: 9 },
  } } } });

  assert.deepEqual([...moduleMap.packages.keys()].sort(), ['b', 'c', 'tslib', 'ui-kit']);
  assert.deepEqual(files(moduleMap, 'ui-kit'), ['dist/node_modules/tslib/tslib.es6.js']);
});

test('file-level rules compare file names without regard to case', () => {
  const rules = {
    version: 't',
    packages: { lodash: { advisories: { 'GHSA-35jh-r3h4-6jhm': { affects: '_.template', files: ['template.js'], source: 'test' } } } },
  };
  const entry = (file) => ({
    roots: new Set(['node_modules/lodash']),
    files: new Set([file]),
    byRoot: new Map([['node_modules/lodash', new Set([file])]]),
    versionByRoot: new Map([['node_modules/lodash', '4.17.20']]),
  });
  const check = (file) => evaluateModuleRule({
    key: 'npm/lodash',
    parsed: { type: 'npm', name: 'lodash', version: '4.17.20' },
    id: 'GHSA-35jh-r3h4-6jhm',
    aliases: [],
    bundleVersions: new Set(['4.17.20']),
    moduleMap: { format: 'test', packages: new Map([['lodash', entry(file)]]) },
    rules,
  });

  assert.equal(check('debounce.js').ok, true);
  assert.equal(check('Template.js').ok, false); // `require('lodash/Template')` on Windows or macOS loads template.js
});

test('a stale module map: a size the bundler did not write, a file newer than the map, an old map left by the plugin', () => {
  const root = project({ 'src/a.js': '', 'dist/a.js': 'x'.repeat(40) });
  const meta = (bytes) => ({ inputs: {}, outputs: { 'dist/a.js': { bytes, inputs: { 'src/a.js': { bytesInOutput: 5 } } } } });

  assert.deepEqual(relativePaths(root, strayOutputs(meta(40), { root }).recorded), ['dist/a.js']);
  assert.throws(
    () => strayOutputs(meta(27), { root }),
    (error) => error instanceof CoverageError && /is 40 bytes, and the bundler wrote 27/.test(error.message),
  );

  const stats = (size) => ({
    outputPath: join(root, 'dist'),
    assets: [{ name: 'a.js', chunks: [1], size }],
    modules: [{ name: './src/a.js', chunks: [1] }],
  });

  assert.doesNotThrow(() => strayOutputs(stats(40), { root }));
  assert.throws(() => strayOutputs(stats(27), { root }), /not the ones this module map describes/);

  // the Vite plugin's map is written when the build closes; an output written much later is another build's
  const vite = {
    vexproof: 1, bundler: 'vite 7', inputs: {}, outputs: { 'dist/a.js': { inputs: { 'src/a.js': { bytesInOutput: 5 } } } }, outDirs: ['dist'],
  };
  const file = join(root, 'vexproof-modules.json');
  writeFileSync(file, JSON.stringify(vite));

  assert.doesNotThrow(() => strayOutputs(vite, { root, file }));

  const later = new Date(Date.now() + 10 * 60 * 1000);
  utimesSync(join(root, 'dist/a.js'), later, later);

  assert.throws(() => strayOutputs(vite, { root, file }), /written after the module map/);

  // a build in which the plugin records nothing removes the map an earlier build left
  const old = join(root, 'old-map.json');
  writeFileSync(old, '{"vexproof":1}');
  const plugin = vexproof({ root, output: 'old-map.json', includeServer: false });
  plugin.configResolved({ root, build: { outDir: 'dist', ssr: true } });

  plugin.buildStart.call({ meta: {} });
  plugin.generateBundle.call({ meta: {} }, { dir: join(root, 'dist') }, {});
  plugin.closeBundle();

  assert.equal(existsSync(old), false);
});

test('compiled code in the output that is an exact copy of an installed file names its package', () => {
  const wasm = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0, 7, 7, 7]);
  const root = project({
    'node_modules/wasm-codec/codec.wasm': wasm,
    'dist/assets/codec-abc123.wasm': wasm,
    'dist/assets/own.wasm': Buffer.from([0, 97, 115, 109, 9]),
  });

  const copies = binaryCopies([join(root, 'dist')], { root });

  assert.deepEqual(copies, ['node_modules/wasm-codec/codec.wasm']);
});

test('--deploy: a package that a deployed package loads from outside the deployment counts as shipped', () => {
  const root = project({
    'node_modules/vuln/package.json': packageJson('vuln'), 'node_modules/vuln/index.js': 'module.exports = 1;',
    'node_modules/optional/package.json': packageJson('optional'), 'node_modules/optional/index.js': '',
    'build/server.js': 'require("node:http"); require("wrapper");\n//# sourceMappingURL=server.js.map',
    'build/server.js.map': sourceMap(['../src/server.js']),
    'src/server.js': '',
    'build/node_modules/wrapper/package.json': packageJson('wrapper'),
    'build/node_modules/wrapper/index.js': 'module.exports = require("vuln"); try { require("optional"); } catch (e) {} require("inside");',
    'build/node_modules/inside/package.json': packageJson('inside'), 'build/node_modules/inside/index.js': '',
  });

  const deployment = readDeployment(['build'], { root, lockNames: new Set(['vuln', 'optional', 'inside', 'wrapper']) });

  // a load behind a test counts too: the lockfile has the package, so it is installed and the load succeeds
  assert.deepEqual(deployment.loadedFromOutside.map((load) => load.name).sort(), ['optional', 'vuln']);
  assert.ok(deployment.packages.has('vuln') && deployment.whole.has('vuln') && deployment.packages.has('optional'));
  assert.deepEqual(deployment.missingRuntime, []);
});

test('--deploy: a map that names a bundle with a map of its own is followed; one with no sources, or two in a file, says nothing', () => {
  const root = project({
    'node_modules/vuln/index.js': '',
    'tmp/stage1.js': 'function bundled(){}', 'tmp/stage1.js.map': sourceMap(['../node_modules/vuln/index.js']),
    'out/min.js': 'function a(){}\n//# sourceMappingURL=min.js.map', 'out/min.js.map': sourceMap(['../tmp/stage1.js']),
    'bad/empty.js': 'function a(){ return 1 }\n//# sourceMappingURL=empty.js.map', 'bad/empty.js.map': sourceMap([]),
    'bad/two.js': 'function a(){ return 1 }\n//# sourceMappingURL=a.js.map\nfunction b(){ return 2 }\n//# sourceMappingURL=two.js.map',
    'bad/two.js.map': sourceMap(['../tmp/stage1.js']),
    // a placeholder with nothing in it, and a file of strings, need no sources in their map (SvelteKit writes both)
    'bad/stub.js': 'import"./empty.js";function e(e){}export{e as component};\n//# sourceMappingURL=stub.js.map',
    'bad/stub.js.map': sourceMap([]),
    'bad/strings.js': 'const e="Add a function",t="Access";export{e as a,t as b};\n//# sourceMappingURL=strings.js.map',
    'bad/strings.js.map': sourceMap([]),
  });

  assert.deepEqual([...readDeployment(['out'], { root }).packages.keys()], ['vuln']);

  const sources = mapSources(JSON.parse(sourceMap(['../tmp/stage1.js'])), join(root, 'out/min.js.map'), root);
  const chained = withChainedSources(sources, root, [root]);

  assert.deepEqual(chained.map((source) => source.path), ['tmp/stage1.js', 'node_modules/vuln/index.js']);

  assert.deepEqual(readDeployment(['bad'], { root }).unmapped.sort(), ['bad/empty.js', 'bad/two.js']);
});

test('--deploy: a chunk that only wires modules together needs no sources in its map; one that computes anything does', () => {
  // Turbopack (Next.js 16) writes these by the hundred, each with a map that names no source and a debug-id line on top
  const debugId = ';!function(){try { var e="undefined"!=typeof globalThis?globalThis:{},n=(new e.Error).stack;n&&((e._debugIds|| (e._debugIds={}))[n]="5125b9d7-95a6-2718-6298-a62fa20ee879")}catch(e){}}();\n';
  const stubs = [
    'module.exports=[745515,t=>{"use strict";t.S([859484,"fromHttp,f"])}];',
    'module.exports=[449719,(a,b,c)=>{b.exports=a.x("http",()=>require("http"))},921517,(a,b,c)=>{b.exports=a.x("zod-52b1",()=>require("zod-52b1"))}];',
    'module.exports=[1,a=>{"use strict";var b=a.i(750227);a.s(["minpath",()=>b.default],462711)},2,a=>a.a(async(b,c)=>{try{var d=await a.y("posthog-node-c56e");a.n(d),c()}catch(a){c(a)}},!0)];',
    'module.exports=[3,a=>{a.v(b=>Promise.all(["server/chunks/ssr/x.js"].map(c=>a.l(c))).then(()=>b(4)))},5,a=>{a.v("/_next/static/media/a.svg"+(globalThis.NEXT_CLIENT_ASSET_SUFFIX||""))}];',
  ];

  for (const stub of stubs) {
    assert.ok(isLoaderStub(debugId + stub), stub);
  }
  // the same list as a browser gets it
  const browserList = `${debugId}(globalThis.TURBOPACK||(globalThis.TURBOPACK=[])).push(["object"==typeof document?document.currentScript:void 0,993608,function(o){o.n(o.i(518537))}]);`;
  const browserCode = '(globalThis.TURBOPACK||(globalThis.TURBOPACK=[])).push(["object"==typeof document?document.currentScript:void 0,1,function(o){return o.a*2}]);';
  assert.ok(isLoaderStub(browserList));
  assert.ok(!isLoaderStub(browserCode));
  assert.ok(isGlue(debugId + 'self.__BUILD_MANIFEST={"/":["a.js"]};'));

  const code = [
    'module.exports=[1,t=>{eval(t)}];',                       // a call of something that is not its own parameter
    'module.exports=[1,t=>{t.S(t.a+1)}];',                    // arithmetic
    'module.exports=[1,function(i){return i?parse(i):null}];', // a branch
    'module.exports=[1,t=>{for(;;)t.x()}];',
    'module.exports=[1,t=>{new Parser(t)}];',                  // making something that was not handed in
    'module.exports=[1,t=>{t.S({get a(){return 1}})}];',       // a getter is a function with a body
    'var x=globalThis.fetch("/a");',
    debugId.replace('n&&', 'require("x");n&&') + stubs[0],     // not the debug-id line if anything else is in it
  ];

  for (const snippet of code) {
    assert.ok(!isLoaderStub(snippet), snippet);
  }

  const root = project({
    'out/stub.js': `${debugId}${stubs[0]}\n//# sourceMappingURL=stub.js.map`,
    'out/stub.js.map': sourceMap([], { sections: [{ offset: { line: 1, column: 0 }, map: { version: 3, sources: [], names: [], mappings: '' } }] }),
    'out/code.js': `${code[2]}\n//# sourceMappingURL=code.js.map`,
    'out/code.js.map': sourceMap([]),
  });

  const deployment = readDeployment(['out'], { root });

  assert.deepEqual(deployment.unmapped, ['out/code.js']);
});

test('files a build tool writes or copies: Workbox\'s service worker, a minified copy named by a hint, a fixture inside a package', () => {
  // the loader that gives a worker `define`, then one call that hands settings to the Workbox library beside it
  const loader = 'if(!self.define){let e,s={};const n=(n,i)=>(n=new URL(n+".js",i).href,s[n]||new Promise((s=>{importScripts(n),s()})).then((()=>{let e=s[n];if(!e)throw new Error(`Module ${n} didn’t register its module`);return e})));self.define=(i,r)=>{s[1]=Promise.all(i.map((e=>n(e,"")))).then((e=>(r(...e),{})))}}';
  const settings = 'define(["./workbox-3631b453"],(function(e){"use strict";self.skipWaiting(),e.clientsClaim(),e.precacheAndRoute([{url:"index.html",revision:"1"}],{}),e.registerRoute(/\\.woff2$/,new e.CacheFirst({cacheName:"fonts",plugins:[new e.ExpirationPlugin({maxEntries:50})]}),"GET")}));';

  assert.deepEqual(generatedBy(loader + settings), ['workbox-build', '@surma/rollup-plugin-off-main-thread']);
  assert.equal(generatedBy(loader + settings.replace('e.clientsClaim(),', 'e.clientsClaim(),(function(i){return eval(i)})(1),')), null);
  assert.equal(generatedBy(settings), null);

  const lib = 'var MESSAGES = ["first of many strings", "second string here", "third", "fourth one", "fifth entry", "sixth", "seventh item", "eighth and last"];\nexport function all() { return MESSAGES; }\n';
  const minified = 'var a=["first of many strings","second string here","third","fourth one","fifth entry","sixth","seventh item","eighth and last"];export function all(){return a}';
  const root = project({
    'src/a.js': '', 'node_modules/editor/min/vs/lang/abap.js': lib, 'node_modules/editor/package.json': packageJson('editor'),
    'node_modules/resolve/package.json': packageJson('resolve'),
    'node_modules/resolve/test/shadowed/node_modules/util/index.js': 'module.exports = 1;',
    'dist/main.js': '', 'dist/vs/lang/abap.js': minified,
    'dist/other/abap.js': 'export function unrelated(){ return [1,2,3].map(function(x){ return x * 2 }) }',
  });
  const stats = { outputPath: join(root, 'dist'), modules: [{ name: './src/a.js', chunks: [1] }], assets: [
    { name: 'main.js', chunks: [1] },
    { name: 'vs/lang/abap.js', chunks: [], info: { copied: true, minimized: true, sourceFilename: 'lang/abap.js' } },
    { name: 'other/abap.js', chunks: [], info: { copied: true, sourceFilename: 'lang/abap.js' } },
  ] };

  const coverage = strayOutputs(stats, { root });
  const account = accountFor(coverage.stray, { root, outDirs: coverage.dirs, hints: coverage.hints });

  assert.deepEqual(
    account.accounted.map((accounted) => [accounted.file, accounted.kind, accounted.adds]),
    [['dist/vs/lang/abap.js', 'copy', ['node_modules/editor/min/vs/lang/abap.js']]],
  );
  assert.deepEqual(account.unknown.map((unknown) => unknown.file), ['dist/other/abap.js']); // the same hint, but not that file's strings

  // a folder inside a package that is itself no package: its files are the holding package's
  const meta = { inputs: {}, outputs: { 'dist/a.js': { inputs: {
    'node_modules/resolve/test/shadowed/node_modules/util/index.js': { bytesInOutput: 9 },
  } } } };

  const moduleMap = attachVersions(readModuleMap(meta), { cwd: root });

  assert.deepEqual(
    [[...moduleMap.packages.keys()], moduleMap.unverified, [...moduleMap.packages.get('resolve').files]],
    [['resolve'], [], ['test/shadowed/node_modules/util/index.js']],
  );
});

test('--deploy: a package that ships its original sources is taken whole, and the VEX is tied to what was deployed', () => {
  const inlineMap = Buffer.from(sourceMap(['../src/parse.js']) + ' '.repeat(120)).toString('base64');
  const inline = `exports.parse = function(){};\n//# sourceMappingURL=data:application/json;base64,${inlineMap}`;
  const root = project({
    'node_modules/ts-lib/package.json': packageJson('ts-lib'),
    'node_modules/ts-lib/src/parse.ts': 'export const parse = 1;',
    'node_modules/ts-lib/dist/parse.js': '',
    'node_modules/js-lib/package.json': packageJson('js-lib'), 'node_modules/js-lib/src/parse.js': '', 'node_modules/js-lib/dist/parse.js': inline,
    'node_modules/plain/package.json': packageJson('plain'), 'node_modules/plain/index.js': 'exports.x = function(){};',
    'out/app.js': 'function a(){}\n//# sourceMappingURL=app.js.map',
    'out/app.js.map': sourceMap(['../node_modules/ts-lib/src/parse.ts', '../node_modules/js-lib/src/parse.js', '../node_modules/plain/index.js']),
  });

  const deployment = readDeployment(['out'], { root });

  assert.ok(deployment.whole.has('ts-lib') && !deployment.whole.has('js-lib') && !deployment.whole.has('plain'));
  assert.deepEqual(inlineMapPackages(deployment, ['js-lib', 'plain', 'ts-lib', 'absent'], root), ['js-lib']);

  const before = deploymentDigest(['out'], root);

  assert.match(before, /^[0-9a-f]{64}$/);
  assert.equal(deploymentDigest(['out'], root), before);

  writeFileSync(join(root, 'out/app.js'), 'function b(){}\n//# sourceMappingURL=app.js.map');

  assert.notEqual(deploymentDigest(['out'], root), before);
});

test('--deploy: the digest covers the source maps the files were read with, in a --maps folder too', () => {
  const root = project({
    'node_modules/lodash/package.json': packageJson('lodash', '4.17.21'),
    'node_modules/lodash/template.js': '',
    'node_modules/lodash/debounce.js': '',
    'out/app.js': 'function a(){}\n//# sourceMappingURL=app.js.map',
    'maps/app.js.map': sourceMap(['../node_modules/lodash/template.js']),
  });
  const digestNow = () => {
    const deployment = readDeployment(['out'], { root, mapDirs: ['maps'] });

    return deploymentDigest(['out'], root, { mapsRead: deployment.mapsRead });
  };

  const before = digestNow();
  assert.deepEqual(readDeployment(['out'], { root, mapDirs: ['maps'] }).mapsRead, [join(root, 'maps/app.js.map')]);

  // the same code, read with a map that names another file: other verdicts, so another digest
  writeFileSync(join(root, 'maps/app.js.map'), sourceMap(['../node_modules/lodash/debounce.js']));

  assert.notEqual(digestNow(), before);
});

test('--deploy: a nested install named in a map is never read as the top-level copy of that package', () => {
  // the map names a/node_modules/b, which is not installed here; the top-level b is another version
  const root = project({
    'node_modules/b/package.json': packageJson('b', '2.0.0'),
    'node_modules/b/index.js': '',
  });
  const mapFile = join(root, 'out/app.js.map');

  const [source] = mapSources(JSON.parse(sourceMap(['webpack://app/./node_modules/a/node_modules/b/index.js'])), mapFile, root);

  assert.equal(source.path, 'node_modules/a/node_modules/b/index.js');
  assert.equal(source.exists, false);
});

test('--deploy: a folder linked into the deployment is read (a script that loads a Node module: coverage.test.js, server check)', (testContext) => {
  const root = project({
    'node_modules/vuln/index.js': '',
    'shared/chunks/api.js': 'function a(){}\n//# sourceMappingURL=api.js.map',
    'shared/chunks/api.js.map': sourceMap(['../../node_modules/vuln/index.js']),
    'out/server/index.js': 'require("./chunks/api.js");',
  });
  try {
    symlinkSync(join(root, 'shared/chunks'), join(root, 'out/server/chunks'), 'junction');
  } catch (error) {
    // only a system that won't make the link skips; any other error is a failure
    if (!['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) {
      throw error;
    }

    testContext.skip(`links cannot be made here: ${error.code}`);
    return;
  }

  const deployment = readDeployment(['out'], { root });

  assert.deepEqual([...deployment.packages.keys()], ['vuln']);
});
