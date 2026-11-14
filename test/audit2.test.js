// SPDX-License-Identifier: MIT
// The narrower cases from the same audit as audit.test.js: defaults that leaned toward "absent", module names
// a bundler decorates, stale module maps, loads from outside a deployment, and packages that ship their sources.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, utimesSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, relative, sep } from 'node:path';
import vexproof from '../src/vite.js';
import { readModuleMap, attachVersions } from '../src/modules.js';
import { strayOutputs, accountFor, binaryCopies, CoverageError } from '../src/coverage.js';
import { readDeployment, withChainedSources, mapSources, inlineMapPackages, deploymentDigest, isGlue, isLoaderStub, generatedBy } from '../src/deploy.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';

const project = (list = {}) => {
  const root = mkdtempSync(join(tmpdir(), 'vxp-audit-'));
  for (const [p, c] of Object.entries({ 'package-lock.json': '{}', ...list })) { mkdirSync(dirname(join(root, p)), { recursive: true }); writeFileSync(join(root, p), c); }
  return root;
};
const pkg = (name, version = '1.0.0') => JSON.stringify({ name, version });
const map = (sources, extra = {}) => JSON.stringify({ version: 3, sources, names: [], mappings: '', ...extra });
const rel = (root, list) => list.map((f) => relative(root, f).split(sep).join('/')).sort();
const files = (mm, name) => [...(mm.packages.get(name)?.files ?? [])].sort();

test('module names: an input with no byte count ships, a DLL-delegated module is its file, Vite\'s helpers are Vite', () => {
  const mm = readModuleMap({ inputs: {}, outputs: { 'dist/a.js': { inputs: {
    'node_modules/lodash/template.js': {},                       // no bytesInOutput: not "dropped"
    'node_modules/lodash/unused.js': { bytesInOutput: 0 },       // dropped, and says so
    'vite/preload-helper.js': { bytesInOutput: 300 },
  } } } });
  assert.deepEqual(files(mm, 'lodash'), ['template.js']);
  assert.ok(mm.packages.has('vite') && mm.whole.has('vite'));
  const dll = readModuleMap({ modules: [{ name: 'delegated ./node_modules/lodash/lodash.js from dll-reference vendor_lib', chunks: [1] }] });
  assert.deepEqual(files(dll, 'lodash'), ['lodash.js']);
});

test('a copy of one package published inside another\'s build is both packages\' code; a nested install is one package\'s', () => {
  const mm = readModuleMap({ inputs: {}, outputs: { 'dist/a.js': { inputs: {
    'node_modules/ui-kit/dist/node_modules/tslib/tslib.es6.js': { bytesInOutput: 9 },
    'node_modules/a/node_modules/b/index.js': { bytesInOutput: 9 },
    'node_modules/.pnpm/c@1.0.0/node_modules/c/index.js': { bytesInOutput: 9 },
  } } } });
  assert.deepEqual([...mm.packages.keys()].sort(), ['b', 'c', 'tslib', 'ui-kit']);
  assert.deepEqual(files(mm, 'ui-kit'), ['dist/node_modules/tslib/tslib.es6.js']);
});

test('file-level rules compare file names without regard to case', () => {
  const rules = { version: 't', packages: { lodash: { advisories: { 'GHSA-35jh-r3h4-6jhm': { affects: '_.template', files: ['template.js'], source: 'test' } } } } };
  const entry = (file) => ({ roots: new Set(['node_modules/lodash']), files: new Set([file]), byRoot: new Map([['node_modules/lodash', new Set([file])]]), versionByRoot: new Map([['node_modules/lodash', '4.17.20']]) });
  const check = (file) => evaluateModuleRule({ key: 'npm/lodash', parsed: { type: 'npm', name: 'lodash', version: '4.17.20' }, id: 'GHSA-35jh-r3h4-6jhm', aliases: [], bundleVersions: new Set(['4.17.20']), moduleMap: { format: 'test', packages: new Map([['lodash', entry(file)]]) }, rules });
  assert.equal(check('debounce.js').ok, true);
  assert.equal(check('Template.js').ok, false); // `require('lodash/Template')` on Windows or macOS loads template.js
});

test('a stale module map: a size the bundler did not write, a file newer than the map, an old map left by the plugin', () => {
  const root = project({ 'src/a.js': '', 'dist/a.js': 'x'.repeat(40) });
  const meta = (bytes) => ({ inputs: {}, outputs: { 'dist/a.js': { bytes, inputs: { 'src/a.js': { bytesInOutput: 5 } } } } });
  assert.deepEqual(rel(root, strayOutputs(meta(40), { root }).recorded), ['dist/a.js']);
  assert.throws(() => strayOutputs(meta(27), { root }), (e) => e instanceof CoverageError && /is 40 bytes, and the bundler wrote 27/.test(e.message));
  const stats = (size) => ({ outputPath: join(root, 'dist'), assets: [{ name: 'a.js', chunks: [1], size }], modules: [{ name: './src/a.js', chunks: [1] }] });
  assert.doesNotThrow(() => strayOutputs(stats(40), { root }));
  assert.throws(() => strayOutputs(stats(27), { root }), /not the ones this module map describes/);

  // the Vite plugin's map is written when the build closes; an output written much later is another build's
  const vite = { vexproof: 1, bundler: 'vite 7', inputs: {}, outputs: { 'dist/a.js': { inputs: { 'src/a.js': { bytesInOutput: 5 } } } }, outDirs: ['dist'] };
  const file = join(root, 'vexproof-modules.json');
  writeFileSync(file, JSON.stringify(vite));
  assert.doesNotThrow(() => strayOutputs(vite, { root, file }));
  const later = new Date(Date.now() + 10 * 60 * 1000);
  utimesSync(join(root, 'dist/a.js'), later, later);
  assert.throws(() => strayOutputs(vite, { root, file }), /written after the module map/);

  // a build in which the plugin records nothing removes the map an earlier build left
  const old = join(root, 'old-map.json');
  writeFileSync(old, '{"vexproof":1}');
  const p = vexproof({ root, output: 'old-map.json', includeServer: false });
  p.configResolved({ root, build: { outDir: 'dist', ssr: true } });
  p.buildStart.call({ meta: {} });
  p.generateBundle.call({ meta: {} }, { dir: join(root, 'dist') }, {});
  p.closeBundle();
  assert.equal(existsSync(old), false);
});

test('compiled code in the output that is an exact copy of an installed file names its package', () => {
  const wasm = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0, 7, 7, 7]);
  const root = project({ 'node_modules/wasm-codec/codec.wasm': wasm, 'dist/assets/codec-abc123.wasm': wasm, 'dist/assets/own.wasm': Buffer.from([0, 97, 115, 109, 9]) });
  assert.deepEqual(binaryCopies([join(root, 'dist')], { root }), ['node_modules/wasm-codec/codec.wasm']);
});

test('--deploy: a package that a deployed package loads from outside the deployment counts as shipped', () => {
  const root = project({
    'node_modules/vuln/package.json': pkg('vuln'), 'node_modules/vuln/index.js': 'module.exports = 1;',
    'node_modules/optional/package.json': pkg('optional'), 'node_modules/optional/index.js': '',
    'build/server.js': 'require("node:http"); require("wrapper");\n//# sourceMappingURL=server.js.map', 'build/server.js.map': map(['../src/server.js']), 'src/server.js': '',
    'build/node_modules/wrapper/package.json': pkg('wrapper'),
    'build/node_modules/wrapper/index.js': 'module.exports = require("vuln"); try { require("optional"); } catch (e) {} require("inside");',
    'build/node_modules/inside/package.json': pkg('inside'), 'build/node_modules/inside/index.js': '',
  });
  const d = readDeployment(['build'], { root, lockNames: new Set(['vuln', 'optional', 'inside', 'wrapper']) });
  assert.deepEqual(d.loadedFromOutside, [{ name: 'vuln', from: 'build/node_modules/wrapper/index.js' }]);
  assert.ok(d.packages.has('vuln') && d.whole.has('vuln') && !d.packages.has('optional'));
  assert.deepEqual(d.missingRuntime, []);
});

test('--deploy: a map that names a bundle with a map of its own is followed; one with no sources, or two in a file, says nothing', () => {
  const root = project({
    'node_modules/vuln/index.js': '', 'tmp/stage1.js': 'function bundled(){}', 'tmp/stage1.js.map': map(['../node_modules/vuln/index.js']),
    'out/min.js': 'function a(){}\n//# sourceMappingURL=min.js.map', 'out/min.js.map': map(['../tmp/stage1.js']),
    'bad/empty.js': 'function a(){ return 1 }\n//# sourceMappingURL=empty.js.map', 'bad/empty.js.map': map([]),
    'bad/two.js': 'function a(){ return 1 }\n//# sourceMappingURL=a.js.map\nfunction b(){ return 2 }\n//# sourceMappingURL=two.js.map', 'bad/two.js.map': map(['../tmp/stage1.js']),
    // a placeholder with nothing in it, and a file of strings, need no sources in their map (SvelteKit writes both)
    'bad/stub.js': 'import"./empty.js";function e(e){}export{e as component};\n//# sourceMappingURL=stub.js.map', 'bad/stub.js.map': map([]),
    'bad/strings.js': 'const e="Add a function",t="Access";export{e as a,t as b};\n//# sourceMappingURL=strings.js.map', 'bad/strings.js.map': map([]),
  });
  assert.deepEqual([...readDeployment(['out'], { root }).packages.keys()], ['vuln']);
  const chained = withChainedSources(mapSources(JSON.parse(map(['../tmp/stage1.js'])), join(root, 'out/min.js.map'), root), root, [root]);
  assert.deepEqual(chained.map((s) => s.path), ['tmp/stage1.js', 'node_modules/vuln/index.js']);
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
  for (const s of stubs) assert.ok(isLoaderStub(debugId + s), s);
  // the same list as a browser gets it
  assert.ok(isLoaderStub(`${debugId}(globalThis.TURBOPACK||(globalThis.TURBOPACK=[])).push(["object"==typeof document?document.currentScript:void 0,993608,function(o){o.n(o.i(518537))}]);`));
  assert.ok(!isLoaderStub('(globalThis.TURBOPACK||(globalThis.TURBOPACK=[])).push(["object"==typeof document?document.currentScript:void 0,1,function(o){return o.a*2}]);'));
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
  for (const c of code) assert.ok(!isLoaderStub(c), c);

  const root = project({
    'out/stub.js': `${debugId}${stubs[0]}\n//# sourceMappingURL=stub.js.map`, 'out/stub.js.map': map([], { sections: [{ offset: { line: 1, column: 0 }, map: { version: 3, sources: [], names: [], mappings: '' } }] }),
    'out/code.js': `${code[2]}\n//# sourceMappingURL=code.js.map`, 'out/code.js.map': map([]),
  });
  assert.deepEqual(readDeployment(['out'], { root }).unmapped, ['out/code.js']);
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
    'src/a.js': '', 'node_modules/editor/min/vs/lang/abap.js': lib, 'node_modules/editor/package.json': pkg('editor'),
    'node_modules/resolve/package.json': pkg('resolve'), 'node_modules/resolve/test/shadowed/node_modules/util/index.js': 'module.exports = 1;',
    'dist/main.js': '', 'dist/vs/lang/abap.js': minified, 'dist/other/abap.js': 'export function unrelated(){ return [1,2,3].map(function(x){ return x * 2 }) }',
  });
  const stats = { outputPath: join(root, 'dist'), modules: [{ name: './src/a.js', chunks: [1] }], assets: [
    { name: 'main.js', chunks: [1] },
    { name: 'vs/lang/abap.js', chunks: [], info: { copied: true, minimized: true, sourceFilename: 'lang/abap.js' } },
    { name: 'other/abap.js', chunks: [], info: { copied: true, sourceFilename: 'lang/abap.js' } },
  ] };
  const s = strayOutputs(stats, { root });
  const a = accountFor(s.stray, { root, outDirs: s.dirs, hints: s.hints });
  assert.deepEqual(a.accounted.map((x) => [x.file, x.kind, x.adds]), [['dist/vs/lang/abap.js', 'copy', ['node_modules/editor/min/vs/lang/abap.js']]]);
  assert.deepEqual(a.unknown.map((x) => x.file), ['dist/other/abap.js']); // the same hint, but not that file's strings

  // a folder inside a package that is itself no package: its files are the holding package's
  const mm = attachVersions(readModuleMap({ inputs: {}, outputs: { 'dist/a.js': { inputs: { 'node_modules/resolve/test/shadowed/node_modules/util/index.js': { bytesInOutput: 9 } } } } }), { cwd: root });
  assert.deepEqual([[...mm.packages.keys()], mm.unverified, [...mm.packages.get('resolve').files]], [['resolve'], [], ['test/shadowed/node_modules/util/index.js']]);
});

test('--deploy: a package that ships its original sources is taken whole, and the VEX is tied to what was deployed', () => {
  const inline = `exports.parse = function(){};\n//# sourceMappingURL=data:application/json;base64,${Buffer.from(map(['../src/parse.js']) + ' '.repeat(120)).toString('base64')}`;
  const root = project({
    'node_modules/ts-lib/package.json': pkg('ts-lib'), 'node_modules/ts-lib/src/parse.ts': 'export const parse = 1;', 'node_modules/ts-lib/dist/parse.js': '',
    'node_modules/js-lib/package.json': pkg('js-lib'), 'node_modules/js-lib/src/parse.js': '', 'node_modules/js-lib/dist/parse.js': inline,
    'node_modules/plain/package.json': pkg('plain'), 'node_modules/plain/index.js': 'exports.x = function(){};',
    'out/app.js': 'function a(){}\n//# sourceMappingURL=app.js.map',
    'out/app.js.map': map(['../node_modules/ts-lib/src/parse.ts', '../node_modules/js-lib/src/parse.js', '../node_modules/plain/index.js']),
  });
  const d = readDeployment(['out'], { root });
  assert.ok(d.whole.has('ts-lib') && !d.whole.has('js-lib') && !d.whole.has('plain'));
  assert.deepEqual(inlineMapPackages(d, ['js-lib', 'plain', 'ts-lib', 'absent'], root), ['js-lib']);

  const before = deploymentDigest(['out'], root);
  assert.match(before, /^[0-9a-f]{64}$/);
  assert.equal(deploymentDigest(['out'], root), before);
  writeFileSync(join(root, 'out/app.js'), 'function b(){}\n//# sourceMappingURL=app.js.map');
  assert.notEqual(deploymentDigest(['out'], root), before);
});

test('--deploy: a folder linked into the deployment is read; a script that loads a Node module is not a server', (t) => {
  const root = project({
    'node_modules/vuln/index.js': '', 'shared/chunks/api.js': 'function a(){}\n//# sourceMappingURL=api.js.map', 'shared/chunks/api.js.map': map(['../../node_modules/vuln/index.js']),
    'out/server/index.js': 'require("./chunks/api.js");',
  });
  try { symlinkSync(join(root, 'shared/chunks'), join(root, 'out/server/chunks'), 'junction'); } catch { t.skip('links cannot be made here'); return; }
  assert.deepEqual([...readDeployment(['out'], { root }).packages.keys()], ['vuln']);
});
