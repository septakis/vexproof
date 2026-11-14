// SPDX-License-Identifier: MIT
// Reading a deployment folder (--deploy): ways deployed code looked absent, found by the code audit of
// 1.0.0-beta.9. Each case gave not_affected for a package whose code runs, or for code nothing examined.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import * as nodeModule from 'node:module';
import { project, write, pkg, git } from './lib/project.js';
import { readDeployment, missingHalves, findMap } from '../src/deploy.js';

const map = (sources, extra = {}) => ({ version: 3, sources, names: [], mappings: '', ...extra });
const victim = { 'node_modules/victim/package.json': pkg('victim'), 'node_modules/victim/index.js': 'module.exports = 1;\n' };

test('a deployed package that loads another from outside the deployment, in any spelling bundlers use, ships it', (t) => {
  for (const [label, code] of [
    ['esbuild __require', 'var __require = (x) => require(x); module.exports = __require("victim");'],
    ['createRequire', 'import { createRequire } from "node:module"; export default createRequire(import.meta.url)("victim");'],
    ['behind a test', 'let v; try { v = require("victim"); } catch {} module.exports = v;'],
  ]) {
    const ext = label === 'createRequire' ? 'mjs' : 'js';
    const root = project(t, { ...victim,
      'out/server.js': 'require("a");\n', // a launcher with no code of its own
      'out/node_modules/a/package.json': pkg('a'), [`out/node_modules/a/index.${ext}`]: code });
    const d = readDeployment(['out'], { root, lockNames: new Set(['a', 'victim']) });
    assert.deepEqual(d.loadedFromOutside.map((x) => x.name), ['victim'], label);
    assert.ok(d.packages.has('victim') && d.whole.has('victim'), label);
  }
});

test('deployed code that loads a file from outside the deployment is reported, not passed over', (t) => {
  const root = project(t, { ...victim,
    'src/server.js': 'x',
    'generated/client.js': 'module.exports = require("victim");\n',
    'dist/server.js': 'const c = require("../generated/client.js"); console.log(c);\n//# sourceMappingURL=server.js.map',
    'dist/server.js.map': map(['../src/server.js']) });
  const d = readDeployment(['dist'], { root, lockNames: new Set(['victim']) });
  assert.deepEqual(d.escapes, [{ target: 'generated/client.js', from: 'dist/server.js' }]);
  // a path that is not there is left alone: what it is where the server runs can't be told from here
  const gone = project(t, { 'src/server.js': 'x', 'dist/server.js': 'require("../config/local.js");\n//# sourceMappingURL=server.js.map', 'dist/server.js.map': map(['../src/server.js']) });
  assert.deepEqual(readDeployment(['dist'], { root: gone }).escapes, []);
});

test('TypeScript that Node runs as it is (type stripping) is read like JavaScript', { skip: typeof nodeModule.stripTypeScriptTypes !== 'function' && 'this Node has no type stripping' }, (t) => {
  const root = project(t, { ...victim, 'app/server.ts': 'import v from "victim";\nconst port: number = 3000;\nconsole.log(v, port);\n' });
  const d = readDeployment(['app'], { root, lockNames: new Set(['victim']) });
  assert.deepEqual(d.missingRuntime, [{ name: 'victim', from: 'app/server.ts' }]);
});

test("the server half of any framework is not a whole deployment without its browser half", (t) => {
  for (const [server, browser] of [
    ['build/server', 'build/client'], // React Router 7
    ['dist/server', 'dist/client'], // Astro's node adapter
    ['dist/app/server', 'dist/app/browser'], // Angular SSR
    ['.svelte-kit/output/server', '.svelte-kit/output/client'], // SvelteKit before an adapter
    ['.output/server', '.output/public'], // Nitro (Nuxt)
  ]) {
    const root = project(t, { [`${server}/index.js`]: 'x', [`${browser}/app.js`]: 'x' });
    assert.deepEqual(missingHalves([server], root), [browser], server);
    assert.deepEqual(missingHalves([server, browser], root), [], `${server} with ${browser}`);
  }
  // a sibling of such a name with no JavaScript in it is no browser half
  const css = project(t, { 'dist/server/index.js': 'x', 'dist/client/style.css': 'x' });
  assert.deepEqual(missingHalves(['dist/server'], css), []);
});

test('a source map whose every source is made up accounts for nothing', (t) => {
  const root = project(t, { ...victim,
    'out/chunk.js': 'function sanitize(s){return s.replace(/</g,"")} module.exports = sanitize;\n//# sourceMappingURL=chunk.js.map',
    'out/chunk.js.map': map(['webpack://app/src/lib/sanitize.js']) });
  const d = readDeployment(['out'], { root, lockNames: new Set(['victim']) });
  assert.deepEqual(d.unmapped, ['out/chunk.js']);
});

test('a source map written on Windows names the same package on every system', (t) => {
  const root = project(t, { ...victim,
    'out/app.js': 'function v(){return 1} module.exports = v;\n//# sourceMappingURL=app.js.map',
    'out/app.js.map': map(['C:\\build\\node_modules\\victim\\index.js']) });
  const d = readDeployment(['out'], { root, lockNames: new Set(['victim']) });
  assert.ok(d.packages.has('victim'));
  assert.deepEqual(d.unattributed, []);
});

test("a map found elsewhere by name must sit in all the file's folders and agree with it", (t) => {
  const bundled = 'function victimTemplate(s){return eval(s)} module.exports = victimTemplate;\n//# sourceMappingURL=page.js.map';
  for (const mapAt of ['maps/server/app/about/page.js.map', 'maps/server/app/contact/page.js.map']) {
    const root = project(t, { ...victim, 'src/other.js': 'x', 'out/server/app/[locale]/about/page.js': bundled, [mapAt]: map(['../../../../src/other.js']) });
    const d = readDeployment(['out'], { root, mapDirs: ['maps'], lockNames: new Set(['victim']) });
    assert.deepEqual(d.unmapped, ['out/server/app/[locale]/about/page.js'], mapAt);
  }
  // a map in folders of the same names all the way up is the file's (Next.js keeps server maps in .next)
  const next = project(t, { 'src/page.js': 'x', '.next/standalone/.next/server/app/about/page.js': bundled, '.next/server/app/about/page.js.map': map(['../../../../src/page.js']) });
  assert.ok(findMap(join(next, '.next/standalone/.next/server/app/about/page.js'), bundled,
    new Map([['page.js.map', [join(next, '.next/server/app/about/page.js.map')]]]), { base: join(next, '.next/standalone') }));
  // ...unless it says it is another file's: by the generated file it names, or by a debug id both carry
  const at = (p) => join(next, p);
  const idCode = `${bundled}\n//# debugId=11111111-2222-3333-4444-555555555555`;
  for (const [name, extra, code] of [['named', { file: 'layout.js' }, bundled], ['debug-id', { debugId: '99999999-2222-3333-4444-555555555555' }, idCode]]) {
    const dir = project(t, { 'src/page.js': 'x', '.next/server/app/about/page.js.map': map(['../../../../src/page.js'], extra) });
    const found = findMap(at('.next/standalone/.next/server/app/about/page.js'), code,
      new Map([['page.js.map', [join(dir, '.next/server/app/about/page.js.map')]]]), { base: at('.next/standalone') });
    assert.equal(found, null, name);
  }
});

test('packages deployed through Yarn\'s pnpm linker are found by name', (t) => {
  const root = project(t, {
    'out/server.js': 'module.exports = require("b");\n//# sourceMappingURL=server.js.map', 'out/server.js.map': map(['../src/server.js']), 'src/server.js': 'x',
    'out/node_modules/.store/b-npm-1.0.0-0123456789/package/package.json': pkg('b'),
    'out/node_modules/.store/b-npm-1.0.0-0123456789/package/index.js': 'module.exports = 1;\n',
  });
  assert.deepEqual(readDeployment(['out'], { root, lockNames: new Set(['b']) }).missingRuntime, []);
});

test("a deployed file that is the project's own only by being tracked by git is marked so", (t) => {
  const sw = 'self.addEventListener("fetch", function (e) { e.respondWith(fetch(e.request)); });\n';
  const root = project(t, { 'public/sw.js': sw });
  assert.equal(git(root, 'init', '-q').status, 0);
  assert.equal(git(root, 'add', 'public/sw.js').status, 0);
  write(root, { 'out/sw.js': sw });
  assert.deepEqual(readDeployment(['out'], { root }).selfVouched, ['public/sw.js']);
});
