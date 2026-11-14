// SPDX-License-Identifier: MIT
// Smaller guards a mutation test of the code audit's fixes showed no test held: each case fails if its guard is
// turned off.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join, resolve } from 'node:path';
import { project, write, pkg, lockfile, idOf } from './lib/project.js';
import { proCopy } from './lib/pro-copy.js';
import { readModuleMap, attachVersions } from '../src/modules.js';
import { installedDirs } from '../src/content-check.js';
import { toStatement } from '../src/openvex.js';
import vexproof from '../src/vite.js';

test("a nested package whose package.json can't be read is not filed under the package around it", (t) => {
  const root = project(t, {
    'node_modules/a/package.json': pkg('a'),
    'node_modules/a/index.js': 'module.exports = require("d");\n',
    'node_modules/a/node_modules/d/package.json': '{ "name": "d", broken',
    'node_modules/a/node_modules/d/index.js': 'module.exports = 1;\n',
  });
  const mm = attachVersions(readModuleMap({ inputs: {}, outputs: { 'dist/a.js': { inputs: {
    'node_modules/a/index.js': { bytesInOutput: 9 }, 'node_modules/a/node_modules/d/index.js': { bytesInOutput: 9 },
  } } } }), { cwd: root });
  assert.deepEqual([...mm.packages.get('a').files], ['index.js']);
  assert.deepEqual([...mm.packages.get('d').files], ['index.js']);
  assert.deepEqual(mm.unverified.map((u) => u.root), ['node_modules/a/node_modules/d']);
});

test("the content check finds packages in Yarn's and Bun's stores", (t) => {
  const root = project(t, {
    'node_modules/.store/left-pad-npm-1.3.0-0123456789/package/package.json': pkg('left-pad', '1.3.0'),
    'node_modules/.bun/is-odd@3.0.1/node_modules/is-odd/package.json': pkg('is-odd', '3.0.1'),
  });
  assert.equal(installedDirs('left-pad', [root]).length, 1);
  assert.equal(installedDirs('is-odd', [root]).length, 1);
});

test('OpenVEX: reviewed states map to the statuses OpenVEX defines', () => {
  const s = (state) => toStatement({ id: 'GHSA-x', purl: 'pkg:npm/a@1', state, detail: 'd' }, { productPurl: 'pkg:npm/app@1' }).status;
  assert.equal(s('exploitable'), 'affected');
  assert.equal(s('false_positive'), 'not_affected');
  assert.equal(s('resolved'), 'fixed');
  assert.equal(s('in_triage'), 'under_investigation');
});

test('Vite plugin: a server build is recorded when includeServer asks for it', () => {
  const run = (includeServer) => {
    const root = resolve(`/vxp-ssr-${includeServer}`);
    const p = vexproof({ root, includeServer });
    p.configResolved({ root, build: { outDir: 'dist/server', ssr: true } });
    p.generateBundle.call({}, { dir: join(root, 'dist/server') }, { 's.js': { type: 'chunk', fileName: 's.js', modules: { [join(root, 'node_modules/x/i.js')]: { renderedLength: 9 } } } });
    return globalThis[Symbol.for('vexproof.vite.registry')].get(resolve(root, 'vexproof-modules.json'));
  };
  assert.equal(run(false).serverBuildsSkipped, 1);
  assert.deepEqual(Object.keys(run(true).outputs), ['dist/server/s.js']);
});

test('Pro, --deploy: a package with source maps inlined in its files counts whole, so no file-level claim is made for it', (t) => {
  const pro = proCopy(t);
  // what a package that ships its own source map inline ends with: a long base64 tail
  const inline = `//# sourceMappingURL=data:application/json;base64,${Buffer.from(JSON.stringify({ version: 3, sources: ['../src/index.ts'], mappings: '' })).toString('base64').repeat(3)}`;
  const root = project(t, {
    'out/node_modules/inl/package.json': pkg('inl'),
    'out/node_modules/inl/index.js': `module.exports = 1;\n${inline}\n`,
    'out/server.js': 'require("inl");\n',
  });
  lockfile(root, [['inl', '1.0.0']]);
  write(root, { 'rules.json': { schema: 1, packages: { inl: { advisories: {
    [idOf('inl')]: { id: idOf('inl'), files: ['lib/vuln.js'], affects: 'a bug', origin: 'reviewed' },
  } } } } });
  const r = pro.run(['--lockfile', 'bom.json', '--findings', 'findings.json', '--deploy', 'out', '--rules', 'rules.json', '--out', 'vex.json', '--quiet'], { cwd: root });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, new RegExp(`in_triage\\s+${idOf('inl')}.*counts as shipped whole`));
});
