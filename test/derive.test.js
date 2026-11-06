// SPDX-License-Identifier: MIT
// Derived rules: the files an advisory's fix changed, taken from npm tarballs. They must never clear shipped
// vulnerable code, they only suggest until accepted, and hand-checked rules always win.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixBoundary, diffForRule, untar, isRuntimeFile, deriveRules, compareVersions } from '../src/derive.js';
import { triage } from '../src/index.js';
import { evaluateModuleRule, mergeRules } from '../src/pro/module-check.js';
import { readModuleMap } from '../src/modules.js';
import { fromNpmAudit } from '../src/sources.js';
import vexproof from '../src/vite.js';

const fx = (f) => JSON.parse(readFileSync(new URL(`./fixtures/${f}`, import.meta.url)));
const hand = fx('../../src/pro/rules/module-rules.json');
const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const B = (s) => Buffer.from(s);

test('fix boundary: first release after the installed one that leaves the range', () => {
  const vs = ['4.17.19', '4.17.20', '4.17.21', '4.17.22', '4.17.23', '4.18.0', '5.0.0-beta.1'];
  assert.deepEqual(fixBoundary(vs, '4.17.21', '>=4.0.0 <=4.17.22'), { vulnerable: '4.17.22', fixed: '4.17.23' });
  assert.deepEqual(fixBoundary(vs, '4.17.20', '<=4.17.23'), { vulnerable: '4.17.23', fixed: '4.18.0' });
  assert.match(fixBoundary(vs, '4.18.0', '>=4.0.0').reason, /no fixed version/);
  assert.ok(compareVersions('5.0.0-beta.1', '5.0.0') < 0);
});

test('rule files = runtime files of the installed version that the fixed release changed or dropped', () => {
  const installedFiles = new Map([['template.js', B('a')], ['trim.js', B('b')], ['omit.js', B('c')], ['README.md', B('x')], ['test/t.js', B('t')], ['index.d.ts', B('d')]]);
  const fixedFiles = new Map([['template.js', B('A')], ['omit.js', B('c')], ['README.md', B('y')], ['test/t.js', B('T')], ['index.d.ts', B('D')], ['new.js', B('n')]]);
  assert.deepEqual(diffForRule({ installedFiles, fixedFiles }), { files: ['template.js', 'trim.js'], runtimeFiles: 3 });
  assert.match(diffForRule({ installedFiles, fixedFiles: installedFiles }).reason, /no runtime JavaScript/);
  assert.match(diffForRule({ installedFiles, fixedFiles: new Map([['lib/other.js', B('')]]) }).reason, /reorganised/);
  assert.ok(isRuntimeFile('lib/loader.mjs') && !isRuntimeFile('__tests__/x.js') && !isRuntimeFile('types/a.d.mts'));
});

test('npm tarballs are read without system tools', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vxp-tar-'));
  mkdirSync(join(dir, 'package/lib/a-very-long-directory-name-that-goes-on-and-on/and-on-and-on-and-on-and-on'), { recursive: true });
  writeFileSync(join(dir, 'package/index.js'), 'module.exports = 1;\n');
  writeFileSync(join(dir, 'package/lib/a-very-long-directory-name-that-goes-on-and-on/and-on-and-on-and-on-and-on/deep-file-name.js'), 'x');
  const tgz = execFileSync('tar', ['-czf', '-', '-C', dir, 'package']);
  const files = untar(tgz);
  assert.equal(files.get('index.js').toString(), 'module.exports = 1;\n');
  assert.ok(files.has('lib/a-very-long-directory-name-that-goes-on-and-on/and-on-and-on-and-on-and-on/deep-file-name.js'));
});

test('deriveRules against a registry: picks the range for this release line, refuses what it cannot locate', async () => {
  const tgz = (files) => {
    const dir = mkdtempSync(join(tmpdir(), 'vxp-pkg-'));
    for (const [p, c] of Object.entries(files)) { mkdirSync(join(dir, 'package', p, '..'), { recursive: true }); writeFileSync(join(dir, 'package', p), c); }
    return execFileSync('tar', ['-czf', '-', '-C', dir, 'package']);
  };
  const tarballs = {
    '1.0.0': tgz({ 'index.js': 'i', 'parse.js': 'bad', 'util.js': 'u' }),
    '1.0.1': tgz({ 'index.js': 'i', 'parse.js': 'good', 'util.js': 'u' }),
    '2.0.0': tgz({ 'index.js': 'I', 'parse.js': 'bad2' }),
    '2.1.0': tgz({ 'index.js': 'I', 'parse.js': 'good2' }),
  };
  const fetchImpl = async (url, init) => {
    const ok = (body) => ({ ok: true, json: async () => body, arrayBuffer: async () => body });
    if (url.endsWith('/advisories/bulk')) return ok({ demo: [
      { url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', title: 'parse bug', vulnerable_versions: '>=2.0.0 <2.1.0' },
      { url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', title: 'parse bug', vulnerable_versions: '<1.0.1' },
    ] });
    if (url.endsWith('/demo')) return ok({ versions: Object.fromEntries(Object.keys(tarballs).map((v) => [v, {}])) });
    const v = /demo-(.+)\.tgz$/.exec(url)?.[1];
    return v ? ok(tarballs[v]) : { ok: false, status: 404 };
  };
  const { rules, report } = await deriveRules([
    { name: 'demo', version: '1.0.0', id: 'GHSA-aaaa-bbbb-cccc' },
    { name: 'demo', version: '2.0.0', id: 'GHSA-aaaa-bbbb-cccc' },
    { name: 'demo', version: '1.0.0', id: 'GHSA-zzzz-zzzz-zzzz' },
  ], { fetchImpl });
  assert.deepEqual(rules.packages.demo.advisories['GHSA-aaaa-bbbb-cccc@1.0.0'].files, ['parse.js']);
  assert.deepEqual(rules.packages.demo.advisories['GHSA-aaaa-bbbb-cccc@2.0.0'].derivedFrom, { installed: '2.0.0', fixed: '2.1.0' });
  assert.match(report[2].reason, /not in the npm registry/);
});

test('real lodash fixes: every derived rule contains the file with the vulnerable code', () => {
  const derived = fx('lodash.derived-rules.json');
  const vulnerableCode = { 'GHSA-35jh-r3h4-6jhm': 'template.js', 'GHSA-r5fr-rjxr-66jc': 'template.js', 'GHSA-29mw-wpgm-hmr9': 'trim.js', 'GHSA-xxjr-mmjv-4gpg': '_baseUnset.js', 'GHSA-f23m-r3pf-42rh': '_baseUnset.js' };
  let n = 0;
  for (const pkg of Object.values(derived.packages))
    for (const r of Object.values(pkg.advisories)) { assert.ok(r.files.includes(vulnerableCode[r.id]), `${r.id}: ${r.files}`); n++; }
  assert.equal(n, 8);
});

test('derived rules never clear what hand-checked rules keep open (Angular and recharts builds)', () => {
  const derived = fx('lodash.derived-rules.json');
  const cases = [
    ['angular.bom.lockfile.json', 'angular-capitalize.bom.bundle.json', 'angular-capitalize.metafile.json', 'angular.audit.json'],
    ['angular.bom.lockfile.json', 'angular-template.bom.bundle.json', 'angular-template.metafile.json', 'angular.audit.json'],
    ['recharts.bom.lockfile.json', 'recharts.bom.bundle.json', 'recharts.metafile.json', 'recharts.audit.json'],
  ];
  for (const [l, b, m, a] of cases) {
    const lock = fx(l), run = (rules, acceptDerived) => triage({ lockfileSbom: lock, bundleSbom: fx(b), moduleMap: readModuleMap(fx(m)), findings: fromNpmAudit(fx(a), lock), rules, moduleCheck: evaluateModuleRule, pro: true, acceptDerived });
    const byHand = run(hand, false), byDerived = run(derived, true);
    byDerived.forEach((r, i) => { if (r.state === 'not_affected') assert.equal(byHand[i].state, 'not_affected', `${m} ${r.id}`); });
  }
});

test('a derived rule only suggests until accepted; hand-checked rules win', () => {
  const lock = fx('angular.bom.lockfile.json'), derived = fx('lodash.derived-rules.json');
  const args = { lockfileSbom: lock, bundleSbom: fx('angular-capitalize.bom.bundle.json'), moduleMap: readModuleMap(fx('angular-capitalize.metafile.json')), findings: fromNpmAudit(fx('angular.audit.json'), lock), moduleCheck: evaluateModuleRule, pro: true };
  const lodash = (rs) => rs.filter((r) => r.purl.includes('lodash-es'));
  const suggested = lodash(triage({ ...args, rules: derived }));
  assert.ok(suggested.every((r) => r.state === 'in_triage' && /derived rule suggests/.test(r.moduleReason)));
  const accepted = lodash(triage({ ...args, rules: derived, acceptDerived: true }));
  assert.ok(accepted.every((r) => r.state === 'not_affected' && r.evidence.ruleOrigin === 'derived'));
  const merged = mergeRules(hand, derived);
  assert.equal(Object.values(merged.packages['lodash-es'].advisories).filter((a) => a.origin === 'derived').length, 0);
  const wrongVersion = structuredClone(derived);
  for (const a of Object.values(wrongVersion.packages['lodash-es'].advisories)) a.versions = ['9.9.9'];
  assert.ok(lodash(triage({ ...args, rules: wrongVersion, acceptDerived: true })).every((r) => r.state === 'in_triage'));
});

test('apps that also run on a server: refused unless the VEX is scoped to the browser bundle', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vxp-ssr-'));
  const lock = fx('recharts.bom.lockfile.json');
  lock.components.push({ type: 'library', name: 'next', version: '15.0.0', purl: 'pkg:npm/next@15.0.0' });
  writeFileSync(join(dir, 'lock.json'), JSON.stringify(lock));
  const run = (...extra) => spawnSync(process.execPath, [CLI, '--lockfile', 'lock.json', '--bundle', fileURLToPath(new URL('./fixtures/recharts.bom.bundle.json', import.meta.url)), '--findings', fileURLToPath(new URL('./fixtures/recharts.audit.json', import.meta.url)), '--out', 'vex.json', '--quiet', ...extra], { cwd: dir, encoding: 'utf8' });
  const refused = run();
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /also runs JavaScript on a server \(next is a dependency\)/);
  assert.equal(run('--browser-only').status, 0);
  const vex = JSON.parse(readFileSync(join(dir, 'vex.json'), 'utf8'));
  assert.equal(vex.metadata.properties.find((p) => p.name === 'vexproof:scope').value, 'browser-bundle');
});

test('the Vite plugin records server builds it skips, so the CLI can refuse', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vxp-vite-ssr-'));
  const p = vexproof({ root: dir, output: 'ssr-modules.json' });
  p.configResolved({ root: dir, build: { outDir: 'dist' } });
  p.buildStart.call({ meta: { viteVersion: '7.0.0', rollupVersion: '4.0.0' } });
  p.generateBundle.call({ environment: { config: { consumer: 'client' } } }, { dir: join(dir, 'dist') }, { 'a.js': { type: 'chunk', fileName: 'a.js', modules: { [join(dir, 'node_modules/x/i.js')]: { renderedLength: 10 } } } });
  p.generateBundle.call({ environment: { config: { consumer: 'server' } } }, { dir: join(dir, 'dist/server') }, { 's.js': { type: 'chunk', fileName: 's.js', modules: {} } });
  p.closeBundle();
  const rec = JSON.parse(readFileSync(join(dir, 'ssr-modules.json'), 'utf8'));
  assert.equal(rec.serverBuildsSkipped, 1);
  assert.deepEqual(Object.keys(rec.outputs), ['dist/a.js']);
});
