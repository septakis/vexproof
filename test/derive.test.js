// SPDX-License-Identifier: MIT
// Derived rules: the files an advisory's fix changed, taken from npm tarballs. They must never clear shipped
// vulnerable code, they only suggest until accepted, and hand-checked rules always win.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { fixBoundary, diffForRule, untar, isRuntimeFile, deriveRules, compareVersions } from '../src/derive.js';
import { triage } from '../src/index.js';
import { evaluateModuleRule, mergeRules } from '../src/pro/module-check.js';
import { readModuleMap } from '../src/modules.js';
import { fromNpmAudit } from '../src/sources.js';
import vexproof from '../src/vite.js';
import { temporaryFolder } from './lib/temporary.js';

const fixture = (fileName) => JSON.parse(readFileSync(new URL(`./fixtures/${fileName}`, import.meta.url)));
const handRules = fixture('../../src/pro/rules/module-rules.json');
const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const bytes = (text) => Buffer.from(text);

test('fix boundary: first release after the installed one that leaves the range', () => {
  const versions = ['4.17.19', '4.17.20', '4.17.21', '4.17.22', '4.17.23', '4.18.0', '5.0.0-beta.1'];

  assert.deepEqual(fixBoundary(versions, '4.17.21', '>=4.0.0 <=4.17.22'), { vulnerable: '4.17.22', fixed: '4.17.23' });
  assert.deepEqual(fixBoundary(versions, '4.17.20', '<=4.17.23'), { vulnerable: '4.17.23', fixed: '4.18.0' });
  assert.match(fixBoundary(versions, '4.18.0', '>=4.0.0').reason, /no fixed version/);
  assert.ok(compareVersions('5.0.0-beta.1', '5.0.0') < 0);
});

test('rule files = JavaScript files of the installed version that the fixed release changed or dropped', () => {
  const installedFiles = new Map([
    ['template.js', bytes('a')], ['trim.js', bytes('b')], ['omit.js', bytes('c')],
    ['README.md', bytes('x')], ['test/t.js', bytes('t')], ['index.d.ts', bytes('d')],
  ]);
  const fixedFiles = new Map([
    ['template.js', bytes('A')], ['omit.js', bytes('c')], ['README.md', bytes('y')],
    ['test/t.js', bytes('T')], ['index.d.ts', bytes('D')], ['new.js', bytes('n')],
  ]);

  // test/t.js is named too: a file that never ships costs nothing, and some "test" or "doc" folders are code
  assert.deepEqual(diffForRule({ installedFiles, fixedFiles }), { files: ['template.js', 'test/t.js', 'trim.js'], javascriptFiles: 4 });
  assert.match(diffForRule({ installedFiles, fixedFiles: installedFiles }).reason, /no runtime JavaScript/);
  assert.match(diffForRule({ installedFiles, fixedFiles: new Map([['lib/other.js', bytes('')]]) }).reason, /reorganised/);

  assert.ok(isRuntimeFile('lib/loader.mjs') && !isRuntimeFile('__tests__/x.js') && !isRuntimeFile('types/a.d.mts'));
});

test('npm tarballs are read without system tools', (testContext) => {
  const dir = temporaryFolder(testContext, 'vxp-tar-');
  const deepFolder = 'package/lib/a-very-long-directory-name-that-goes-on-and-on/and-on-and-on-and-on-and-on';
  mkdirSync(join(dir, deepFolder), { recursive: true });
  writeFileSync(join(dir, 'package/index.js'), 'module.exports = 1;\n');
  writeFileSync(join(dir, `${deepFolder}/deep-file-name.js`), 'x');
  const tgz = execFileSync('tar', ['-czf', '-', '-C', dir, 'package']);

  const files = untar(tgz);

  assert.equal(files.get('index.js').toString(), 'module.exports = 1;\n');
  assert.ok(files.has('lib/a-very-long-directory-name-that-goes-on-and-on/and-on-and-on-and-on-and-on/deep-file-name.js'));
});

test('tarballs: a "./package/" folder is read like "package/", and an entry that can\'t be read stops the reading', () => {
  // one tar entry, written by hand: name, size in octal, type "0" (a file), then the content padded to 512 bytes
  const entry = (name, content, { sizeField = content.length.toString(8).padStart(11, '0') } = {}) => {
    const header = Buffer.alloc(512);
    header.write(name, 0, 'utf8');
    header.write('0000644\0', 100, 'utf8');
    header.write(`${sizeField}\0`, 124, 'utf8');
    header.write('0', 156, 'utf8');
    header.write('ustar\0', 257, 'utf8');
    const body = Buffer.alloc(Math.ceil(content.length / 512) * 512);
    body.write(content, 0, 'utf8');

    return Buffer.concat([header, body]);
  };
  const archive = (...entries) => gzipSync(Buffer.concat([...entries, Buffer.alloc(1024)]));

  const dotted = untar(archive(entry('./package/index.js', 'module.exports = 1;'), entry('./package/lib/parse.js', 'parse')));
  assert.deepEqual([...dotted.keys()], ['index.js', 'lib/parse.js']);

  // a size that is not octal would have ended the reading quietly, and parse.js would have looked absent
  const badSize = archive(entry('package/index.js', 'x', { sizeField: '\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01' }), entry('package/lib/parse.js', 'parse'));
  assert.throws(() => untar(badSize), /unreadable tar archive: the entry "package\/index\.js" gives its size/);

  const cutShort = gzipSync(entry('package/index.js', 'x'.repeat(2000)).subarray(0, 1024));
  assert.throws(() => untar(cutShort), /the entry "package\/index\.js" is cut short/);
});

test('deriveRules against a registry: picks the range for this release line, refuses what it cannot locate', async (testContext) => {
  const tgz = (files) => {
    const dir = temporaryFolder(testContext, 'vxp-pkg-');
    for (const [filePath, content] of Object.entries(files)) {
      mkdirSync(join(dir, 'package', filePath, '..'), { recursive: true });
      writeFileSync(join(dir, 'package', filePath), content);
    }
    return execFileSync('tar', ['-czf', '-', '-C', dir, 'package']);
  };
  const tarballs = {
    '1.0.0': tgz({ 'index.js': 'i', 'parse.js': 'bad', 'util.js': 'u' }),
    '1.0.1': tgz({ 'index.js': 'i', 'parse.js': 'good', 'util.js': 'u' }),
    '2.0.0': tgz({ 'index.js': 'I', 'parse.js': 'bad2' }),
    '2.1.0': tgz({ 'index.js': 'I', 'parse.js': 'good2' }),
  };
  const integrity = (tarball) => `sha512-${createHash('sha512').update(tarball).digest('base64')}`;
  const fetchImpl = async (url, init) => {
    const ok = (body) => ({ ok: true, json: async () => body, arrayBuffer: async () => body });
    if (url.endsWith('/advisories/bulk')) {
      return ok({ demo: [
        { url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', title: 'parse bug', vulnerable_versions: '>=2.0.0 <2.1.0' },
        { url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', title: 'parse bug', vulnerable_versions: '<1.0.1' },
      ] });
    }
    if (url.endsWith('/demo')) {
      const versions = Object.entries(tarballs).map(([version, tarball]) => [version, { dist: { integrity: integrity(tarball) } }]);
      return ok({ versions: Object.fromEntries(versions) });
    }
    const version = /demo-(.+)\.tgz$/.exec(url)?.[1];
    return version ? ok(tarballs[version]) : { ok: false, status: 404 };
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
  const derived = fixture('lodash.derived-rules.json');
  const vulnerableCode = {
    'GHSA-35jh-r3h4-6jhm': 'template.js',
    'GHSA-r5fr-rjxr-66jc': 'template.js',
    'GHSA-29mw-wpgm-hmr9': 'trim.js',
    'GHSA-xxjr-mmjv-4gpg': '_baseUnset.js',
    'GHSA-f23m-r3pf-42rh': '_baseUnset.js',
  };

  let checked = 0;
  for (const packageRules of Object.values(derived.packages)) {
    for (const rule of Object.values(packageRules.advisories)) {
      assert.ok(rule.files.includes(vulnerableCode[rule.id]), `${rule.id}: ${rule.files}`);
      checked++;
    }
  }

  assert.equal(checked, 8);
});

test('derived rules never clear what hand-checked rules keep open (Angular and recharts builds)', () => {
  const derived = fixture('lodash.derived-rules.json');
  const cases = [
    ['angular.bom.lockfile.json', 'angular-capitalize.bom.bundle.json', 'angular-capitalize.metafile.json', 'angular.audit.json'],
    ['angular.bom.lockfile.json', 'angular-template.bom.bundle.json', 'angular-template.metafile.json', 'angular.audit.json'],
    ['recharts.bom.lockfile.json', 'recharts.bom.bundle.json', 'recharts.metafile.json', 'recharts.audit.json'],
  ];

  let settledCount = 0;
  for (const [lockFile, bundleFile, metafileFile, auditFile] of cases) {
    const lock = fixture(lockFile);
    const run = (rules, acceptDerived) => triage({
      lockfileSbom: lock,
      bundleSbom: fixture(bundleFile),
      moduleMap: readModuleMap(fixture(metafileFile)),
      findings: fromNpmAudit(fixture(auditFile), lock),
      rules,
      moduleCheck: evaluateModuleRule,
      pro: true,
      acceptDerived,
    });

    const byHand = run(handRules, false);
    const byDerived = run(derived, true);

    // matched by advisory and package, not by position: each rule set adds its own aliases before findings merge
    const handVerdict = new Map(byHand.map((result) => [`${result.id}|${result.purl}`, result.state]));
    const settledByDerived = byDerived.filter((result) => result.state === 'not_affected');
    for (const result of settledByDerived) {
      assert.equal(handVerdict.get(`${result.id}|${result.purl}`), 'not_affected', `${metafileFile} ${result.id}`);
    }
    // and the comparison is about something: the derived rules settle at least one finding in these builds
    settledCount += settledByDerived.length;
  }
  assert.ok(settledCount > 0, 'the derived rules settle nothing here, so the comparison checks nothing');
});

test('a derived rule only suggests until accepted; hand-checked rules win', () => {
  const lock = fixture('angular.bom.lockfile.json');
  const derived = fixture('lodash.derived-rules.json');
  const args = {
    lockfileSbom: lock,
    bundleSbom: fixture('angular-capitalize.bom.bundle.json'),
    moduleMap: readModuleMap(fixture('angular-capitalize.metafile.json')),
    findings: fromNpmAudit(fixture('angular.audit.json'), lock),
    moduleCheck: evaluateModuleRule,
    pro: true,
  };
  const lodash = (results) => results.filter((result) => result.purl.includes('lodash-es'));

  const suggested = lodash(triage({ ...args, rules: derived }));

  assert.ok(suggested.every((result) => result.state === 'in_triage' && /derived rule suggests/.test(result.moduleReason)));

  const accepted = lodash(triage({ ...args, rules: derived, acceptDerived: true }));

  assert.ok(accepted.every((result) => result.state === 'not_affected' && result.evidence.ruleOrigin === 'derived'));

  const merged = mergeRules(handRules, derived);

  assert.equal(Object.values(merged.packages['lodash-es'].advisories).filter((advisory) => advisory.origin === 'derived').length, 0);

  const wrongVersion = structuredClone(derived);
  for (const advisory of Object.values(wrongVersion.packages['lodash-es'].advisories)) {
    advisory.versions = ['9.9.9'];
  }

  const unmatched = lodash(triage({ ...args, rules: wrongVersion, acceptDerived: true }));

  assert.ok(unmatched.every((result) => result.state === 'in_triage'));
});

test('apps that also run on a server: refused unless the VEX is scoped to the browser bundle', (testContext) => {
  const dir = temporaryFolder(testContext, 'vxp-ssr-');
  const lock = fixture('recharts.bom.lockfile.json');
  lock.components.push({ type: 'library', name: 'next', version: '15.0.0', purl: 'pkg:npm/next@15.0.0' });
  writeFileSync(join(dir, 'lock.json'), JSON.stringify(lock));
  const bundle = fileURLToPath(new URL('./fixtures/recharts.bom.bundle.json', import.meta.url));
  const findings = fileURLToPath(new URL('./fixtures/recharts.audit.json', import.meta.url));
  const run = (...extra) => spawnSync(
    process.execPath,
    [CLI, '--lockfile', 'lock.json', '--bundle', bundle, '--findings', findings, '--out', 'vex.json', '--quiet', ...extra],
    { cwd: dir, encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: '' } }, // free, whatever this machine holds
  );

  const refused = run();

  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /also runs JavaScript on a server \(next is a dependency\)/);

  assert.equal(run('--browser-only').status, 0);

  const vex = JSON.parse(readFileSync(join(dir, 'vex.json'), 'utf8'));
  assert.equal(vex.metadata.properties.find((property) => property.name === 'vexproof:scope').value, 'browser-bundle');
});

test('the Vite plugin records server builds it skips, so the CLI can refuse', (testContext) => {
  const dir = temporaryFolder(testContext, 'vxp-vite-ssr-');
  const plugin = vexproof({ root: dir, output: 'ssr-modules.json' });
  plugin.configResolved({ root: dir, build: { outDir: 'dist' } });
  plugin.buildStart.call({ meta: { viteVersion: '7.0.0', rollupVersion: '4.0.0' } });
  const clientContext = { environment: { config: { consumer: 'client' } } };
  const serverContext = { environment: { config: { consumer: 'server' } } };

  plugin.generateBundle.call(clientContext, { dir: join(dir, 'dist') }, {
    'a.js': { type: 'chunk', fileName: 'a.js', modules: { [join(dir, 'node_modules/x/i.js')]: { renderedLength: 10 } } },
  });
  plugin.generateBundle.call(serverContext, { dir: join(dir, 'dist/server') }, { 's.js': { type: 'chunk', fileName: 's.js', modules: {} } });
  plugin.closeBundle();

  const record = JSON.parse(readFileSync(join(dir, 'ssr-modules.json'), 'utf8'));
  assert.equal(record.serverBuildsSkipped, 1);
  assert.deepEqual(Object.keys(record.outputs), ['dist/a.js']);
});
