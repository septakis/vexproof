// SPDX-License-Identifier: MIT
// Module rules and the versions they are checked against: ways a rule could settle a finding on code that
// shipped, found by the code audit of 1.0.0-beta.9.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseVersion, compareVersions, inAdvisoryRange } from '../src/versions.js';
import { fixBoundary, diffForRule } from '../src/derive.js';
import { fromBunAudit, fromNpmAudit } from '../src/sources.js';
import { mergeRules, validateRules, evaluateModuleRule } from '../src/pro/module-check.js';
import { triage } from '../src/index.js';
import { readModuleMap } from '../src/modules.js';

const toBytes = (text) => Buffer.from(text);
const fixture = (fileName) => JSON.parse(readFileSync(new URL(`./fixtures/${fileName}`, import.meta.url)));
const shipped = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));

test('versions compare as semver says, prereleases and build metadata included', () => {
  assert.ok(compareVersions('1.0.0-alpha', '1.0.0-beta') < 0 && compareVersions('1.0.0-beta', '1.0.0-alpha') > 0);
  assert.ok(compareVersions('1.0.0-rc.2', '1.0.0-rc.10') < 0);
  assert.ok(compareVersions('1.0.0-rc.1', '1.0.0') < 0);
  assert.equal(compareVersions('1.0.0+build.1', '1.0.0'), 0);
  assert.deepEqual(parseVersion('1.2'), { n: [1, 2, 0], pre: [] });
  assert.throws(() => compareVersions('one', '1.0.0'), /not a version: one/);
});

test('advisory ranges: spaces after operators, hyphen ranges and prereleases are read as written', () => {
  assert.ok(inAdvisoryRange('1.5.0', '>= 1.0.0 < 2.0.0'));
  assert.ok(inAdvisoryRange('1.5.0', '1.0.0 - 2.0.0'));
  assert.ok(!inAdvisoryRange('2.0.1', '1.0.0 - 2.0.0'));
  assert.ok(inAdvisoryRange('2.0.0-rc.1', '<2.0.0-rc.3'));
  assert.ok(!inAdvisoryRange('2.0.0-rc.3', '<2.0.0-rc.3'));
  assert.ok(inAdvisoryRange('0.9.0', '>=4.0.0 <=4.17.22 || <1.2'));
  // what can't be read keeps a version inside, so nothing is settled on a misreading
  assert.ok(inAdvisoryRange('1.5.0', '^1.2.0') && inAdvisoryRange('x', '<1.0.0') && inAdvisoryRange('1.0.0', ''));
});

test('a bound without its minor or patch covers every version that starts that way, as npm reads it', () => {
  // "<=1.2" is "<1.3.0": 1.2.3 is inside it, so it can't be picked as the fixed release
  assert.ok(inAdvisoryRange('1.2.3', '<=1.2'));
  assert.ok(!inAdvisoryRange('1.3.0', '<=1.2'));
  assert.ok(inAdvisoryRange('1.9.9', '<=1'));
  assert.ok(!inAdvisoryRange('2.0.0', '<=1'));

  // "1.2" alone is every 1.2.x
  assert.ok(inAdvisoryRange('1.2.7', '1.2'));
  assert.ok(!inAdvisoryRange('1.3.0', '1.2') && !inAdvisoryRange('1.1.9', '1.2'));

  // ">1.2" is ">=1.3.0"; "<1.2" and ">=1.2" start at 1.2.0
  assert.ok(!inAdvisoryRange('1.2.5', '>1.2') && inAdvisoryRange('1.3.0', '>1.2'));
  assert.ok(!inAdvisoryRange('1.2.0', '<1.2') && inAdvisoryRange('1.1.9', '<1.2'));
  assert.ok(inAdvisoryRange('1.2.0', '>=1.2') && !inAdvisoryRange('1.1.9', '>=1.2'));

  // a hyphen range's partial upper end covers its whole line too
  assert.ok(inAdvisoryRange('2.0.4', '1.0.0 - 2.0'));
});

test('a bun audit finding is never dropped because no listed version reads as in range', () => {
  // bun reported the advisory for this package; a range that reads as leaving the installed version out
  // (here, rightly or not) must not make the finding vanish
  const lock = { components: [{ purl: 'pkg:npm/pdfjs-dist@2.0.0-rc.1' }] };

  const findings = fromBunAudit({ 'pdfjs-dist': [{ url: 'https://github.com/advisories/GHSA-pdfj-pdfj-pdfj', vulnerable_versions: '<1.0.0' }] }, lock);

  assert.deepEqual(findings.map((finding) => finding.purl), ['pkg:npm/pdfjs-dist@2.0.0-rc.1']);
});

test('the fix is outside every range the advisory gives, not only the one for this release line', () => {
  // listed once per line: <=1.8.3 and >=2.0.0 <2.1.3; 2.0.0 is still vulnerable, so it is not the fix for 1.5.0
  assert.deepEqual(fixBoundary(['1.5.0', '2.0.0', '2.1.3'], '1.5.0', '<=1.8.3 || >=2.0.0 <2.1.3'), { vulnerable: '2.0.0', fixed: '2.1.3' });
});

test('a derived rule names every changed file, ignores a version constant, and refuses a dependency fix', () => {
  // runtime code in a folder named like documentation (yaml's dist/doc): named when it changed
  const installedFiles = new Map([['package.json', toBytes('{"version":"1.0.0"}')], ['dist/index.js', toBytes('a')], ['dist/doc/Document.js', toBytes('bad')]]);
  const fixedFiles = new Map([['package.json', toBytes('{"version":"1.0.1"}')], ['dist/index.js', toBytes('A')], ['dist/doc/Document.js', toBytes('good')]]);

  assert.deepEqual(diffForRule({ installedFiles, fixedFiles }).files, ['dist/doc/Document.js', 'dist/index.js']);

  // a file that differs only in the version written into it did not change
  const withConstant = (version, extra) => new Map([['lib/env/data.js', toBytes(`module.exports = { VERSION: "${version}" };`)], ['lib/a.js', toBytes(extra)]]);

  assert.deepEqual(diffForRule({ installedFiles: withConstant('1.0.0', 'old'), fixedFiles: withConstant('1.0.1', 'new'), versions: { installed: '1.0.0', fixed: '1.0.1' } }).files, ['lib/a.js']);
  assert.match(diffForRule({ installedFiles: withConstant('1.0.0', 'same'), fixedFiles: withConstant('1.0.1', 'same'), versions: { installed: '1.0.0', fixed: '1.0.1' } }).reason, /no runtime JavaScript/);

  // a fix that moved to a patched dependency may have changed nothing here that matters
  const deps = (range, code) => new Map([['package.json', toBytes(JSON.stringify({ dependencies: { follow: range } }))], ['index.js', toBytes(code)]]);

  assert.match(diffForRule({ installedFiles: deps('^1.0.0', 'a'), fixedFiles: deps('^1.15.6', 'b') }).reason, /changed the package's dependencies/);
});

test('rules from a --rules file keep the full-build guards, and a rule must name its files', () => {
  const extra = { packages: { 'chart-kit': { monoliths: ['dist/chart-kit.min.js'], monolithDirs: ['umd/'], advisories: {
    'GHSA-aaaa-bbbb-cccc': { id: 'GHSA-aaaa-bbbb-cccc', files: ['lib/tooltip.js'], affects: 'tooltip XSS' },
  } } } };

  const merged = mergeRules(shipped, validateRules(extra));

  assert.deepEqual(merged.packages['chart-kit'].monoliths, ['dist/chart-kit.min.js']);
  assert.deepEqual(merged.packages['chart-kit'].monolithDirs, ['umd/']);

  const moduleMap = readModuleMap({ inputs: {}, outputs: { 'dist/a.js': { inputs: { 'node_modules/chart-kit/dist/chart-kit.min.js': { bytesInOutput: 9 } } } } });

  const result = evaluateModuleRule({ key: 'npm/chart-kit', parsed: { type: 'npm', name: 'chart-kit', version: '2.0.0' }, id: 'GHSA-aaaa-bbbb-cccc', bundleVersions: new Set(['2.0.0']), moduleMap, rules: merged });

  assert.equal(result.ok, false);
  assert.match(result.reason, /full build \(dist\/chart-kit\.min\.js\) is bundled/);
  // the shipped lodash guards survive a file that adds lodash rules
  assert.ok(mergeRules(shipped, { packages: { lodash: { advisories: {} } } }).packages.lodash.monoliths.includes('lodash.js'));

  assert.throws(() => validateRules({ packages: { x: { advisories: { A: { files: [] } } } } }, 'my-rules.json'), /my-rules\.json: the rule x A must list the files/);
  assert.throws(() => validateRules({ packages: { x: { advisories: { A: {} } } } }), /must list the files/);
  assert.throws(() => validateRules({ packages: { x: { monoliths: 'a.js', advisories: {} } } }), /x\.monoliths must be a list/);
  assert.throws(() => validateRules([]), /no "packages"/);
});

test("lodash's full build keeps every lodash finding open (a real webpack build that ships lodash.js)", () => {
  // test/fixtures/webpack-monolith.stats.json: the build imports all of lodash
  const lockfileSbom = fixture('webpack.bom.lockfile.json');

  const results = triage({
    lockfileSbom, bundleSbom: fixture('webpack-pertrim.bom.bundle.json'), findings: fromNpmAudit(fixture('webpack.audit.json'), lockfileSbom),
    moduleMap: readModuleMap(fixture('webpack-monolith.stats.json')), rules: shipped, moduleCheck: evaluateModuleRule, pro: true,
  });

  const lodash = results.filter((result) => result.key === 'npm/lodash');
  assert.ok(lodash.length >= 5);
  for (const result of lodash) {
    assert.equal(result.state, 'in_triage', result.id);
    assert.match(result.moduleReason, /full build \(lodash\.js\) is bundled/, result.id);
  }
});

test('a lodash/fp file in the build is a full build too (monolithDirs)', () => {
  const moduleMap = readModuleMap({ inputs: {}, outputs: { 'dist/a.js': { inputs: { 'node_modules/lodash/fp/map.js': { bytesInOutput: 9 } } } } });
  // every lodash advisory with a rule, so the check does not hang on the order of the rules file
  const advisories = Object.entries(shipped.packages.lodash.advisories);
  assert.ok(advisories.length >= 2);

  for (const [id, rule] of advisories) {
    const version = rule.versions?.[0] ?? '4.17.20';
    const parsed = { type: 'npm', name: 'lodash', version };

    const result = evaluateModuleRule({ key: 'npm/lodash', parsed, id: rule.id ?? id, bundleVersions: new Set([version]), moduleMap, rules: shipped });

    assert.equal(result.ok, false, id);
    assert.match(result.reason, /full build \(fp\/map\.js\) is bundled/, id);
  }
});

test('rules derive diffs against the release that fixes every line of the advisory', async (testContext) => {
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import('node:fs');
  const { execFileSync } = await import('node:child_process');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { createHash } = await import('node:crypto');
  const { deriveRules } = await import('../src/derive.js');
  const tarballOf = (files) => {
    const dir = mkdtempSync(join(tmpdir(), 'vxp-pkg-'));
    testContext.after(() => rmSync(dir, { recursive: true, force: true }));
    for (const [filePath, content] of Object.entries(files)) {
      mkdirSync(join(dir, 'package', filePath, '..'), { recursive: true });
      writeFileSync(join(dir, 'package', filePath), content);
    }

    return execFileSync('tar', ['-czf', '-', '-C', dir, 'package']);
  };
  // 2.0.0 changed index.js and is still vulnerable on its own line; the fix of parse.js is in 2.1.3
  const tarballs = {
    '1.5.0': tarballOf({ 'index.js': 'one', 'lib/parse.js': 'bad' }),
    '2.0.0': tarballOf({ 'index.js': 'two', 'lib/parse.js': 'bad' }),
    '2.1.3': tarballOf({ 'index.js': 'two', 'lib/parse.js': 'good' }),
  };
  const okResponse = (body) => ({ ok: true, status: 200, json: async () => body, arrayBuffer: async () => body });
  const fetchImpl = async (url) => {
    if (url.endsWith('/advisories/bulk')) {
      return okResponse({ demo: [
        { url: 'https://github.com/advisories/GHSA-line-line-line', title: 'parse bug', vulnerable_versions: '<=1.8.3' },
        { url: 'https://github.com/advisories/GHSA-line-line-line', title: 'parse bug', vulnerable_versions: '>=2.0.0 <2.1.3' },
      ] });
    }
    if (url.endsWith('/demo')) {
      return okResponse({ versions: Object.fromEntries(Object.entries(tarballs).map(([version, tarball]) => [version, { dist: { integrity: `sha512-${createHash('sha512').update(tarball).digest('base64')}` } }])) });
    }
    const version = /demo-(.+)\.tgz$/.exec(url)?.[1];

    return version ? okResponse(tarballs[version]) : { ok: false, status: 404 };
  };

  const { rules } = await deriveRules([{ name: 'demo', version: '1.5.0', id: 'GHSA-line-line-line' }], { fetchImpl });

  const rule = rules.packages.demo.advisories['GHSA-line-line-line@1.5.0'];
  assert.deepEqual(rule.derivedFrom, { installed: '1.5.0', fixed: '2.1.3' });
  assert.ok(rule.files.includes('lib/parse.js'));
});
