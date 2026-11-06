// SPDX-License-Identifier: MIT
// Two shipped copies of one package (common with pnpm): findings are checked against the matching copy only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readModuleMap, attachVersions, versionFromPnpmPath, bundleSbomFromModules } from '../src/modules.js';
import { triage } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { readFindings } from '../src/sources.js';

const fx = (f) => JSON.parse(readFileSync(new URL(`./fixtures/${f}`, import.meta.url)));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));

test('pnpm store paths give the copy version, for scoped names and peer suffixes too', () => {
  assert.equal(versionFromPnpmPath('node_modules/.pnpm/lodash-es@4.17.23/node_modules/lodash-es', 'lodash-es'), '4.17.23');
  assert.equal(versionFromPnpmPath('node_modules/.pnpm/@vue+shared@3.5.0/node_modules/@vue/shared', '@vue/shared'), '3.5.0');
  assert.equal(versionFromPnpmPath('node_modules/.pnpm/react-dom@18.3.1_react@18.3.1/node_modules/react-dom', 'react-dom'), '18.3.1');
  assert.equal(versionFromPnpmPath('node_modules/.pnpm/pkg@2.0.0(react@18.3.1)/node_modules/pkg', 'pkg'), '2.0.0');
  assert.equal(versionFromPnpmPath('node_modules/.pnpm/other@1.0.0/node_modules/lodash-es', 'lodash-es'), undefined);
  assert.equal(versionFromPnpmPath('node_modules/lodash-es', 'lodash-es'), undefined);
});

test('Gitea (real, Vite 8 + pnpm): lodash-es ships at 4.17.23 and 4.18.1; the 4.17.23 advisories settle on that copy', () => {
  const lock = fx('gitea.lodash-es.bom.lockfile.json');
  const moduleMap = attachVersions(readModuleMap(fx('gitea.lodash-es.modules.json')), { cwd: '/nonexistent' });
  const entry = moduleMap.packages.get('lodash-es');
  assert.deepEqual([...entry.versionByRoot.values()].sort(), ['4.17.23', '4.18.1']);
  const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom: lock, cwd: '/nonexistent' });
  const findings = readFindings(fx('gitea.pnpm-audit.json')).findings.filter((f) => f.purl.startsWith('pkg:npm/lodash-es@'));
  const rs = triage({ lockfileSbom: lock, bundleSbom, moduleMap, rules, moduleCheck: evaluateModuleRule, pro: true, findings });
  assert.equal(rs.length, 2);
  for (const r of rs) {
    assert.equal(r.state, 'not_affected', r.id);
    assert.equal(r.level, 'module');
    assert.deepEqual(r.evidence.copies, ['node_modules/.pnpm/lodash-es@4.17.23/node_modules/lodash-es']);
    assert.match(r.detail, /counting only the 4\.17\.23 copy; 1 other copy is a different version/);
  }
});

// synthetic: two copies with controlled file sets
const two = (filesOld, filesNew, versions = ['4.17.20', '4.18.1']) => {
  const roots = versions.map((v) => `node_modules/.pnpm/lodash-es@${v}/node_modules/lodash-es`);
  const byRoot = new Map([[roots[0], new Set(filesOld)], [roots[1], new Set(filesNew)]]);
  const mm = { format: 'test', packages: new Map([['lodash-es', { roots: new Set(roots), files: new Set([...filesOld, ...filesNew]), byRoot }]]) };
  return attachVersions(mm, { cwd: '/nonexistent' });
};
const args = (moduleMap, bundleVersions = ['4.17.20', '4.18.1']) => ({ key: 'npm/lodash-es', parsed: { type: 'npm', name: 'lodash-es', version: '4.17.20' }, id: 'GHSA-35jh-r3h4-6jhm', bundleVersions: new Set(bundleVersions), moduleMap, rules });

test('a vulnerable file in the other (fixed) copy does not block the verdict', () => {
  const r = evaluateModuleRule(args(two(['capitalize.js'], ['capitalize.js', 'template.js'])));
  assert.equal(r.ok, true);
});

test('a vulnerable file in the vulnerable copy blocks it, whatever the other copy ships', () => {
  const r = evaluateModuleRule(args(two(['capitalize.js', 'template.js'], ['capitalize.js'])));
  assert.equal(r.ok, false);
  assert.match(r.reason, /template\.js/);
});

test('an unreadable copy version means no claim', () => {
  const mm = two(['capitalize.js'], ['capitalize.js']);
  mm.packages.get('lodash-es').versionByRoot.set([...mm.packages.get('lodash-es').roots][1], undefined);
  assert.match(evaluateModuleRule(args(mm)).reason, /version of 1 is unknown/);
});

test('no shipped copy at the finding version contradicts the bundle SBOM: no claim', () => {
  assert.match(evaluateModuleRule(args(two(['a.js'], ['a.js'], ['4.17.21', '4.18.1']))).reason, /no shipped copy of lodash-es is version 4\.17\.20/);
});

test('single copy whose installed version disagrees with the finding: no claim', () => {
  const root = 'node_modules/lodash-es';
  const mm = { format: 'test', packages: new Map([['lodash-es', { roots: new Set([root]), files: new Set(['capitalize.js']), byRoot: new Map([[root, new Set(['capitalize.js'])]]), versionByRoot: new Map([[root, '4.18.1']]) }]]) };
  assert.match(evaluateModuleRule(args(mm, ['4.17.20'])).reason, /shipped copy of lodash-es is 4\.18\.1/);
});

test('npm nested installs: versions come from each copy\'s package.json on disk', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'vxp-'));
  const put = (dir, version) => { mkdirSync(join(cwd, dir), { recursive: true }); writeFileSync(join(cwd, dir, 'package.json'), JSON.stringify({ name: 'lodash-es', version })); };
  put('node_modules/lodash-es', '4.18.1');
  put('node_modules/some-lib/node_modules/lodash-es', '4.17.20');
  const meta = { inputs: {}, outputs: { 'app.js': { inputs: {
    'node_modules/lodash-es/capitalize.js': { bytesInOutput: 5 },
    'node_modules/lodash-es/template.js': { bytesInOutput: 5 },
    'node_modules/some-lib/node_modules/lodash-es/toPath.js': { bytesInOutput: 5 },
  } } } };
  const mm = attachVersions(readModuleMap(meta), { cwd });
  const r = evaluateModuleRule({ ...args(mm), moduleMap: mm });
  assert.equal(r.ok, true, r.reason); // template.js ships, but only from the fixed 4.18.1 copy
  assert.deepEqual(r.evidence.copies, ['node_modules/some-lib/node_modules/lodash-es']);
});
