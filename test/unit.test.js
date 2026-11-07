// SPDX-License-Identifier: MIT
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePurl, triage, toCycloneDxVex, normalizeFindings } from '../src/index.js';

const sbom = (purls) => ({
  bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:test',
  components: purls.map((purl) => ({ type: 'library', purl })),
});

const lockfile = sbom([
  'pkg:npm/react@18.3.1',
  'pkg:npm/lodash@4.17.20',
  'pkg:npm/%40babel/core@7.24.0',
  'pkg:npm/express@4.17.1',
]);
const bundle = sbom(['pkg:npm/react@18.3.1', 'pkg:npm/express@4.16.0']);

const findings = [
  { purl: 'pkg:npm/lodash@4.17.20', ids: ['GHSA-lodash-1'] },          // absent from bundle
  { purl: 'pkg:npm/react@18.3.1', ids: ['GHSA-react-1'] },             // present in bundle
  { purl: 'pkg:npm/express@4.17.1', ids: ['GHSA-express-1'] },         // present, different version
  { purl: 'pkg:npm/%40babel/core@7.24.0', ids: ['GHSA-babel-1'] },     // scoped, absent
  { purl: 'pkg:npm/leftpad@1.0.0', ids: ['GHSA-leftpad-1'] },          // not even in lockfile
];

test('parsePurl handles scoped npm names and qualifiers', () => {
  assert.deepEqual(parsePurl('pkg:npm/%40babel/core@7.24.0?vcs_url=x'), { type: 'npm', name: '@babel/core', version: '7.24.0' });
  assert.deepEqual(parsePurl('pkg:npm/react@18.3.1'), { type: 'npm', name: 'react', version: '18.3.1' });
  assert.equal(parsePurl('not a purl'), null);
});

test('only packages absent from the bundle become not_affected', () => {
  const byId = Object.fromEntries(triage({ lockfileSbom: lockfile, bundleSbom: bundle, findings }).map((r) => [r.id, r]));
  assert.equal(byId['GHSA-lodash-1'].state, 'not_affected');
  assert.equal(byId['GHSA-lodash-1'].justification, 'code_not_present');
  assert.equal(byId['GHSA-babel-1'].state, 'not_affected');
  assert.equal(byId['GHSA-react-1'].state, 'in_triage');
  // conservative: same package name, different version -> still in_triage
  assert.equal(byId['GHSA-express-1'].state, 'in_triage');
  // conservative: unknown to lockfile -> no claim
  assert.equal(byId['GHSA-leftpad-1'].state, 'in_triage');
  assert.equal(byId['GHSA-leftpad-1'].justification, undefined);
});

test('empty bundle SBOM makes no not_affected claims', () => {
  // an empty bundle SBOM is more likely a broken build than "we ship nothing"
  const results = triage({ lockfileSbom: lockfile, bundleSbom: sbom([]), findings });
  assert.ok(results.every((r) => r.state === 'in_triage'), 'should not claim not_affected against an empty bundle');
});

test('normalizeFindings reads osv-scanner JSON', () => {
  const osv = { results: [{ packages: [{
    package: { name: '@babel/core', version: '7.24.0', ecosystem: 'npm' },
    vulnerabilities: [{ id: 'GHSA-babel-1', aliases: ['CVE-2024-0001'] }],
  }]}]};
  assert.deepEqual(normalizeFindings(osv), [{ purl: 'pkg:npm/%40babel/core@7.24.0', id: 'GHSA-babel-1', aliases: ['CVE-2024-0001'] }]);
});

test('VEX output is well-formed CycloneDX 1.6 with justification only on not_affected', () => {
  const results = triage({ lockfileSbom: lockfile, bundleSbom: bundle, findings });
  const vex = toCycloneDxVex({ results, bundleSbom: bundle, lockfileSbom: lockfile, productPurl: 'pkg:npm/my-app@1.0.0' });
  assert.equal(vex.bomFormat, 'CycloneDX');
  assert.equal(vex.specVersion, '1.6');
  assert.equal(vex.vulnerabilities.length, findings.length);
  for (const v of vex.vulnerabilities) {
    // no valid SBOM serial in this fixture → affects falls back to the package itself (BOM-Links are tested in scanners.test.js)
    assert.equal(v.affects[0].ref, v.properties.find((p) => p.name === 'vexproof:package').value);
    if (v.analysis.state === 'not_affected') assert.equal(v.analysis.justification, 'code_not_present');
    else assert.equal(v.analysis.justification, undefined);
  }
});

test('an unrecognised module map is refused by name, with the supported formats listed', async () => {
  const { readModuleMap, detectModuleFormat } = await import('../src/modules.js');
  for (const json of [{ chunks: [] }, { version: 1, files: {} }, [], 'text', null]) {
    assert.throws(() => detectModuleFormat(json), /Unrecognised module map \(expected vexproof-modules\.json, an esbuild or bun build metafile, Angular stats\.json, or webpack stats JSON\)/);
    assert.throws(() => readModuleMap(json), /Unrecognised module map/);
  }
});
