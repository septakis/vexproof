// SPDX-License-Identifier: MIT
// How the lockfile and bundle SBOMs are read: ways a shipped package could look absent, found by the code audit
// of 1.0.0-beta.9. Each one gave not_affected for a package that ships.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { triage, indexSbom, packageKey, parsePurl, NpmNameSet } from '../src/index.js';

const bom = (components) => ({ bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:11111111-1111-4111-8111-111111111111', components });
const lib = (purl, extra = {}) => ({ type: 'library', purl, ...extra });
const verdicts = (lockfileSbom, bundleSbom, findings) => Object.fromEntries(triage({ lockfileSbom, bundleSbom, findings }).map((r) => [r.id, r.state]));

test('npm names are compared without regard to case: cyclonedx-npm lower-cases them, bundlers do not', () => {
  // what cyclonedx-npm 7 writes for JSONStream, and what a bundle SBOM built from the module map says
  const lock = bom([lib('pkg:npm/jsonstream@1.3.5', { name: 'JSONStream' }), lib('pkg:npm/react@18.3.1')]);
  const bundle = bom([lib('pkg:npm/JSONStream@1.3.5'), lib('pkg:npm/react@18.3.1')]);
  const v = verdicts(lock, bundle, [{ purl: 'pkg:npm/jsonstream@1.3.5', ids: ['GHSA-case-0001'] }]);
  assert.equal(v['GHSA-case-0001'], 'in_triage');
  assert.equal(packageKey('pkg:npm/JSONStream@1.3.5'), 'npm/jsonstream');
  assert.equal(packageKey('pkg:npm/%40Scope/Name@1'), 'npm/@scope/name');
  // other ecosystems keep their names as written
  assert.equal(packageKey('pkg:maven/org.Acme/Lib@1'), 'maven/org.Acme/Lib');
  const names = new NpmNameSet(['JSONStream']);
  assert.ok(names.has('jsonstream') && names.has('JSONStream'));
});

test('a bundle component listed by name and version, without a purl, counts as shipped', () => {
  const lock = bom([lib('pkg:npm/lodash@4.17.21'), lib('pkg:npm/react@18.3.1'), lib('pkg:npm/%40scope/ui@1.0.0')]);
  const bundle = bom([
    { type: 'library', name: 'lodash', version: '4.17.21' },
    { type: 'library', group: '@scope', name: 'ui', version: '1.0.0' },
    lib('pkg:npm/react@18.3.1'),
  ]);
  const v = verdicts(lock, bundle, [
    { purl: 'pkg:npm/lodash@4.17.21', ids: ['GHSA-nopurl-0001'] },
    { purl: 'pkg:npm/%40scope/ui@1.0.0', ids: ['GHSA-nopurl-0002'] },
  ]);
  assert.equal(v['GHSA-nopurl-0001'], 'in_triage');
  assert.equal(v['GHSA-nopurl-0002'], 'in_triage');
  // only on the side where an extra package can keep findings open: the lockfile is read by purl alone
  assert.equal(indexSbom(bom([{ type: 'library', name: 'x', version: '1' }])).size, 0);
  assert.deepEqual([...indexSbom(bom([{ type: 'library', name: 'x', version: '1' }]), { withoutPurl: true }).keys()], ['npm/x']);
});

test('a bundle SBOM that shares no npm package with the lockfile settles nothing', () => {
  const lock = bom([lib('pkg:npm/lodash@4.17.21'), lib('pkg:npm/react@18.3.1')]);
  const findings = [{ purl: 'pkg:npm/lodash@4.17.21', ids: ['GHSA-empty-0001'] }];
  for (const bundle of [
    bom([]), // empty
    bom([{ type: 'application', name: 'app', purl: 'pkg:generic/app@1.0.0' }]), // only the app itself
    bom([lib('pkg:npm/left-pad@1.3.0')]), // another project's bundle
  ]) {
    const [r] = triage({ lockfileSbom: lock, bundleSbom: bundle, findings });
    assert.equal(r.state, 'in_triage');
    assert.match(r.detail, /names none of the npm packages in the lockfile SBOM/);
  }
  assert.equal(verdicts(lock, bom([lib('pkg:npm/react@18.3.1')]), findings)['GHSA-empty-0001'], 'not_affected');
});

test('a purl with a broken %-escape is left open, not fatal', () => {
  assert.equal(parsePurl('pkg:npm/foo%zz@1.0.0'), null);
  const lock = bom([lib('pkg:npm/react@18.3.1')]);
  const [r] = triage({ lockfileSbom: lock, bundleSbom: lock, findings: [{ purl: 'pkg:npm/foo%zz@1.0.0', ids: ['GHSA-bad-0001'] }] });
  assert.equal(r.state, 'in_triage');
  assert.match(r.detail, /Could not parse purl/);
});
