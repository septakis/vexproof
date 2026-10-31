// SPDX-License-Identifier: MIT
// Dependency-Track's CycloneDX VEX import, modelled on CycloneDXVexImporter in its 4.14.x branch
// (src/main/java/org/dependencytrack/parser/cyclonedx/CycloneDXVexImporter.java):
//   - an entry is applied only with an id, a source name Dependency-Track knows, affects, and an analysis
//   - the vulnerability is looked up by (source, id); GHSA ids are filed under GITHUB by both its GitHub and OSV
//     mirrors (OsvDownloadTask.extractSource), CVEs under NVD
//   - an affects ref that is a BOM-Link not naming a component in the VEX itself applies to every component in
//     the project that has that finding, and the last analysis written wins
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { triage, toCycloneDxVex, vulnerabilitySource } from '../src/index.js';

const KNOWN = new Set(['NVD', 'NPM', 'GITHUB', 'VULNDB', 'OSSINDEX', 'RETIREJS', 'INTERNAL', 'OSV', 'SNYK', 'TRIVY', 'UNKNOWN']);
const sbom = (purls, serial = '22222222-2222-4222-8222-222222222222') => ({ bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: `urn:uuid:${serial}`, version: 1, components: purls.map((purl) => ({ type: 'library', purl, 'bom-ref': purl })) });

/** Dependency-Track 4.14: what each project component's analysis ends up as after the VEX upload. */
function applyLikeDependencyTrack(vex, findings) {
  // findings: [{ source, id, component }] the project already has
  const analysis = new Map();
  for (const v of vex.vulnerabilities) {
    if (!v.id || !v.source?.name || !KNOWN.has(v.source.name) || !v.affects?.length || !v.analysis) continue;
    const hits = findings.filter((f) => f.source === v.source.name && f.id === v.id);
    for (const a of v.affects) if (/^urn:cdx:/.test(a.ref)) for (const f of hits) analysis.set(`${f.id} ${f.component}`, v.analysis.state);
  }
  return analysis;
}

test('every GHSA and CVE entry names its source, so Dependency-Track 4.x does not skip it', () => {
  const lock = sbom(['pkg:npm/lodash@4.17.20', 'pkg:npm/react@18.3.1']);
  const results = triage({ lockfileSbom: lock, bundleSbom: sbom(['pkg:npm/react@18.3.1']), findings: [{ purl: 'pkg:npm/lodash@4.17.20', id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1111'] }] });
  const vex = toCycloneDxVex({ results, lockfileSbom: lock, productPurl: 'pkg:npm/app@1' });
  assert.deepEqual(vex.vulnerabilities.map((v) => [v.id, v.source?.name]), [['GHSA-aaaa-bbbb-cccc', 'GITHUB'], ['CVE-2026-1111', 'NVD']]);
  assert.equal(vulnerabilitySource('GHSA-x').url, 'https://github.com/advisories/GHSA-x');
  assert.equal(vulnerabilitySource('MAL-2026-1'), null);
  const applied = applyLikeDependencyTrack(vex, [
    { source: 'GITHUB', id: 'GHSA-aaaa-bbbb-cccc', component: 'lodash@4.17.20' },
    { source: 'NVD', id: 'CVE-2026-1111', component: 'lodash@4.17.20' },
  ]);
  assert.equal(applied.get('GHSA-aaaa-bbbb-cccc lodash@4.17.20'), 'not_affected');
  assert.equal(applied.get('CVE-2026-1111 lodash@4.17.20'), 'not_affected');
});

test('when one advisory hits a copy that ships and one that does not, Dependency-Track ends on the open verdict', () => {
  // Two copies of one package with different verdicts (a module-level check, or a review, can do this): the
  // vulnerable files ship in 4.17.15 and not in 4.17.20. Dependency-Track applies both statements to both
  // components, so the order decides, and the copy that ships must never end up suppressed.
  const lock = sbom(['pkg:npm/lodash@4.17.20', 'pkg:npm/lodash@4.17.15']);
  const results = [
    { purl: 'pkg:npm/lodash@4.17.15', id: 'GHSA-aaaa-bbbb-cccc', aliases: [], state: 'in_triage', detail: 'ships' },
    { purl: 'pkg:npm/lodash@4.17.20', id: 'GHSA-aaaa-bbbb-cccc', aliases: [], state: 'not_affected', justification: 'code_not_present', level: 'module', detail: 'files not shipped' },
  ];
  for (const order of [results, [...results].reverse()]) {
    const vex = toCycloneDxVex({ results: order, lockfileSbom: lock, productPurl: 'pkg:npm/app@1' });
    assert.deepEqual(vex.vulnerabilities.map((v) => v.analysis.state), ['not_affected', 'in_triage']);
    const applied = applyLikeDependencyTrack(vex, [
      { source: 'GITHUB', id: 'GHSA-aaaa-bbbb-cccc', component: 'lodash@4.17.15' },
      { source: 'GITHUB', id: 'GHSA-aaaa-bbbb-cccc', component: 'lodash@4.17.20' },
    ]);
    assert.equal(applied.get('GHSA-aaaa-bbbb-cccc lodash@4.17.15'), 'in_triage');
  }
});
