// SPDX-License-Identifier: MIT
// Interop: scanner inputs, OpenVEX output, and CycloneDX VEX that Trivy can apply.
// Fixtures: trivy-upstream-npm.golden.json is Trivy's own integration golden file;
// recharts.* come from a real esbuild build of an app that imports recharts 2.15.4 (lodash 4.17.21)
// and never imports lodash itself. recharts.trivy/grype.json follow each scanner's JSON schema.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { triage, toCycloneDxVex, normalizeFindings, bomLinks, goQueryEscape } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { readFindings, fromGrype, fromSnyk, enrichAliases, fromNpmAudit } from '../src/sources.js';
import { toOpenVex } from '../src/openvex.js';
import { readModuleMap } from '../src/modules.js';
import { readBaseline, applyBaseline } from '../src/pro/baseline.js';
import { recordReview } from '../src/review.js';

const require = createRequire(import.meta.url);
const fixture = (fileName) => JSON.parse(readFileSync(new URL(`./fixtures/${fileName}`, import.meta.url)));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const APP = 'pkg:npm/chart-dashboard@1.0.0';
const demo = {
  lockfileSbom: fixture('recharts.bom.lockfile.json'),
  bundleSbom: fixture('recharts.bom.bundle.json'),
  moduleMap: readModuleMap(fixture('recharts.metafile.json')),
  rules,
  moduleCheck: evaluateModuleRule,
  pro: true,
};

// ---------- scanner inputs ----------

test("Trivy's own npm golden file parses", () => {
  const parsed = readFindings(fixture('trivy-upstream-npm.golden.json'));

  assert.equal(parsed.format, 'trivy');
  assert.deepEqual(parsed.findings, [{ purl: 'pkg:npm/jquery@3.3.9', id: 'CVE-2019-11358', aliases: [] }]);
});

test('Grype JSON: GHSA id with CVE from relatedVulnerabilities', () => {
  const findings = fromGrype(fixture('recharts.grype.json'));

  assert.equal(findings.length, 3);
  assert.deepEqual(findings[0], { purl: 'pkg:npm/lodash@4.17.21', id: 'GHSA-r5fr-rjxr-66jc', aliases: ['CVE-2026-4800'] });
});

test('Snyk JSON: one finding per issue per package, GHSA preferred, Snyk id kept as alias', () => {
  const snyk = { packageManager: 'npm', projectName: 'x', dependencyCount: 3, vulnerabilities: [
    { id: 'SNYK-JS-EXAMPLE-1', packageName: 'lodash', version: '4.17.21', from: ['x', 'recharts', 'lodash'], identifiers: { CVE: ['CVE-2026-2950'], GHSA: ['GHSA-f23m-r3pf-42rh'] } },
    { id: 'SNYK-JS-EXAMPLE-1', packageName: 'lodash', version: '4.17.21', from: ['x', 'other', 'lodash'], identifiers: { CVE: ['CVE-2026-2950'], GHSA: ['GHSA-f23m-r3pf-42rh'] } },
    { id: 'SNYK-JS-EXAMPLE-2', packageName: '@scope/pkg', version: '1.0.0', identifiers: { CVE: ['CVE-2099-0001'] } },
  ] };

  const parsed = readFindings(snyk);

  assert.equal(parsed.format, 'snyk');
  assert.deepEqual(parsed.findings, [
    { purl: 'pkg:npm/lodash@4.17.21', id: 'GHSA-f23m-r3pf-42rh', aliases: ['CVE-2026-2950', 'SNYK-JS-EXAMPLE-1'] },
    { purl: 'pkg:npm/%40scope/pkg@1.0.0', id: 'CVE-2099-0001', aliases: ['SNYK-JS-EXAMPLE-2'] },
  ]);

  assert.equal(fromSnyk([{ packageManager: 'pip', vulnerabilities: [{ id: 'x', packageName: 'y', version: '1' }] }]).length, 0);
});

test('findings for one package that name the same advisory two ways are merged', () => {
  const findings = normalizeFindings([
    { purl: 'pkg:npm/a@1', id: 'GHSA-aaaa', aliases: ['CVE-1'] },
    { purl: 'pkg:npm/a@1', id: 'CVE-1', aliases: [] },
    { purl: 'pkg:npm/b@1', id: 'CVE-1', aliases: [] },
  ]);

  // a@1's two entries are one advisory; b@1's is the same advisory on another package, kept apart
  assert.deepEqual(findings, [
    { purl: 'pkg:npm/a@1', id: 'GHSA-aaaa', aliases: ['CVE-1'] },
    { purl: 'pkg:npm/b@1', id: 'CVE-1', aliases: [] },
  ]);
});

test('OSV alias enrichment adds aliases and survives being offline', async () => {
  const findings = normalizeFindings([{ purl: 'pkg:npm/lodash@4.17.21', ids: ['GHSA-f23m-r3pf-42rh'] }]);

  const osvReply = async () => ({ ok: true, json: async () => ({ aliases: ['CVE-2026-2950'] }) });

  const online = await enrichAliases(findings, { fetchImpl: osvReply });

  assert.equal(online.added, 1);
  assert.deepEqual(findings[0].aliases, ['CVE-2026-2950']);

  const offlineFindings = normalizeFindings([{ purl: 'pkg:npm/x@1', ids: ['GHSA-x'] }]);
  const failingFetch = async () => {
    throw new Error('offline');
  };

  const offline = await enrichAliases(offlineFindings, { fetchImpl: failingFetch, sleep: async () => {} });

  assert.equal(offline.resolved, 0);
  assert.deepEqual(offlineFindings[0].aliases, []);
});

// ---------- the transitive case ----------

test('recharts app: lodash ships though the app never imports it; the omit/unset advisories stay open', () => {
  const mainSource = readFileSync(new URL('../demo/src/main.jsx', import.meta.url), 'utf8');

  assert.doesNotMatch(mainSource, /lodash/);

  const lodash = demo.moduleMap.packages.get('lodash');

  assert.ok(lodash.files.has('omit.js') && lodash.files.has('_baseUnset.js') && !lodash.files.has('template.js'));

  for (const input of ['recharts.trivy.json', 'recharts.grype.json']) {
    const results = triage({ ...demo, findings: readFindings(fixture(input)).findings });

    const byRule = (ghsaId, cveId) => results.find((result) => result.id === ghsaId || result.id === cveId);
    assert.equal(byRule('GHSA-r5fr-rjxr-66jc', 'CVE-2026-4800').state, 'not_affected', input);
    for (const [ghsaId, cveId] of [['GHSA-f23m-r3pf-42rh', 'CVE-2026-2950'], ['GHSA-xxjr-mmjv-4gpg', 'CVE-2025-13465']]) {
      const result = byRule(ghsaId, cveId);
      assert.equal(result.state, 'in_triage', input);
      assert.match(result.moduleReason, /_baseUnset\.js, omit\.js/);
      assert.ok([result.id, ...result.aliases].includes(ghsaId) && [result.id, ...result.aliases].includes(cveId), 'rule aliases attached');
    }
  }
});

// ---------- CycloneDX VEX that Trivy applies ----------

test('BOM-Link fragment is escaped exactly like Go url.QueryEscape', () => {
  assert.equal(goQueryEscape('chart-dashboard@1.0.0|lodash@4.17.21'), 'chart-dashboard%401.0.0%7Clodash%404.17.21');
  assert.equal(goQueryEscape("a b!'()*~._-"), "a+b%21%27%28%29%2A~._-");
});

test('CycloneDX VEX: affects are BOM-Links into the lockfile SBOM, with a CVE-keyed entry for Trivy', () => {
  const results = triage({ ...demo, findings: fromNpmAudit(fixture('recharts.audit.json'), demo.lockfileSbom) });

  const vex = toCycloneDxVex({ results, lockfileSbom: demo.lockfileSbom, bundleSbom: demo.bundleSbom, productPurl: APP });

  const serial = demo.lockfileSbom.serialNumber.replace('urn:uuid:', '');
  const lodashRef = demo.lockfileSbom.components.find((component) => component.purl === 'pkg:npm/lodash@4.17.21')['bom-ref'];
  assert.deepEqual(bomLinks(demo.lockfileSbom, 'pkg:npm/lodash@4.17.21'), [`urn:cdx:${serial}/1#${goQueryEscape(lodashRef)}`]);
  for (const vulnerability of vex.vulnerabilities) {
    assert.match(vulnerability.affects[0].ref, new RegExp(`^urn:cdx:${serial}/1#`));
  }

  const ids = vex.vulnerabilities.map((vulnerability) => vulnerability.id);
  for (const id of ['GHSA-r5fr-rjxr-66jc', 'CVE-2026-4800', 'GHSA-f23m-r3pf-42rh', 'CVE-2026-2950']) {
    assert.ok(ids.includes(id), id);
  }

  const alias = vex.vulnerabilities.find((vulnerability) => vulnerability.id === 'CVE-2026-4800');
  assert.equal(alias.analysis.state, 'not_affected');
  assert.ok(alias.properties.some((property) => property.name === 'vexproof:alias-of' && property.value === 'GHSA-r5fr-rjxr-66jc'));

  // an alias entry is a copy: changing the primary entry in memory leaves it as it was
  const primary = vex.vulnerabilities.find((vulnerability) => vulnerability.id === 'GHSA-r5fr-rjxr-66jc');
  primary.analysis.detail = 'changed';
  primary.affects.push({ ref: 'another' });
  primary.properties.push({ name: 'vexproof:other', value: 'x' });
  assert.notEqual(alias.analysis.detail, 'changed');
  assert.ok(!alias.affects.some((affected) => affected.ref === 'another'));
  assert.ok(!alias.properties.some((property) => property.name === 'vexproof:other'));
});

test('CycloneDX VEX validates against the CycloneDX 1.6 schema', async () => {
  const { Validation, Spec } = require('@cyclonedx/cyclonedx-library');
  const results = triage({ ...demo, findings: readFindings(fixture('recharts.trivy.json')).findings });
  const vex = toCycloneDxVex({ results, lockfileSbom: demo.lockfileSbom, bundleSbom: demo.bundleSbom, productPurl: APP });

  const validationError = await new Validation.JsonStrictValidator(Spec.Version.v1dot6).validate(JSON.stringify(vex));

  assert.equal(validationError, null, JSON.stringify(validationError));
});

test('CycloneDX VEX can be written as 1.7 and validates against the 1.7 schema; other versions are refused', async () => {
  const { Validation, Spec } = require('@cyclonedx/cyclonedx-library');
  const results = triage({ ...demo, findings: fromNpmAudit(fixture('recharts.audit.json'), demo.lockfileSbom) });

  const vex = toCycloneDxVex({
    results, lockfileSbom: demo.lockfileSbom, bundleSbom: demo.bundleSbom, productPurl: APP, specVersion: '1.7',
  });

  assert.equal(vex.specVersion, '1.7');

  const validationError = await new Validation.JsonStrictValidator(Spec.Version.v1dot7).validate(JSON.stringify(vex));

  assert.equal(validationError, null, JSON.stringify(validationError));

  assert.throws(() => toCycloneDxVex({ results, lockfileSbom: demo.lockfileSbom, productPurl: APP, specVersion: '1.5' }), /not supported/);
});

test('baseline and review follow an advisory across id schemes (npm audit GHSA → Trivy CVE)', () => {
  const npmAuditResults = triage({ ...demo, findings: fromNpmAudit(fixture('recharts.audit.json'), demo.lockfileSbom) });
  const reviewedVex = toCycloneDxVex({ results: npmAuditResults, lockfileSbom: demo.lockfileSbom, productPurl: APP });
  recordReview(reviewedVex, {
    id: 'GHSA-f23m-r3pf-42rh',
    state: 'not_affected',
    justification: 'code_not_reachable',
    detail: 'Treemap never receives user-controlled paths',
    by: 'Jane Doe',
  });

  const trivyResults = triage({ ...demo, findings: readFindings(fixture('recharts.trivy.json')).findings });

  const results = applyBaseline(trivyResults, readBaseline(reviewedVex));

  const reviewed = results.find((result) => result.id === 'CVE-2026-2950');
  assert.equal(reviewed.origin, 'reviewed');
  assert.equal(reviewed.reviewedBy, 'Jane Doe');
  assert.equal(results.filter((result) => result.isNew).length, 0);
});

// ---------- OpenVEX ----------

function openVexValidator() {
  const Ajv2020 = require('ajv/dist/2020').default;
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  require('ajv-formats').default(ajv);
  ajv.addFormat('iri', /^[a-z][a-z0-9+.-]*:\S+$/i);
  return ajv.compile(JSON.parse(readFileSync(new URL('./schemas/openvex-0.2.0.schema.json', import.meta.url))));
}

test('OpenVEX validates against the official v0.2.0 schema and maps verdicts', () => {
  const results = triage({ ...demo, findings: readFindings(fixture('recharts.grype.json')).findings });

  const doc = toOpenVex({ results, productPurl: APP });

  const validate = openVexValidator();
  assert.ok(validate(doc), JSON.stringify(validate.errors));
  const byName = Object.fromEntries(doc.statements.map((statement) => [statement.vulnerability.name, statement]));
  assert.equal(byName['GHSA-r5fr-rjxr-66jc'].status, 'not_affected');
  assert.equal(byName['GHSA-r5fr-rjxr-66jc'].justification, 'vulnerable_code_not_present');
  assert.deepEqual(byName['GHSA-r5fr-rjxr-66jc'].vulnerability.aliases, ['CVE-2026-4800']);
  assert.equal(byName['GHSA-f23m-r3pf-42rh'].status, 'under_investigation');
  assert.deepEqual(byName['GHSA-f23m-r3pf-42rh'].products, [{ '@id': APP, subcomponents: [{ '@id': 'pkg:npm/lodash@4.17.21' }] }]);
});

test('OpenVEX: package-level absence maps to component_not_present; Grype form is opt-in', () => {
  const angularLock = fixture('angular.bom.lockfile.json');
  const findings = fromNpmAudit(fixture('angular.audit.json'), angularLock);
  const results = triage({ lockfileSbom: angularLock, bundleSbom: fixture('angular-capitalize.bom.bundle.json'), findings, rules });

  const plain = toOpenVex({ results, productPurl: 'pkg:npm/ngapp@0.0.0' });

  const moment = plain.statements.find((statement) => statement.products[0].subcomponents[0]['@id'].includes('moment'));
  assert.equal(moment.justification, 'component_not_present');
  assert.ok(plain.statements.every((statement) => statement.products.length === 1));

  const grype = toOpenVex({ results, productPurl: 'pkg:npm/ngapp@0.0.0', packageProducts: true });

  assert.ok(grype.statements.every((statement) => statement.products.length === 2
    && statement.products[1]['@id'] === statement.products[0].subcomponents[0]['@id']));
  const validate = openVexValidator();
  assert.ok(validate(grype), JSON.stringify(validate.errors));
});

// ---------- Rspack: module map only, no bundle SBOM plugin (the CycloneDX webpack plugin fails on Rspack) ----------

test('Rspack (VexproofPlugin stats): bundle contents come from the module map and verdicts match the esbuild build', async () => {
  const { bundleSbomFromModules } = await import('../src/modules.js');

  const moduleMap = readModuleMap(fixture('recharts.rspack-plugin.json'));

  assert.match(moduleMap.format, /^webpack-stats \(rspack /);
  const lodash = moduleMap.packages.get('lodash');
  assert.equal(lodash.files.size, demo.moduleMap.packages.get('lodash').files.size);

  // no node_modules here: versions fall back to the lockfile SBOM, which lists one lodash
  const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom: demo.lockfileSbom, cwd: '/nonexistent' });

  assert.ok(bundleSbom.components.some((component) => component.purl === 'pkg:npm/lodash@4.17.21'));

  const results = triage({ ...demo, bundleSbom, moduleMap, findings: fromNpmAudit(fixture('recharts.audit.json'), demo.lockfileSbom) });

  const states = Object.fromEntries(results.map((result) => [result.id, result.state]));
  assert.deepEqual(states, { 'GHSA-r5fr-rjxr-66jc': 'not_affected', 'GHSA-f23m-r3pf-42rh': 'in_triage', 'GHSA-xxjr-mmjv-4gpg': 'in_triage' });
});

test('module-map bundle claims no version it cannot read', async () => {
  const { bundleSbomFromModules } = await import('../src/modules.js');
  const moduleMap = {
    format: 'webpack-stats',
    packages: new Map([['left-pad', { roots: new Set(['node_modules/left-pad']), files: new Set(['index.js']) }]]),
  };
  const lockfileSbom = { components: [{ purl: 'pkg:npm/left-pad@1.0.0' }, { purl: 'pkg:npm/left-pad@1.3.0' }] };

  const bundle = bundleSbomFromModules(moduleMap, { lockfileSbom, cwd: '/nonexistent' });

  assert.equal(bundle.components[0].purl, 'pkg:npm/left-pad');
});

test('pnpm audit JSON (Gitea, real): GHSA ids with CVE aliases and a version per finding', () => {
  const parsed = readFindings(fixture('gitea.pnpm-audit.json'));

  assert.equal(parsed.format, 'pnpm-audit');
  assert.equal(parsed.findings.length, 8);
  assert.ok(parsed.findings.every((finding) => /^GHSA-/.test(finding.id) && /^pkg:npm\/.+@\d/.test(finding.purl)));
  assert.ok(parsed.findings.some((finding) => finding.purl === 'pkg:npm/lodash-es@4.17.23' && finding.id === 'GHSA-r5fr-rjxr-66jc'));
});
