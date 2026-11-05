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
import { readFindings, fromTrivy, fromGrype, fromSnyk, enrichAliases, fromNpmAudit } from '../src/sources.js';
import { toOpenVex } from '../src/openvex.js';
import { readModuleMap } from '../src/modules.js';
import { readBaseline, applyBaseline } from '../src/pro/baseline.js';
import { recordReview } from '../src/review.js';

const require = createRequire(import.meta.url);
const fx = (f) => JSON.parse(readFileSync(new URL(`./fixtures/${f}`, import.meta.url)));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const APP = 'pkg:npm/chart-dashboard@1.0.0';
const demo = {
  lockfileSbom: fx('recharts.bom.lockfile.json'),
  bundleSbom: fx('recharts.bom.bundle.json'),
  moduleMap: readModuleMap(fx('recharts.metafile.json')),
  rules,
  moduleCheck: evaluateModuleRule,
  pro: true,
};

// ---------- scanner inputs ----------

test("Trivy's own npm golden file parses", () => {
  const r = readFindings(fx('trivy-upstream-npm.golden.json'));
  assert.equal(r.format, 'trivy');
  assert.deepEqual(r.findings, [{ purl: 'pkg:npm/jquery@3.3.9', id: 'CVE-2019-11358', aliases: [] }]);
});

test('Grype JSON: GHSA id with CVE from relatedVulnerabilities', () => {
  const f = fromGrype(fx('recharts.grype.json'));
  assert.equal(f.length, 3);
  assert.deepEqual(f[0], { purl: 'pkg:npm/lodash@4.17.21', id: 'GHSA-r5fr-rjxr-66jc', aliases: ['CVE-2026-4800'] });
});

test('Snyk JSON: one finding per issue per package, GHSA preferred, Snyk id kept as alias', () => {
  const snyk = { packageManager: 'npm', projectName: 'x', dependencyCount: 3, vulnerabilities: [
    { id: 'SNYK-JS-EXAMPLE-1', packageName: 'lodash', version: '4.17.21', from: ['x', 'recharts', 'lodash'], identifiers: { CVE: ['CVE-2026-2950'], GHSA: ['GHSA-f23m-r3pf-42rh'] } },
    { id: 'SNYK-JS-EXAMPLE-1', packageName: 'lodash', version: '4.17.21', from: ['x', 'other', 'lodash'], identifiers: { CVE: ['CVE-2026-2950'], GHSA: ['GHSA-f23m-r3pf-42rh'] } },
    { id: 'SNYK-JS-EXAMPLE-2', packageName: '@scope/pkg', version: '1.0.0', identifiers: { CVE: ['CVE-2099-0001'] } },
  ] };
  const r = readFindings(snyk);
  assert.equal(r.format, 'snyk');
  assert.deepEqual(r.findings, [
    { purl: 'pkg:npm/lodash@4.17.21', id: 'GHSA-f23m-r3pf-42rh', aliases: ['CVE-2026-2950', 'SNYK-JS-EXAMPLE-1'] },
    { purl: 'pkg:npm/%40scope/pkg@1.0.0', id: 'CVE-2099-0001', aliases: ['SNYK-JS-EXAMPLE-2'] },
  ]);
  assert.equal(fromSnyk([{ packageManager: 'pip', vulnerabilities: [{ id: 'x', packageName: 'y', version: '1' }] }]).length, 0);
});

test('findings for one package that name the same advisory two ways are merged', () => {
  const f = normalizeFindings([{ purl: 'pkg:npm/a@1', id: 'GHSA-aaaa', aliases: ['CVE-1'] }, { purl: 'pkg:npm/a@1', id: 'CVE-1', aliases: [] }, { purl: 'pkg:npm/b@1', id: 'CVE-1', aliases: [] }]);
  assert.equal(f.length, 2);
});

test('OSV alias enrichment adds aliases and survives being offline', async () => {
  const f = normalizeFindings([{ purl: 'pkg:npm/lodash@4.17.21', ids: ['GHSA-f23m-r3pf-42rh'] }]);
  const ok = await enrichAliases(f, { fetchImpl: async () => ({ ok: true, json: async () => ({ aliases: ['CVE-2026-2950'] }) }) });
  assert.equal(ok.added, 1);
  assert.deepEqual(f[0].aliases, ['CVE-2026-2950']);
  const g = normalizeFindings([{ purl: 'pkg:npm/x@1', ids: ['GHSA-x'] }]);
  const off = await enrichAliases(g, { fetchImpl: async () => { throw new Error('offline'); }, sleep: async () => {} });
  assert.equal(off.resolved, 0);
  assert.deepEqual(g[0].aliases, []);
});

// ---------- the transitive case ----------

test('recharts app: lodash ships though the app never imports it; the omit/unset advisories stay open', () => {
  const src = readFileSync(new URL('../demo/src/main.jsx', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /lodash/);
  const lodash = demo.moduleMap.packages.get('lodash');
  assert.ok(lodash.files.has('omit.js') && lodash.files.has('_baseUnset.js') && !lodash.files.has('template.js'));

  for (const input of ['recharts.trivy.json', 'recharts.grype.json']) {
    const rs = triage({ ...demo, findings: readFindings(fx(input)).findings });
    const byRule = (g, c) => rs.find((r) => r.id === g || r.id === c);
    assert.equal(byRule('GHSA-r5fr-rjxr-66jc', 'CVE-2026-4800').state, 'not_affected', input);
    for (const [g, c] of [['GHSA-f23m-r3pf-42rh', 'CVE-2026-2950'], ['GHSA-xxjr-mmjv-4gpg', 'CVE-2025-13465']]) {
      const r = byRule(g, c);
      assert.equal(r.state, 'in_triage', input);
      assert.match(r.moduleReason, /_baseUnset\.js, omit\.js/);
      assert.ok([r.id, ...r.aliases].includes(g) && [r.id, ...r.aliases].includes(c), 'rule aliases attached');
    }
  }
});

// ---------- CycloneDX VEX that Trivy applies ----------

test('BOM-Link fragment is escaped exactly like Go url.QueryEscape', () => {
  assert.equal(goQueryEscape('chart-dashboard@1.0.0|lodash@4.17.21'), 'chart-dashboard%401.0.0%7Clodash%404.17.21');
  assert.equal(goQueryEscape("a b!'()*~._-"), "a+b%21%27%28%29%2A~._-");
});

test('CycloneDX VEX: affects are BOM-Links into the lockfile SBOM, with a CVE-keyed entry for Trivy', () => {
  const rs = triage({ ...demo, findings: fromNpmAudit(fx('recharts.audit.json'), demo.lockfileSbom) });
  const vex = toCycloneDxVex({ results: rs, lockfileSbom: demo.lockfileSbom, bundleSbom: demo.bundleSbom, productPurl: APP });
  const serial = demo.lockfileSbom.serialNumber.replace('urn:uuid:', '');
  const lodashRef = demo.lockfileSbom.components.find((c) => c.purl === 'pkg:npm/lodash@4.17.21')['bom-ref'];
  assert.deepEqual(bomLinks(demo.lockfileSbom, 'pkg:npm/lodash@4.17.21'), [`urn:cdx:${serial}/1#${goQueryEscape(lodashRef)}`]);
  for (const v of vex.vulnerabilities) assert.match(v.affects[0].ref, new RegExp(`^urn:cdx:${serial}/1#`));
  const ids = vex.vulnerabilities.map((v) => v.id);
  for (const id of ['GHSA-r5fr-rjxr-66jc', 'CVE-2026-4800', 'GHSA-f23m-r3pf-42rh', 'CVE-2026-2950']) assert.ok(ids.includes(id), id);
  const alias = vex.vulnerabilities.find((v) => v.id === 'CVE-2026-4800');
  assert.equal(alias.analysis.state, 'not_affected');
  assert.ok(alias.properties.some((p) => p.name === 'vexproof:alias-of' && p.value === 'GHSA-r5fr-rjxr-66jc'));
});

test('CycloneDX VEX validates against the CycloneDX 1.6 schema', async () => {
  const { Validation, Spec } = require('@cyclonedx/cyclonedx-library');
  const rs = triage({ ...demo, findings: readFindings(fx('recharts.trivy.json')).findings });
  const vex = toCycloneDxVex({ results: rs, lockfileSbom: demo.lockfileSbom, bundleSbom: demo.bundleSbom, productPurl: APP });
  const err = await new Validation.JsonStrictValidator(Spec.Version.v1dot6).validate(JSON.stringify(vex));
  assert.equal(err, null, JSON.stringify(err));
});

test('CycloneDX VEX can be written as 1.7 and validates against the 1.7 schema; other versions are refused', async () => {
  const { Validation, Spec } = require('@cyclonedx/cyclonedx-library');
  const rs = triage({ ...demo, findings: fromNpmAudit(fx('recharts.audit.json'), demo.lockfileSbom) });
  const vex = toCycloneDxVex({ results: rs, lockfileSbom: demo.lockfileSbom, bundleSbom: demo.bundleSbom, productPurl: APP, specVersion: '1.7' });
  assert.equal(vex.specVersion, '1.7');
  const err = await new Validation.JsonStrictValidator(Spec.Version.v1dot7).validate(JSON.stringify(vex));
  assert.equal(err, null, JSON.stringify(err));
  assert.throws(() => toCycloneDxVex({ results: rs, lockfileSbom: demo.lockfileSbom, productPurl: APP, specVersion: '1.5' }), /not supported/);
});

test('baseline and review follow an advisory across id schemes (npm audit GHSA → Trivy CVE)', () => {
  const r1 = toCycloneDxVex({ results: triage({ ...demo, findings: fromNpmAudit(fx('recharts.audit.json'), demo.lockfileSbom) }), lockfileSbom: demo.lockfileSbom, productPurl: APP });
  recordReview(r1, { id: 'GHSA-f23m-r3pf-42rh', state: 'not_affected', justification: 'code_not_reachable', detail: 'Treemap never receives user-controlled paths', by: 'Jane Doe' });
  const rs = applyBaseline(triage({ ...demo, findings: readFindings(fx('recharts.trivy.json')).findings }), readBaseline(r1));
  const t = rs.find((r) => r.id === 'CVE-2026-2950');
  assert.equal(t.origin, 'reviewed');
  assert.equal(t.reviewedBy, 'Jane Doe');
  assert.equal(rs.filter((r) => r.isNew).length, 0);
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
  const rs = triage({ ...demo, findings: readFindings(fx('recharts.grype.json')).findings });
  const doc = toOpenVex({ results: rs, productPurl: APP });
  const validate = openVexValidator();
  assert.ok(validate(doc), JSON.stringify(validate.errors));
  const s = Object.fromEntries(doc.statements.map((x) => [x.vulnerability.name, x]));
  assert.equal(s['GHSA-r5fr-rjxr-66jc'].status, 'not_affected');
  assert.equal(s['GHSA-r5fr-rjxr-66jc'].justification, 'vulnerable_code_not_present');
  assert.deepEqual(s['GHSA-r5fr-rjxr-66jc'].vulnerability.aliases, ['CVE-2026-4800']);
  assert.equal(s['GHSA-f23m-r3pf-42rh'].status, 'under_investigation');
  assert.deepEqual(s['GHSA-f23m-r3pf-42rh'].products, [{ '@id': APP, subcomponents: [{ '@id': 'pkg:npm/lodash@4.17.21' }] }]);
});

test('OpenVEX: package-level absence maps to component_not_present; Grype form is opt-in', () => {
  const ng = fx('angular.bom.lockfile.json');
  const rs = triage({ lockfileSbom: ng, bundleSbom: fx('angular-capitalize.bom.bundle.json'), findings: fromNpmAudit(fx('angular.audit.json'), ng), rules });
  const plain = toOpenVex({ results: rs, productPurl: 'pkg:npm/ngapp@0.0.0' });
  const moment = plain.statements.find((x) => x.products[0].subcomponents[0]['@id'].includes('moment'));
  assert.equal(moment.justification, 'component_not_present');
  assert.ok(plain.statements.every((x) => x.products.length === 1));
  const grype = toOpenVex({ results: rs, productPurl: 'pkg:npm/ngapp@0.0.0', packageProducts: true });
  assert.ok(grype.statements.every((x) => x.products.length === 2 && x.products[1]['@id'] === x.products[0].subcomponents[0]['@id']));
  const validate = openVexValidator();
  assert.ok(validate(grype), JSON.stringify(validate.errors));
});

// ---------- Rspack: module map only, no bundle SBOM plugin (the CycloneDX webpack plugin fails on Rspack) ----------

test('Rspack (VexproofPlugin stats): bundle contents come from the module map and verdicts match the esbuild build', async () => {
  const { bundleSbomFromModules } = await import('../src/modules.js');
  const moduleMap = readModuleMap(fx('recharts.rspack-plugin.json'));
  assert.match(moduleMap.format, /^webpack-stats \(rspack /);
  const lodash = moduleMap.packages.get('lodash');
  assert.equal(lodash.files.size, demo.moduleMap.packages.get('lodash').files.size);
  // no node_modules here: versions fall back to the lockfile SBOM, which lists one lodash
  const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom: demo.lockfileSbom, cwd: '/nonexistent' });
  assert.ok(bundleSbom.components.some((c) => c.purl === 'pkg:npm/lodash@4.17.21'));
  const rs = triage({ ...demo, bundleSbom, moduleMap, findings: fromNpmAudit(fx('recharts.audit.json'), demo.lockfileSbom) });
  const st = Object.fromEntries(rs.map((r) => [r.id, r.state]));
  assert.deepEqual(st, { 'GHSA-r5fr-rjxr-66jc': 'not_affected', 'GHSA-f23m-r3pf-42rh': 'in_triage', 'GHSA-xxjr-mmjv-4gpg': 'in_triage' });
});

test('module-map bundle claims no version it cannot read', async () => {
  const { bundleSbomFromModules } = await import('../src/modules.js');
  const mm = { format: 'webpack-stats', packages: new Map([['left-pad', { roots: new Set(['node_modules/left-pad']), files: new Set(['index.js']) }]]) };
  const b = bundleSbomFromModules(mm, { lockfileSbom: { components: [{ purl: 'pkg:npm/left-pad@1.0.0' }, { purl: 'pkg:npm/left-pad@1.3.0' }] }, cwd: '/nonexistent' });
  assert.equal(b.components[0].purl, 'pkg:npm/left-pad');
});

test('pnpm audit JSON (Gitea, real): GHSA ids with CVE aliases and a version per finding', () => {
  const r = readFindings(fx('gitea.pnpm-audit.json'));
  assert.equal(r.format, 'pnpm-audit');
  assert.equal(r.findings.length, 8);
  assert.ok(r.findings.every((f) => /^GHSA-/.test(f.id) && /^pkg:npm\/.+@\d/.test(f.purl)));
  assert.ok(r.findings.some((f) => f.purl === 'pkg:npm/lodash-es@4.17.23' && f.id === 'GHSA-r5fr-rjxr-66jc'));
});
