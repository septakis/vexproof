// SPDX-License-Identifier: MIT
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, writeFileSync, cpSync, symlinkSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readModuleMap, splitNodeModulesPath } from '../src/modules.js';
import { triage, toCycloneDxVex, summarize } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { fromNpmAudit } from '../src/sources.js';
import { verifyLicense, b64u, PRO_FEATURES, RESERVED_FEATURES } from '../src/pro/license.js';
import { readBaseline, applyBaseline } from '../src/pro/baseline.js';
import { recordReview } from '../src/review.js';
import { renderReport } from '../src/pro/report.js';

const fx = (f) => JSON.parse(readFileSync(new URL(`./fixtures/${f}`, import.meta.url)));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const byId = (rs, purlPart) => Object.fromEntries(rs.filter((r) => r.purl.includes(purlPart)).map((r) => [r.id, r]));

// ---------- module maps from real builds ----------

test('splitNodeModulesPath handles nesting, scopes and loader prefixes', () => {
  assert.deepEqual(splitNodeModulesPath('./node_modules/a/node_modules/@s/p/lib/x.js'), { name: '@s/p', root: 'node_modules/a/node_modules/@s/p', file: 'lib/x.js' });
  assert.deepEqual(splitNodeModulesPath('babel-loader!./node_modules/lodash-es/trim.js'), { name: 'lodash-es', root: 'node_modules/lodash-es', file: 'trim.js' });
  assert.equal(splitNodeModulesPath('src/app.ts'), null);
});

test('esbuild (Angular) and webpack agree on which lodash-es files shipped', () => {
  const esb = readModuleMap(fx('angular-capitalize.metafile.json'));
  const wp = readModuleMap(fx('webpack-pertrim.stats.json'));
  assert.equal(esb.format, 'esbuild-metafile');
  assert.equal(wp.format, 'webpack-stats');
  const a = [...esb.packages.get('lodash-es').files].sort();
  const b = [...wp.packages.get('lodash-es').files].sort();
  assert.deepEqual(a, b);
  assert.ok(a.includes('capitalize.js') && !a.includes('template.js') && !a.includes('toNumber.js'));
});

// ---------- module-level verdicts on real Angular builds ----------

const ng = { lockfileSbom: fx('angular.bom.lockfile.json') };
ng.findings = fromNpmAudit(fx('angular.audit.json'), ng.lockfileSbom);

test('Angular app using only capitalize: Pro settles all five lodash-es advisories', () => {
  const rs = triage({ ...ng, bundleSbom: fx('angular-capitalize.bom.bundle.json'), moduleMap: readModuleMap(fx('angular-capitalize.metafile.json')), rules, moduleCheck: evaluateModuleRule, pro: true });
  const l = Object.values(byId(rs, 'lodash-es'));
  assert.equal(l.length, 5);
  for (const r of l) {
    assert.equal(r.state, 'not_affected');
    assert.equal(r.level, 'module');
    assert.ok(r.evidence.survivingFiles.includes('capitalize.js'));
  }
  const s = summarize(rs);
  assert.equal(s.in_triage, 0);
});

test('Angular app using template and omit: those advisories stay open, ReDoS still settles', () => {
  const rs = triage({ ...ng, bundleSbom: fx('angular-template.bom.bundle.json'), moduleMap: readModuleMap(fx('angular-template.metafile.json')), rules, moduleCheck: evaluateModuleRule, pro: true });
  const l = byId(rs, 'lodash-es');
  for (const id of ['GHSA-35jh-r3h4-6jhm', 'GHSA-r5fr-rjxr-66jc']) assert.match(l[id].moduleReason, /template\.js/);
  for (const id of ['GHSA-xxjr-mmjv-4gpg', 'GHSA-f23m-r3pf-42rh']) assert.match(l[id].moduleReason, /_baseUnset\.js/);
  assert.equal(l['GHSA-29mw-wpgm-hmr9'].state, 'not_affected');
  assert.equal(rs.filter((r) => r.state === 'in_triage').length, 4);
});

test('free mode never writes module-level verdicts, but counts what Pro would settle', () => {
  const rs = triage({ ...ng, bundleSbom: fx('angular-capitalize.bom.bundle.json'), moduleMap: readModuleMap(fx('angular-capitalize.metafile.json')), rules, moduleCheck: evaluateModuleRule, pro: false });
  assert.ok(rs.every((r) => r.level !== 'module'));
  assert.equal(summarize(rs).proWouldSettle, 5);
});

// ---------- webpack: per-method CJS import and monolith guard ----------

const wpBase = { lockfileSbom: fx('webpack.bom.lockfile.json') };
wpBase.findings = fromNpmAudit(fx('webpack.audit.json'), wpBase.lockfileSbom);

test('webpack: lodash/trim import keeps the ReDoS advisory open for lodash only', () => {
  const rs = triage({ ...wpBase, bundleSbom: fx('webpack-pertrim.bom.bundle.json'), moduleMap: readModuleMap(fx('webpack-pertrim.stats.json')), rules, moduleCheck: evaluateModuleRule, pro: true });
  const open = rs.filter((r) => r.state === 'in_triage');
  assert.equal(open.length, 1);
  assert.equal(open[0].id, 'GHSA-29mw-wpgm-hmr9');
  assert.match(open[0].purl, /pkg:npm\/lodash@/);
});

// ---------- guards (synthetic, one at a time) ----------

const map = (files, roots = ['node_modules/lodash-es']) => ({ format: 'esbuild-metafile', packages: new Map([['lodash-es', { roots: new Set(roots), files: new Set(files) }]]) });
const base = { key: 'npm/lodash-es', parsed: { type: 'npm', name: 'lodash-es', version: '4.17.20' }, id: 'GHSA-35jh-r3h4-6jhm', bundleVersions: new Set(['4.17.20']), rules };

test('guard: monolith build bundled', () => {
  assert.match(evaluateModuleRule({ ...base, moduleMap: map(['capitalize.js', 'lodash.default.js']) }).reason, /full build/);
});
test('guard: two copies of the package installed', () => {
  assert.match(evaluateModuleRule({ ...base, moduleMap: map(['capitalize.js'], ['node_modules/lodash-es', 'node_modules/x/node_modules/lodash-es']) }).reason, /2 locations/);
});
test('guard: bundle version differs from finding version', () => {
  assert.match(evaluateModuleRule({ ...base, bundleVersions: new Set(['4.17.21']), moduleMap: map(['capitalize.js']) }).reason, /4\.17\.21/);
});
test('guard: bundle SBOM says present but module map shows nothing', () => {
  assert.match(evaluateModuleRule({ ...base, moduleMap: { format: 'x', packages: new Map() } }).reason, /contradicts/);
});
test('guard: advisory without a rule stays open', () => {
  assert.match(evaluateModuleRule({ ...base, id: 'GHSA-unknown', moduleMap: map(['capitalize.js']) }).reason, /no module rule/);
});
test('rule matches on an alias as well as the primary id', () => {
  assert.equal(evaluateModuleRule({ ...base, id: 'CVE-2021-23337', aliases: ['GHSA-35jh-r3h4-6jhm'], moduleMap: map(['capitalize.js']) }).ok, true);
});

// ---------- licensing ----------

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
const issue = (payload, key = privateKey) => {
  const head = `vxp1.${b64u.enc(JSON.stringify(payload))}`;
  return `${head}.${b64u.enc(sign(null, Buffer.from(head), key))}`;
};
const now = new Date('2026-09-25T00:00:00Z');

test('license: valid token unlocks listed features only', () => {
  const l = verifyLicense(issue({ org: 'Acme', exp: '2027-01-01', features: ['modules', 'bogus'] }), { publicKeyPem: pubPem, now });
  assert.equal(l.valid, true);
  assert.deepEqual(l.features, ['modules']);
});
test('license: dependabot is a Pro feature', () => {
  assert.ok(PRO_FEATURES.includes('dependabot'));
  assert.deepEqual(verifyLicense(issue({ org: 'Acme', exp: '2027-01-01', features: ['dependabot'] }), { publicKeyPem: pubPem, now }).features, ['dependabot']);
});
test('license: csaf, signing and rollup are Pro features now; a name vexproof does not know unlocks nothing', () => {
  assert.deepEqual(RESERVED_FEATURES, []);
  for (const f of ['csaf', 'signing', 'rollup']) assert.ok(PRO_FEATURES.includes(f), f);
  const l = verifyLicense(issue({ org: 'Acme', exp: '2027-01-01', features: ['future-thing'] }), { publicKeyPem: pubPem, now });
  assert.equal(l.valid, true);
  assert.equal(l.pro, false);
  assert.deepEqual(l.features, []);
});
test('issue-license: a default key carries every Pro feature, and rejects unknown ones', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vexproof-issue-'));
  const key = join(dir, 'private.pem');
  writeFileSync(key, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const script = fileURLToPath(new URL('../scripts/issue-license.js', import.meta.url));
  const run = (...a) => spawnSync(process.execPath, [script, '--org', 'Acme', '--exp', '2027-01-01', '--key', key, ...a], { encoding: 'utf8' });
  const payload = JSON.parse(b64u.dec(run().stdout.trim().split('.')[1]).toString('utf8'));
  assert.deepEqual(payload.features, [...PRO_FEATURES, ...RESERVED_FEATURES]);
  assert.match(run('--features', 'modules,bogus').stderr, /unknown feature\(s\): bogus/);
});
test('license: tampered payload or wrong key fails closed to free', () => {
  const t = issue({ org: 'Acme', exp: '2027-01-01', features: ['modules'] });
  const [p, , s] = t.split('.');
  const forged = `${p}.${b64u.enc(JSON.stringify({ org: 'Acme', exp: '2099-01-01', features: ['modules'] }))}.${s}`;
  assert.equal(verifyLicense(forged, { publicKeyPem: pubPem, now }).valid, false);
  const other = generateKeyPairSync('ed25519').privateKey;
  assert.equal(verifyLicense(issue({ org: 'Acme', exp: '2027-01-01', features: ['modules'] }, other), { publicKeyPem: pubPem, now }).valid, false);
  assert.equal(verifyLicense('garbage', { publicKeyPem: pubPem, now }).valid, false);
});
test('license: 14-day grace after expiry, then free', () => {
  const t = issue({ org: 'Acme', exp: '2026-09-20', features: ['modules'] });
  const inGrace = verifyLicense(t, { publicKeyPem: pubPem, now });
  assert.equal(inGrace.valid, true);
  assert.match(inGrace.warning, /expired/);
  assert.equal(verifyLicense(t, { publicKeyPem: pubPem, now: new Date('2026-10-10') }).valid, false);
});

// ---------- baseline and review ----------

const productPurl = 'pkg:npm/ngapp@0.0.0';
function freshTemplateRun() {
  return triage({ ...ng, bundleSbom: fx('angular-template.bom.bundle.json'), moduleMap: readModuleMap(fx('angular-template.metafile.json')), rules, moduleCheck: evaluateModuleRule, pro: true });
}

test('review records a decision; baseline carries it forward and it no longer counts as new', () => {
  const release1 = toCycloneDxVex({ results: freshTemplateRun(), productPurl });
  recordReview(release1, { id: 'GHSA-35jh-r3h4-6jhm', state: 'not_affected', justification: 'code_not_reachable', detail: 'template() only receives compile-time constants', by: 'brad' });
  const rs = applyBaseline(freshTemplateRun(), readBaseline(release1));
  const t = rs.find((r) => r.id === 'GHSA-35jh-r3h4-6jhm');
  assert.equal(t.state, 'not_affected');
  assert.equal(t.origin, 'reviewed');
  assert.equal(t.reviewedBy, 'brad');
  assert.equal(rs.filter((r) => r.isNew).length, 0);
});

test('baseline flags regressions: a package that was absent and is now bundled is new', () => {
  const release1 = toCycloneDxVex({ results: triage({ ...ng, bundleSbom: { components: [{ purl: 'pkg:npm/rxjs@7.8.2' }] }, rules }), productPurl });
  const rs = applyBaseline(freshTemplateRun(), readBaseline(release1));
  assert.equal(rs.filter((r) => r.isNew).length, 4);
});

test('review rejects incomplete or invalid decisions', () => {
  const v = toCycloneDxVex({ results: freshTemplateRun(), productPurl });
  assert.throws(() => recordReview(v, { id: 'GHSA-35jh-r3h4-6jhm', state: 'not_affected', detail: 'x', by: 'b' }), /justification/);
  assert.throws(() => recordReview(v, { id: 'GHSA-35jh-r3h4-6jhm', state: 'fine', detail: 'x', by: 'b' }), /state must be/);
  assert.throws(() => recordReview(v, { id: 'GHSA-35jh-r3h4-6jhm', state: 'exploitable', detail: 'x' }), /--by/);
  assert.throws(() => recordReview(v, { id: 'GHSA-nope', state: 'exploitable', detail: 'x', by: 'b' }), /no statement/);
});

// ---------- report ----------

test('report shows input hashes, evidence and every statement', () => {
  const rs = freshTemplateRun();
  const html = renderReport({ results: rs, summary: summarize(rs), inputs: [{ role: 'lockfile-sbom', path: 'bom.json', sha256: 'abc123' }], productPurl, license: { org: 'Acme' }, command: 'vexproof …', version: 'test' });
  assert.match(html, /sha256 abc123/);
  assert.match(html, /licensed to Acme/);
  assert.match(html, /surviving files/);
  for (const r of rs) assert.ok(html.includes(r.id), `report is missing ${r.id}`);
  assert.match(html, /Module-level check: vulnerable file\(s\) bundled: template\.js/);
  assert.match(html, /Applies to all 19 advisories/);
  assert.ok(!/<script/i.test(html));
});

// ---------- CLI behaviour ----------

const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const f = (n) => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));
const runArgs = ['--lockfile', f('angular.bom.lockfile.json'), '--bundle', f('angular-template.bom.bundle.json'), '--findings', f('angular.audit.json'), '--modules', f('angular-template.metafile.json')];

test('CLI free: shows a Pro hint, gate on in_triage exits 1, --quiet hides the hint', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bvx-'));
  const env = { ...process.env, VEXPROOF_LICENSE: '' };
  const r = spawnSync('node', [cli, ...runArgs, '--out', join(dir, 'v.json'), '--fail-on', 'in_triage'], { env, cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Pro would settle 1 of your 5 open/);
  const q = spawnSync('node', [cli, ...runArgs, '--out', join(dir, 'v.json'), '--quiet'], { env, cwd: dir, encoding: 'utf8' });
  assert.equal(q.status, 0);
  assert.doesNotMatch(q.stderr, /Pro/);
});

test('CLI: invalid license never breaks the build', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bvx-'));
  const r = spawnSync('node', [cli, ...runArgs, '--out', join(dir, 'v.json'), '--license', 'vxp1.bad.token'], { cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stderr, /running free features only/);
});

const keyFile = fileURLToPath(new URL('../.keys/license-private.pem', import.meta.url));
test('CLI Pro: report, baseline and --fail-on new (needs .keys from scripts/keygen.js)', { skip: !existsSync(keyFile) && 'no signing key; run npm run keygen' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'bvx-'));
  const lic = execFileSync('node', [fileURLToPath(new URL('../scripts/issue-license.js', import.meta.url)), '--org', 'Test Org', '--exp', '2099-01-01', '--key', keyFile], { encoding: 'utf8' }).trim();
  const env = { ...process.env, VEXPROOF_LICENSE: lic };
  const v1 = join(dir, 'v1.json');
  let r = spawnSync('node', [cli, ...runArgs, '--out', v1, '--report', join(dir, 'r.html')], { env, cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(existsSync(join(dir, 'r.html')));
  assert.doesNotMatch(r.stderr, /Pro would/);
  // nothing new against itself
  r = spawnSync('node', [cli, ...runArgs, '--out', join(dir, 'v2.json'), '--baseline', v1, '--fail-on', 'new'], { env, cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  // a baseline where lodash-es was absent → the four bundled advisories are new → gate trips
  const old = JSON.parse(readFileSync(v1, 'utf8'));
  old.vulnerabilities = old.vulnerabilities.filter((v) => !v.properties.some((p) => p.value.includes('lodash-es')));
  writeFileSync(join(dir, 'old.json'), JSON.stringify(old));
  r = spawnSync('node', [cli, ...runArgs, '--out', join(dir, 'v3.json'), '--baseline', join(dir, 'old.json'), '--fail-on', 'new'], { env, cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /4 new open finding/);
});

// ---------- revocation ----------

test('license: a revoked id is invalid, and the same license without the revocation is not', () => {
  const id = '5d0c1c62-6a1e-4c2b-9f6a-0d8f1a2b3c4d';
  const t = issue({ id, org: 'Acme', exp: '2027-01-01', features: ['modules'] });
  assert.equal(verifyLicense(t, { publicKeyPem: pubPem, now, revoked: new Set() }).valid, true);
  const r = verifyLicense(t, { publicKeyPem: pubPem, now, revoked: [id.toUpperCase()] });
  assert.equal(r.valid, false);
  assert.equal(r.revoked, true);
  assert.match(r.reason, /license for Acme \(5d0c1c62-.*\) has been revoked/);
  // a forged token can't dodge the list by changing its id: the signature breaks first
  assert.equal(verifyLicense(t.replace(/\.[^.]+\./, `.${b64u.enc(JSON.stringify({ id: 'x', org: 'Acme', exp: '2027-01-01', features: ['modules'] }))}.`), { publicKeyPem: pubPem, now, revoked: [] }).valid, false);
});

test('license: the shipped revocation list loads and is well formed', async () => {
  const { loadRevoked } = await import('../src/pro/license.js');
  const doc = JSON.parse(readFileSync(new URL('../src/pro/revoked.json', import.meta.url), 'utf8'));
  assert.ok(Array.isArray(doc.revoked));
  for (const r of doc.revoked) assert.match(r.id, /^[0-9a-f-]{36}$/), assert.match(r.date, /^\d{4}-\d{2}-\d{2}$/);
  assert.equal(loadRevoked().size, new Set(doc.revoked.map((r) => r.id)).size);
});

test('revoke-license: adds an id once, lists it, and refuses junk', () => {
  const script = fileURLToPath(new URL('../scripts/revoke-license.js', import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), 'vxp-revoke-'));
  const file = join(dir, 'revoked.json');
  writeFileSync(file, JSON.stringify({ license: 'LicenseRef-vexproof-Pro', revoked: [] }));
  const run = (...a) => spawnSync('node', [script, '--file', file, ...a], { encoding: 'utf8' });
  const id = '5D0C1C62-6A1E-4C2B-9F6A-0D8F1A2B3C4D';
  assert.equal(run('--id', id, '--date', '2026-10-11').status, 0);
  assert.match(run('--id', id).stdout, /already revoked/);
  assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')).revoked, [{ id: id.toLowerCase(), date: '2026-10-11' }]);
  assert.match(run('--list').stdout, /2026-10-11 {2}5d0c1c62/);
  assert.equal(run('--id', 'not-an-id').status, 2);
  assert.equal(run('--token', 'vxp1.e30.c2ln').status, 1); // signed by some other key: nothing to revoke
  assert.equal(run().status, 2);
});

test('CLI: a revoked license runs free features and says why (needs .keys)', { skip: !existsSync(keyFile) && 'no signing key; run npm run keygen' }, () => {
  const lic = execFileSync('node', [fileURLToPath(new URL('../scripts/issue-license.js', import.meta.url)), '--org', 'Revoked Org', '--exp', '2099-01-01', '--key', keyFile], { encoding: 'utf8' }).trim();
  const { id } = JSON.parse(b64u.dec(lic.split('.')[1]).toString('utf8'));
  // a copy of the package whose revocation list names this license
  const root = fileURLToPath(new URL('..', import.meta.url));
  const pkg = mkdtempSync(join(tmpdir(), 'vxp-revoked-pkg-'));
  cpSync(join(root, 'src'), join(pkg, 'src'), { recursive: true });
  cpSync(join(root, 'package.json'), join(pkg, 'package.json'));
  symlinkSync(join(root, 'node_modules'), join(pkg, 'node_modules'), 'junction');
  writeFileSync(join(pkg, 'src/pro/revoked.json'), JSON.stringify({ license: 'LicenseRef-vexproof-Pro', revoked: [{ id, date: '2026-10-11' }] }));
  const dir = mkdtempSync(join(tmpdir(), 'bvx-'));
  const env = { ...process.env, VEXPROOF_LICENSE: lic };
  const revoked = spawnSync('node', [join(pkg, 'src/cli.js'), ...runArgs, '--out', join(dir, 'v.json'), '--report', join(dir, 'r.html')], { env, cwd: dir, encoding: 'utf8' });
  assert.equal(revoked.status, 0, revoked.stderr);
  assert.match(revoked.stderr, /license for Revoked Org \(.+\) has been revoked; running free features only/);
  assert.ok(!existsSync(join(dir, 'r.html')));
  // the same license in the real package, where it isn't listed, still works
  const fine = spawnSync('node', [cli, ...runArgs, '--out', join(dir, 'v2.json'), '--report', join(dir, 'r2.html')], { env, cwd: dir, encoding: 'utf8' });
  assert.equal(fine.status, 0, fine.stderr);
  assert.ok(existsSync(join(dir, 'r2.html')));
});
