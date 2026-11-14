// SPDX-License-Identifier: MIT
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readModuleMap, splitNodeModulesPath } from '../src/modules.js';
import { triage, toCycloneDxVex, summarize } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { fromNpmAudit } from '../src/sources.js';
import { verifyLicense, b64u, PRO_FEATURES, RESERVED_FEATURES } from '../src/pro/license.js';
import { modulesArgs } from './lib/built.js';
import { proCopy } from './lib/pro-copy.js';
import { readBaseline, applyBaseline } from '../src/pro/baseline.js';
import { recordReview } from '../src/review.js';
import { renderReport } from '../src/pro/report.js';
import { temporaryFolder } from './lib/temporary.js';

const readFixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url)));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const byId = (results, purlPart) => Object.fromEntries(
  results.filter((result) => result.purl.includes(purlPart)).map((result) => [result.id, result]),
);

// ---------- module maps from real builds ----------

test('splitNodeModulesPath handles nesting, scopes and loader prefixes', () => {
  assert.deepEqual(
    splitNodeModulesPath('./node_modules/a/node_modules/@s/p/lib/x.js'),
    { name: '@s/p', root: 'node_modules/a/node_modules/@s/p', file: 'lib/x.js' },
  );
  assert.deepEqual(
    splitNodeModulesPath('babel-loader!./node_modules/lodash-es/trim.js'),
    { name: 'lodash-es', root: 'node_modules/lodash-es', file: 'trim.js' },
  );
  assert.equal(splitNodeModulesPath('src/app.ts'), null);
});

test('esbuild (Angular) and webpack agree on which lodash-es files shipped', () => {
  const esbuildMap = readModuleMap(readFixture('angular-capitalize.metafile.json'));
  const webpackMap = readModuleMap(readFixture('webpack-pertrim.stats.json'));

  assert.equal(esbuildMap.format, 'esbuild-metafile');
  assert.equal(webpackMap.format, 'webpack-stats');

  const esbuildFiles = [...esbuildMap.packages.get('lodash-es').files].sort();
  const webpackFiles = [...webpackMap.packages.get('lodash-es').files].sort();
  assert.deepEqual(esbuildFiles, webpackFiles);
  assert.ok(esbuildFiles.includes('capitalize.js') && !esbuildFiles.includes('template.js') && !esbuildFiles.includes('toNumber.js'));
});

// ---------- module-level verdicts on real Angular builds ----------

const angular = { lockfileSbom: readFixture('angular.bom.lockfile.json') };
angular.findings = fromNpmAudit(readFixture('angular.audit.json'), angular.lockfileSbom);

test('Angular app using only capitalize: Pro settles all five lodash-es advisories', () => {
  const results = triage({
    ...angular,
    bundleSbom: readFixture('angular-capitalize.bom.bundle.json'),
    moduleMap: readModuleMap(readFixture('angular-capitalize.metafile.json')),
    rules,
    moduleCheck: evaluateModuleRule,
    pro: true,
  });

  const lodash = Object.values(byId(results, 'lodash-es'));
  assert.equal(lodash.length, 5);
  for (const result of lodash) {
    assert.equal(result.state, 'not_affected');
    assert.equal(result.level, 'module');
    assert.ok(result.evidence.survivingFiles.includes('capitalize.js'));
  }

  const summary = summarize(results);
  assert.equal(summary.in_triage, 0);
});

test('Angular app using template and omit: those advisories stay open, ReDoS still settles', () => {
  const results = triage({
    ...angular,
    bundleSbom: readFixture('angular-template.bom.bundle.json'),
    moduleMap: readModuleMap(readFixture('angular-template.metafile.json')),
    rules,
    moduleCheck: evaluateModuleRule,
    pro: true,
  });

  const lodash = byId(results, 'lodash-es');
  for (const id of ['GHSA-35jh-r3h4-6jhm', 'GHSA-r5fr-rjxr-66jc']) assert.match(lodash[id].moduleReason, /template\.js/);
  for (const id of ['GHSA-xxjr-mmjv-4gpg', 'GHSA-f23m-r3pf-42rh']) assert.match(lodash[id].moduleReason, /_baseUnset\.js/);
  assert.equal(lodash['GHSA-29mw-wpgm-hmr9'].state, 'not_affected');
  assert.equal(results.filter((result) => result.state === 'in_triage').length, 4);
});

test('free mode never writes module-level verdicts, but counts what Pro would settle', () => {
  const results = triage({
    ...angular,
    bundleSbom: readFixture('angular-capitalize.bom.bundle.json'),
    moduleMap: readModuleMap(readFixture('angular-capitalize.metafile.json')),
    rules,
    moduleCheck: evaluateModuleRule,
    pro: false,
  });

  assert.ok(results.every((result) => result.level !== 'module'));
  assert.equal(summarize(results).proWouldSettle, 5);
});

// ---------- webpack: per-method CommonJS imports (the monolith guard is under guards, below) ----------

const webpackBase = { lockfileSbom: readFixture('webpack.bom.lockfile.json') };
webpackBase.findings = fromNpmAudit(readFixture('webpack.audit.json'), webpackBase.lockfileSbom);

test('webpack: lodash/trim import keeps the ReDoS advisory open for lodash only', () => {
  const results = triage({
    ...webpackBase,
    bundleSbom: readFixture('webpack-pertrim.bom.bundle.json'),
    moduleMap: readModuleMap(readFixture('webpack-pertrim.stats.json')),
    rules,
    moduleCheck: evaluateModuleRule,
    pro: true,
  });

  const open = results.filter((result) => result.state === 'in_triage');
  assert.equal(open.length, 1);
  assert.equal(open[0].id, 'GHSA-29mw-wpgm-hmr9');
  assert.match(open[0].purl, /pkg:npm\/lodash@/);
});

// ---------- guards (synthetic, one at a time) ----------

const map = (files, roots = ['node_modules/lodash-es']) => ({
  format: 'esbuild-metafile',
  packages: new Map([['lodash-es', { roots: new Set(roots), files: new Set(files) }]]),
});
const base = {
  key: 'npm/lodash-es',
  parsed: { type: 'npm', name: 'lodash-es', version: '4.17.20' },
  id: 'GHSA-35jh-r3h4-6jhm',
  bundleVersions: new Set(['4.17.20']),
  rules,
};

test('guard: monolith build bundled', () => {
  assert.match(evaluateModuleRule({ ...base, moduleMap: map(['capitalize.js', 'lodash.default.js']) }).reason, /full build/);
});

test('guard: two copies of the package installed', () => {
  const moduleMap = map(['capitalize.js'], ['node_modules/lodash-es', 'node_modules/x/node_modules/lodash-es']);
  assert.match(evaluateModuleRule({ ...base, moduleMap }).reason, /2 locations/);
});

test('guard: bundle version differs from finding version', () => {
  const verdict = evaluateModuleRule({ ...base, bundleVersions: new Set(['4.17.21']), moduleMap: map(['capitalize.js']) });
  assert.match(verdict.reason, /4\.17\.21/);
});

test('guard: bundle SBOM says present but module map shows nothing', () => {
  assert.match(evaluateModuleRule({ ...base, moduleMap: { format: 'x', packages: new Map() } }).reason, /contradicts/);
});

test('guard: advisory without a rule stays open', () => {
  assert.match(evaluateModuleRule({ ...base, id: 'GHSA-unknown', moduleMap: map(['capitalize.js']) }).reason, /no module rule/);
});

test('rule matches on an alias as well as the primary id', () => {
  const verdict = evaluateModuleRule({
    ...base, id: 'CVE-2021-23337', aliases: ['GHSA-35jh-r3h4-6jhm'], moduleMap: map(['capitalize.js']),
  });
  assert.equal(verdict.ok, true);
});

// ---------- licensing ----------

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const issue = (payload, key = privateKey) => {
  const head = `vxp1.${b64u.enc(JSON.stringify(payload))}`;
  return `${head}.${b64u.enc(sign(null, Buffer.from(head), key))}`;
};
const now = new Date('2026-09-25T00:00:00Z');

test('license: valid token unlocks listed features only', () => {
  const license = verifyLicense(issue({ org: 'Acme', exp: '2027-01-01', features: ['modules', 'bogus'] }), { publicKeyPem, now });

  assert.equal(license.valid, true);
  assert.deepEqual(license.features, ['modules']);
});

test('license: dependabot is a Pro feature', () => {
  assert.ok(PRO_FEATURES.includes('dependabot'));

  const token = issue({ org: 'Acme', exp: '2027-01-01', features: ['dependabot'] });
  assert.deepEqual(verifyLicense(token, { publicKeyPem, now }).features, ['dependabot']);
});

test('license: csaf, signing and rollup are Pro features now; a name vexproof does not know unlocks nothing', () => {
  assert.deepEqual(RESERVED_FEATURES, []);
  for (const feature of ['csaf', 'signing', 'rollup']) assert.ok(PRO_FEATURES.includes(feature), feature);

  const license = verifyLicense(issue({ org: 'Acme', exp: '2027-01-01', features: ['future-thing'] }), { publicKeyPem, now });
  assert.equal(license.valid, true);
  assert.equal(license.pro, false);
  assert.deepEqual(license.features, []);
});

test('license: tampered payload or wrong key fails closed to free', () => {
  const token = issue({ org: 'Acme', exp: '2027-01-01', features: ['modules'] });
  const [prefix, , signature] = token.split('.');
  const forged = `${prefix}.${b64u.enc(JSON.stringify({ org: 'Acme', exp: '2099-01-01', features: ['modules'] }))}.${signature}`;
  assert.equal(verifyLicense(forged, { publicKeyPem, now }).valid, false);

  const other = generateKeyPairSync('ed25519').privateKey;
  assert.equal(verifyLicense(issue({ org: 'Acme', exp: '2027-01-01', features: ['modules'] }, other), { publicKeyPem, now }).valid, false);

  assert.equal(verifyLicense('garbage', { publicKeyPem, now }).valid, false);
});

test('license: 14-day grace after expiry, then free', () => {
  const token = issue({ org: 'Acme', exp: '2026-09-20', features: ['modules'] });

  const inGrace = verifyLicense(token, { publicKeyPem, now });
  assert.equal(inGrace.valid, true);
  assert.match(inGrace.warning, /expired/);

  assert.equal(verifyLicense(token, { publicKeyPem, now: new Date('2026-10-10') }).valid, false);
});

// ---------- baseline and review ----------

const productPurl = 'pkg:npm/ngapp@0.0.0';
function freshTemplateRun() {
  return triage({
    ...angular,
    bundleSbom: readFixture('angular-template.bom.bundle.json'),
    moduleMap: readModuleMap(readFixture('angular-template.metafile.json')),
    rules,
    moduleCheck: evaluateModuleRule,
    pro: true,
  });
}

test('review records a decision; baseline carries it forward and it no longer counts as new', () => {
  const release1 = toCycloneDxVex({ results: freshTemplateRun(), productPurl });
  recordReview(release1, {
    id: 'GHSA-35jh-r3h4-6jhm',
    state: 'not_affected',
    justification: 'code_not_reachable',
    detail: 'template() only receives compile-time constants',
    by: 'brad',
  });

  const results = applyBaseline(freshTemplateRun(), readBaseline(release1));

  const reviewed = results.find((result) => result.id === 'GHSA-35jh-r3h4-6jhm');
  assert.equal(reviewed.state, 'not_affected');
  assert.equal(reviewed.origin, 'reviewed');
  assert.equal(reviewed.reviewedBy, 'brad');
  assert.equal(results.filter((result) => result.isNew).length, 0);
});

test('baseline flags regressions: a package that was absent and is now bundled is new', () => {
  const release1 = toCycloneDxVex({
    results: triage({ ...angular, bundleSbom: { components: [{ purl: 'pkg:npm/rxjs@7.8.2' }] }, rules }),
    productPurl,
  });

  const results = applyBaseline(freshTemplateRun(), readBaseline(release1));

  assert.equal(results.filter((result) => result.isNew).length, 4);
});

test('review rejects incomplete or invalid decisions', () => {
  const vex = toCycloneDxVex({ results: freshTemplateRun(), productPurl });

  assert.throws(() => recordReview(vex, { id: 'GHSA-35jh-r3h4-6jhm', state: 'not_affected', detail: 'x', by: 'b' }), /justification/);
  assert.throws(() => recordReview(vex, { id: 'GHSA-35jh-r3h4-6jhm', state: 'fine', detail: 'x', by: 'b' }), /state must be/);
  assert.throws(() => recordReview(vex, { id: 'GHSA-35jh-r3h4-6jhm', state: 'exploitable', detail: 'x' }), /--by/);
  assert.throws(() => recordReview(vex, { id: 'GHSA-nope', state: 'exploitable', detail: 'x', by: 'b' }), /no statement/);
});

// ---------- report ----------

test('report shows input hashes, evidence and every statement', () => {
  const results = freshTemplateRun();

  const html = renderReport({
    results,
    summary: summarize(results),
    inputs: [{ role: 'lockfile-sbom', path: 'bom.json', sha256: 'abc123' }],
    productPurl,
    license: { org: 'Acme' },
    command: 'vexproof …',
    version: 'test',
  });

  assert.match(html, /sha256 abc123/);
  assert.match(html, /licensed to Acme/);
  assert.match(html, /surviving files/);
  for (const result of results) assert.ok(html.includes(result.id), `report is missing ${result.id}`);
  assert.match(html, /Module-level check: vulnerable file\(s\) bundled: template\.js/);
  assert.match(html, /Applies to all 19 advisories/);
  assert.ok(!/<script/i.test(html));
});

// ---------- CLI behaviour ----------

const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const fixturePath = (name) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
const runArgs = [
  '--lockfile', fixturePath('angular.bom.lockfile.json'),
  '--bundle', fixturePath('angular-template.bom.bundle.json'),
  '--findings', fixturePath('angular.audit.json'),
  ...modulesArgs(fixturePath('angular-template.metafile.json')),
];

test('CLI free: shows a Pro hint, gate on in_triage exits 1, --quiet hides the hint', (testContext) => {
  const dir = temporaryFolder(testContext, 'bvx-');
  const env = { ...process.env, VEXPROOF_LICENSE: '' };

  const gated = spawnSync(
    process.execPath,
    [cli, ...runArgs, '--out', join(dir, 'v.json'), '--fail-on', 'in_triage'],
    { env, cwd: dir, encoding: 'utf8' },
  );
  assert.equal(gated.status, 1);
  assert.match(gated.stderr, /Pro would settle 1 of your 5 open/);
  assert.match(gated.stderr, /hide this with --quiet/);
  assert.doesNotMatch(gated.stderr, /\$\d/, 'the hint names no price; the pricing page does');

  const quiet = spawnSync(
    process.execPath,
    [cli, ...runArgs, '--out', join(dir, 'v.json'), '--quiet'],
    { env, cwd: dir, encoding: 'utf8' },
  );
  assert.equal(quiet.status, 0);
  assert.doesNotMatch(quiet.stderr, /Pro/);
});

test('CLI: invalid license never breaks the build', (testContext) => {
  const dir = temporaryFolder(testContext, 'bvx-');

  const result = spawnSync(
    process.execPath,
    [cli, ...runArgs, '--out', join(dir, 'v.json'), '--license', 'vxp1.bad.token'],
    { cwd: dir, encoding: 'utf8' },
  );

  assert.equal(result.status, 0);
  assert.match(result.stderr, /running free features only/);
});

// A copy of src/ that trusts a key this test made, and a license signed with it: the licensed paths run
// everywhere, CI included, with no private key of the project's.

test('CLI Pro: report, baseline and --fail-on new, with a signed license', (context) => {
  const pro = proCopy(context);
  const cli = pro.cli;
  const dir = temporaryFolder(context, 'bvx-');
  const license = pro.token({ id: randomUUID(), org: 'Test Org' });
  const env = { ...process.env, VEXPROOF_LICENSE: license };
  const firstVex = join(dir, 'v1.json');

  const first = spawnSync(
    process.execPath,
    [cli, ...runArgs, '--out', firstVex, '--report', join(dir, 'r.html')],
    { env, cwd: dir, encoding: 'utf8' },
  );
  assert.equal(first.status, 0, first.stderr);
  assert.ok(existsSync(join(dir, 'r.html')));
  assert.doesNotMatch(first.stderr, /Pro would/);

  // nothing new against itself
  const againstItself = spawnSync(
    process.execPath,
    [cli, ...runArgs, '--out', join(dir, 'v2.json'), '--baseline', firstVex, '--fail-on', 'new'],
    { env, cwd: dir, encoding: 'utf8' },
  );
  assert.equal(againstItself.status, 0, againstItself.stderr);

  // a baseline where lodash-es was absent → the four bundled advisories are new → gate trips
  const old = JSON.parse(readFileSync(firstVex, 'utf8'));
  old.vulnerabilities = old.vulnerabilities.filter(
    (vulnerability) => !vulnerability.properties.some((property) => property.value.includes('lodash-es')),
  );
  writeFileSync(join(dir, 'old.json'), JSON.stringify(old));
  const againstOld = spawnSync(
    process.execPath,
    [cli, ...runArgs, '--out', join(dir, 'v3.json'), '--baseline', join(dir, 'old.json'), '--fail-on', 'new'],
    { env, cwd: dir, encoding: 'utf8' },
  );
  assert.equal(againstOld.status, 1);
  assert.match(againstOld.stderr, /4 new open finding/);
});

// ---------- revocation ----------

test('license: a revoked id is invalid, and the same license without the revocation is not', () => {
  const id = '5d0c1c62-6a1e-4c2b-9f6a-0d8f1a2b3c4d';
  const token = issue({ id, org: 'Acme', exp: '2027-01-01', features: ['modules'] });

  assert.equal(verifyLicense(token, { publicKeyPem, now, revoked: new Set() }).valid, true);

  const revoked = verifyLicense(token, { publicKeyPem, now, revoked: [id.toUpperCase()] });
  assert.equal(revoked.valid, false);
  assert.equal(revoked.revoked, true);
  assert.match(revoked.reason, /license for Acme \(5d0c1c62-.*\) has been revoked/);

  // a forged token can't dodge the list by changing its id: the signature breaks first
  const forgedPayload = b64u.enc(JSON.stringify({ id: 'x', org: 'Acme', exp: '2027-01-01', features: ['modules'] }));
  const forged = token.replace(/\.[^.]+\./, `.${forgedPayload}.`);
  assert.equal(verifyLicense(forged, { publicKeyPem, now, revoked: [] }).valid, false);
});

test('license: the shipped revocation list loads and is well formed', async () => {
  const { loadRevoked } = await import('../src/pro/license.js');

  const doc = JSON.parse(readFileSync(new URL('../src/pro/revoked.json', import.meta.url), 'utf8'));

  assert.ok(Array.isArray(doc.revoked));
  for (const entry of doc.revoked) {
    assert.match(entry.id, /^[0-9a-f-]{36}$/);
    assert.match(entry.date, /^\d{4}-\d{2}-\d{2}$/);
  }
  assert.equal(loadRevoked().size, new Set(doc.revoked.map((entry) => entry.id)).size);
});

test('CLI: a revoked license runs free features and says why', (context) => {
  // a copy of the package that trusts this test's key, and whose revocation list names the license
  const pro = proCopy(context);
  const license = pro.token({ id: randomUUID(), org: 'Revoked Org' });
  const { id } = JSON.parse(b64u.dec(license.split('.')[1]).toString('utf8'));
  const dir = temporaryFolder(context, 'bvx-');
  const env = { ...process.env, VEXPROOF_LICENSE: license };
  const runCopy = (out, report) => spawnSync(
    process.execPath,
    [pro.cli, ...runArgs, '--out', join(dir, out), '--report', join(dir, report)],
    { env, cwd: dir, encoding: 'utf8' },
  );

  // before it is listed, the license works
  const fine = runCopy('v1.json', 'r1.html');
  assert.equal(fine.status, 0, fine.stderr);
  assert.ok(existsSync(join(dir, 'r1.html')));

  // once the package's revocation list names it, the same license runs free features only, and says why
  const revocations = { license: 'LicenseRef-vexproof-Pro', revoked: [{ id, date: '2026-10-11' }] };
  writeFileSync(join(pro.dir, 'src/pro/revoked.json'), JSON.stringify(revocations));
  const revoked = runCopy('v2.json', 'r2.html');
  assert.equal(revoked.status, 0, revoked.stderr);
  assert.match(revoked.stderr, /license for Revoked Org \(.+\) has been revoked; running free features only/);
  assert.ok(!existsSync(join(dir, 'r2.html')));
});
