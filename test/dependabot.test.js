// SPDX-License-Identifier: MIT
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { triage, toCycloneDxVex } from '../src/index.js';
import { inVulnerableRange, readDocuments, planAlerts, judge, comment, github, syncDependabot, explain, inScope, GitHubError } from '../src/pro/dependabot.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const sbom = (purls) => ({ bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:11111111-1111-4111-8111-111111111111', version: 1, components: purls.map((purl) => ({ type: 'library', purl, 'bom-ref': purl })) });
const lock = sbom(['pkg:npm/react@18.3.1', 'pkg:npm/lodash@4.17.20', 'pkg:npm/express@4.17.1']);
const bundle = sbom(['pkg:npm/react@18.3.1', 'pkg:npm/express@4.17.1']);
const sha = (o) => createHash('sha256').update(JSON.stringify(o)).digest('hex');
const makeVex = (extra = {}) => {
  const results = triage({ lockfileSbom: lock, bundleSbom: bundle, findings: [
    { purl: 'pkg:npm/lodash@4.17.20', id: 'GHSA-lodash-0001', aliases: ['CVE-2026-0001'] }, // absent → not_affected
    { purl: 'pkg:npm/express@4.17.1', id: 'GHSA-expr-0001', aliases: [] },                    // present → in_triage
  ] });
  const vex = toCycloneDxVex({ results, bundleSbom: bundle, lockfileSbom: lock, productPurl: 'pkg:npm/app@1', inputs: [{ role: 'lockfile-sbom', path: 'l.json', sha256: sha(lock) }], ...extra });
  return vex;
};
const lockEntry = { file: 'l.json', sbom: lock, sha256: sha(lock) };
const alert = (n, name, ghsa, o = {}) => ({
  number: n, state: 'open', html_url: `https://github.com/o/r/security/dependabot/${n}`,
  dependency: { package: { ecosystem: 'npm', name }, manifest_path: 'package-lock.json', scope: 'runtime' },
  security_advisory: { ghsa_id: ghsa, cve_id: null, identifiers: [{ type: 'GHSA', value: ghsa }] },
  security_vulnerability: { vulnerable_version_range: '< 4.17.21' },
  dismissed_by: null, dismissed_comment: null, ...o,
});
const docs = () => readDocuments([{ file: 'vex.json', vex: makeVex() }], [lockEntry]);

test('version ranges as GitHub writes them', () => {
  assert.equal(inVulnerableRange('4.17.20', '< 4.17.21'), true);
  assert.equal(inVulnerableRange('4.17.21', '< 4.17.21'), false);
  assert.equal(inVulnerableRange('4.0.0', '>= 4.0.0, < 4.17.21'), true);
  assert.equal(inVulnerableRange('3.9.9', '>= 4.0.0, < 4.17.21'), false);
  assert.equal(inVulnerableRange('2.0.0', '= 2.0.0'), true);
  assert.equal(inVulnerableRange('2.0.1', '= 2.0.0'), false);
  assert.equal(inVulnerableRange('2.0.0-beta.1', '< 2.0.0'), true);
  assert.equal(inVulnerableRange('1.0.0', 'weird'), true); // unreadable range → still needs a statement
});

test('an alert is dismissed only when the VEX settles it, by its GHSA or CVE', () => {
  const { plan } = planAlerts({ alerts: [alert(1, 'lodash', 'GHSA-lodash-0001'), alert(2, 'express', 'GHSA-expr-0001', { security_vulnerability: { vulnerable_version_range: '< 5.0.0' } }), alert(3, 'lodash', 'GHSA-other-0001')], docs: docs(), scopes: [''] });
  assert.deepEqual(plan.map((p) => p.action), ['dismiss', 'open', 'open']);
  assert.equal(plan[0].body.state, 'dismissed');
  assert.equal(plan[0].body.dismissed_reason, 'not_used');
  assert.match(plan[0].body.dismissed_comment, /^vexproof: lodash@4\.17\.20 is not in the production build/);
  assert.match(plan[1].why, /in triage/);
  assert.match(plan[2].why, /no statement/);
  const byCve = { ...alert(4, 'lodash', 'GHSA-zzz'), security_advisory: { ghsa_id: 'GHSA-zzz', cve_id: 'CVE-2026-0001', identifiers: [] } };
  assert.equal(judge(byCve, docs()).kind, 'settled');
});

test('a version in range that the VEX says nothing about keeps the alert open', () => {
  // react ships, so the bundle SBOM shares a package with the lockfile and can vouch for lodash's absence
  const l2 = sbom(['pkg:npm/lodash@4.17.20', 'pkg:npm/lodash@4.17.19', 'pkg:npm/react@1.0.0']);
  const results = triage({ lockfileSbom: l2, bundleSbom: sbom(['pkg:npm/react@1.0.0']), findings: [{ purl: 'pkg:npm/lodash@4.17.20', id: 'GHSA-lodash-0001', aliases: [] }] });
  const vex = toCycloneDxVex({ results, bundleSbom: bundle, lockfileSbom: l2, productPurl: 'pkg:npm/app@1', inputs: [{ role: 'lockfile-sbom', path: 'l', sha256: sha(l2) }] });
  const d = readDocuments([{ file: 'v', vex }], [{ file: 'l', sbom: l2, sha256: sha(l2) }]);
  const j = judge(alert(1, 'lodash', 'GHSA-lodash-0001'), d);
  assert.equal(j.kind, 'unsettled');
  assert.match(j.why, /lodash@4\.17\.19/);
});

test('alerts for development dependencies and uninstalled versions are not touched', () => {
  const dev = alert(1, 'lodash', 'GHSA-lodash-0001', { security_vulnerability: { vulnerable_version_range: '< 4.0.0' } });
  assert.equal(judge(dev, docs()).kind, 'unknown');
  const devOnly = alert(2, 'jest', 'GHSA-jest-1');
  devOnly.dependency.scope = 'development';
  assert.match(judge(devOnly, docs()).why, /development dependency/);
});

test('vexproof reopens its own dismissals that are no longer settled, and never touches a person\'s', () => {
  const ours = alert(1, 'express', 'GHSA-expr-0001', { state: 'dismissed', dismissed_comment: 'vexproof: earlier run' });
  const theirs = alert(2, 'express', 'GHSA-expr-0001', { state: 'dismissed', dismissed_comment: 'we use a sanitizer', dismissed_by: { login: 'sam' } });
  const still = alert(3, 'lodash', 'GHSA-lodash-0001', { state: 'dismissed', dismissed_comment: 'vexproof: earlier run' });
  const { plan } = planAlerts({ alerts: [ours, theirs, still], docs: docs(), scopes: [''] });
  assert.deepEqual(plan.map((p) => p.action), ['reopen', 'person', 'kept']);
  assert.deepEqual(plan[0].body, { state: 'open' });
  assert.match(plan[1].why, /@sam/);
});

test('a pending dismissal request and non-npm alerts are left alone', () => {
  const pending = alert(1, 'lodash', 'GHSA-lodash-0001', { dismissal_request: { status: 'pending' } });
  const pip = alert(2, 'django', 'GHSA-d'); pip.dependency.package.ecosystem = 'pip';
  const { plan } = planAlerts({ alerts: [pending, pip], docs: docs(), scopes: [''] });
  assert.deepEqual(plan.map((p) => p.action), ['pending']);
});

test('scopes: root by default, a folder, or an exact manifest', () => {
  assert.equal(inScope('package-lock.json', ['']), true);
  assert.equal(inScope('apps/web/package-lock.json', ['']), false);
  assert.equal(inScope('apps/web/package-lock.json', ['apps/web']), true);
  assert.equal(inScope('apps/web/package-lock.json', ['./apps/web/']), true);
  assert.equal(inScope('apps/web/package-lock.json', ['apps/web/package-lock.json']), true);
  assert.equal(inScope('apps/web/yarn.lock', ['apps/web/package-lock.json']), false);
  const p = planAlerts({ alerts: [alert(1, 'lodash', 'GHSA-lodash-0001', { dependency: { package: { ecosystem: 'npm', name: 'lodash' }, manifest_path: 'apps/web/package-lock.json', scope: 'runtime' } })], docs: docs(), scopes: [''] });
  assert.equal(p.plan.length, 0);
  assert.deepEqual(p.elsewhere, ['apps/web/package-lock.json']);
});

test('VEX files it must not act on are refused', () => {
  assert.throws(() => readDocuments([{ file: 'x', vex: { metadata: {} } }], [lockEntry]), /not written by vexproof/);
  assert.throws(() => readDocuments([{ file: 'x', vex: makeVex({ scope: 'browser-bundle' }) }], [lockEntry]), /browser bundle only/);
  assert.throws(() => readDocuments([{ file: 'x', vex: makeVex() }], [{ ...lockEntry, sha256: 'other' }]), /different lockfile SBOM/);
});

test('the dismissal comment fits GitHub\'s 280 characters and keeps the link', () => {
  const c = comment('vexproof: ' + 'x'.repeat(400), 'https://github.com/o/r/actions/runs/1');
  assert.ok(c.length <= 280);
  assert.ok(c.endsWith(' https://github.com/o/r/actions/runs/1'));
});

// ---------- a stand-in for api.github.com ----------
function fakeGitHub(alerts, { patchStatus = {}, flaky = 0 } = {}) {
  const log = [];
  let fails = flaky;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      log.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), auth: req.headers.authorization, body: body ? JSON.parse(body) : null });
      const send = (code, obj, h = {}) => { res.writeHead(code, { 'content-type': 'application/json', ...h }); res.end(JSON.stringify(obj)); };
      if (fails > 0) { fails--; return send(502, { message: 'bad gateway' }); }
      const m = /^\/repos\/o\/r\/dependabot\/alerts(?:\/(\d+))?$/.exec(url.pathname);
      if (!m) return send(404, { message: 'Not Found' });
      if (req.method === 'GET') {
        const page = Number(url.searchParams.get('after') ?? 0), size = 2;
        const next = page + size < alerts.length ? { link: `<http://127.0.0.1:${server.address().port}${url.pathname}?ecosystem=npm&state=open,dismissed&per_page=100&after=${page + size}>; rel="next"` } : {};
        return send(200, alerts.slice(page, page + size), next);
      }
      const a = alerts.find((x) => x.number === Number(m[1]));
      if (patchStatus[a?.number]) return send(patchStatus[a.number], { message: 'Resource not accessible by integration' });
      Object.assign(a, { state: JSON.parse(body).state, dismissed_comment: JSON.parse(body).dismissed_comment ?? null });
      send(200, a);
    });
  });
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => ok({ server, log, url: `http://127.0.0.1:${server.address().port}` })));
}

test('the client follows pagination and sends the headers GitHub asks for', async () => {
  const f = await fakeGitHub([1, 2, 3, 4, 5].map((n) => alert(n, 'lodash', 'GHSA-lodash-0001')));
  try {
    const got = await github({ token: 't0k', repo: 'o/r', apiUrl: f.url }).listAlerts();
    assert.equal(got.length, 5);
    assert.equal(f.log.length, 3);
    assert.equal(f.log[0].auth, 'Bearer t0k');
    assert.equal(f.log[0].query.ecosystem, 'npm');
    assert.equal(f.log[0].query.per_page, '100');
  } finally { f.server.close(); }
});

test('the client retries a 5xx and then gives up with a clear error', async () => {
  const f = await fakeGitHub([alert(1, 'lodash', 'GHSA-lodash-0001')], { flaky: 1 });
  try {
    const got = await github({ token: 't', repo: 'o/r', apiUrl: f.url, sleep: async () => {} }).listAlerts();
    assert.equal(got.length, 1);
  } finally { f.server.close(); }
  const g = await fakeGitHub([], { flaky: 99 });
  try {
    await assert.rejects(github({ token: 't', repo: 'o/r', apiUrl: g.url, sleep: async () => {} }).listAlerts(), (e) => e.status === 502);
  } finally { g.server.close(); }
});

test('sync dismisses and reopens, pausing between writes; a dry run writes nothing', async () => {
  const alerts = [alert(1, 'lodash', 'GHSA-lodash-0001'), alert(2, 'express', 'GHSA-expr-0001', { state: 'dismissed', dismissed_comment: 'vexproof: old' }), alert(3, 'react', 'GHSA-r', { security_vulnerability: { vulnerable_version_range: '< 19.0.0' } })];
  const f = await fakeGitHub(alerts);
  try {
    const client = github({ token: 't', repo: 'o/r', apiUrl: f.url });
    const dry = await syncDependabot({ client, docs: docs(), scopes: [''], dryRun: true });
    assert.deepEqual(dry.plan.map((p) => p.result), ['planned', 'planned', undefined]);
    assert.equal(f.log.filter((l) => l.method === 'PATCH').length, 0);
    const pauses = [];
    const r = await syncDependabot({ client, docs: docs(), scopes: [''], link: 'https://example/run/1', pause: 250, sleep: async (ms) => pauses.push(ms) });
    assert.deepEqual(r.plan.map((p) => p.result), ['done', 'done', undefined]);
    assert.deepEqual(pauses, [250]);
    const patches = f.log.filter((l) => l.method === 'PATCH');
    assert.equal(patches[0].body.dismissed_reason, 'not_used');
    assert.match(patches[0].body.dismissed_comment, /https:\/\/example\/run\/1$/);
    assert.deepEqual(patches[1].body, { state: 'open' });
    assert.equal(alerts[2].state, 'open');
  } finally { f.server.close(); }
});

test('a token that can read but not write stops the run with advice, not a stack trace', async () => {
  const f = await fakeGitHub([alert(1, 'lodash', 'GHSA-lodash-0001')], { patchStatus: { 1: 403 } });
  try {
    const client = github({ token: 't', repo: 'o/r', apiUrl: f.url });
    await assert.rejects(syncDependabot({ client, docs: docs(), scopes: [''], pause: 0 }), (e) => {
      assert.ok(e instanceof GitHubError);
      assert.match(explain(e, 'o/r'), /read Dependabot alerts but not change them/);
      return true;
    });
  } finally { f.server.close(); }
  assert.match(explain(new GitHubError(403, 'x', 'GET'), 'o/r'), /vulnerability-alerts: read/);
  assert.match(explain(new GitHubError(404, 'Not Found', 'GET'), 'o/r'), /not found/);
});

// ---------- the command, end to end ----------
const keyFile = fileURLToPath(new URL('../.keys/license-private.pem', import.meta.url));
const needsKey = { skip: !existsSync(keyFile) && 'no signing key; run npm run keygen' };
const issue = (...a) => execFileSync(process.execPath, [fileURLToPath(new URL('../scripts/issue-license.js', import.meta.url)), '--org', 'Test Org', '--exp', '2099-01-01', '--key', keyFile, ...a], { encoding: 'utf8' }).trim();
const runFree = (args, env) => new Promise((resolve) => {
  const p = spawn(process.execPath, [CLI, 'dependabot', ...args], { env: { PATH: process.env.PATH, ...env }, cwd: tmpdir() });
  let out = '', err = '';
  p.stdout.on('data', (c) => (out += c)); p.stderr.on('data', (c) => (err += c));
  p.on('close', (code) => resolve({ code, out, err }));
});

const run = (args, env) => runFree(args, { VEXPROOF_LICENSE: issue(), ...env });

test('vexproof dependabot: without a license it changes nothing and the job passes', async () => {
  const alerts = [alert(1, 'lodash', 'GHSA-lodash-0001')];
  const f = await fakeGitHub(alerts);
  try {
    const env = { GITHUB_API_URL: f.url, GITHUB_REPOSITORY: 'o/r', GH_TOKEN: 'abc' };
    for (const args of [[], ['--dry-run'], ['--vex', 'v.json', '--lockfile', 'l.json']]) {
      const r = await runFree(args, env);
      assert.equal(r.code, 0, r.err);
      assert.match(r.err, /vexproof dependabot is a Pro feature; no alerts changed/);
    }
    const bad = await runFree([], { ...env, VEXPROOF_LICENSE: 'vxp1.x.y' });
    assert.equal(bad.code, 0, bad.err);
    assert.match(bad.err, /running free features only/);
    assert.match(bad.err, /no alerts changed/);
    assert.equal(alerts[0].state, 'open');
  } finally { f.server.close(); }
});

test('vexproof dependabot: dismisses what the VEX settles and writes the job summary', needsKey, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vxp-dep-'));
  writeFileSync(join(dir, 'lock.json'), JSON.stringify(lock));
  const vex = makeVex();
  vex.metadata.properties.find((p) => p.name === 'vexproof:input:lockfile-sbom:sha256').value = createHash('sha256').update(readFileSync(join(dir, 'lock.json'))).digest('hex');
  writeFileSync(join(dir, 'vex.json'), JSON.stringify(vex));
  const alerts = [alert(1, 'lodash', 'GHSA-lodash-0001'), alert(2, 'express', 'GHSA-expr-0001', { security_vulnerability: { vulnerable_version_range: '< 5.0.0' } })];
  const f = await fakeGitHub(alerts);
  const summary = join(dir, 'summary.md');
  try {
    const env = { GITHUB_API_URL: f.url, GITHUB_REPOSITORY: 'o/r', GH_TOKEN: 'abc', GITHUB_STEP_SUMMARY: summary };
    const r = await run(['--vex', join(dir, 'vex.json'), '--lockfile', join(dir, 'lock.json'), '--manifest', ''], env);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /dismissed\s+#1\s+GHSA-lodash-0001\s+lodash/);
    assert.match(r.out, /left open\s+#2/);
    assert.match(r.out, /1 dismissed, 0 reopened, 1 left open/);
    assert.equal(alerts[0].state, 'dismissed');
    assert.equal(alerts[1].state, 'open');
    assert.match(readFileSync(summary, 'utf8'), /\| \[#1\]/);

    const dry = await run(['--vex', join(dir, 'vex.json'), '--lockfile', join(dir, 'lock.json'), '--manifest', '', '--dry-run'], env);
    assert.equal(dry.code, 0, dry.err);
    assert.match(dry.out, /0 to dismiss/);
  } finally { f.server.close(); }
});

test('vexproof dependabot: asks for what is missing, and previews on a branch that is not the default', needsKey, async () => {
  const none = await run([], {});
  assert.equal(none.code, 2);
  assert.match(none.err, /needs --vex/);
  const dir = mkdtempSync(join(tmpdir(), 'vxp-dep-'));
  writeFileSync(join(dir, 'lock.json'), JSON.stringify(lock));
  const vex = makeVex();
  vex.metadata.properties.find((p) => p.name === 'vexproof:input:lockfile-sbom:sha256').value = createHash('sha256').update(readFileSync(join(dir, 'lock.json'))).digest('hex');
  writeFileSync(join(dir, 'vex.json'), JSON.stringify(vex));
  const args = ['--vex', join(dir, 'vex.json'), '--lockfile', join(dir, 'lock.json'), '--manifest', ''];
  const noTok = await run(args, { GITHUB_REPOSITORY: 'o/r' });
  assert.match(noTok.err, /needs a GitHub token/);
  const alerts = [alert(1, 'lodash', 'GHSA-lodash-0001')];
  const f = await fakeGitHub(alerts);
  try {
    writeFileSync(join(dir, 'event.json'), JSON.stringify({ repository: { default_branch: 'main' } }));
    const r = await run(args, { GITHUB_API_URL: f.url, GITHUB_REPOSITORY: 'o/r', GH_TOKEN: 'x', GITHUB_ACTIONS: 'true', GITHUB_EVENT_PATH: join(dir, 'event.json'), GITHUB_REF: 'refs/pull/5/merge' });
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /previewing only/);
    assert.equal(alerts[0].state, 'open');
  } finally { f.server.close(); }
});

test('vexproof dependabot: a key without the feature, or an open-source key for another repository, changes nothing', needsKey, async () => {
  const noFeature = await runFree([], { VEXPROOF_LICENSE: issue('--features', 'modules,report,baseline') });
  assert.equal(noFeature.code, 0, noFeature.err);
  assert.match(noFeature.err, /no alerts changed/);

  const oss = issue('--plan', 'oss', '--repos', 'github.com/o/r');
  const covered = await runFree([], { VEXPROOF_LICENSE: oss, GITHUB_REPOSITORY: 'o/r' });
  assert.equal(covered.code, 2);
  assert.match(covered.err, /needs --vex/);
  const elsewhere = await runFree(['--repo', 'o/other'], { VEXPROOF_LICENSE: oss, GITHUB_REPOSITORY: 'o/r' });
  assert.equal(elsewhere.code, 0, elsewhere.err);
  assert.match(elsewhere.err, /covers github\.com\/o\/r, not github\.com\/o\/other/);
  assert.match(elsewhere.err, /no alerts changed/);
});

// ---------- which VEX speaks for which alert (code audit of 1.0.0-beta.9) ----------

const onManifest = (n, manifest) => alert(n, 'lodash', 'GHSA-lodash-0001', { dependency: { package: { ecosystem: 'npm', name: 'lodash' }, manifest_path: manifest, scope: 'runtime' } });

test("one application's VEX never settles another application's alert", () => {
  const a = docs();
  // two scopes, one VEX: refused, rather than judging app B's alert by app A's VEX
  assert.throws(() => planAlerts({ alerts: [onManifest(7, 'apps/b/package-lock.json')], docs: a, scopes: ['apps/a', 'apps/b'] }), /one --vex for each/);
  // paired in order: app A's VEX judges app A's alert, and only app B's VEX (which ships lodash) judges app B's
  const shipsLodash = sbom(['pkg:npm/react@18.3.1', 'pkg:npm/lodash@4.17.20']);
  const bResults = triage({ lockfileSbom: lock, bundleSbom: shipsLodash, findings: [{ purl: 'pkg:npm/lodash@4.17.20', id: 'GHSA-lodash-0001', aliases: [] }] });
  const bVex = readDocuments([{ file: 'b.json', vex: toCycloneDxVex({ results: bResults, bundleSbom: shipsLodash, lockfileSbom: lock, productPurl: 'pkg:npm/b@1', inputs: [{ role: 'lockfile-sbom', path: 'l.json', sha256: sha(lock) }] }) }], [lockEntry]);
  const { plan } = planAlerts({ alerts: [onManifest(1, 'apps/a/package-lock.json'), onManifest(2, 'apps/b/package-lock.json')], docs: [...a, ...bVex], scopes: ['apps/a', 'apps/b'] });
  assert.deepEqual(plan.map((i) => i.action), ['dismiss', 'open']);
});

test("a workspace's root lockfile is judged only by a VEX for the root package", () => {
  const root = (m) => (m === 'package-lock.json' ? 'monorepo' : null);
  const { plan } = planAlerts({ alerts: [onManifest(1, 'package-lock.json')], docs: docs(), scopes: [''], workspaceRoot: root });
  assert.equal(plan[0].action, 'open');
  assert.match(plan[0].why, /lockfile of the workspace monorepo, and vex\.json speaks for app only/);
  // a VEX made for the root package itself may
  const forRoot = readDocuments([{ file: 'vex.json', vex: makeVex({ productPurl: 'pkg:npm/monorepo@1' }) }], [lockEntry]);
  assert.equal(planAlerts({ alerts: [onManifest(1, 'package-lock.json')], docs: forRoot, scopes: [''], workspaceRoot: root }).plan[0].action, 'dismiss');
});

test('alert package names are matched without regard to case', () => {
  const upper = alert(1, 'LoDash', 'GHSA-lodash-0001');
  assert.equal(judge(upper, docs()).kind, 'settled');
});
