// SPDX-License-Identifier: MIT
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { triage, toCycloneDxVex } from '../src/index.js';
import {
  inVulnerableRange, readDocuments, planAlerts, judge, comment, github, syncDependabot, explain, inScope, GitHubError, markdownSummary,
} from '../src/pro/dependabot.js';
import * as dependabotModule from '../src/pro/dependabot.js';
import { proCopy } from './lib/pro-copy.js';
import { temporaryFolder } from './lib/temporary.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const sbom = (purls) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: 'urn:uuid:11111111-1111-4111-8111-111111111111',
  version: 1,
  components: purls.map((purl) => ({ type: 'library', purl, 'bom-ref': purl })),
});
const lock = sbom(['pkg:npm/react@18.3.1', 'pkg:npm/lodash@4.17.20', 'pkg:npm/express@4.17.1']);
const bundle = sbom(['pkg:npm/react@18.3.1', 'pkg:npm/express@4.17.1']);
const sha = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const makeVex = (extra = {}) => {
  const results = triage({ lockfileSbom: lock, bundleSbom: bundle, findings: [
    { purl: 'pkg:npm/lodash@4.17.20', id: 'GHSA-lodash-0001', aliases: ['CVE-2026-0001'] }, // absent → not_affected
    { purl: 'pkg:npm/express@4.17.1', id: 'GHSA-expr-0001', aliases: [] },                    // present → in_triage
  ] });
  const vex = toCycloneDxVex({
    results,
    bundleSbom: bundle,
    lockfileSbom: lock,
    productPurl: 'pkg:npm/app@1',
    inputs: [{ role: 'lockfile-sbom', path: 'l.json', sha256: sha(lock) }],
    ...extra,
  });

  return vex;
};
const lockEntry = { file: 'l.json', sbom: lock, sha256: sha(lock) };
const alert = (number, name, ghsa, overrides = {}) => ({
  number, state: 'open', html_url: `https://github.com/o/r/security/dependabot/${number}`,
  dependency: { package: { ecosystem: 'npm', name }, manifest_path: 'package-lock.json', scope: 'runtime' },
  security_advisory: { ghsa_id: ghsa, cve_id: null, identifiers: [{ type: 'GHSA', value: ghsa }] },
  security_vulnerability: { vulnerable_version_range: '< 4.17.21' },
  dismissed_by: null, dismissed_comment: null, ...overrides,
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
  assert.equal(inVulnerableRange('9.0.0', '>= 4.0.0, < 4.17.21, weird'), true); // one unreadable part is enough
  assert.equal(inVulnerableRange('4.17.30', '>= 4.0.0, <= 4.17'), true); // "<= 4.17" is every 4.17.x
});

test('an alert is dismissed only when the VEX settles it, by its GHSA or CVE', () => {
  const alerts = [
    alert(1, 'lodash', 'GHSA-lodash-0001'),
    alert(2, 'express', 'GHSA-expr-0001', { security_vulnerability: { vulnerable_version_range: '< 5.0.0' } }),
    alert(3, 'lodash', 'GHSA-other-0001'),
  ];

  const { plan } = planAlerts({ alerts, docs: docs(), scopes: [''] });

  assert.deepEqual(plan.map((item) => item.action), ['dismiss', 'open', 'open']);
  assert.equal(plan[0].body.state, 'dismissed');
  assert.equal(plan[0].body.dismissed_reason, 'not_used');
  assert.match(plan[0].body.dismissed_comment, /^vexproof: lodash@4\.17\.20 is not in the production build/);
  assert.match(plan[1].why, /in triage/);
  assert.match(plan[2].why, /no statement/);

  const byCve = {
    ...alert(4, 'lodash', 'GHSA-zzz'),
    security_advisory: { ghsa_id: 'GHSA-zzz', cve_id: 'CVE-2026-0001', identifiers: [] },
  };
  assert.equal(judge(byCve, docs()).kind, 'settled');
});

test('a version in range that the VEX says nothing about keeps the alert open', () => {
  // react ships, so the bundle SBOM shares a package with the lockfile and can vouch for lodash's absence
  const twoLodashLock = sbom(['pkg:npm/lodash@4.17.20', 'pkg:npm/lodash@4.17.19', 'pkg:npm/react@1.0.0']);
  const reactOnlyBundle = sbom(['pkg:npm/react@1.0.0']);
  const results = triage({
    lockfileSbom: twoLodashLock,
    bundleSbom: reactOnlyBundle,
    findings: [{ purl: 'pkg:npm/lodash@4.17.20', id: 'GHSA-lodash-0001', aliases: [] }],
  });
  const vex = toCycloneDxVex({
    results,
    bundleSbom: reactOnlyBundle,
    lockfileSbom: twoLodashLock,
    productPurl: 'pkg:npm/app@1',
    inputs: [{ role: 'lockfile-sbom', path: 'l', sha256: sha(twoLodashLock) }],
  });
  const documents = readDocuments([{ file: 'v', vex }], [{ file: 'l', sbom: twoLodashLock, sha256: sha(twoLodashLock) }]);

  const verdict = judge(alert(1, 'lodash', 'GHSA-lodash-0001'), documents);

  assert.equal(verdict.kind, 'unsettled');
  assert.match(verdict.why, /lodash@4\.17\.19/);
});

test('alerts for development dependencies and uninstalled versions are not touched', () => {
  const notInstalled = alert(1, 'lodash', 'GHSA-lodash-0001', { security_vulnerability: { vulnerable_version_range: '< 4.0.0' } });
  assert.equal(judge(notInstalled, docs()).kind, 'unknown');

  const devOnly = alert(2, 'jest', 'GHSA-jest-1');
  devOnly.dependency.scope = 'development';
  assert.match(judge(devOnly, docs()).why, /development dependency/);
});

test('vexproof reopens its own dismissals that are no longer settled, and never touches a person\'s', () => {
  const ours = alert(1, 'express', 'GHSA-expr-0001', {
    state: 'dismissed',
    dismissed_comment: 'vexproof: express@4.17.1 is not in the production build (code_not_present).',
  });
  const theirs = alert(2, 'express', 'GHSA-expr-0001', {
    state: 'dismissed',
    dismissed_comment: 'we use a sanitizer',
    dismissed_by: { login: 'sam' },
  });
  const still = alert(3, 'lodash', 'GHSA-lodash-0001', {
    state: 'dismissed',
    dismissed_comment: 'vexproof: lodash@4.17.20 is not in the production build (code_not_present).',
  });

  const { plan } = planAlerts({ alerts: [ours, theirs, still], docs: docs(), scopes: [''] });

  assert.deepEqual(plan.map((item) => item.action), ['reopen', 'person', 'kept']);
  assert.deepEqual(plan[0].body, { state: 'open' });
  assert.match(plan[1].why, /@sam/);
});

test('a pending dismissal request and non-npm alerts are left alone', () => {
  const pending = alert(1, 'lodash', 'GHSA-lodash-0001', { dismissal_request: { status: 'pending' } });
  const pip = alert(2, 'django', 'GHSA-d');
  pip.dependency.package.ecosystem = 'pip';

  const { plan } = planAlerts({ alerts: [pending, pip], docs: docs(), scopes: [''] });

  assert.deepEqual(plan.map((item) => item.action), ['pending']);
});

test('scopes: root by default, a folder, or an exact manifest', () => {
  assert.equal(inScope('package-lock.json', ['']), true);
  assert.equal(inScope('apps/web/package-lock.json', ['']), false);
  assert.equal(inScope('apps/web/package-lock.json', ['apps/web']), true);
  assert.equal(inScope('apps/web/package-lock.json', ['./apps/web/']), true);
  assert.equal(inScope('apps/web/package-lock.json', ['apps/web/package-lock.json']), true);
  assert.equal(inScope('apps/web/yarn.lock', ['apps/web/package-lock.json']), false);

  const inWeb = alert(1, 'lodash', 'GHSA-lodash-0001', {
    dependency: { package: { ecosystem: 'npm', name: 'lodash' }, manifest_path: 'apps/web/package-lock.json', scope: 'runtime' },
  });
  const planned = planAlerts({ alerts: [inWeb], docs: docs(), scopes: [''] });
  assert.equal(planned.plan.length, 0);
  assert.deepEqual(planned.elsewhere, ['apps/web/package-lock.json']);
});

test('VEX files it must not act on are refused', () => {
  assert.throws(() => readDocuments([{ file: 'x', vex: { metadata: {} } }], [lockEntry]), /not written by vexproof/);
  assert.throws(() => readDocuments([{ file: 'x', vex: makeVex({ scope: 'browser-bundle' }) }], [lockEntry]), /browser bundle only/);
  assert.throws(() => readDocuments([{ file: 'x', vex: makeVex() }], [{ ...lockEntry, sha256: 'other' }]), /different lockfile SBOM/);
});

test('the dismissal comment fits GitHub\'s 280 characters and keeps the link', () => {
  const shortened = comment('vexproof: ' + 'x'.repeat(400), 'https://github.com/o/r/actions/runs/1');

  assert.ok(shortened.length <= 280);
  assert.ok(shortened.endsWith(' https://github.com/o/r/actions/runs/1'));
});

test('a link too long to leave room for the reason is left out of the comment', () => {
  const longLink = `https://github.com/o/r/actions/runs/1?${'q'.repeat(300)}`;

  const written = comment('vexproof: lodash@4.17.21 is not in the production build (code_not_present).', longLink);

  assert.ok(written.length <= 280);
  assert.equal(written, 'vexproof: lodash@4.17.21 is not in the production build (code_not_present).');
});

test('a reopen GitHub did not apply is reported as unchanged, not done', async () => {
  const dismissedByVexproof = alert(2, 'express', 'GHSA-expr-0001', {
    state: 'dismissed',
    dismissed_comment: 'vexproof: express@4.17.1 is not in the production build (code_not_present).',
  });
  const client = {
    listAlerts: async () => [dismissedByVexproof],
    // GitHub answers, but the alert stays dismissed
    updateAlert: async () => ({ ...dismissedByVexproof }),
  };

  const synced = await syncDependabot({ client, docs: docs(), scopes: [''], pause: 0 });

  assert.deepEqual(synced.plan.map((item) => [item.action, item.result]), [['reopen', 'unchanged']]);
});

test('the job summary keeps each alert on one table row', () => {
  const plan = [{
    action: 'dismiss',
    result: 'done',
    why: 'not in the build\nsecond line | with a pipe',
    alert: alert(1, 'lodash', 'GHSA-lodash-0001'),
  }];

  const summary = markdownSummary({ repo: 'o/r', plan, dryRun: false });

  const row = summary.split('\n').find((line) => line.startsWith('| [#1]'));
  assert.match(row, /not in the build second line \\\| with a pipe \|$/);
});

// ---------- a stand-in for api.github.com ----------
function fakeGitHub(alerts, { patchStatus = {}, flaky = 0 } = {}) {
  const log = [];
  let fails = flaky;
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => (body += chunk));
    request.on('end', () => {
      const url = new URL(request.url, 'http://x');
      log.push({
        method: request.method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams),
        auth: request.headers.authorization,
        body: body ? JSON.parse(body) : null,
      });
      const send = (status, payload, headers = {}) => {
        response.writeHead(status, { 'content-type': 'application/json', ...headers });
        response.end(JSON.stringify(payload));
      };
      if (fails > 0) {
        fails--;
        return send(502, { message: 'bad gateway' });
      }
      const match = /^\/repos\/o\/r\/dependabot\/alerts(?:\/(\d+))?$/.exec(url.pathname);
      if (!match) {
        return send(404, { message: 'Not Found' });
      }
      if (request.method === 'GET') {
        const page = Number(url.searchParams.get('after') ?? 0);
        const size = 2;
        const origin = `http://127.0.0.1:${server.address().port}`;
        const nextUrl = `${origin}${url.pathname}?ecosystem=npm&state=open,dismissed&per_page=100&after=${page + size}`;
        const next = page + size < alerts.length ? { link: `<${nextUrl}>; rel="next"` } : {};
        return send(200, alerts.slice(page, page + size), next);
      }
      const target = alerts.find((candidate) => candidate.number === Number(match[1]));
      if (patchStatus[target?.number]) {
        return send(patchStatus[target.number], { message: 'Resource not accessible by integration' });
      }
      Object.assign(target, { state: JSON.parse(body).state, dismissed_comment: JSON.parse(body).dismissed_comment ?? null });
      send(200, target);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, log, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

test('the client follows pagination and sends the headers GitHub asks for', async () => {
  const fake = await fakeGitHub([1, 2, 3, 4, 5].map((number) => alert(number, 'lodash', 'GHSA-lodash-0001')));
  try {
    const got = await github({ token: 't0k', repo: 'o/r', apiUrl: fake.url }).listAlerts();

    assert.equal(got.length, 5);
    assert.equal(fake.log.length, 3);
    assert.equal(fake.log[0].auth, 'Bearer t0k');
    assert.equal(fake.log[0].query.ecosystem, 'npm');
    assert.equal(fake.log[0].query.per_page, '100');
  } finally {
    fake.server.close();
  }
});

test('the client retries a 5xx and then gives up with a clear error', async () => {
  const flaky = await fakeGitHub([alert(1, 'lodash', 'GHSA-lodash-0001')], { flaky: 1 });
  try {
    const got = await github({ token: 't', repo: 'o/r', apiUrl: flaky.url, sleep: async () => {} }).listAlerts();
    assert.equal(got.length, 1);
  } finally {
    flaky.server.close();
  }

  const down = await fakeGitHub([], { flaky: 99 });
  try {
    const client = github({ token: 't', repo: 'o/r', apiUrl: down.url, sleep: async () => {} });
    await assert.rejects(client.listAlerts(), (error) => error.status === 502);
  } finally {
    down.server.close();
  }
});

test('sync dismisses and reopens, pausing between writes; a dry run writes nothing', async () => {
  const alerts = [
    alert(1, 'lodash', 'GHSA-lodash-0001'),
    alert(2, 'express', 'GHSA-expr-0001', {
      state: 'dismissed',
      dismissed_comment: 'vexproof: express@4.17.1 is not in the production build (code_not_present).',
    }),
    alert(3, 'react', 'GHSA-r', { security_vulnerability: { vulnerable_version_range: '< 19.0.0' } }),
  ];
  const fake = await fakeGitHub(alerts);
  try {
    const client = github({ token: 't', repo: 'o/r', apiUrl: fake.url });

    const dry = await syncDependabot({ client, docs: docs(), scopes: [''], dryRun: true });
    assert.deepEqual(dry.plan.map((item) => item.result), ['planned', 'planned', undefined]);
    assert.equal(fake.log.filter((request) => request.method === 'PATCH').length, 0);

    const pauses = [];
    const synced = await syncDependabot({
      client,
      docs: docs(),
      scopes: [''],
      link: 'https://example/run/1',
      pause: 250,
      sleep: async (milliseconds) => pauses.push(milliseconds),
    });
    assert.deepEqual(synced.plan.map((item) => item.result), ['done', 'done', undefined]);
    assert.deepEqual(pauses, [250]);
    const patches = fake.log.filter((request) => request.method === 'PATCH');
    assert.equal(patches[0].body.dismissed_reason, 'not_used');
    assert.match(patches[0].body.dismissed_comment, /https:\/\/example\/run\/1$/);
    assert.deepEqual(patches[1].body, { state: 'open' });
    assert.equal(alerts[2].state, 'open');
  } finally {
    fake.server.close();
  }
});

test('a token that can read but not write stops the run with advice, not a stack trace', async () => {
  const fake = await fakeGitHub([alert(1, 'lodash', 'GHSA-lodash-0001')], { patchStatus: { 1: 403 } });
  try {
    const client = github({ token: 't', repo: 'o/r', apiUrl: fake.url });

    await assert.rejects(syncDependabot({ client, docs: docs(), scopes: [''], pause: 0 }), (error) => {
      assert.ok(error instanceof GitHubError);
      assert.match(explain(error, 'o/r'), /read Dependabot alerts but not change them/);
      return true;
    });
  } finally {
    fake.server.close();
  }

  assert.match(explain(new GitHubError(403, 'x', 'GET'), 'o/r'), /vulnerability-alerts: read/);
  assert.match(explain(new GitHubError(404, 'Not Found', 'GET'), 'o/r'), /not found/);
});

// ---------- the command, end to end ----------
const runCli = (cli, args, env) => new Promise((resolve) => {
  const child = spawn(process.execPath, [cli, 'dependabot', ...args], { env: { PATH: process.env.PATH, ...env }, cwd: tmpdir() });
  let out = '';
  let err = '';
  child.stdout.on('data', (chunk) => (out += chunk));
  child.stderr.on('data', (chunk) => (err += chunk));
  child.on('close', (code) => resolve({ code, out, err }));
});
const runFree = (args, env) => runCli(CLI, args, env);

/**
 * A copy of src/ that trusts a key this test made, `issue` signing licenses for it (with every Pro feature unless
 * the payload says otherwise), and `run` running the command there with such a license: the licensed paths run
 * everywhere, CI included.
 */
function licensed(context) {
  const pro = proCopy(context);
  const issue = (payload = {}) => pro.token({ org: 'Test Org', ...payload });
  const run = (args, env) => runCli(pro.cli, args, { VEXPROOF_LICENSE: issue(), ...env });
  const runWith = (license, args, env) => runCli(pro.cli, args, { VEXPROOF_LICENSE: license, ...env });

  return { issue, run, runWith };
}

test('vexproof dependabot: without a license it changes nothing and the job passes', async () => {
  const alerts = [alert(1, 'lodash', 'GHSA-lodash-0001')];
  const fake = await fakeGitHub(alerts);
  try {
    const env = { GITHUB_API_URL: fake.url, GITHUB_REPOSITORY: 'o/r', GH_TOKEN: 'abc' };

    for (const args of [[], ['--dry-run'], ['--vex', 'v.json', '--lockfile', 'l.json']]) {
      const result = await runFree(args, env);
      assert.equal(result.code, 0, result.err);
      assert.match(result.err, /vexproof dependabot is a Pro feature; no alerts changed/);
    }

    const bad = await runFree([], { ...env, VEXPROOF_LICENSE: 'vxp1.x.y' });
    assert.equal(bad.code, 0, bad.err);
    assert.match(bad.err, /running free features only/);
    assert.match(bad.err, /no alerts changed/);
    assert.equal(alerts[0].state, 'open');
  } finally {
    fake.server.close();
  }
});

test('vexproof dependabot: dismisses what the VEX settles and writes the job summary', async (context) => {
  const { run } = licensed(context);
  const dir = temporaryFolder(context, 'vxp-dep-');
  writeFileSync(join(dir, 'lock.json'), JSON.stringify(lock));
  const vex = makeVex();
  const lockHash = createHash('sha256').update(readFileSync(join(dir, 'lock.json'))).digest('hex');
  vex.metadata.properties.find((property) => property.name === 'vexproof:input:lockfile-sbom:sha256').value = lockHash;
  writeFileSync(join(dir, 'vex.json'), JSON.stringify(vex));
  const alerts = [
    alert(1, 'lodash', 'GHSA-lodash-0001'),
    alert(2, 'express', 'GHSA-expr-0001', { security_vulnerability: { vulnerable_version_range: '< 5.0.0' } }),
  ];
  const fake = await fakeGitHub(alerts);
  const summary = join(dir, 'summary.md');
  try {
    const env = { GITHUB_API_URL: fake.url, GITHUB_REPOSITORY: 'o/r', GH_TOKEN: 'abc', GITHUB_STEP_SUMMARY: summary };

    const result = await run(['--vex', join(dir, 'vex.json'), '--lockfile', join(dir, 'lock.json'), '--manifest', '.'], env);
    assert.equal(result.code, 0, result.err);
    assert.match(result.out, /dismissed\s+#1\s+GHSA-lodash-0001\s+lodash/);
    assert.match(result.out, /left open\s+#2/);
    assert.match(result.out, /1 dismissed, 0 reopened, 1 left open/);
    assert.equal(alerts[0].state, 'dismissed');
    assert.equal(alerts[1].state, 'open');
    assert.match(readFileSync(summary, 'utf8'), /\| \[#1\]/);

    const dry = await run(['--vex', join(dir, 'vex.json'), '--lockfile', join(dir, 'lock.json'), '--manifest', '.', '--dry-run'], env);
    assert.equal(dry.code, 0, dry.err);
    assert.match(dry.out, /0 to dismiss/);
  } finally {
    fake.server.close();
  }
});

test('vexproof dependabot: asks for what is missing, and previews on a branch that is not the default', async (context) => {
  const { run } = licensed(context);

  const none = await run([], {});
  assert.equal(none.code, 2);
  assert.match(none.err, /needs --vex/);

  const dir = temporaryFolder(context, 'vxp-dep-');
  writeFileSync(join(dir, 'lock.json'), JSON.stringify(lock));
  const vex = makeVex();
  const lockHash = createHash('sha256').update(readFileSync(join(dir, 'lock.json'))).digest('hex');
  vex.metadata.properties.find((property) => property.name === 'vexproof:input:lockfile-sbom:sha256').value = lockHash;
  writeFileSync(join(dir, 'vex.json'), JSON.stringify(vex));
  const args = ['--vex', join(dir, 'vex.json'), '--lockfile', join(dir, 'lock.json'), '--manifest', '.'];

  const noToken = await run(args, { GITHUB_REPOSITORY: 'o/r' });
  assert.match(noToken.err, /needs a GitHub token/);

  const alerts = [alert(1, 'lodash', 'GHSA-lodash-0001')];
  const fake = await fakeGitHub(alerts);
  try {
    writeFileSync(join(dir, 'event.json'), JSON.stringify({ repository: { default_branch: 'main' } }));

    const result = await run(args, {
      GITHUB_API_URL: fake.url,
      GITHUB_REPOSITORY: 'o/r',
      GH_TOKEN: 'x',
      GITHUB_ACTIONS: 'true',
      GITHUB_EVENT_PATH: join(dir, 'event.json'),
      GITHUB_REF: 'refs/pull/5/merge',
    });

    assert.equal(result.code, 0, result.err);
    assert.match(result.err, /previewing only/);
    assert.equal(alerts[0].state, 'open');
  } finally {
    fake.server.close();
  }
});

test('vexproof dependabot: a key without the feature, or an open-source key for another repository, changes nothing', async (context) => {
  const { issue, runWith } = licensed(context);

  const noFeature = await runWith(issue({ features: ['modules', 'report', 'baseline'] }), [], {});
  assert.equal(noFeature.code, 0, noFeature.err);
  assert.match(noFeature.err, /no alerts changed/);

  const oss = issue({ plan: 'oss', repos: ['github.com/o/r'] });
  const covered = await runWith(oss, [], { GITHUB_REPOSITORY: 'o/r' });
  assert.equal(covered.code, 2);
  assert.match(covered.err, /needs --vex/);

  const elsewhere = await runWith(oss, ['--repo', 'o/other'], { GITHUB_REPOSITORY: 'o/r' });
  assert.equal(elsewhere.code, 0, elsewhere.err);
  assert.match(elsewhere.err, /covers github\.com\/o\/r, not github\.com\/o\/other/);
  assert.match(elsewhere.err, /no alerts changed/);
});

// ---------- which VEX speaks for which alert (code audit of 1.0.0-beta.9) ----------

const onManifest = (number, manifest) => alert(number, 'lodash', 'GHSA-lodash-0001', {
  dependency: { package: { ecosystem: 'npm', name: 'lodash' }, manifest_path: manifest, scope: 'runtime' },
});

test("one application's VEX never settles another application's alert", () => {
  const docsForA = docs();
  // two scopes, one VEX: refused, rather than judging app B's alert by app A's VEX
  assert.throws(
    () => planAlerts({ alerts: [onManifest(7, 'apps/b/package-lock.json')], docs: docsForA, scopes: ['apps/a', 'apps/b'] }),
    /one --vex for each/,
  );

  // paired in order: app A's VEX judges app A's alert, and only app B's VEX (which ships lodash) judges app B's
  const shipsLodash = sbom(['pkg:npm/react@18.3.1', 'pkg:npm/lodash@4.17.20']);
  const bResults = triage({
    lockfileSbom: lock,
    bundleSbom: shipsLodash,
    findings: [{ purl: 'pkg:npm/lodash@4.17.20', id: 'GHSA-lodash-0001', aliases: [] }],
  });
  const bVexDocument = toCycloneDxVex({
    results: bResults,
    bundleSbom: shipsLodash,
    lockfileSbom: lock,
    productPurl: 'pkg:npm/b@1',
    inputs: [{ role: 'lockfile-sbom', path: 'l.json', sha256: sha(lock) }],
  });
  const bVex = readDocuments([{ file: 'b.json', vex: bVexDocument }], [lockEntry]);
  const { plan } = planAlerts({
    alerts: [onManifest(1, 'apps/a/package-lock.json'), onManifest(2, 'apps/b/package-lock.json')],
    docs: [...docsForA, ...bVex],
    scopes: ['apps/a', 'apps/b'],
  });
  assert.deepEqual(plan.map((item) => item.action), ['dismiss', 'open']);
});

test("a workspace's root lockfile is judged only by a VEX for the root package", () => {
  const root = (manifest) => (manifest === 'package-lock.json' ? 'monorepo' : null);

  const { plan } = planAlerts({ alerts: [onManifest(1, 'package-lock.json')], docs: docs(), scopes: [''], workspaceRoot: root });
  assert.equal(plan[0].action, 'open');
  assert.match(plan[0].why, /lockfile of the workspace monorepo, and vex\.json speaks for app only/);

  // a VEX made for the root package itself may
  const forRoot = readDocuments([{ file: 'vex.json', vex: makeVex({ productPurl: 'pkg:npm/monorepo@1' }) }], [lockEntry]);
  const rootPlan = planAlerts({ alerts: [onManifest(1, 'package-lock.json')], docs: forRoot, scopes: [''], workspaceRoot: root });
  assert.equal(rootPlan.plan[0].action, 'dismiss');
});

test('alert package names are matched without regard to case', () => {
  const upper = alert(1, 'LoDash', 'GHSA-lodash-0001');
  assert.equal(judge(upper, docs()).kind, 'settled');
});

test("only a comment vexproof wrote makes a dismissal vexproof's own; a person's that starts the same is left alone", () => {
  const person = alert(9, 'express', 'GHSA-expr-0001', {
    state: 'dismissed',
    dismissed_comment: 'vexproof: not our problem, see the ticket',
    dismissed_by: { login: 'sam' },
  });
  const { plan } = planAlerts({ alerts: [person], docs: docs(), scopes: [''] });
  assert.equal(plan[0].action, 'person');

  // the comments vexproof writes are recognised, also cut short at GitHub's limit
  const { writtenByVexproof } = dependabotModule;
  assert.ok(writtenByVexproof('vexproof: lodash@4.17.20 is not in the production build (code_not_present). https://example/run/1'));
  assert.ok(writtenByVexproof('vexproof: lodash@4.17.20: not affected, code_not_reachable, reviewed by Jane. omit() only gets fixed keys and so on and…'));
  assert.ok(!writtenByVexproof('vexproof: old'));
});

test('GitHub calls time out, retry a 429 and a secondary rate limit, and explain a used-up rate limit', async () => {
  const signals = [];
  const replies = [
    { status: 429, headers: {} },
    { status: 403, headers: { 'retry-after': '1' }, body: { message: 'You have exceeded a secondary rate limit' } },
    { status: 200, headers: {}, body: [] },
  ];
  const fetchImpl = async (url, init) => {
    signals.push(Boolean(init.signal));
    const reply = replies.shift();
    return {
      ok: reply.status < 300,
      status: reply.status,
      headers: { get: (name) => reply.headers[name] ?? null },
      json: async () => reply.body,
      text: async () => JSON.stringify(reply.body ?? {}),
    };
  };
  const client = github({ token: 't', repo: 'o/r', apiUrl: 'https://api.example', fetchImpl, sleep: async () => {} });

  assert.deepEqual(await client.listAlerts(), []);
  assert.deepEqual(signals, [true, true, true]);

  const limited = github({
    token: 't',
    repo: 'o/r',
    apiUrl: 'https://api.example',
    sleep: async () => {},
    fetchImpl: async () => ({
      ok: false,
      status: 403,
      headers: { get: (name) => ({ 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1800000000' })[name] ?? null },
      text: async () => '{"message":"API rate limit exceeded"}',
    }),
  });
  await assert.rejects(limited.listAlerts(), (error) => {
    assert.match(explain(error, 'o/r'), /used up its GitHub API rate limit; it resets at 2027-01-15T08:00:00\.000Z/);
    return true;
  });
});
