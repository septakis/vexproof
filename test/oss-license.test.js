// SPDX-License-Identifier: MIT
// Open-source licenses: Pro for free, scoped to named repositories, still verified locally.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyLicense, detectRepository, normalizeRepo, b64u } from '../src/pro/license.js';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const issue = (payload) => { const head = `vxp1.${b64u.enc(JSON.stringify(payload))}`; return `${head}.${b64u.enc(sign(null, Buffer.from(head), privateKey))}`; };
const now = new Date('2026-09-28T00:00:00Z');
const oss = issue({ org: 'acme', plan: 'oss', repos: ['github.com/acme/widget'], exp: '2027-09-30', features: ['modules', 'report', 'baseline'] });

test('repository names normalise across remote URL styles', () => {
  for (const u of ['git@github.com:Acme/Widget.git', 'https://github.com/acme/widget', 'https://github.com/acme/widget.git/', 'ssh://git@github.com/acme/widget.git', 'ssh://git@github.com:22/acme/widget', 'github.com/acme/widget'])
    assert.equal(normalizeRepo(u), 'github.com/acme/widget', u);
  assert.equal(normalizeRepo('https://gitlab.com/group/sub/proj.git'), 'gitlab.com/group/sub/proj');
  assert.equal(normalizeRepo('acme/widget'), null); // host required
});

test('an open-source license unlocks Pro only in the repositories it names', () => {
  const here = verifyLicense(oss, { publicKeyPem, now, repo: 'git@github.com:acme/widget.git' });
  assert.equal(here.valid, true);
  assert.equal(here.plan, 'oss');
  assert.deepEqual(here.features, ['modules', 'report', 'baseline']);
  const elsewhere = verifyLicense(oss, { publicKeyPem, now, repo: 'github.com/acme/private-app' });
  assert.equal(elsewhere.valid, false);
  assert.match(elsewhere.reason, /covers github\.com\/acme\/widget, not github\.com\/acme\/private-app/);
  assert.match(verifyLicense(oss, { publicKeyPem, now, repo: null }).reason, /couldn't be identified/);
  assert.match(verifyLicense(issue({ org: 'x', plan: 'oss', exp: '2027-01-01', features: ['modules'] }), { publicKeyPem, now, repo: 'github.com/a/b' }).reason, /names no repositories/);
  assert.equal(verifyLicense(issue({ org: 'x', plan: 'gold', exp: '2027-01-01', features: ['modules'] }), { publicKeyPem, now }).valid, false);
});

test('a paid license is not tied to a repository', () => {
  const l = verifyLicense(issue({ org: 'Acme', exp: '2027-01-01', features: ['modules'] }), { publicKeyPem, now, repo: null });
  assert.equal(l.valid, true);
  assert.equal(l.plan, 'pro');
});

test('the repository comes from CI variables, else the origin remote', () => {
  assert.equal(detectRepository({ env: { GITHUB_REPOSITORY: 'Acme/Widget', GITHUB_SERVER_URL: 'https://github.com' } }), 'github.com/acme/widget');
  assert.equal(detectRepository({ env: { CI_PROJECT_PATH: 'grp/proj', CI_SERVER_HOST: 'gitlab.example.com' } }), 'gitlab.example.com/grp/proj');
  const dir = mkdtempSync(join(tmpdir(), 'vxp-repo-'));
  mkdirSync(join(dir, '.git')); mkdirSync(join(dir, 'packages/app'), { recursive: true });
  writeFileSync(join(dir, '.git/config'), '[core]\n\tbare = false\n[remote "upstream"]\n\turl = https://github.com/other/fork\n[remote "origin"]\n\turl = git@github.com:acme/widget.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n');
  assert.equal(detectRepository({ env: {}, cwd: join(dir, 'packages/app') }), 'github.com/acme/widget');
  assert.equal(detectRepository({ env: {}, cwd: mkdtempSync(join(tmpdir(), 'vxp-norepo-')) }), null);
});

const keyFile = fileURLToPath(new URL('../.keys/license-private.pem', import.meta.url));
test('CLI: an issued open-source license works in its repository and not elsewhere', { skip: !existsSync(keyFile) && 'no signing key' }, () => {
  const issueScript = fileURLToPath(new URL('../scripts/issue-license.js', import.meta.url));
  const lic = execFileSync('node', [issueScript, '--plan', 'oss', '--org', 'acme', '--repos', 'github.com/acme/widget', '--exp', '2099-01-01', '--key', keyFile], { encoding: 'utf8' }).trim();
  assert.equal(spawnSync('node', [issueScript, '--plan', 'oss', '--org', 'acme', '--exp', '2099-01-01', '--key', keyFile]).status, 2); // repos required
  const fx = (f) => fileURLToPath(new URL(`./fixtures/${f}`, import.meta.url));
  const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
  const run = (origin) => {
    const dir = mkdtempSync(join(tmpdir(), 'vxp-oss-'));
    mkdirSync(join(dir, '.git'));
    writeFileSync(join(dir, '.git/config'), `[remote "origin"]\n\turl = ${origin}\n`);
    const env = { ...process.env, VEXPROOF_LICENSE: lic };
    for (const k of ['GITHUB_REPOSITORY', 'CI_PROJECT_PATH', 'BITBUCKET_REPO_FULL_NAME']) delete env[k];
    const r = spawnSync('node', [cli, '--lockfile', fx('recharts.bom.lockfile.json'), '--modules', fx('recharts.metafile.json'), '--findings', fx('recharts.audit.json'), '--out', join(dir, 'v.json'), '--report', join(dir, 'r.html')], { cwd: dir, env, encoding: 'utf8' });
    return { r, dir };
  };
  const ok = run('https://github.com/acme/widget.git');
  assert.equal(ok.r.status, 0, ok.r.stderr);
  assert.doesNotMatch(ok.r.stderr, /free features only/);
  assert.match(readFileSync(join(ok.dir, 'r.html'), 'utf8'), /licensed to acme \(open-source license\)/);
  const no = run('git@github.com:acme/closed.git');
  assert.match(no.r.stderr, /covers github\.com\/acme\/widget, not github\.com\/acme\/closed; running free features only/);
});
