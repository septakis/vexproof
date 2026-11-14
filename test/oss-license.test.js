// SPDX-License-Identifier: MIT
// Open-source licenses: Pro for free, scoped to named repositories, still verified locally.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyLicense, detectRepository, normalizeRepo, b64u } from '../src/pro/license.js';
import { modulesArgs } from './lib/built.js';
import { temporaryFolder } from './lib/temporary.js';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const issue = (payload) => {
  const head = `vxp1.${b64u.enc(JSON.stringify(payload))}`;
  return `${head}.${b64u.enc(sign(null, Buffer.from(head), privateKey))}`;
};
const now = new Date('2026-09-28T00:00:00Z');
const oss = issue({
  org: 'acme',
  plan: 'oss',
  repos: ['github.com/acme/widget'],
  exp: '2027-09-30',
  features: ['modules', 'report', 'baseline'],
});

test('repository names normalise across remote URL styles', () => {
  const remotes = [
    'git@github.com:Acme/Widget.git',
    'https://github.com/acme/widget',
    'https://github.com/acme/widget.git/',
    'ssh://git@github.com/acme/widget.git',
    'ssh://git@github.com:22/acme/widget',
    'github.com/acme/widget',
  ];
  for (const remote of remotes) assert.equal(normalizeRepo(remote), 'github.com/acme/widget', remote);

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

  const noRepos = issue({ org: 'x', plan: 'oss', exp: '2027-01-01', features: ['modules'] });
  assert.match(verifyLicense(noRepos, { publicKeyPem, now, repo: 'github.com/a/b' }).reason, /names no repositories/);

  const unknownPlan = issue({ org: 'x', plan: 'gold', exp: '2027-01-01', features: ['modules'] });
  assert.equal(verifyLicense(unknownPlan, { publicKeyPem, now }).valid, false);
});

test('a paid license is not tied to a repository', () => {
  const license = verifyLicense(issue({ org: 'Acme', exp: '2027-01-01', features: ['modules'] }), { publicKeyPem, now, repo: null });

  assert.equal(license.valid, true);
  assert.equal(license.plan, 'pro');
});

test('the repository comes from CI variables, else the origin remote', (testContext) => {
  assert.equal(
    detectRepository({ env: { GITHUB_REPOSITORY: 'Acme/Widget', GITHUB_SERVER_URL: 'https://github.com' } }),
    'github.com/acme/widget',
  );
  assert.equal(
    detectRepository({ env: { CI_PROJECT_PATH: 'grp/proj', CI_SERVER_HOST: 'gitlab.example.com' } }),
    'gitlab.example.com/grp/proj',
  );

  const dir = temporaryFolder(testContext, 'vxp-repo-');
  mkdirSync(join(dir, '.git'));
  mkdirSync(join(dir, 'packages/app'), { recursive: true });
  writeFileSync(join(dir, '.git/config'), '[core]\n\tbare = false\n[remote "upstream"]\n\turl = https://github.com/other/fork\n[remote "origin"]\n\turl = git@github.com:acme/widget.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n');

  assert.equal(detectRepository({ env: {}, cwd: join(dir, 'packages/app') }), 'github.com/acme/widget');
  assert.equal(detectRepository({ env: {}, cwd: temporaryFolder(testContext, 'vxp-norepo-') }), null);
});

test('CLI: an issued open-source license works in its repository and not elsewhere', async (context) => {
  // a copy of src/ that trusts a key this test made, so a license signed with it runs everywhere
  const { proCopy } = await import('./lib/pro-copy.js');
  const pro = proCopy(context);
  const license = pro.token({ plan: 'oss', org: 'acme', repos: ['github.com/acme/widget'] });

  const fixturePath = (name) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
  const cli = pro.cli;
  const run = (origin) => {
    const dir = temporaryFolder(context, 'vxp-oss-');
    mkdirSync(join(dir, '.git'));
    writeFileSync(join(dir, '.git/config'), `[remote "origin"]\n\turl = ${origin}\n`);
    const env = { ...process.env, VEXPROOF_LICENSE: license };
    for (const name of ['GITHUB_REPOSITORY', 'CI_PROJECT_PATH', 'BITBUCKET_REPO_FULL_NAME']) delete env[name];
    const result = spawnSync(process.execPath, [
      cli,
      '--lockfile', fixturePath('recharts.bom.lockfile.json'),
      ...modulesArgs(fixturePath('recharts.metafile.json')),
      '--findings', fixturePath('recharts.audit.json'),
      '--out', join(dir, 'v.json'),
      '--report', join(dir, 'r.html'),
    ], { cwd: dir, env, encoding: 'utf8' });

    return { result, dir };
  };

  const ok = run('https://github.com/acme/widget.git');
  assert.equal(ok.result.status, 0, ok.result.stderr);
  assert.doesNotMatch(ok.result.stderr, /free features only/);
  assert.match(readFileSync(join(ok.dir, 'r.html'), 'utf8'), /licensed to acme \(open-source license\)/);

  const no = run('git@github.com:acme/closed.git');
  assert.match(no.result.stderr, /covers github\.com\/acme\/widget, not github\.com\/acme\/closed; running free features only/);
});

test('the repository is found from a git worktree, whose .git file names an absolute git folder', async (context) => {
  const { detectRepository } = await import('../src/pro/license.js');
  const { project, write } = await import('./lib/project.js');
  const main = project(context, { '.git/config': '[remote "origin"]\n\turl = git@github.com:vitejs/vite.git\n' });
  write(main, { '.git/worktrees/feature/commondir': '../..\n', '.git/worktrees/feature/HEAD': 'ref: refs/heads/feature\n' });
  const worktree = project(context, { '.git': `gitdir: ${join(main, '.git', 'worktrees', 'feature')}\n` });

  assert.equal(detectRepository({ env: {}, cwd: main }), 'github.com/vitejs/vite');
  assert.equal(detectRepository({ env: {}, cwd: worktree }), 'github.com/vitejs/vite');
});
