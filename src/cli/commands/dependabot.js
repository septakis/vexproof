// SPDX-License-Identifier: MIT
// vexproof dependabot (Pro): apply a VEX to the repository's Dependabot npm alerts. This file only reads the
// command line and the environment; what happens to each alert is src/pro/dependabot.js's.
import { readFileSync, appendFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { VERSION } from '../../index.js';
import { Stop, EXIT } from '../../stop.js';
import { pro, readJson, sha256, log, loadLicense, licensedFor } from '../common.js';

/** A git command's output, or null when it fails (no git, not a checkout). */
function git(...args) {
  try {
    return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return null;
  }
}

/** The repository whose alerts change: --repo, then GITHUB_REPOSITORY, then the origin remote. */
function repositoryOf(options, env) {
  const origin = /github\.com[:/]([^/]+\/[^/]+?)(?:\.git)?\/?$/.exec(git('config', '--get', 'remote.origin.url') ?? '')?.[1];
  const repo = options.repo ?? env.GITHUB_REPOSITORY ?? origin;
  if (!repo || !/^[^/\s]+\/[^/\s]+$/.test(repo)) throw new Stop('pass --repo owner/name (the repository whose Dependabot alerts to change)');

  return repo;
}

/** Whether to change nothing: --dry-run, or a GitHub Actions run of a ref that is not the default branch. */
function previewOnly(options, env) {
  if (options['dry-run']) {
    return true;
  }
  if (env.GITHUB_ACTIONS !== 'true' || !env.GITHUB_EVENT_PATH) {
    return false;
  }

  // Dependabot alerts describe the default branch, so only a build of that branch may change them.
  let defaultBranch = null;
  try {
    defaultBranch = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, 'utf8')).repository?.default_branch ?? null;
  } catch {
    defaultBranch = null;
  }
  if (!defaultBranch || env.GITHUB_REF === `refs/heads/${defaultBranch}`) {
    return false;
  }

  log(`vexproof: this run builds ${env.GITHUB_REF ?? 'another ref'}, but Dependabot alerts describe ${defaultBranch}; previewing only`);
  return true;
}

export async function dependabot({ options, env = process.env }) {
  // An open-source key must cover the repository whose alerts change, not just the one this runs in.
  const host = (url) => {
    try {
      return new URL(url).host;
    } catch {
      return 'github.com';
    }
  };
  const named = options.repo ? `${host(env.GITHUB_SERVER_URL)}/${options.repo}` : undefined;
  if (!licensedFor(loadLicense(options.license, { repo: named }), 'dependabot')) {
    log('vexproof dependabot is a Pro feature; no alerts changed');

    return EXIT.ok;
  }

  const sync = pro.dependabot;
  const vexFiles = options.vex ?? [];
  const lockFiles = options.lockfile ?? [];
  if (!vexFiles.length || !lockFiles.length) throw new Stop('dependabot needs --vex and the --lockfile SBOM each VEX was made from');

  const token = options.token ?? env.VEXPROOF_DEPENDABOT_TOKEN ?? env.GH_TOKEN ?? env.GITHUB_TOKEN;
  if (!token) throw new Stop('dependabot needs a GitHub token: --token, or VEXPROOF_DEPENDABOT_TOKEN, GH_TOKEN or GITHUB_TOKEN');

  const repo = repositoryOf(options, env);
  const scopes = options.manifest?.length ? options.manifest : [(git('rev-parse', '--show-prefix') ?? '').replace(/\/$/, '')];
  const dryRun = previewOnly(options, env);
  const runLink = env.GITHUB_SERVER_URL && env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : null;
  const link = options.link ?? runLink;

  let outcome;
  try {
    const lockfiles = lockFiles.map((file) => ({ file, sbom: readJson(file, 'lockfile SBOM'), sha256: sha256(file) }));
    const documents = sync.readDocuments(vexFiles.map((file) => ({ file, vex: readJson(file, 'VEX') })), lockfiles);
    const client = sync.github({ token, repo, apiUrl: env.GITHUB_API_URL || 'https://api.github.com', userAgent: `vexproof/${VERSION}` });
    log(`vexproof: ${dryRun ? 'previewing' : 'applying'} ${vexFiles.join(', ')} to Dependabot's npm alerts in ${repo}, on manifests ${sync.scopeLabel(scopes)}`);

    const top = git('rev-parse', '--show-toplevel');
    outcome = await sync.syncDependabot({ client, docs: documents, scopes, link, dryRun, workspaceRoot: top ? sync.workspaceRootIn(top) : null });
  } catch (error) {
    if (error instanceof Stop) throw error;
    throw new Stop(sync.explain(error, repo));
  }
  const { plan, elsewhere } = outcome;

  const shown = plan.filter((item) => item.action !== 'kept');
  const nameWidth = Math.max(8, ...shown.map((item) => String(item.alert.dependency?.package?.name ?? '').length));
  for (const item of shown) {
    const alert = item.alert;
    const advisory = String(alert.security_advisory?.ghsa_id ?? '').padEnd(20);
    const name = String(alert.dependency?.package?.name ?? '').padEnd(nameWidth);
    console.log(`  ${sync.verb(item).padEnd(20)} #${String(alert.number).padEnd(5)} ${advisory} ${name}  ${item.error ?? item.why}`);
  }
  console.log(`vexproof: ${sync.summaryLine(plan, dryRun)}`);
  if (!plan.length && elsewhere.length) {
    log(`vexproof: no npm alerts on manifests ${sync.scopeLabel(scopes)}; there are alerts on ${elsewhere.slice(0, 5).join(', ')}. Pass --manifest to choose.`);
  }
  if (env.GITHUB_STEP_SUMMARY) {
    try {
      appendFileSync(env.GITHUB_STEP_SUMMARY, sync.markdownSummary({ repo, plan, dryRun }));
    } catch {
      // the job summary is a courtesy: a run is not stopped for it
    }
  }

  // some alert updates failed after others were made: docs/CONTRACT.md, exit codes
  return plan.some((item) => item.result === 'failed' || item.result === 'unchanged') ? EXIT.stopped : EXIT.ok;
}
