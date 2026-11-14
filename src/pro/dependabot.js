// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Dependabot reads no VEX. This applies vexproof's VEX to a repository's Dependabot alerts through GitHub's API:
// it dismisses the npm alerts the VEX settles, with the reason attached, and reopens alerts vexproof dismissed
// earlier once a later VEX no longer settles them. A dismissal counts as vexproof's only when its comment is one
// vexproof writes (see OWN_COMMENTS); every other dismissed alert is never touched.
//
// An alert is settled only when every installed version of its package that falls in the alert's vulnerable range
// (read from the lockfile SBOM the VEX was made from) has a not_affected or false_positive statement. A version the
// VEX says nothing about keeps the alert open, so a scanner that missed a version can't lead to a dismissal.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { indexSbom, parsePurl, npmName } from '../index.js'; // npmName: see src/names.js
import { readPackageJson } from '../package-json.js';
import { fetchRetrying } from '../sources.js';
import { parseVersion, inAdvisoryRange } from '../versions.js';

const MARKER = 'vexproof:';
const COMMENT_MAX = 280; // GitHub's limit for dismissed_comment
const SETTLED = new Set(['not_affected', 'false_positive']);
const prop = (list, name) => list?.find((property) => property.name === name)?.value;
const upperCase = (text) => String(text).toUpperCase();
const words = (state) => String(state).replace(/_/g, ' ');

// ---------- reading the VEX ----------

/**
 * One document per VEX file: its statements on npm packages, and the package versions its lockfile SBOM lists.
 * `lockfiles` are the CycloneDX SBOMs given alongside, each with its sha256; the one a VEX was made from is
 * found by the hash the VEX records for its lockfile input.
 */
export function readDocuments(vexes, lockfiles) {
  return vexes.map(({ file, vex }) => {
    if (!vex?.metadata?.tools?.components?.some((component) => component.name === 'vexproof')) {
      throw new Error(`${file} was not written by vexproof`);
    }
    if (prop(vex.metadata.properties, 'vexproof:scope') === 'browser-bundle') {
      throw new Error(`${file} covers the browser bundle only (--browser-only). ` +
        `Packages it leaves out may still run on the server, so it can't settle Dependabot alerts`);
    }

    const hash = prop(vex.metadata.properties, 'vexproof:input:lockfile-sbom:sha256');
    const lock = lockfiles.find((lockfile) => lockfile.sha256 === hash);
    if (!lock) {
      const given = lockfiles.length === 1 ? lockfiles[0].file : 'the ones given';
      throw new Error(`${file} was made from a different lockfile SBOM than ${given}; pass the --lockfile it was made from`);
    }

    const installed = new Map();
    for (const [key, versions] of indexSbom(lock.sbom)) {
      if (key.startsWith('npm/')) installed.set(key.slice(4), versions);
    }

    const statements = [];
    for (const vulnerability of vex.vulnerabilities ?? []) {
      if (prop(vulnerability.properties, 'vexproof:alias-of')) continue; // alias entries mirror their primary statement
      const parsed = parsePurl(prop(vulnerability.properties, 'vexproof:package'));
      if (parsed?.type !== 'npm') continue;
      const ids = [vulnerability.id, ...(vulnerability.references ?? []).map((reference) => reference.id)];
      statements.push({
        ids: new Set(ids.filter(Boolean).map(upperCase)),
        name: npmName(parsed.name), // compared without case, as indexSbom's keys are
        version: parsed.version ?? null,
        state: vulnerability.analysis?.state,
        justification: vulnerability.analysis?.justification ?? null,
        detail: vulnerability.analysis?.detail ?? '',
        level: prop(vulnerability.properties, 'vexproof:level') ?? null,
        origin: prop(vulnerability.properties, 'vexproof:origin') ?? 'auto',
        reviewedBy: prop(vulnerability.properties, 'vexproof:reviewed-by') ?? null,
      });
    }

    // the product the VEX speaks for: the application whose lockfile SBOM it was made from
    const product = parsePurl(vex.metadata?.component?.purl)?.name ?? vex.metadata?.component?.name ?? null;

    return { file, statements, installed, product };
  });
}

// ---------- versions ----------

/**
 * Whether a version falls in a range as GitHub writes them: ">= 4.0.0, < 4.17.21", "< 1.2.3", "= 2.0.0".
 * Anything it can't read counts as in range, so the version still needs a statement before an alert is dismissed:
 * one part that can't be read leaves the whole range unread.
 */
export function inVulnerableRange(version, range) {
  const parts = String(range ?? '').split(',').map((part) => part.trim()).filter(Boolean);

  const everyPartReadable = parts.every((part) => parseVersion(part.replace(/^(>=|<=|>|<|=)\s*/, '')));
  if (!everyPartReadable) {
    return true;
  }

  // GitHub's commas join comparisons that must all hold, as spaces do in an npm range
  return inAdvisoryRange(version, parts.join(' '));
}

// ---------- deciding ----------

function alertIds(alert) {
  const advisory = alert.security_advisory ?? {};
  const ids = [advisory.ghsa_id, advisory.cve_id, ...(advisory.identifiers ?? []).map((identifier) => identifier.value)];

  return new Set(ids.filter(Boolean).map(upperCase));
}

/**
 * What the VEX documents say about one alert:
 *   settled   every installed version in the vulnerable range has a not_affected or false_positive statement
 *   unsettled some installed version in the range has no statement, or one that leaves it open
 *   unknown   no installed version is in the range, so the VEX can't speak to it either way
 */
export function judge(alert, docs) {
  const shown = alert.dependency?.package?.name;
  const name = npmName(shown); // the lockfile SBOM's purls may spell it in lower case (see npmName)
  const range = alert.security_vulnerability?.vulnerable_version_range ?? null;
  const ids = alertIds(alert);

  const needed = [];
  for (const doc of docs) {
    for (const installedVersion of doc.installed.get(name) ?? []) {
      if (inVulnerableRange(installedVersion, range)) needed.push({ doc, version: installedVersion });
    }
  }
  if (!needed.length) {
    let why;
    if (alert.dependency?.scope === 'development') why = 'a development dependency; vexproof speaks only for what ships';
    else if (docs.some((doc) => doc.installed.has(name))) why = `no installed version is in the vulnerable range (${range})`;
    else why = `${shown} is not in the lockfile SBOM`;

    return { kind: 'unknown', why };
  }

  const proven = [];
  for (const { doc, version } of needed) {
    const found = doc.statements.filter((statement) => statement.name === name
      && (!statement.version || statement.version === version)
      && [...statement.ids].some((id) => ids.has(id)));
    if (!found.length) {
      return { kind: 'unsettled', why: `the VEX has no statement for ${shown}@${version}` };
    }

    const open = found.find((statement) => !SETTLED.has(statement.state));
    if (open) {
      return { kind: 'unsettled', why: `${shown}@${version} is ${words(open.state)} in the VEX` };
    }

    proven.push(...found);
  }

  const versions = [...new Set(needed.map((need) => need.version))];

  return { kind: 'settled', statements: proven, versions, ...dismissal(shown, versions, proven) };
}

function dismissal(name, versions, statements) {
  const reasonOf = (statement) => {
    if (statement.state === 'false_positive') {
      return 'inaccurate';
    }
    if (['code_not_present', 'code_not_reachable'].includes(statement.justification)) {
      return 'not_used';
    }

    return 'tolerable_risk';
  };

  const reasons = new Set(statements.map(reasonOf));
  let reason;
  if (reasons.size === 1) {
    reason = [...reasons][0];
  } else if (reasons.has('tolerable_risk')) {
    reason = 'tolerable_risk';
  } else {
    reason = 'not_used';
  }

  const label = versions.length === 1 ? `${name}@${versions[0]}` : `${name} ${versions.join(', ')}`;
  const reviewed = statements.find((statement) => statement.origin === 'reviewed');
  if (reviewed) {
    const what = [words(reviewed.state), reviewed.justification].filter(Boolean).join(', ');

    return {
      reason,
      why: `reviewed by ${reviewed.reviewedBy ?? 'a person'}`,
      text: `${MARKER} ${label}: ${what}, reviewed by ${reviewed.reviewedBy ?? 'a person'}. ${reviewed.detail}`,
    };
  }

  const levels = new Set(statements.map((statement) => statement.level));
  if (levels.size === 1 && levels.has('package')) {
    return { reason, why: 'not in the production build', text: `${MARKER} ${label} is not in the production build (code_not_present).` };
  }
  if (levels.size === 1 && levels.has('module')) {
    return {
      reason,
      why: 'its vulnerable files are not in the build',
      text: `${MARKER} ${label} ships, but not the files this advisory affects (code_not_present).`,
    };
  }

  return {
    reason,
    why: 'vulnerable code not in the build',
    text: `${MARKER} the vulnerable code in ${label} is not in the production build (code_not_present).`,
  };
}

// The comments dismissal() writes, by how they begin (a long one is cut at its end). A dismissal is vexproof's
// own only when its comment has one of these shapes: a person who starts a comment with "vexproof:" has not
// handed the alert to vexproof, and an alert a person dismissed is never reopened.
const OWN_COMMENTS = [
  /^vexproof: \S.*?: (?:not affected|false positive)(?:, [a-z_]+)?, reviewed by /,
  /^vexproof: \S.* is not in the production build \(code_not_present\)\./,
  /^vexproof: \S.* ships, but not the files this advisory affects \(code_not_present\)\./,
  /^vexproof: the vulnerable code in \S.* is not in the production build \(code_not_present\)\./,
];
export const writtenByVexproof = (comment) => OWN_COMMENTS.some((shape) => shape.test(String(comment ?? '')));

/** The dismissal comment: the reason, then the link, cut to GitHub's 280 characters. */
export function comment(text, link) {
  const body = text.trim();
  // a link that would leave the reason too little room is left out: the reason is what the comment is for
  const MINIMUM_REASON = 80;
  const tail = link && COMMENT_MAX - (link.length + 1) >= MINIMUM_REASON ? ` ${link}` : '';
  const room = COMMENT_MAX - tail.length;

  return (body.length > room ? `${body.slice(0, room - 1).trimEnd()}…` : body) + tail;
}

const MANIFEST = /(^|\/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/;
const clean = (filePath) => String(filePath).replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');
const dirOf = (filePath) => (filePath.includes('/') ? filePath.slice(0, filePath.lastIndexOf('/')) : '');

export const scopeLabel = (scopes) => scopes.map((scope) => {
  const cleaned = clean(scope);
  if (MANIFEST.test(cleaned)) {
    return cleaned;
  }

  return cleaned ? `in ${cleaned}/` : 'at the repository root';
}).join(', ');

/** A scope is a manifest file (exact match) or a folder (manifests directly in it); '' is the repository root. */
export function inScope(manifestPath, scopes) {
  const manifest = clean(manifestPath);

  return scopes.some((scope) => {
    const cleaned = clean(scope);

    return MANIFEST.test(cleaned) ? manifest === cleaned : dirOf(manifest) === cleaned;
  });
}

/**
 * The documents that may judge each alert. With one scope every document speaks for it. With several, the n-th
 * --vex is for the n-th --manifest: an alert is judged only by the documents for the scope it is in, so that one
 * application's VEX never settles another's alert. Returns (alert) => documents.
 */
function documentsByScope(docs, scopes) {
  if (scopes.length <= 1) {
    return () => docs;
  }
  if (docs.length !== scopes.length) {
    throw new Error(
      `with ${scopes.length} --manifest scopes, give one --vex for each, in the same order (got ${docs.length}): ` +
      'an alert is settled only by the VEX of the application it belongs to',
    );
  }

  return (alert) => docs.filter((_doc, index) => inScope(alert.dependency?.manifest_path ?? '', [scopes[index]]));
}

/**
 * A workspace's root lockfile lists the packages of every application in it. A VEX made for one of them says
 * nothing about the packages only the others use, so it may judge an alert on that lockfile only when it is
 * the root package's own. `workspaceRoot(manifestPath)` names the root package when the manifest is such a
 * lockfile, else null. Returns why the documents can't judge the alert, or null when they can.
 */
function workspaceMismatch(alert, docs, workspaceRoot) {
  const manifest = alert.dependency?.manifest_path ?? '';
  const root = workspaceRoot?.(manifest);
  if (!root) {
    return null;
  }

  const others = docs.filter((doc) => !doc.product || npmName(doc.product) !== npmName(root));
  if (!others.length) {
    return null;
  }

  const files = others.map((doc) => doc.file).join(', ');

  return `${manifest} is the lockfile of the workspace ${root}, and ${files} speaks for ${others[0].product ?? 'another application'} only`;
}

/**
 * What to do with each npm alert in scope. Actions:
 *   dismiss   open, and the VEX settles it
 *   reopen    dismissed by vexproof, and the VEX now leaves an installed vulnerable version unsettled
 *   open      open, and the VEX doesn't settle it: left as it is
 *   kept      dismissed by vexproof and still settled (or no longer installed): left as it is
 *   pending   open with a dismissal request waiting for approval: left as it is
 *   person    dismissed by someone else: never touched
 */
export function planAlerts({ alerts, docs, scopes, link = null, workspaceRoot = null }) {
  const plan = [];
  const elsewhere = new Set();
  const docsFor = documentsByScope(docs, scopes);

  for (const alert of alerts) {
    if (alert.dependency?.package?.ecosystem !== 'npm') continue;
    if (alert.state !== 'open' && alert.state !== 'dismissed') continue;
    if (!inScope(alert.dependency?.manifest_path ?? '', scopes)) {
      elsewhere.add(alert.dependency?.manifest_path);
      continue;
    }

    const forAlert = docsFor(alert);
    const mismatch = workspaceMismatch(alert, forAlert, workspaceRoot);
    const verdict = mismatch ? { kind: 'unknown', why: mismatch } : judge(alert, forAlert);
    const ours = alert.state === 'dismissed' && writtenByVexproof(alert.dismissed_comment);

    let item;
    if (alert.state === 'open') {
      if (alert.dismissal_request?.status === 'pending') {
        item = { action: 'pending', why: 'a dismissal request is waiting for approval' };
      } else if (verdict.kind === 'settled') {
        item = {
          action: 'dismiss',
          why: verdict.why,
          body: { state: 'dismissed', dismissed_reason: verdict.reason, dismissed_comment: comment(verdict.text, link) },
        };
      } else {
        item = { action: 'open', why: verdict.why };
      }
    } else if (!ours) {
      item = { action: 'person', why: `dismissed by ${alert.dismissed_by?.login ? `@${alert.dismissed_by.login}` : 'someone else'}` };
    } else if (verdict.kind === 'unsettled') {
      item = { action: 'reopen', why: verdict.why, body: { state: 'open' } };
    } else {
      item = { action: 'kept', why: verdict.kind === 'settled' ? 'still settled' : verdict.why };
    }
    plan.push({ alert, ...item });
  }

  return { plan, elsewhere: [...elsewhere].filter(Boolean).sort() };
}

/**
 * workspaceRoot for planAlerts, reading the checkout at `repoDir`: a lockfile whose folder holds a package.json
 * with "workspaces", or a pnpm-workspace.yaml, belongs to a workspace, named by that package.json.
 */
export function workspaceRootIn(repoDir) {
  const cache = new Map();

  return (manifestPath) => {
    const manifest = clean(manifestPath);
    if (!/(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/.test(manifest)) {
      return null;
    }

    const dir = join(repoDir, dirOf(manifest));
    if (!cache.has(dir)) {
      const pkg = readPackageJson(dir).pkg;
      const isRoot = Boolean(pkg?.workspaces) || existsSync(join(dir, 'pnpm-workspace.yaml'));
      let rootName = null;
      if (isRoot) {
        rootName = typeof pkg?.name === 'string' && pkg.name ? pkg.name : '(unnamed root)';
      }
      cache.set(dir, rootName);
    }

    return cache.get(dir);
  };
}

// ---------- GitHub ----------

/** A GitHub call that failed: its HTTP status (0 when GitHub could not be reached), method, and whether the token's rate limit was used up. */
export class GitHubError extends Error {
  constructor(status, message, method, { rateLimited = false, resetsAt = null } = {}) {
    super(message);
    this.status = status;
    this.method = method;
    this.rateLimited = rateLimited;
    this.resetsAt = resetsAt;
  }
}

const nextLink = (header) => /<([^>]+)>;\s*rel="next"/.exec(header ?? '')?.[1] ?? null;

/**
 * The few GitHub calls the sync needs. Every request goes through fetchRetrying: it times out, and 429, 5xx and a
 * 403 that says when to try again (GitHub's secondary rate limit) are retried. Any other failure is a GitHubError.
 */
export function github({
  token,
  repo,
  apiUrl = 'https://api.github.com',
  fetchImpl = globalThis.fetch,
  sleep = (milliseconds) => new Promise((resolveWait) => setTimeout(resolveWait, milliseconds)),
  userAgent = 'vexproof',
}) {
  const base = apiUrl.replace(/\/+$/, '');
  const headers = {
    accept: 'application/vnd.github+json',
    authorization: `Bearer ${token}`,
    'x-github-api-version': '2022-11-28',
    'user-agent': userAgent,
  };
  const retryOn = (status, response) => status === 429
    || status >= 500
    || (status === 403 && Number(response.headers?.get?.('retry-after')) > 0);

  async function call(method, url, body) {
    let response;
    try {
      const init = {
        method,
        headers: body ? { ...headers, 'content-type': 'application/json' } : headers,
        body: body ? JSON.stringify(body) : undefined,
      };
      response = await fetchRetrying(url, init, { fetchImpl, sleep, retryOn, returnLast: true });
    } catch (error) {
      throw new GitHubError(0, `could not reach ${base}: ${error.cause?.message ?? error.message}`, method);
    }
    if (response.ok) {
      return response;
    }

    const text = await response.text();
    let message;
    try {
      message = JSON.parse(text).message;
    } catch {
      message = text.slice(0, 200);
    }

    // the token's own (primary) rate limit: GitHub says it is used up, and when it resets
    const rateLimited = response.headers?.get?.('x-ratelimit-remaining') === '0';
    const reset = Number(response.headers?.get?.('x-ratelimit-reset'));
    const resetsAt = rateLimited && reset > 0 ? new Date(reset * 1000).toISOString() : null;
    throw new GitHubError(response.status, message || `HTTP ${response.status}`, method, { rateLimited, resetsAt });
  }

  return {
    repo,
    async listAlerts() {
      const all = [];
      let url = `${base}/repos/${repo}/dependabot/alerts?ecosystem=npm&state=open,dismissed&per_page=100`;
      while (url) {
        const response = await call('GET', url);
        all.push(...(await response.json()));
        url = nextLink(response.headers.get('link'));
      }

      return all;
    },
    async updateAlert(number, body) {
      const response = await call('PATCH', `${base}/repos/${repo}/dependabot/alerts/${number}`, body);

      return response.json();
    },
  };
}

/** A failed call, explained in terms of what the token needs. */
export function explain(error, repo) {
  if (!(error instanceof GitHubError)) {
    return error.message;
  }

  const githubSaid = `GitHub said: ${error.message}`;
  if (error.rateLimited) {
    const resets = error.resetsAt ? `; it resets at ${error.resetsAt}` : '';

    return `this token has used up its GitHub API rate limit${resets}. Run again after that. ${githubSaid}`;
  }
  if (error.status === 401) {
    return `GitHub rejected the token. ${githubSaid}`;
  }
  if (error.status === 404) {
    return `${repo} was not found, or this token can't see it. ${githubSaid}`;
  }
  if (error.status === 403 && error.method === 'GET') {
    return `this token can't read Dependabot alerts for ${repo}. A fine-grained token needs "Dependabot alerts" read access; ` +
      `in a workflow, give the job \`permissions: vulnerability-alerts: read\`. ${githubSaid}`;
  }
  if (error.status === 403) {
    return `this token can read Dependabot alerts but not change them. The workflow's own token is read-only for Dependabot alerts; ` +
      `use a fine-grained or GitHub App token with "Dependabot alerts" read and write access. ${githubSaid}`;
  }

  return githubSaid;
}

/**
 * Lists the alerts, plans, and (unless dryRun) applies the plan. Mutations go one at a time with a pause between
 * them, as GitHub asks of clients that make many. A 401 or 403 stops the run; other failures are recorded per alert.
 */
export async function syncDependabot({
  client,
  docs,
  scopes,
  link = null,
  dryRun = false,
  workspaceRoot = null,
  pause = 1000,
  sleep = (milliseconds) => new Promise((resolveWait) => setTimeout(resolveWait, milliseconds)),
}) {
  documentsByScope(docs, scopes); // refuse a mismatched pairing before anything is read from GitHub
  const alerts = await client.listAlerts();
  const { plan, elsewhere } = planAlerts({ alerts, docs, scopes, link, workspaceRoot });

  let first = true;
  for (const item of plan) {
    if (!item.body) continue;
    if (dryRun) {
      item.result = 'planned';
      continue;
    }

    if (!first && pause) await sleep(pause);
    first = false;
    try {
      // what GitHub did, from the alert it sends back: a change it did not make is not reported as made
      const after = await client.updateAlert(item.alert.number, item.body);
      if (item.action === 'dismiss' && after?.state !== 'dismissed') {
        item.result = after?.dismissal_request?.status === 'pending' ? 'requested' : 'unchanged';
      } else if (item.action === 'reopen' && after?.state !== 'open') {
        item.result = 'unchanged';
      } else {
        item.result = 'done';
      }
    } catch (error) {
      if (error instanceof GitHubError && (error.status === 401 || error.status === 403)) throw error;
      item.result = 'failed';
      item.error = error instanceof GitHubError ? `GitHub said: ${error.message}` : error.message;
    }
  }

  return { plan, elsewhere, total: alerts.length };
}

// ---------- reporting ----------

const VERB = {
  dismiss: {
    planned: 'would dismiss',
    done: 'dismissed',
    requested: 'dismissal requested',
    unchanged: 'not dismissed',
    failed: 'dismiss failed',
  },
  reopen: { planned: 'would reopen', done: 'reopened', unchanged: 'not reopened', failed: 'reopen failed' },
  open: 'left open',
  kept: 'kept dismissed',
  pending: 'awaiting approval',
  person: 'left alone',
};
export const verb = (item) => (typeof VERB[item.action] === 'string' ? VERB[item.action] : VERB[item.action][item.result ?? 'planned']);

export function summaryLine(plan, dryRun) {
  const count = (predicate) => plan.filter(predicate).length;
  const parts = [];

  const changed = (action) => count((item) => item.action === action && (dryRun ? item.result === 'planned' : item.result === 'done'));
  parts.push(`${changed('dismiss')} ${dryRun ? 'to dismiss' : 'dismissed'}`);
  parts.push(`${changed('reopen')} ${dryRun ? 'to reopen' : 'reopened'}`);

  const requested = count((item) => item.result === 'requested');
  if (requested) parts.push(`${requested} dismissal request${requested === 1 ? '' : 's'} sent`);

  const failed = count((item) => item.result === 'failed' || item.result === 'unchanged');
  if (failed) parts.push(`${failed} failed`);

  parts.push(`${count((item) => item.action === 'open' || item.action === 'pending')} left open`);

  const kept = count((item) => item.action === 'kept');
  if (kept) parts.push(`${kept} still dismissed`);

  const person = count((item) => item.action === 'person');
  if (person) parts.push(`${person} dismissed by people, left alone`);

  return parts.join(', ');
}

/** Markdown for the GitHub Actions job summary. */
export function markdownSummary({ repo, plan, dryRun }) {
  const rows = plan.filter((item) => item.action !== 'kept' && item.action !== 'person');
  const lines = [`### vexproof → Dependabot (${repo})`, '', `${summaryLine(plan, dryRun)}.`];

  // a table cell holds one line: a pipe is escaped, a line break becomes a space
  const cell = (value) => String(value ?? '').replace(/\|/g, '\\|').replace(/\s*\r?\n\s*/g, ' ');

  if (rows.length) {
    lines.push('', '| Alert | Advisory | Package | What happened | Why |', '|---|---|---|---|---|');
    for (const item of rows) {
      const alert = item.alert;
      const advisory = cell(alert.security_advisory?.ghsa_id);
      const packageName = cell(alert.dependency?.package?.name);
      const happened = cell(verb(item));
      const why = cell(item.error ?? item.why);
      lines.push(`| [#${alert.number}](${alert.html_url}) | ${advisory} | ${packageName} | ${happened} | ${why} |`);
    }
  }

  return `${lines.join('\n')}\n`;
}
