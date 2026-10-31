// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Dependabot reads no VEX. This applies vexproof's VEX to a repository's Dependabot alerts through GitHub's API:
// it dismisses the npm alerts the VEX settles, with the reason attached, and reopens alerts vexproof dismissed
// earlier once a later VEX no longer settles them. Alerts dismissed by anyone else are never touched.
//
// An alert is settled only when every installed version of its package that falls in the alert's vulnerable range
// (read from the lockfile SBOM the VEX was made from) has a not_affected or false_positive statement. A version the
// VEX says nothing about keeps the alert open, so a scanner that missed a version can't lead to a dismissal.
import { indexSbom, parsePurl } from '../index.js';

export const MARKER = 'vexproof:';
export const COMMENT_MAX = 280; // GitHub's limit for dismissed_comment
const SETTLED = new Set(['not_affected', 'false_positive']);
const prop = (list, name) => list?.find((p) => p.name === name)?.value;
const up = (s) => String(s).toUpperCase();
const words = (state) => String(state).replace(/_/g, ' ');

// ---------- reading the VEX ----------

/**
 * One document per VEX file: its statements on npm packages, and the package versions its lockfile SBOM lists.
 * `lockfiles` are the CycloneDX SBOMs given alongside, each with its sha256; the one a VEX was made from is
 * found by the hash the VEX records for its lockfile input.
 */
export function readDocuments(vexes, lockfiles) {
  return vexes.map(({ file, vex }) => {
    if (!vex?.metadata?.tools?.components?.some((c) => c.name === 'vexproof')) throw new Error(`${file} was not written by vexproof`);
    if (prop(vex.metadata.properties, 'vexproof:scope') === 'browser-bundle') {
      throw new Error(`${file} covers the browser bundle only (--browser-only). Packages it leaves out may still run on the server, so it can't settle Dependabot alerts`);
    }
    const hash = prop(vex.metadata.properties, 'vexproof:input:lockfile-sbom:sha256');
    const lock = lockfiles.find((l) => l.sha256 === hash);
    if (!lock) throw new Error(`${file} was made from a different lockfile SBOM than ${lockfiles.length === 1 ? lockfiles[0].file : 'the ones given'}; pass the --lockfile it was made from`);
    const installed = new Map();
    for (const [key, versions] of indexSbom(lock.sbom)) if (key.startsWith('npm/')) installed.set(key.slice(4), versions);
    const statements = [];
    for (const v of vex.vulnerabilities ?? []) {
      if (prop(v.properties, 'vexproof:alias-of')) continue; // alias entries mirror their primary statement
      const p = parsePurl(prop(v.properties, 'vexproof:package'));
      if (p?.type !== 'npm') continue;
      statements.push({
        ids: new Set([v.id, ...(v.references ?? []).map((r) => r.id)].filter(Boolean).map(up)),
        name: p.name,
        version: p.version ?? null,
        state: v.analysis?.state,
        justification: v.analysis?.justification ?? null,
        detail: v.analysis?.detail ?? '',
        level: prop(v.properties, 'vexproof:level') ?? null,
        origin: prop(v.properties, 'vexproof:origin') ?? 'auto',
        reviewedBy: prop(v.properties, 'vexproof:reviewed-by') ?? null,
      });
    }
    return { file, statements, installed };
  });
}

// ---------- versions ----------

function parseVersion(v) {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(String(v).trim());
  return m ? { n: [m[1], m[2] ?? 0, m[3] ?? 0].map(Number), pre: m[4] ? m[4].split('.') : [] } : null;
}

export function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) if (a.n[i] !== b.n[i]) return Math.sign(a.n[i] - b.n[i]);
  if (!a.pre.length || !b.pre.length) return (a.pre.length === 0) - (b.pre.length === 0);
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const x = a.pre[i], y = b.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny && Number(x) !== Number(y)) return Math.sign(Number(x) - Number(y));
    if (nx !== ny) return nx ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Whether a version falls in a range as GitHub writes them: ">= 4.0.0, < 4.17.21", "< 1.2.3", "= 2.0.0".
 * Anything it can't read counts as in range, so the version still needs a statement before an alert is dismissed.
 */
export function inVulnerableRange(version, range) {
  const v = parseVersion(version);
  if (!v || !range) return true;
  for (const part of String(range).split(',')) {
    const m = /^\s*(>=|<=|>|<|=)?\s*(\S+)\s*$/.exec(part);
    const bound = m && parseVersion(m[2]);
    if (!bound) return true;
    const c = compareVersions(v, bound);
    const ok = { '>=': c >= 0, '<=': c <= 0, '>': c > 0, '<': c < 0, '=': c === 0 }[m[1] ?? '='];
    if (!ok) return false;
  }
  return true;
}

// ---------- deciding ----------

export function alertIds(alert) {
  const a = alert.security_advisory ?? {};
  return new Set([a.ghsa_id, a.cve_id, ...(a.identifiers ?? []).map((i) => i.value)].filter(Boolean).map(up));
}

/**
 * What the VEX documents say about one alert:
 *   settled   every installed version in the vulnerable range has a not_affected or false_positive statement
 *   unsettled some installed version in the range has no statement, or one that leaves it open
 *   unknown   no installed version is in the range, so the VEX can't speak to it either way
 */
export function judge(alert, docs) {
  const name = alert.dependency?.package?.name;
  const range = alert.security_vulnerability?.vulnerable_version_range ?? null;
  const ids = alertIds(alert);
  const needed = [];
  for (const doc of docs) for (const v of doc.installed.get(name) ?? []) if (inVulnerableRange(v, range)) needed.push({ doc, version: v });
  if (!needed.length) {
    let why;
    if (alert.dependency?.scope === 'development') why = 'a development dependency; vexproof speaks only for what ships';
    else if (docs.some((d) => d.installed.has(name))) why = `no installed version is in the vulnerable range (${range})`;
    else why = `${name} is not in the lockfile SBOM`;
    return { kind: 'unknown', why };
  }
  const proven = [];
  for (const { doc, version } of needed) {
    const found = doc.statements.filter((s) => s.name === name && (!s.version || s.version === version) && [...s.ids].some((i) => ids.has(i)));
    if (!found.length) return { kind: 'unsettled', why: `the VEX has no statement for ${name}@${version}` };
    const open = found.find((s) => !SETTLED.has(s.state));
    if (open) return { kind: 'unsettled', why: `${name}@${version} is ${words(open.state)} in the VEX` };
    proven.push(...found);
  }
  const versions = [...new Set(needed.map((n) => n.version))];
  return { kind: 'settled', statements: proven, versions, ...dismissal(name, versions, proven) };
}

function dismissal(name, versions, statements) {
  const reasonOf = (s) => (s.state === 'false_positive' ? 'inaccurate' : ['code_not_present', 'code_not_reachable'].includes(s.justification) ? 'not_used' : 'tolerable_risk');
  const reasons = new Set(statements.map(reasonOf));
  const reason = reasons.size === 1 ? [...reasons][0] : reasons.has('tolerable_risk') ? 'tolerable_risk' : 'not_used';
  const label = versions.length === 1 ? `${name}@${versions[0]}` : `${name} ${versions.join(', ')}`;
  const reviewed = statements.find((s) => s.origin === 'reviewed');
  if (reviewed) {
    const what = [words(reviewed.state), reviewed.justification].filter(Boolean).join(', ');
    return { reason, why: `reviewed by ${reviewed.reviewedBy ?? 'a person'}`, text: `${MARKER} ${label}: ${what}, reviewed by ${reviewed.reviewedBy ?? 'a person'}. ${reviewed.detail}` };
  }
  const levels = new Set(statements.map((s) => s.level));
  if (levels.size === 1 && levels.has('package')) return { reason, why: 'not in the production build', text: `${MARKER} ${label} is not in the production build (code_not_present).` };
  if (levels.size === 1 && levels.has('module')) return { reason, why: 'its vulnerable files are not in the build', text: `${MARKER} ${label} ships, but not the files this advisory affects (code_not_present).` };
  return { reason, why: 'vulnerable code not in the build', text: `${MARKER} the vulnerable code in ${label} is not in the production build (code_not_present).` };
}

/** The dismissal comment: the reason, then the link, cut to GitHub's 280 characters. */
export function comment(text, link) {
  const tail = link ? ` ${link}` : '';
  const room = COMMENT_MAX - tail.length;
  const body = text.trim();
  return (body.length > room ? `${body.slice(0, room - 1).trimEnd()}…` : body) + tail;
}

const MANIFEST = /(^|\/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/;
const clean = (p) => String(p).replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');
const dirOf = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');

export const scopeLabel = (scopes) => scopes.map((s) => { const c = clean(s); return MANIFEST.test(c) ? c : c ? `in ${c}/` : 'at the repository root'; }).join(', ');

/** A scope is a manifest file (exact match) or a folder (manifests directly in it); '' is the repository root. */
export function inScope(manifestPath, scopes) {
  const m = clean(manifestPath);
  return scopes.some((s) => { const c = clean(s); return MANIFEST.test(c) ? m === c : dirOf(m) === c; });
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
export function planAlerts({ alerts, docs, scopes, link = null }) {
  const plan = [];
  const elsewhere = new Set();
  for (const alert of alerts) {
    if (alert.dependency?.package?.ecosystem !== 'npm') continue;
    if (alert.state !== 'open' && alert.state !== 'dismissed') continue;
    if (!inScope(alert.dependency?.manifest_path ?? '', scopes)) { elsewhere.add(alert.dependency?.manifest_path); continue; }
    const verdict = judge(alert, docs);
    const ours = alert.state === 'dismissed' && String(alert.dismissed_comment ?? '').startsWith(MARKER);
    let item;
    if (alert.state === 'open') {
      if (alert.dismissal_request?.status === 'pending') item = { action: 'pending', why: 'a dismissal request is waiting for approval' };
      else if (verdict.kind === 'settled') item = { action: 'dismiss', why: verdict.why, body: { state: 'dismissed', dismissed_reason: verdict.reason, dismissed_comment: comment(verdict.text, link) } };
      else item = { action: 'open', why: verdict.why };
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

// ---------- GitHub ----------

export class GitHubError extends Error {
  constructor(status, message, method) { super(message); this.status = status; this.method = method; }
}

const nextLink = (header) => /<([^>]+)>;\s*rel="next"/.exec(header ?? '')?.[1] ?? null;

export function github({ token, repo, apiUrl = 'https://api.github.com', fetchImpl = globalThis.fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), userAgent = 'vexproof' }) {
  const base = apiUrl.replace(/\/+$/, '');
  const headers = { accept: 'application/vnd.github+json', authorization: `Bearer ${token}`, 'x-github-api-version': '2022-11-28', 'user-agent': userAgent };
  async function call(method, url, body) {
    for (let attempt = 0; ; attempt++) {
      let res;
      try {
        res = await fetchImpl(url, { method, headers: body ? { ...headers, 'content-type': 'application/json' } : headers, body: body ? JSON.stringify(body) : undefined });
      } catch (e) {
        if (attempt < 2) { await sleep(2000 * (attempt + 1)); continue; }
        throw new GitHubError(0, `could not reach ${base}: ${e.cause?.message ?? e.message}`, method);
      }
      if (res.ok) return res;
      const text = await res.text();
      let message;
      try { message = JSON.parse(text).message; } catch { message = text.slice(0, 200); }
      const wait = Number(res.headers.get('retry-after'));
      const secondary = (res.status === 403 || res.status === 429) && (wait > 0 || /secondary rate limit/i.test(message ?? ''));
      if ((secondary || res.status >= 500) && attempt < 3) { await sleep(Math.min((wait > 0 ? wait : 2 ** attempt * 5) * 1000, 60000)); continue; }
      throw new GitHubError(res.status, message || `HTTP ${res.status}`, method);
    }
  }
  return {
    repo,
    async listAlerts() {
      const all = [];
      let url = `${base}/repos/${repo}/dependabot/alerts?ecosystem=npm&state=open,dismissed&per_page=100`;
      while (url) {
        const res = await call('GET', url);
        all.push(...(await res.json()));
        url = nextLink(res.headers.get('link'));
      }
      return all;
    },
    async updateAlert(number, body) {
      return (await call('PATCH', `${base}/repos/${repo}/dependabot/alerts/${number}`, body)).json();
    },
  };
}

/** A failed call, explained in terms of what the token needs. */
export function explain(e, repo) {
  if (!(e instanceof GitHubError)) return e.message;
  const gh = `GitHub said: ${e.message}`;
  if (e.status === 401) return `GitHub rejected the token. ${gh}`;
  if (e.status === 404) return `${repo} was not found, or this token can't see it. ${gh}`;
  if (e.status === 403 && e.method === 'GET') return `this token can't read Dependabot alerts for ${repo}. A fine-grained token needs "Dependabot alerts" read access; in a workflow, give the job \`permissions: vulnerability-alerts: read\`. ${gh}`;
  if (e.status === 403) return `this token can read Dependabot alerts but not change them. The workflow's own token is read-only for Dependabot alerts; use a fine-grained or GitHub App token with "Dependabot alerts" read and write access. ${gh}`;
  return gh;
}

/**
 * Lists the alerts, plans, and (unless dryRun) applies the plan. Mutations go one at a time with a pause between
 * them, as GitHub asks of clients that make many. A 401 or 403 stops the run; other failures are recorded per alert.
 */
export async function syncDependabot({ client, docs, scopes, link = null, dryRun = false, pause = 1000, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
  const alerts = await client.listAlerts();
  const { plan, elsewhere } = planAlerts({ alerts, docs, scopes, link });
  let first = true;
  for (const item of plan) {
    if (!item.body) continue;
    if (dryRun) { item.result = 'planned'; continue; }
    if (!first && pause) await sleep(pause);
    first = false;
    try {
      const after = await client.updateAlert(item.alert.number, item.body);
      if (item.action === 'dismiss' && after?.state !== 'dismissed') item.result = after?.dismissal_request?.status === 'pending' ? 'requested' : 'unchanged';
      else item.result = 'done';
    } catch (e) {
      if (e instanceof GitHubError && (e.status === 401 || e.status === 403)) throw e;
      item.result = 'failed';
      item.error = e instanceof GitHubError ? `GitHub said: ${e.message}` : e.message;
    }
  }
  return { plan, elsewhere, total: alerts.length };
}

// ---------- reporting ----------

const VERB = {
  dismiss: { planned: 'would dismiss', done: 'dismissed', requested: 'dismissal requested', unchanged: 'not dismissed', failed: 'dismiss failed' },
  reopen: { planned: 'would reopen', done: 'reopened', unchanged: 'not reopened', failed: 'reopen failed' },
  open: 'left open', kept: 'kept dismissed', pending: 'awaiting approval', person: 'left alone',
};
export const verb = (item) => (typeof VERB[item.action] === 'string' ? VERB[item.action] : VERB[item.action][item.result ?? 'planned']);

export function summaryLine(plan, dryRun) {
  const count = (pred) => plan.filter(pred).length;
  const parts = [];
  const changed = (action) => count((i) => i.action === action && (dryRun ? i.result === 'planned' : i.result === 'done'));
  parts.push(`${changed('dismiss')} ${dryRun ? 'to dismiss' : 'dismissed'}`);
  parts.push(`${changed('reopen')} ${dryRun ? 'to reopen' : 'reopened'}`);
  const requested = count((i) => i.result === 'requested');
  if (requested) parts.push(`${requested} dismissal request${requested === 1 ? '' : 's'} sent`);
  const failed = count((i) => i.result === 'failed' || i.result === 'unchanged');
  if (failed) parts.push(`${failed} failed`);
  parts.push(`${count((i) => i.action === 'open' || i.action === 'pending')} left open`);
  const kept = count((i) => i.action === 'kept');
  if (kept) parts.push(`${kept} still dismissed`);
  const person = count((i) => i.action === 'person');
  if (person) parts.push(`${person} dismissed by people, left alone`);
  return parts.join(', ');
}

/** Markdown for the GitHub Actions job summary. */
export function markdownSummary({ repo, plan, dryRun }) {
  const rows = plan.filter((i) => i.action !== 'kept' && i.action !== 'person');
  const lines = [`### vexproof → Dependabot (${repo})`, '', `${summaryLine(plan, dryRun)}.`];
  if (rows.length) {
    lines.push('', '| Alert | Advisory | Package | What happened | Why |', '|---|---|---|---|---|');
    for (const i of rows) {
      const a = i.alert;
      const cell = (s) => String(s ?? '').replace(/\|/g, '\\|');
      lines.push(`| [#${a.number}](${a.html_url}) | ${cell(a.security_advisory?.ghsa_id)} | ${cell(a.dependency?.package?.name)} | ${cell(verb(i))} | ${cell(i.error ?? i.why)} |`);
    }
  }
  return `${lines.join('\n')}\n`;
}
