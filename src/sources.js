// SPDX-License-Identifier: MIT
// Findings sources: OSV (direct), npm audit, osv-scanner, Trivy, Grype, Snyk, internal shape.
import { sbomPurls, parsePurl, npmPurl, mergeFindings } from './index.js';

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 1000; // OSV's documented limit per querybatch call

const TIMEOUT_MS = 30_000;
const RETRIES = 3;
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * fetch for the public sources vexproof reads (OSV, the npm registry): each attempt times out, and 429, 5xx and
 * network errors are retried with backoff (a Retry-After header, when sent, sets the wait). Anything else is
 * returned as is. Throws once the retries are spent, so a run never continues on a lookup that did not happen.
 */
export async function fetchRetrying(url, init = {}, { fetchImpl = globalThis.fetch, retries = RETRIES, timeoutMs = TIMEOUT_MS, sleep = pause } = {}) {
  let last;
  for (let attempt = 0; ; attempt++) {
    let wait = Math.min(500 * 2 ** attempt, 8000);
    try {
      const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
      const status = res.status ?? (res.ok ? 200 : 500);
      if (status !== 429 && status < 500) return res;
      last = new Error(`HTTP ${status}`);
      const after = Number(res.headers?.get?.('retry-after'));
      if (after > 0) wait = Math.min(after * 1000, 60_000);
    } catch (e) {
      last = e?.name === 'TimeoutError' ? new Error(`no response within ${timeoutMs / 1000}s`) : e;
    }
    if (attempt >= retries) throw new Error(`${url}: ${last.message} (gave up after ${attempt + 1} attempts)`);
    await sleep(wait);
  }
}

/** Query OSV for every npm component in a lockfile SBOM. Returns internal [{purl, ids}]. */
export async function fetchOsvFindings(lockfileSbom, { fetchImpl = globalThis.fetch, sleep = pause } = {}) {
  const pkgs = sbomPurls(lockfileSbom)
    .map((purl) => ({ purl, p: parsePurl(purl) }))
    .filter(({ p }) => p && p.type === 'npm' && p.version);
  const out = [];
  for (let i = 0; i < pkgs.length; i += BATCH_SIZE) {
    const chunk = pkgs.slice(i, i + BATCH_SIZE);
    const body = { queries: chunk.map(({ p }) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })) };
    let res;
    try {
      res = await fetchRetrying(OSV_BATCH, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }, { fetchImpl, sleep });
    } catch (e) { throw new Error(`OSV lookup failed: ${e.message}. Pass --findings with a scanner's output to run without it.`); }
    if (!res.ok) throw new Error(`OSV lookup failed: HTTP ${res.status}. Pass --findings with a scanner's output to run without it.`);
    const json = await res.json();
    (json.results ?? []).forEach((r, k) => {
      const ids = (r.vulns ?? []).map((v) => v.id);
      if (ids.length) out.push({ purl: chunk[k].purl, ids });
    });
  }
  return out;
}

/**
 * Convert `npm audit --json` output. Audit output names no installed versions; each advisory carries its range,
 * so every version of the package in the lockfile SBOM inside that range gets the finding (a package installed
 * at 8.4.30 and 8.5.23 gets it only on 8.4.30). Without a lockfile version in range, the first one is used.
 */
export function fromNpmAudit(audit, lockfileSbom) {
  const versions = new Map();
  for (const purl of sbomPurls(lockfileSbom ?? {})) {
    const p = parsePurl(purl);
    if (p?.type === 'npm' && p.version) versions.set(p.name, [...new Set([...(versions.get(p.name) ?? []), p.version])]);
  }
  const out = [];
  for (const [name, v] of Object.entries(audit?.vulnerabilities ?? {})) {
    // `via` holds advisory objects for the package itself, or strings naming the dependency that carries the advisory
    for (const x of (v.via ?? []).filter((x) => typeof x === 'object' && x.url)) {
      const id = x.url.match(/GHSA-[a-z0-9-]+/i)?.[0] ?? String(x.source);
      const all = versions.get(name) ?? [];
      const hits = x.range ? all.filter((ver) => inAdvisoryRange(ver, x.range)) : [];
      for (const ver of hits.length ? hits : [all[0]]) out.push({ purl: npmPurl(name, ver), id, aliases: [] });
    }
  }
  return mergeFindings(out);
}

/** Does `version` satisfy an npm advisory range like ">=4.0.0 <=4.17.22 || <1.2"? Unparseable → true (keeps it). */
export function inAdvisoryRange(version, range) {
  const num = (v) => { const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(-[0-9A-Za-z.-]+)?/.exec(String(v).trim()); return m ? [+m[1], +(m[2] ?? 0), +(m[3] ?? 0), m[4] ? 0 : 1] : null; };
  const cmp = (a, b) => { for (let i = 0; i < 4; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; return 0; };
  const v = num(version);
  if (!v || typeof range !== 'string' || !range.trim()) return true;
  return range.split('||').some((alt) => {
    const parts = alt.trim().split(/\s+/).filter(Boolean);
    if (!parts.length || parts.includes('*')) return true;
    return parts.every((c) => {
      const m = /^(<=|>=|<|>|=)?(.+)$/.exec(c);
      const b = num(m[2]);
      if (!b) return true;
      const r = cmp(v, b);
      return { '<': r < 0, '<=': r <= 0, '>': r > 0, '>=': r >= 0, '=': r === 0, undefined: r === 0 }[m[1]];
    });
  });
}

const looksLikeBunAudit = (json) => json && typeof json === 'object' && !Array.isArray(json) && Object.keys(json).length > 0
  && Object.values(json).every((a) => Array.isArray(a) && a.every((x) => x && typeof x === 'object' && 'url' in x && 'vulnerable_versions' in x));

/**
 * `bun audit --json`: {"lodash":[{url:".../GHSA-…", vulnerable_versions:">=4.0.0 <=4.17.22", …}]}. No installed
 * version is given, so every version of the package in the lockfile SBOM is checked against each advisory's range.
 */
export function fromBunAudit(audit, lockfileSbom) {
  const versions = new Map();
  for (const purl of sbomPurls(lockfileSbom ?? {})) {
    const p = parsePurl(purl);
    if (p?.type === 'npm' && p.version) versions.set(p.name, new Set([...(versions.get(p.name) ?? []), p.version]));
  }
  const out = [];
  for (const [name, advisories] of Object.entries(audit)) {
    const vs = [...(versions.get(name) ?? [])];
    for (const a of advisories) {
      const id = a.url?.match(/GHSA-[a-z0-9-]+/i)?.[0] ?? String(a.id);
      const hits = vs.filter((v) => inAdvisoryRange(v, a.vulnerable_versions));
      for (const v of hits.length || vs.length ? hits : [undefined]) out.push({ purl: npmPurl(name, v), id, aliases: [] });
    }
  }
  return mergeFindings(out);
}

// ---------- existing scanners ----------

const NPM_TRIVY_TYPES = new Set(['npm', 'yarn', 'pnpm', 'bun', 'node-pkg']);
const isNpmPurl = (p) => typeof p === 'string' && p.startsWith('pkg:npm/');

/** `trivy fs|sbom --format json`. Trivy reports npm issues by CVE; VendorIDs carry GHSA ids when present. */
export function fromTrivy(report) {
  const out = [];
  for (const r of report?.Results ?? []) {
    if (!NPM_TRIVY_TYPES.has(r.Type)) continue;
    for (const v of r.Vulnerabilities ?? []) {
      const purl = v.PkgIdentifier?.PURL ?? npmPurl(v.PkgName, v.InstalledVersion);
      if (!isNpmPurl(purl)) continue;
      out.push({ purl, id: v.VulnerabilityID, aliases: v.VendorIDs ?? [] });
    }
  }
  return mergeFindings(out);
}

/** `grype <target> -o json`. For npm, the id is usually a GHSA and relatedVulnerabilities hold the CVE. */
export function fromGrype(report) {
  const out = [];
  for (const m of report?.matches ?? []) {
    const a = m.artifact ?? {};
    const purl = a.purl || (a.type === 'npm' ? npmPurl(a.name, a.version) : null);
    if (!isNpmPurl(purl)) continue;
    out.push({ purl, id: m.vulnerability?.id, aliases: (m.relatedVulnerabilities ?? []).map((r) => r.id) });
  }
  return mergeFindings(out.filter((f) => f.id));
}

/** `snyk test --json` (one project, or an array for --all-projects). Snyk's own ids become aliases. */
export function fromSnyk(report) {
  const out = [];
  for (const proj of Array.isArray(report) ? report : [report]) {
    if (proj?.packageManager && !['npm', 'yarn', 'pnpm'].includes(proj.packageManager)) continue;
    for (const v of proj?.vulnerabilities ?? []) {
      const ids = [...(v.identifiers?.GHSA ?? []), ...(v.identifiers?.CVE ?? [])];
      const id = ids[0] ?? v.id;
      out.push({ purl: npmPurl(v.packageName ?? v.moduleName, v.version), id, aliases: [...ids.slice(1), v.id].filter((x) => x && x !== id) });
    }
  }
  return mergeFindings(out); // Snyk repeats an issue once per dependency path
}

/** `pnpm audit --json` and `npm audit --json` from npm 6: an advisories map with a version per finding. */
export function fromPnpmAudit(report) {
  const out = [];
  for (const a of Object.values(report?.advisories ?? {})) {
    const id = a.github_advisory_id ?? a.url?.match(/GHSA-[a-z0-9-]+/i)?.[0] ?? String(a.id);
    const aliases = (a.cves ?? []).filter((c) => c !== id);
    for (const f of a.findings ?? []) out.push({ purl: npmPurl(a.module_name, f.version), id, aliases });
  }
  return mergeFindings(out);
}

/** OSV knows every alias (GHSA ↔ CVE). One GET per unique id; failures leave findings unchanged. */
export async function enrichAliases(findings, { fetchImpl = globalThis.fetch, limit = 8, sleep = pause } = {}) {
  const ids = [...new Set(findings.map((f) => f.id))];
  const known = new Map();
  for (let i = 0; i < ids.length; i += limit) {
    await Promise.all(ids.slice(i, i + limit).map(async (id) => {
      try {
        const res = await fetchRetrying(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {}, { fetchImpl, sleep });
        if (res.ok) known.set(id, (await res.json()).aliases ?? []);
      } catch { /* request failed: keep what we have */ }
    }));
  }
  let added = 0;
  for (const f of findings) for (const a of known.get(f.id) ?? []) if (a !== f.id && !f.aliases.includes(a)) { f.aliases.push(a); added++; }
  return { findings, looked: ids.length, resolved: known.size, added };
}

/** Sniff a findings file's format. */
export function detectFormat(json) {
  if (Array.isArray(json) && json.length && (json[0]?.vulnerabilities || json[0]?.packageManager)) return 'snyk';
  if (Array.isArray(json)) return 'internal';
  if (json?.auditReportVersion) return 'npm-audit';
  if (json?.advisories && typeof json.advisories === 'object' && json?.metadata) return 'pnpm-audit';
  if (json?.SchemaVersion && Array.isArray(json?.Results)) return 'trivy';
  if (Array.isArray(json?.matches) && (json?.descriptor || json?.source)) return 'grype';
  if (Array.isArray(json?.vulnerabilities) && ('packageManager' in json || 'projectName' in json || 'dependencyCount' in json)) return 'snyk';
  if (Array.isArray(json?.results)) return 'osv-scanner';
  if (looksLikeBunAudit(json)) return 'bun-audit';
  throw new Error('Unrecognised findings format (expected npm, pnpm, yarn or bun audit, osv-scanner, Trivy, Grype or Snyk JSON, or [{purl, ids}])');
}

/** Any supported findings JSON → [{purl, id, aliases}] or the internal shape. */
export function readFindings(json, lockfileSbom) {
  const fmt = detectFormat(json);
  const f = { 'npm-audit': () => fromNpmAudit(json, lockfileSbom), 'pnpm-audit': () => fromPnpmAudit(json), 'bun-audit': () => fromBunAudit(json, lockfileSbom), trivy: () => fromTrivy(json), grype: () => fromGrype(json), snyk: () => fromSnyk(json) }[fmt];
  return { format: fmt, findings: f ? f() : json };
}

/**
 * Findings from file text. Handles single JSON documents and Yarn Classic's `yarn audit --json`, which
 * writes one JSON object per line (auditAdvisory lines carry the same advisory shape as pnpm audit).
 */
export function readFindingsText(text, lockfileSbom) {
  try {
    return readFindings(JSON.parse(text), lockfileSbom);
  } catch (e) {
    if (!(e instanceof SyntaxError)) throw e;
  }
  const lines = text.split(/\r?\n/).filter((l) => l.trim()).map((l) => { try { return JSON.parse(l); } catch { return null; } });
  // Yarn Classic: {"type":"auditAdvisory","data":{"advisory":{...}}}
  const advisories = {};
  for (const l of lines) if (l?.type === 'auditAdvisory' && l.data?.advisory) advisories[l.data.advisory.id ?? Object.keys(advisories).length] = l.data.advisory;
  if (Object.keys(advisories).length) return { format: 'yarn-audit', findings: fromPnpmAudit({ advisories, metadata: {} }) };
  // Yarn 2+ (`yarn npm audit --json --recursive`): {"value":"lodash","children":{"ID":…,"URL":".../GHSA-…","Tree Versions":["4.17.21"]}}
  const berry = [];
  for (const l of lines) {
    const c = l?.children;
    const ghsa = c?.URL?.match(/GHSA-[a-z0-9-]+/i)?.[0];
    if (!l?.value || !ghsa) continue; // deprecation notices carry no advisory
    for (const v of c['Tree Versions'] ?? []) berry.push({ purl: npmPurl(l.value, v), id: ghsa, aliases: [] });
  }
  if (berry.length) return { format: 'yarn-berry-audit', findings: mergeFindings(berry) };
  throw new Error('Unrecognised findings file: not JSON, and no yarn audit advisories found');
}

