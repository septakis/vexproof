// SPDX-License-Identifier: MIT
// Findings sources: OSV (queried directly), npm, pnpm, Yarn and bun audits, osv-scanner, Trivy, Grype, Snyk, and
// the internal [{ purl, ids }] shape. Each reader turns its format into [{ purl, id, aliases }].
import { sbomPurls, parsePurl, npmPurl, mergeFindings } from './index.js';
import { inAdvisoryRange } from './versions.js';

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns/';
const BATCH_SIZE = 1000; // OSV's documented limit per querybatch call

const TIMEOUT_MS = 30_000;
const RETRIES = 3;
const MAX_WAIT_MS = 60_000;
const pause = (milliseconds) => new Promise((resolveWait) => setTimeout(resolveWait, milliseconds));

/** The GHSA id in a string (an advisory URL), or undefined. */
const ghsaIn = (text) => String(text ?? '').match(/GHSA-[a-z0-9-]+/i)?.[0];

/** The default answer to "try again?": too many requests, or the server failed. */
const retryable = (status) => status === 429 || status >= 500;

/**
 * fetch for the services vexproof calls (OSV, the npm registry, GitHub): each attempt times out, and network
 * errors and the responses `retryOn(status, response)` picks (by default 429 and 5xx) are retried with backoff
 * (a Retry-After header, when sent, sets the wait, up to a minute). Anything else is returned as it is. Throws
 * once the retries are spent, so a run never continues on a call that did not happen; with `returnLast`, a
 * response that was still being retried is returned instead, for a caller that explains it in its own terms.
 */
export async function fetchRetrying(url, init = {}, { fetchImpl = globalThis.fetch, retries = RETRIES, timeoutMs = TIMEOUT_MS, sleep = pause, retryOn = retryable, returnLast = false } = {}) {
  let lastError;

  for (let attempt = 0; ; attempt++) {
    let wait = Math.min(500 * 2 ** attempt, 8000);

    try {
      const response = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
      const status = response.status ?? (response.ok ? 200 : 500);
      if (response.ok || !retryOn(status, response)) {
        return response;
      }
      if (returnLast && attempt >= retries) {
        return response;
      }

      lastError = new Error(`HTTP ${status}`);
      const retryAfter = Number(response.headers?.get?.('retry-after'));
      if (retryAfter > 0) wait = Math.min(retryAfter * 1000, MAX_WAIT_MS);
    } catch (error) {
      lastError = error?.name === 'TimeoutError' ? new Error(`no response within ${timeoutMs / 1000}s`) : error;
    }

    if (attempt >= retries) {
      throw new Error(`${url}: ${lastError.message} (gave up after ${attempt + 1} attempts)`);
    }
    await sleep(wait);
  }
}

/**
 * Query OSV for every npm component in a lockfile SBOM. Returns internal [{ purl, ids }].
 *
 * OSV pages a batch's results: a query with many vulnerabilities comes back with a next_page_token, and only
 * some queries of a batch may have one. Each such query is asked again with its token until none is left, so
 * no finding is lost to paging.
 */
export async function fetchOsvFindings(lockfileSbom, { fetchImpl = globalThis.fetch, sleep = pause } = {}) {
  const packages = sbomPurls(lockfileSbom)
    .map((purl) => ({ purl, parsed: parsePurl(purl) }))
    .filter(({ parsed }) => parsed && parsed.type === 'npm' && parsed.version);

  const idsByPurl = new Map();
  const ask = async (pending) => {
    const body = { queries: pending.map(({ parsed, pageToken }) => ({ package: { name: parsed.name, ecosystem: 'npm' }, version: parsed.version, ...(pageToken ? { page_token: pageToken } : {}) })) };
    let response;
    try {
      response = await fetchRetrying(OSV_BATCH, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }, { fetchImpl, sleep });
    } catch (error) {
      throw new Error(`OSV lookup failed: ${error.message}. Pass --findings with a scanner's output to run without it.`);
    }
    if (!response.ok) {
      throw new Error(`OSV lookup failed: HTTP ${response.status}. Pass --findings with a scanner's output to run without it.`);
    }

    return (await response.json()).results ?? [];
  };

  for (let start = 0; start < packages.length; start += BATCH_SIZE) {
    let pending = packages.slice(start, start + BATCH_SIZE);

    while (pending.length) {
      const results = await ask(pending);
      const next = [];
      results.forEach((result, index) => {
        const query = pending[index];
        const ids = idsByPurl.get(query.purl) ?? [];
        for (const vuln of result?.vulns ?? []) if (!ids.includes(vuln.id)) ids.push(vuln.id);
        idsByPurl.set(query.purl, ids);
        if (result?.next_page_token) next.push({ ...query, pageToken: result.next_page_token });
      });
      pending = next;
    }
  }

  return [...idsByPurl].filter(([, ids]) => ids.length).map(([purl, ids]) => ({ purl, ids }));
}

/** Map of npm package name → the versions of it in the lockfile SBOM, in the order they are listed. */
function lockfileVersions(lockfileSbom) {
  const versions = new Map();
  for (const purl of sbomPurls(lockfileSbom ?? {})) {
    const parsed = parsePurl(purl);
    if (parsed?.type !== 'npm' || !parsed.version) {
      continue;
    }

    const known = versions.get(parsed.name) ?? [];
    if (!known.includes(parsed.version)) known.push(parsed.version);
    versions.set(parsed.name, known);
  }

  return versions;
}

/**
 * Convert `npm audit --json` output. Audit output names no installed versions; each advisory carries its range,
 * so every version of the package in the lockfile SBOM inside that range gets the finding (a package installed
 * at 8.4.30 and 8.5.23 gets it only on 8.4.30). Without a lockfile version in range, the first one is used.
 */
export function fromNpmAudit(audit, lockfileSbom) {
  const versions = lockfileVersions(lockfileSbom);
  const findings = [];

  for (const [name, vulnerability] of Object.entries(audit?.vulnerabilities ?? {})) {
    // `via` holds advisory objects for the package itself, or strings naming the dependency that carries the advisory
    const advisories = (vulnerability.via ?? []).filter((via) => typeof via === 'object' && via.url);
    for (const advisory of advisories) {
      const id = ghsaIn(advisory.url) ?? String(advisory.source);
      const installed = versions.get(name) ?? [];
      const inRange = advisory.range ? installed.filter((version) => inAdvisoryRange(version, advisory.range)) : [];
      for (const version of inRange.length ? inRange : [installed[0]]) findings.push({ purl: npmPurl(name, version), id, aliases: [] });
    }
  }

  return mergeFindings(findings);
}

// inAdvisoryRange lives in versions.js; it is exported from here too, where it has always been
export { inAdvisoryRange };

const looksLikeBunAudit = (json) => json && typeof json === 'object' && !Array.isArray(json) && Object.keys(json).length > 0
  && Object.values(json).every((advisories) => Array.isArray(advisories)
    && advisories.every((advisory) => advisory && typeof advisory === 'object' && 'url' in advisory && 'vulnerable_versions' in advisory));

/**
 * `bun audit --json`: {"lodash":[{url:".../GHSA-…", vulnerable_versions:">=4.0.0 <=4.17.22", …}]}. No installed
 * version is given, so every version of the package in the lockfile SBOM is checked against each advisory's range.
 */
export function fromBunAudit(audit, lockfileSbom) {
  const versions = lockfileVersions(lockfileSbom);
  const findings = [];

  for (const [name, advisories] of Object.entries(audit)) {
    const installed = versions.get(name) ?? [];
    for (const advisory of advisories) {
      const id = ghsaIn(advisory.url) ?? String(advisory.id);
      // bun reported the advisory for this package, so it stands even when no listed version seems to be in its
      // range: then it is attached to every installed version (or, with none listed, to the package)
      const inRange = installed.filter((version) => inAdvisoryRange(version, advisory.vulnerable_versions));
      const attachTo = inRange.length ? inRange : installed.length ? installed : [undefined];
      for (const version of attachTo) findings.push({ purl: npmPurl(name, version), id, aliases: [] });
    }
  }

  return mergeFindings(findings);
}

// ---------- scanners ----------

const NPM_TRIVY_TYPES = new Set(['npm', 'yarn', 'pnpm', 'bun', 'node-pkg']);
const isNpmPurl = (purl) => typeof purl === 'string' && purl.startsWith('pkg:npm/');

/** `trivy fs|sbom --format json`. Trivy reports npm issues by CVE; VendorIDs carry GHSA ids when present. */
function fromTrivy(report) {
  const findings = [];
  for (const result of report?.Results ?? []) {
    if (!NPM_TRIVY_TYPES.has(result.Type)) {
      continue;
    }

    for (const vulnerability of result.Vulnerabilities ?? []) {
      const purl = vulnerability.PkgIdentifier?.PURL ?? npmPurl(vulnerability.PkgName, vulnerability.InstalledVersion);
      if (!isNpmPurl(purl)) {
        continue;
      }

      findings.push({ purl, id: vulnerability.VulnerabilityID, aliases: vulnerability.VendorIDs ?? [] });
    }
  }

  return mergeFindings(findings);
}

/** `grype <target> -o json`. For npm, the id is usually a GHSA and relatedVulnerabilities hold the CVE. */
export function fromGrype(report) {
  const findings = [];
  for (const match of report?.matches ?? []) {
    const artifact = match.artifact ?? {};
    const purl = artifact.purl || (artifact.type === 'npm' ? npmPurl(artifact.name, artifact.version) : null);
    if (!isNpmPurl(purl)) {
      continue;
    }

    findings.push({ purl, id: match.vulnerability?.id, aliases: (match.relatedVulnerabilities ?? []).map((related) => related.id) });
  }

  return mergeFindings(findings.filter((finding) => finding.id));
}

/** `snyk test --json` (one project, or an array for --all-projects). Snyk's own ids become aliases. */
export function fromSnyk(report) {
  const findings = [];
  for (const project of Array.isArray(report) ? report : [report]) {
    if (project?.packageManager && !['npm', 'yarn', 'pnpm'].includes(project.packageManager)) {
      continue;
    }

    for (const vulnerability of project?.vulnerabilities ?? []) {
      const ids = [...(vulnerability.identifiers?.GHSA ?? []), ...(vulnerability.identifiers?.CVE ?? [])];
      const id = ids[0] ?? vulnerability.id;
      const aliases = [...ids.slice(1), vulnerability.id].filter((alias) => alias && alias !== id);
      findings.push({ purl: npmPurl(vulnerability.packageName ?? vulnerability.moduleName, vulnerability.version), id, aliases });
    }
  }

  return mergeFindings(findings); // Snyk repeats an issue once per dependency path
}

/** `pnpm audit --json` and `npm audit --json` from npm 6: an advisories map with a version per finding. */
function fromPnpmAudit(report) {
  const findings = [];
  for (const advisory of Object.values(report?.advisories ?? {})) {
    const id = advisory.github_advisory_id ?? ghsaIn(advisory.url) ?? String(advisory.id);
    const aliases = (advisory.cves ?? []).filter((cve) => cve !== id);
    for (const finding of advisory.findings ?? []) findings.push({ purl: npmPurl(advisory.module_name, finding.version), id, aliases });
  }

  return mergeFindings(findings);
}

/**
 * OSV knows every alias (GHSA ↔ CVE). One GET per unique id. An id OSV does not know keeps only itself; so does
 * one OSV could not be reached for, after the retries: aliases help scanners match a VEX, and a run is not
 * stopped for want of them. Returns { findings, looked, resolved, unreachable, added }.
 */
export async function enrichAliases(findings, { fetchImpl = globalThis.fetch, limit = 8, sleep = pause } = {}) {
  const ids = [...new Set(findings.map((finding) => finding.id))];
  const aliasesById = new Map();
  let unreachable = 0;

  for (let start = 0; start < ids.length; start += limit) {
    await Promise.all(ids.slice(start, start + limit).map(async (id) => {
      try {
        const response = await fetchRetrying(`${OSV_VULN}${encodeURIComponent(id)}`, {}, { fetchImpl, sleep });
        if (response.ok) aliasesById.set(id, (await response.json()).aliases ?? []);
      } catch {
        unreachable++;
      }
    }));
  }

  let added = 0;
  for (const finding of findings) {
    for (const alias of aliasesById.get(finding.id) ?? []) {
      if (alias === finding.id || finding.aliases.includes(alias)) {
        continue;
      }

      finding.aliases.push(alias);
      added++;
    }
  }

  return { findings, looked: ids.length, resolved: aliasesById.size, unreachable, added };
}

/** Sniff a findings file's format. */
export function detectFormat(json) {
  if (Array.isArray(json) && json.length && (json[0]?.vulnerabilities || json[0]?.packageManager)) {
    return 'snyk';
  }
  if (Array.isArray(json)) {
    return 'internal';
  }
  if (json?.auditReportVersion) {
    return 'npm-audit';
  }
  if (json?.advisories && typeof json.advisories === 'object' && json?.metadata) {
    return 'pnpm-audit';
  }
  if (json?.SchemaVersion && Array.isArray(json?.Results)) {
    return 'trivy';
  }
  if (Array.isArray(json?.matches) && (json?.descriptor || json?.source)) {
    return 'grype';
  }
  if (Array.isArray(json?.vulnerabilities) && ('packageManager' in json || 'projectName' in json || 'dependencyCount' in json)) {
    return 'snyk';
  }
  if (Array.isArray(json?.results)) {
    return 'osv-scanner';
  }
  if (looksLikeBunAudit(json)) {
    return 'bun-audit';
  }
  if (json && typeof json === 'object' && !Array.isArray(json) && !Object.keys(json).length) {
    // `{}` is what bun audit prints for a clean project, and also what a broken tool may write
    throw new Error('the findings file is an empty JSON object, which says nothing about which advisories were looked for. If it is a clean `bun audit`, use another scanner\'s output (npm audit, osv-scanner), or leave --findings out to query OSV');
  }

  throw new Error('Unrecognised findings format (expected npm, pnpm, yarn or bun audit, osv-scanner, Trivy, Grype or Snyk JSON, or [{purl, ids}])');
}

/** Any supported findings JSON → { format, findings }, findings as [{ purl, id, aliases }] or the internal shape. */
export function readFindings(json, lockfileSbom) {
  const format = detectFormat(json);
  const readers = {
    'npm-audit': () => fromNpmAudit(json, lockfileSbom),
    'pnpm-audit': () => fromPnpmAudit(json),
    'bun-audit': () => fromBunAudit(json, lockfileSbom),
    trivy: () => fromTrivy(json),
    grype: () => fromGrype(json),
    snyk: () => fromSnyk(json),
  };

  return { format, findings: readers[format] ? readers[format]() : json };
}

/** Total of a Yarn 1 auditSummary's counts, or null when the line has none. */
function summaryTotal(summary) {
  const counts = summary?.data?.vulnerabilities;
  if (!counts || typeof counts !== 'object') {
    return null;
  }

  return Object.values(counts).reduce((sum, count) => sum + (Number(count) || 0), 0);
}

/**
 * Findings from file text. Handles single JSON documents and Yarn's audits, which write one JSON object per line:
 * Yarn 1's `yarn audit --json` (auditAdvisory lines carry the pnpm audit shape, and an auditSummary line counts
 * them) and Yarn 2+'s `yarn npm audit --json --recursive`.
 */
export function readFindingsText(text, lockfileSbom) {
  let whole;
  try {
    whole = JSON.parse(text);
  } catch (error) {
    if (!(error instanceof SyntaxError)) {
      throw error;
    }
  }
  // one JSON document, unless it is a single line of Yarn 1's output (a clean audit writes only its summary)
  const yarnLine = (value) => value && typeof value === 'object' && ['auditSummary', 'auditAdvisory'].includes(value.type);
  if (whole !== undefined && !yarnLine(whole)) {
    return readFindings(whole, lockfileSbom);
  }

  const lines = text.split(/\r?\n/).filter((line) => line.trim()).map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  });

  // Yarn 1: {"type":"auditAdvisory","data":{"advisory":{...}}}
  const advisories = {};
  for (const line of lines) {
    if (line?.type !== 'auditAdvisory' || !line.data?.advisory) {
      continue;
    }

    advisories[line.data.advisory.id ?? Object.keys(advisories).length] = line.data.advisory;
  }
  if (Object.keys(advisories).length) {
    return { format: 'yarn-audit', findings: fromPnpmAudit({ advisories, metadata: {} }) };
  }

  // Yarn 1 on a clean project writes only its summary: zero findings, when the summary says zero
  const summary = lines.find((line) => line?.type === 'auditSummary');
  if (summary) {
    const total = summaryTotal(summary);
    if (total === 0) {
      return { format: 'yarn-audit', findings: [] };
    }
    throw new Error(`the yarn audit summary counts ${total ?? 'an unknown number of'} vulnerabilities, but the file holds no advisory for them. Run yarn audit --json again and pass its whole output`);
  }

  // Yarn 2+: {"value":"lodash","children":{"ID":…,"URL":".../GHSA-…","Tree Versions":["4.17.21"]}}
  const berry = [];
  for (const line of lines) {
    const children = line?.children;
    const ghsa = ghsaIn(children?.URL);
    if (!line?.value || !ghsa) {
      continue; // deprecation notices carry no advisory
    }

    for (const version of children['Tree Versions'] ?? []) berry.push({ purl: npmPurl(line.value, version), id: ghsa, aliases: [] });
  }
  if (berry.length) {
    return { format: 'yarn-berry-audit', findings: mergeFindings(berry) };
  }

  throw new Error(text.trim()
    ? 'Unrecognised findings file: not JSON, and no yarn audit advisories found'
    : 'the findings file is empty. A scanner that found nothing still says so in its output; pass that, or leave --findings out to query OSV');
}
