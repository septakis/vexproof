// SPDX-License-Identifier: MIT
// Derived module rules: which files of a package an advisory's fix changed.
//
// For a finding on name@V with vulnerable range R:
//   F = the first published version after V outside R (the fix)
// The runtime files of V that differ in F, or are gone from F, are the rule files. Diffing V against F, not the
// last vulnerable release against F, matters: advisory ranges are sometimes wider than the real fix (lodash-es
// fixed GHSA-xxjr-mmjv-4gpg's code in 4.17.22, yet 4.17.22 is inside its range), and the narrow diff then
// shows only unrelated files.
//
// A derived rule is weaker than a hand-checked one: a fix can change a caller (say, add validation in an
// entry file) while the vulnerable code sits in a file it didn't touch. So derived rules only SUGGEST a
// verdict unless the run passes --accept-derived, and every refusal below errs toward no rule at all.
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { fetchRetrying } from './sources.js';
import { parseVersion, compareVersions, inAdvisoryRange } from './versions.js';

const REGISTRY = 'https://registry.npmjs.org';

// ---------- versions ----------

export { compareVersions }; // from versions.js, exported here as before

/**
 * { vulnerable: L, fixed: F } for installed V, or { reason } when no fix brackets it. `range` is the whole of
 * the advisory's vulnerable range: when the registry lists it once per release line, all of those ranges joined
 * with ||, so that a release still vulnerable on another line is not taken for the fix.
 */
export function fixBoundary(versions, installed, range) {
  const stable = versions.filter((version) => parseVersion(version) && !parseVersion(version).pre.length).sort(compareVersions);
  if (!parseVersion(installed)) {
    return { reason: `cannot read version ${installed}` };
  }

  const fixed = stable.find((version) => compareVersions(version, installed) > 0 && !inAdvisoryRange(version, range));
  if (!fixed) {
    return { reason: 'no fixed version has been published' };
  }

  const vulnerable = stable
    .filter((version) => compareVersions(version, fixed) < 0
      && compareVersions(version, installed) >= 0
      && inAdvisoryRange(version, range))
    .at(-1);
  if (!vulnerable) {
    return { reason: `no vulnerable release between ${installed} and ${fixed}` };
  }

  return { vulnerable, fixed };
}

// ---------- tarballs ----------

/** Minimal ustar/pax reader: Map<path inside the package, Buffer>. */
export function untar(tgz) {
  const archive = gunzipSync(tgz);
  const files = new Map();
  let offset = 0;
  let longName = null;

  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      break;
    }

    const field = (start, end) => header.subarray(start, end).toString('utf8').replace(/\0.*$/s, '');
    let name = field(0, 100);
    const prefix = field(345, 500);
    if (prefix) {
      name = `${prefix}/${name}`;
    }

    // A size that can't be read, or a file cut short, would end the reading early, and the files after it would
    // look absent from the package. That could hide the very file a fix changed, so it stops the reading instead.
    const sizeText = field(124, 136).trim() || '0';
    if (!/^[0-7]+$/.test(sizeText)) {
      throw new Error(`unreadable tar archive: the entry "${name}" gives its size as "${sizeText}"`);
    }
    const size = parseInt(sizeText, 8);
    if (offset + 512 + size > archive.length) {
      throw new Error(`unreadable tar archive: the entry "${name}" is cut short`);
    }

    const type = String.fromCharCode(header[156] || 48);
    const body = archive.subarray(offset + 512, offset + 512 + size);

    if (type === 'x') {
      const match = /\d+ path=([^\n]+)\n/.exec(body.toString('utf8'));
      if (match) longName = match[1];
    } else if (type === 'L') {
      longName = body.toString('utf8').replace(/\0.*$/s, '');
    } else if (type === '0' || type === '\0' || type === '7') {
      // npm tarballs nest everything under one folder, usually package/ (written "./package/" by some tools)
      const path = (longName ?? name).replace(/^(\.\/)+/, '').replace(/^[^/]+\//, '');
      files.set(path, Buffer.from(body));
      longName = null;
    } else {
      longName = null;
    }

    offset += 512 + Math.ceil(size / 512) * 512;
  }

  return files;
}

const RUNTIME = /\.(m|c)?js$/;
const NOT_RUNTIME = /(^|\/)(test|tests|__tests__|spec|specs|benchmark|benchmarks|example|examples|docs?|fixtures?|coverage)\/|\.d\.(m|c)?ts$|\.(test|spec)\.(m|c)?js$/;
/** Whether a package file is runtime JavaScript: not a test, spec, benchmark, example, doc, fixture or coverage file. */
export const isRuntimeFile = (filePath) => RUNTIME.test(filePath) && !NOT_RUNTIME.test(filePath);

const CODE = /\.(m|c)?js$/;
const DEPENDENCY_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];

/**
 * Files of V to treat as vulnerable: every JavaScript file of V that differs in F or is missing from F. Files in
 * folders that usually hold no runtime code (spec/, docs/, examples/) are included when they changed: some
 * packages run code from them (yaml's dist/doc, three's examples/jsm), and naming a file that never ships costs
 * nothing. A file that differs only in V's version number written as F's (a version constant) did not change.
 *
 * Refuses (returns { reason }) when
 *   - the fix changed the package's dependencies: the vulnerable code may be in one of them, out of sight;
 *   - no runtime file changed (the fix was elsewhere, or not in code);
 *   - most of V's runtime files moved away (a reorganised package, whose fix can't be located by path).
 * `versions` ({ installed, fixed }) enables the version-constant rule; without it files compare as bytes.
 */
export function diffForRule({ installedFiles, fixedFiles, versions = null }) {
  const dependenciesOf = (files) => {
    try {
      const manifest = JSON.parse(files.get('package.json')?.toString('utf8') ?? '{}');

      return JSON.stringify(DEPENDENCY_FIELDS.map((field) => manifest[field] ?? {}));
    } catch {
      return null;
    }
  };
  if (installedFiles.has('package.json')
    && fixedFiles.has('package.json')
    && dependenciesOf(installedFiles) !== dependenciesOf(fixedFiles)) {
    return { reason: 'the fix also changed the package\'s dependencies, so the vulnerable code may be in one of them' };
  }

  const same = (before, after) => after.equals(before)
    || (versions && before.toString('utf8').split(versions.installed).join(versions.fixed) === after.toString('utf8'));
  const code = [...installedFiles.keys()].filter((filePath) => CODE.test(filePath));
  const runtime = code.filter(isRuntimeFile);
  const changed = [];
  const gone = [];
  for (const filePath of code) {
    const after = fixedFiles.get(filePath);
    if (!after) {
      gone.push(filePath);
    } else if (!same(installedFiles.get(filePath), after)) {
      changed.push(filePath);
    }
  }

  if (![...changed, ...gone].some(isRuntimeFile)) {
    return { reason: 'the fix changed no runtime JavaScript file (a dependency update or a non-code fix)' };
  }

  const goneRuntime = gone.filter(isRuntimeFile).length;
  if (goneRuntime > runtime.length / 2) {
    return { reason: `the package was reorganised before the fix (${goneRuntime} of ${runtime.length} files moved)` };
  }

  return { files: [...changed, ...gone].sort(), runtimeFiles: runtime.length };
}

// ---------- registry ----------

async function fetchJson(url, fetchImpl, init) {
  const response = await fetchRetrying(url, init, { fetchImpl });
  if (!response.ok) {
    throw new Error(`${url}: HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Throws unless the bytes are the ones the registry's own record of the version describes (`dist.integrity`,
 * or `dist.shasum` for releases from before npm recorded one). A rule says which files a fix changed; one made
 * from a download that was cut short or altered on the way would say it about the wrong files.
 */
export function checkTarball(bytes, dist, key) {
  const integrity = String(dist?.integrity ?? '')
    .split(/\s+/)
    .map((entry) => /^(sha512|sha384|sha256)-(.+)$/.exec(entry))
    .filter(Boolean)
    .sort((left, right) => right[1].localeCompare(left[1]))[0]; // the strongest listed
  if (integrity) {
    if (createHash(integrity[1]).update(bytes).digest('base64') !== integrity[2]) {
      throw new Error(`tarball ${key} does not match the registry's checksum (${integrity[1]})`);
    }

    return;
  }

  if (typeof dist?.shasum === 'string' && dist.shasum) {
    if (createHash('sha1').update(bytes).digest('hex') !== dist.shasum.toLowerCase()) {
      throw new Error(`tarball ${key} does not match the registry's checksum (sha1)`);
    }

    return;
  }

  throw new Error(`the registry lists no checksum for ${key}, so its tarball can't be checked`);
}

async function tarball(name, version, fetchImpl, cache, dist) {
  const key = `${name}@${version}`;
  if (!cache.has(key)) {
    const unscopedName = name.startsWith('@') ? name.split('/')[1] : name;
    const response = await fetchRetrying(`${REGISTRY}/${name.replace('/', '%2f')}/-/${unscopedName}-${version}.tgz`, {}, { fetchImpl });
    if (!response.ok) {
      throw new Error(`tarball ${key}: HTTP ${response.status}`);
    }

    const bytes = Buffer.from(await response.arrayBuffer());
    checkTarball(bytes, dist, key);
    cache.set(key, untar(bytes));
  }

  return cache.get(key);
}

/** npm's advisory API: every advisory affecting these versions, with its range. */
async function npmAdvisories(byName, { fetchImpl = globalThis.fetch } = {}) {
  return fetchJson(`${REGISTRY}/-/npm/v1/security/advisories/bulk`, fetchImpl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(byName),
  });
}

/**
 * Derive rules for findings [{purl-parsed name, version, id, aliases}].
 * Returns { rules (module-rules.json shape, origin "derived"), report: [{name, version, id, rule? , reason?}] }.
 */
export async function deriveRules(findings, { fetchImpl = globalThis.fetch, now = new Date() } = {}) {
  const byName = {};
  for (const finding of findings) {
    (byName[finding.name] ??= new Set()).add(finding.version);
  }

  const versionsByName = Object.fromEntries(Object.entries(byName).map(([name, versions]) => [name, [...versions]]));
  const advisories = await npmAdvisories(versionsByName, { fetchImpl });

  const packuments = new Map();
  const cache = new Map();
  const rules = { schema: 1, version: now.toISOString().slice(0, 10), origin: 'derived', packages: {} };
  const report = [];

  for (const finding of findings) {
    const names = [finding.id, ...(finding.aliases ?? [])];
    // One advisory can be listed once per release line, each with its own range. The entry covering this version
    // names it; the fix must be outside all of them (see fixBoundary).
    const entries = (advisories[finding.name] ?? []).filter((entry) => names.some((name) => entry.url?.endsWith(`/${name}`)));
    const advisory = entries.find((entry) => inAdvisoryRange(finding.version, entry.vulnerable_versions));
    const wholeRange = entries
      .map((entry) => entry.vulnerable_versions)
      .filter((range) => typeof range === 'string' && range.trim())
      .join(' || ');
    const row = { name: finding.name, version: finding.version, id: finding.id };
    report.push(row);
    if (!advisory) {
      row.reason = 'advisory not in the npm registry\'s database';
      continue;
    }

    try {
      if (!packuments.has(finding.name)) {
        packuments.set(finding.name, await fetchJson(`${REGISTRY}/${finding.name.replace('/', '%2f')}`, fetchImpl));
      }

      const publishedVersions = Object.keys(packuments.get(finding.name).versions ?? {});
      const boundary = fixBoundary(publishedVersions, finding.version, wholeRange || advisory.vulnerable_versions);
      if (boundary.reason) {
        row.reason = boundary.reason;
        continue;
      }

      const versionRecords = packuments.get(finding.name).versions ?? {};
      const downloads = [finding.version, boundary.fixed]
        .map((version) => tarball(finding.name, version, fetchImpl, cache, versionRecords[version]?.dist));
      const [installedFiles, fixedFiles] = await Promise.all(downloads);
      const diff = diffForRule({ installedFiles, fixedFiles, versions: { installed: finding.version, fixed: boundary.fixed } });
      if (diff.reason) {
        row.reason = diff.reason;
        continue;
      }

      const ghsa = advisory.url.match(/GHSA-[a-z0-9-]+/i)?.[0] ?? finding.id;
      const packageRules = (rules.packages[finding.name] ??= { advisories: {} });
      const key = `${ghsa}@${finding.version}`;
      packageRules.advisories[key] = {
        id: ghsa,
        versions: [finding.version],
        files: diff.files,
        affects: advisory.title,
        source: advisory.url,
        origin: 'derived',
        derivedFrom: { installed: finding.version, fixed: boundary.fixed },
        aliases: [...new Set(names.filter((name) => name !== ghsa))],
      };
      Object.assign(row, { rule: key, files: diff.files, runtimeFiles: diff.runtimeFiles, ...boundary });
    } catch (error) {
      row.reason = error.message;
    }
  }

  return { rules, report };
}
