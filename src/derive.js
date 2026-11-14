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
  const stable = versions.filter((v) => parseVersion(v) && !parseVersion(v).pre.length).sort(compareVersions);
  if (!parseVersion(installed)) return { reason: `cannot read version ${installed}` };
  const fixed = stable.find((v) => compareVersions(v, installed) > 0 && !inAdvisoryRange(v, range));
  if (!fixed) return { reason: 'no fixed version has been published' };
  const vulnerable = stable.filter((v) => compareVersions(v, fixed) < 0 && compareVersions(v, installed) >= 0 && inAdvisoryRange(v, range)).at(-1);
  if (!vulnerable) return { reason: `no vulnerable release between ${installed} and ${fixed}` };
  return { vulnerable, fixed };
}

// ---------- tarballs ----------

/** Minimal ustar/pax reader: Map<path inside the package, Buffer>. */
export function untar(tgz) {
  const buf = gunzipSync(tgz);
  const files = new Map();
  let off = 0, longName = null;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    const str = (s, e) => h.subarray(s, e).toString('utf8').replace(/\0.*$/s, '');
    let name = str(0, 100);
    const prefix = str(345, 500);
    if (prefix) name = `${prefix}/${name}`;
    const size = parseInt(str(124, 136).trim() || '0', 8);
    const type = String.fromCharCode(h[156] || 48);
    const body = buf.subarray(off + 512, off + 512 + size);
    if (type === 'x') { const m = /\d+ path=([^\n]+)\n/.exec(body.toString('utf8')); if (m) longName = m[1]; }
    else if (type === 'L') longName = body.toString('utf8').replace(/\0.*$/s, '');
    else if (type === '0' || type === '\0' || type === '7') {
      const path = (longName ?? name).replace(/^[^/]+\//, ''); // npm tarballs nest everything under package/
      files.set(path, Buffer.from(body));
      longName = null;
    } else longName = null;
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return files;
}

const RUNTIME = /\.(m|c)?js$/;
const NOT_RUNTIME = /(^|\/)(test|tests|__tests__|spec|specs|benchmark|benchmarks|example|examples|docs?|fixtures?|coverage)\/|\.d\.(m|c)?ts$|\.(test|spec)\.(m|c)?js$/;
export const isRuntimeFile = (p) => RUNTIME.test(p) && !NOT_RUNTIME.test(p);

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
  const deps = (files) => { try { const p = JSON.parse(files.get('package.json')?.toString('utf8') ?? '{}'); return JSON.stringify(DEPENDENCY_FIELDS.map((k) => p[k] ?? {})); } catch { return null; } };
  if (installedFiles.has('package.json') && fixedFiles.has('package.json') && deps(installedFiles) !== deps(fixedFiles)) {
    return { reason: 'the fix also changed the package\'s dependencies, so the vulnerable code may be in one of them' };
  }
  const same = (before, after) => after.equals(before)
    || (versions && before.toString('utf8').split(versions.installed).join(versions.fixed) === after.toString('utf8'));
  const code = [...installedFiles.keys()].filter((p) => CODE.test(p));
  const runtime = code.filter(isRuntimeFile);
  const changed = [], gone = [];
  for (const p of code) {
    const after = fixedFiles.get(p);
    if (!after) gone.push(p);
    else if (!same(installedFiles.get(p), after)) changed.push(p);
  }
  if (![...changed, ...gone].some(isRuntimeFile)) return { reason: 'the fix changed no runtime JavaScript file (a dependency update or a non-code fix)' };
  const goneRuntime = gone.filter(isRuntimeFile).length;
  if (goneRuntime > runtime.length / 2) return { reason: `the package was reorganised before the fix (${goneRuntime} of ${runtime.length} files moved)` };
  return { files: [...changed, ...gone].sort(), runtimeFiles: runtime.length };
}

// ---------- registry ----------

async function json(url, fetchImpl, init) {
  const r = await fetchRetrying(url, init, { fetchImpl });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.json();
}
/**
 * Throws unless the bytes are the ones the registry's own record of the version describes (`dist.integrity`,
 * or `dist.shasum` for releases from before npm recorded one). A rule says which files a fix changed; one made
 * from a download that was cut short or altered on the way would say it about the wrong files.
 */
export function checkTarball(bytes, dist, key) {
  const sri = String(dist?.integrity ?? '').split(/\s+/).map((x) => /^(sha512|sha384|sha256)-(.+)$/.exec(x)).filter(Boolean)
    .sort((a, b) => b[1].localeCompare(a[1]))[0]; // the strongest listed
  if (sri) {
    if (createHash(sri[1]).update(bytes).digest('base64') !== sri[2]) throw new Error(`tarball ${key} does not match the registry's checksum (${sri[1]})`);
    return;
  }
  if (typeof dist?.shasum === 'string' && dist.shasum) {
    if (createHash('sha1').update(bytes).digest('hex') !== dist.shasum.toLowerCase()) throw new Error(`tarball ${key} does not match the registry's checksum (sha1)`);
    return;
  }
  throw new Error(`the registry lists no checksum for ${key}, so its tarball can't be checked`);
}

async function tarball(name, version, fetchImpl, cache, dist) {
  const key = `${name}@${version}`;
  if (!cache.has(key)) {
    const base = name.startsWith('@') ? name.split('/')[1] : name;
    const r = await fetchRetrying(`${REGISTRY}/${name.replace('/', '%2f')}/-/${base}-${version}.tgz`, {}, { fetchImpl });
    if (!r.ok) throw new Error(`tarball ${key}: HTTP ${r.status}`);
    const bytes = Buffer.from(await r.arrayBuffer());
    checkTarball(bytes, dist, key);
    cache.set(key, untar(bytes));
  }
  return cache.get(key);
}

/** npm's advisory API: every advisory affecting these versions, with its range. */
export async function npmAdvisories(byName, { fetchImpl = globalThis.fetch } = {}) {
  return json(`${REGISTRY}/-/npm/v1/security/advisories/bulk`, fetchImpl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(byName),
  });
}

/**
 * Derive rules for findings [{purl-parsed name, version, id, aliases}].
 * Returns { rules (module-rules.json shape, origin "derived"), report: [{name, version, id, rule? , reason?}] }.
 */
export async function deriveRules(findings, { fetchImpl = globalThis.fetch, now = new Date() } = {}) {
  const byName = {};
  for (const f of findings) (byName[f.name] ??= new Set()).add(f.version);
  const advisories = await npmAdvisories(Object.fromEntries(Object.entries(byName).map(([k, v]) => [k, [...v]])), { fetchImpl });
  const packuments = new Map(), cache = new Map();
  const rules = { schema: 1, version: now.toISOString().slice(0, 10), origin: 'derived', packages: {} };
  const report = [];
  for (const f of findings) {
    const names = [f.id, ...(f.aliases ?? [])];
    // One advisory can be listed once per release line, each with its own range. The entry covering this version
    // names it; the fix must be outside all of them (see fixBoundary).
    const entries = (advisories[f.name] ?? []).filter((a) => names.some((n) => a.url?.endsWith(`/${n}`)));
    const adv = entries.find((a) => inAdvisoryRange(f.version, a.vulnerable_versions));
    const wholeRange = entries.map((a) => a.vulnerable_versions).filter((r) => typeof r === 'string' && r.trim()).join(' || ');
    const row = { name: f.name, version: f.version, id: f.id };
    report.push(row);
    if (!adv) { row.reason = 'advisory not in the npm registry\'s database'; continue; }
    try {
      if (!packuments.has(f.name)) packuments.set(f.name, await json(`${REGISTRY}/${f.name.replace('/', '%2f')}`, fetchImpl));
      const b = fixBoundary(Object.keys(packuments.get(f.name).versions ?? {}), f.version, wholeRange || adv.vulnerable_versions);
      if (b.reason) { row.reason = b.reason; continue; }
      const versions = packuments.get(f.name).versions ?? {};
      const [installedFiles, fixedFiles] = await Promise.all([f.version, b.fixed].map((v) => tarball(f.name, v, fetchImpl, cache, versions[v]?.dist)));
      const d = diffForRule({ installedFiles, fixedFiles, versions: { installed: f.version, fixed: b.fixed } });
      if (d.reason) { row.reason = d.reason; continue; }
      const ghsa = adv.url.match(/GHSA-[a-z0-9-]+/i)?.[0] ?? f.id;
      const pkg = (rules.packages[f.name] ??= { advisories: {} });
      const key = `${ghsa}@${f.version}`;
      pkg.advisories[key] = {
        id: ghsa,
        versions: [f.version],
        files: d.files,
        affects: adv.title,
        source: adv.url,
        origin: 'derived',
        derivedFrom: { installed: f.version, fixed: b.fixed },
        aliases: [...new Set(names.filter((n) => n !== ghsa))],
      };
      Object.assign(row, { rule: key, files: d.files, runtimeFiles: d.runtimeFiles, ...b });
    } catch (e) {
      row.reason = e.message;
    }
  }
  return { rules, report };
}
