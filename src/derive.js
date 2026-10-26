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
import { inAdvisoryRange } from './sources.js';

const REGISTRY = 'https://registry.npmjs.org';

// ---------- versions ----------

const parse = (v) => {
  const m = /^(\d+)\.(\d+)\.(\d+)(-.+)?$/.exec(v);
  return m ? { n: [+m[1], +m[2], +m[3]], pre: m[4] ?? null } : null;
};
export function compareVersions(a, b) {
  const x = parse(a), y = parse(b);
  for (let i = 0; i < 3; i++) if (x.n[i] !== y.n[i]) return x.n[i] - y.n[i];
  if (x.pre === y.pre) return 0;
  return x.pre ? -1 : 1;
}

/** { vulnerable: L, fixed: F } for installed V, or { reason } when no fix brackets it. */
export function fixBoundary(versions, installed, range) {
  const stable = versions.filter((v) => parse(v) && !parse(v).pre).sort(compareVersions);
  if (!parse(installed)) return { reason: `cannot read version ${installed}` };
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

/**
 * Files of V to treat as vulnerable: every runtime file of V that differs in F or is missing from F.
 * Refuses (returns { reason }) when no runtime file changed (the fix was a dependency update or not in code),
 * or when most of V's runtime files moved away (a reorganised package, whose fix can't be located by path).
 */
export function diffForRule({ installedFiles, fixedFiles }) {
  const runtime = [...installedFiles.keys()].filter(isRuntimeFile);
  const changed = [], gone = [];
  for (const p of runtime) {
    const after = fixedFiles.get(p);
    if (!after) gone.push(p);
    else if (!after.equals(installedFiles.get(p))) changed.push(p);
  }
  if (!changed.length && !gone.length) return { reason: 'the fix changed no runtime JavaScript file (a dependency update or a non-code fix)' };
  if (gone.length > runtime.length / 2) return { reason: `the package was reorganised before the fix (${gone.length} of ${runtime.length} files moved)` };
  return { files: [...changed, ...gone].sort(), runtimeFiles: runtime.length };
}

// ---------- registry ----------

async function json(url, fetchImpl, init) {
  const r = await fetchImpl(url, init);
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.json();
}
async function tarball(name, version, fetchImpl, cache) {
  const key = `${name}@${version}`;
  if (!cache.has(key)) {
    const base = name.startsWith('@') ? name.split('/')[1] : name;
    const r = await fetchImpl(`${REGISTRY}/${name.replace('/', '%2f')}/-/${base}-${version}.tgz`);
    if (!r.ok) throw new Error(`tarball ${key}: HTTP ${r.status}`);
    cache.set(key, untar(Buffer.from(await r.arrayBuffer())));
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
    // one advisory can be listed once per release line, each with its own range: take the one covering this version
    const adv = (advisories[f.name] ?? []).find((a) => names.some((n) => a.url?.endsWith(`/${n}`)) && inAdvisoryRange(f.version, a.vulnerable_versions));
    const row = { name: f.name, version: f.version, id: f.id };
    report.push(row);
    if (!adv) { row.reason = 'advisory not in the npm registry\'s database'; continue; }
    try {
      if (!packuments.has(f.name)) packuments.set(f.name, await json(`${REGISTRY}/${f.name.replace('/', '%2f')}`, fetchImpl));
      const b = fixBoundary(Object.keys(packuments.get(f.name).versions ?? {}), f.version, adv.vulnerable_versions);
      if (b.reason) { row.reason = b.reason; continue; }
      const [installedFiles, fixedFiles] = await Promise.all([f.version, b.fixed].map((v) => tarball(f.name, v, fetchImpl, cache)));
      const d = diffForRule({ installedFiles, fixedFiles });
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
