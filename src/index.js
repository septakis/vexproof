// SPDX-License-Identifier: MIT
// vexproof — turn "this code never made it into the shipped bundle"
// into conservative, auditable VEX (CycloneDX and OpenVEX).
//
// Inputs:
//   - lockfile SBOM  (CycloneDX JSON; everything the lockfile says you depend on)
//   - bundle SBOM    (CycloneDX JSON; what actually survived bundling/tree-shaking)
//   - findings       (vulnerabilities per package, e.g. from osv-scanner --format json,
//                     or the simple internal {purl, ids[]} shape)
//
// Rule (deliberately narrow): a vulnerability is marked `not_affected` with
// justification `code_not_present` ONLY when the vulnerable package name does
// not appear in the bundle SBOM at all. Everything else is `in_triage`.

import { createHash } from 'node:crypto';
import { fingerprintProperties } from './evidence.js';

// ---------- determinism ----------

const UUID_NAMESPACE = Buffer.from('f5466259a7f9427fa41e673c18411e32', 'hex'); // vexproof's own UUIDv5 namespace

/** UUIDv5 of a document's content, so the same output always carries the same serial number. */
export function contentUuid(doc) {
  const h = createHash('sha1').update(UUID_NAMESPACE).update(JSON.stringify(doc)).digest();
  h[6] = (h[6] & 0x0f) | 0x50;
  h[8] = (h[8] & 0x3f) | 0x80;
  const x = h.subarray(0, 16).toString('hex');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}

/**
 * The time to stamp output with: SOURCE_DATE_EPOCH (seconds since 1970, the reproducible-builds convention)
 * when it is set, otherwise now. Throws on a value that is not a whole number of seconds.
 */
export function outputTime(env = process.env) {
  const v = env.SOURCE_DATE_EPOCH;
  if (v === undefined || v === '') return new Date();
  if (!/^\d+$/.test(v)) throw new Error(`SOURCE_DATE_EPOCH must be whole seconds since 1970, got "${v}"`);
  return new Date(Number(v) * 1000);
}

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// ---------- purl helpers ----------

/** "pkg:npm/%40scope/name@1.2.3?x=y" -> { type, name, version } */
export function parsePurl(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return null;
  const body = purl.slice(4).split('?')[0].split('#')[0];
  const slash = body.indexOf('/');
  if (slash < 0) return null;
  const type = body.slice(0, slash);
  let rest = decodeURIComponent(body.slice(slash + 1));
  let version;
  const at = rest.lastIndexOf('@');
  // scoped npm names start with "@", so only treat "@" past index 0 as the version separator
  if (at > 0) {
    version = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  return { type, name: rest, version };
}

export function packageKey(purl) {
  const p = parsePurl(purl);
  return p ? `${p.type}/${p.name}` : null;
}

// ---------- SBOM reading ----------

function walkComponents(list, out) {
  for (const c of list ?? []) {
    out.push(c);
    if (Array.isArray(c.components)) walkComponents(c.components, out);
  }
}

/** All purls in a CycloneDX SBOM (nested components included). */
export function sbomPurls(sbom) {
  const all = [];
  walkComponents(sbom?.components, all);
  return all.map((c) => c.purl).filter(Boolean);
}

export function indexSbom(sbom) {
  const byName = new Map(); // "npm/lodash" -> Set(versions)
  for (const purl of sbomPurls(sbom)) {
    const p = parsePurl(purl);
    if (!p) continue;
    const key = `${p.type}/${p.name}`;
    if (!byName.has(key)) byName.set(key, new Set());
    if (p.version) byName.get(key).add(p.version);
  }
  return byName;
}

// ---------- findings normalisation ----------

export function npmPurl(name, version) {
  const enc = name.startsWith('@') ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${enc}${version ? '@' + version : ''}`;
}

/**
 * Accepts either:
 *   A) internal shape: [{ purl, ids: [...] }] or [{ purl, id, aliases: [...] }]
 *   B) osv-scanner JSON: { results: [{ packages: [{ package:{name,version,ecosystem}, vulnerabilities:[{id, aliases}] }] }] }
 * Returns [{ purl, id, aliases }], one per advisory per package. Two findings for the same
 * package whose ids or aliases overlap (e.g. a GHSA and its CVE) are merged into one.
 */
export function normalizeFindings(input) {
  const raw = [];
  if (Array.isArray(input)) {
    for (const f of input) {
      if (f.id) raw.push({ purl: f.purl, id: f.id, aliases: f.aliases ?? [] });
      else for (const id of f.ids ?? []) raw.push({ purl: f.purl, id, aliases: [] });
    }
  } else {
    for (const r of input?.results ?? []) {
      for (const pkg of r.packages ?? []) {
        const { name, version, ecosystem } = pkg.package ?? {};
        if (!name) continue;
        const eco = String(ecosystem ?? '').toLowerCase();
        const purl = eco === 'npm' ? npmPurl(name, version) : `pkg:${eco}/${name}${version ? '@' + version : ''}`;
        for (const v of pkg.vulnerabilities ?? []) raw.push({ purl, id: v.id, aliases: v.aliases ?? [] });
      }
    }
  }
  return mergeFindings(raw);
}

export function mergeFindings(list) {
  const out = [];
  for (const f of list) {
    const names = new Set([f.id, ...(f.aliases ?? [])]);
    const hit = out.find((o) => o.purl === f.purl && [o.id, ...o.aliases].some((x) => names.has(x)));
    if (hit) {
      for (const n of names) if (n !== hit.id && !hit.aliases.includes(n)) hit.aliases.push(n);
    } else {
      out.push({ purl: f.purl, id: f.id, aliases: [...new Set((f.aliases ?? []).filter((a) => a !== f.id))] });
    }
  }
  return out;
}

/** Attach the aliases a module rule knows (e.g. GHSA ↔ CVE) so every downstream format can match. */
export function applyRuleAliases(findings, rules) {
  for (const f of findings) {
    const p = parsePurl(f.purl);
    const advisories = rules?.packages?.[p?.name]?.advisories ?? {};
    const names = [f.id, ...f.aliases];
    for (const [key, rule] of Object.entries(advisories)) {
      const all = [key, ...(rule.aliases ?? [])];
      if (all.some((x) => names.includes(x))) for (const a of all) if (a !== f.id && !f.aliases.includes(a)) f.aliases.push(a);
    }
  }
  return findings;
}

// ---------- triage ----------

export const VERSION = '1.0.0-beta.3';

/**
 * `moduleCheck` decides whether a package that IS in the bundle still doesn't ship the vulnerable code. It is not
 * part of this file: vexproof Pro supplies one (src/pro/module-check.js, under its own license). Without it,
 * every finding on a bundled package stays in_triage. `pro` says whether its answers may settle findings;
 * when false they are only counted (proWouldSettle).
 */
export function triage({ lockfileSbom, bundleSbom, findings, moduleMap = null, rules = null, moduleCheck = null, pro = false, acceptDerived = false }) {
  const lock = indexSbom(lockfileSbom);
  const bundle = indexSbom(bundleSbom);
  const results = [];
  // An empty bundle SBOM almost always means a broken build or wrong file, not
  // "we ship no third-party code". Refuse to make any not_affected claim from it.
  const bundleUsable = bundle.size > 0;

  for (const f of applyRuleAliases(normalizeFindings(findings), rules)) {
    const key = packageKey(f.purl);
    const parsed = parsePurl(f.purl);
    let state = 'in_triage', justification, detail, level = null, evidence = null, proWouldSettle = false, moduleReason = null;

    if (!key) {
      detail = `Could not parse purl "${f.purl}".`;
    } else if (!bundleUsable) {
      detail = 'Bundle SBOM contains no components; refusing to infer absence from it.';
    } else if (!lock.has(key)) {
      // finding refers to a package we don't even claim to depend on; don't guess
      detail = `${key} is not listed in the lockfile SBOM; no claim made.`;
    } else if (bundle.has(key)) {
      const versions = [...bundle.get(key)].join(', ') || 'unknown version';
      detail = `${key} (${versions}) is present in the shipped bundle; requires manual review.`;
      const m = moduleCheck ? moduleCheck({ key, parsed, id: f.id, aliases: f.aliases, bundleVersions: bundle.get(key), moduleMap, rules }) : { ok: false, reason: null };
      if (m.ok && m.derived && !acceptDerived) {
        // a derived rule only suggests: someone accepts it, per run (--accept-derived) or per finding (review)
        if (pro) {
          moduleReason = 'a derived rule suggests not affected; review it, or pass --accept-derived';
          detail = `${detail} Suggested by a derived rule, not yet accepted: ${m.detail}`;
        } else proWouldSettle = true;
      } else if (m.ok && pro) {
        state = 'not_affected'; justification = 'code_not_present'; level = 'module'; detail = m.detail; evidence = m.evidence;
      } else if (m.ok) {
        proWouldSettle = true;
      } else {
        moduleReason = m.reason;
        if (moduleMap && m.reason) detail += ` Module-level check: ${m.reason}.`;
      }
    } else {
      state = 'not_affected';
      justification = 'code_not_present';
      level = 'package';
      detail =
        `${key}@${parsed.version ?? '?'} appears in the lockfile SBOM but no component named ` +
        `${key} appears in the bundle SBOM generated from the production build. ` +
        `The package's code is not present in the shipped artifact.`;
    }
    results.push({ ...f, key, state, justification, detail, level, evidence, proWouldSettle, moduleReason, origin: 'auto' });
  }
  return results;
}

// ---------- CycloneDX VEX output ----------

/** Go's url.QueryEscape, which is what cyclonedx-go (and so Trivy) uses for a BOM-Link fragment. */
export function goQueryEscape(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()).replace(/%20/g, '+');
}

const bare = (purl) => String(purl).split('?')[0].split('#')[0];

/**
 * BOM-Links (urn:cdx:serial/version#bom-ref) to every lockfile-SBOM component with this PURL.
 * Trivy only applies CycloneDX VEX through BOM-Links into the SBOM it is scanning.
 */
export function bomLinks(lockfileSbom, purl) {
  const serial = String(lockfileSbom?.serialNumber ?? '').replace(/^urn:uuid:/, '');
  if (!/^[0-9a-f-]{36}$/.test(serial)) return [];
  const version = lockfileSbom.version ?? 1;
  const all = [];
  walkComponents(lockfileSbom.components, all);
  return all.filter((c) => c.purl && bare(c.purl) === bare(purl)).map((c) => `urn:cdx:${serial}/${version}#${goQueryEscape(c['bom-ref'] ?? bare(c.purl))}`);
}

/**
 * Where a vulnerability id comes from, named as Dependency-Track names its sources. Dependency-Track 4.x skips
 * VEX entries that have no source; its GitHub and OSV mirrors both file GHSA ids under GITHUB, and CVEs under NVD.
 */
export function vulnerabilitySource(id) {
  const s = String(id);
  if (/^GHSA-/i.test(s)) return { name: 'GITHUB', url: `https://github.com/advisories/${s}` };
  if (/^CVE-/i.test(s)) return { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${s}` };
  if (/^SNYK-/i.test(s)) return { name: 'SNYK', url: `https://security.snyk.io/vuln/${s}` };
  return null;
}

export const CYCLONEDX_VERSIONS = ['1.6', '1.7'];
const SETTLED_STATES = new Set(['not_affected', 'false_positive', 'resolved', 'resolved_with_pedigree']);

export function toCycloneDxVex({ results, bundleSbom, lockfileSbom, productPurl, inputs = [], licensee = null, scope = null, aliasEntries = true, specVersion = '1.6', now = new Date() }) {
  if (!CYCLONEDX_VERSIONS.includes(specVersion)) throw new Error(`CycloneDX ${specVersion} is not supported; use ${CYCLONEDX_VERSIONS.join(' or ')}`);
  const evidence = {
    bundleSbomSerial: bundleSbom?.serialNumber ?? null,
    lockfileSbomSerial: lockfileSbom?.serialNumber ?? null,
    bundleComponentCount: sbomPurls(bundleSbom).length,
    lockfileComponentCount: sbomPurls(lockfileSbom).length,
  };
  const props = Object.entries(evidence).map(([k, v]) => ({ name: `vexproof:${k}`, value: String(v) }));
  for (const i of inputs) props.push({ name: `vexproof:input:${i.role}:sha256`, value: i.sha256 });
  if (licensee) props.push({ name: 'vexproof:licensee', value: licensee });
  if (scope) props.push({ name: 'vexproof:scope', value: scope });

  const vulnerabilities = [];
  for (const r of results) {
    const p = [
      { name: 'vexproof:package', value: r.purl },
      { name: 'vexproof:origin', value: r.origin ?? 'auto' },
    ];
    if (r.level) p.push({ name: 'vexproof:level', value: r.level });
    if (r.reviewedBy) p.push({ name: 'vexproof:reviewed-by', value: r.reviewedBy });
    if (r.reviewedAt) p.push({ name: 'vexproof:reviewed-at', value: r.reviewedAt });
    if (r.evidence?.ruleSource) p.push({ name: 'vexproof:rule-source', value: r.evidence.ruleSource });
    if (r.evidence?.survivingFiles) p.push({ name: 'vexproof:surviving-files', value: r.evidence.survivingFiles.join(' ') });
    if (r.evidence?.copies?.length) p.push({ name: 'vexproof:copies-checked', value: r.evidence.copies.join(' ') });
    p.push(...fingerprintProperties(r.fingerprint));
    if (r.carriedFrom) p.push({ name: 'vexproof:carried-from', value: `${r.carriedFrom.purl} reviewed ${r.carriedFrom.reviewedAt}` });
    if (r.evidence?.ruleOrigin === 'derived') p.push({ name: 'vexproof:rule-origin', value: `derived: files changed between ${parsePurl(r.purl)?.version} and the fixed ${r.evidence.derivedFrom?.fixed}` });
    const links = bomLinks(lockfileSbom, r.purl);
    const entry = {
      id: r.id,
      ...(vulnerabilitySource(r.id) ? { source: vulnerabilitySource(r.id) } : {}),
      ...(r.aliases?.length ? { references: r.aliases.map((a) => ({ id: a, source: { name: 'alias' } })) } : {}),
      analysis: {
        state: r.state,
        ...(r.justification ? { justification: r.justification } : {}),
        ...(r.response ? { response: r.response } : {}),
        detail: r.detail,
        firstIssued: (r.firstIssued ?? now.toISOString()),
        lastUpdated: now.toISOString(),
      },
      affects: (links.length ? links : [r.purl]).map((ref) => ({ ref })),
      properties: p,
    };
    vulnerabilities.push(entry);
    // Scanners look statements up by their own id scheme (Trivy: CVE for npm; Dependency-Track: GHSA or CVE),
    // so each GHSA/CVE alias gets its own entry pointing back at the primary one.
    if (aliasEntries) {
      for (const a of r.aliases ?? []) {
        if (!/^(CVE|GHSA)-/.test(a) || a === r.id) continue;
        const { source: _primary, ...rest } = entry;
        vulnerabilities.push({ ...rest, id: a, ...(vulnerabilitySource(a) ? { source: vulnerabilitySource(a) } : {}), references: [{ id: r.id, source: { name: 'alias' } }], properties: [...p, { name: 'vexproof:alias-of', value: r.id }] });
      }
    }
  }
  // Settled statements first, open ones last. Two consumers keep only the last word on an id: Trivy keeps one
  // statement per id, and Dependency-Track applies a BOM-Link statement to every component with that finding.
  // With open statements last, a package that ships is never suppressed by a statement about one that doesn't.
  // Within each group, order by advisory (each primary entry followed by its alias entries) and package, so the
  // same input always writes the same file.
  const rank = (v) => (SETTLED_STATES.has(v.analysis.state) ? 0 : 1);
  const prop = (v, name) => v.properties.find((x) => x.name === name)?.value ?? '';
  const primary = (v) => prop(v, 'vexproof:alias-of') || v.id;
  vulnerabilities.sort((a, b) => rank(a) - rank(b) || cmp(primary(a), primary(b)) || cmp(prop(a, 'vexproof:package'), prop(b, 'vexproof:package')) || cmp(Boolean(prop(a, 'vexproof:alias-of')), Boolean(prop(b, 'vexproof:alias-of'))) || cmp(a.id, b.id));

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion,
    serialNumber: null,
    version: 1,
    metadata: {
      timestamp: now.toISOString(),
      tools: { components: [{ type: 'application', name: 'vexproof', version: VERSION }] },
      component: { type: 'application', 'bom-ref': productPurl, purl: productPurl, name: productPurl },
      properties: props,
    },
    vulnerabilities,
  };
  bom.serialNumber = `urn:uuid:${contentUuid(bom)}`;
  return bom;
}

export function summarize(results) {
  const s = { not_affected: 0, in_triage: 0, module: 0, package: 0, reviewed: 0, proWouldSettle: 0 };
  for (const r of results) {
    s[r.state] = (s[r.state] ?? 0) + 1;
    if (r.level) s[r.level]++;
    if (r.origin === 'reviewed') s.reviewed++;
    if (r.proWouldSettle) s.proWouldSettle++;
  }
  return s;
}
