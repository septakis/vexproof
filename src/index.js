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
// justification `code_not_present` when the vulnerable package does not appear
// in what shipped at all: the bundle SBOM, which the CLI may build from a module
// map or a deployment. vexproof Pro can also settle one at module level, when
// the package shipped but the files a rule names did not. Everything else is
// `in_triage`.

import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fingerprintProperties } from './evidence.js';
import { npmName } from './names.js';

export { npmName, NpmNameSet } from './names.js';

// ---------- determinism ----------

const UUID_NAMESPACE = Buffer.from('f5466259a7f9427fa41e673c18411e32', 'hex'); // vexproof's own UUIDv5 namespace

/** UUIDv5 of a document's content, so the same output always carries the same serial number. */
export function contentUuid(doc) {
  const hash = createHash('sha1').update(UUID_NAMESPACE).update(JSON.stringify(doc)).digest();
  hash[6] = (hash[6] & 0x0f) | 0x50;
  hash[8] = (hash[8] & 0x3f) | 0x80;

  const hex = hash.subarray(0, 16).toString('hex');

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * The time to stamp output with: SOURCE_DATE_EPOCH (seconds since 1970, the reproducible-builds convention)
 * when it is set, otherwise now. Throws on a value that is not a whole number of seconds.
 */
export function outputTime(env = process.env) {
  const epoch = env.SOURCE_DATE_EPOCH;
  if (epoch === undefined || epoch === '') {
    return new Date();
  }
  if (!/^\d+$/.test(epoch)) {
    throw new Error(`SOURCE_DATE_EPOCH must be whole seconds since 1970, got "${epoch}"`);
  }

  const date = new Date(Number(epoch) * 1000);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`SOURCE_DATE_EPOCH ${epoch} is later than any date a VEX can carry`);
  }

  return date;
}

const compare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

const compareKeys = (leftKeys, rightKeys) => {
  for (let position = 0; position < leftKeys.length; position++) {
    const order = compare(leftKeys[position], rightKeys[position]);
    if (order !== 0) {
      return order;
    }
  }

  return 0;
};

// ---------- purl helpers ----------

/** "pkg:npm/%40scope/name@1.2.3?x=y" -> { type, name, version } */
export function parsePurl(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) {
    return null;
  }

  const body = purl.slice(4).split('?')[0].split('#')[0];
  const slash = body.indexOf('/');
  if (slash < 0) {
    return null;
  }

  const type = body.slice(0, slash);
  let rest;
  try {
    rest = decodeURIComponent(body.slice(slash + 1));
  } catch {
    return null; // a bad %-escape: not a purl
  }

  let version;
  const atSign = rest.lastIndexOf('@');
  // scoped npm names start with "@", so only treat "@" past index 0 as the version separator
  if (atSign > 0) {
    version = rest.slice(atSign + 1);
    rest = rest.slice(0, atSign);
  }

  return { type, name: rest, version };
}

/** "npm/<name>" (lowercased, see npmName in names.js) or "<type>/<name>" for a purl, or null when it can't be read. */
export function packageKey(purl) {
  const parsed = parsePurl(purl);

  return parsed ? keyOf(parsed.type, parsed.name) : null;
}

const keyOf = (type, name) => `${type}/${type === 'npm' ? npmName(name) : name}`;

// ---------- SBOM reading ----------

function walkComponents(list, out) {
  for (const component of list ?? []) {
    out.push(component);
    if (Array.isArray(component.components)) walkComponents(component.components, out);
  }
}

/** All purls in a CycloneDX SBOM (nested components included). */
export function sbomPurls(sbom) {
  const all = [];
  walkComponents(sbom?.components, all);

  return all.map((component) => component.purl).filter(Boolean);
}

/**
 * Map of "npm/lodash" (see packageKey) → Set of versions, for every component of a CycloneDX SBOM.
 *
 * With `withoutPurl`, a component that has no purl counts as an npm package by its group and name. CycloneDX
 * makes the purl optional, and a bundle SBOM that lists a shipped package by name alone must not make that
 * package look absent. Only use it where an extra package can only keep findings open: the bundle side.
 */
export function indexSbom(sbom, { withoutPurl = false } = {}) {
  const byName = new Map();
  const put = (key, version) => {
    if (!byName.has(key)) byName.set(key, new Set());
    if (version) byName.get(key).add(version);
  };

  const all = [];
  walkComponents(sbom?.components, all);

  for (const component of all) {
    if (component.purl) {
      const parsed = parsePurl(component.purl);
      if (parsed) put(keyOf(parsed.type, parsed.name), parsed.version);
    } else if (withoutPurl && component.name) {
      const name = component.group ? `${component.group}/${component.name}` : component.name;
      put(keyOf('npm', name), component.version);
    }
  }

  return byName;
}

// ---------- findings normalisation ----------

/** The npm purl for a package name and an optional version ("@scope/name" is written "%40scope/name"). */
export function npmPurl(name, version) {
  const encodedName = name.startsWith('@') ? `%40${name.slice(1)}` : name;

  return `pkg:npm/${encodedName}${version ? '@' + version : ''}`;
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
    for (const finding of input) {
      if (finding.id) {
        raw.push({ purl: finding.purl, id: finding.id, aliases: finding.aliases ?? [] });
      } else {
        for (const id of finding.ids ?? []) raw.push({ purl: finding.purl, id, aliases: [] });
      }
    }
  } else {
    for (const result of input?.results ?? []) {
      for (const packageEntry of result.packages ?? []) {
        const { name, version, ecosystem } = packageEntry.package ?? {};
        if (!name) {
          continue;
        }

        const purlType = String(ecosystem ?? '').toLowerCase();
        const purl = purlType === 'npm' ? npmPurl(name, version) : `pkg:${purlType}/${name}${version ? '@' + version : ''}`;
        for (const vulnerability of packageEntry.vulnerabilities ?? []) {
          raw.push({ purl, id: vulnerability.id, aliases: vulnerability.aliases ?? [] });
        }
      }
    }
  }

  return mergeFindings(raw);
}

/** Merges findings on the same purl whose ids or aliases overlap, keeping the first one's id. */
export function mergeFindings(list) {
  const merged = [];
  for (const finding of list) {
    const names = new Set([finding.id, ...(finding.aliases ?? [])]);
    const hit = merged.find((existing) => existing.purl === finding.purl
      && [existing.id, ...existing.aliases].some((name) => names.has(name)));

    if (hit) {
      for (const name of names) {
        if (name !== hit.id && !hit.aliases.includes(name)) hit.aliases.push(name);
      }
    } else {
      const aliases = [...new Set((finding.aliases ?? []).filter((alias) => alias !== finding.id))];
      merged.push({ purl: finding.purl, id: finding.id, aliases });
    }
  }

  return merged;
}

/** Attach the aliases a module rule knows (e.g. GHSA ↔ CVE) so every downstream format can match. */
export function applyRuleAliases(findings, rules) {
  for (const finding of findings) {
    const parsed = parsePurl(finding.purl);
    const advisories = rules?.packages?.[parsed?.name]?.advisories ?? {};
    const findingNames = [finding.id, ...finding.aliases];

    for (const [key, rule] of Object.entries(advisories)) {
      const ruleNames = [key, ...(rule.aliases ?? [])];
      if (ruleNames.some((name) => findingNames.includes(name))) {
        for (const alias of ruleNames) {
          if (alias !== finding.id && !finding.aliases.includes(alias)) finding.aliases.push(alias);
        }
      }
    }
  }

  return findings;
}

// ---------- triage ----------

/** The package version, read from package.json so a release cannot ship with a stale constant. */
export const VERSION = createRequire(import.meta.url)('../package.json').version;

// What a package's absence was read from, as a not_affected detail names it: the bundle SBOM (--bundle), the
// production build's module map (--modules), or the deployment (--deploy).
const ABSENCE_EVIDENCE = {
  'bundle-sbom': (name) => `the bundle SBOM of the production build lists no component named ${name}`,
  'module-map': (name) => `the production build's module map holds no file of ${name}`,
  deployment: (name) => `the deployment holds no file of ${name}, and its source maps name none`,
};

/** The detail of a package-level not_affected statement, naming each kind of evidence in `shippedFrom`. */
function absenceDetail(name, version, shippedFrom) {
  const known = shippedFrom.filter((kind) => ABSENCE_EVIDENCE[kind]);
  const reasons = (known.length ? known : ['bundle-sbom']).map((kind) => ABSENCE_EVIDENCE[kind](name));

  return `${name}@${version ?? '?'} is in the lockfile SBOM, but ${reasons.join('; ')}. ` +
    'The package\'s code is not present in the shipped artifact.';
}

/**
 * Packages that write into a build's output, and the advisories that are about what they write (a bundler's
 * runtime code, a compiler's output, a generated config). See the note in the file.
 */
export const GENERATED_CODE = createRequire(import.meta.url)('./generated-code.json');

/** The listed advisory a finding on this package is, as { id, affects }, or null. */
function generatedCodeAdvisory(generatedCode, packageName, finding) {
  const findingNames = [finding.id, ...(finding.aliases ?? [])];

  for (const [advisoryId, advisory] of Object.entries(generatedCode?.packages?.[packageName]?.advisories ?? {})) {
    if ([advisoryId, ...(advisory.aliases ?? [])].some((name) => findingNames.includes(name))) {
      return { id: advisoryId, affects: advisory.affects };
    }
  }

  return null;
}

/**
 * `moduleCheck` decides whether a package that IS in the bundle still doesn't ship the vulnerable code. It is not
 * part of this file: vexproof Pro supplies one (src/pro/module-check.js, under its own license). Without it,
 * every finding on a bundled package stays in_triage. `pro` says whether its answers may settle findings;
 * when false they are only counted (proWouldSettle). `shippedFrom` names what the bundle SBOM was read from
 * ('bundle-sbom', 'module-map', 'deployment'), for the wording of a not_affected detail.
 *
 * `generatedCode` lists the packages that write into a build's output. An advisory listed there is about what the
 * package wrote, so neither its absence from the bundle nor a module rule settles it: it stays in_triage for a
 * person to review. For any other advisory on such a package, a rule derived from the files a fix changed does
 * not apply either: the fix may be to what the package writes, which no file list shows.
 */
export function triage({
  lockfileSbom,
  bundleSbom,
  findings,
  moduleMap = null,
  rules = null,
  moduleCheck = null,
  pro = false,
  acceptDerived = false,
  shippedFrom = ['bundle-sbom'],
  generatedCode = GENERATED_CODE,
}) {
  const lock = indexSbom(lockfileSbom);
  const bundle = indexSbom(bundleSbom, { withoutPurl: true });
  const results = [];

  // A bundle SBOM that names none of the lockfile's npm packages almost always means a broken build or the
  // wrong file, not "we ship no third-party code" (an empty file, or one that lists only the app itself).
  // Refuse to make any not_affected claim from it.
  const bundleUsable = [...bundle.keys()].some((bundleKey) => bundleKey.startsWith('npm/') && lock.has(bundleKey));

  // A rule's aliases can show two findings to be one advisory (a GHSA and its CVE, reported apart): merged again
  // after they are added, so that one advisory on one package is one statement.
  for (const finding of mergeFindings(applyRuleAliases(normalizeFindings(findings), rules))) {
    const key = packageKey(finding.purl);
    const parsed = parsePurl(finding.purl);
    let state = 'in_triage';
    let justification;
    let detail;
    let level = null;
    let evidence = null;
    let proWouldSettle = false;
    let moduleReason = null;

    const writesIntoBuilds = parsed?.type === 'npm' && Boolean(generatedCode?.packages?.[parsed.name]);
    const generated = writesIntoBuilds ? generatedCodeAdvisory(generatedCode, parsed.name, finding) : null;

    if (!key) {
      detail = `Could not parse purl "${finding.purl}".`;
    } else if (!bundleUsable) {
      detail = 'The bundle SBOM names none of the npm packages in the lockfile SBOM; refusing to infer absence from it.';
    } else if (parsed?.type !== 'npm') {
      // a JavaScript build's records say what npm packages are in it, and nothing about a Python or Go package
      detail = `${key} is not an npm package; a JavaScript build says nothing about it, so no claim is made.`;
    } else if (!lock.has(key)) {
      // finding refers to a package we don't even claim to depend on; don't guess
      detail = `${key} is not listed in the lockfile SBOM; no claim made.`;
    } else if (generated) {
      // what the package wrote is in the build whether or not the package is, so its files prove nothing
      moduleReason = `${generated.id} is about what ${parsed.name} writes into a build, which its own files don't show`;
      detail = `${generated.id} is about what ${parsed.name} writes into a build's output (${generated.affects}), ` +
        `so whether ${parsed.name}'s own files shipped says nothing about it; requires manual review.`;
    } else if (bundle.has(key)) {
      const versions = [...bundle.get(key)].join(', ') || 'unknown version';
      detail = `${key} (${versions}) is present in the shipped bundle; requires manual review.`;

      let moduleVerdict = moduleCheck
        ? moduleCheck({ key, parsed, id: finding.id, aliases: finding.aliases, bundleVersions: bundle.get(key), moduleMap, rules })
        : { ok: false, reason: null };

      if (moduleVerdict.ok && moduleVerdict.derived && writesIntoBuilds) {
        moduleVerdict = {
          ok: false,
          reason: `${parsed.name} writes code into the build that no file list shows, so only hand-checked rules apply to it, ` +
            `and ${finding.id} has none`,
        };
      }

      if (moduleVerdict.ok && moduleVerdict.derived && !acceptDerived) {
        // a derived rule only suggests: someone accepts it, per run (--accept-derived) or per finding (review)
        if (pro) {
          moduleReason = 'a derived rule suggests not affected; review it, or pass --accept-derived';
          detail = `${detail} Suggested by a derived rule, not yet accepted: ${moduleVerdict.detail}`;
        } else {
          proWouldSettle = true;
        }
      } else if (moduleVerdict.ok && pro) {
        state = 'not_affected';
        justification = 'code_not_present';
        level = 'module';
        detail = moduleVerdict.detail;
        evidence = moduleVerdict.evidence;
      } else if (moduleVerdict.ok) {
        proWouldSettle = true;
      } else {
        moduleReason = moduleVerdict.reason;
        if (moduleMap && moduleVerdict.reason) detail += ` Module-level check: ${moduleVerdict.reason}.`;
      }
    } else {
      state = 'not_affected';
      justification = 'code_not_present';
      level = 'package';
      detail = absenceDetail(parsed.name, parsed.version, shippedFrom);
    }

    results.push({
      ...finding, key, state, justification, detail, level, evidence, proWouldSettle, moduleReason,
      generatedCode: generated?.id ?? null,
      origin: 'auto',
    });
  }

  return results;
}

// ---------- CycloneDX VEX output ----------

/** Go's url.QueryEscape, which is what cyclonedx-go (and so Trivy) uses for a BOM-Link fragment. */
export function goQueryEscape(text) {
  return encodeURIComponent(text)
    .replace(/[!'()*]/g, (character) => '%' + character.charCodeAt(0).toString(16).toUpperCase())
    .replace(/%20/g, '+');
}

const bare = (purl) => String(purl).split('?')[0].split('#')[0];

/**
 * BOM-Links (urn:cdx:serial/version#bom-ref) to every lockfile-SBOM component with this PURL.
 * Trivy only applies CycloneDX VEX through BOM-Links into the SBOM it is scanning.
 */
export function bomLinks(lockfileSbom, purl) {
  const serial = String(lockfileSbom?.serialNumber ?? '').replace(/^urn:uuid:/, '');
  if (!/^[0-9a-f-]{36}$/.test(serial)) {
    return [];
  }

  const version = lockfileSbom.version ?? 1;
  const all = [];
  walkComponents(lockfileSbom.components, all);

  return all
    .filter((component) => component.purl && bare(component.purl) === bare(purl))
    .map((component) => `urn:cdx:${serial}/${version}#${goQueryEscape(component['bom-ref'] ?? bare(component.purl))}`);
}

/**
 * Where a vulnerability id comes from, named as Dependency-Track names its sources. Dependency-Track 4.x skips
 * VEX entries that have no source; its GitHub and OSV mirrors both file GHSA ids under GITHUB, and CVEs under NVD.
 */
export function vulnerabilitySource(id) {
  const advisoryId = String(id);
  if (/^GHSA-/i.test(advisoryId)) {
    return { name: 'GITHUB', url: `https://github.com/advisories/${advisoryId}` };
  }
  if (/^CVE-/i.test(advisoryId)) {
    return { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${advisoryId}` };
  }
  if (/^SNYK-/i.test(advisoryId)) {
    return { name: 'SNYK', url: `https://security.snyk.io/vuln/${advisoryId}` };
  }

  return null;
}

export const CYCLONEDX_VERSIONS = ['1.6', '1.7'];
const SETTLED_STATES = new Set(['not_affected', 'false_positive', 'resolved', 'resolved_with_pedigree']);

/** The CycloneDX VEX document for a set of triage results. Throws on an unsupported `specVersion`. */
export function toCycloneDxVex({
  results,
  bundleSbom,
  lockfileSbom,
  productPurl,
  inputs = [],
  licensee = null,
  scope = null,
  aliasEntries = true,
  specVersion = '1.6',
  now = new Date(),
}) {
  if (!CYCLONEDX_VERSIONS.includes(specVersion)) {
    throw new Error(`CycloneDX ${specVersion} is not supported; use ${CYCLONEDX_VERSIONS.join(' or ')}`);
  }

  // The component counts are of components with a purl: the ones a finding can be matched against. A serial
  // number the SBOM doesn't have (a bundle SBOM vexproof made from a module map or a deployment) is left out.
  const evidence = {
    bundleSbomSerial: bundleSbom?.serialNumber ?? null,
    lockfileSbomSerial: lockfileSbom?.serialNumber ?? null,
    bundleComponentCount: sbomPurls(bundleSbom).length,
    lockfileComponentCount: sbomPurls(lockfileSbom).length,
  };
  const metadataProperties = Object.entries(evidence)
    .filter(([, value]) => value !== null)
    .map(([name, value]) => ({ name: `vexproof:${name}`, value: String(value) }));
  for (const input of inputs) metadataProperties.push({ name: `vexproof:input:${input.role}:sha256`, value: input.sha256 });
  if (licensee) metadataProperties.push({ name: 'vexproof:licensee', value: licensee });
  if (scope) metadataProperties.push({ name: 'vexproof:scope', value: scope });

  const vulnerabilities = [];
  for (const result of results) {
    const properties = [
      { name: 'vexproof:package', value: result.purl },
      { name: 'vexproof:origin', value: result.origin ?? 'auto' },
    ];
    if (result.level) properties.push({ name: 'vexproof:level', value: result.level });
    if (result.reviewedBy) properties.push({ name: 'vexproof:reviewed-by', value: result.reviewedBy });
    if (result.reviewedAt) properties.push({ name: 'vexproof:reviewed-at', value: result.reviewedAt });
    if (result.evidence?.ruleSource) properties.push({ name: 'vexproof:rule-source', value: result.evidence.ruleSource });
    if (result.evidence?.survivingFiles) {
      properties.push({ name: 'vexproof:surviving-files', value: result.evidence.survivingFiles.join(' ') });
    }
    if (result.evidence?.copies?.length) {
      properties.push({ name: 'vexproof:copies-checked', value: result.evidence.copies.join(' ') });
    }
    properties.push(...fingerprintProperties(result.fingerprint));
    if (result.carriedFrom) {
      properties.push({ name: 'vexproof:carried-from', value: `${result.carriedFrom.purl} reviewed ${result.carriedFrom.reviewedAt}` });
    }
    if (result.evidence?.ruleOrigin === 'derived') {
      const packageVersion = parsePurl(result.purl)?.version;
      const fixedVersion = result.evidence.derivedFrom?.fixed;
      const ruleOrigin = `derived: files changed between ${packageVersion} and the fixed ${fixedVersion}`;
      properties.push({ name: 'vexproof:rule-origin', value: ruleOrigin });
    }

    const links = bomLinks(lockfileSbom, result.purl);
    const entry = {
      id: result.id,
      ...(vulnerabilitySource(result.id) ? { source: vulnerabilitySource(result.id) } : {}),
      ...(result.aliases?.length ? { references: result.aliases.map((alias) => ({ id: alias, source: { name: 'alias' } })) } : {}),
      analysis: {
        state: result.state,
        ...(result.justification ? { justification: result.justification } : {}),
        ...(result.response ? { response: result.response } : {}),
        detail: result.detail,
        firstIssued: (result.firstIssued ?? now.toISOString()),
        lastUpdated: now.toISOString(),
      },
      affects: (links.length ? links : [result.purl]).map((ref) => ({ ref })),
      properties,
    };
    vulnerabilities.push(entry);

    // Scanners look statements up by their own id scheme (Trivy: CVE for npm; Dependency-Track: GHSA or CVE),
    // so each GHSA/CVE alias gets its own entry pointing back at the primary one.
    if (aliasEntries) {
      for (const alias of result.aliases ?? []) {
        if (!/^(CVE|GHSA)-/.test(alias) || alias === result.id) {
          continue;
        }

        // a copy, not shared objects: changing one entry in memory must never change the other
        const { source: _primary, ...entryWithoutSource } = structuredClone(entry);
        vulnerabilities.push({
          ...entryWithoutSource,
          id: alias,
          ...(vulnerabilitySource(alias) ? { source: vulnerabilitySource(alias) } : {}),
          references: [{ id: result.id, source: { name: 'alias' } }],
          properties: [...entryWithoutSource.properties, { name: 'vexproof:alias-of', value: result.id }],
        });
      }
    }
  }

  // Settled statements first, open ones last. Two consumers keep only the last word on an id: Trivy keeps one
  // statement per id, and Dependency-Track applies a BOM-Link statement to every component with that finding.
  // With open statements last, a package that ships is never suppressed by a statement about one that doesn't.
  // Within each group, order by advisory (each primary entry followed by its alias entries) and package, so the
  // same input always writes the same file.
  const rank = (vulnerability) => (SETTLED_STATES.has(vulnerability.analysis.state) ? 0 : 1);
  const propertyValue = (vulnerability, name) => vulnerability.properties.find((property) => property.name === name)?.value ?? '';
  const primaryId = (vulnerability) => propertyValue(vulnerability, 'vexproof:alias-of') || vulnerability.id;
  const sortKey = (vulnerability) => [
    rank(vulnerability),
    primaryId(vulnerability),
    propertyValue(vulnerability, 'vexproof:package'),
    Boolean(propertyValue(vulnerability, 'vexproof:alias-of')),
    vulnerability.id,
  ];
  vulnerabilities.sort((left, right) => compareKeys(sortKey(left), sortKey(right)));

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion,
    serialNumber: null,
    version: 1,
    metadata: {
      timestamp: now.toISOString(),
      tools: { components: [{ type: 'application', name: 'vexproof', version: VERSION }] },
      component: { type: 'application', 'bom-ref': productPurl, purl: productPurl, name: productPurl },
      properties: metadataProperties,
    },
    vulnerabilities,
  };
  bom.serialNumber = `urn:uuid:${contentUuid(bom)}`;

  return bom;
}

/** Counts of results by state and level, and of reviewed results and those Pro would settle. */
export function summarize(results) {
  const summary = { not_affected: 0, in_triage: 0, module: 0, package: 0, reviewed: 0, proWouldSettle: 0 };
  for (const result of results) {
    summary[result.state] = (summary[result.state] ?? 0) + 1;
    if (result.level) summary[result.level]++;
    if (result.origin === 'reviewed') summary.reviewed++;
    if (result.proWouldSettle) summary.proWouldSettle++;
  }

  return summary;
}
