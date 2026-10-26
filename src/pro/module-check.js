// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Module-level analysis: a package is in the bundle, but did the files holding the vulnerable code ship?
// Rules (hand-checked in ./rules/module-rules.json, or derived from an advisory's fix) name those files.

/** Hand-checked rules plus derived ones. A hand-checked rule for the same package and advisory always wins. */
export function mergeRules(base, ...extra) {
  const out = { ...base, packages: structuredClone(base?.packages ?? {}) };
  for (const r of extra) {
    for (const [name, pkg] of Object.entries(r?.packages ?? {})) {
      const into = (out.packages[name] ??= { advisories: {} });
      into.advisories ??= {};
      const handIds = new Set(Object.entries(into.advisories).filter(([, a]) => a.origin !== 'derived').flatMap(([k, a]) => [a.id ?? k, ...(a.aliases ?? [])]));
      for (const [k, a] of Object.entries(pkg.advisories ?? {})) {
        if ([a.id ?? k, ...(a.aliases ?? [])].some((x) => handIds.has(x))) continue;
        into.advisories[k] = { ...a, origin: a.origin ?? r.origin ?? 'derived' };
      }
    }
  }
  return out;
}

/**
 * Module-level check for a package that IS in the bundle. Returns { ok, detail, evidence } or { ok:false, reason }.
 * Every guard below errs toward "no claim".
 */
export function evaluateModuleRule({ key, parsed, id, aliases = [], bundleVersions, moduleMap, rules }) {
  if (!moduleMap) return { ok: false, reason: 'no module map supplied' };
  if (parsed?.type !== 'npm') return { ok: false, reason: 'not an npm package' };
  const pkgRules = rules?.packages?.[parsed.name];
  if (!pkgRules) return { ok: false, reason: `no module rules for ${parsed.name}` };
  const names = [id, ...aliases];
  const matches = (k) => {
    const r = pkgRules.advisories[k];
    return [r.id ?? k, ...(r.aliases ?? [])].some((x) => names.includes(x)) && (!r.versions || r.versions.includes(parsed.version));
  };
  const ruleKey = Object.keys(pkgRules.advisories ?? {}).find(matches);
  if (!ruleKey) return { ok: false, reason: `no module rule for ${id}` };
  const rule = pkgRules.advisories[ruleKey];
  const ruleId = rule.id ?? ruleKey;
  const derived = rule.origin === 'derived';

  if (moduleMap.whole?.has(parsed.name))
    return { ok: false, reason: `${parsed.name} publishes its own source maps, so the bundler's maps name its original sources, not the files that shipped; only package-level claims apply` };
  const entry = moduleMap.packages.get(parsed.name);
  if (!entry || entry.files.size === 0)
    return { ok: false, reason: `module map shows no surviving files for ${parsed.name}, which contradicts the bundle SBOM` };
  const sbomVersions = [...(bundleVersions ?? [])];
  if (!sbomVersions.includes(parsed.version))
    return { ok: false, reason: `bundle has ${parsed.name} at ${sbomVersions.join(', ') || 'unknown version'}, finding is for ${parsed.version}` };

  // Which shipped copies are the vulnerable version? With one copy, the bundle SBOM's single version decides.
  // With several, every copy's version must be known, or no copy can be ruled out.
  let roots;
  if (entry.roots.size === 1) {
    if (sbomVersions.length !== 1) return { ok: false, reason: `bundle has ${parsed.name} at ${sbomVersions.join(', ')} but the module map shows one copy` };
    const installed = entry.versionByRoot?.get([...entry.roots][0]);
    if (installed && installed !== parsed.version) return { ok: false, reason: `the shipped copy of ${parsed.name} is ${installed}, but the finding and bundle SBOM say ${parsed.version}` };
    roots = [...entry.roots];
  } else {
    const vbr = entry.versionByRoot;
    const unknown = [...entry.roots].filter((r) => !vbr?.get(r));
    if (unknown.length) return { ok: false, reason: `${parsed.name} ships from ${entry.roots.size} locations and the version of ${unknown.length} is unknown` };
    roots = [...entry.roots].filter((r) => vbr.get(r) === parsed.version);
    if (!roots.length) return { ok: false, reason: `no shipped copy of ${parsed.name} is version ${parsed.version}, which contradicts the bundle SBOM` };
  }
  const copyFiles = new Set(roots.flatMap((r) => [...(entry.byRoot?.get(r) ?? entry.files)]));
  const files = [...copyFiles].sort();
  const monolith = files.find((f) => (pkgRules.monoliths ?? []).includes(f) || (pkgRules.monolithDirs ?? []).some((d) => f.startsWith(d)));
  if (monolith) return { ok: false, reason: `the full build (${monolith}) is bundled` };
  const hit = rule.files.filter((f) => copyFiles.has(f));
  const list = (a) => (a.length > 5 ? `${a.slice(0, 5).join(', ')} and ${a.length - 5} more` : a.join(', '));
  if (hit.length) return { ok: false, derived, reason: derived ? `files the fix changed (${parsed.version} → ${rule.derivedFrom?.fixed}) are bundled: ${list(hit)}` : `vulnerable file(s) bundled: ${hit.join(', ')}` };
  const others = entry.roots.size - roots.length;

  const lead = `${key}@${parsed.version} is in the bundle, but only ${files.length} of its files survived the production build ` +
    (others ? `(counting only the ${parsed.version} copy; ${others} other cop${others > 1 ? 'ies are' : 'y is'} a different version) ` : '') +
    `(${moduleMap.format}). `;
  return {
    ok: true,
    derived,
    detail: derived
      ? lead + `The fix for ${ruleId} (${rule.affects}) changed ${rule.files.length} runtime file(s) between ${parsed.version} and ${rule.derivedFrom?.fixed}: ${list(rule.files)}. None of them are present in the shipped output.`
      : lead + `The code affected by ${ruleId} — ${rule.affects} — lives in ${rule.files.join(', ')}, none of which are present in the shipped output.`,
    evidence: { survivingFiles: files, checkedFiles: rule.files, ruleSource: rule.source, ruleOrigin: derived ? 'derived' : 'reviewed', derivedFrom: rule.derivedFrom, rulesVersion: rules.version, moduleMapFormat: moduleMap.format, copies: roots },
  };
}
