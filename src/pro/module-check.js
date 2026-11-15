// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Module-level analysis: a package is in the bundle, but did the files holding the vulnerable code ship?
// Rules (hand-checked in ./rules/module-rules.json, or derived from an advisory's fix) name those files.

import { ruleFilesShipped } from '../modules.js';

/**
 * A rules file as vexproof can use it, or a thrown Error naming what is wrong. Every advisory rule must list the
 * files that hold the code (a rule with none would claim every build); monoliths, monolithDirs and injected,
 * when given, are lists of paths.
 */
export function validateRules(rules, where = 'the rules file') {
  const fail = (what) => {
    throw new Error(`${where}: ${what}`);
  };
  if (!rules || typeof rules !== 'object' || typeof rules.packages !== 'object' || !rules.packages) fail('has no "packages" object');

  const paths = (value) => Array.isArray(value) && value.every((item) => typeof item === 'string' && item);
  for (const [name, pkg] of Object.entries(rules.packages)) {
    for (const field of ['monoliths', 'monolithDirs', 'injected']) {
      if (pkg?.[field] !== undefined && !paths(pkg[field])) fail(`${name}.${field} must be a list of paths`);
    }
    for (const [key, advisory] of Object.entries(pkg?.advisories ?? {})) {
      if (!paths(advisory?.files) || !advisory.files.length) {
        fail(`the rule ${name} ${key} must list the files that hold the vulnerable code ("files")`);
      }
    }
  }

  return rules;
}

/**
 * Hand-checked rules plus extra ones (derived, or a --rules file). A hand-checked rule for the same package and
 * advisory always wins. A package's guards are kept from every file: a file that adds rules for a package must
 * not lose the guard that keeps them from applying to a full build. Full-build guards (monoliths, monolithDirs)
 * add up; `injected` lists narrow to the names every file allows.
 */
export function mergeRules(base, ...extra) {
  const merged = { ...base, packages: structuredClone(base?.packages ?? {}) };

  for (const extraRules of extra) {
    for (const [name, pkg] of Object.entries(extraRules?.packages ?? {})) {
      const into = (merged.packages[name] ??= { advisories: {} });
      into.advisories ??= {};

      for (const field of ['monoliths', 'monolithDirs']) {
        if (Array.isArray(pkg[field]) && pkg[field].length) into[field] = [...new Set([...(into[field] ?? []), ...pkg[field]])];
      }

      if (Array.isArray(pkg.injected)) {
        const allowed = new Set(pkg.injected);
        into.injected = into.injected
          ? into.injected.filter((file) => allowed.has(file))
          : [...pkg.injected];
      }

      const handIds = new Set(Object.entries(into.advisories)
        .filter(([, advisory]) => advisory.origin !== 'derived')
        .flatMap(([advisoryKey, advisory]) => [advisory.id ?? advisoryKey, ...(advisory.aliases ?? [])]));
      for (const [advisoryKey, advisory] of Object.entries(pkg.advisories ?? {})) {
        if ([advisory.id ?? advisoryKey, ...(advisory.aliases ?? [])].some((name) => handIds.has(name))) continue;
        into.advisories[advisoryKey] = { ...advisory, origin: advisory.origin ?? extraRules.origin ?? 'derived' };
      }
    }
  }

  return merged;
}

/**
 * Module-level check for a package that IS in the bundle. Returns { ok, detail, evidence } or { ok:false, reason }.
 * Every guard below errs toward "no claim".
 */
export function evaluateModuleRule({ key, parsed, id, aliases = [], bundleVersions, moduleMap, rules }) {
  if (!moduleMap) {
    return { ok: false, reason: 'no module map supplied' };
  }
  if (parsed?.type !== 'npm') {
    return { ok: false, reason: 'not an npm package' };
  }

  const pkgRules = rules?.packages?.[parsed.name];
  if (!pkgRules) {
    return { ok: false, reason: `no module rules for ${parsed.name}` };
  }

  const names = [id, ...aliases];
  const matches = (advisoryKey) => {
    const candidate = pkgRules.advisories[advisoryKey];

    return [candidate.id ?? advisoryKey, ...(candidate.aliases ?? [])].some((name) => names.includes(name))
      && (!candidate.versions || candidate.versions.includes(parsed.version));
  };
  const ruleKey = Object.keys(pkgRules.advisories ?? {}).find(matches);
  if (!ruleKey) {
    return { ok: false, reason: `no module rule for ${id}` };
  }

  const rule = pkgRules.advisories[ruleKey];
  const ruleId = rule.id ?? ruleKey;
  const derived = rule.origin === 'derived';

  if (moduleMap.whole?.has(parsed.name)) {
    return {
      ok: false,
      reason: `${parsed.name} counts as shipped whole (it is loaded at runtime by name, ` +
        'or its own source maps name its original sources, not the files that shipped), ' +
        'so which of its files shipped is not known; only package-level claims apply',
    };
  }
  const entry = moduleMap.packages.get(parsed.name);
  if (!entry || entry.files.size === 0) {
    return { ok: false, reason: `module map shows no surviving files for ${parsed.name}, which contradicts the bundle SBOM` };
  }
  const sbomVersions = [...(bundleVersions ?? [])];
  if (!sbomVersions.includes(parsed.version)) {
    return {
      ok: false,
      reason: `bundle has ${parsed.name} at ${sbomVersions.join(', ') || 'unknown version'}, finding is for ${parsed.version}`,
    };
  }

  // Which shipped copies are the vulnerable version? With one copy, the bundle SBOM's single version decides.
  // With several, every copy's version must be known, or no copy can be ruled out.
  let roots;
  if (entry.roots.size === 1) {
    if (sbomVersions.length !== 1) {
      return { ok: false, reason: `bundle has ${parsed.name} at ${sbomVersions.join(', ')} but the module map shows one copy` };
    }

    const installed = entry.versionByRoot?.get([...entry.roots][0]);
    if (installed && installed !== parsed.version) {
      return {
        ok: false,
        reason: `the shipped copy of ${parsed.name} is ${installed}, but the finding and bundle SBOM say ${parsed.version}`,
      };
    }

    roots = [...entry.roots];
  } else {
    const versionByRoot = entry.versionByRoot;
    const unknown = [...entry.roots].filter((root) => !versionByRoot?.get(root));
    if (unknown.length) {
      return {
        ok: false,
        reason: `${parsed.name} ships from ${entry.roots.size} locations and the version of ${unknown.length} is unknown`,
      };
    }

    roots = [...entry.roots].filter((root) => versionByRoot.get(root) === parsed.version);
    if (!roots.length) {
      return { ok: false, reason: `no shipped copy of ${parsed.name} is version ${parsed.version}, which contradicts the bundle SBOM` };
    }
  }

  const copyFiles = new Set(roots.flatMap((root) => [...(entry.byRoot?.get(root) ?? entry.files)]));
  const files = [...copyFiles].sort();
  // File names are compared without regard to case: Windows and macOS load `Template.js` for 'template.js',
  // and a bundler records the spelling the import used. Matching too much can only keep a finding open.
  const lower = (file) => String(file).toLowerCase();
  const monolith = files.find((file) => (pkgRules.monoliths ?? []).some((monolithFile) => lower(monolithFile) === lower(file))
    || (pkgRules.monolithDirs ?? []).some((monolithDir) => lower(file).startsWith(lower(monolithDir))));
  if (monolith) {
    return { ok: false, reason: `the full build (${monolith}) is bundled` };
  }

  const list = (items) => (items.length > 5 ? `${items.slice(0, 5).join(', ')} and ${items.length - 5} more` : items.join(', '));

  // A build tool (Vite) writes helper code into the output, recorded under made-up names, and its rules hold only
  // for a bundle that has nothing else of it. Its bugs can also reach the output as code it generates, which no
  // file list shows, so a rule derived from the files a fix changed says nothing about it: only hand-checked ones
  // apply. The helpers' names are the bundler's own ids and are compared exactly: unlike a rule's files, a looser
  // match here would allow more, not less.
  const injected = pkgRules.injected ? new Set(pkgRules.injected) : null;
  if (injected) {
    if (derived) {
      return {
        ok: false,
        derived,
        reason: `${parsed.name} writes code into the build that no file list shows, so only hand-checked rules apply to it, and ${ruleId} has none`,
      };
    }

    const ownFiles = files.filter((file) => !injected.has(file));
    if (ownFiles.length) {
      return {
        ok: false,
        reason: `the bundle has more of ${parsed.name} than the helpers it writes into a build (${list(ownFiles)}), so its rules don't apply`,
      };
    }
  }

  const hit = ruleFilesShipped(rule.files, files);
  // a derived rule names the release it was derived from; a rule file without that is described without it
  const fixedIn = rule.derivedFrom?.fixed ? ` → ${rule.derivedFrom.fixed}` : '';
  if (hit.length) {
    return {
      ok: false,
      derived,
      reason: derived
        ? `files the fix changed (${parsed.version}${fixedIn}) are bundled: ${list(hit)}`
        : `vulnerable file(s) bundled: ${hit.join(', ')}`,
    };
  }
  const others = entry.roots.size - roots.length;

  const otherCopies = others
    ? `(counting only the ${parsed.version} copy; ${others} other cop${others > 1 ? 'ies are' : 'y is'} a different version) `
    : '';
  const lead = injected
    ? `${key}@${parsed.version} is in the bundle only as the helper code it writes into a build: ${list(files)} ` +
      otherCopies +
      `(${moduleMap.format}). `
    : `${key}@${parsed.version} is in the bundle, but only ${files.length} of its files survived the production build ` +
      otherCopies +
      `(${moduleMap.format}). `;
  // a rule entry ending in "/" is a folder: none of its files may ship
  const absent = rule.files.some((file) => file.endsWith('/'))
    ? '; nothing from there is in the shipped output.'
    : ', none of which are present in the shipped output.';

  return {
    ok: true,
    derived,
    detail: derived
      ? lead + `The fix for ${ruleId} (${rule.affects}) changed ${rule.files.length} runtime file(s)` +
        `${rule.derivedFrom?.fixed ? ` between ${parsed.version} and ${rule.derivedFrom.fixed}` : ''}: ${list(rule.files)}. ` +
        'None of them are present in the shipped output.'
      : lead + `The code affected by ${ruleId} — ${rule.affects} — lives in ${rule.files.join(', ')}${absent}`,
    evidence: {
      survivingFiles: files,
      checkedFiles: rule.files,
      ruleSource: rule.source,
      ruleOrigin: derived ? 'derived' : 'reviewed',
      derivedFrom: rule.derivedFrom,
      rulesVersion: rules.version,
      moduleMapFormat: moduleMap.format,
      copies: roots,
    },
  };
}
