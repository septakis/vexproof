// SPDX-License-Identifier: MIT
// Evidence fingerprints: what a reviewed decision about an open finding rests on.
//
//   files      the shipped files holding the vulnerable code (the rule's files that ship from the copy at the
//              finding's version; without a rule, every shipped file of that copy), each with a content hash
//   importers  the code outside the package that pulls those files in: your own modules, or another
//              package's (named with its version). Found by walking the bundler's import graph backwards from
//              the vulnerable files, through the package's own internal files, until it leaves the package.
//
// A review carries into a later release only if both are unchanged, whatever the version number did. When
// either changes, the finding goes back to the reviewer with the difference.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { splitNodeModulesPath, splitShipped, ruleFilesShipped } from './modules.js';
import { parsePurl } from './index.js';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const shortHash = (hash) => hash.slice(0, 16);
const PER_FILE_LIMIT = 20; // above this, one hash for all files keeps the VEX readable

// The properties hold space-separated lists, and each file's hash after an "=". A path holding a space, an "=" or
// a "%" has those %-escaped, so it reads back whole; every other path is written as it is, as before.
const ESCAPED = { '%': '%25', ' ': '%20', '=': '%3D' };
const UNESCAPED = { '%25': '%', '%20': ' ', '%3D': '=' };
const escapePath = (path) => String(path).replace(/[% =]/g, (character) => ESCAPED[character]);
const unescapePath = (text) => text.replace(/%25|%20|%3D/gi, (code) => UNESCAPED[code.toUpperCase()]);
const pathList = (value) => value.split(' ').filter(Boolean).map(unescapePath);

function ruleFor(rules, name, id, aliases, version) {
  const advisories = rules?.packages?.[name]?.advisories ?? {};
  const names = [id, ...(aliases ?? [])];
  const matchingKey = Object.keys(advisories).find((key) => {
    const rule = advisories[key];

    return [rule.id ?? key, ...(rule.aliases ?? [])].some((ruleName) => names.includes(ruleName))
      && (!rule.versions || rule.versions.includes(version));
  });

  return matchingKey ? advisories[matchingKey] : null;
}

/**
 * Adds result.fingerprint = { vulnerableFiles, files: {file: hash} | null, filesDigest, importers: [..] | null }
 * to each open result on a bundled npm package. A part that can't be established is null, never empty: a null
 * part can't be compared, and a review then carries only for the exact same package version (see
 * fingerprintChanges and applyBaseline).
 */
export function attachFingerprints(results, {
  moduleMap,
  rules,
  cwd = process.cwd(),
  readFile = (filePath) => readFileSync(filePath),
}) {
  if (!moduleMap) {
    return results;
  }

  const keyIndex = new Map(); // "root\0file" -> module-map key
  for (const shippedKey of moduleMap.graph?.shipped ?? []) {
    const split = splitNodeModulesPath(shippedKey);
    if (split) keyIndex.set(`${split.root}\0${split.file}`, shippedKey);
  }

  for (const result of results) {
    if (result.state !== 'in_triage') {
      continue;
    }

    const parsed = parsePurl(result.purl);
    const entry = parsed?.type === 'npm' ? moduleMap.packages.get(parsed.name) : null;
    if (!entry) {
      continue;
    }

    const versionByRoot = entry.versionByRoot;
    let roots = [...entry.roots].filter((root) => versionByRoot?.get(root) === parsed.version);
    if (!roots.length && entry.roots.size === 1) roots = [...entry.roots];
    if (!roots.length) {
      continue;
    }

    const rule = ruleFor(rules, parsed.name, result.id, result.aliases, parsed.version);
    const pairs = roots.flatMap((root) => [...(entry.byRoot?.get(root) ?? [])].map((file) => ({ root, file })));
    // the rule's files matched as the module check matches them (without case, a folder entry covering its files)
    const vulnerable = rule
      ? pairs.filter((pair) => ruleFilesShipped(rule.files ?? [], [pair.file]).length > 0)
      : pairs;
    if (!vulnerable.length) {
      continue;
    }

    // Content hashes, read from the installed package. The same version can be installed in more than one place:
    // a file's hash then covers every copy, so a change to any one of them shows. Copies that are all the same
    // hash as one copy does, so a second install of identical code is no change.
    let files = {};
    try {
      const hashesByFile = new Map();
      for (const { root, file } of vulnerable) {
        const hash = shortHash(sha256(readFile(join(cwd, root, file))));
        hashesByFile.set(file, [...(hashesByFile.get(file) ?? []), hash]);
      }

      for (const [file, hashes] of hashesByFile) {
        const distinct = [...new Set(hashes)].sort();
        files[file] = distinct.length === 1 ? distinct[0] : shortHash(sha256(distinct.join('\n')));
      }
    } catch {
      files = null;
    }

    const filesDigest = files
      ? shortHash(sha256(Object.keys(files).sort().map((file) => `${file}\0${files[file]}`).join('\n')))
      : null;

    // Importers from outside the package. Known only when the import graph names every vulnerable file: one it
    // doesn't (a file added from the output check, a workspace package) leaves who imports it unknown, not none.
    let importers = null;
    const graph = moduleMap.graph;
    if (graph && vulnerable.every((pair) => keyIndex.has(`${pair.root}\0${pair.file}`))) {
      const outside = new Set();
      const seen = new Set();
      const inPackage = (moduleKey) => {
        const split = splitShipped(moduleMap, moduleKey);

        return split && split.name === parsed.name && roots.includes(split.root);
      };
      const stack = vulnerable.map((pair) => keyIndex.get(`${pair.root}\0${pair.file}`)).filter(Boolean);

      while (stack.length) {
        const moduleKey = stack.pop();
        if (seen.has(moduleKey)) {
          continue;
        }
        seen.add(moduleKey);

        for (const importer of graph.importers.get(moduleKey) ?? []) {
          if (inPackage(importer)) {
            stack.push(importer);
            continue;
          }
          if (!graph.shipped.has(importer)) {
            continue; // code that didn't ship can't call anything
          }

          const split = splitShipped(moduleMap, importer);
          if (split) {
            const importerVersion = moduleMap.packages.get(split.name)?.versionByRoot?.get(split.root) ?? '?';
            outside.add(`${split.name}@${importerVersion}/${split.file}`);
          } else {
            outside.add(importer);
          }
        }
      }

      importers = [...outside].sort();
    }

    const distinctFiles = [...new Set(vulnerable.map((pair) => pair.file))].sort();
    result.fingerprint = {
      vulnerableFiles: rule ? distinctFiles : null,
      files: files && Object.keys(files).length <= PER_FILE_LIMIT ? files : null,
      fileCount: distinctFiles.length,
      filesDigest,
      importers,
    };
  }

  return results;
}

/**
 * How a reviewed fingerprint and the current one differ: { changed, incomparable }, each a list of reasons.
 * `changed` is evidence that is different now; `incomparable` names the parts that one side doesn't have
 * (a deployment has no import graph), which neither confirm nor contradict the review.
 */
export function fingerprintChanges(before, now) {
  const changes = [];
  const incomparable = [];

  if (!before?.filesDigest || !now?.filesDigest) {
    incomparable.push('the vulnerable files could not be compared');
  } else if (before.filesDigest !== now.filesDigest) {
    if (before.files && now.files) {
      const names = [...new Set([...Object.keys(before.files), ...Object.keys(now.files)])].sort();
      const changed = names.filter((file) => before.files[file] !== now.files[file]);
      changes.push(`vulnerable files changed: ${changed.join(', ')}`);
    } else {
      changes.push(`the package's shipped files changed (${now.fileCount} files)`);
    }
  }

  if (!before?.importers || !now?.importers) {
    incomparable.push('the code importing them could not be compared');
  } else {
    const added = now.importers.filter((importer) => !before.importers.includes(importer));
    const removed = before.importers.filter((importer) => !now.importers.includes(importer));
    if (added.length) changes.push(`new importer${added.length > 1 ? 's' : ''}: ${added.join(', ')}`);
    if (removed.length && !added.length) changes.push(`no longer imported by: ${removed.join(', ')}`);
  }

  return { changed: changes, incomparable };
}

// ---------- as CycloneDX properties ----------

/** A fingerprint as `vexproof:` CycloneDX properties (read back by fingerprintFromProperties). */
export function fingerprintProperties(fingerprint) {
  if (!fingerprint) {
    return [];
  }

  const properties = [];

  if (fingerprint.vulnerableFiles) {
    properties.push({ name: 'vexproof:vulnerable-files', value: fingerprint.vulnerableFiles.map(escapePath).join(' ') });
  }

  if (fingerprint.filesDigest) {
    const value = fingerprint.files
      ? Object.entries(fingerprint.files).map(([file, hash]) => `${escapePath(file)}=${hash}`).join(' ')
      : `${fingerprint.fileCount} files=${fingerprint.filesDigest}`;
    properties.push({ name: 'vexproof:evidence-files', value });
    properties.push({ name: 'vexproof:evidence-files-digest', value: fingerprint.filesDigest });
  }

  if (fingerprint.importers) {
    properties.push({ name: 'vexproof:importers', value: fingerprint.importers.map(escapePath).join(' ') || '(none)' });
  }

  return properties;
}

/** The files a `vexproof:vulnerable-files` property value lists, read as fingerprintProperties wrote them. */
export function vulnerableFilesFrom(value) {
  return value === undefined || value === null ? null : pathList(value);
}

/** The fingerprint that fingerprintProperties wrote into these properties, or null when they hold none. */
export function fingerprintFromProperties(properties) {
  const propertyValue = (name) => properties?.find((property) => property.name === name)?.value;
  const digest = propertyValue('vexproof:evidence-files-digest');
  const evidenceFiles = propertyValue('vexproof:evidence-files');
  const importerList = propertyValue('vexproof:importers');
  const vulnerableFileList = propertyValue('vexproof:vulnerable-files');
  if (!digest && importerList === undefined) {
    return null;
  }

  let files = null;
  let fileCount = null;
  if (evidenceFiles && !/^\d+ files=/.test(evidenceFiles)) {
    files = Object.fromEntries(evidenceFiles.split(' ').filter(Boolean).map((pair) => {
      const [file, hash] = pair.split('=');

      return [unescapePath(file), hash];
    }));
    fileCount = Object.keys(files).length;
  } else if (evidenceFiles) {
    fileCount = Number(evidenceFiles.split(' ')[0]);
  }

  return {
    vulnerableFiles: vulnerableFileList === undefined ? null : pathList(vulnerableFileList),
    files,
    fileCount,
    filesDigest: digest ?? null,
    importers: importerList === undefined ? null : importerList === '(none)' ? [] : pathList(importerList),
  };
}
