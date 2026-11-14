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
import { splitNodeModulesPath, splitShipped } from './modules.js';
import { parsePurl } from './index.js';

const sha = (b) => createHash('sha256').update(b).digest('hex');
const short = (h) => h.slice(0, 16);
const PER_FILE_LIMIT = 20; // above this, one hash for all files keeps the VEX readable

function ruleFor(rules, name, id, aliases, version) {
  const adv = rules?.packages?.[name]?.advisories ?? {};
  const names = [id, ...(aliases ?? [])];
  const k = Object.keys(adv).find((key) => {
    const r = adv[key];
    return [r.id ?? key, ...(r.aliases ?? [])].some((x) => names.includes(x)) && (!r.versions || r.versions.includes(version));
  });
  return k ? adv[k] : null;
}

/**
 * Adds r.fingerprint = { vulnerableFiles, files: {file: hash} | null, filesDigest, importers: [..] | null }
 * to each open result on a bundled npm package. Parts that can't be established are null, and a null part
 * never matches: the review then carries only for the exact same package version, as before.
 */
export function attachFingerprints(results, { moduleMap, rules, cwd = process.cwd(), readFile = (p) => readFileSync(p) }) {
  if (!moduleMap) return results;
  const keyIndex = new Map(); // "root\0file" -> module-map key
  for (const k of moduleMap.graph?.shipped ?? []) {
    const s = splitNodeModulesPath(k);
    if (s) keyIndex.set(`${s.root}\0${s.file}`, k);
  }
  for (const r of results) {
    if (r.state !== 'in_triage') continue;
    const p = parsePurl(r.purl);
    const entry = p?.type === 'npm' ? moduleMap.packages.get(p.name) : null;
    if (!entry) continue;
    const vbr = entry.versionByRoot;
    let roots = [...entry.roots].filter((root) => vbr?.get(root) === p.version);
    if (!roots.length && entry.roots.size === 1) roots = [...entry.roots];
    if (!roots.length) continue;

    const rule = ruleFor(rules, p.name, r.id, r.aliases, p.version);
    const pairs = roots.flatMap((root) => [...(entry.byRoot?.get(root) ?? [])].map((file) => ({ root, file })));
    const vulnerable = rule ? pairs.filter((x) => rule.files.includes(x.file)) : pairs;
    if (!vulnerable.length) continue;

    // content hashes, read from the installed package
    let files = {};
    try {
      for (const { root, file } of vulnerable) files[file] = short(sha(readFile(join(cwd, root, file))));
    } catch { files = null; }
    const filesDigest = files ? short(sha(Object.keys(files).sort().map((f) => `${f}\0${files[f]}`).join('\n'))) : null;

    // importers from outside the package
    let importers = null;
    const g = moduleMap.graph;
    if (g) {
      const out = new Set(), seen = new Set();
      const inPackage = (k) => { const s = splitShipped(moduleMap, k); return s && s.name === p.name && roots.includes(s.root); };
      const stack = vulnerable.map((x) => keyIndex.get(`${x.root}\0${x.file}`)).filter(Boolean);
      while (stack.length) {
        const k = stack.pop();
        if (seen.has(k)) continue;
        seen.add(k);
        for (const imp of g.importers.get(k) ?? []) {
          if (inPackage(imp)) { stack.push(imp); continue; }
          if (!g.shipped.has(imp)) continue; // code that didn't ship can't call anything
          const s = splitShipped(moduleMap, imp);
          out.add(s ? `${s.name}@${moduleMap.packages.get(s.name)?.versionByRoot?.get(s.root) ?? '?'}/${s.file}` : imp);
        }
      }
      importers = [...out].sort();
    }
    r.fingerprint = {
      vulnerableFiles: rule ? vulnerable.map((x) => x.file).sort() : null,
      files: files && Object.keys(files).length <= PER_FILE_LIMIT ? files : null,
      fileCount: vulnerable.length,
      filesDigest,
      importers,
    };
  }
  return results;
}

/** What changed between a reviewed fingerprint and the current one; [] when the evidence is the same. */
export function fingerprintChanges(before, now) {
  const changes = [];
  if (!before?.filesDigest || !now?.filesDigest) changes.push('the vulnerable files could not be compared');
  else if (before.filesDigest !== now.filesDigest) {
    if (before.files && now.files) {
      const names = [...new Set([...Object.keys(before.files), ...Object.keys(now.files)])].sort();
      const changed = names.filter((f) => before.files[f] !== now.files[f]);
      changes.push(`vulnerable files changed: ${changed.join(', ')}`);
    } else changes.push(`the package's shipped files changed (${now.fileCount} files)`);
  }
  if (!before?.importers || !now?.importers) changes.push('the code importing them could not be compared');
  else {
    const added = now.importers.filter((i) => !before.importers.includes(i));
    const removed = before.importers.filter((i) => !now.importers.includes(i));
    if (added.length) changes.push(`new importer${added.length > 1 ? 's' : ''}: ${added.join(', ')}`);
    if (removed.length && !added.length) changes.push(`no longer imported by: ${removed.join(', ')}`);
  }
  return changes;
}

// ---------- as CycloneDX properties ----------

export function fingerprintProperties(fp) {
  if (!fp) return [];
  const p = [];
  if (fp.vulnerableFiles) p.push({ name: 'vexproof:vulnerable-files', value: fp.vulnerableFiles.join(' ') });
  if (fp.filesDigest) p.push({ name: 'vexproof:evidence-files', value: fp.files ? Object.entries(fp.files).map(([f, h]) => `${f}=${h}`).join(' ') : `${fp.fileCount} files=${fp.filesDigest}` });
  if (fp.filesDigest) p.push({ name: 'vexproof:evidence-files-digest', value: fp.filesDigest });
  if (fp.importers) p.push({ name: 'vexproof:importers', value: fp.importers.join(' ') || '(none)' });
  return p;
}

export function fingerprintFromProperties(props) {
  const get = (n) => props?.find((x) => x.name === n)?.value;
  const digest = get('vexproof:evidence-files-digest');
  const ev = get('vexproof:evidence-files');
  const imp = get('vexproof:importers');
  if (!digest && imp === undefined) return null;
  let files = null, fileCount = null;
  if (ev && !/^\d+ files=/.test(ev)) { files = Object.fromEntries(ev.split(' ').map((x) => x.split('='))); fileCount = Object.keys(files).length; }
  else if (ev) fileCount = Number(ev.split(' ')[0]);
  return {
    vulnerableFiles: get('vexproof:vulnerable-files')?.split(' ') ?? null,
    files, fileCount, filesDigest: digest ?? null,
    importers: imp === undefined ? null : imp === '(none)' ? [] : imp.split(' '),
  };
}
