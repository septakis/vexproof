// SPDX-License-Identifier: MIT
// A second line of evidence, independent of module maps and source maps: before a package is called absent,
// look for its own text in the files that ship.
//
// A minifier renames identifiers and drops comments, but it keeps what string literals say. So the string
// literals of an installed package (an error message, a header name) are searched for in the shipped
// JavaScript and HTML. A string that is found counts against the package only if no file the build's records
// already name contains it too: helper code and vendored copies put the same strings in many packages.
//
// Finding such strings does not prove the package ships, and finding none does not prove it doesn't. The check
// can only keep a finding open, never close one.
import { readdirSync, readFileSync, statSync, realpathSync } from 'node:fs';
import { join, resolve, relative, sep } from 'node:path';
import { npmName } from './names.js';
import { readPackageJson } from './package-json.js';
import { listFiles } from './walk.js';

const JS = /\.(m|c)?js$/;
const SHIPPED = /\.(m|c)?js$|\.html?$/i;
const posix = (p) => p.split(sep).join('/');
const MIN = 20, MAX = 160, KEY = 16;
const PER_FILE = 4 * 1024 * 1024, PER_PACKAGE = 40 * 1024 * 1024, MARKERS_PER_PACKAGE = 4000;

// What a string literal must look like to be searched for as it stands: nothing a minifier would re-escape or
// re-quote, and something a person wrote (words), not an alphabet, a hash or a MIME type.
const PLAIN = /^[A-Za-z0-9 _.,:;!?()[\]<>=+*/@#%&|~^-]+$/;
const LITERAL = /"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'|`((?:[^`\\$]|\\.)*)`/g;
function worthSearching(s) {
  if (s.length < MIN || s.length > MAX || !PLAIN.test(s)) return false;
  // prose: three different words. A string that holds code (")throw new TypeError(") is not a message.
  const words = s.split(/[^A-Za-z]+/).filter((w) => w.length >= 3);
  return new Set(words.map((w) => w.toLowerCase())).size >= 3 && !/[;{}]|\)\(|=>|\bthrow new\b|\bfunction ?\(/.test(s);
}

/** Every plain string literal of a source text, of four characters or more: what a minified copy of it still says. */
export function literalsOf(text, into = new Set()) {
  for (const m of text.matchAll(LITERAL)) {
    const s = m[1] ?? m[2] ?? m[3];
    if (s && s.length >= 4 && s.length <= MAX && PLAIN.test(s)) into.add(s);
  }
  return into;
}

/** String literals of one source text that are worth searching for. */
export function markersOf(text, into = new Set()) {
  for (const m of text.matchAll(LITERAL)) {
    const s = m[1] ?? m[2] ?? m[3];
    if (s && worthSearching(s)) into.add(s);
  }
  return into;
}

const scan = (dir) => { try { return readdirSync(dir, { withFileTypes: true }); } catch { return []; } };
const real = (p) => { try { return realpathSync(p); } catch { return null; } };
const nameIn = (dir) => readPackageJson(dir).pkg?.name;
const sameName = (a, b) => typeof a === 'string' && npmName(a) === npmName(b);
// A child folder spelled like `part` without regard to case: lockfile SBOMs lower-case npm names (see npmName),
// while node_modules keeps the published spelling, and on Linux the two are different paths.
const childLike = (dir, part) => {
  const exact = join(dir, part);
  if (real(exact)) return exact;
  const e = scan(dir).find((x) => x.name.toLowerCase() === part.toLowerCase());
  return e ? join(dir, e.name) : null;
};
const pathLike = (dir, name) => name.split('/').reduce((d, part) => (d ? childLike(d, part) : null), dir);

/**
 * Where a package is installed: node_modules/<name> under each base, and its folders in the stores of pnpm,
 * Bun and Yarn. Names are matched without regard to case (see npmName). Copies nested inside other packages
 * are not looked for.
 */
export function installedDirs(name, bases) {
  const out = new Set();
  const flat = npmName(name).replace('/', '+'), dashed = npmName(name).replace('/', '-');
  const keep = (d) => { const r = d && real(d); if (r && sameName(nameIn(r), name)) out.add(r); };
  for (const b of bases) {
    const nm = join(b, 'node_modules');
    keep(pathLike(nm, name));
    for (const store of ['.pnpm', '.bun']) {
      for (const e of scan(join(nm, store))) {
        if (e.name.toLowerCase().startsWith(`${flat}@`)) keep(pathLike(join(nm, store, e.name, 'node_modules'), name));
      }
    }
    for (const e of scan(join(nm, '.store'))) {
      if (e.name.toLowerCase().startsWith(`${dashed}-`)) keep(join(nm, '.store', e.name, 'package'));
    }
  }
  return [...out];
}

function packageMarkers(dirs) {
  const out = new Set();
  let budget = PER_PACKAGE;
  const walk = (dir) => {
    for (const e of scan(dir)) {
      if (budget <= 0 || out.size >= MARKERS_PER_PACKAGE) return;
      const p = join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules') walk(p); continue; }
      if (!e.isFile() || !JS.test(e.name)) continue;
      let size; try { size = statSync(p).size; } catch { continue; }
      if (size > PER_FILE) continue;
      budget -= size;
      try { markersOf(readFileSync(p, 'utf8'), out); } catch { /* unreadable */ }
    }
  };
  for (const d of dirs) walk(d);
  return out;
}

/** The JavaScript and HTML under the shipped folders, linked folders included (see listFiles). */
function shippedFiles(dirs) {
  // packages deployed as folders are counted by name already; their files would only repeat that
  const enter = (name) => name !== 'node_modules';
  return [...new Set(dirs.flatMap((d) => listFiles(resolve(d), { enter })).filter((p) => SHIPPED.test(p)))];
}

/**
 * Search the shipped files for the strings of each package in `absent` (names). Returns
 * Map<name, { markers, hits: [{ text, file }] }> for the names that are installed; a hit is a string found in
 * the shipped files that no recorded file outside the package itself contains.
 *
 * `recorded()` returns the absolute paths of the files the build's records name as shipped (package files and
 * the project's own). It is called only when something was found.
 */
export function findPackageText(absent, { root, bases, shippedDirs, recorded = () => [] }) {
  const out = new Map();
  const wanted = [...new Set(absent)];
  if (!wanted.length || !shippedDirs.length) return out;
  const owners = new Map(); // marker -> names of the wanted packages that contain it
  const dirsOf = new Map();
  for (const name of wanted) {
    const dirs = installedDirs(name, bases);
    if (!dirs.length) continue;
    dirsOf.set(name, dirs);
    const markers = packageMarkers(dirs);
    out.set(name, { markers: markers.size, hits: [] });
    for (const m of markers) { if (!owners.has(m)) owners.set(m, []); owners.get(m).push(name); }
  }
  // a string two of these packages share says nothing about either
  const byKey = new Map();
  for (const [m, names] of owners) {
    if (names.length !== 1) { for (const n of names) out.get(n).markers--; continue; }
    const k = m.slice(0, KEY);
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(m);
  }
  if (!byKey.size) return out;
  const found = new Map(); // marker -> file
  for (const file of shippedFiles(shippedDirs)) {
    let text;
    try { if (statSync(file).size > 64 * 1024 * 1024) continue; text = readFileSync(file, 'utf8'); } catch { continue; }
    // a literal starts after a quote; only those positions are looked at
    for (let i = 0; i < text.length - KEY; i++) {
      const c = text.charCodeAt(i);
      if (c !== 34 && c !== 39 && c !== 96) continue;
      const cands = byKey.get(text.substr(i + 1, KEY));
      if (!cands) continue;
      for (const m of cands) {
        if (found.has(m) || !text.startsWith(m, i + 1)) continue;
        const end = text.charCodeAt(i + 1 + m.length);
        if (end !== 34 && end !== 39 && end !== 96) continue; // the whole literal, not the start of a longer one
        found.set(m, posix(relative(root, file)));
      }
    }
  }
  if (!found.size) return out;
  // a string that a recorded file also holds is accounted for by that file, unless the file is the package's own
  const open = new Map([...found.keys()].map((m) => [m, owners.get(m)[0]]));
  for (const f of new Set(recorded())) {
    if (!open.size) break;
    if (!/\.(m|c)?[jt]sx?$|\.vue$|\.svelte$|\.json$/.test(f)) continue;
    let text; try { if (statSync(f).size > PER_FILE * 4) continue; text = readFileSync(f, 'utf8'); } catch { continue; }
    const at = real(f) ?? f;
    for (const [m, name] of open) {
      if (!text.includes(m)) continue;
      if (dirsOf.get(name).some((d) => at === d || at.startsWith(d + sep))) continue;
      open.delete(m);
    }
  }
  for (const [m, name] of open) out.get(name).hits.push({ text: m, file: found.get(m) });
  return out;
}

/** How many of a package's strings must be found before its absence is doubted. */
export const enoughHits = (r) => r.hits.length >= (r.markers <= 3 ? 1 : 2);

/**
 * Keep open every package-level `not_affected` whose package has its own strings in the shipped files. Returns
 * { checked, uncheckable, kept: [{ name, hits, markers }] }.
 */
export function contentCheck(results, opts) {
  // package-level claims only: a file-level claim is about a package that does ship, so its strings are there
  const closing = results.filter((r) => r.state === 'not_affected' && r.level === 'package' && r.origin === 'auto' && r.key?.startsWith('npm/'));
  const names = closing.map((r) => r.key.slice(4));
  const found = findPackageText(names, opts);
  const kept = [];
  for (const [name, r] of found) {
    if (!enoughHits(r)) continue;
    kept.push({ name, hits: r.hits, markers: r.markers });
    const eg = r.hits[0];
    for (const res of closing) {
      if (res.key !== `npm/${name}`) continue;
      res.state = 'in_triage';
      res.justification = undefined;
      res.level = null;
      res.evidence = null;
      res.moduleReason = `${r.hits.length} string(s) from ${name}'s own files are in the shipped output`;
      res.contentHits = r.hits.slice(0, 5);
      res.detail = `The build's own records do not show ${res.key}, but ${r.hits.length} of the ${r.markers} distinctive string(s) in its installed files ` +
        `are in the shipped output and in no file the records name (for example "${eg.text}" in ${eg.file}). The records may be incomplete for this package; requires manual review.`;
    }
  }
  const uncheckable = [...new Set(names)].filter((n) => !found.has(n));
  return { checked: found.size, uncheckable, kept };
}
