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
import { NO_PROGRESS } from './progress.js';

const JAVASCRIPT = /\.(m|c)?js$/;
const SHIPPED = /\.(m|c)?js$|\.html?$/i;
const posix = (filePath) => filePath.split(sep).join('/');
const MIN_LENGTH = 20;
const MAX_LENGTH = 160;
const KEY_LENGTH = 16;
const PER_FILE = 4 * 1024 * 1024;
const PER_PACKAGE = 40 * 1024 * 1024;
const MARKERS_PER_PACKAGE = 4000;

// What a string literal must look like to be searched for as it stands: nothing a minifier would re-escape or
// re-quote, and something a person wrote (words), not an alphabet, a hash or a MIME type.
const PLAIN = /^[A-Za-z0-9 _.,:;!?()[\]<>=+*/@#%&|~^-]+$/;
const LITERAL = /"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'|`((?:[^`\\$]|\\.)*)`/g;

function worthSearching(literal) {
  if (literal.length < MIN_LENGTH || literal.length > MAX_LENGTH || !PLAIN.test(literal)) {
    return false;
  }

  // prose: three different words. A string that holds code (")throw new TypeError(") is not a message.
  const words = literal.split(/[^A-Za-z]+/).filter((word) => word.length >= 3);

  return new Set(words.map((word) => word.toLowerCase())).size >= 3
    && !/[;{}]|\)\(|=>|\bthrow new\b|\bfunction ?\(/.test(literal);
}

/** Every plain string literal of a source text, of four characters or more: what a minified copy of it still says. */
export function literalsOf(text, into = new Set()) {
  for (const match of text.matchAll(LITERAL)) {
    const literal = match[1] ?? match[2] ?? match[3];
    if (literal && literal.length >= 4 && literal.length <= MAX_LENGTH && PLAIN.test(literal)) into.add(literal);
  }

  return into;
}

/** String literals of one source text that are worth searching for. */
export function markersOf(text, into = new Set()) {
  for (const match of text.matchAll(LITERAL)) {
    const literal = match[1] ?? match[2] ?? match[3];
    if (literal && worthSearching(literal)) into.add(literal);
  }

  return into;
}

const scan = (directory) => {
  try {
    return readdirSync(directory, { withFileTypes: true });
  } catch {
    return [];
  }
};
const real = (filePath) => {
  try {
    return realpathSync(filePath);
  } catch {
    return null;
  }
};
const nameIn = (directory) => readPackageJson(directory).pkg?.name;
const sameName = (candidate, name) => typeof candidate === 'string' && npmName(candidate) === npmName(name);
// A child folder spelled like `part` without regard to case: lockfile SBOMs lower-case npm names (see npmName),
// while node_modules keeps the published spelling, and on Linux the two are different paths.
const childLike = (directory, part) => {
  const exact = join(directory, part);
  if (real(exact)) {
    return exact;
  }

  const child = scan(directory).find((entry) => entry.name.toLowerCase() === part.toLowerCase());

  return child ? join(directory, child.name) : null;
};
const pathLike = (directory, name) => name.split('/').reduce((current, part) => (current ? childLike(current, part) : null), directory);

/**
 * Where a package is installed: node_modules/<name> under each base, and its folders in the stores of pnpm,
 * Bun and Yarn. Names are matched without regard to case (see npmName). Copies nested inside other packages
 * are not looked for.
 */
export function installedDirs(name, bases) {
  const found = new Set();
  const flatName = npmName(name).replace('/', '+');
  const dashedName = npmName(name).replace('/', '-');
  const keep = (directory) => {
    const resolved = directory && real(directory);
    if (resolved && sameName(nameIn(resolved), name)) found.add(resolved);
  };

  for (const base of bases) {
    const nodeModules = join(base, 'node_modules');
    keep(pathLike(nodeModules, name));

    for (const store of ['.pnpm', '.bun']) {
      for (const entry of scan(join(nodeModules, store))) {
        if (entry.name.toLowerCase().startsWith(`${flatName}@`)) {
          keep(pathLike(join(nodeModules, store, entry.name, 'node_modules'), name));
        }
      }
    }

    for (const entry of scan(join(nodeModules, '.store'))) {
      if (entry.name.toLowerCase().startsWith(`${dashedName}-`)) keep(join(nodeModules, '.store', entry.name, 'package'));
    }
  }

  return [...found];
}

function packageMarkers(directories) {
  const markers = new Set();
  let budget = PER_PACKAGE;

  const walk = (directory) => {
    for (const entry of scan(directory)) {
      if (budget <= 0 || markers.size >= MARKERS_PER_PACKAGE) {
        return;
      }

      const entryPath = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules') walk(entryPath);
        continue;
      }
      if (!entry.isFile() || !JAVASCRIPT.test(entry.name)) {
        continue;
      }

      let size;
      try {
        size = statSync(entryPath).size;
      } catch {
        continue;
      }
      if (size > PER_FILE) {
        continue;
      }

      budget -= size;
      try {
        markersOf(readFileSync(entryPath, 'utf8'), markers);
      } catch {
        /* unreadable */
      }
    }
  };

  for (const directory of directories) walk(directory);

  return markers;
}

/** The JavaScript and HTML under the shipped folders, linked folders included (see listFiles). */
function shippedFiles(directories) {
  // packages deployed as folders are counted by name already; their files would only repeat that
  const enter = (name) => name !== 'node_modules';
  const files = directories.flatMap((directory) => listFiles(resolve(directory), { enter }));

  return [...new Set(files.filter((file) => SHIPPED.test(file)))];
}

/**
 * Search the shipped files for the strings of each package in `absent` (names). Returns
 * Map<name, { markers, hits: [{ text, file }] }> for the names that are installed; a hit is a string found in
 * the shipped files that no recorded file outside the package itself contains.
 *
 * `recorded()` returns the absolute paths of the files the build's records name as shipped (package files and
 * the project's own). It is called only when something was found.
 */
export function findPackageText(absent, { root, bases, shippedDirs, recorded = () => [], progress = NO_PROGRESS }) {
  const out = new Map();
  const wanted = [...new Set(absent)];
  if (!wanted.length || !shippedDirs.length) {
    return out;
  }

  const owners = new Map(); // marker -> names of the wanted packages that contain it
  const directoriesOf = new Map();
  for (const name of wanted) {
    const directories = installedDirs(name, bases);
    if (!directories.length) {
      continue;
    }

    directoriesOf.set(name, directories);
    const markers = packageMarkers(directories);
    out.set(name, { markers: markers.size, hits: [] });
    for (const marker of markers) {
      if (!owners.has(marker)) owners.set(marker, []);
      owners.get(marker).push(name);
    }
  }

  // a string two of these packages share says nothing about either
  const byKey = new Map();
  for (const [marker, names] of owners) {
    if (names.length !== 1) {
      for (const ownerName of names) out.get(ownerName).markers--;
      continue;
    }

    const key = marker.slice(0, KEY_LENGTH);
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(marker);
  }
  if (!byKey.size) {
    return out;
  }

  const found = new Map(); // marker -> file
  const files = shippedFiles(shippedDirs);
  const stage = progress.stage(`content check of ${wanted.length} absent package(s)`, files.length);
  for (const [position, file] of files.entries()) {
    stage.step(position + 1);
    let text;
    try {
      if (statSync(file).size > 64 * 1024 * 1024) {
        continue;
      }
      text = readFileSync(file, 'utf8');
    } catch {
      continue;
    }

    // a literal starts after a quote; only those positions are looked at
    for (let position = 0; position < text.length - KEY_LENGTH; position++) {
      const opening = text.charCodeAt(position);
      if (opening !== 34 && opening !== 39 && opening !== 96) {
        continue;
      }

      const candidates = byKey.get(text.substr(position + 1, KEY_LENGTH));
      if (!candidates) {
        continue;
      }

      for (const marker of candidates) {
        if (found.has(marker) || !text.startsWith(marker, position + 1)) {
          continue;
        }

        const closing = text.charCodeAt(position + 1 + marker.length);
        if (closing !== 34 && closing !== 39 && closing !== 96) {
          continue; // the whole literal, not the start of a longer one
        }

        found.set(marker, posix(relative(root, file)));
      }
    }
  }
  stage.end();

  if (!found.size) {
    return out;
  }

  // a string that a recorded file also holds is accounted for by that file, unless the file is the package's own
  const open = new Map([...found.keys()].map((marker) => [marker, owners.get(marker)[0]]));
  for (const recordedFile of new Set(recorded())) {
    if (!open.size) {
      break;
    }
    if (!/\.(m|c)?[jt]sx?$|\.vue$|\.svelte$|\.json$/.test(recordedFile)) {
      continue;
    }

    let text;
    try {
      if (statSync(recordedFile).size > PER_FILE * 4) {
        continue;
      }
      text = readFileSync(recordedFile, 'utf8');
    } catch {
      continue;
    }

    const realPath = real(recordedFile) ?? recordedFile;
    for (const [marker, name] of open) {
      if (!text.includes(marker)) {
        continue;
      }
      if (directoriesOf.get(name).some((directory) => realPath === directory || realPath.startsWith(directory + sep))) {
        continue;
      }

      open.delete(marker);
    }
  }

  for (const [marker, name] of open) out.get(name).hits.push({ text: marker, file: found.get(marker) });

  return out;
}

// A page can load a package from a public npm CDN instead of from the bundle: a script tag, an import map, or
// an import of a URL. The build's records then show nothing of the package, and it still runs in production.
// Each pattern ends where the package name starts.
const CDN_PREFIXES = [
  'unpkg\\.com/',
  'npmcdn\\.com/',
  '(?:cdn|fastly|gcore|testingcf)\\.jsdelivr\\.net/npm/',
  'esm\\.run/',
  '(?:cdn\\.)?esm\\.sh/(?:v\\d+/|stable/|gh/)?',
  'cdn\\.skypack\\.dev/(?:-/|pin/)?',
  'ga\\.jspm\\.io/npm:',
  'jspm\\.dev/(?:npm:)?',
  'cdnjs\\.cloudflare\\.com/ajax/libs/',
  'cdn\\.bootcdn\\.net/ajax/libs/',
];
const CDN_URL = new RegExp(`//(?:${CDN_PREFIXES.join('|')})((?:@[a-z0-9~._-]+/)?[a-z0-9~._-]+)`, 'gi');

/**
 * The packages in `absent` (names) that a shipped HTML or JavaScript file loads from a public npm CDN, as
 * Map<name, { url, file }> with the first place each one was seen. cdnjs names some libraries with a ".js"
 * the npm name lacks (lodash.js), so a name is also compared without it. The version in the URL is not
 * compared: any copy of the package loaded this way leaves its absence from the bundle meaningless.
 */
export function findCdnLoads(absent, { root, shippedDirs }) {
  const loads = new Map();
  const wanted = new Map([...new Set(absent)].map((name) => [npmName(name), name]));
  if (!wanted.size || !shippedDirs.length) {
    return loads;
  }

  for (const file of shippedFiles(shippedDirs)) {
    let text;
    try {
      if (statSync(file).size > 64 * 1024 * 1024) {
        continue;
      }
      text = readFileSync(file, 'utf8');
    } catch {
      continue;
    }

    for (const match of text.matchAll(CDN_URL)) {
      // a name ends at the version or the next path step, so "lodash@4.17.21" and "lodash.js" both name lodash
      const written = npmName(match[1].replace(/@[^/@]*$/, ''));
      const name = wanted.get(written) ?? wanted.get(written.replace(/\.js$/, ''));

      if (name && !loads.has(name)) {
        loads.set(name, { url: match[0].slice(2), file: posix(relative(root, file)) });
      }
    }
  }

  return loads;
}

/** How many of a package's strings must be found before its absence is doubted. */
const enoughHits = (search) => search.hits.length >= (search.markers <= 3 ? 1 : 2);

/**
 * Keep open every package-level `not_affected` whose package has its own strings in the shipped files. Returns
 * { checked, uncheckable, kept: [{ name, hits, markers }] }.
 */
export function contentCheck(results, options) {
  // package-level claims only: a file-level claim is about a package that does ship, so its strings are there
  const closing = results.filter((result) => result.state === 'not_affected'
    && result.level === 'package'
    && result.origin === 'auto'
    && result.key?.startsWith('npm/'));
  const names = closing.map((result) => result.key.slice(4));
  const found = findPackageText(names, options);

  const kept = [];
  for (const [name, search] of found) {
    if (!enoughHits(search)) {
      continue;
    }

    kept.push({ name, hits: search.hits, markers: search.markers });
    const example = search.hits[0];
    for (const result of closing) {
      if (result.key !== `npm/${name}`) {
        continue;
      }

      result.state = 'in_triage';
      result.justification = undefined;
      result.level = null;
      result.evidence = null;
      result.moduleReason = `${search.hits.length} string(s) from ${name}'s own files are in the shipped output`;
      result.contentHits = search.hits.slice(0, 5);
      result.detail = `The build's own records do not show ${result.key}, but ${search.hits.length} of the ${search.markers} ` +
        'distinctive string(s) in its installed files are in the shipped output and in no file the records name ' +
        `(for example "${example.text}" in ${example.file}). The records may be incomplete for this package; requires manual review.`;
    }
  }

  // a package the shipped pages load from a CDN runs in production whatever the bundle holds
  const loaded = [];
  for (const [name, load] of findCdnLoads(names, options)) {
    loaded.push({ name, ...load });
    for (const result of closing) {
      if (result.key !== `npm/${name}` || result.state !== 'not_affected') {
        continue;
      }

      result.state = 'in_triage';
      result.justification = undefined;
      result.level = null;
      result.evidence = null;
      result.moduleReason = `${load.file} loads ${name} from a CDN (${load.url})`;
      result.detail = `The build's own records do not show ${result.key}, but the shipped file ${load.file} loads it from a CDN ` +
        `(${load.url}), so it runs in production from there. Which version that is was not compared; requires manual review.`;
    }
  }

  const uncheckable = [...new Set(names)].filter((name) => !found.has(name));

  return { checked: found.size, uncheckable, kept, loaded };
}
