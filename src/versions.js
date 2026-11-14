// SPDX-License-Identifier: MIT
// npm version numbers and advisory ranges, in one place: which version is newer, and whether one is inside a
// range an advisory gives. Reading a range wrongly can only make vexproof settle the wrong thing, so a part of a
// range that can't be read keeps a version inside it.

/**
 * "1.2.3-rc.1+build.5" as { n: [1, 2, 3], pre: ['rc', 1] }, or null when it is not a version. A missing minor or
 * patch counts as 0, as advisories write them ("<1.2" is "<1.2.0"); build metadata is ignored.
 */
export function parseVersion(v) {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(String(v ?? '').trim());
  if (!m) return null;
  const pre = m[4] ? m[4].split('.').map((x) => (/^\d+$/.test(x) ? Number(x) : x)) : [];
  return { n: [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)], pre };
}

/**
 * Semver order of two versions: negative when a is older, 0 when they are the same, positive when a is newer.
 * A prerelease is older than its release; prerelease identifiers compare as semver says (numbers by value and
 * before words). Throws on a string that is not a version.
 */
export function compareVersions(a, b) {
  const x = parseVersion(a), y = parseVersion(b);
  if (!x || !y) throw new Error(`not a version: ${x ? b : a}`);
  for (let i = 0; i < 3; i++) if (x.n[i] !== y.n[i]) return x.n[i] - y.n[i];
  if (!x.pre.length || !y.pre.length) return y.pre.length - x.pre.length;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i], q = y.pre[i];
    if (p === q) continue;
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    if (typeof p === 'number' && typeof q === 'number') return p - q;
    if (typeof p === 'number') return -1;
    if (typeof q === 'number') return 1;
    return p < q ? -1 : 1;
  }
  return 0;
}

/**
 * Does `version` satisfy an advisory range such as ">=4.0.0 <=4.17.22 || <1.2"? Also read: a space after an
 * operator (">= 1.0.0") and a hyphen range ("1.0.0 - 2.0.0"). A version that can't be read, an empty range,
 * and any part of a range that can't be read ("^1.2.0", "1.x") count as inside it.
 */
export function inAdvisoryRange(version, range) {
  if (!parseVersion(version) || typeof range !== 'string' || !range.trim()) return true;
  return range.split('||').some((alt) => {
    const text = alt.trim().replace(/(<=|>=|<|>|=)\s+/g, '$1').replace(/^(\S+)\s+-\s+(\S+)$/, '>=$1 <=$2');
    const parts = text.split(/\s+/).filter(Boolean);
    if (!parts.length || parts.includes('*')) return true;
    return parts.every((part) => {
      const [, op = '=', bound] = /^(<=|>=|<|>|=)?(.+)$/.exec(part);
      if (!parseVersion(bound)) return true;
      const r = compareVersions(version, bound);
      return op === '<' ? r < 0 : op === '<=' ? r <= 0 : op === '>' ? r > 0 : op === '>=' ? r >= 0 : r === 0;
    });
  });
}
