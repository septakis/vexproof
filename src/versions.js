// SPDX-License-Identifier: MIT
// npm version numbers and advisory ranges, in one place: which version is newer, and whether one is inside a
// range an advisory gives. Reading a range wrongly can only make vexproof settle the wrong thing, so a part of a
// range that can't be read keeps a version inside it.

/**
 * "1.2.3-rc.1+build.5" as { n: [1, 2, 3], pre: ['rc', 1] }, or null when it is not a version. A missing minor or
 * patch counts as 0 ("1.2" is read as 1.2.0; a range reads it as every 1.2.x, see satisfiesBound); build
 * metadata is ignored.
 */
export function parseVersion(version) {
  const match = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(String(version ?? '').trim());
  if (!match) {
    return null;
  }

  const prerelease = match[4]
    ? match[4].split('.').map((identifier) => (/^\d+$/.test(identifier) ? Number(identifier) : identifier))
    : [];

  return { n: [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)], pre: prerelease };
}

/**
 * Semver order of two versions: negative when `left` is older, 0 when they are the same, positive when `left` is newer.
 * A prerelease is older than its release; prerelease identifiers compare as semver says (numbers by value and
 * before words). Throws on a string that is not a version.
 */
export function compareVersions(left, right) {
  const leftVersion = parseVersion(left);
  const rightVersion = parseVersion(right);
  if (!leftVersion || !rightVersion) {
    throw new Error(`not a version: ${leftVersion ? right : left}`);
  }

  for (let part = 0; part < 3; part++) {
    if (leftVersion.n[part] !== rightVersion.n[part]) {
      return leftVersion.n[part] - rightVersion.n[part];
    }
  }

  if (!leftVersion.pre.length || !rightVersion.pre.length) {
    return rightVersion.pre.length - leftVersion.pre.length;
  }

  for (let position = 0; position < Math.max(leftVersion.pre.length, rightVersion.pre.length); position++) {
    const leftIdentifier = leftVersion.pre[position];
    const rightIdentifier = rightVersion.pre[position];
    if (leftIdentifier === rightIdentifier) {
      continue;
    }
    if (leftIdentifier === undefined) {
      return -1;
    }
    if (rightIdentifier === undefined) {
      return 1;
    }
    if (typeof leftIdentifier === 'number' && typeof rightIdentifier === 'number') {
      return leftIdentifier - rightIdentifier;
    }
    if (typeof leftIdentifier === 'number') {
      return -1;
    }
    if (typeof rightIdentifier === 'number') {
      return 1;
    }

    return leftIdentifier < rightIdentifier ? -1 : 1;
  }

  return 0;
}

/**
 * Does `version` satisfy an advisory range such as ">=4.0.0 <=4.17.22 || <1.2"? Also read: a space after an
 * operator (">= 1.0.0"), a hyphen range ("1.0.0 - 2.0.0") and bounds that leave out the minor or patch
 * ("<=1.2"). A version that can't be read, an empty range, and any part of a range that can't be read
 * ("^1.2.0", "1.x") count as inside it.
 */
export function inAdvisoryRange(version, range) {
  if (!parseVersion(version) || typeof range !== 'string' || !range.trim()) {
    return true;
  }

  return range.split('||').some((alternative) => {
    const text = alternative.trim().replace(/(<=|>=|<|>|=)\s+/g, '$1').replace(/^(\S+)\s+-\s+(\S+)$/, '>=$1 <=$2');
    const parts = text.split(/\s+/).filter(Boolean);
    if (!parts.length || parts.includes('*')) {
      return true;
    }

    return parts.every((part) => {
      const [, operator = '=', bound] = /^(<=|>=|<|>|=)?(.+)$/.exec(part);
      if (!parseVersion(bound)) {
        return true;
      }

      return satisfiesBound(version, operator, bound);
    });
  });
}

/**
 * Does `version` satisfy one comparison, such as "<=4.17.22"? A bound that leaves out its minor or patch ("1.2",
 * "1") stands for every version that starts that way, as npm reads it: "<=1.2" is "<1.3.0", "1.2" alone is
 * ">=1.2.0 <1.3.0" and ">1.2" is ">=1.3.0", while "<1.2" and ">=1.2" are "<1.2.0" and ">=1.2.0".
 */
function satisfiesBound(version, operator, bound) {
  // against the lowest version the bound stands for: "1.2" is compared as "1.2.0"
  const fromLowest = compareVersions(version, bound);

  const partial = /^v?(\d+)(?:\.(\d+))?$/.exec(bound);
  if (!partial) {
    switch (operator) {
      case '<':
        return fromLowest < 0;
      case '<=':
        return fromLowest <= 0;
      case '>':
        return fromLowest > 0;
      case '>=':
        return fromLowest >= 0;
      default:
        return fromLowest === 0;
    }
  }

  // the first release after every version the bound stands for: "1.2" is followed by "1.3.0", "1" by "2.0.0"
  const [, major, minor] = partial;
  const firstAfter = minor === undefined ? `${Number(major) + 1}.0.0` : `${major}.${Number(minor) + 1}.0`;
  const beforeFirstAfter = compareVersions(version, firstAfter) < 0;

  switch (operator) {
    case '<':
      return fromLowest < 0;
    case '<=':
      return beforeFirstAfter;
    case '>':
      return !beforeFirstAfter;
    case '>=':
      return fromLowest >= 0;
    default:
      return fromLowest >= 0 && beforeFirstAfter;
  }
}
