// SPDX-License-Identifier: MIT
// What a run prints about its findings: the open ones first, by package and with the reason each stays open,
// then the settled ones as counts, and the totals last, where a long log is read. Every line fits in 80 columns
// unless a single word (a path, a package name) is longer than that.
import { parsePurl } from '../index.js';

export const WIDTH = 80;

/**
 * `text` as lines no wider than `width`, broken at spaces. Lines after the first start with `hanging`; a word
 * longer than the width stays whole on a line of its own.
 */
export function wrap(text, { width = WIDTH, indent = '', hanging = indent } = {}) {
  const lines = [];
  let line = indent;
  let empty = true;

  for (const word of String(text).split(/\s+/).filter(Boolean)) {
    if (!empty && line.length + 1 + word.length > width) {
      lines.push(line);
      line = hanging;
      empty = true;
    }

    line += empty ? word : ` ${word}`;
    empty = false;
  }

  if (!empty) {
    lines.push(line);
  }

  return lines;
}

const plural = (count, one, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;

/** A package as a person writes it: @scope/name@1.2.3, not the purl with its escapes. */
export function packageLabel(result) {
  const parsed = parsePurl(result.purl ?? '');
  if (parsed?.type !== 'npm' || !parsed.name) {
    return String(result.purl);
  }

  return parsed.version ? `${parsed.name}@${parsed.version}` : parsed.name;
}

/**
 * Why an open finding is open, in a few words. The module-level check's reason when there is one; otherwise
 * what the statement's detail says. The finding's own id is left out: the line it is printed under names it.
 */
export function whyOpen(result) {
  const detail = String(result.detail ?? '');
  let reason;

  if (result.proWouldSettle) {
    reason = 'the package is in the build; Pro\'s file-level check would settle this';
  } else if (/^no module rules? for /.test(result.moduleReason ?? '')) {
    reason = 'the package is in the build, and no file-level rule covers this advisory';
  } else if (result.moduleReason && result.moduleReason !== 'no module map supplied') {
    reason = result.moduleReason;
  } else if (/is not listed in the lockfile SBOM/.test(detail)) {
    reason = 'not in the lockfile SBOM, so no claim is made';
  } else if (/is not an npm package/.test(detail)) {
    reason = 'not an npm package: a JavaScript build says nothing about it';
  } else if (/Could not parse purl/.test(detail)) {
    reason = 'its package URL could not be read';
  } else if (/names none of the npm packages/.test(detail)) {
    reason = 'the bundle SBOM names none of the lockfile\'s packages, so absence is not inferred from it';
  } else {
    reason = 'the package is in the build';
  }

  const ownNames = [result.generatedCode, result.id].filter(Boolean);
  for (const name of ownNames) {
    reason = reason
      .split(`no module rule for ${name}`).join('no module rule for this advisory')
      .split(`and ${name} has none`).join('and this advisory has none')
      .split(`${name} is about`).join('it is about');
  }

  return reason;
}

/** Results grouped by package label, in label order: [[label, results]]. */
function byPackage(results) {
  const groups = new Map();
  for (const result of results) {
    const label = packageLabel(result);
    if (!groups.has(label)) groups.set(label, []);
    groups.get(label).push(result);
  }

  return [...groups].sort(([left], [right]) => left.localeCompare(right));
}

/** One open or reviewed package: its name, then each reason with the advisories it holds for. */
function detailedSection(results, describe) {
  const lines = [];

  for (const [label, packageResults] of byPackage(results)) {
    lines.push(`  ${label}`);

    const byReason = new Map();
    for (const result of packageResults) {
      const reason = describe(result);
      if (!byReason.has(reason)) byReason.set(reason, []);
      byReason.get(reason).push(`${result.id}${result.isNew ? ' [new]' : ''}`);
    }

    for (const [reason, ids] of byReason) {
      lines.push(...wrap(ids.sort().join('  '), { indent: '    ' }));
      lines.push(...wrap(reason, { indent: '      ' }));
    }
  }

  return lines;
}

/** Settled findings as counts: "cookie@0.6.0, sharp@0.34.5 (3)", wrapped. */
function countedSection(results) {
  const entries = byPackage(results).map(([label, packageResults]) => (packageResults.length > 1 ? `${label} (${packageResults.length})` : label));

  // a package and its count stay together on a line: the space between them is put back after wrapping
  const JOINED = '';

  return wrap(entries.map((entry) => entry.replace(' (', `${JOINED}(`)).join(', '), { indent: '  ' }).map((line) => line.split(JOINED).join(' '));
}

const heading = (title, results) => {
  const packages = new Set(results.map(packageLabel)).size;

  return `${title}: ${plural(results.length, 'finding')} in ${plural(packages, 'package')}`;
};

/**
 * The lines a run prints about its results. `written` names the files it wrote, `signedBy` the signing key.
 * The last line is the run's totals, in the same words every release has used.
 */
export function summaryLines(results, { summary, written, signedBy = null }) {
  const lines = ['']; // a gap after the run's own notes, which come first
  const section = (title, sectionResults, body) => {
    if (!sectionResults.length) {
      return;
    }

    lines.push(heading(title, sectionResults), ...body(sectionResults), '');
  };

  const reviewed = (result) => result.origin === 'reviewed';
  // a finding on a package the lockfile SBOM doesn't list is open, but there is nothing in it to act on here
  const outsideLockfile = (result) => result.state === 'in_triage' && /is not listed in the lockfile SBOM/.test(String(result.detail ?? ''));
  const open = results.filter((result) => result.state === 'in_triage' && !outsideLockfile(result));
  const unclaimed = results.filter(outsideLockfile);
  const exploitable = results.filter((result) => result.state === 'exploitable');
  const reviewedSettled = results.filter((result) => reviewed(result) && result.state !== 'in_triage' && result.state !== 'exploitable');
  const automatic = results.filter((result) => !reviewed(result) && result.state !== 'in_triage' && result.state !== 'exploitable');
  const atModuleLevel = automatic.filter((result) => result.level === 'module');
  const atPackageLevel = automatic.filter((result) => result.level !== 'module');

  section('Confirmed exploitable', exploitable, (sectionResults) => detailedSection(sectionResults, () => 'a review says this is exploitable'));
  section('Open', open, (sectionResults) => detailedSection(sectionResults, whyOpen));
  section('Open, not in the lockfile SBOM (no claim made)', unclaimed, countedSection);
  section('Settled by review', reviewedSettled, (sectionResults) => detailedSection(sectionResults, (result) => `${result.state}${result.carriedFrom ? ', carried from an earlier review' : ', reviewed'}`));
  section('Not affected, vulnerable files not in the build', atModuleLevel, countedSection);
  section('Not affected, package not in the build', atPackageLevel, countedSection);

  const parts = [`${summary.not_affected} not_affected${summary.module ? ` (${summary.module} at module level)` : ''}`];
  if (summary.reviewed) parts.push(`${summary.reviewed} reviewed`);
  parts.push(`${summary.in_triage} in_triage`);
  lines.push(`vexproof: ${results.length} finding(s) → ${parts.join(', ')} → ${written.join(' + ')}${signedBy ? ` (signed by ${signedBy})` : ''}`);

  return lines;
}

/** The Pro hint for a run without a license, as lines: which packages Pro's file-level check would settle. */
export function proHintLines(results, { summary, url }) {
  const counts = new Map();
  for (const result of results) {
    if (!result.proWouldSettle) continue;
    const name = String(result.key).replace(/^npm\//, '');
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }

  const list = [...counts].map(([name, count]) => `${name} ${count}`).join(', ');

  return [
    ...wrap(`vexproof Pro would settle ${summary.proWouldSettle} of your ${summary.in_triage} open finding(s) by checking which files of each package shipped (${list}), and write an audit-ready report with the evidence.`),
    ...wrap(`One yearly price per organization, free for community open-source projects: ${url} (hide this with --quiet)`),
  ];
}
