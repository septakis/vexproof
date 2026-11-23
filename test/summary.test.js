// SPDX-License-Identifier: MIT
// What a run prints about its findings: open ones first with their reasons, settled ones counted, totals last,
// and nothing wider than 80 columns.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarize } from '../src/index.js';
import { summaryLines, proHintLines, whyOpen, packageLabel, wrap, WIDTH } from '../src/cli/summary.js';
import { forTerminal } from '../src/cli/common.js';

const finding = (name, version, id, extra = {}) => ({
  purl: `pkg:npm/${name.replace('@', '%40')}@${version}`, key: `npm/${name}`, id, aliases: [], state: 'in_triage', level: null,
  origin: 'auto', moduleReason: null, proWouldSettle: false, generatedCode: null, detail: `npm/${name} is present in the shipped bundle; requires manual review.`,
  ...extra,
});
const settled = (name, version, id, level = 'package', extra = {}) => finding(name, version, id, { state: 'not_affected', level, justification: 'code_not_present', ...extra });

test('wrap: breaks at spaces, indents what follows, and leaves a word that is too long whole', () => {
  assert.deepEqual(wrap('one two three four', { width: 9 }), ['one two', 'three', 'four']);
  assert.deepEqual(wrap('one two three', { width: 10, indent: '  ', hanging: '    ' }), ['  one two', '    three']);
  assert.deepEqual(wrap('a/very/long/path/that/does/not/fit.js here', { width: 12, indent: '  ' }), ['  a/very/long/path/that/does/not/fit.js', '  here']);
  assert.deepEqual(wrap('   ', { width: 10 }), []);
});

test('a package is named as a person writes it, not as its purl spells it', () => {
  assert.equal(packageLabel({ purl: 'pkg:npm/%40sveltejs/kit@2.70.3' }), '@sveltejs/kit@2.70.3');
  assert.equal(packageLabel({ purl: 'pkg:npm/lodash@4.17.21' }), 'lodash@4.17.21');
  assert.equal(packageLabel({ purl: 'pkg:pypi/requests@2.31.0' }), 'pkg:pypi/requests@2.31.0');
  assert.equal(packageLabel({ purl: 'not a purl' }), 'not a purl');
});

test('every open finding gets a reason, without its own id said twice', () => {
  assert.equal(whyOpen(finding('lodash', '4.17.21', 'GHSA-a')), 'the package is in the build');
  assert.equal(whyOpen(finding('lodash', '4.17.21', 'GHSA-a', { moduleReason: 'no module map supplied' })), 'the package is in the build');
  assert.equal(whyOpen(finding('lodash', '4.17.21', 'GHSA-a', { moduleReason: 'vulnerable file(s) bundled: omit.js' })), 'vulnerable file(s) bundled: omit.js');
  assert.equal(whyOpen(finding('katex', '0.16.47', 'GHSA-a', { moduleReason: 'no module rules for katex' })), 'the package is in the build, and no file-level rule covers this advisory');
  assert.equal(whyOpen(finding('qs', '6.15.2', 'GHSA-a', { moduleReason: 'no module rule for GHSA-a' })), 'the package is in the build, and no file-level rule covers this advisory');
  assert.equal(whyOpen(finding('vite', '5.4.21', 'GHSA-a', { proWouldSettle: true, moduleReason: null })), 'the package is in the build; Pro\'s file-level check would settle this');
  assert.equal(
    whyOpen(finding('rollup', '4.20.0', 'CVE-2024-47068', { generatedCode: 'GHSA-gcx4-mw62-g8wm', moduleReason: 'GHSA-gcx4-mw62-g8wm is about what rollup writes into a build, which its own files don\'t show' })),
    'it is about what rollup writes into a build, which its own files don\'t show',
  );
  assert.equal(whyOpen(finding('next', '14.1.4', 'GHSA-a', { detail: 'npm/next is not listed in the lockfile SBOM; no claim made.' })), 'not in the lockfile SBOM, so no claim is made');
  assert.match(whyOpen(finding('requests', '2.31.0', 'GHSA-a', { detail: 'pypi/requests is not an npm package; a JavaScript build says nothing about it, so no claim is made.' })), /^not an npm package/);
});

test('the summary: open findings by package with their reasons, settled ones counted, totals last', () => {
  const results = [
    settled('moment', '2.29.1', 'GHSA-8hfj-j24r-96c4'),
    finding('@sveltejs/kit', '2.70.3', 'GHSA-3r8g-jcqq-3p5j', { moduleReason: 'no module rules for @sveltejs/kit' }),
    finding('lodash', '4.17.21', 'GHSA-xxjr-mmjv-4gpg', { moduleReason: 'vulnerable file(s) bundled: _baseUnset.js, omit.js' }),
    settled('vite', '5.4.21', 'GHSA-vg6x-rcgg-rjx6', 'module'),
    finding('@sveltejs/kit', '2.70.3', 'GHSA-6cf5-gc4q-fm3x', { moduleReason: 'no module rules for @sveltejs/kit', isNew: true }),
    settled('moment', '2.29.1', 'GHSA-wc69-rhjr-hc9g'),
    settled('cookie', '0.6.0', 'GHSA-pxg6-pf52-xh8x'),
  ];

  const lines = summaryLines(results, { summary: summarize(results), written: ['vex.cdx.json', 'vex.openvex.json'] });

  assert.deepEqual(lines, [
    '',
    'Open: 3 findings in 2 packages',
    '  @sveltejs/kit@2.70.3',
    '    GHSA-3r8g-jcqq-3p5j GHSA-6cf5-gc4q-fm3x [new]',
    '      the package is in the build, and no file-level rule covers this advisory',
    '  lodash@4.17.21',
    '    GHSA-xxjr-mmjv-4gpg',
    '      vulnerable file(s) bundled: _baseUnset.js, omit.js',
    '',
    'Not affected, vulnerable files not in the build: 1 finding in 1 package',
    '  vite@5.4.21',
    '',
    'Not affected, package not in the build: 3 findings in 2 packages',
    '  cookie@0.6.0, moment@2.29.1 (2)',
    '',
    'vexproof: 7 finding(s) → 4 not_affected (1 at module level), 3 in_triage → vex.cdx.json + vex.openvex.json',
  ]);
});

test('the summary: reviews, carried reviews and a confirmed exploitable finding have sections of their own', () => {
  const results = [
    finding('marked', '4.0.0', 'GHSA-rrrm-qjm4-v8hf', { state: 'exploitable', origin: 'reviewed' }),
    settled('qs', '6.5.2', 'GHSA-hrpp-h998-j3pp', null, { origin: 'reviewed', carriedFrom: '1.0.0' }),
    finding('semver', '7.5.0', 'GHSA-c2qf-rxjj-qqgw', { state: 'false_positive', origin: 'reviewed' }),
    finding('lodash', '4.17.21', 'GHSA-35jh-r3h4-6jhm', { origin: 'reviewed', reReview: true, moduleReason: 'the review by Ana needs re-confirming: new importer: src/filters.js' }),
  ];

  const lines = summaryLines(results, { summary: summarize(results), written: ['vex.json'], signedBy: 'Acme release signing' });

  assert.deepEqual(lines, [
    '',
    'Confirmed exploitable: 1 finding in 1 package',
    '  marked@4.0.0',
    '    GHSA-rrrm-qjm4-v8hf',
    '      a review says this is exploitable',
    '',
    'Open: 1 finding in 1 package',
    '  lodash@4.17.21',
    '    GHSA-35jh-r3h4-6jhm',
    '      the review by Ana needs re-confirming: new importer: src/filters.js',
    '',
    'Settled by review: 2 findings in 2 packages',
    '  qs@6.5.2',
    '    GHSA-hrpp-h998-j3pp',
    '      not_affected, carried from an earlier review',
    '  semver@7.5.0',
    '    GHSA-c2qf-rxjj-qqgw',
    '      false_positive, reviewed',
    '',
    'vexproof: 4 finding(s) → 1 not_affected, 4 reviewed, 1 in_triage → vex.json (signed by Acme release signing)',
  ]);
});

test('no line of a large summary is wider than 80 columns, apart from the totals with their file names', () => {
  const results = [];
  for (let index = 0; index < 60; index += 1) {
    results.push(settled(`@scope-${index}/a-rather-long-package-name`, `1.${index}.0`, `GHSA-aaaa-bbbb-${String(index).padStart(4, '0')}`));
    results.push(finding('nanoid', '3.3.3', `GHSA-cccc-dddd-${String(index).padStart(4, '0')}`, { moduleReason: 'files the fix changed (3.3.3 → 3.3.16) are bundled: index.browser.js, another/file/of/the/package.js, and/one/more.js' }));
  }

  const lines = summaryLines(results, { summary: summarize(results), written: ['vex.json'] });
  const body = lines.slice(0, -1);

  assert.ok(body.every((line) => line.length <= WIDTH), body.find((line) => line.length > WIDTH));
  assert.match(lines.at(-1), /^vexproof: 120 finding\(s\) → 60 not_affected, 60 in_triage → vex\.json$/);
  // sixty advisories with one reason are one block, not sixty
  assert.equal(body.filter((line) => line.includes('files the fix changed')).length, 1);
});

test('the Pro hint fits in 80 columns and names what Pro would settle', () => {
  const results = [
    finding('vite', '5.4.21', 'GHSA-a', { proWouldSettle: true }),
    finding('vite', '5.4.21', 'GHSA-b', { proWouldSettle: true }),
    finding('lodash', '4.17.21', 'GHSA-c', { proWouldSettle: true }),
    finding('katex', '0.16.47', 'GHSA-d'),
  ];

  const lines = proHintLines(results, { summary: summarize(results), url: 'https://vexproof.dev/#pricing' });

  assert.ok(lines.every((line) => line.length <= WIDTH));
  assert.match(lines.join(' '), /Pro would settle 3 of your 4 open finding\(s\) by checking which files of each package shipped \(vite 2, lodash 1\)/);
  assert.match(lines.join(' '), /https:\/\/vexproof\.dev\/#pricing \(hide this with --quiet\)$/);
});

test('messages are broken at spaces for a terminal, and left as they are for a pipe or a log', () => {
  const message = 'vexproof: packages/app/vexproof-modules.json: the module map records build output in "build", but V:/work/app/build does not exist. Run vexproof from the folder the build ran in.';

  assert.equal(forTerminal(message, { isTTY: false }), message);
  assert.equal(forTerminal(42, { isTTY: true, columns: 80 }), 42);
  assert.equal(forTerminal('short', { isTTY: true, columns: 80 }), 'short');

  const shown = forTerminal(message, { isTTY: true, columns: 72 }).split('\n');

  assert.ok(shown.length > 1 && shown.every((line) => line.length <= 72), shown.join('\n'));
  assert.ok(shown.slice(1).every((line) => line.startsWith('  ')));
  assert.equal(shown.map((line) => line.trim()).join(' '), message);

  // a wide terminal is not filled edge to edge, and an indented list entry keeps its indent
  assert.ok(forTerminal(message, { isTTY: true, columns: 240 }).split('\n').every((line) => line.length <= 100));
  assert.ok(forTerminal(`  build/sw.js: ${'word '.repeat(30)}`, { isTTY: true, columns: 60 }).split('\n').every((line) => line.startsWith('  ')));
});

test('findings on packages outside the lockfile SBOM are counted apart from the ones to act on', () => {
  const outside = (name, version, id) => finding(name, version, id, { detail: `npm/${name} is not listed in the lockfile SBOM; no claim made.` });
  const results = [
    outside('next', '14.1.4', 'GHSA-a'), outside('next', '14.1.4', 'GHSA-b'), outside('vitest', '3.0.6', 'GHSA-c'),
    finding('katex', '0.16.47', 'GHSA-d', { moduleReason: 'no module rules for katex' }),
  ];

  const lines = summaryLines(results, { summary: summarize(results), written: ['vex.json'] });

  assert.deepEqual(lines, [
    '',
    'Open: 1 finding in 1 package',
    '  katex@0.16.47',
    '    GHSA-d',
    '      the package is in the build, and no file-level rule covers this advisory',
    '',
    'Open, not in the lockfile SBOM (no claim made): 3 findings in 2 packages',
    '  next@14.1.4 (2), vitest@3.0.6',
    '',
    'vexproof: 4 finding(s) → 0 not_affected, 4 in_triage → vex.json',
  ]);
});
