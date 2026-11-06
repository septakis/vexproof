#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Compares a scanner's report without VEX (--baseline) and with it (--with) against vexproof's CycloneDX VEX
// (--vex): every finding the VEX settles must be gone, and every other finding must still be there.
//   node live-check.mjs --scanner trivy|grype --label "…" --baseline a.json --with b.json --vex vex.cdx.json
// Prints one line (PASS or FAIL, with counts) and the differences on failure. Exit 0 on PASS, 1 on FAIL.
import { readFileSync } from 'node:fs';

const argv = process.argv.slice(2);
const opt = (k) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : undefined; };
const read = (p) => JSON.parse(readFileSync(p, 'utf8'));
const up = (s) => String(s).toUpperCase();

/** Findings as [{ ids: [...], name, version }], one per reported occurrence. */
export function findings(report, scanner) {
  if (scanner === 'trivy') {
    return (report.Results ?? []).flatMap((r) => (r.Vulnerabilities ?? []).map((v) => ({ ids: [v.VulnerabilityID], name: v.PkgName, version: v.InstalledVersion, where: r.Target })));
  }
  if (scanner === 'grype') {
    return (report.matches ?? []).map((m) => ({ ids: [m.vulnerability?.id, ...(m.relatedVulnerabilities ?? []).map((r) => r.id)].filter(Boolean), name: m.artifact?.name, version: m.artifact?.version, where: m.artifact?.locations?.[0]?.path ?? '' }));
  }
  throw new Error(`unknown scanner ${scanner}`);
}

/** pkg@version → ids the VEX settles (not_affected, false_positive) for it. */
export function settled(vex) {
  const out = new Map();
  for (const v of vex.vulnerabilities ?? []) {
    if (!['not_affected', 'false_positive'].includes(v.analysis?.state)) continue;
    const purl = v.properties?.find((p) => p.name === 'vexproof:package')?.value ?? '';
    const m = /^pkg:npm\/(.+)@([^@?#]+)/.exec(decodeURIComponent(purl));
    if (!m) continue;
    const key = `${m[1]}@${m[2]}`;
    if (!out.has(key)) out.set(key, new Set());
    for (const id of [v.id, ...(v.references ?? []).map((r) => r.id)]) out.get(key).add(up(id));
  }
  return out;
}

export function compare({ baseline, withVex, vex }) {
  const ok = settled(vex);
  const key = (f) => `${f.ids[0]} ${f.name}@${f.version}`;
  const isSettled = (f) => f.ids.some((id) => ok.get(`${f.name}@${f.version}`)?.has(up(id)));
  const count = (list) => list.reduce((m, f) => m.set(key(f), (m.get(key(f)) ?? 0) + 1), new Map());
  const before = count(baseline), after = count(withVex);
  const settledKeys = new Set(baseline.filter(isSettled).map(key));
  const stillShown = [...settledKeys].filter((k) => after.get(k));
  const lost = [...before].filter(([k, n]) => !settledKeys.has(k) && (after.get(k) ?? 0) < n).map(([k]) => k);
  const added = [...after].filter(([k, n]) => n > (before.get(k) ?? 0)).map(([k]) => k);
  return {
    total: baseline.length,
    expected: baseline.filter(isSettled).length,
    hidden: baseline.length - withVex.length,
    stillShown, lost, added,
    pass: settledKeys.size > 0 && !stillShown.length && !lost.length && !added.length,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const scanner = opt('scanner');
  const r = compare({ baseline: findings(read(opt('baseline')), scanner), withVex: findings(read(opt('with')), scanner), vex: read(opt('vex')) });
  const label = (opt('label') ?? scanner).padEnd(46);
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${label} ${r.total} findings, ${r.hidden} hidden (${r.expected} settled by the VEX)`);
  if (!r.expected) console.log('      the VEX settles none of this scanner\'s findings, so nothing was checked');
  for (const k of r.stillShown) console.log(`      still shown, though the VEX settles it: ${k}`);
  for (const k of r.lost) console.log(`      hidden, though the VEX does not settle it: ${k}`);
  for (const k of r.added) console.log(`      new with the VEX applied: ${k}`);
  process.exit(r.pass ? 0 : 1);
}
