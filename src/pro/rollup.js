// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Rollup: one CycloneDX VEX for an organization, from the VEX files of each of its applications. Every statement
// keeps its evidence and names the application it is about, so a customer or auditor asks one question of one
// document: "across everything you ship, where does this advisory stand?"
import { contentUuid, vulnerabilitySource } from '../index.js';

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const prop = (v, name) => v.properties?.find((p) => p.name === name)?.value;
const SETTLED = new Set(['not_affected', 'false_positive', 'resolved', 'resolved_with_pedigree']);

/** Reads one application's VEX. Throws on anything that is not a vexproof CycloneDX VEX. */
export function readApplication({ file, vex, sha256 }) {
  if (vex?.bomFormat !== 'CycloneDX' || !Array.isArray(vex.vulnerabilities)) throw new Error(`${file}: not a CycloneDX VEX`);
  const purl = vex.metadata?.component?.purl ?? vex.metadata?.component?.['bom-ref'];
  if (!purl) throw new Error(`${file}: the VEX names no product (metadata.component); it was not written by vexproof`);
  if (!vex.vulnerabilities.every((v) => prop(v, 'vexproof:package'))) throw new Error(`${file}: statements lack vexproof:package properties; only vexproof's own VEX can be rolled up`);
  return { file, purl, name: vex.metadata.component.name ?? purl, vex, sha256, timestamp: vex.metadata?.timestamp ?? null, licensee: vex.metadata?.properties?.find((p) => p.name === 'vexproof:licensee')?.value ?? null };
}

/**
 * Build the rollup.
 *   apps         from readApplication, one per application
 *   productPurl  the organization-level product the rollup speaks for (required: there is no sensible default)
 *   licensee     the organization in the license
 * Returns { vex, summary }, where summary lists each application's counts and the advisories whose verdicts
 * differ between applications on the same package version.
 */
export function rollup({ apps, productPurl, licensee = null, version = '0', now = new Date() }) {
  if (!productPurl) throw new Error('a rollup needs --product: the purl of the product the rollup speaks for');
  const sorted = [...apps].sort((a, b) => cmp(a.purl, b.purl));
  const seen = new Set();
  for (const a of sorted) {
    if (seen.has(a.purl)) throw new Error(`two VEX files describe ${a.purl}; a rollup takes one per application version`);
    seen.add(a.purl);
  }

  const components = sorted.map((a) => ({ type: 'application', 'bom-ref': a.purl, purl: a.purl, name: a.name, ...(a.vex.metadata?.component?.version ? { version: a.vex.metadata.component.version } : {}) }));
  const vulnerabilities = [];
  const byVerdict = new Map(); // `${id}|${package purl}` → Set of states, to spot disagreements between apps
  const summary = { applications: [], disagreements: [] };

  for (const a of sorted) {
    const counts = { statements: 0, not_affected: 0, in_triage: 0, reviewed: 0 };
    for (const v of a.vex.vulnerabilities) {
      const pkg = prop(v, 'vexproof:package');
      const alias = prop(v, 'vexproof:alias-of');
      const state = v.analysis?.state;
      if (!alias) {
        counts.statements++;
        if (state === 'not_affected') counts.not_affected++;
        if (state === 'in_triage') counts.in_triage++;
        if (prop(v, 'vexproof:origin') === 'reviewed') counts.reviewed++;
        const k = `${v.id}|${pkg}`;
        if (!byVerdict.has(k)) byVerdict.set(k, new Map());
        byVerdict.get(k).set(a.purl, state);
      }
      vulnerabilities.push({
        id: v.id,
        ...(v.source ? { source: v.source } : vulnerabilitySource(v.id) ? { source: vulnerabilitySource(v.id) } : {}),
        ...(v.references ? { references: v.references } : {}),
        analysis: v.analysis,
        affects: [{ ref: a.purl }],
        properties: [...(v.properties ?? []), { name: 'vexproof:application', value: a.purl }],
      });
    }
    summary.applications.push({ purl: a.purl, file: a.file, ...counts });
  }

  for (const [k, states] of byVerdict) {
    const distinct = new Set([...states.values()].map((s) => (SETTLED.has(s) ? 'settled' : 'open')));
    if (distinct.size > 1) {
      const [id, pkg] = k.split('|');
      summary.disagreements.push({ id, package: pkg, applications: [...states.entries()].map(([purl, state]) => ({ purl, state })) });
    }
  }
  summary.disagreements.sort((a, b) => cmp(a.id, b.id) || cmp(a.package, b.package));

  // Settled first, open last (the same rule as a single VEX, for the same consumers), then by advisory,
  // package and application.
  const rank = (v) => (SETTLED.has(v.analysis?.state) ? 0 : 1);
  const primary = (v) => prop(v, 'vexproof:alias-of') || v.id;
  vulnerabilities.sort((a, b) => rank(a) - rank(b) || cmp(primary(a), primary(b)) || cmp(prop(a, 'vexproof:package'), prop(b, 'vexproof:package')) || cmp(prop(a, 'vexproof:application'), prop(b, 'vexproof:application')) || cmp(Boolean(prop(a, 'vexproof:alias-of')), Boolean(prop(b, 'vexproof:alias-of'))) || cmp(a.id, b.id));

  const props = [
    { name: 'vexproof:rollup', value: String(sorted.length) },
    ...sorted.map((a) => ({ name: `vexproof:input:rollup:${a.purl}:sha256`, value: a.sha256 })),
  ];
  if (licensee) props.push({ name: 'vexproof:licensee', value: licensee });

  const vex = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: null,
    version: 1,
    metadata: {
      timestamp: now.toISOString(),
      tools: { components: [{ type: 'application', name: 'vexproof', version }] },
      component: { type: 'application', 'bom-ref': productPurl, purl: productPurl, name: productPurl },
      properties: props,
    },
    components,
    vulnerabilities,
  };
  vex.serialNumber = `urn:uuid:${contentUuid(vex)}`;
  return { vex, summary };
}
