// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Rollup: one CycloneDX VEX for an organization, from the VEX files of each of its applications. Every statement
// keeps its evidence and names the application it is about, so a customer or auditor asks one question of one
// document: "across everything you ship, where does this advisory stand?"
import { contentUuid, vulnerabilitySource } from '../index.js';

const compare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const property = (statement, name) => statement.properties?.find((entry) => entry.name === name)?.value;
const SETTLED = new Set(['not_affected', 'false_positive', 'resolved', 'resolved_with_pedigree']);

/** Reads one application's VEX. Throws on anything that is not a vexproof CycloneDX VEX. */
export function readApplication({ file, vex, sha256 }) {
  if (vex?.bomFormat !== 'CycloneDX' || !Array.isArray(vex.vulnerabilities)) {
    throw new Error(`${file}: not a CycloneDX VEX`);
  }

  const purl = vex.metadata?.component?.purl ?? vex.metadata?.component?.['bom-ref'];
  if (!purl) {
    throw new Error(`${file}: the VEX names no product (metadata.component); it was not written by vexproof`);
  }
  if (!vex.vulnerabilities.every((statement) => property(statement, 'vexproof:package'))) {
    throw new Error(`${file}: statements lack vexproof:package properties; only vexproof's own VEX can be rolled up`);
  }

  return { file, purl, name: vex.metadata.component.name ?? purl, vex, sha256 };
}

/**
 * Groups of one advisory on one package across applications. Applications may name an advisory differently (one
 * scanned with GHSA ids, another with CVE ids); a statement lists its other names as references, so statements
 * whose names overlap are one advisory. Returns { add(pkg, names, application, state), groups() }.
 */
function advisoryGroups() {
  const byPackage = new Map(); // package purl → [{ names: Set, states: Map<application, state> }]

  const add = (pkg, names, application, state) => {
    const groups = byPackage.get(pkg) ?? [];
    byPackage.set(pkg, groups);

    // every group that shares a name with this statement is the same advisory: merge them into one
    const matching = groups.filter((group) => names.some((name) => group.names.has(name)));
    const into = matching[0] ?? { names: new Set(), states: new Map() };
    for (const other of matching.slice(1)) {
      for (const name of other.names) into.names.add(name);
      for (const [app, otherState] of other.states) into.states.set(app, otherState);
      groups.splice(groups.indexOf(other), 1);
    }
    if (!matching.length) groups.push(into);

    for (const name of names) into.names.add(name);
    into.states.set(application, state);
  };

  const groups = () => [...byPackage].flatMap(([pkg, list]) => list.map((group) => ({ pkg, ...group })));

  return { add, groups };
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
  if (!productPurl) {
    throw new Error('a rollup needs --product: the purl of the product the rollup speaks for');
  }

  const sorted = [...apps].sort((left, right) => compare(left.purl, right.purl));
  const seen = new Set();
  for (const app of sorted) {
    if (seen.has(app.purl)) {
      throw new Error(`two VEX files describe ${app.purl}; a rollup takes one per application version`);
    }

    seen.add(app.purl);
  }

  const components = sorted.map((app) => ({
    type: 'application', 'bom-ref': app.purl, purl: app.purl, name: app.name,
    ...(app.vex.metadata?.component?.version ? { version: app.vex.metadata.component.version } : {}),
  }));
  const vulnerabilities = [];
  const advisories = advisoryGroups();
  const summary = { applications: [], disagreements: [] };

  for (const app of sorted) {
    const counts = { statements: 0, not_affected: 0, in_triage: 0, reviewed: 0 };

    for (const statement of app.vex.vulnerabilities) {
      const pkg = property(statement, 'vexproof:package');
      const state = statement.analysis?.state;
      if (!property(statement, 'vexproof:alias-of')) {
        counts.statements++;
        if (state === 'not_affected') counts.not_affected++;
        if (state === 'in_triage') counts.in_triage++;
        if (property(statement, 'vexproof:origin') === 'reviewed') counts.reviewed++;

        const names = [statement.id, ...(statement.references ?? []).map((reference) => reference.id)].filter(Boolean);
        advisories.add(pkg, names, app.purl, state);
      }

      const source = statement.source ?? vulnerabilitySource(statement.id);
      vulnerabilities.push({
        id: statement.id,
        ...(source ? { source } : {}),
        ...(statement.references ? { references: statement.references } : {}),
        analysis: statement.analysis,
        affects: [{ ref: app.purl }],
        properties: [...(statement.properties ?? []), { name: 'vexproof:application', value: app.purl }],
      });
    }

    summary.applications.push({ purl: app.purl, file: app.file, ...counts });
  }

  for (const group of advisories.groups()) {
    const verdicts = new Set([...group.states.values()].map((state) => (SETTLED.has(state) ? 'settled' : 'open')));
    if (verdicts.size < 2) {
      continue;
    }

    // named by its GHSA id where it has one, as most of vexproof's input does
    const names = [...group.names].sort(compare);
    const id = names.find((name) => /^GHSA-/i.test(name)) ?? names[0];
    summary.disagreements.push({ id, package: group.pkg, applications: [...group.states.entries()].map(([purl, state]) => ({ purl, state })) });
  }
  summary.disagreements.sort((left, right) => compare(left.id, right.id) || compare(left.package, right.package));

  // Settled first, open last (the same rule as a single VEX, for the same consumers), then by advisory,
  // package and application, primary statements before their alias entries.
  const sortKey = (statement) => [
    SETTLED.has(statement.analysis?.state) ? 0 : 1,
    property(statement, 'vexproof:alias-of') || statement.id,
    property(statement, 'vexproof:package'),
    property(statement, 'vexproof:application'),
    property(statement, 'vexproof:alias-of') ? 1 : 0,
    statement.id,
  ];
  vulnerabilities.sort((left, right) => {
    const leftKey = sortKey(left), rightKey = sortKey(right);
    for (let position = 0; position < leftKey.length; position++) {
      const order = compare(leftKey[position], rightKey[position]);
      if (order) {
        return order;
      }
    }

    return 0;
  });

  const properties = [
    { name: 'vexproof:rollup', value: String(sorted.length) },
    ...sorted.map((app) => ({ name: `vexproof:input:rollup:${app.purl}:sha256`, value: app.sha256 })),
  ];
  if (licensee) properties.push({ name: 'vexproof:licensee', value: licensee });

  const vex = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: null,
    version: 1,
    metadata: {
      timestamp: now.toISOString(),
      tools: { components: [{ type: 'application', name: 'vexproof', version }] },
      component: { type: 'application', 'bom-ref': productPurl, purl: productPurl, name: productPurl },
      properties,
    },
    components,
    vulnerabilities,
  };
  vex.serialNumber = `urn:uuid:${contentUuid(vex)}`;

  return { vex, summary };
}
