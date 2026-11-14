// SPDX-License-Identifier: MIT
// OpenVEX v0.2.0 output. Shaped so the matchers inside Trivy and Grype (openvex/go-vex) apply it:
//  - Trivy: product = the app's PURL, subcomponent = the vulnerable package's PURL (applies on every Trivy target)
//  - Grype: on directory and SBOM scans it only tries the package's own PURL as the product, so that form is
//    added when packageProducts is set. Such a file makes claims about packages, so use it only for this app.
import { VERSION, contentUuid } from './index.js';

const stripQualifiers = (purl) => String(purl).split('?')[0].split('#')[0];

const JUSTIFY = {
  code_not_present: (result) => (result.level === 'package' ? 'component_not_present' : 'vulnerable_code_not_present'),
  code_not_reachable: () => 'vulnerable_code_not_in_execute_path',
  requires_configuration: () => 'vulnerable_code_cannot_be_controlled_by_adversary',
  requires_dependency: () => 'vulnerable_code_cannot_be_controlled_by_adversary',
  requires_environment: () => 'vulnerable_code_cannot_be_controlled_by_adversary',
  protected_by_compiler: () => 'inline_mitigations_already_exist',
  protected_at_runtime: () => 'inline_mitigations_already_exist',
  protected_at_perimeter: () => 'inline_mitigations_already_exist',
  protected_by_mitigating_control: () => 'inline_mitigations_already_exist',
};

/** The OpenVEX statement for one triage result. */
export function toStatement(result, { productPurl, packageProducts = false }) {
  const subcomponents = [{ '@id': stripQualifiers(result.purl) }];
  const products = [{ '@id': stripQualifiers(productPurl), subcomponents }];
  if (packageProducts) products.push({ '@id': stripQualifiers(result.purl) });

  const statement = {
    vulnerability: { name: result.id, ...(result.aliases?.length ? { aliases: result.aliases } : {}) },
    products,
  };

  switch (result.state) {
    case 'not_affected': {
      statement.status = 'not_affected';
      const justification = JUSTIFY[result.justification]?.(result);
      if (justification) statement.justification = justification;
      statement.impact_statement = result.detail;
      break;
    }
    case 'false_positive':
      statement.status = 'not_affected';
      statement.impact_statement = `False positive: ${result.detail}`;
      break;
    case 'exploitable':
      statement.status = 'affected';
      statement.action_statement = result.detail || 'Affected; remediation required.';
      break;
    case 'resolved':
    case 'resolved_with_pedigree':
      statement.status = 'fixed';
      break;
    default:
      statement.status = 'under_investigation';
      if (result.detail) statement.status_notes = result.detail;
  }

  return statement;
}

const SETTLED = new Set(['not_affected', 'fixed']);
const compare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

const compareKeys = (leftKeys, rightKeys) => {
  for (let position = 0; position < leftKeys.length; position++) {
    const order = compare(leftKeys[position], rightKeys[position]);
    if (order !== 0) {
      return order;
    }
  }

  return 0;
};

/** The OpenVEX document for a set of triage results. */
export function toOpenVex({ results, productPurl, author = 'vexproof', packageProducts = false, now = new Date() }) {
  // Settled statements first and open ones last, as in the CycloneDX file; then by advisory and package,
  // so the same input always writes the same file.
  const rank = (statement) => (SETTLED.has(statement.status) ? 0 : 1);
  const sortKey = (statement) => [rank(statement), statement.vulnerability.name, statement.products[0].subcomponents[0]['@id']];
  const statements = results
    .map((result) => ({ ...toStatement(result, { productPurl, packageProducts }), timestamp: now.toISOString() }))
    .sort((left, right) => compareKeys(sortKey(left), sortKey(right)));

  const doc = {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': null,
    author,
    role: 'Document Creator',
    timestamp: now.toISOString(),
    version: 1,
    tooling: `vexproof/${VERSION}`,
    statements,
  };
  doc['@id'] = `urn:uuid:${contentUuid(doc)}`;

  return doc;
}
