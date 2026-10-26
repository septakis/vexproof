// SPDX-License-Identifier: MIT
// OpenVEX v0.2.0 output. Shaped so the matchers inside Trivy and Grype (openvex/go-vex) apply it:
//  - Trivy: product = the app's PURL, subcomponent = the vulnerable package's PURL (applies on every Trivy target)
//  - Grype: on directory and SBOM scans it only tries the package's own PURL as the product, so that form is
//    added when packageProducts is set. Such a file makes claims about packages, so use it only for this app.
import { randomUUID } from 'node:crypto';
import { VERSION } from './index.js';

const stripQualifiers = (purl) => String(purl).split('?')[0].split('#')[0];

const JUSTIFY = {
  code_not_present: (r) => (r.level === 'package' ? 'component_not_present' : 'vulnerable_code_not_present'),
  code_not_reachable: () => 'vulnerable_code_not_in_execute_path',
  requires_configuration: () => 'vulnerable_code_cannot_be_controlled_by_adversary',
  requires_dependency: () => 'vulnerable_code_cannot_be_controlled_by_adversary',
  requires_environment: () => 'vulnerable_code_cannot_be_controlled_by_adversary',
  protected_by_compiler: () => 'inline_mitigations_already_exist',
  protected_at_runtime: () => 'inline_mitigations_already_exist',
  protected_at_perimeter: () => 'inline_mitigations_already_exist',
  protected_by_mitigating_control: () => 'inline_mitigations_already_exist',
};

export function toStatement(r, { productPurl, packageProducts = false }) {
  const sub = [{ '@id': stripQualifiers(r.purl) }];
  const products = [{ '@id': stripQualifiers(productPurl), subcomponents: sub }];
  if (packageProducts) products.push({ '@id': stripQualifiers(r.purl) });
  const s = {
    vulnerability: { name: r.id, ...(r.aliases?.length ? { aliases: r.aliases } : {}) },
    products,
  };
  switch (r.state) {
    case 'not_affected': {
      s.status = 'not_affected';
      const j = JUSTIFY[r.justification]?.(r);
      if (j) s.justification = j;
      s.impact_statement = r.detail;
      break;
    }
    case 'false_positive':
      s.status = 'not_affected';
      s.impact_statement = `False positive: ${r.detail}`;
      break;
    case 'exploitable':
      s.status = 'affected';
      s.action_statement = r.detail || 'Affected; remediation required.';
      break;
    case 'resolved':
    case 'resolved_with_pedigree':
      s.status = 'fixed';
      break;
    default:
      s.status = 'under_investigation';
      if (r.detail) s.status_notes = r.detail;
  }
  return s;
}

export function toOpenVex({ results, productPurl, author = 'vexproof', packageProducts = false, now = new Date() }) {
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `urn:uuid:${randomUUID()}`,
    author,
    role: 'Document Creator',
    timestamp: now.toISOString(),
    version: 1,
    tooling: `vexproof/${VERSION}`,
    statements: results.map((r) => ({ ...toStatement(r, { productPurl, packageProducts }), timestamp: now.toISOString() })),
  };
}
