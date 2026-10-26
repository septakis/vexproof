// SPDX-License-Identifier: MIT
// Reviews: record a human decision in a VEX file, and find open findings that share its cause.

const prop = (v, name) => v.properties?.find((p) => p.name === name)?.value;

export const STATES = ['resolved', 'resolved_with_pedigree', 'exploitable', 'in_triage', 'false_positive', 'not_affected'];
export const JUSTIFICATIONS = ['code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency', 'requires_environment', 'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter', 'protected_by_mitigating_control'];

export function recordReview(vex, { id, purl, state, justification, detail, by, now = new Date() }) {
  if (!STATES.includes(state)) throw new Error(`state must be one of: ${STATES.join(', ')}`);
  if (state === 'not_affected' && !JUSTIFICATIONS.includes(justification)) throw new Error(`not_affected needs --justification, one of: ${JUSTIFICATIONS.join(', ')}`);
  if (justification && !JUSTIFICATIONS.includes(justification)) throw new Error(`unknown justification "${justification}"`);
  if (!by || !detail) throw new Error('a review needs --by and --detail');
  const matches = (vex.vulnerabilities ?? []).filter((v) => !prop(v, 'vexproof:alias-of') && (v.id === id || (v.references ?? []).some((x) => x.id === id)) && (!purl || prop(v, 'vexproof:package') === purl));
  if (matches.length === 0) throw new Error(`no statement for ${id}${purl ? ' on ' + purl : ''}`);
  if (matches.length > 1) throw new Error(`${id} appears on ${matches.length} packages; pass --package to pick one`);
  const v = matches[0];
  v.analysis = { ...v.analysis, state, detail, lastUpdated: now.toISOString() };
  if (justification) v.analysis.justification = justification; else delete v.analysis.justification;
  const setProp = (name, value) => {
    v.properties = (v.properties ?? []).filter((p) => p.name !== name);
    v.properties.push({ name, value });
  };
  setProp('vexproof:origin', 'reviewed');
  setProp('vexproof:reviewed-by', by);
  setProp('vexproof:reviewed-at', now.toISOString());
  v.properties = v.properties.filter((p) => !['vexproof:level', 'vexproof:rule-source', 'vexproof:surviving-files', 'vexproof:carried-from'].includes(p.name));
  // alias entries mirror the primary statement
  for (const a of vex.vulnerabilities ?? []) if (prop(a, 'vexproof:alias-of') === v.id && prop(a, 'vexproof:package') === prop(v, 'vexproof:package')) {
    a.analysis = { ...v.analysis };
    a.properties = [...v.properties.filter((p) => p.name !== 'vexproof:alias-of'), { name: 'vexproof:alias-of', value: v.id }];
  }
  return v;
}

/**
 * Open statements on the same package whose vulnerable files overlap the reviewed one's: the same code, so the
 * same decision usually applies (lodash's GHSA-xxjr-mmjv-4gpg and GHSA-f23m-r3pf-42rh are both _baseUnset.js).
 */
export function sameCause(vex, v) {
  const files = prop(v, 'vexproof:vulnerable-files')?.split(' ');
  if (!files?.length) return [];
  return (vex.vulnerabilities ?? []).filter((o) => o !== v && !prop(o, 'vexproof:alias-of') && o.analysis?.state === 'in_triage'
    && prop(o, 'vexproof:package') === prop(v, 'vexproof:package')
    && (prop(o, 'vexproof:vulnerable-files')?.split(' ') ?? []).some((f) => files.includes(f)));
}
