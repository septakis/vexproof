// SPDX-License-Identifier: MIT
// Reviews: record a human decision in a VEX file, and find open findings that share its cause.
import { contentUuid } from './index.js';
import { vulnerableFilesFrom } from './evidence.js';

const property = (statement, name) => statement.properties?.find((entry) => entry.name === name)?.value;

const STATES = ['resolved', 'resolved_with_pedigree', 'exploitable', 'in_triage', 'false_positive', 'not_affected'];
const JUSTIFICATIONS = ['code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency', 'requires_environment', 'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter', 'protected_by_mitigating_control'];

// What an automatic verdict recorded about how it was reached. A person's decision replaces it, so these go.
const AUTOMATIC_EVIDENCE = ['vexproof:level', 'vexproof:rule-source', 'vexproof:rule-origin', 'vexproof:surviving-files', 'vexproof:carried-from'];

/** The statements a review of `id` (optionally on package `purl`) applies to: primary statements, not alias entries. */
function statementsFor(vex, id, purl) {
  return (vex.vulnerabilities ?? []).filter((statement) => {
    if (property(statement, 'vexproof:alias-of')) {
      return false;
    }

    const named = statement.id === id || (statement.references ?? []).some((reference) => reference.id === id);

    return named && (!purl || property(statement, 'vexproof:package') === purl);
  });
}

/**
 * Record a decision on the statement for `id` in `vex`, in place, and return that statement. Its alias entries
 * (the same advisory under its other ids) follow it. Throws on a state, justification or statement that can't be.
 */
export function recordReview(vex, { id, purl, state, justification, detail, by, now = new Date() }) {
  if (!STATES.includes(state)) {
    throw new Error(`state must be one of: ${STATES.join(', ')}`);
  }
  if (state === 'not_affected' && !JUSTIFICATIONS.includes(justification)) {
    throw new Error(`not_affected needs --justification, one of: ${JUSTIFICATIONS.join(', ')}`);
  }
  if (justification && !JUSTIFICATIONS.includes(justification)) {
    throw new Error(`unknown justification "${justification}"`);
  }
  if (!by || !detail) {
    throw new Error('a review needs --by and --detail');
  }

  const matches = statementsFor(vex, id, purl);
  if (matches.length === 0) {
    throw new Error(`no statement for ${id}${purl ? ` on ${purl}` : ''}`);
  }
  if (matches.length > 1) {
    throw new Error(`${id} appears on ${matches.length} packages; pass --package to pick one`);
  }

  const statement = matches[0];
  statement.analysis = { ...statement.analysis, state, detail, lastUpdated: now.toISOString() };
  if (justification) {
    statement.analysis.justification = justification;
  } else {
    delete statement.analysis.justification;
  }

  const setProperty = (name, value) => {
    statement.properties = (statement.properties ?? []).filter((entry) => entry.name !== name);
    statement.properties.push({ name, value });
  };
  setProperty('vexproof:origin', 'reviewed');
  setProperty('vexproof:reviewed-by', by);
  setProperty('vexproof:reviewed-at', now.toISOString());
  statement.properties = statement.properties.filter((entry) => !AUTOMATIC_EVIDENCE.includes(entry.name));

  // alias entries mirror the primary statement
  const reviewedPackage = property(statement, 'vexproof:package');
  for (const alias of vex.vulnerabilities ?? []) {
    if (property(alias, 'vexproof:alias-of') !== statement.id || property(alias, 'vexproof:package') !== reviewedPackage) {
      continue;
    }

    alias.analysis = { ...statement.analysis };
    const sharedProperties = statement.properties.filter((entry) => entry.name !== 'vexproof:alias-of');
    alias.properties = [...sharedProperties, { name: 'vexproof:alias-of', value: statement.id }];
  }

  return statement;
}

/**
 * After the reviews are recorded, make the document true to its new content: its timestamp is now, its serial
 * number is derived from its content again (as vexproof writes it), and a signature, which covered the content
 * before the review, is removed. Returns { wasSigned }, so the caller can say the file must be signed again.
 */
export function finishReview(vex, { now = new Date() } = {}) {
  const wasSigned = Boolean(vex.signature);
  delete vex.signature;

  if (vex.metadata) {
    vex.metadata.timestamp = now.toISOString();
  }
  if ('serialNumber' in vex) {
    vex.serialNumber = null;
    vex.serialNumber = `urn:uuid:${contentUuid(vex)}`;
  }

  return { wasSigned };
}

/**
 * Open statements on the same package whose vulnerable files overlap the reviewed one's: the same code, so the
 * same decision usually applies (lodash's GHSA-xxjr-mmjv-4gpg and GHSA-f23m-r3pf-42rh are both _baseUnset.js).
 */
export function sameCause(vex, reviewed) {
  const files = vulnerableFilesFrom(property(reviewed, 'vexproof:vulnerable-files'));
  if (!files?.length) {
    return [];
  }

  const reviewedPackage = property(reviewed, 'vexproof:package');

  return (vex.vulnerabilities ?? []).filter((other) => {
    if (other === reviewed || property(other, 'vexproof:alias-of') || other.analysis?.state !== 'in_triage') {
      return false;
    }
    if (property(other, 'vexproof:package') !== reviewedPackage) {
      return false;
    }

    const otherFiles = vulnerableFilesFrom(property(other, 'vexproof:vulnerable-files')) ?? [];

    return otherFiles.some((file) => files.includes(file));
  });
}
