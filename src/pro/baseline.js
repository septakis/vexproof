// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Baselines: carry human triage decisions from the previous release's VEX, and tell new risk from known risk.
import { fingerprintFromProperties, fingerprintChanges } from '../evidence.js';

const keyOf = (id, purl) => `${id}|${purl}`;
const prop = (vulnerability, name) => vulnerability.properties?.find((property) => property.name === name)?.value;

export function readBaseline(vex) {
  const baseline = new Map();
  baseline.reviewed = []; // reviewed decisions, looked up by advisory and package name so they can outlive a version

  for (const vulnerability of vex?.vulnerabilities ?? []) {
    const purl = prop(vulnerability, 'vexproof:package');
    if (!purl || prop(vulnerability, 'vexproof:alias-of')) continue; // alias entries mirror a primary one

    const names = [vulnerability.id, ...(vulnerability.references ?? []).map((reference) => reference.id)];
    const decision = {
      purl,
      names,
      state: vulnerability.analysis?.state,
      justification: vulnerability.analysis?.justification,
      response: vulnerability.analysis?.response,
      detail: vulnerability.analysis?.detail,
      firstIssued: vulnerability.analysis?.firstIssued,
      origin: prop(vulnerability, 'vexproof:origin') ?? 'auto',
      reviewedBy: prop(vulnerability, 'vexproof:reviewed-by'),
      reviewedAt: prop(vulnerability, 'vexproof:reviewed-at') ?? vulnerability.analysis?.lastUpdated,
      reviewedPurl: prop(vulnerability, 'vexproof:carried-from')?.split(' ')[0] ?? purl, // the version the person actually looked at
      fingerprint: fingerprintFromProperties(vulnerability.properties),
    };

    // index under every name, so a switch of scanner (GHSA ↔ CVE) still finds last release's decision
    for (const name of names) {
      if (!baseline.has(keyOf(name, purl))) baseline.set(keyOf(name, purl), decision);
    }
    if (decision.origin === 'reviewed') baseline.reviewed.push(decision);
  }

  return baseline;
}

// Justifications that rest on things vexproof can't see (configuration, infrastructure). A review giving one
// of these is kept only for the same package version, however the evidence looks.
const UNVERIFIABLE = [
  'requires_configuration',
  'requires_environment',
  'protected_at_perimeter',
  'protected_at_runtime',
  'protected_by_mitigating_control',
];
const packageNameOf = (purl) => String(purl).replace(/^pkg:npm\//, '').replace(/@[^@/]*$/, '');
const versionOf = (purl) => /@([^@/]+)$/.exec(String(purl))?.[1];
const CARRIED = / \[Carried forward from the review by [^\]]*\]$/;
const MILLISECONDS_PER_DAY = 86_400_000;

/**
 * Mutates results:
 *  - keeps each statement's original firstIssued date
 *  - a reviewed decision replaces an automatic in_triage (automatic not_affected evidence always wins) when:
 *      the evidence fingerprints recorded with the review match the current ones (the vulnerable files and
 *      the code importing them are unchanged), whatever the version did; or, where fingerprints or a part of
 *      them are missing on either side and nothing that can be compared changed, the package version is the
 *      same
 *    and the review is younger than maxAgeDays. Otherwise the finding goes back for review, with the reason.
 *    A review whose date can't be read counts as too old.
 *  - isNew = still in_triage and not open or reviewed-and-still-valid in the baseline
 *    (so a package that used to be absent and is now bundled counts as new)
 */
export function applyBaseline(results, baseline, { now = new Date(), maxAgeDays = null } = {}) {
  for (const result of results) {
    const names = [result.id, ...(result.aliases ?? [])];
    const previous = names.map((name) => baseline.get(keyOf(name, result.purl))).find(Boolean);
    if (previous?.firstIssued) result.firstIssued = previous.firstIssued;

    if (result.state === 'in_triage') {
      const candidates = (baseline.reviewed ?? []).filter((candidate) => packageNameOf(candidate.purl) === packageNameOf(result.purl)
        && candidate.names.some((name) => names.includes(name)));
      const decision = candidates.find((candidate) => candidate.purl === result.purl)
        ?? candidates.sort((left, right) => String(right.reviewedAt).localeCompare(String(left.reviewedAt)))[0];

      if (decision) {
        const date = String(decision.reviewedAt ?? '').slice(0, 10);
        // a review that names no one, or no date, says so in every sentence that mentions it
        const reviewer = decision.reviewedBy ?? 'an unnamed reviewer';
        const reviewedOn = date || 'an unknown date';
        const who = `the review by ${reviewer} on ${reviewedOn}`;
        const days = (now - new Date(decision.reviewedAt)) / MILLISECONDS_PER_DAY;
        const age = Number.isFinite(days) ? days : Infinity;
        const samePurl = decision.purl === result.purl;

        let changes = [];
        if (maxAgeDays != null && age > maxAgeDays) {
          changes = [Number.isFinite(days) ? `it is older than ${maxAgeDays} days` : 'its date could not be read'];
        } else if (decision.fingerprint && result.fingerprint) {
          const { changed, incomparable } = fingerprintChanges(decision.fingerprint, result.fingerprint);
          changes = changed;
          // what can't be compared neither confirms nor contradicts the review: then only the version can
          if (!changes.length && incomparable.length && !samePurl) {
            changes = [`it was for ${versionOf(decision.purl)}, and ${incomparable.join(' and ')}`];
          }
          if (!changes.length && !samePurl && UNVERIFIABLE.includes(decision.justification)) {
            changes = [`a "${decision.justification}" decision is only kept for the same version (${versionOf(decision.purl)})`];
          }
        } else if (!samePurl) {
          changes = [`it was for ${versionOf(decision.purl)}, and the evidence to carry it forward wasn't recorded`];
        }

        if (!changes.length) {
          const base = String(decision.detail ?? '').replace(CARRIED, '');
          const carried = decision.reviewedPurl !== result.purl;
          Object.assign(result, {
            state: decision.state,
            justification: decision.justification,
            response: decision.response,
            origin: 'reviewed',
            reviewedBy: decision.reviewedBy,
            reviewedAt: decision.reviewedAt,
            level: null,
            proWouldSettle: false,
            detail: carried
              ? `${base} [Carried forward from the review by ${reviewer} on ${reviewedOn} for ${versionOf(decision.reviewedPurl)}: ` +
                'the vulnerable files and the code importing them are unchanged.]'
              : base,
            carriedFrom: carried ? { purl: decision.reviewedPurl, reviewedAt: date } : null,
          });
        } else {
          result.reReview = { by: decision.reviewedBy, at: date, changes };
          result.moduleReason = `${who} needs re-confirming: ${changes.join('; ')}`;
          const previousVerdict = `${decision.state}${decision.justification ? `, ${decision.justification}` : ''}`;
          result.detail = `${result.detail} Previously reviewed (${previousVerdict}) by ${reviewer} on ${reviewedOn}; ` +
            `needs re-confirming: ${changes.join('; ')}.`;
        }
      }
    }

    result.isNew = result.state === 'in_triage'
      && (Boolean(result.reReview) || !(previous && (previous.state === 'in_triage' || previous.origin === 'reviewed')));
  }

  return results;
}
