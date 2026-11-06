// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Baselines: carry human triage decisions from the previous release's VEX, and tell new risk from known risk.
import { fingerprintFromProperties, fingerprintChanges } from '../evidence.js';

const keyOf = (id, purl) => `${id}|${purl}`;
const prop = (v, name) => v.properties?.find((p) => p.name === name)?.value;

export function readBaseline(vex) {
  const map = new Map();
  map.reviewed = []; // reviewed decisions, looked up by advisory and package name so they can outlive a version
  for (const v of vex?.vulnerabilities ?? []) {
    const purl = prop(v, 'vexproof:package');
    if (!purl || prop(v, 'vexproof:alias-of')) continue; // alias entries mirror a primary one
    const names = [v.id, ...(v.references ?? []).map((x) => x.id)];
    const rec = {
      purl,
      names,
      state: v.analysis?.state,
      justification: v.analysis?.justification,
      response: v.analysis?.response,
      detail: v.analysis?.detail,
      firstIssued: v.analysis?.firstIssued,
      origin: prop(v, 'vexproof:origin') ?? 'auto',
      reviewedBy: prop(v, 'vexproof:reviewed-by'),
      reviewedAt: prop(v, 'vexproof:reviewed-at') ?? v.analysis?.lastUpdated,
      reviewedPurl: prop(v, 'vexproof:carried-from')?.split(' ')[0] ?? purl, // the version the person actually looked at
      fingerprint: fingerprintFromProperties(v.properties),
    };
    // index under every name, so a switch of scanner (GHSA ↔ CVE) still finds last release's decision
    for (const name of names) if (!map.has(keyOf(name, purl))) map.set(keyOf(name, purl), rec);
    if (rec.origin === 'reviewed') map.reviewed.push(rec);
  }
  return map;
}

// Justifications that rest on things vexproof can't see (configuration, infrastructure). A review giving one
// of these is kept only for the same package version, however the evidence looks.
export const UNVERIFIABLE = ['requires_configuration', 'requires_environment', 'protected_at_perimeter', 'protected_at_runtime', 'protected_by_mitigating_control'];
const pkgName = (purl) => String(purl).replace(/^pkg:npm\//, '').replace(/@[^@/]*$/, '');
const versionOf = (purl) => /@([^@/]+)$/.exec(String(purl))?.[1];
const CARRIED = / \[Carried forward from the review by [^\]]*\]$/;

/**
 * Mutates results:
 *  - keeps each statement's original firstIssued date
 *  - a reviewed decision replaces an automatic in_triage (automatic not_affected evidence always wins) when:
 *      the evidence fingerprints recorded with the review match the current ones (the vulnerable files and
 *      the code importing them are unchanged), whatever the version did; or, where fingerprints are missing
 *      on either side, the package version is the same
 *    and the review is younger than maxAgeDays. Otherwise the finding goes back for review, with the reason.
 *  - isNew = still in_triage and not open or reviewed-and-still-valid in the baseline
 *    (so a package that used to be absent and is now bundled counts as new)
 */
export function applyBaseline(results, baseline, { now = new Date(), maxAgeDays = null } = {}) {
  for (const r of results) {
    const names = [r.id, ...(r.aliases ?? [])];
    const b = names.map((n) => baseline.get(keyOf(n, r.purl))).find(Boolean);
    if (b?.firstIssued) r.firstIssued = b.firstIssued;
    if (r.state === 'in_triage') {
      const candidates = (baseline.reviewed ?? []).filter((x) => pkgName(x.purl) === pkgName(r.purl) && x.names.some((n) => names.includes(n)));
      const rec = candidates.find((x) => x.purl === r.purl) ?? candidates.sort((x, y) => String(y.reviewedAt).localeCompare(String(x.reviewedAt)))[0];
      if (rec) {
        const date = String(rec.reviewedAt ?? '').slice(0, 10);
        const who = `the review by ${rec.reviewedBy ?? 'unknown'} on ${date || 'an unknown date'}`;
        const age = rec.reviewedAt ? (now - new Date(rec.reviewedAt)) / 864e5 : Infinity;
        const samePurl = rec.purl === r.purl;
        let changes = [];
        if (maxAgeDays != null && age > maxAgeDays) changes = [`it is older than ${maxAgeDays} days`];
        else if (rec.fingerprint && r.fingerprint) {
          changes = fingerprintChanges(rec.fingerprint, r.fingerprint);
          if (!changes.length && !samePurl && UNVERIFIABLE.includes(rec.justification)) changes = [`a "${rec.justification}" decision is only kept for the same version (${versionOf(rec.purl)})`];
        } else if (!samePurl) changes = [`it was for ${versionOf(rec.purl)}, and the evidence to carry it forward wasn't recorded`];
        if (!changes.length) {
          const base = String(rec.detail ?? '').replace(CARRIED, '');
          const carried = rec.reviewedPurl !== r.purl;
          Object.assign(r, {
            state: rec.state, justification: rec.justification, response: rec.response, origin: 'reviewed',
            reviewedBy: rec.reviewedBy, reviewedAt: rec.reviewedAt, level: null, proWouldSettle: false,
            detail: carried ? `${base} [Carried forward from the review by ${rec.reviewedBy} on ${date} for ${versionOf(rec.reviewedPurl)}: the vulnerable files and the code importing them are unchanged.]` : base,
            carriedFrom: carried ? { purl: rec.reviewedPurl, reviewedAt: date } : null,
          });
        } else {
          r.reReview = { by: rec.reviewedBy, at: date, changes };
          r.moduleReason = `${who} needs re-confirming: ${changes.join('; ')}`;
          r.detail = `${r.detail} Previously reviewed (${rec.state}${rec.justification ? `, ${rec.justification}` : ''}) by ${rec.reviewedBy} on ${date}; needs re-confirming: ${changes.join('; ')}.`;
        }
      }
    }
    r.isNew = r.state === 'in_triage' && (Boolean(r.reReview) || !(b && (b.state === 'in_triage' || b.origin === 'reviewed')));
  }
  return results;
}
