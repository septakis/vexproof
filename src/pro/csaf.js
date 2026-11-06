// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// CSAF 2.0 VEX (profile 5): the document a supplier hands to customers, procurement portals and regulators. It says
// the same as the CycloneDX VEX, organised by advisory: the release is the product, each package with a statement is
// a component of it, and every status names that relationship ("lodash 4.17.21 as a component of my-app 1.4.0").
// Scanners keep OpenVEX and CycloneDX; this is written alongside them, never instead.
import { parsePurl } from '../index.js';

export const CSAF_STATUSES = ['draft', 'interim', 'final'];
export const CSAF_TLP = ['WHITE', 'GREEN', 'AMBER', 'RED'];

// CycloneDX justification → CSAF flag label. Package-level code_not_present means the component is absent.
const FLAG = {
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

// CycloneDX response → CSAF remediation category, for known_affected products.
const REMEDIATION = { update: 'vendor_fix', rollback: 'vendor_fix', workaround_available: 'workaround', will_not_fix: 'no_fix_planned', can_not_fix: 'no_fix_planned' };

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const isCve = (s) => /^CVE-\d{4}-\d{4,}$/i.test(String(s));
const isGhsa = (s) => /^GHSA-/i.test(String(s));

/** Sort object keys recursively (optional test 6.2.13 wants a document whose keys are sorted). */
export function sortKeys(x) {
  if (Array.isArray(x)) return x.map(sortKeys);
  if (x && typeof x === 'object') return Object.fromEntries(Object.keys(x).sort(cmp).map((k) => [k, sortKeys(x[k])]));
  return x;
}

/** A product id that is safe, readable and unique: the purl with everything but [A-Za-z0-9.-] turned into "_". */
const productId = (prefix, purl) => `${prefix}-${String(purl).replace(/^pkg:/, '').replace(/[^A-Za-z0-9.-]+/g, '_')}`;

/** Section 5.1 of the spec: the file name a CSAF document should be published under. */
export function csafFileName(trackingId) {
  return `${String(trackingId).toLowerCase().replace(/[^a-z0-9+-]+/g, '_')}.json`;
}

/** The default tracking id: <PRODUCT>-<VERSION>-VEX, from the product purl. */
export function defaultTrackingId(productPurl) {
  const p = parsePurl(productPurl);
  const name = (p?.name ?? String(productPurl)).replace(/^@/, '').replace(/[^A-Za-z0-9.+-]+/g, '-');
  return `${name}-${p?.version ?? '0'}-VEX`.toUpperCase();
}

/**
 * Group results by advisory. CSAF allows one vulnerability entry per CVE (mandatory test 6.1.23), so results
 * whose ids or aliases share a CVE merge into one entry; the rest are keyed by their own id.
 */
function groupByAdvisory(results) {
  const groups = new Map();
  for (const r of results) {
    const names = [r.id, ...(r.aliases ?? [])];
    const cve = names.find(isCve);
    const key = cve ? cve.toUpperCase() : r.id;
    if (!groups.has(key)) groups.set(key, { key, cve: cve ? cve.toUpperCase() : null, ids: new Set(), results: [] });
    const g = groups.get(key);
    for (const n of names) if (!isCve(n)) g.ids.add(n);
    g.results.push(r);
  }
  return [...groups.values()].sort((a, b) => cmp(a.key, b.key));
}

function idSystem(id) {
  if (isGhsa(id)) return 'GitHub Advisory';
  if (/^SNYK-/i.test(id)) return 'Snyk';
  if (/^MAL-/i.test(id)) return 'OpenSSF Malicious Packages';
  if (/^GO-|^PYSEC-|^RUSTSEC-|^OSV-/i.test(id)) return 'OSV';
  return 'vexproof';
}

/**
 * Build a CSAF 2.0 VEX document.
 *   results      vexproof's triage results (after baseline and reviews)
 *   productPurl  the release
 *   publisher    { name, namespace, category? }   namespace is required by the spec and has no default
 *   trackingId   default <PRODUCT>-<VERSION>-VEX
 *   status       draft | interim | final (default final)
 *   tlp          WHITE | GREEN | AMBER | RED (default WHITE; CSAF 2.0 uses TLP 1.0 names)
 *   url          canonical URL of this document, written as its "self" reference
 *   previous     the previous revision of this document, to carry its history forward and bump the version
 *   licensee     the organization named in the license, used as the default publisher name
 */
export function toCsaf({ results, productPurl, publisher = {}, trackingId, status = 'final', tlp = 'WHITE', url = null, previous = null, licensee = null, version: toolVersion = '0', now = new Date() }) {
  const name = publisher.name ?? licensee;
  if (!name) throw new Error('CSAF needs a publisher name: pass --csaf-publisher (a Pro license supplies one by default)');
  if (!publisher.namespace || !/^https?:\/\//.test(publisher.namespace)) throw new Error('CSAF needs a publisher namespace URL: pass --csaf-namespace https://your-company.example');
  if (!CSAF_STATUSES.includes(status)) throw new Error(`--csaf-status must be one of ${CSAF_STATUSES.join(', ')}`);
  if (!CSAF_TLP.includes(tlp)) throw new Error(`--csaf-tlp must be one of ${CSAF_TLP.join(', ')}`);
  if (status === 'final' && results.length === 0) throw new Error('nothing to say: no findings, so no CSAF document');

  const p = parsePurl(productPurl) ?? { name: String(productPurl), version: null };
  const appId = productId('APP', productPurl);
  const date = now.toISOString();
  trackingId = trackingId ?? defaultTrackingId(productPurl);

  // Tracking: a new document starts at version 1; a revision carries the previous history and bumps it.
  let versionNo = 1;
  let history = [];
  let initial = date;
  if (previous) {
    const t = previous?.document?.tracking;
    if (!t) throw new Error('--csaf-previous is not a CSAF document');
    if (t.id !== trackingId) throw new Error(`--csaf-previous has tracking id ${t.id}, not ${trackingId}; pass --csaf-id to match or drop --csaf-previous`);
    versionNo = Number(t.version) + 1;
    if (!Number.isInteger(versionNo) || versionNo < 2) throw new Error(`--csaf-previous has a non-integer version "${t.version}"`);
    history = (t.revision_history ?? []).map((h) => ({ date: h.date, number: String(h.number), summary: h.summary }));
    initial = t.initial_release_date ?? initial;
  }
  if (status === 'draft' && !previous) versionNo = 0; // mandatory test 6.1.17: a draft is version 0 or a pre-release
  const versionStr = String(versionNo);
  history.push({ date, number: versionStr, summary: previous ? `Revision ${versionStr}: statements regenerated from the ${p.version ?? 'current'} build.` : 'Initial version.' });

  // Product tree: vendor → product name → version, plus every package as a component of the release.
  const pkgs = new Map(); // purl → { pid, relId }
  for (const r of results) if (!pkgs.has(r.purl)) pkgs.set(r.purl, { pid: productId('PKG', r.purl), relId: productId('REL', r.purl) });
  const releaseName = `${p.name}${p.version ? ` ${p.version}` : ''}`;
  const product_tree = {
    branches: [{
      category: 'vendor',
      name,
      branches: [{
        category: 'product_name',
        name: p.name,
        branches: [{ category: 'product_version', name: p.version ?? 'unversioned', product: { name: releaseName, product_id: appId, product_identification_helper: { purl: productPurl } } }],
      }],
    }],
    full_product_names: [...pkgs.entries()].sort(([a], [b]) => cmp(a, b)).map(([purl, { pid }]) => {
      const q = parsePurl(purl);
      return { name: q ? `${q.name}${q.version ? ` ${q.version}` : ''}` : purl, product_id: pid, product_identification_helper: { purl } };
    }),
    relationships: [...pkgs.entries()].sort(([a], [b]) => cmp(a, b)).map(([purl, { pid, relId }]) => {
      const q = parsePurl(purl);
      return {
        category: 'default_component_of',
        product_reference: pid,
        relates_to_product_reference: appId,
        full_product_name: { name: `${q ? `${q.name} ${q.version ?? ''}`.trim() : purl} as a component of ${releaseName}`, product_id: relId, product_identification_helper: { purl } },
      };
    }),
  };

  // One vulnerability entry per advisory, every product it touches listed under one status.
  const vulnerabilities = groupByAdvisory(results).map((g) => {
    const status = { known_not_affected: [], known_affected: [], under_investigation: [], fixed: [] };
    const flags = new Map(); // label → product ids
    const threats = [];
    const remediations = [];
    const notes = new Set();
    for (const r of [...g.results].sort((a, b) => cmp(a.purl, b.purl))) {
      const id = pkgs.get(r.purl).relId;
      switch (r.state) {
        case 'not_affected': {
          status.known_not_affected.push(id);
          const label = FLAG[r.justification]?.(r);
          if (label) { if (!flags.has(label)) flags.set(label, []); flags.get(label).push(id); }
          threats.push({ category: 'impact', date, details: r.detail, product_ids: [id] });
          break;
        }
        case 'false_positive':
          status.known_not_affected.push(id);
          threats.push({ category: 'impact', date, details: `False positive: ${r.detail}`, product_ids: [id] });
          break;
        case 'exploitable':
          status.known_affected.push(id);
          remediations.push({ category: REMEDIATION[r.response] ?? 'none_available', date, details: r.detail || 'Affected; remediation required.', product_ids: [id] });
          break;
        case 'resolved':
        case 'resolved_with_pedigree':
          status.fixed.push(id);
          break;
        default:
          status.under_investigation.push(id);
      }
      notes.add(r.detail);
    }
    const v = {
      ...(g.cve ? { cve: g.cve } : {}),
      ...(g.ids.size ? { ids: [...g.ids].sort(cmp).map((text) => ({ system_name: idSystem(text), text })) } : {}),
      notes: [{ category: 'description', title: 'Statements', text: [...notes].join(' ') }],
      product_status: Object.fromEntries(Object.entries(status).filter(([, ids]) => ids.length)),
      ...(flags.size ? { flags: [...flags.entries()].sort(([a], [b]) => cmp(a, b)).map(([label, product_ids]) => ({ date, label, product_ids })) } : {}),
      ...(threats.length ? { threats } : {}),
      ...(remediations.length ? { remediations } : {}),
    };
    return v;
  });

  const doc = {
    document: {
      category: 'csaf_vex',
      csaf_version: '2.0',
      title: `${releaseName}: vulnerability exploitability (VEX)`,
      lang: 'en',
      publisher: { category: publisher.category ?? 'vendor', name, namespace: publisher.namespace },
      distribution: { tlp: { label: tlp, url: 'https://www.first.org/tlp/v1/' } },
      tracking: {
        id: trackingId,
        status,
        version: versionStr,
        initial_release_date: initial,
        current_release_date: date,
        revision_history: history,
        generator: { date, engine: { name: 'vexproof', version: toolVersion } },
      },
      notes: [{ category: 'summary', title: 'How these statements were made', text: `vexproof compared the packages the lockfile installs with what the production build of ${releaseName} contains. A package or vulnerable file that never reached the build is not affected; everything else is reviewed by a person or left under investigation.` }],
      ...(url ? { references: [{ category: 'self', summary: 'Canonical URL of this document', url }] } : {}),
    },
    product_tree,
    vulnerabilities,
  };
  return sortKeys(doc);
}
