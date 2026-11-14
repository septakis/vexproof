// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// CSAF 2.0 VEX (profile 5): the document a supplier hands to customers, procurement portals and regulators. It says
// the same as the CycloneDX VEX, organised by advisory: the release is the product, each package with a statement is
// a component of it, and every status names that relationship ("lodash 4.17.21 as a component of my-app 1.4.0").
// Scanners keep OpenVEX and CycloneDX; this is written alongside them, never instead.
import { createHash } from 'node:crypto';
import { parsePurl } from '../index.js';

const CSAF_STATUSES = ['draft', 'interim', 'final'];
const CSAF_TLP = ['WHITE', 'GREEN', 'AMBER', 'RED'];

// CycloneDX justification → CSAF flag label. Package-level code_not_present means the component is absent.
const FLAG = {
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

// CycloneDX response → CSAF remediation category, for known_affected products.
const REMEDIATION = { update: 'vendor_fix', rollback: 'vendor_fix', workaround_available: 'workaround', will_not_fix: 'no_fix_planned', can_not_fix: 'no_fix_planned' };

const compare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const isCve = (id) => /^CVE-\d{4}-\d{4,}$/i.test(String(id));
const isGhsa = (id) => /^GHSA-/i.test(String(id));

/** Sort object keys recursively (optional test 6.2.13 wants a document whose keys are sorted). */
export function sortKeys(value) {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort(compare).map((key) => [key, sortKeys(value[key])]));
  }

  return value;
}

/**
 * Product ids for purls, readable and unique: the purl with everything but [A-Za-z0-9.-] turned into "_". Two
 * purls that read the same that way (@a/b_c and @a_b/c) would share an id, which test 6.1.2 refuses, so a purl
 * whose readable id is taken gets a short hash of itself added. Map of purl → id; sorted, so ids are stable.
 */
function productIds(prefix, purls) {
  const ids = new Map();
  const taken = new Set();
  for (const purl of [...new Set(purls)].sort(compare)) {
    let id = `${prefix}-${String(purl).replace(/^pkg:/, '').replace(/[^A-Za-z0-9.-]+/g, '_')}`;
    if (taken.has(id)) id = `${id}-${createHash('sha256').update(purl).digest('hex').slice(0, 8)}`;

    taken.add(id);
    ids.set(purl, id);
  }

  return ids;
}

/** Section 5.1 of the spec: the file name a CSAF document should be published under. */
export function csafFileName(trackingId) {
  return `${String(trackingId).toLowerCase().replace(/[^a-z0-9+-]+/g, '_')}.json`;
}

/** The default tracking id: <PRODUCT>-<VERSION>-VEX, from the product purl. */
export function defaultTrackingId(productPurl) {
  const parsed = parsePurl(productPurl);
  const name = (parsed?.name ?? String(productPurl)).replace(/^@/, '').replace(/[^A-Za-z0-9.+-]+/g, '-');

  return `${name}-${parsed?.version ?? '0'}-VEX`.toUpperCase();
}

/**
 * Group results by advisory. CSAF allows one vulnerability entry per CVE (mandatory test 6.1.23), so results
 * whose ids or aliases share a CVE merge into one entry; the rest are keyed by their own id.
 */
function groupByAdvisory(results) {
  const groups = new Map();
  for (const result of results) {
    const names = [result.id, ...(result.aliases ?? [])];
    const cve = names.find(isCve);
    const key = cve ? cve.toUpperCase() : result.id;
    if (!groups.has(key)) groups.set(key, { key, cve: cve ? cve.toUpperCase() : null, ids: new Set(), results: [] });

    const group = groups.get(key);
    for (const name of names) if (!isCve(name)) group.ids.add(name);
    group.results.push(result);
  }

  return [...groups.values()].sort((left, right) => compare(left.key, right.key));
}

function idSystem(id) {
  if (isGhsa(id)) {
    return 'GitHub Advisory';
  }
  if (/^SNYK-/i.test(id)) {
    return 'Snyk';
  }
  if (/^MAL-/i.test(id)) {
    return 'OpenSSF Malicious Packages';
  }
  if (/^GO-|^PYSEC-|^RUSTSEC-|^OSV-/i.test(id)) {
    return 'OSV';
  }

  return 'vexproof';
}

/**
 * The tracking version and revision history of a new document, given the previous revision (or none).
 *
 * CSAF numbers versions with integers here. Test 6.1.17 says a draft must be version 0, and 6.1.18 that a
 * released (interim or final) document's history holds no version 0. So:
 *   - a new draft is version 0; a new released document is version 1
 *   - a draft revised as a draft stays version 0, its one history entry renewed
 *   - a draft released is version 1: its draft history goes, and its release date is the date it is released
 *   - a released document revised is the next version, with its history carried forward
 *   - a released document can't go back to draft
 */
function tracking({ previous, trackingId, status, date }) {
  if (!previous) {
    return { version: status === 'draft' ? 0 : 1, history: [], initial: date };
  }

  const before = previous?.document?.tracking;
  if (!before) {
    throw new Error('--csaf-previous is not a CSAF document');
  }
  if (before.id !== trackingId) {
    throw new Error(`--csaf-previous has tracking id ${before.id}, not ${trackingId}; pass --csaf-id to match or drop --csaf-previous`);
  }

  const previousVersion = Number(before.version);
  if (!Number.isInteger(previousVersion) || previousVersion < 0) {
    throw new Error(`--csaf-previous has version "${before.version}", which is not a whole number`);
  }

  const history = (before.revision_history ?? []).map((entry) => ({ date: entry.date, number: String(entry.number), summary: entry.summary }));
  const wasDraft = previousVersion === 0;
  if (status === 'draft') {
    if (!wasDraft) {
      throw new Error(`--csaf-previous is released (version ${previousVersion}); a released document can't become a draft again`);
    }

    return { version: 0, history: [], initial: before.initial_release_date ?? date };
  }
  if (wasDraft) {
    return { version: 1, history: history.filter((entry) => entry.number !== '0'), initial: date };
  }

  return { version: previousVersion + 1, history, initial: before.initial_release_date ?? date };
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
  const publisherName = publisher.name ?? licensee;
  if (!publisherName) {
    throw new Error('CSAF needs a publisher name: pass --csaf-publisher (a Pro license supplies one by default)');
  }
  if (!publisher.namespace || !/^https?:\/\//.test(publisher.namespace)) {
    throw new Error('CSAF needs a publisher namespace URL: pass --csaf-namespace https://your-company.example');
  }
  if (!CSAF_STATUSES.includes(status)) {
    throw new Error(`--csaf-status must be one of ${CSAF_STATUSES.join(', ')}`);
  }
  if (!CSAF_TLP.includes(tlp)) {
    throw new Error(`--csaf-tlp must be one of ${CSAF_TLP.join(', ')}`);
  }

  // a document with no vulnerability and no product fails the schema, whatever its status
  if (results.length === 0) {
    throw new Error('nothing to say: no findings, so no CSAF document');
  }

  const product = parsePurl(productPurl) ?? { name: String(productPurl), version: null };
  const appId = productIds('APP', [productPurl]).get(productPurl);
  const date = now.toISOString();
  const id = trackingId ?? defaultTrackingId(productPurl);

  const revision = tracking({ previous, trackingId: id, status, date });
  const versionText = String(revision.version);
  const summary = previous ? `Revision ${versionText}: statements regenerated from the ${product.version ?? 'current'} build.` : 'Initial version.';
  const history = [...revision.history, { date, number: versionText, summary }];

  // Product tree: vendor → product name → version, plus every package as a component of the release.
  const purls = [...new Set(results.map((result) => result.purl))].sort(compare);
  const packageIds = productIds('PKG', purls);
  const relationshipIds = productIds('REL', purls);
  const releaseName = `${product.name}${product.version ? ` ${product.version}` : ''}`;
  const componentName = (purl) => {
    const parsed = parsePurl(purl);

    return parsed ? `${parsed.name}${parsed.version ? ` ${parsed.version}` : ''}` : purl;
  };
  const product_tree = {
    branches: [{
      category: 'vendor',
      name: publisherName,
      branches: [{
        category: 'product_name',
        name: product.name,
        branches: [{ category: 'product_version', name: product.version ?? 'unversioned', product: { name: releaseName, product_id: appId, product_identification_helper: { purl: productPurl } } }],
      }],
    }],
    full_product_names: purls.map((purl) => ({ name: componentName(purl), product_id: packageIds.get(purl), product_identification_helper: { purl } })),
    relationships: purls.map((purl) => ({
      category: 'default_component_of',
      product_reference: packageIds.get(purl),
      relates_to_product_reference: appId,
      full_product_name: { name: `${componentName(purl)} as a component of ${releaseName}`, product_id: relationshipIds.get(purl), product_identification_helper: { purl } },
    })),
  };

  // One vulnerability entry per advisory, every product it touches listed once under one status.
  const vulnerabilities = groupByAdvisory(results).map((group) => {
    const statuses = { known_not_affected: new Set(), known_affected: new Set(), under_investigation: new Set(), fixed: new Set() };
    const flags = new Map(); // label → product ids
    const threats = [];
    const remediations = [];
    const notes = new Set();

    for (const result of [...group.results].sort((left, right) => compare(left.purl, right.purl))) {
      const productId = relationshipIds.get(result.purl);
      switch (result.state) {
        case 'not_affected': {
          statuses.known_not_affected.add(productId);
          const label = FLAG[result.justification]?.(result);
          if (label) {
            if (!flags.has(label)) flags.set(label, new Set());
            flags.get(label).add(productId);
          }
          threats.push({ category: 'impact', date, details: result.detail, product_ids: [productId] });
          break;
        }
        case 'false_positive':
          statuses.known_not_affected.add(productId);
          threats.push({ category: 'impact', date, details: `False positive: ${result.detail}`, product_ids: [productId] });
          break;
        case 'exploitable':
          statuses.known_affected.add(productId);
          remediations.push({ category: REMEDIATION[result.response] ?? 'none_available', date, details: result.detail || 'Affected; remediation required.', product_ids: [productId] });
          break;
        case 'resolved':
        case 'resolved_with_pedigree':
          statuses.fixed.add(productId);
          break;
        default:
          statuses.under_investigation.add(productId);
      }
      notes.add(result.detail);
    }

    const productStatus = Object.fromEntries(Object.entries(statuses).filter(([, ids]) => ids.size).map(([name, ids]) => [name, [...ids]]));
    const flagList = [...flags.entries()].sort(([left], [right]) => compare(left, right)).map(([label, ids]) => ({ date, label, product_ids: [...ids] }));

    return {
      ...(group.cve ? { cve: group.cve } : {}),
      ...(group.ids.size ? { ids: [...group.ids].sort(compare).map((text) => ({ system_name: idSystem(text), text })) } : {}),
      notes: [{ category: 'description', title: 'Statements', text: [...notes].join(' ') }],
      product_status: productStatus,
      ...(flagList.length ? { flags: flagList } : {}),
      ...(threats.length ? { threats } : {}),
      ...(remediations.length ? { remediations } : {}),
    };
  });

  const document = {
    document: {
      category: 'csaf_vex',
      csaf_version: '2.0',
      title: `${releaseName}: vulnerability exploitability (VEX)`,
      lang: 'en',
      publisher: { category: publisher.category ?? 'vendor', name: publisherName, namespace: publisher.namespace },
      distribution: { tlp: { label: tlp, url: 'https://www.first.org/tlp/v1/' } },
      tracking: {
        id,
        status,
        version: versionText,
        initial_release_date: revision.initial,
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

  return sortKeys(document);
}
