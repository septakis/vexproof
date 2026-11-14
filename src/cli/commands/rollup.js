// SPDX-License-Identifier: MIT
// vexproof rollup (Pro): one CycloneDX VEX for an organization, from each application's VEX.
import { VERSION } from '../../index.js';
import { Stop, EXIT } from '../../stop.js';
import { pro, readJson, sha256, log, loadLicense, licensedFor } from '../common.js';
import { writeAll } from '../output.js';

export async function rollup({ options, now }) {
  const files = options.vex ?? [];
  if (!files.length) throw new Stop('rollup needs at least one --vex');

  const license = loadLicense(options.license);
  if (!licensedFor(license, 'rollup')) throw new Stop('vexproof rollup is a Pro feature; nothing written');

  const out = options.out ?? 'vex.rollup.cdx.json';
  let result;
  try {
    const apps = files.map((file) => pro.rollup.readApplication({ file, vex: readJson(file, 'VEX'), sha256: sha256(file) }));
    result = pro.rollup.rollup({ apps, productPurl: options.product, licensee: license.org, version: VERSION, now });
  } catch (error) {
    if (error instanceof Stop) throw error;
    throw new Stop(error.message);
  }
  let { vex } = result;

  let signedBy = null;
  if (options.sign) {
    if (!licensedFor(license, 'signing')) {
      log('vexproof: --sign is a Pro feature not covered by this license; the rollup is unsigned');
    } else {
      let key;
      try {
        key = pro.sign.loadPrivateKey(options.sign);
      } catch (error) {
        throw new Stop(`cannot read --sign key: ${error.message}`);
      }
      vex = pro.sign.signCycloneDx(vex, key, { keyId: options.signer ?? null });
      signedBy = vex.signature.keyId;
    }
  }

  writeAll([{ path: out, text: JSON.stringify(vex, null, 2) }]);

  for (const app of result.summary.applications) {
    const reviewed = app.reviewed ? `, ${app.reviewed} reviewed` : '';
    console.log(`  ${app.purl.padEnd(40)} ${app.statements} statement(s): ${app.not_affected} not_affected, ${app.in_triage} in_triage${reviewed}`);
  }
  console.log(`vexproof: ${result.summary.applications.length} application(s), ${vex.vulnerabilities.length} statement(s) → ${out}${signedBy ? ` (signed by ${signedBy})` : ''}`);
  for (const disagreement of result.summary.disagreements) {
    const where = disagreement.applications.map((entry) => `${entry.purl} ${entry.state}`).join(', ');
    log(`vexproof: ${disagreement.id} on ${disagreement.package} differs between applications: ${where}`);
  }

  return EXIT.ok;
}
