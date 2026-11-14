// SPDX-License-Identifier: MIT
// vexproof review: record a person's decision on one statement of a VEX file, in place.
import { recordReview, sameCause, finishReview } from '../../review.js';
import { Stop, EXIT } from '../../stop.js';
import { readJson, log } from '../common.js';
import { writeAll } from '../output.js';

const property = (statement, name) => statement.properties.find((entry) => entry.name === name)?.value;

export async function review({ options, now }) {
  for (const name of ['vex', 'id', 'state']) if (!options[name]) throw new Stop(`missing --${name}`);

  const file = options.vex;
  const vex = readJson(file, 'VEX');
  const decision = { state: options.state, justification: options.justification, detail: options.detail, by: options.by, now };

  let reviewed;
  let alsoReviewed = [];
  try {
    reviewed = recordReview(vex, { id: options.id, purl: options.package, ...decision });
    alsoReviewed = options['same-cause'] ? sameCause(vex, reviewed) : [];
    for (const other of alsoReviewed) recordReview(vex, { id: other.id, purl: property(other, 'vexproof:package'), ...decision });
  } catch (error) {
    throw new Stop(error.message);
  }

  const { wasSigned } = finishReview(vex, { now });
  writeAll([{ path: file, text: JSON.stringify(vex, null, 2) }]);

  if (wasSigned) log(`vexproof: ${file} was signed. The signature covered the file before this review, so it was removed: sign the reviewed file again before you publish it.`);
  console.log(`vexproof: ${reviewed.id} → ${reviewed.analysis.state} (reviewed by ${options.by}) in ${file}`);
  for (const other of alsoReviewed) console.log(`vexproof: ${other.id} → ${other.analysis.state} (same vulnerable files: ${property(other, 'vexproof:vulnerable-files')})`);

  return EXIT.ok;
}
