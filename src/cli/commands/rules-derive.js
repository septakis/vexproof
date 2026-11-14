// SPDX-License-Identifier: MIT
// vexproof rules derive: write module rules from the files each advisory's fix changed, from the npm registry.
import { readModuleMap } from '../../modules.js';
import { normalizeFindings, parsePurl } from '../../index.js';
import { readFindingsText } from '../../sources.js';
import { deriveRules } from '../../derive.js';
import { Stop, EXIT } from '../../stop.js';
import { readJson, readText, log } from '../common.js';
import { writeAll } from '../output.js';

export async function rulesDerive({ options, now }) {
  for (const name of ['lockfile', 'findings']) if (!options[name]) throw new Stop(`missing --${name}`);

  const lockfileSbom = readJson(options.lockfile, 'lockfile SBOM');
  const findings = normalizeFindings(readFindingsText(readText(options.findings, 'findings file'), lockfileSbom).findings);

  // with a module map, derive only for packages that ship: the rest settle at package level
  let shipping = null;
  if (options.modules) shipping = new Set(options.modules.flatMap((file) => [...readModuleMap(readJson(file, 'module map')).packages.keys()]));

  const wanted = findings
    .map((finding) => ({ ...parsePurl(finding.purl), id: finding.id, aliases: finding.aliases }))
    .filter((finding) => finding.type === 'npm' && finding.version && (!shipping || shipping.has(finding.name)));

  log(`vexproof: deriving rules for ${wanted.length} finding(s) from the npm registry…`);
  const { rules, report } = await deriveRules(wanted, { now });

  const out = options.out ?? 'vexproof-rules.derived.json';
  writeAll([{ path: out, text: JSON.stringify(rules, null, 2) }]);

  for (const row of report) {
    const what = row.files ? `${row.files.length} of ${row.runtimeFiles} files changed by ${row.version} → ${row.fixed}` : `no rule: ${row.reason}`;
    console.log(`  ${String(row.id).padEnd(22)} ${`${row.name}@${row.version}`.padEnd(28)} ${what}`);
  }
  console.log(`vexproof: ${report.filter((row) => row.files).length} of ${report.length} rule(s) → ${out}`);

  return EXIT.ok;
}
