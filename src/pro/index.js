// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// vexproof Pro: everything in this directory. The MIT part of vexproof (src/cli.js) loads this one file, and
// runs without it.
import { readFileSync } from 'node:fs';

export { verifyLicense, loadLicenseToken, PRO_FEATURES } from './license.js';
export { evaluateModuleRule, mergeRules, validateRules } from './module-check.js';
export { readBaseline, applyBaseline } from './baseline.js';
export { renderReport } from './report.js';
export * as dependabot from './dependabot.js';
export * as csaf from './csaf.js';
export * as sign from './sign.js';
export * as rollup from './rollup.js';

/** The hand-checked module rules that ship with vexproof. */
export const loadRules = () => JSON.parse(readFileSync(new URL('./rules/module-rules.json', import.meta.url), 'utf8'));
