// SPDX-License-Identifier: MIT
// What every command shares: reading inputs, the license, and vexproof Pro when this copy has it.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Stop } from '../stop.js';

// vexproof Pro lives in src/pro/ under its own license (src/pro/LICENSE.md); everything else is MIT. This is the
// one place MIT code reaches it, and a copy without that directory runs the MIT features only.
export const pro = await import('../pro/index.js').catch((error) => {
  if (error?.code === 'ERR_MODULE_NOT_FOUND') {
    return null;
  }

  throw error;
});

export const NO_PRO = 'this copy of vexproof has no Pro files (src/pro/)';

/** Diagnostics, warnings and hints go to standard error; the summary goes to standard output. */
export const log = (...lines) => console.error(...lines);

/** A JSON input, read; a file that can't be read or parsed stops the run, naming the file and what it is. */
export function readJson(path, what = 'input') {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    throw new Stop(`can't read the ${what} ${path}: ${error.code === 'ENOENT' ? 'no such file' : error.message}`);
  }
  try {
    return JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch (error) {
    throw new Stop(`the ${what} ${path} is not valid JSON: ${error.message}`);
  }
}

/** A file's text; one that can't be read stops the run, naming the file. */
export function readText(path, what = 'input') {
  try {
    return readFileSync(path, 'utf8');
  } catch (error) {
    throw new Stop(`can't read the ${what} ${path}: ${error.code === 'ENOENT' ? 'no such file' : error.message}`);
  }
}

export const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

/**
 * The license, from --license (a token or a file), VEXPROOF_LICENSE, or ./.vexproof-license. One that is given
 * and not valid says so, once; vexproof then runs its free features, and never fails for it. `repo` names the
 * repository an open-source license must cover, when it is not the one vexproof runs in.
 */
export function loadLicense(licenseOption, { repo } = {}) {
  if (!pro) {
    // a license given to a copy without Pro is said to do nothing here, as an invalid one would be
    if (licenseOption ?? process.env.VEXPROOF_LICENSE) log(`vexproof: ${NO_PRO}; running free features only`);

    return { valid: false, features: [], reason: NO_PRO };
  }

  const token = pro.loadLicenseToken({ arg: licenseOption });
  const license = pro.verifyLicense(token, repo ? { repo } : undefined);
  if (token && !license.valid) log(`vexproof: ${license.reason}; running free features only`);
  if (license.warning) log(`vexproof: ${license.warning}`);

  return license;
}

/** Whether a license covers a Pro feature. */
export const licensedFor = (license, feature) => license.valid && license.features.includes(feature);
