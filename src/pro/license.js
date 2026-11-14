// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Licenses are Ed25519-signed tokens, verified locally. No network, no phone-home.
// A missing, invalid or expired license never fails a build — vexproof falls back to free features.
import { createPublicKey, verify } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { PUBLIC_KEY_PEM } from './license-key.js';

export const PRO_FEATURES = ['modules', 'report', 'baseline', 'dependabot', 'csaf', 'signing', 'rollup'];
// Names reserved for Pro features not built yet. Keys carry them, so a release that adds one works with keys
// already issued. Empty since 1.0.0-beta.3, when csaf, signing and rollup shipped.
export const RESERVED_FEATURES = [];
const GRACE_DAYS = 14;
const PREFIX = 'vxp1';
const MILLISECONDS_PER_DAY = 86_400_000;

const b64u = {
  enc: (bytes) => Buffer.from(bytes).toString('base64url'),
  dec: (encoded) => Buffer.from(encoded, 'base64url'),
};

export const PLANS = ['pro', 'oss'];

let revokedCache = null;

/**
 * License ids withdrawn before their expiry date, from revoked.json beside this file. The list ships with
 * each release, so a revocation reaches a user when they move to a version that contains it: no network.
 */
export function loadRevoked() {
  if (!revokedCache) {
    try {
      const list = JSON.parse(readFileSync(new URL('./revoked.json', import.meta.url), 'utf8')).revoked ?? [];
      revokedCache = new Set(list.map((entry) => String(entry.id).toLowerCase()));
    } catch {
      revokedCache = new Set();
    }
  }

  return revokedCache;
}

/**
 * Returns { valid, pro, features, org, exp, id, plan, repos, warning, reason }; a license that is refused for being
 * revoked also has `revoked: true`, and one refused for another repository names it in `repo`.
 * An open-source ('oss') license lists the repositories it covers, as host/owner/repo. It unlocks Pro
 * features only when `repo` (see detectRepository) is one of them; anywhere else vexproof runs free.
 * A license whose id is in `revoked` (by default, revoked.json) is treated as invalid.
 */
export function verifyLicense(token, { publicKeyPem = PUBLIC_KEY_PEM, now = new Date(), repo, revoked = loadRevoked() } = {}) {
  const free = (reason, extra = {}) => ({ valid: false, pro: false, features: [], reason, ...extra });
  if (!token) {
    return free('no license');
  }

  const parts = String(token).trim().split('.');
  if (parts.length !== 3 || parts[0] !== PREFIX) {
    return free('malformed license');
  }

  let signatureValid = false;
  try {
    signatureValid = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey(publicKeyPem), b64u.dec(parts[2]));
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    return free('license signature does not verify');
  }

  let payload;
  try {
    payload = JSON.parse(b64u.dec(parts[1]).toString('utf8'));
  } catch {
    return free('unreadable license payload');
  }

  const revokedIds = revoked instanceof Set ? revoked : new Set([...revoked].map((id) => String(id).toLowerCase()));
  if (payload.id && revokedIds.has(String(payload.id).toLowerCase())) {
    return free(`license for ${payload.org} (${payload.id}) has been revoked`, { org: payload.org, id: payload.id, revoked: true });
  }

  // A license issued "until 2027-09-30" is valid through that day, UTC: a date alone ends when the day does.
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(String(payload.exp));
  const expiresAt = dateOnly ? new Date(Date.parse(payload.exp) + MILLISECONDS_PER_DAY) : new Date(payload.exp);
  if (Number.isNaN(expiresAt.getTime())) {
    return free('license has no valid expiry');
  }

  const graceEnd = new Date(expiresAt.getTime() + GRACE_DAYS * MILLISECONDS_PER_DAY);
  const features = (payload.features ?? []).filter((feature) => PRO_FEATURES.includes(feature));

  const plan = payload.plan ?? 'pro';
  const repos = (payload.repos ?? []).map(normalizeRepo).filter(Boolean);
  if (!PLANS.includes(plan)) {
    return free(`unknown license plan "${plan}"`);
  }
  if (now > graceEnd) {
    return free(`license for ${payload.org} expired on ${payload.exp}`, { org: payload.org, exp: payload.exp, plan });
  }
  if (plan === 'oss') {
    if (!repos.length) {
      return free('open-source license names no repositories', { org: payload.org, plan });
    }

    const here = repo === undefined ? detectRepository() : normalizeRepo(repo);
    if (!here) {
      return free(
        `open-source license for ${repos.join(', ')}, but this checkout's repository couldn't be identified`,
        { org: payload.org, plan, repos },
      );
    }
    if (!repos.includes(here)) {
      return free(`open-source license covers ${repos.join(', ')}, not ${here}`, { org: payload.org, plan, repos, repo: here });
    }
  }

  const warning = now > expiresAt
    ? `license for ${payload.org} expired on ${payload.exp}; Pro features stop on ${graceEnd.toISOString().slice(0, 10)}`
    : null;

  return {
    valid: true,
    pro: features.length > 0,
    features,
    org: payload.org,
    exp: payload.exp,
    id: payload.id,
    plan,
    repos,
    warning,
  };
}

/** --license value (token or file path) → VEXPROOF_LICENSE → ./.vexproof-license */
export function loadLicenseToken({ arg, env = process.env, cwd = process.cwd() } = {}) {
  const read = (value) => (value && existsSync(value) ? readFileSync(value, 'utf8').trim() : value?.trim());
  if (arg) {
    return read(arg);
  }
  if (env.VEXPROOF_LICENSE) {
    return read(env.VEXPROOF_LICENSE);
  }

  const local = `${cwd}/.vexproof-license`;

  return existsSync(local) ? readFileSync(local, 'utf8').trim() : null;
}

/** 'git@github.com:Acme/Widget.git', 'https://github.com/acme/widget', 'github.com/acme/widget' → 'github.com/acme/widget' */
export function normalizeRepo(value) {
  if (!value) {
    return null;
  }

  let normalized = String(value).trim().toLowerCase().replace(/\/+$/, '').replace(/\.git$/, '');
  normalized = normalized.replace(/^[a-z+]+:\/\//, '').replace(/^[^@/]+@/, ''); // scheme, user@
  normalized = normalized.replace(/^([^/:]+):(?!\d+\/)/, '$1/'); // scp-style host:path
  normalized = normalized.replace(/^([^/:]+):\d+\//, '$1/'); // host:port/

  return /^[^/]+\/[^/]+\/.+/.test(normalized) ? normalized : null;
}

/** The repository this run is in: CI variables first, then the origin remote in .git/config. */
export function detectRepository({ env = process.env, cwd = process.cwd() } = {}) {
  const host = (url, fallback) => {
    try {
      return new URL(url).host;
    } catch {
      return fallback;
    }
  };
  if (env.GITHUB_REPOSITORY) {
    return normalizeRepo(`${host(env.GITHUB_SERVER_URL, 'github.com')}/${env.GITHUB_REPOSITORY}`);
  }
  if (env.CI_PROJECT_PATH) {
    return normalizeRepo(`${env.CI_SERVER_HOST ?? 'gitlab.com'}/${env.CI_PROJECT_PATH}`);
  }
  if (env.BITBUCKET_REPO_FULL_NAME) {
    return normalizeRepo(`bitbucket.org/${env.BITBUCKET_REPO_FULL_NAME}`);
  }

  for (let dir = cwd; ; dir = dirname(dir)) {
    const config = gitConfigAt(dir);
    if (config) {
      const origin = /\[remote "origin"\][^[]*?\burl\s*=\s*(\S+)/.exec(readFileSync(config, 'utf8'));

      return origin ? normalizeRepo(origin[1]) : null;
    }
    if (dirname(dir) === dir) {
      return null;
    }
  }
}

/**
 * The git config file for a checkout at `dir`, or null when `dir` is not one. In a worktree or a submodule,
 * `.git` is a file naming the real git folder (`gitdir:`, often an absolute path); a worktree's git folder
 * names the repository's own in `commondir`, and the remotes are in that one's config.
 */
function gitConfigAt(dir) {
  const dotGit = join(dir, '.git');
  if (existsSync(join(dotGit, 'config'))) {
    return join(dotGit, 'config');
  }
  if (!existsSync(dotGit)) {
    return null;
  }

  let gitDir;
  try {
    const pointer = /gitdir:\s*(.+)/.exec(readFileSync(dotGit, 'utf8'));
    if (!pointer) {
      return null;
    }

    gitDir = resolve(dir, pointer[1].trim());
  } catch {
    return null; // .git is a folder without a config: not a checkout vexproof can read
  }
  if (existsSync(join(gitDir, 'config'))) {
    return join(gitDir, 'config'); // a submodule keeps its own config
  }

  let common = join(gitDir, '..', '..');
  try {
    common = resolve(gitDir, readFileSync(join(gitDir, 'commondir'), 'utf8').trim());
  } catch {
    // older git writes no commondir: a worktree's folder is <repository>/.git/worktrees/<name>
  }

  return existsSync(join(common, 'config')) ? join(common, 'config') : null;
}

export const LICENSE_PREFIX = PREFIX;
export { b64u };
