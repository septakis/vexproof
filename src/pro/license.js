// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Licenses are Ed25519-signed tokens, verified locally. No network, no phone-home.
// A missing, invalid or expired license never fails a build — vexproof falls back to free features.
import { createPublicKey, verify } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { PUBLIC_KEY_PEM } from './license-key.js';

export const PRO_FEATURES = ['modules', 'report', 'baseline', 'dependabot'];
// Reserved for Pro, not built yet. Keys carry them from now on, so a release that adds one works with keys
// already issued. They unlock nothing until they move to PRO_FEATURES.
export const RESERVED_FEATURES = ['csaf', 'signing', 'rollup'];
export const GRACE_DAYS = 14;
const PREFIX = 'vxp1';

const b64u = {
  enc: (buf) => Buffer.from(buf).toString('base64url'),
  dec: (s) => Buffer.from(s, 'base64url'),
};

export const PLANS = ['pro', 'oss'];

/**
 * License ids withdrawn before their expiry date, from revoked.json beside this file. The list ships with
 * each release, so a revocation reaches a user when they move to a version that contains it: no network.
 */
let revokedCache = null;
export function loadRevoked() {
  if (!revokedCache) {
    try {
      const list = JSON.parse(readFileSync(new URL('./revoked.json', import.meta.url), 'utf8')).revoked ?? [];
      revokedCache = new Set(list.map((r) => String(r.id).toLowerCase()));
    } catch { revokedCache = new Set(); }
  }
  return revokedCache;
}

/**
 * Returns { valid, pro, features, org, exp, plan, repos, warning, reason }.
 * An open-source ('oss') license lists the repositories it covers, as host/owner/repo. It unlocks Pro
 * features only when `repo` (see detectRepository) is one of them; anywhere else vexproof runs free.
 * A license whose id is in `revoked` (by default, revoked.json) is treated as invalid.
 */
export function verifyLicense(token, { publicKeyPem = PUBLIC_KEY_PEM, now = new Date(), repo, revoked = loadRevoked() } = {}) {
  const free = (reason, extra = {}) => ({ valid: false, pro: false, features: [], reason, ...extra });
  if (!token) return free('no license');
  const parts = String(token).trim().split('.');
  if (parts.length !== 3 || parts[0] !== PREFIX) return free('malformed license');

  let ok = false;
  try {
    ok = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey(publicKeyPem), b64u.dec(parts[2]));
  } catch { ok = false; }
  if (!ok) return free('license signature does not verify');

  let payload;
  try { payload = JSON.parse(b64u.dec(parts[1]).toString('utf8')); } catch { return free('unreadable license payload'); }

  const revokedIds = revoked instanceof Set ? revoked : new Set([...revoked].map((r) => String(r).toLowerCase()));
  if (payload.id && revokedIds.has(String(payload.id).toLowerCase())) {
    return free(`license for ${payload.org} (${payload.id}) has been revoked`, { org: payload.org, id: payload.id, revoked: true });
  }

  const exp = new Date(payload.exp);
  if (Number.isNaN(exp.getTime())) return free('license has no valid expiry');
  const graceEnd = new Date(exp.getTime() + GRACE_DAYS * 86400e3);
  const features = (payload.features ?? []).filter((f) => PRO_FEATURES.includes(f));

  const plan = payload.plan ?? 'pro';
  const repos = (payload.repos ?? []).map(normalizeRepo).filter(Boolean);
  if (!PLANS.includes(plan)) return free(`unknown license plan "${plan}"`);
  if (now > graceEnd) return free(`license for ${payload.org} expired on ${payload.exp}`, { org: payload.org, exp: payload.exp, plan });
  if (plan === 'oss') {
    if (!repos.length) return free('open-source license names no repositories', { org: payload.org, plan });
    const here = repo === undefined ? detectRepository() : normalizeRepo(repo);
    if (!here) return free(`open-source license for ${repos.join(', ')}, but this checkout's repository couldn't be identified`, { org: payload.org, plan, repos });
    if (!repos.includes(here)) return free(`open-source license covers ${repos.join(', ')}, not ${here}`, { org: payload.org, plan, repos, repo: here });
  }
  const warning = now > exp ? `license for ${payload.org} expired on ${payload.exp}; Pro features stop on ${graceEnd.toISOString().slice(0, 10)}` : null;
  return { valid: true, pro: features.length > 0, features, org: payload.org, exp: payload.exp, id: payload.id, plan, repos, warning };
}

/** --license value (token or file path) → VEXPROOF_LICENSE → ./.vexproof-license */
export function loadLicenseToken({ arg, env = process.env, cwd = process.cwd() } = {}) {
  const read = (v) => (v && existsSync(v) ? readFileSync(v, 'utf8').trim() : v?.trim());
  if (arg) return read(arg);
  if (env.VEXPROOF_LICENSE) return read(env.VEXPROOF_LICENSE);
  const local = `${cwd}/.vexproof-license`;
  return existsSync(local) ? readFileSync(local, 'utf8').trim() : null;
}

/** 'git@github.com:Acme/Widget.git', 'https://github.com/acme/widget', 'github.com/acme/widget' → 'github.com/acme/widget' */
export function normalizeRepo(v) {
  if (!v) return null;
  let s = String(v).trim().toLowerCase().replace(/\/+$/, '').replace(/\.git$/, '');
  s = s.replace(/^[a-z+]+:\/\//, '').replace(/^[^@/]+@/, ''); // scheme, user@
  s = s.replace(/^([^/:]+):(?!\d+\/)/, '$1/'); // scp-style host:path
  s = s.replace(/^([^/:]+):\d+\//, '$1/'); // host:port/
  return /^[^/]+\/[^/]+\/.+/.test(s) ? s : null;
}

/** The repository this run is in: CI variables first, then the origin remote in .git/config. */
export function detectRepository({ env = process.env, cwd = process.cwd() } = {}) {
  const host = (u, d) => { try { return new URL(u).host; } catch { return d; } };
  if (env.GITHUB_REPOSITORY) return normalizeRepo(`${host(env.GITHUB_SERVER_URL, 'github.com')}/${env.GITHUB_REPOSITORY}`);
  if (env.CI_PROJECT_PATH) return normalizeRepo(`${env.CI_SERVER_HOST ?? 'gitlab.com'}/${env.CI_PROJECT_PATH}`);
  if (env.BITBUCKET_REPO_FULL_NAME) return normalizeRepo(`bitbucket.org/${env.BITBUCKET_REPO_FULL_NAME}`);
  for (let dir = cwd; ; dir = dirname(dir)) {
    let cfg = join(dir, '.git', 'config');
    const gitFile = join(dir, '.git');
    if (existsSync(gitFile) && !existsSync(cfg)) { // worktree or submodule: .git is a file pointing at the real git dir
      const m = /gitdir:\s*(.+)/.exec(readFileSync(gitFile, 'utf8'));
      if (m) { const gd = join(dir, m[1].trim()); cfg = existsSync(join(gd, 'config')) ? join(gd, 'config') : join(gd, '..', '..', 'config'); }
    }
    if (existsSync(cfg)) {
      const m = /\[remote "origin"\][^[]*?\burl\s*=\s*(\S+)/.exec(readFileSync(cfg, 'utf8'));
      return m ? normalizeRepo(m[1]) : null;
    }
    if (dirname(dir) === dir) return null;
  }
}

export const LICENSE_PREFIX = PREFIX;
export { b64u };
