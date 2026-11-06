// SPDX-License-Identifier: MIT
// A copy of src/ whose Pro public key is one the test owns, so CLI tests can run with a real license without the
// production signing key. The copy shares node_modules through a junction.
import { mkdtempSync, cpSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const b64u = (buf) => Buffer.from(buf).toString('base64url');

export function proCopy() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const dir = mkdtempSync(join(tmpdir(), 'vexproof-pro-'));
  cpSync(join(ROOT, 'src'), join(dir, 'src'), { recursive: true });
  cpSync(join(ROOT, 'package.json'), join(dir, 'package.json'));
  symlinkSync(join(ROOT, 'node_modules'), join(dir, 'node_modules'), 'junction');
  writeFileSync(join(dir, 'src', 'pro', 'license-key.js'), `export const PUBLIC_KEY_PEM = ${JSON.stringify(publicKey.export({ type: 'spki', format: 'pem' }))};\n`);
  const token = (payload = {}) => {
    const head = `vxp1.${b64u(JSON.stringify({ v: 1, id: 'test-license', org: 'Acme GmbH', plan: 'pro', features: ['modules', 'report', 'baseline', 'dependabot', 'csaf', 'signing', 'rollup'], iat: '2026-01-01', exp: '2099-01-01', ...payload }))}`;
    return `${head}.${b64u(sign(null, Buffer.from(head), privateKey))}`;
  };
  const cli = join(dir, 'src', 'cli.js');
  const run = (args, { license = token(), env = {}, cwd = dir } = {}) => spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: license ?? '', ...env } });
  return { dir, cli, token, run };
}

export const fixture = (f) => fileURLToPath(new URL(`../fixtures/${f}`, import.meta.url));
