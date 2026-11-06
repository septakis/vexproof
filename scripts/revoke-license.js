#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Revoke a license before it expires, by adding its id to src/pro/revoked.json.
//   node scripts/revoke-license.js --id <license id> [--note "text"]
//   node scripts/revoke-license.js --token <token|file> [--note "text"]   (takes the id from the license itself)
//   node scripts/revoke-license.js --list
// A revocation takes effect in the next version of vexproof you publish. Installs that stay on an older
// version keep accepting the license until it expires. The list, notes included, ships in the npm package.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { LICENSE_PREFIX, b64u } from '../src/pro/license.js';
import { PUBLIC_KEY_PEM } from '../src/pro/license-key.js';

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(`--${name}`);
const opt = (name) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : undefined; };
const file = opt('file') ?? fileURLToPath(new URL('../src/pro/revoked.json', import.meta.url));
const fail = (msg, code = 2) => { console.error(msg); process.exit(code); };

const doc = JSON.parse(readFileSync(file, 'utf8'));
doc.revoked ??= [];

if (flag('list')) {
  if (!doc.revoked.length) console.log('No licenses revoked.');
  for (const r of doc.revoked) console.log(`${r.date}  ${r.id}${r.note ? `  ${r.note}` : ''}`);
  process.exit(0);
}

let id = opt('id');
if (opt('token')) {
  const raw = opt('token');
  const token = existsSync(raw) ? readFileSync(raw, 'utf8').trim() : raw.trim();
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== LICENSE_PREFIX) fail('that is not a vexproof license');
  let ok = false;
  try { ok = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey(PUBLIC_KEY_PEM), b64u.dec(parts[2])); } catch { ok = false; }
  if (!ok) fail('that license was not signed with this repository\'s key, so vexproof already rejects it; nothing to revoke', 1);
  const payload = JSON.parse(b64u.dec(parts[1]).toString('utf8'));
  if (!payload.id) fail('that license has no id, so it cannot be revoked by id; it stays valid until it expires', 1);
  id = payload.id;
  console.log(`License for ${payload.org}, expiring ${payload.exp}, id ${id}`);
}
if (!id) fail('usage: revoke-license --id <license id> | --token <token|file> [--note "text"] | --list');
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) fail(`not a license id: ${id}`);
id = id.toLowerCase();

if (doc.revoked.some((r) => String(r.id).toLowerCase() === id)) {
  console.log(`${id} is already revoked.`);
  process.exit(0);
}
const entry = { id, date: opt('date') ?? new Date().toISOString().slice(0, 10) };
if (opt('note')) entry.note = opt('note');
doc.revoked.push(entry);
writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`Revoked ${id}. Publish a new version of vexproof for it to take effect.`);
if (entry.note) console.log('The note is published with the package; keep customer names and private details out of it.');
