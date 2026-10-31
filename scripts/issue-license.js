#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Issue a license: node scripts/issue-license.js --org "Acme GmbH" --exp 2027-09-30 [--features modules,report,baseline,dependabot] [--key .keys/license-private.pem]
// With no --features, the key carries every Pro feature, the reserved ones included.
// Open-source license: --plan oss --org "vitejs" --repos github.com/vitejs/vite[,github.com/vitejs/other] --exp 2027-09-30
import { createPrivateKey, sign, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { PRO_FEATURES, RESERVED_FEATURES, PLANS, LICENSE_PREFIX, b64u, normalizeRepo } from '../src/pro/license.js';

const args = Object.fromEntries(process.argv.slice(2).map((a, i, arr) => (a.startsWith('--') ? [a.slice(2), arr[i + 1]] : null)).filter(Boolean));
if (!args.org || !args.exp) { console.error('usage: issue-license --org <name> --exp YYYY-MM-DD [--features a,b] [--key path]'); process.exit(2); }
const known = [...PRO_FEATURES, ...RESERVED_FEATURES];
const features = (args.features ?? known.join(',')).split(',').map((s) => s.trim()).filter(Boolean);
const bad = features.filter((f) => !known.includes(f));
if (bad.length) { console.error(`unknown feature(s): ${bad.join(', ')}`); process.exit(2); }

const plan = args.plan ?? 'pro';
if (!PLANS.includes(plan)) { console.error(`unknown plan: ${plan} (${PLANS.join(', ')})`); process.exit(2); }
const repos = (args.repos ?? '').split(',').map((r) => r.trim()).filter(Boolean);
const bogus = repos.filter((r) => !normalizeRepo(r));
if (bogus.length) { console.error(`not a host/owner/repo: ${bogus.join(', ')}`); process.exit(2); }
if (plan === 'oss' && !repos.length) { console.error('an open-source license needs --repos host/owner/repo[,…]'); process.exit(2); }

const payload = { v: 1, id: randomUUID(), org: args.org, plan, ...(repos.length ? { repos: repos.map(normalizeRepo) } : {}), features, iat: new Date().toISOString().slice(0, 10), exp: args.exp };
const head = `${LICENSE_PREFIX}.${b64u.enc(JSON.stringify(payload))}`;
const key = createPrivateKey(readFileSync(args.key ?? '.keys/license-private.pem'));
console.log(`${head}.${b64u.enc(sign(null, Buffer.from(head), key))}`);
