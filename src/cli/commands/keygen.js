// SPDX-License-Identifier: MIT
// vexproof keygen: make a signing key pair for --sign. Needs no license.
import { existsSync } from 'node:fs';
import { Stop, EXIT } from '../../stop.js';
import { pro, NO_PRO } from '../common.js';
import { writeAll } from '../output.js';

export async function keygen({ options }) {
  if (!pro) throw new Stop(`${NO_PRO}, which hold the signature code`);

  const prefix = options.out ?? 'vexproof-signing';
  const privateFile = `${prefix}.pem`;
  const publicFile = `${prefix}.pub.pem`;
  const taken = [privateFile, publicFile].find((file) => existsSync(file));
  if (taken) throw new Stop(`${taken} already exists; pass another --out`);

  const key = pro.sign.generateSigningKey(options.type ?? 'ed25519');
  writeAll([
    { path: privateFile, text: key.privateKeyPem, mode: 0o600 },
    { path: publicFile, text: key.publicKeyPem },
  ]);

  console.log(`vexproof: wrote ${privateFile} (private: keep it with your release secrets) and ${publicFile} (public: publish it)`);
  console.log(`vexproof: key fingerprint ${key.fingerprint}`);

  return EXIT.ok;
}
