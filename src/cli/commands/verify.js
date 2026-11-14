// SPDX-License-Identifier: MIT
// vexproof verify: check a signature vexproof wrote. Needs no license: anyone can check one.
import { readFileSync } from 'node:fs';
import { Stop, EXIT } from '../../stop.js';
import { pro, NO_PRO, log } from '../common.js';

export async function verify({ options, words }) {
  const file = words[0];
  if (!file) throw new Stop('verify needs the file to check: vexproof verify <file> [--key <public.pem>]');
  if (!pro) throw new Stop(`${NO_PRO}, which hold the signature code`);

  let publicKey = null;
  if (options.key) {
    try {
      publicKey = pro.sign.loadPublicKey(options.key);
    } catch (error) {
      throw new Stop(`cannot read --key: ${error.message}`);
    }
  }

  let bytes;
  try {
    bytes = readFileSync(file);
  } catch (error) {
    throw new Stop(`cannot read ${file}: ${error.message}`);
  }
  let document = null;
  try {
    document = JSON.parse(bytes.toString('utf8'));
  } catch {
    document = null; // not JSON: its signature can only be the detached kind
  }

  let result;
  if (document?.bomFormat === 'CycloneDX' && document.signature) {
    result = pro.sign.verifyCycloneDx(document, { publicKey });
  } else {
    let detached;
    try {
      detached = JSON.parse(readFileSync(`${file}.sig`, 'utf8'));
    } catch {
      throw new Stop(`${file} carries no signature and there is no ${file}.sig beside it`);
    }
    result = pro.sign.verifyBytes(bytes, detached, { publicKey });
  }

  if (!result.ok) {
    log(`vexproof: signature on ${file} does not check: ${result.reason}`);

    return EXIT.failed;
  }

  // Without --key the signature was checked against the key that came with it, which anyone can make.
  if (!publicKey) log('vexproof: no --key given, so this shows the file is unchanged since it was signed, not who signed it. Compare the key below with the one the publisher gave you, or pass it with --key.');
  console.log(`vexproof: ${file} is signed (${result.algorithm}) by ${result.keyId ?? 'an unnamed key'}; the public key is:`);
  console.log(result.publicKey.trim());

  return EXIT.ok;
}
