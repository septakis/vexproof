// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Signed VEX: proof of who produced a document, checked by anyone with the public key and no service of ours.
//  - CycloneDX gets an enveloped signature in JSON Signature Format (the schema's top-level "signature"), over the
//    JCS canonical form (RFC 8785) of the document with the signature's "value" left out, as JSF specifies.
//  - OpenVEX and CSAF have no signature slot, so they get a detached signature file next to them (<file>.sig),
//    over the file's exact bytes.
// Keys: Ed25519 or ECDSA P-256, PEM, made with openssl or `vexproof keygen`. Nothing here needs a network.
import { createPrivateKey, createPublicKey, createHash, sign, verify, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';

/** RFC 8785 canonical JSON: keys sorted by UTF-16 code units, ES6 number and string serialization. */
export function canonicalize(x) {
  if (x === null || typeof x !== 'object') return JSON.stringify(x);
  if (Array.isArray(x)) return `[${x.map(canonicalize).join(',')}]`;
  return `{${Object.keys(x).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).filter((k) => x[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonicalize(x[k])}`).join(',')}}`;
}

function algorithmFor(key) {
  const t = key.asymmetricKeyType;
  if (t === 'ed25519') return { algorithm: 'Ed25519', node: null };
  if (t === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1') return { algorithm: 'ES256', node: 'sha256' };
  throw new Error(`unsupported key type ${t}${key.asymmetricKeyDetails?.namedCurve ? ` (${key.asymmetricKeyDetails.namedCurve})` : ''}; use Ed25519 or ECDSA P-256`);
}

/** SHA-256 of the public key's DER encoding, the key id used when no signer name is given. */
export function fingerprint(publicKey) {
  return `sha256:${createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex')}`;
}

export function loadPrivateKey(pemOrPath) {
  const pem = /-----BEGIN/.test(pemOrPath) ? pemOrPath : readFileSync(pemOrPath, 'utf8');
  return createPrivateKey(pem);
}

export function loadPublicKey(pemOrPath) {
  const pem = /-----BEGIN/.test(pemOrPath) ? pemOrPath : readFileSync(pemOrPath, 'utf8');
  return createPublicKey(pem);
}

const rawSign = (data, key, node) => sign(node, Buffer.from(data), node ? { key, dsaEncoding: 'ieee-p1363' } : key);
const rawVerify = (data, key, node, sig) => verify(node, Buffer.from(data), node ? { key, dsaEncoding: 'ieee-p1363' } : key, sig);

/** The signer object JSF puts in the document (everything but "value"), from a key and an optional name. */
function signer(privateKey, keyId) {
  const publicKey = createPublicKey(privateKey);
  const { algorithm, node } = algorithmFor(privateKey);
  return { head: { algorithm, keyId: keyId ?? fingerprint(publicKey), publicKey: publicKey.export({ format: 'jwk' }) }, node };
}

/** Adds a JSF signature to a CycloneDX document (replacing any existing one). Returns the signed document. */
export function signCycloneDx(doc, privateKey, { keyId = null } = {}) {
  const { head, node } = signer(privateKey, keyId);
  const { signature: _old, ...body } = doc;
  const value = rawSign(canonicalize({ ...body, signature: head }), privateKey, node).toString('base64url');
  return { ...body, signature: { ...head, value } };
}

/** Checks a CycloneDX document's JSF signature. Returns { ok, keyId, algorithm, publicKey (PEM), reason }. */
export function verifyCycloneDx(doc, { publicKey = null } = {}) {
  const s = doc?.signature;
  if (!s || !s.value) return { ok: false, reason: 'no signature in the document' };
  if (s.signers || s.chain) return { ok: false, reason: 'multiple signatures and signature chains are not supported' };
  if (s.excludes?.length) return { ok: false, reason: 'signatures with "excludes" are not supported' };
  let key;
  try { key = publicKey ?? (s.publicKey ? createPublicKey({ key: s.publicKey, format: 'jwk' }) : null); } catch (e) { return { ok: false, reason: `unreadable public key: ${e.message}` }; }
  if (!key) return { ok: false, reason: 'the signature carries no public key; pass --key' };
  if (publicKey && s.publicKey) {
    const embedded = createPublicKey({ key: s.publicKey, format: 'jwk' });
    if (fingerprint(embedded) !== fingerprint(publicKey)) return { ok: false, reason: 'the document was signed with a different key than --key' };
  }
  let alg;
  try { alg = algorithmFor(key); } catch (e) { return { ok: false, reason: e.message }; }
  if (alg.algorithm !== s.algorithm) return { ok: false, reason: `signature algorithm ${s.algorithm} does not match the key (${alg.algorithm})` };
  const { value, ...head } = s;
  const { signature: _s, ...body } = doc;
  const ok = rawVerify(canonicalize({ ...body, signature: head }), key, alg.node, Buffer.from(value, 'base64url'));
  return { ok, keyId: s.keyId ?? null, algorithm: s.algorithm, publicKey: key.export({ type: 'spki', format: 'pem' }), reason: ok ? null : 'signature does not match the document' };
}

/** A detached signature over a file's bytes, for formats with no signature slot. */
export function signBytes(bytes, privateKey, { keyId = null } = {}) {
  const { head, node } = signer(privateKey, keyId);
  return { ...head, sha256: createHash('sha256').update(bytes).digest('hex'), value: rawSign(bytes, privateKey, node).toString('base64url') };
}

export function verifyBytes(bytes, sig, { publicKey = null } = {}) {
  if (!sig?.value || !sig.algorithm) return { ok: false, reason: 'not a vexproof signature file' };
  let key;
  try { key = publicKey ?? (sig.publicKey ? createPublicKey({ key: sig.publicKey, format: 'jwk' }) : null); } catch (e) { return { ok: false, reason: `unreadable public key: ${e.message}` }; }
  if (!key) return { ok: false, reason: 'the signature carries no public key; pass --key' };
  if (publicKey && sig.publicKey && fingerprint(createPublicKey({ key: sig.publicKey, format: 'jwk' })) !== fingerprint(publicKey)) return { ok: false, reason: 'the file was signed with a different key than --key' };
  let alg;
  try { alg = algorithmFor(key); } catch (e) { return { ok: false, reason: e.message }; }
  if (alg.algorithm !== sig.algorithm) return { ok: false, reason: `signature algorithm ${sig.algorithm} does not match the key (${alg.algorithm})` };
  if (sig.sha256 && createHash('sha256').update(bytes).digest('hex') !== sig.sha256) return { ok: false, reason: 'the file has changed since it was signed' };
  const ok = rawVerify(bytes, key, alg.node, Buffer.from(sig.value, 'base64url'));
  return { ok, keyId: sig.keyId ?? null, algorithm: sig.algorithm, publicKey: key.export({ type: 'spki', format: 'pem' }), reason: ok ? null : 'signature does not match the file' };
}

/** A fresh signing key pair as PEM. */
export function generateSigningKey(type = 'ed25519') {
  const { privateKey, publicKey } = type === 'p256'
    ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    : generateKeyPairSync('ed25519');
  return { privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }), fingerprint: fingerprint(publicKey) };
}
