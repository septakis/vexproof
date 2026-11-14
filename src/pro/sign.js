// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Signed VEX: proof of who produced a document, checked by anyone with the public key and no service of ours.
//  - CycloneDX gets an enveloped signature in JSON Signature Format (the schema's top-level "signature"), over the
//    JCS canonical form (RFC 8785) of the document with the signature's "value" left out, as JSF specifies.
//  - OpenVEX and CSAF have no signature slot, so they get a detached signature file next to them (<file>.sig),
//    over the file's exact bytes. That file is vexproof's own format, checked with `vexproof verify`.
// Keys: Ed25519 or ECDSA P-256, PEM, made with openssl or `vexproof keygen`. Nothing here needs a network.
import { createPrivateKey, createPublicKey, createHash, sign, verify, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * RFC 8785 canonical JSON: keys sorted by UTF-16 code units, ES6 number and string serialization. Only plain
 * JSON is accepted: a value JSON.stringify would write differently (undefined in an array, a Date, NaN) would
 * be signed in one form and written in another, so it throws instead.
 */
export function canonicalize(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`can't sign ${value}: JSON has no such number`);
    }

    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => {
      if (item === undefined) {
        throw new Error("can't sign an array that holds undefined");
      }

      return canonicalize(item);
    }).join(',')}]`;
  }
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));

    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }

  throw new Error(`can't sign a ${value?.constructor?.name ?? typeof value}: only plain JSON values can be signed`);
}

function algorithmFor(key) {
  const type = key.asymmetricKeyType;
  if (type === 'ed25519') {
    return { algorithm: 'Ed25519', digest: null };
  }
  if (type === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1') {
    return { algorithm: 'ES256', digest: 'sha256' };
  }

  const curve = key.asymmetricKeyDetails?.namedCurve;
  throw new Error(`unsupported key type ${type}${curve ? ` (${curve})` : ''}; use Ed25519 or ECDSA P-256`);
}

/** SHA-256 of the public key's DER encoding, the key id used when no signer name is given. */
export function fingerprint(publicKey) {
  return `sha256:${createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex')}`;
}

const pemOf = (pemOrPath) => (/-----BEGIN/.test(pemOrPath) ? pemOrPath : readFileSync(pemOrPath, 'utf8'));

export function loadPrivateKey(pemOrPath) {
  return createPrivateKey(pemOf(pemOrPath));
}

export function loadPublicKey(pemOrPath) {
  return createPublicKey(pemOf(pemOrPath));
}

const rawSign = (data, key, digest) => sign(digest, Buffer.from(data), digest ? { key, dsaEncoding: 'ieee-p1363' } : key);
const rawVerify = (data, key, digest, signature) => verify(digest, Buffer.from(data), digest ? { key, dsaEncoding: 'ieee-p1363' } : key, signature);

/** The signer object JSF puts in the document (everything but "value"), from a key and an optional name. */
function signer(privateKey, keyId) {
  const publicKey = createPublicKey(privateKey);
  const { algorithm, digest } = algorithmFor(privateKey);

  return { head: { algorithm, keyId: keyId ?? fingerprint(publicKey), publicKey: publicKey.export({ format: 'jwk' }) }, digest };
}

/**
 * The key to check a signature with: `given` (from --key) when there is one, which must then be the key the
 * signature carries, else the one it carries. Returns { key } or { reason }.
 */
function checkingKey(embeddedJwk, given, what) {
  let embedded = null;
  if (embeddedJwk) {
    try {
      embedded = createPublicKey({ key: embeddedJwk, format: 'jwk' });
    } catch (error) {
      return { reason: `unreadable public key: ${error.message}` };
    }
  }

  if (given && embedded && fingerprint(embedded) !== fingerprint(given)) {
    return { reason: `the ${what} was signed with a different key than --key` };
  }
  const key = given ?? embedded;
  if (!key) {
    return { reason: 'the signature carries no public key; pass --key' };
  }

  return { key };
}

/**
 * Adds a JSF signature to a CycloneDX document (replacing any existing one). Returns the signed document. The
 * document is signed as JSON will write it, so what is checked later is exactly what was signed.
 */
export function signCycloneDx(doc, privateKey, { keyId = null } = {}) {
  const { head, digest } = signer(privateKey, keyId);
  const { signature: _previous, ...body } = JSON.parse(JSON.stringify(doc));
  const value = rawSign(canonicalize({ ...body, signature: head }), privateKey, digest).toString('base64url');

  return { ...body, signature: { ...head, value } };
}

/** Checks a CycloneDX document's JSF signature. Returns { ok, keyId, algorithm, publicKey (PEM), reason }. */
export function verifyCycloneDx(doc, { publicKey = null } = {}) {
  const signature = doc?.signature;
  if (!signature || !signature.value) {
    return { ok: false, reason: 'no signature in the document' };
  }
  if (signature.signers || signature.chain) {
    return { ok: false, reason: 'multiple signatures and signature chains are not supported' };
  }
  if (signature.excludes?.length) {
    return { ok: false, reason: 'signatures with "excludes" are not supported' };
  }

  const { key, reason } = checkingKey(signature.publicKey, publicKey, 'document');
  if (!key) {
    return { ok: false, reason };
  }

  let algorithm;
  try {
    algorithm = algorithmFor(key);
  } catch (error) {
    return { ok: false, reason: error.message };
  }
  if (algorithm.algorithm !== signature.algorithm) {
    return { ok: false, reason: `signature algorithm ${signature.algorithm} does not match the key (${algorithm.algorithm})` };
  }

  const { value, ...head } = signature;
  const { signature: _signature, ...body } = doc;
  const ok = rawVerify(canonicalize({ ...body, signature: head }), key, algorithm.digest, Buffer.from(value, 'base64url'));

  return { ok, keyId: signature.keyId ?? null, algorithm: signature.algorithm, publicKey: key.export({ type: 'spki', format: 'pem' }), reason: ok ? null : 'signature does not match the document' };
}

/** A detached signature over a file's bytes, for formats with no signature slot. */
export function signBytes(bytes, privateKey, { keyId = null } = {}) {
  const { head, digest } = signer(privateKey, keyId);
  const value = rawSign(bytes, privateKey, digest).toString('base64url');

  return { ...head, sha256: createHash('sha256').update(bytes).digest('hex'), value };
}

export function verifyBytes(bytes, signature, { publicKey = null } = {}) {
  if (!signature?.value || !signature.algorithm) {
    return { ok: false, reason: 'not a vexproof signature file' };
  }

  const { key, reason } = checkingKey(signature.publicKey, publicKey, 'file');
  if (!key) {
    return { ok: false, reason };
  }

  let algorithm;
  try {
    algorithm = algorithmFor(key);
  } catch (error) {
    return { ok: false, reason: error.message };
  }
  if (algorithm.algorithm !== signature.algorithm) {
    return { ok: false, reason: `signature algorithm ${signature.algorithm} does not match the key (${algorithm.algorithm})` };
  }
  if (signature.sha256 && createHash('sha256').update(bytes).digest('hex') !== signature.sha256) {
    return { ok: false, reason: 'the file has changed since it was signed' };
  }

  const ok = rawVerify(bytes, key, algorithm.digest, Buffer.from(signature.value, 'base64url'));

  return { ok, keyId: signature.keyId ?? null, algorithm: signature.algorithm, publicKey: key.export({ type: 'spki', format: 'pem' }), reason: ok ? null : 'signature does not match the file' };
}

/** A fresh signing key pair as PEM. */
export function generateSigningKey(type = 'ed25519') {
  const { privateKey, publicKey } = type === 'p256'
    ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    : generateKeyPairSync('ed25519');

  return { privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }), fingerprint: fingerprint(publicKey) };
}
