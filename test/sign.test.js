// SPDX-License-Identifier: MIT
// Signed VEX (Pro): JSF inside CycloneDX, detached beside the others; verify needs no license.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { triage, toCycloneDxVex } from '../src/index.js';
import { fromNpmAudit } from '../src/sources.js';
import { canonicalize, signCycloneDx, verifyCycloneDx, signBytes, verifyBytes, generateSigningKey, loadPrivateKey, loadPublicKey, fingerprint } from '../src/pro/sign.js';
import { proCopy, fixture } from './lib/pro-copy.js';

const require = createRequire(import.meta.url);
const fx = (f) => JSON.parse(readFileSync(fixture(f)));
const lockfileSbom = fx('recharts.bom.lockfile.json');
const bundleSbom = fx('recharts.bom.bundle.json');
const APP = 'pkg:npm/my-app@1.4.0';
const makeVex = () => toCycloneDxVex({ results: triage({ lockfileSbom, bundleSbom, findings: fromNpmAudit(fx('recharts.audit.json'), lockfileSbom) }), lockfileSbom, bundleSbom, productPurl: APP });

test('canonical JSON follows RFC 8785: sorted keys, no whitespace, ES6 numbers and strings', () => {
  assert.equal(canonicalize({ b: 1, a: [true, null, 'xé', 1e21, 0.5], c: { z: 1, y: undefined } }), '{"a":[true,null,"xé",1e+21,0.5],"b":1,"c":{"z":1}}');
});

for (const type of ['ed25519', 'p256']) {
  test(`${type}: a CycloneDX signature verifies, carries the key, survives the schema, and fails on any change`, async () => {
    const k = generateSigningKey(type);
    const priv = loadPrivateKey(k.privateKeyPem);
    const signed = signCycloneDx(makeVex(), priv, { keyId: 'Acme release signing' });
    assert.equal(signed.signature.algorithm, type === 'ed25519' ? 'Ed25519' : 'ES256');
    assert.equal(signed.signature.keyId, 'Acme release signing');
    const embedded = verifyCycloneDx(signed);
    assert.equal(embedded.ok, true, embedded.reason);
    assert.equal(embedded.publicKey, k.publicKeyPem);
    assert.equal(verifyCycloneDx(signed, { publicKey: loadPublicKey(k.publicKeyPem) }).ok, true);
    const { Validation, Spec } = require('@cyclonedx/cyclonedx-library');
    assert.equal(await new Validation.JsonStrictValidator(Spec.Version.v1dot6).validate(JSON.stringify(signed)), null);
    // the same document signed twice gives a different signature only for ECDSA; both verify
    assert.equal(verifyCycloneDx(signCycloneDx(signed, priv)).ok, true);
    const tampered = JSON.parse(JSON.stringify(signed));
    tampered.vulnerabilities[0].analysis.state = 'not_affected';
    assert.match(verifyCycloneDx(tampered).reason, /does not match/);
    const other = loadPublicKey(generateSigningKey(type).publicKeyPem);
    assert.match(verifyCycloneDx(signed, { publicKey: other }).reason, /different key/);
    const unsigned = makeVex();
    assert.match(verifyCycloneDx(unsigned).reason, /no signature/);
  });
}

test('a detached signature covers the exact bytes and names the key', () => {
  const k = generateSigningKey();
  const priv = loadPrivateKey(k.privateKeyPem);
  const bytes = Buffer.from(JSON.stringify(makeVex()));
  const sig = signBytes(bytes, priv);
  assert.equal(sig.keyId, k.fingerprint);
  assert.equal(sig.keyId, fingerprint(loadPublicKey(k.publicKeyPem)));
  assert.equal(verifyBytes(bytes, sig).ok, true);
  assert.match(verifyBytes(Buffer.concat([bytes, Buffer.from('\n')]), sig).reason, /changed since it was signed/);
  assert.match(verifyBytes(bytes, { ...sig, algorithm: 'ES256' }).reason, /does not match the key/);
});

test('an RSA or unsupported key is refused with a clear message', () => {
  const { generateKeyPairSync } = require('node:crypto');
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  assert.throws(() => signCycloneDx(makeVex(), rsa), /Ed25519 or ECDSA P-256/);
});

test('CLI: keygen, --sign on every output, verify with and without --key, tampering, and the free path', () => {
  const { dir, run } = proCopy();
  const keygen = run(['keygen', '--out', join(dir, 'rel')], { license: null });
  assert.equal(keygen.status, 0, keygen.stderr);
  assert.ok(existsSync(join(dir, 'rel.pem')) && existsSync(join(dir, 'rel.pub.pem')));
  assert.equal(run(['keygen', '--out', join(dir, 'rel')], { license: null }).status, 2, 'never overwrites');

  const base = ['--lockfile', fixture('recharts.bom.lockfile.json'), '--findings', fixture('recharts.audit.json'), '--bundle', fixture('recharts.bom.bundle.json'), '--product', APP];
  const out = join(dir, 'vex.cdx.json'), ov = join(dir, 'vex.openvex.json'), csaf = join(dir, 'vex.csaf.json');
  const r = run([...base, '--out', out, '--openvex', ov, '--csaf', csaf, '--csaf-namespace', 'https://acme.example', '--sign', join(dir, 'rel.pem'), '--signer', 'Acme release signing']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /signed by Acme release signing/);
  assert.ok(JSON.parse(readFileSync(out, 'utf8')).signature?.value);
  assert.ok(existsSync(`${ov}.sig`) && existsSync(`${csaf}.sig`));

  for (const f of [out, ov, csaf]) {
    const v = run(['verify', f], { license: null });
    assert.equal(v.status, 0, v.stderr);
    assert.match(v.stdout, /signed \(Ed25519\) by Acme release signing/);
    assert.match(v.stdout, /BEGIN PUBLIC KEY/);
    assert.equal(run(['verify', f, '--key', join(dir, 'rel.pub.pem')], { license: null }).status, 0);
  }
  // a different public key is refused
  run(['keygen', '--out', join(dir, 'other')], { license: null });
  const wrong = run(['verify', out, '--key', join(dir, 'other.pub.pem')], { license: null });
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /different key/);
  // a changed statement is caught in the enveloped and the detached form
  const doc = JSON.parse(readFileSync(out, 'utf8'));
  doc.vulnerabilities[0].analysis.state = 'not_affected';
  writeFileSync(out, JSON.stringify(doc, null, 2));
  assert.equal(run(['verify', out], { license: null }).status, 1);
  writeFileSync(ov, readFileSync(ov, 'utf8') + '\n');
  const det = run(['verify', ov], { license: null });
  assert.equal(det.status, 1);
  assert.match(det.stderr, /changed since it was signed/);
  // no signature at all
  const plain = run([...base, '--out', join(dir, 'plain.json')], { license: null });
  assert.equal(plain.status, 0);
  assert.equal(run(['verify', join(dir, 'plain.json')], { license: null }).status, 2);
  // --sign without a license is skipped, not an error
  const free = run([...base, '--out', join(dir, 'free.json'), '--sign', join(dir, 'rel.pem')], { license: null });
  assert.equal(free.status, 0, free.stderr);
  assert.match(free.stderr, /--sign is a Pro feature; skipped/);
  assert.ok(!JSON.parse(readFileSync(join(dir, 'free.json'), 'utf8')).signature);
});
