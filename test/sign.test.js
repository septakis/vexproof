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
const readFixture = (name) => JSON.parse(readFileSync(fixture(name)));
const lockfileSbom = readFixture('recharts.bom.lockfile.json');
const bundleSbom = readFixture('recharts.bom.bundle.json');
const APP = 'pkg:npm/my-app@1.4.0';
const makeVex = () => toCycloneDxVex({
  results: triage({ lockfileSbom, bundleSbom, findings: fromNpmAudit(readFixture('recharts.audit.json'), lockfileSbom) }),
  lockfileSbom,
  bundleSbom,
  productPurl: APP,
});

test('canonical JSON follows RFC 8785: sorted keys, no whitespace, ES6 numbers and strings', () => {
  assert.equal(
    canonicalize({ b: 1, a: [true, null, 'xé', 1e21, 0.5], c: { z: 1, y: undefined } }),
    '{"a":[true,null,"xé",1e+21,0.5],"b":1,"c":{"z":1}}',
  );
});

for (const type of ['ed25519', 'p256']) {
  test(`${type}: a CycloneDX signature verifies, carries the key, survives the schema, and fails on any change`, async () => {
    const keyPair = generateSigningKey(type);
    const privateKey = loadPrivateKey(keyPair.privateKeyPem);

    const signed = signCycloneDx(makeVex(), privateKey, { keyId: 'Acme release signing' });

    assert.equal(signed.signature.algorithm, type === 'ed25519' ? 'Ed25519' : 'ES256');
    assert.equal(signed.signature.keyId, 'Acme release signing');
    const embedded = verifyCycloneDx(signed);
    assert.equal(embedded.ok, true, embedded.reason);
    assert.equal(embedded.publicKey, keyPair.publicKeyPem);
    assert.equal(verifyCycloneDx(signed, { publicKey: loadPublicKey(keyPair.publicKeyPem) }).ok, true);
    const { Validation, Spec } = require('@cyclonedx/cyclonedx-library');
    assert.equal(await new Validation.JsonStrictValidator(Spec.Version.v1dot6).validate(JSON.stringify(signed)), null);

    // Signed again, an already signed document has its signature replaced, not covered. The same document
    // signed twice gives a different signature only for ECDSA (Ed25519 is deterministic); both verify.
    const signedAgain = signCycloneDx(signed, privateKey, { keyId: 'Acme release signing' });
    assert.equal(verifyCycloneDx(signedAgain).ok, true);
    if (type === 'ed25519') {
      assert.equal(signedAgain.signature.value, signed.signature.value);
    } else {
      assert.notEqual(signedAgain.signature.value, signed.signature.value);
    }

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
  const keyPair = generateSigningKey();
  const privateKey = loadPrivateKey(keyPair.privateKeyPem);
  const bytes = Buffer.from(JSON.stringify(makeVex()));

  const signature = signBytes(bytes, privateKey);

  assert.equal(signature.keyId, keyPair.fingerprint);
  assert.equal(signature.keyId, fingerprint(loadPublicKey(keyPair.publicKeyPem)));
  assert.equal(verifyBytes(bytes, signature).ok, true);
  assert.match(verifyBytes(Buffer.concat([bytes, Buffer.from('\n')]), signature).reason, /changed since it was signed/);
  assert.match(verifyBytes(bytes, { ...signature, algorithm: 'ES256' }).reason, /does not match the key/);
});

test('an RSA or unsupported key is refused with a clear message', () => {
  const { generateKeyPairSync } = require('node:crypto');
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;

  assert.throws(() => signCycloneDx(makeVex(), rsa), /Ed25519 or ECDSA P-256/);
});

test('CLI: keygen, --sign on every output, verify with and without --key, tampering, and the free path', (context) => {
  const { dir, run } = proCopy(context);

  const keygen = run(['keygen', '--out', join(dir, 'rel')], { license: null });
  assert.equal(keygen.status, 0, keygen.stderr);
  assert.ok(existsSync(join(dir, 'rel.pem')) && existsSync(join(dir, 'rel.pub.pem')));
  assert.equal(run(['keygen', '--out', join(dir, 'rel')], { license: null }).status, 2, 'never overwrites');

  const base = [
    '--lockfile', fixture('recharts.bom.lockfile.json'),
    '--findings', fixture('recharts.audit.json'),
    '--bundle', fixture('recharts.bom.bundle.json'),
    '--product', APP,
  ];
  const out = join(dir, 'vex.cdx.json');
  const openvex = join(dir, 'vex.openvex.json');
  const csaf = join(dir, 'vex.csaf.json');
  const result = run([
    ...base,
    '--out', out,
    '--openvex', openvex,
    '--csaf', csaf,
    '--csaf-namespace', 'https://acme.example',
    '--sign', join(dir, 'rel.pem'),
    '--signer', 'Acme release signing',
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /signed by Acme release signing/);
  assert.ok(JSON.parse(readFileSync(out, 'utf8')).signature?.value);
  assert.ok(existsSync(`${openvex}.sig`) && existsSync(`${csaf}.sig`));

  for (const file of [out, openvex, csaf]) {
    const verified = run(['verify', file], { license: null });
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stdout, /signed \(Ed25519\) by Acme release signing/);
    assert.match(verified.stdout, /BEGIN PUBLIC KEY/);
    assert.equal(run(['verify', file, '--key', join(dir, 'rel.pub.pem')], { license: null }).status, 0);
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
  writeFileSync(openvex, readFileSync(openvex, 'utf8') + '\n');
  const detached = run(['verify', openvex], { license: null });
  assert.equal(detached.status, 1);
  assert.match(detached.stderr, /changed since it was signed/);

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

test('only plain JSON is signed, and a malformed embedded key is a reason, with --key or without', async () => {
  const { canonicalize, verifyCycloneDx, generateSigningKey, loadPublicKey } = await import('../src/pro/sign.js');
  assert.throws(() => canonicalize([undefined]), /undefined/);
  assert.throws(() => canonicalize({ when: new Date(0) }), /Date/);
  assert.throws(() => canonicalize({ count: Number.NaN }), /no such number/);
  assert.equal(canonicalize({ b: 1, a: [true, null, 'x'] }), '{"a":[true,null,"x"],"b":1}');

  const broken = { bomFormat: 'CycloneDX', signature: { algorithm: 'Ed25519', value: 'x', publicKey: { kty: 'OKP', crv: 'Ed25519' } } };
  const key = loadPublicKey(generateSigningKey().publicKeyPem);
  for (const options of [{}, { publicKey: key }]) {
    const result = verifyCycloneDx(broken, options);
    assert.equal(result.ok, false);
    assert.match(result.reason, /unreadable public key/);
  }
});
