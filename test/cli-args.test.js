// SPDX-License-Identifier: MIT
// What a review of the published 1.0.0-beta.8 package found: options the CLI skipped in silence (so a misspelt
// --fail-on left a build with no gate), a gate that could not run and said so in one easily missed line, a webpack configuration
// array whose module maps replaced one another, and registry downloads that were never checked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { readModuleMap } from '../src/modules.js';
import { strayOutputs } from '../src/coverage.js';
import { checkTarball } from '../src/derive.js';
import vexproof from '../src/vite.js';

const require = createRequire(import.meta.url);
const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const put = (root, rel, text) => { const p = join(root, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; };

function project() {
  const dir = mkdtempSync(join(tmpdir(), 'vxp-args-'));
  put(dir, 'lock.json', JSON.stringify({
    bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:11111111-1111-4111-8111-111111111111',
    metadata: { component: { type: 'application', name: 't', version: '1.0.0', purl: 'pkg:npm/t@1.0.0', 'bom-ref': 't' } },
    components: [{ type: 'library', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20', 'bom-ref': 'pkg:npm/lodash@4.17.20' }],
  }));
  put(dir, 'bundle.json', JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ type: 'library', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' }] }));
  put(dir, 'f.json', JSON.stringify([{ purl: 'pkg:npm/lodash@4.17.20', ids: ['GHSA-35jh-r3h4-6jhm'] }]));
  return dir;
}
const run = (dir, ...extra) => spawnSync(process.execPath, [CLI, '--lockfile', 'lock.json', '--bundle', 'bundle.json', '--findings', 'f.json', '--quiet', ...extra],
  { cwd: dir, encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: '' } });

test('--name=value is read like --name value, so --fail-on=in_triage trips the gate', () => {
  const dir = project();
  const r = run(dir, '--fail-on=in_triage', '--out=eq.json');
  assert.equal(r.status, 1, r.stderr);
  assert.ok(existsSync(join(dir, 'eq.json')));
  assert.equal(run(dir, '--fail-on', 'in_triage').status, 1);
});

test('an option vexproof does not have stops the run and names the one that was meant', () => {
  const dir = project();
  let r = run(dir, '--failon', 'in_triage');
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown option --failon \(did you mean --fail-on\?\)/);
  assert.ok(!existsSync(join(dir, 'vex.cdx.json')), 'nothing is written');
  r = run(dir, '--fail_on', 'in_triage');
  assert.match(r.stderr, /did you mean --fail-on/);
  assert.match(run(dir, '-x').stderr, /unknown option -x/);
  assert.match(run(dir, '--zzzzzz', '1').stderr, /unknown option --zzzzzz; see/);
});

test('a missing value, a value on a flag that takes none, and a stray word each stop the run', () => {
  const dir = project();
  for (const [extra, message] of [
    [['--out'], /--out needs a value/],
    [['--out='], /--out needs a value/],
    [['--out', '--openvex', 'o.json'], /--out needs a value/],
    [['--quiet=1'], /--quiet takes no value/],
    [['stray'], /unknown command "stray"/],
  ]) {
    const r = run(dir, ...extra);
    assert.equal(r.status, 2, extra.join(' '));
    assert.match(r.stderr, message);
  }
  const rules = spawnSync(process.execPath, [CLI, 'rules'], { encoding: 'utf8' });
  assert.equal(rules.status, 2);
  assert.match(rules.stderr, /vexproof rules derive/);
});

test('-h prints the help and -v the version', () => {
  const h = spawnSync(process.execPath, [CLI, '-h'], { encoding: 'utf8' });
  assert.equal(h.status, 0);
  assert.match(h.stdout, /^vexproof .*build-proven VEX/);
  const v = spawnSync(process.execPath, [CLI, '-v'], { encoding: 'utf8' });
  assert.equal(v.stdout.trim(), require('../package.json').version);
});

test('--fail-on is checked before anything is written', () => {
  const dir = project();
  let r = run(dir, '--fail-on', 'bogus');
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown --fail-on mode "bogus"/);
  r = run(dir, '--fail-on', 'new');
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--fail-on new needs --baseline/);
  assert.ok(!existsSync(join(dir, 'vex.cdx.json')));
});

test('--fail-on new without a license that covers --baseline never fails the build, and says twice that no gate ran', () => {
  const dir = project();
  assert.equal(run(dir, '--out', 'old.json').status, 0);
  const env = { ...process.env, VEXPROOF_LICENSE: '', GITHUB_ACTIONS: 'true' };
  const r = spawnSync(process.execPath, [CLI, '--lockfile', 'lock.json', '--bundle', 'bundle.json', '--findings', 'f.json', '--quiet', '--baseline', 'old.json', '--fail-on', 'new', '--out', 'new.json'], { cwd: dir, encoding: 'utf8', env });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stderr.match(/WARNING: --fail-on new did not run/g)?.length, 2);
  assert.match(r.stdout, /^::warning title=vexproof gate did not run::/m);
  assert.ok(existsSync(join(dir, 'new.json')));
});

test('verify without --key says the signer is unchecked', { skip: !existsSync(new URL('../src/pro/sign.js', import.meta.url)) && 'no Pro files' }, async () => {
  const { generateSigningKey, signCycloneDx, loadPrivateKey } = await import('../src/pro/sign.js');
  const dir = mkdtempSync(join(tmpdir(), 'vxp-verify-'));
  const k = generateSigningKey();
  put(dir, 'v.json', JSON.stringify(signCycloneDx({ bomFormat: 'CycloneDX', specVersion: '1.6', vulnerabilities: [] }, loadPrivateKey(k.privateKeyPem))));
  put(dir, 'pub.pem', k.publicKeyPem);
  let r = spawnSync(process.execPath, [CLI, 'verify', 'v.json'], { cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /not who signed it/);
  r = spawnSync(process.execPath, [CLI, 'verify', 'v.json', '--key', 'pub.pem'], { cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /not who signed it/);
});

// ---------- webpack: a configuration array ----------

const fakeCompiler = (context, outDir, modules, asset) => {
  let done;
  return {
    context, outputPath: join(context, outDir), webpack: { version: '5.0.0' },
    hooks: { done: { tap: (_name, fn) => { done = fn; } } },
    finish: () => done({ toJson: () => ({ modules, assets: [{ name: asset, size: 12, chunks: [1] }], chunks: [], children: [] }) }),
  };
};

test('VexproofPlugin: every configuration of an array is in the module map, not only the last', () => {
  const { VexproofPlugin } = require('../src/webpack.cjs');
  const dir = mkdtempSync(join(tmpdir(), 'vxp-multi-'));
  put(dir, 'dist-a/main.js', 'aaaaaaaaaaaa');
  put(dir, 'dist-b/main.js', 'bbbbbbbbbbbb');
  const a = fakeCompiler(dir, 'dist-a', [{ name: './node_modules/left-pad/index.js', chunks: [1] }], 'main.js');
  const b = fakeCompiler(dir, 'dist-b', [{ name: './node_modules/is-odd/index.js', chunks: [1] }], 'main.js');
  new VexproofPlugin().apply(a);
  new VexproofPlugin().apply(b);
  a.finish();
  const file = join(dir, 'vexproof-modules.json');
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).vexproofOutDir, 'dist-a', 'one configuration: its own stats, as before');
  b.finish();
  const json = JSON.parse(readFileSync(file, 'utf8'));
  assert.deepEqual(json.children.map((c) => c.outputPath), ['dist-a', 'dist-b']);
  const mm = readModuleMap(json);
  assert.ok(mm.packages.has('left-pad') && mm.packages.has('is-odd'));
  assert.match(mm.format, /^webpack-stats \(webpack 5/);
  const { stray, dirs } = strayOutputs(json, { root: dir, file });
  assert.deepEqual(stray, []);
  assert.equal(dirs.length, 2);
  // a rebuild in watch mode replaces that configuration's record
  a.finish();
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).children.length, 2);
});

test('webpack stats of a configuration array: child compilations of each configuration are read', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vxp-multi2-'));
  put(dir, 'dist-a/main.js', 'aaaaaaaaaaaa');
  put(dir, 'dist-a/worker.js', 'wwwwwwwwwwww');
  const json = { children: [{
    outputPath: 'dist-a', modules: [{ name: './src/a.js', chunks: [1] }], assets: [{ name: 'main.js', size: 12, chunks: [1] }],
    children: [{ modules: [{ name: './node_modules/in-worker/index.js', chunks: [7] }], assets: [{ name: 'worker.js', size: 12, chunks: [7] }] }],
  }] };
  assert.ok(readModuleMap(structuredClone(json)).packages.has('in-worker'));
  assert.deepEqual(strayOutputs(json, { root: dir, file: join(dir, 'stats.json') }).stray, []);
});

// ---------- Vite: watch mode ----------

test('vite plugin: a watch rebuild drops the records of chunks it no longer writes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vxp-watch-'));
  const p = vexproof({ root: dir });
  p.configResolved({ root: dir, build: { outDir: 'dist' } });
  const build = (name) => {
    p.buildStart.call({ meta: { rollupVersion: '4', watchMode: true } });
    put(dir, `dist/${name}`, 'x');
    p.generateBundle.call({}, { dir: join(dir, 'dist') }, { [name]: { type: 'chunk', fileName: name, modules: { [join(dir, 'node_modules/x/i.js')]: { renderedLength: 10 } } } });
    p.closeBundle();
    return Object.keys(JSON.parse(readFileSync(join(dir, 'vexproof-modules.json'), 'utf8')).outputs);
  };
  assert.deepEqual(build('app-111.js'), ['dist/app-111.js']);
  // the old file is still on disk (emptyOutDir off): its record stays
  assert.deepEqual(build('app-222.js').sort(), ['dist/app-111.js', 'dist/app-222.js']);
  rmSync(join(dir, 'dist/app-111.js'));
  assert.deepEqual(build('app-333.js').sort(), ['dist/app-222.js', 'dist/app-333.js']);
});

// ---------- rules derive: downloads are checked ----------

test('a registry tarball must match the checksum the registry lists for it', () => {
  const bytes = Buffer.from('tarball');
  const sha512 = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
  const sha1 = createHash('sha1').update(bytes).digest('hex');
  checkTarball(bytes, { integrity: sha512 }, 'x@1.0.0');
  checkTarball(bytes, { integrity: `sha1-AAAA ${sha512}` }, 'x@1.0.0');
  checkTarball(bytes, { shasum: sha1 }, 'x@1.0.0');
  assert.throws(() => checkTarball(Buffer.from('other'), { integrity: sha512 }, 'x@1.0.0'), /does not match the registry's checksum \(sha512\)/);
  assert.throws(() => checkTarball(Buffer.from('other'), { shasum: sha1 }, 'x@1.0.0'), /checksum \(sha1\)/);
  assert.throws(() => checkTarball(bytes, {}, 'x@1.0.0'), /lists no checksum/);
  assert.throws(() => checkTarball(bytes, undefined, 'x@1.0.0'), /lists no checksum/);
});

// ---------- the package ----------

test('every entry point has types, and package.json can be read through exports', () => {
  const pkg = require('../package.json');
  for (const [name, e] of Object.entries(pkg.exports)) {
    if (name === './package.json') continue;
    assert.ok(existsSync(new URL(`../${e.types}`, import.meta.url)), `${name} types`);
    assert.ok(existsSync(new URL(`../${e.default}`, import.meta.url)), `${name} code`);
  }
  assert.equal(pkg.exports['./package.json'], './package.json');
});

test('the Action runs the version it was released as unless the workflow names one', () => {
  const action = readFileSync(new URL('../action.yml', import.meta.url), 'utf8');
  assert.doesNotMatch(action, /default: latest/);
  assert.match(action, /ACTION_PATH: \$\{\{ github\.action_path \}\}/);
  assert.equal(action.match(/"\$ACTION_PATH\/package\.json"/g)?.length, 2, 'both steps resolve the same version');
});
