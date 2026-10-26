// SPDX-License-Identifier: MIT
// The package has two licenses. These tests keep the line between them where the LICENSE file says it is.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync, mkdtempSync, cpSync, symlinkSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const ROOT = new URL('..', import.meta.url).pathname;
const walk = (dir) => readdirSync(dir).flatMap((f) => { const p = join(dir, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
const sources = walk(join(ROOT, 'src')).filter((f) => /\.(js|cjs)$/.test(f));
const isPro = (f) => relative(ROOT, f).split(sep).join('/').startsWith('src/pro/');
const fx = (f) => new URL(`./fixtures/${f}`, import.meta.url).pathname;

test('every source file names its license, and the license matches where the file lives', () => {
  for (const f of sources) {
    const id = /SPDX-License-Identifier: (\S+)/.exec(readFileSync(f, 'utf8').split('\n').slice(0, 3).join('\n'))?.[1];
    assert.equal(id, isPro(f) ? 'LicenseRef-vexproof-Pro' : 'MIT', relative(ROOT, f));
  }
  assert.match(JSON.parse(readFileSync(join(ROOT, 'src/pro/rules/module-rules.json'))).license, /LicenseRef-vexproof-Pro/);
});

test('both license texts ship, and package.json names both', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json')));
  assert.equal(pkg.license, 'SEE LICENSE IN LICENSE'); // npm's form for a package that is not under one SPDX license
  assert.match(readFileSync(join(ROOT, 'LICENSE'), 'utf8'), /src\/pro\/LICENSE\.md[\s\S]*MIT License/);
  assert.ok(existsSync(join(ROOT, 'src/pro/LICENSE.md')));
  assert.ok(pkg.files.includes('src/') && pkg.files.includes('LICENSE'));
});

test('MIT files reach Pro only through the one optional import in the CLI', () => {
  for (const f of sources.filter((x) => !isPro(x))) {
    const refs = readFileSync(f, 'utf8').split('\n').filter((l) => /(from|import\(|require\()\s*['"][^'"]*\/pro\//.test(l));
    if (relative(ROOT, f) === join('src', 'cli.js')) assert.deepEqual(refs.map((l) => /import\('\.\/pro\/index\.js'\)\.catch/.test(l)), [true]);
    else assert.deepEqual(refs, [], relative(ROOT, f));
  }
});

test('with src/pro removed, the CLI still writes package-level VEX and offers nothing from Pro', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vexproof-mit-'));
  cpSync(join(ROOT, 'src'), join(dir, 'src'), { recursive: true, filter: (s) => !isPro(s + sep) && !s.endsWith(`${sep}pro`) });
  cpSync(join(ROOT, 'package.json'), join(dir, 'package.json'));
  symlinkSync(join(ROOT, 'node_modules'), join(dir, 'node_modules'));
  assert.ok(!existsSync(join(dir, 'src', 'pro')));
  const run = (...a) => spawnSync(process.execPath, [join(dir, 'src', 'cli.js'), '--lockfile', fx('recharts.bom.lockfile.json'), '--findings', fx('recharts.audit.json'), '--out', join(dir, 'vex.json'), ...a], { cwd: dir, encoding: 'utf8' });

  const pkgLevel = run('--bundle', fx('recharts.bom.bundle.json'));
  assert.equal(pkgLevel.status, 0, pkgLevel.stderr);
  const vex = JSON.parse(readFileSync(join(dir, 'vex.json')));
  assert.ok(vex.vulnerabilities.length > 0);
  assert.doesNotMatch(pkgLevel.stderr, /Pro would settle/);

  // a module map and Pro flags are accepted, but nothing settles at module level and nothing crashes
  const withMap = run('--modules', fx('recharts.metafile.json'), '--rules', fx('lodash.derived-rules.json'), '--report', join(dir, 'r.html'), '--license', 'vxp1.x.y');
  assert.equal(withMap.status, 0, withMap.stderr);
  assert.doesNotMatch(withMap.stdout, /\(module\)/);
  assert.match(withMap.stderr, /no Pro files/);
  assert.ok(!existsSync(join(dir, 'r.html')));
});
