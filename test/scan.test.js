'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan, DEFAULT_LIMITS, readCappedText, walk } = require('../lib/scan');
const { EXPECTATIONS } = require('../fixtures/expectations');

const GOOD_MV3 = path.join(__dirname, '..', 'fixtures', 'good-mv3');
const BAD_MV3 = path.join(__dirname, '..', 'fixtures', 'bad-mv3');

function assertFindingsMatch(actual, expected) {
  assert.equal(actual.length, expected.length, 'finding count');
  actual.forEach((f, i) => {
    assert.equal(f.ruleId, expected[i].ruleId, `finding[${i}].ruleId`);
    assert.equal(f.level, expected[i].level, `finding[${i}].level`);
    assert.equal(f.path, expected[i].path, `finding[${i}].path`);
    assert.equal(f.line, expected[i].line, `finding[${i}].line`);
  });
}

// The full fixture set (not just the fast selfCheck subset) against the same
// single source of truth self-check uses.
for (const [name, entry] of Object.entries(EXPECTATIONS)) {
  test(`fixture "${name}" matches expectations exactly`, () => {
    const result = scan(entry.dir);
    assert.equal(result.status, entry.expected.status, 'status');
    assert.equal(result.exitCode, entry.expected.exitCode, 'exitCode');
    assert.equal(result.thresholdTriggered, entry.expected.thresholdTriggered, 'thresholdTriggered');
    for (const key of Object.keys(entry.expected.summary)) {
      assert.equal(result.summary[key], entry.expected.summary[key], `summary.${key}`);
    }
    assertFindingsMatch(result.findings, entry.expected.findings);
  });
}

test('a missing directory is an operational failure, not a crash', () => {
  const result = scan(path.join(os.tmpdir(), 'cws-gate-does-not-exist-' + Date.now()));
  assert.equal(result.status, 'incomplete');
  assert.equal(result.exitCode, 2);
  assert.ok(result.operationalError);
});

test('a file path (not a directory) is an operational failure', () => {
  const result = scan(__filename);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.exitCode, 2);
});

test('an invalid --fail-on value is an operational failure', () => {
  const result = scan(GOOD_MV3, { failOn: 'bogus' });
  assert.equal(result.status, 'incomplete');
  assert.equal(result.exitCode, 2);
  assert.match(result.operationalError, /fail-on/);
});

test('fail-on: never disables the threshold regardless of findings', () => {
  const result = scan(BAD_MV3, { failOn: 'never' });
  assert.equal(result.thresholdTriggered, false);
  assert.equal(result.exitCode, 0);
});

test('fail-on: note fails on note-level findings too', () => {
  const result = scan(BAD_MV3, { failOn: 'note' });
  assert.equal(result.thresholdTriggered, true);
  assert.equal(result.exitCode, 1);
});

test('symlinks inside the scanned tree are never followed (outside-root escape vector)', (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-symlink-'));
  const outside = path.join(tmp, 'outside-secret.js');
  fs.writeFileSync(outside, 'eval("outside the package root, should never be scanned");');
  const root = path.join(tmp, 'pkg');
  fs.mkdirSync(root);
  fs.writeFileSync(
    path.join(root, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'Symlink test', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } }),
  );
  fs.writeFileSync(path.join(root, 'i.png'), 'x');
  try {
    fs.symlinkSync(outside, path.join(root, 'linked.js'));
  } catch (err) {
    t.skip(`symlink creation not permitted in this environment: ${err.message}`);
    return;
  }
  const result = scan(root);
  assert.ok(!result.findings.some((f) => f.path.includes('linked')), 'the symlink is never listed as a scanned file');
  assert.equal(result.summary.filesScanned, 2, 'manifest.json + i.png only; the symlink is skipped, not followed');
});

test('structural caps (file count) mark the scan incomplete with exit code 2', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-caps-'));
  fs.writeFileSync(
    path.join(tmp, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'Caps', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } }),
  );
  fs.writeFileSync(path.join(tmp, 'i.png'), 'x');
  for (let i = 0; i < 5; i++) fs.writeFileSync(path.join(tmp, `extra${i}.txt`), 'x');
  const result = scan(tmp, { limits: { ...DEFAULT_LIMITS, maxFiles: 3 } });
  assert.equal(result.status, 'incomplete');
  assert.equal(result.exitCode, 2, 'incomplete always exits 2 regardless of fail-on or findings');
  assert.equal(result.findings.length, 0, 'a structural cap hit reports zero findings, never a partial list');
  assert.ok(result.operationalError, 'a generic operational reason is present');
});

test('structural caps (total bytes) mark the scan incomplete with zero findings, not a partial result', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-bytecap-'));
  fs.writeFileSync(
    path.join(tmp, 'manifest.json'),
    JSON.stringify({
      manifest_version: 3,
      name: 'Bytecap',
      version: '1.0.0',
      description: 'd',
      icons: { 128: 'i.png' },
      content_security_policy: { extension_pages: "script-src 'unsafe-eval'" },
    }),
  );
  fs.writeFileSync(path.join(tmp, 'i.png'), Buffer.alloc(1000));
  const result = scan(tmp, { limits: { ...DEFAULT_LIMITS, maxTotalBytes: 10 } });
  assert.equal(result.status, 'incomplete');
  assert.equal(result.exitCode, 2);
  assert.equal(result.findings.length, 0, 'a byte-cap hit must not leak the CWSG010 finding a full scan would have computed');
  assert.ok(result.operationalError);
});

test('walk(): a directory whose readdirSync throws mid-traversal sets traversalError, not just a silent skip', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-walk-flag-'));
  const stuck = path.join(tmp, 'stuck-dir');
  fs.mkdirSync(stuck);
  fs.writeFileSync(path.join(stuck, 'inner.js'), 'eval("hidden");');
  fs.writeFileSync(path.join(tmp, 'ok.txt'), 'x');

  const originalReaddirSync = fs.readdirSync;
  // Monkeypatch fs.readdirSync for the duration of this one synchronous
  // call, same pattern test/network-guard.test.js already uses for
  // fs/net stubs; walk() is fully synchronous so there is no interleaving
  // risk, and the original is always restored in finally.
  fs.readdirSync = function (dir, ...rest) {
    if (path.resolve(String(dir)) === path.resolve(stuck)) {
      throw Object.assign(new Error('simulated EACCES'), { code: 'EACCES' });
    }
    return originalReaddirSync.call(fs, dir, ...rest);
  };
  let result;
  try {
    result = walk(tmp, DEFAULT_LIMITS);
  } finally {
    fs.readdirSync = originalReaddirSync;
  }
  assert.equal(result.traversalError, true, 'a readdirSync throw for any directory must set traversalError, not just continue silently');
  assert.ok(!result.files.some((f) => f.path.includes('inner.js')), 'the unreadable subdirectory contributes no files');
});

test('scan(): an entry whose lstat throws mid-walk marks the whole scan incomplete, never silently "complete"', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-walk-lstat-err-'));
  fs.writeFileSync(
    path.join(tmp, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'Walkerr', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } }),
  );
  fs.writeFileSync(path.join(tmp, 'i.png'), 'x');
  const flaky = path.join(tmp, 'flaky.js');
  fs.writeFileSync(flaky, 'eval("hidden");');

  const originalLstatSync = fs.lstatSync;
  fs.lstatSync = function (p, ...rest) {
    if (path.resolve(String(p)) === path.resolve(flaky)) {
      throw Object.assign(new Error('simulated race: gone before lstat'), { code: 'ENOENT' });
    }
    return originalLstatSync.call(fs, p, ...rest);
  };
  let result;
  try {
    result = scan(tmp);
  } finally {
    fs.lstatSync = originalLstatSync;
  }
  assert.equal(result.status, 'incomplete', 'an entry whose lstat failed must never be silently skipped from an otherwise "complete" result');
  assert.equal(result.exitCode, 2);
  assert.equal(result.findings.length, 0);
  assert.ok(result.operationalError);
  assert.match(result.operationalError, /could not be fully read/i);
});

test('content-inspection caps (max findings) truncate gracefully without forcing incomplete', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-findings-cap-'));
  fs.writeFileSync(
    path.join(tmp, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'Findings cap', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } }),
  );
  fs.writeFileSync(path.join(tmp, 'i.png'), 'x');
  fs.writeFileSync(path.join(tmp, 'bg.js'), Array.from({ length: 5 }, () => 'eval("x");').join('\n'));
  const result = scan(tmp, { limits: { ...DEFAULT_LIMITS, maxFindings: 2 } });
  assert.equal(result.status, 'complete', 'a findings-cap hit is content-level, not structural incompleteness');
  assert.equal(result.summary.findingsTruncated, true);
  assert.equal(result.findings.length, 2);
});

test('a failOn value that collides with an Object.prototype property is still invalid, not a gate bypass', () => {
  for (const bogus of ['toString', 'constructor', 'hasOwnProperty', '__proto__']) {
    const result = scan(GOOD_MV3, { failOn: bogus });
    assert.equal(result.status, 'incomplete', `"${bogus}" must be rejected as an invalid --fail-on value`);
    assert.equal(result.exitCode, 2);
  }
});

test('an oversized manifest.json is treated as invalid rather than fully read into memory', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-manifest-cap-'));
  const bigManifest = JSON.stringify({
    manifest_version: 3,
    name: 'Big',
    version: '1.0.0',
    description: 'd',
    icons: { 128: 'i.png' },
    padding: 'x'.repeat(200),
  });
  fs.writeFileSync(path.join(tmp, 'manifest.json'), bigManifest);
  fs.writeFileSync(path.join(tmp, 'i.png'), 'x');
  const result = scan(tmp, { limits: { ...DEFAULT_LIMITS, maxFileTextBytes: 100 } });
  assert.equal(result.status, 'complete', 'an oversized manifest is a content problem, not structural incompleteness');
  assert.ok(result.findings.some((f) => f.ruleId === 'CWSG001'), 'oversized manifest.json is reported as CWSG001 (unreadable)');
});

test('a manifest.json with a leading UTF-8 BOM parses successfully, matching Chrome\'s own reader', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-bom-'));
  const manifest = { manifest_version: 3, name: 'BOM', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } };
  fs.writeFileSync(path.join(tmp, 'manifest.json'), '﻿' + JSON.stringify(manifest));
  fs.writeFileSync(path.join(tmp, 'i.png'), 'x');
  const result = scan(tmp);
  assert.ok(!result.findings.some((f) => f.ruleId === 'CWSG001'), 'a BOM-prefixed manifest must not be reported as invalid JSON');
});

test('structural caps (directory count) mark the scan incomplete even with very few files', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-dircap-'));
  fs.writeFileSync(
    path.join(tmp, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'Dircap', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } }),
  );
  fs.writeFileSync(path.join(tmp, 'i.png'), 'x');
  for (let i = 0; i < 10; i++) fs.mkdirSync(path.join(tmp, `empty${i}`));
  const result = scan(tmp, { limits: { ...DEFAULT_LIMITS, maxFiles: 5 } });
  assert.equal(result.status, 'incomplete', 'many directories must trip a structural cap even though file count alone is small');
  assert.equal(result.exitCode, 2);
  assert.equal(result.findings.length, 0, 'a structural cap hit reports zero findings, never a partial list');
});

test('a binary (NUL-containing) file is skipped as content, not read as text', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-binary-'));
  fs.writeFileSync(
    path.join(tmp, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'Binary', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } }),
  );
  fs.writeFileSync(path.join(tmp, 'i.png'), 'x');
  fs.writeFileSync(path.join(tmp, 'bg.js'), Buffer.from('eval("x");\0binary-noise-after-nul'));
  const result = scan(tmp);
  assert.equal(
    result.status, 'incomplete',
    'a targeted JS file that could not be fully read makes the whole scan operationally incomplete, not silently partial',
  );
  assert.equal(result.exitCode, 2);
  assert.equal(result.findings.length, 0, 'an incomplete scan reports zero findings, never a partial list');
  assert.ok(result.operationalError, 'a generic operational reason is present');
});

test('a targeted JS file over the per-file text cap makes the scan operationally incomplete', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-textcap-'));
  fs.writeFileSync(
    path.join(tmp, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'Textcap', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } }),
  );
  fs.writeFileSync(path.join(tmp, 'i.png'), 'x');
  fs.writeFileSync(path.join(tmp, 'bg.js'), 'x'.repeat(1000));
  const result = scan(tmp, { limits: { ...DEFAULT_LIMITS, maxFileTextBytes: 10 } });
  assert.equal(result.status, 'incomplete');
  assert.equal(result.exitCode, 2);
  assert.equal(result.findings.length, 0, 'the over-cap file must not simply be skipped from an otherwise "complete" result');
  assert.ok(result.operationalError);
});

test('the shared total text budget running out mid-scan makes the scan operationally incomplete', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-textbudget-'));
  fs.writeFileSync(
    path.join(tmp, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'Textbudget', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } }),
  );
  fs.writeFileSync(path.join(tmp, 'i.png'), 'x');
  fs.writeFileSync(path.join(tmp, 'a.js'), 'x'.repeat(500));
  fs.writeFileSync(path.join(tmp, 'b.js'), 'y'.repeat(500));
  // Each file alone (500 bytes) is under the 1000-byte per-file cap, but the
  // pair together exceeds the 600-byte shared budget - this must trip the
  // budget branch specifically, independent of the per-file cap branch above.
  const result = scan(tmp, { limits: { ...DEFAULT_LIMITS, maxFileTextBytes: 1000, maxTotalTextBytes: 600 } });
  assert.equal(result.status, 'incomplete');
  assert.equal(result.exitCode, 2);
  assert.equal(result.findings.length, 0);
});

test('readCappedText: a read failure (e.g. a file gone missing) is reported, never thrown', () => {
  const nonexistent = path.join(os.tmpdir(), `cws-gate-readcappedtext-missing-${Date.now()}.js`);
  const outcome = readCappedText(nonexistent, 10, DEFAULT_LIMITS, { remaining: DEFAULT_LIMITS.maxTotalTextBytes });
  assert.equal(outcome.ok, false);
});

test('readCappedText: a successful read returns the text and debits the shared budget', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-readcappedtext-'));
  const p = path.join(tmp, 'a.js');
  fs.writeFileSync(p, 'hello');
  const budget = { remaining: 1000 };
  const outcome = readCappedText(p, 5, DEFAULT_LIMITS, budget);
  assert.equal(outcome.ok, true);
  assert.equal(outcome.text, 'hello');
  assert.equal(budget.remaining, 995, 'the buffer length actually read is debited from the shared budget');
});

test('readCappedText: cachedSize already over the per-file cap is rejected without touching the filesystem', () => {
  const outcome = readCappedText(
    path.join(os.tmpdir(), 'cws-gate-readcappedtext-never-opened.js'),
    DEFAULT_LIMITS.maxFileTextBytes + 1,
    DEFAULT_LIMITS,
    { remaining: DEFAULT_LIMITS.maxTotalTextBytes },
  );
  assert.equal(outcome.ok, false);
});

test('CWSG002 wrapper-directory finding never echoes the raw wrapper directory name', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-wrapper-'));
  const wrapperName = 'sk_live_should_never_leak_wrapper_dir_name';
  const wrapper = path.join(tmp, wrapperName);
  fs.mkdirSync(wrapper);
  fs.writeFileSync(
    path.join(wrapper, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'Wrapper', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } }),
  );
  fs.writeFileSync(path.join(wrapper, 'i.png'), 'x');
  const result = scan(tmp);
  assert.equal(result.status, 'complete');
  assert.ok(result.findings.some((f) => f.ruleId === 'CWSG002'), 'the fixture must actually exercise CWSG002');
  for (const f of result.findings) {
    assert.ok(!f.message.includes(wrapperName), 'the wrapper directory name must never be echoed into a finding message');
  }
});
