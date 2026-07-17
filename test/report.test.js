'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan, DEFAULT_LIMITS } = require('../lib/scan');
const { renderText, renderJson, renderSarif } = require('../lib/report');

const BAD_MV3 = path.join(__dirname, '..', 'fixtures', 'bad-mv3');
const GOOD_MV3 = path.join(__dirname, '..', 'fixtures', 'good-mv3');
const PRIVACY = path.join(__dirname, '..', 'fixtures', 'privacy-sentinel');

// Minimal hand-built result/finding objects for tests that need to control
// exactly which fields differ (line/column vs. detectorKey) - renderSarif is
// a pure function of this shape, so it needs no real scan() or fixture file.
function fakeResult(findings) {
  return {
    tool: { name: 'cws-gate', version: '0.0.0-test' },
    ruleset: { id: 'validation-beta', version: '2026-07-16', policyAsOf: '2026-07-16' },
    disclaimer: 'test disclaimer',
    status: 'complete',
    thresholdTriggered: false,
    operationalError: undefined,
    summary: { errors: 0, warnings: 0, notes: 0, filesScanned: 0, bytesScanned: 0, findingsTruncated: false },
    findings,
  };
}

function fakeFinding(overrides) {
  return {
    ruleId: 'CWSG011',
    level: 'error',
    message: 'test message',
    path: 'popup.html',
    line: 1,
    column: 1,
    fix: 'fix it',
    policyUrl: 'https://example.com',
    policyAsOf: '2026-07-16',
    detectorKey: 'cwsg011-abc-0',
    ...overrides,
  };
}

test('renderText includes every finding, the summary line, and the disclaimer', () => {
  const result = scan(BAD_MV3);
  const text = renderText(result);
  for (const f of result.findings) {
    assert.ok(text.includes(f.ruleId), `text should mention ${f.ruleId}`);
  }
  assert.match(text, /Summary: \d+ error/);
  assert.ok(text.includes(result.disclaimer));
});

test('renderText on a clean scan says so plainly', () => {
  const text = renderText(scan(GOOD_MV3));
  assert.match(text, /No findings\./);
});

test('renderText sanitizes CR/LF and other control characters out of finding path/message (GitHub Actions workflow-command injection)', () => {
  const malicious = fakeFinding({
    path: 'evil.html\n::error::injected-via-path',
    message: 'benign text\r\n::error::injected-via-message',
  });
  const text = renderText(fakeResult([malicious]));

  assert.ok(!text.includes('\n::error::'), 'a raw LF immediately before "::error::" must never survive into the report');
  assert.ok(!text.includes('\r'), 'CR is stripped too');

  const injectedLines = text.split('\n').filter((l) => l.startsWith('::error::'));
  assert.equal(injectedLines.length, 0, 'attacker-controlled path/message must never start its own output line');
});

test('renderJson is valid JSON, omits exitCode, keeps everything else', () => {
  const result = scan(BAD_MV3);
  const json = JSON.parse(renderJson(result));
  assert.equal(json.exitCode, undefined, 'exitCode is a process concern, not report content');
  assert.equal(json.status, result.status);
  assert.equal(json.findings.length, result.findings.length);
  assert.equal(json.disclaimer, result.disclaimer);
  assert.ok(json.privacy);
  assert.equal(json.privacy.network, 'none');
});

test('renderSarif is well-formed 2.1.0 with stable rule descriptors and deterministic fingerprints', () => {
  const result = scan(BAD_MV3);
  const sarif = JSON.parse(renderSarif(result));
  assert.equal(sarif.version, '2.1.0');
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'cws-gate');
  assert.equal(run.tool.driver.rules.length, 16, 'all 16 frozen rules are static descriptors regardless of what fired');
  assert.equal(run.results.length, result.findings.length);
  assert.equal(run.invocations[0].executionSuccessful, true);

  for (const r of run.results) {
    assert.ok(r.partialFingerprints['cwsGate/v1']);
    assert.equal(r.locations[0].physicalLocation.artifactLocation.uri.startsWith('/'), false, 'relative, not absolute');
  }

  const again = JSON.parse(renderSarif(result));
  assert.deepEqual(
    run.results.map((r) => r.partialFingerprints['cwsGate/v1']),
    again.runs[0].results.map((r) => r.partialFingerprints['cwsGate/v1']),
    'identical input renders identical fingerprints - no timestamp or salt',
  );
});

test('renderSarif on an operational failure marks the invocation unsuccessful', () => {
  const result = scan(path.join(__dirname, 'this-directory-does-not-exist-at-all'));
  const sarif = JSON.parse(renderSarif(result));
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, false);
  assert.ok(sarif.runs[0].invocations[0].toolExecutionNotifications[0].message.text);
});

test('privacy sentinel: source secrets and the absolute fixture path never appear in any rendered report', () => {
  const result = scan(PRIVACY);
  // A sanity floor, not just a vacuous pass: CWSG008/010/011/012/014 (and the
  // pre-existing CWSG013) must actually fire for this assertion to mean
  // anything.
  assert.ok(result.findings.length >= 5, 'the fixture must genuinely exercise CWSG008/010/011/012/014');
  const secrets = [
    'sk_live_should_never_appear_in_any_cws_gate_report',
    'sk_live_popup_secret_should_never_leak',
    'sk_live_csp_secret_should_never_leak',
    'sk_live_host_secret_should_never_leak',
    'sk_live_importscripts_secret_should_never_leak',
    'sk_live_html_secret_should_never_leak',
  ];
  const rendered = { text: renderText(result), json: renderJson(result), sarif: renderSarif(result) };
  for (const [name, output] of Object.entries(rendered)) {
    for (const secret of secrets) {
      assert.ok(!output.includes(secret), `${name} report must never include secret "${secret}"`);
    }
    assert.ok(!output.includes(PRIVACY), `${name} report must never include the absolute fixture path`);
    assert.ok(!output.includes(process.cwd()), `${name} report must never include the machine's cwd`);
  }
});

test('renderSarif fingerprint formula: identical ruleId/path/detectorKey fingerprints identically regardless of line/column', () => {
  const result = fakeResult([fakeFinding({ path: 'a.html', line: 5, column: 1, detectorKey: 'cwsg011-aaa-0' })]);
  const shifted = fakeResult([fakeFinding({ path: 'a.html', line: 99, column: 40, detectorKey: 'cwsg011-aaa-0' })]);
  const fp1 = JSON.parse(renderSarif(result)).runs[0].results[0].partialFingerprints['cwsGate/v1'];
  const fp2 = JSON.parse(renderSarif(shifted)).runs[0].results[0].partialFingerprints['cwsGate/v1'];
  assert.equal(fp1, fp2, 'the fingerprint must depend only on ruleId|path|detectorKey, never line/column');
});

test('renderSarif fingerprint: same-line duplicate findings with distinct detectorKeys fingerprint differently', () => {
  const result = fakeResult([
    fakeFinding({ path: 'a.html', line: 5, column: 1, detectorKey: 'cwsg011-aaa-0' }),
    fakeFinding({ path: 'a.html', line: 5, column: 40, detectorKey: 'cwsg011-aaa-1' }),
  ]);
  const [r1, r2] = JSON.parse(renderSarif(result)).runs[0].results;
  assert.notEqual(
    r1.partialFingerprints['cwsGate/v1'], r2.partialFingerprints['cwsGate/v1'],
    'two same-line findings must not collide just because they share a line/column',
  );
});

test('renderSarif fingerprint: a harmless earlier line shift leaves an existing finding\'s fingerprint stable', () => {
  // Simulates a file gaining one harmless extra line above an existing match:
  // the finding's line shifts down but its content (and therefore
  // detectorKey) is unchanged, so the SARIF fingerprint must not move either.
  const before = fakeResult([fakeFinding({ path: 'a.html', line: 10, detectorKey: 'cwsg011-xyz-0' })]);
  const after = fakeResult([fakeFinding({ path: 'a.html', line: 11, detectorKey: 'cwsg011-xyz-0' })]);
  const fp1 = JSON.parse(renderSarif(before)).runs[0].results[0].partialFingerprints['cwsGate/v1'];
  const fp2 = JSON.parse(renderSarif(after)).runs[0].results[0].partialFingerprints['cwsGate/v1'];
  assert.equal(fp1, fp2);
});

test('renderSarif: a rootPrefix produces a repo-root-relative uri directly, with no uriBaseId indirection', () => {
  const result = fakeResult([fakeFinding({ path: 'popup.html' })]);

  const withoutPrefix = JSON.parse(renderSarif(result));
  const locNoPrefix = withoutPrefix.runs[0].results[0].locations[0].physicalLocation.artifactLocation;
  assert.equal(locNoPrefix.uri, 'popup.html', 'no argument means package-relative, unchanged');
  assert.equal(locNoPrefix.uriBaseId, undefined);
  assert.equal(withoutPrefix.runs[0].originalUriBaseIds, undefined);

  const withPrefix = JSON.parse(renderSarif(result, 'ventures/cws-gate'));
  const loc = withPrefix.runs[0].results[0].locations[0].physicalLocation.artifactLocation;
  assert.equal(loc.uri, 'ventures/cws-gate/popup.html', 'uri is the repo-root-relative path directly, forward slashes, no leading slash');
  assert.equal(loc.uriBaseId, undefined, 'the uriBaseId mechanism is dropped entirely');
  assert.equal(withPrefix.runs[0].originalUriBaseIds, undefined, 'originalUriBaseIds is dropped entirely');
});

test('renderSarif: a Windows-style or leading-slash rootPrefix normalizes to forward slashes with no leading/trailing slash', () => {
  const result = fakeResult([fakeFinding({ path: 'popup.html' })]);

  const backslashes = JSON.parse(renderSarif(result, 'ventures\\cws-gate\\'));
  assert.equal(
    backslashes.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    'ventures/cws-gate/popup.html',
  );

  const leadingSlash = JSON.parse(renderSarif(result, '/ventures/cws-gate/'));
  assert.equal(
    leadingSlash.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    'ventures/cws-gate/popup.html',
    'a leading slash on the prefix must not produce a double slash in the uri',
  );
});

test('renderSarif: primaryLocationLineHash is present, content-derived, stable across a harmless line shift, and distinct for same-line duplicates', () => {
  const before = fakeResult([fakeFinding({ path: 'a.html', line: 10, detectorKey: 'cwsg011-xyz-0' })]);
  const after = fakeResult([fakeFinding({ path: 'a.html', line: 11, detectorKey: 'cwsg011-xyz-0' })]);
  const h1 = JSON.parse(renderSarif(before)).runs[0].results[0].partialFingerprints.primaryLocationLineHash;
  const h2 = JSON.parse(renderSarif(after)).runs[0].results[0].partialFingerprints.primaryLocationLineHash;
  assert.ok(h1, 'primaryLocationLineHash is present');
  assert.equal(h1, h2, 'a line shift alone must not change the alert-identity hash');

  const duplicates = fakeResult([
    fakeFinding({ path: 'a.html', line: 5, column: 1, detectorKey: 'cwsg011-aaa-0' }),
    fakeFinding({ path: 'a.html', line: 5, column: 40, detectorKey: 'cwsg011-aaa-1' }),
  ]);
  const [r1, r2] = JSON.parse(renderSarif(duplicates)).runs[0].results;
  assert.notEqual(
    r1.partialFingerprints.primaryLocationLineHash, r2.partialFingerprints.primaryLocationLineHash,
    'two same-line findings must not collide just because they share a line/column',
  );

  // 'cwsGate/v1' is kept alongside the new key, unaffected.
  assert.ok(JSON.parse(renderSarif(before)).runs[0].results[0].partialFingerprints['cwsGate/v1']);
});

test('renderSarif: primaryLocationLineHash moves with rootPrefix (keyed on the emitted uri) while cwsGate/v1 does not (keyed on package-relative path)', () => {
  const result = fakeResult([fakeFinding({ path: 'popup.html', detectorKey: 'cwsg011-abc-0' })]);
  const packageRelative = JSON.parse(renderSarif(result)).runs[0].results[0].partialFingerprints;
  const rootRelative = JSON.parse(renderSarif(result, 'nested/ext-dir')).runs[0].results[0].partialFingerprints;
  assert.equal(packageRelative['cwsGate/v1'], rootRelative['cwsGate/v1'], 'cwsGate/v1 never moves just from a rootPrefix');
  assert.notEqual(
    packageRelative.primaryLocationLineHash, rootRelative.primaryLocationLineHash,
    'primaryLocationLineHash is keyed on the actual emitted uri, so two repo-root locations do not collide',
  );
});

test('both real callers (CLI, Action) invoke renderSarif with one argument (or an equivalent empty prefix), so default output stays package-relative and byte-compatible', () => {
  const result = scan(BAD_MV3);
  const noArg = JSON.parse(renderSarif(result));
  const emptyPrefix = JSON.parse(renderSarif(result, ''));
  assert.deepEqual(emptyPrefix, noArg, 'an explicit empty-string prefix renders byte-identically to the no-argument call');
  assert.equal(noArg.runs[0].originalUriBaseIds, undefined);
  assert.equal(noArg.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uriBaseId, undefined);
  assert.equal(
    noArg.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    result.findings[0].path,
    'package-relative uri equals the finding\'s own path when no prefix is given',
  );
});

test('a structural cap hit renders zero findings in JSON and SARIF too, not just text', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-report-cap-'));
  fs.writeFileSync(
    path.join(tmp, 'manifest.json'),
    JSON.stringify({
      manifest_version: 3,
      name: 'Cap',
      version: '1.0.0',
      description: 'd',
      icons: { 128: 'i.png' },
      content_security_policy: { extension_pages: "script-src 'unsafe-eval'" },
    }),
  );
  fs.writeFileSync(path.join(tmp, 'i.png'), 'x');
  const result = scan(tmp, { limits: { ...DEFAULT_LIMITS, maxFiles: 1 } });
  assert.equal(result.status, 'incomplete');
  const json = JSON.parse(renderJson(result));
  assert.equal(json.findings.length, 0, 'JSON must not leak partial findings on a structural cap hit');
  const sarif = JSON.parse(renderSarif(result));
  assert.equal(sarif.runs[0].results.length, 0, 'SARIF must not leak partial findings on a structural cap hit');
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, false);
});
