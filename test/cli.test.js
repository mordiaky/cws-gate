'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { main } = require('../bin/cws-gate');
const pkg = require('../package.json');

const GOOD_MV3 = path.join(__dirname, '..', 'fixtures', 'good-mv3');
const BAD_MV3 = path.join(__dirname, '..', 'fixtures', 'bad-mv3');
const BIN = path.join(__dirname, '..', 'bin', 'cws-gate.js');

function fakeIo() {
  const out = [];
  const err = [];
  return {
    stdout: { write: (s) => out.push(s) },
    stderr: { write: (s) => err.push(s) },
    out: () => out.join(''),
    err: () => err.join(''),
  };
}

test('--version prints the package version and exits 0', () => {
  const io = fakeIo();
  const code = main(['--version'], io);
  assert.equal(code, 0);
  assert.equal(io.out(), `cws-gate ${pkg.version}\n`);
});

test('--help prints usage and exits 0', () => {
  const io = fakeIo();
  const code = main(['--help'], io);
  assert.equal(code, 0);
  assert.match(io.out(), /Usage: cws-gate/);
});

test('--self-check runs the bundled fixtures through the CLI and exits 0 on a healthy tree', () => {
  const io = fakeIo();
  const code = main(['--self-check'], io);
  assert.equal(code, 0);
  assert.match(io.out(), /self-check: PASS/);
});

test('an unknown flag is a CLI usage error: exit 2, message on stderr, no crash', () => {
  const io = fakeIo();
  const code = main(['--nonsense-flag'], io);
  assert.equal(code, 2);
  assert.ok(io.err().length > 0);
});

test('scanning a clean directory exits 0 and reports no findings', () => {
  const io = fakeIo();
  const code = main([GOOD_MV3], io);
  assert.equal(code, 0);
  assert.match(io.out(), /No findings\./);
});

test('--fail-on exit-code matrix against the bad-mv3 fixture (which has errors, warnings, and notes)', () => {
  const matrix = [
    ['error', 1],
    ['warn', 1],
    ['note', 1],
    ['never', 0],
  ];
  for (const [failOn, expectedCode] of matrix) {
    const io = fakeIo();
    const code = main([BAD_MV3, '--fail-on', failOn], io);
    assert.equal(code, expectedCode, `--fail-on ${failOn}`);
  }
});

test('an invalid --fail-on value is an operational error, exit 2', () => {
  const io = fakeIo();
  const code = main([GOOD_MV3, '--fail-on', 'bogus'], io);
  assert.equal(code, 2);
});

test('--json and --sarif write report files to the requested paths', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-cli-out-'));
  const jsonFile = path.join(tmp, 'out.json');
  const sarifFile = path.join(tmp, 'out.sarif');
  const io = fakeIo();
  const code = main([GOOD_MV3, '--json', jsonFile, '--sarif', sarifFile], io);
  assert.equal(code, 0);
  const json = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
  assert.equal(json.status, 'complete');
  const sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
  assert.equal(sarif.version, '2.1.0');
});

test('end-to-end: the published bin script runs as a real child process and prints a clean report', () => {
  const output = execFileSync(process.execPath, [BIN, GOOD_MV3], { encoding: 'utf8' });
  assert.match(output, /No findings\./);
});

test('end-to-end: the bin script process exit code mirrors the scan result', () => {
  let caught = null;
  try {
    execFileSync(process.execPath, [BIN, BAD_MV3], { encoding: 'utf8' });
  } catch (err) {
    caught = err;
  }
  assert.ok(caught, 'bad-mv3 has error-level findings, so the process must exit non-zero');
  assert.equal(caught.status, 1);
  assert.match(caught.stdout, /CWSG012/);
});
