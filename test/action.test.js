'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runAction, isPathInside, realOrNull, resolveOutputTarget, writeOutput } = require('../action/index');
// outputTargetsCollide now lives in lib/paths.js, shared with bin/cws-gate.js
// (see lib/paths.js and bin/cws-gate.js) - imported from its actual home
// rather than re-exported through action/index.js.
const { outputTargetsCollide } = require('../lib/paths');

const GOOD_MV3 = path.join(__dirname, '..', 'fixtures', 'good-mv3');
const BAD_MV3 = path.join(__dirname, '..', 'fixtures', 'bad-mv3');

function tmpOutputsFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-'));
  return path.join(dir, 'outputs.env');
}

function readOutputs(file) {
  const map = {};
  for (const line of fs.readFileSync(file, 'utf8').split('\n').filter(Boolean)) {
    const idx = line.indexOf('=');
    map[line.slice(0, idx)] = line.slice(idx + 1);
  }
  return map;
}

function fakeLog() {
  const lines = [];
  return { log: (s) => lines.push(s), all: () => lines.join('\n') };
}

test('runAction reads hyphenated input names via the INPUT_<NAME> convention (fail-on -> INPUT_FAIL-ON)', () => {
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const env = { 'INPUT_PATH': GOOD_MV3, 'INPUT_FAIL-ON': 'never', GITHUB_OUTPUT: outputsFile };
  const code = runAction(env, io);
  assert.equal(code, 0, '--fail-on never always exits 0 regardless of findings');
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'complete');
  assert.equal(outputs['threshold-triggered'], 'false');
});

test('runAction resolves a relative path input against GITHUB_WORKSPACE', () => {
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const env = {
    'INPUT_PATH': 'fixtures/good-mv3',
    GITHUB_WORKSPACE: path.join(__dirname, '..'),
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 0);
  assert.match(io.all(), /No findings\./);
});

test('runAction defaults path to "." and fail-on to "error" when those inputs are absent', () => {
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const env = { GITHUB_WORKSPACE: GOOD_MV3, GITHUB_OUTPUT: outputsFile };
  const code = runAction(env, io);
  assert.equal(code, 0);
});

// json-file/sarif-file must now themselves resolve inside GITHUB_WORKSPACE
// (same as `path`), so the report targets live inside a fresh workspace
// directory alongside a small intentionally-bad manifest (mirrors bad-mv3's
// shape closely enough to guarantee findings) rather than pointing at an
// unrelated os.tmpdir() directory outside any workspace.
test('runAction writes json-file and sarif-file reports and their outputs when those inputs are set', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-reports-'));
  fs.writeFileSync(
    path.join(workspace, 'manifest.json'),
    JSON.stringify({ manifest_version: 2, name: 'Bad', version: '1.0.0', description: 'd' }),
  );
  const jsonFile = path.join(workspace, 'out.json');
  const sarifFile = path.join(workspace, 'out.sarif');
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_FAIL-ON': 'never',
    'INPUT_JSON-FILE': jsonFile,
    'INPUT_SARIF-FILE': sarifFile,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 0);
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs['json-file'], jsonFile);
  assert.equal(outputs['sarif-file'], sarifFile);
  const json = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
  assert.ok(json.findings.length > 0);
  const sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
  assert.equal(sarif.version, '2.1.0');
});

test('runAction resolves a relative json-file/sarif-file against GITHUB_WORKSPACE and reports the resolved absolute path', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-relreports-'));
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_FAIL-ON': 'never',
    'INPUT_JSON-FILE': path.join('nested', 'out.json'),
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  fs.mkdirSync(path.join(workspace, 'nested'));
  const code = runAction(env, io);
  assert.equal(code, 0);
  const expected = path.join(workspace, 'nested', 'out.json');
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs['json-file'], expected);
  assert.ok(fs.existsSync(expected));
});

test('runAction overwriting an existing json-file inside the workspace succeeds (existing targets are realpath-checked)', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-overwrite-'));
  const jsonFile = path.join(workspace, 'out.json');
  fs.writeFileSync(jsonFile, 'stale content from a previous run');
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_FAIL-ON': 'never',
    'INPUT_JSON-FILE': jsonFile,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 0);
  const json = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
  assert.equal(json.status, 'complete');
});

test('runAction rejects a json-file input that resolves outside GITHUB_WORKSPACE, as a full operational failure', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-badjson-ws-'));
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-badjson-outside-'));
  const jsonFile = path.join(outsideDir, 'out.json');
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_JSON-FILE': jsonFile,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2);
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
  assert.equal('json-file' in outputs, false);
  assert.equal(fs.existsSync(jsonFile), false, 'nothing should be written to a rejected target');
});

test('runAction rejects a sarif-file input whose parent directory does not exist', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-missingparent-'));
  const sarifFile = path.join(workspace, 'no', 'such', 'dir', 'out.sarif');
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_SARIF-FILE': sarifFile,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2);
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
});

test('runAction rejects a json-file input containing an embedded CR or LF', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-crlf-'));
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_JSON-FILE': `out.json\nfake-output=pwned`,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2);
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
  assert.equal('fake-output' in outputs, false, 'a newline in the input must never forge an extra output key');
});

test('runAction rejects a sarif-file whose parent directory is really a symlink/junction to outside the workspace', (t) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-jsonlinkws-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-jsonlinktarget-'));
  const linkedParent = path.join(workspace, 'linked-reports');
  try {
    fs.symlinkSync(outside, linkedParent, 'junction');
  } catch (err) {
    t.skip(`symlink/junction creation not permitted in this environment: ${err.message}`);
    return;
  }
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_SARIF-FILE': path.join(linkedParent, 'out.sarif'),
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2, 'a parent directory that really links outside the workspace must be rejected');
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
  assert.equal(fs.existsSync(path.join(outside, 'out.sarif')), false, 'nothing should be written through the escaping link');
});

test('resolveOutputTarget: direct unit coverage of empty/CR-LF/missing-workspace/missing-parent rejection, independent of runAction', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-resolveoutput-'));
  const workspaceReal = fs.realpathSync(workspace);
  assert.equal(resolveOutputTarget(workspace, workspaceReal, ''), null, 'empty input is not a target at all');
  assert.equal(resolveOutputTarget(workspace, workspaceReal, 'out.json\r\n'), null, 'embedded CR/LF is rejected');
  assert.equal(resolveOutputTarget(workspace, null, 'out.json'), null, 'an unresolvable workspace rejects everything');
  assert.equal(resolveOutputTarget(workspace, workspaceReal, path.join('missing-dir', 'out.json')), null, 'a missing parent directory is rejected');
  assert.equal(resolveOutputTarget(workspace, workspaceReal, 'out.json'), path.join(workspace, 'out.json'), 'a plain new target inside the workspace resolves');
});

test('runAction catches a JSON-file write failure (target is really a directory) as an operational exit 2, not a crash or exit 1', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-writefail-json-'));
  const jsonDir = path.join(workspace, 'out.json');
  fs.mkdirSync(jsonDir); // fs.writeFileSync on an existing directory throws EISDIR
  const io = fakeLog();
  // Deliberately no INPUT_PATH manifest.json in workspace root, and the
  // default fail-on ('error') - this scan alone would exit 1 (CWSG001). The
  // write failure must override that to exit 2, proving the failure is not
  // silently swallowed into an ordinary threshold-triggered exit.
  const env = { 'INPUT_JSON-FILE': jsonDir, GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: outputsFile };
  const code = runAction(env, io);
  assert.equal(code, 2, 'a write failure must surface as operational exit 2, never the scan\'s own exit 1');
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
  assert.equal(outputs.errors, '0', 'outputs revert to the generic zeroed shape, not the real (now-untrustworthy) scan numbers');
  assert.equal('json-file' in outputs, false, 'a failed write must not claim to have written the file');
  assert.doesNotMatch(io.all(), /EISDIR|at Object|at Module/, 'no raw error code or stack frame should ever be logged');
  assert.match(io.all(), /ERROR: A report file could not be written\./, 'the log must explain why the step exits 2, not just show the earlier clean scan');
});

test('runAction catches a SARIF-file write failure (target is really a directory) as an operational exit 2, not a crash', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-writefail-sarif-'));
  const sarifDir = path.join(workspace, 'out.sarif');
  fs.mkdirSync(sarifDir);
  const io = fakeLog();
  // Deliberately no INPUT_PATH manifest.json in workspace root, and the
  // default fail-on ('error') - this scan alone would exit 1 (CWSG001). The
  // write failure must override that to exit 2, same proof as the JSON-write
  // failure test above but for the SARIF branch.
  const env = { 'INPUT_SARIF-FILE': sarifDir, GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: outputsFile };
  const code = runAction(env, io);
  assert.equal(code, 2, 'a write failure must surface as operational exit 2, never the scan\'s own exit 1');
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
  assert.equal('sarif-file' in outputs, false);
  assert.match(io.all(), /ERROR: A report file could not be written\./, 'the log must explain why the step exits 2, not just show the earlier clean scan');
});

test('runAction: a json-file write that succeeds alongside a sarif-file write that fails still reports the successful one', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-partialfail-'));
  const jsonFile = path.join(workspace, 'out.json');
  const sarifDir = path.join(workspace, 'out.sarif');
  fs.mkdirSync(sarifDir);
  const io = fakeLog();
  // Again no INPUT_PATH manifest.json, so this is a genuine complete scan
  // (CWSG001, would-be exit 1) whose json write really succeeds while the
  // sarif write fails - not a path already broken for an unrelated reason.
  const env = {
    'INPUT_JSON-FILE': jsonFile,
    'INPUT_SARIF-FILE': sarifDir,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2, 'overall exit code still reflects the sarif failure');
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs['json-file'], jsonFile, 'the json write that really succeeded is still reported');
  assert.equal('sarif-file' in outputs, false);
  assert.ok(fs.existsSync(jsonFile) && fs.readFileSync(jsonFile, 'utf8').length > 0);
  assert.match(io.all(), /CWSG001/, 'the log still shows the real scan finding from the genuinely-completed scan');
  assert.match(io.all(), /ERROR: A report file could not be written\./, 'and also explains why the step still exits 2');
});

// Output collision: json-file and sarif-file must not be allowed to resolve
// to the one real file. Without this check the second fs.writeFileSync
// would silently clobber the first with the *other* format's content while
// writeOutput still reported both as successfully-written outputs.
test('runAction rejects json-file and sarif-file inputs that are the literal same path, as a full operational failure', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-collide-literal-'));
  const target = path.join(workspace, 'out.json');
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_FAIL-ON': 'never',
    'INPUT_JSON-FILE': target,
    'INPUT_SARIF-FILE': target,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2, 'a json-file/sarif-file collision must be a full operational failure, not a silent overwrite');
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
  assert.equal('json-file' in outputs, false, 'neither output may be reported as successfully written');
  assert.equal('sarif-file' in outputs, false);
  assert.equal(fs.existsSync(target), false, 'nothing should be written to a colliding target');
});

test('runAction rejects json-file and sarif-file inputs that are different strings but resolve to the same real path (relative vs absolute)', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-collide-relabs-'));
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_FAIL-ON': 'never',
    'INPUT_JSON-FILE': 'out.json', // relative
    'INPUT_SARIF-FILE': path.join(workspace, 'out.json'), // absolute spelling of the same target
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2, 'a relative and an absolute spelling of the same target must still be caught as a collision');
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
  assert.equal('json-file' in outputs, false);
  assert.equal('sarif-file' in outputs, false);
  assert.equal(fs.existsSync(path.join(workspace, 'out.json')), false);
});

test('runAction rejects json-file and sarif-file whose parent directories are really symlink/junction aliases of the one real directory', (t) => {
  // Directory junctions (unlike file symlinks) do not need admin/Developer
  // Mode on Windows - see the identical rationale on the workspace-escaping
  // junction tests above - so this exercises outputTargetsCollide's realpath
  // fallback (for a target that does not exist yet, only its parent does)
  // without depending on filesystem case-insensitivity or file-symlink
  // privilege.
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-collide-alias-ws-'));
  const realReports = path.join(workspace, 'real-reports');
  fs.mkdirSync(realReports);
  const linkA = path.join(workspace, 'link-a');
  const linkB = path.join(workspace, 'link-b');
  try {
    fs.symlinkSync(realReports, linkA, 'junction');
    fs.symlinkSync(realReports, linkB, 'junction');
  } catch (err) {
    t.skip(`symlink/junction creation not permitted in this environment: ${err.message}`);
    return;
  }
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_FAIL-ON': 'never',
    'INPUT_JSON-FILE': path.join(linkA, 'out.json'),
    'INPUT_SARIF-FILE': path.join(linkB, 'out.json'),
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2, 'two differently-named parent directories that really alias the one real directory must still collide on the same basename');
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
  assert.equal('json-file' in outputs, false);
  assert.equal('sarif-file' in outputs, false);
  assert.equal(fs.existsSync(path.join(realReports, 'out.json')), false, 'nothing should be written through either alias');
});

test('runAction does not flag genuinely different json-file/sarif-file targets (different basenames) as a collision', () => {
  // Regression guard alongside the three collision tests above: two
  // legitimately distinct report files in the same directory must still
  // both be written normally.
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-nocollide-'));
  const jsonFile = path.join(workspace, 'out.json');
  const sarifFile = path.join(workspace, 'out.sarif');
  const io = fakeLog();
  const env = {
    'INPUT_PATH': '.',
    'INPUT_FAIL-ON': 'never',
    'INPUT_JSON-FILE': jsonFile,
    'INPUT_SARIF-FILE': sarifFile,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 0);
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs['json-file'], jsonFile);
  assert.equal(outputs['sarif-file'], sarifFile);
  assert.ok(fs.existsSync(jsonFile) && fs.existsSync(sarifFile));
});

test('outputTargetsCollide: direct unit coverage of the identity and different-basename cases, independent of runAction', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-collide-unit-'));
  const a = path.join(workspace, 'out.json');
  const b = path.join(workspace, 'out.sarif');
  assert.equal(outputTargetsCollide(a, a), true, 'a target always collides with itself');
  assert.equal(outputTargetsCollide(a, b), false, 'two different basenames in the same real directory do not collide');
});

test('writeOutput refuses a CR/LF-bearing name or value instead of writing a corrupting line, and never throws', () => {
  const outputsFile = tmpOutputsFile();
  const env = { GITHUB_OUTPUT: outputsFile };
  assert.doesNotThrow(() => writeOutput(env, 'evil\nfake-key', 'x'));
  assert.doesNotThrow(() => writeOutput(env, 'value-case', 'safe\nfake-key=pwned'));
  writeOutput(env, 'legit', 'ok');
  const outputs = readOutputs(outputsFile);
  assert.deepEqual(outputs, { legit: 'ok' }, 'only the well-formed write should appear; both CR/LF-bearing calls must be silently refused');
});

test('runAction: the Action passes renderSarif a workspace-relative prefix for a scanned subdirectory, so SARIF uris are repo-root-relative while JSON stays package-relative', () => {
  const outputsFile = tmpOutputsFile();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-action-srcroot-'));
  const sub = path.join('nested', 'ext-dir');
  fs.mkdirSync(path.join(workspace, sub), { recursive: true });
  fs.writeFileSync(
    path.join(workspace, sub, 'manifest.json'),
    JSON.stringify({ manifest_version: 2, name: 'Bad', version: '1.0.0', description: 'd' }),
  );
  const jsonFile = path.join(workspace, 'out.json');
  const sarifFile = path.join(workspace, 'out.sarif');
  const io = fakeLog();
  const env = {
    'INPUT_PATH': sub,
    'INPUT_FAIL-ON': 'never',
    'INPUT_JSON-FILE': jsonFile,
    'INPUT_SARIF-FILE': sarifFile,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 0);
  const sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
  assert.equal(sarif.runs[0].originalUriBaseIds, undefined, 'uriBaseId indirection was removed; uris are self-contained');
  const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
  assert.equal(loc.artifactLocation.uriBaseId, undefined);
  assert.equal(loc.artifactLocation.uri, 'nested/ext-dir/manifest.json', 'the SARIF uri combines the workspace-relative scan prefix with the finding\'s package-relative path');
  assert.equal(typeof sarif.runs[0].results[0].partialFingerprints.primaryLocationLineHash, 'string');
  const json = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
  assert.equal(json.findings[0].path, 'manifest.json', 'JSON stays package-relative, unaffected by the SARIF-only prefix');
});

test('isPathInside allows a child whose name merely starts with ".." but is not a traversal (e.g. "..extension")', () => {
  const parent = path.join(os.tmpdir(), 'cws-gate-dotdot-parent');
  assert.equal(isPathInside(parent, path.join(parent, '..extension')), true);
  assert.equal(isPathInside(parent, path.join(parent, '..extension', 'nested', 'file.js')), true);
  assert.equal(isPathInside(parent, path.join(parent, '..')), false, 'exactly ".." (the real parent) is still rejected');
  assert.equal(isPathInside(parent, path.join(parent, '..', 'sibling')), false, '".." followed by a separator is still a real traversal');
});

test('runAction never emits json-file/sarif-file outputs when those inputs are unset', () => {
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  runAction({ 'INPUT_PATH': GOOD_MV3, GITHUB_OUTPUT: outputsFile }, io);
  const outputs = readOutputs(outputsFile);
  assert.equal('json-file' in outputs, false);
  assert.equal('sarif-file' in outputs, false);
});

test('runAction does not throw when GITHUB_OUTPUT is unset (e.g. run outside a real runner)', () => {
  const io = fakeLog();
  assert.doesNotThrow(() => runAction({ 'INPUT_PATH': GOOD_MV3 }, io));
});

test('runAction exit code reflects error-level findings on bad-mv3 with the default fail-on', () => {
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const code = runAction({ 'INPUT_PATH': BAD_MV3, GITHUB_OUTPUT: outputsFile }, io);
  assert.equal(code, 1);
  const outputs = readOutputs(outputsFile);
  assert.ok(Number(outputs.errors) > 0);
  assert.equal(outputs.findings, String(Number(outputs.errors) + Number(outputs.warnings) + Number(outputs.notes)));
});

test('runAction rejects a relative path that escapes GITHUB_WORKSPACE', () => {
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const env = {
    'INPUT_PATH': path.join('..', '..', '..', '..', 'etc'),
    GITHUB_WORKSPACE: GOOD_MV3,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2);
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
  assert.doesNotMatch(io.all(), /etc/, 'the rejected path itself must never be echoed back');
});

test('runAction rejects an absolute path outside GITHUB_WORKSPACE', () => {
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-outside-'));
  const env = {
    'INPUT_PATH': outsideDir,
    GITHUB_WORKSPACE: GOOD_MV3,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2);
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
});

test('runAction allows a relative path containing ".." that still resolves inside GITHUB_WORKSPACE', () => {
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const env = {
    'INPUT_PATH': path.join('fixtures', 'bad-mv3', '..', 'good-mv3'),
    GITHUB_WORKSPACE: path.join(__dirname, '..'),
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 0, 'the path stays inside the workspace once resolved, despite containing ".."');
});

test('runAction rejects a workspace-relative path that does not exist, with a generic reason', () => {
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const env = {
    'INPUT_PATH': 'this-directory-does-not-exist',
    GITHUB_WORKSPACE: GOOD_MV3,
    GITHUB_OUTPUT: outputsFile,
  };
  const code = runAction(env, io);
  assert.equal(code, 2);
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
});

// Focused, environment-independent unit coverage of the two containment
// primitives: no filesystem links required, so this always runs (unlike the
// junction-based integration test below, which depends on OS permissions).
test('realOrNull/isPathInside: containment is computed on real, not lexical, paths', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-real-ws-'));
  assert.equal(realOrNull(workspace), fs.realpathSync(workspace));
  assert.equal(realOrNull(path.join(workspace, 'does-not-exist')), null, 'a missing path resolves to null, never throws');
  assert.equal(isPathInside(workspace, workspace), true, 'a directory is inside itself');
  assert.equal(isPathInside(workspace, path.join(workspace, 'child')), true);
  assert.equal(isPathInside(workspace, path.dirname(workspace)), false, 'the parent of the workspace is outside it');
});

test('runAction rejects a workspace-relative path that is really a symlink/junction to outside it', (t) => {
  // A directory *junction* on Windows (unlike a full symlink) does not need
  // admin/Developer Mode, so this - unlike the file-symlink test in
  // scan.test.js - should actually run rather than skip on a stock Windows
  // box. fs.symlinkSync's 'junction' type argument is a no-op on POSIX,
  // where it just creates an ordinary (unprivileged) directory symlink.
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-linkws-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'cws-gate-linktarget-'));
  fs.writeFileSync(
    path.join(outside, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'Outside', version: '1.0.0', description: 'd', icons: { 128: 'i.png' } }),
  );
  fs.writeFileSync(path.join(outside, 'i.png'), 'x');
  const linkPath = path.join(workspace, 'linked-out');
  try {
    fs.symlinkSync(outside, linkPath, 'junction');
  } catch (err) {
    t.skip(`symlink/junction creation not permitted in this environment: ${err.message}`);
    return;
  }
  const outputsFile = tmpOutputsFile();
  const io = fakeLog();
  const env = { 'INPUT_PATH': 'linked-out', GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: outputsFile };
  const code = runAction(env, io);
  assert.equal(code, 2, 'a workspace-relative path that really links outside must be rejected, not scanned');
  const outputs = readOutputs(outputsFile);
  assert.equal(outputs.status, 'incomplete');
  assert.doesNotMatch(io.all(), /linktarget/, 'the real (rejected) target path must never be echoed back');
});
