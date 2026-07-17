'use strict';

// GitHub Action entry point. Hand-rolled INPUT_*/GITHUB_OUTPUT handling
// (no @actions/core, no dependencies at all) around the same scan() +
// renderers the CLI uses.

const fs = require('node:fs');
const path = require('node:path');
const { scan, operationalFailure } = require('../lib/scan');
const { renderText, renderJson, renderSarif } = require('../lib/report');
const { realOrNull, outputTargetsCollide } = require('../lib/paths');

// GitHub Actions env-var convention: INPUT_<NAME> with the name uppercased
// and spaces (not hyphens) turned into underscores, e.g. "fail-on" ->
// INPUT_FAIL-ON.
function input(env, name) {
  const key = 'INPUT_' + name.replace(/ /g, '_').toUpperCase();
  return env[key] || '';
}

// path.relative(parent, child) is '' when the two are equal (inside), is
// exactly '..' or starts with '..' + path.sep when child escapes upward
// through one or more parent references, or is itself absolute on a
// Windows cross-drive mismatch - those are the only "outside" cases. A
// relative path that merely *starts with* the two characters '..' without
// the separator that follows it - e.g. a real child directory named
// "..extension" - is an ordinary contained name, not a traversal, and must
// not be rejected. Both arguments must already be resolved/normalized
// before this is called.
function isPathInside(parent, child) {
  const rel = path.relative(parent, child);
  if (rel === '') return true;
  if (path.isAbsolute(rel)) return false;
  return rel !== '..' && !rel.startsWith(`..${path.sep}`);
}

// realOrNull (see lib/paths.js) follows symlinks *and* Windows junctions to
// their true target via fs.realpathSync. Containment must be checked against
// these real paths, not the lexical ones: a directory that is lexically
// inside GITHUB_WORKSPACE can still be a symlink/junction pointing outside
// it, and scan() itself realpath-resolves whatever root directory it is
// given before walking - so a lexical-only check here could wave a link
// through and have scan() silently follow it outside the workspace.

// Resolves an optional json-file/sarif-file input the same way `path` is
// resolved and contained (see isPathInside/realOrNull above), but for a
// file target that is usually about to be *created* rather than already
// existing. Returns the resolved absolute path on success, or null when the
// raw value must be rejected: empty, an embedded CR/LF (these values are
// later written verbatim into GITHUB_OUTPUT - see writeOutput below - and
// must never be able to inject extra lines there), an unresolvable
// workspace, or a target that is not really contained in GITHUB_WORKSPACE.
// Containment is checked against the target's own realpath when it already
// exists (e.g. overwriting a prior run's report), or against its real
// *parent* directory when it does not yet exist (the common case) - so
// neither the file itself nor its parent directory can be a symlink or
// junction smuggling the write outside the workspace, and a missing (or
// non-directory) parent is rejected outright rather than left for the write
// itself to fail on.
function resolveOutputTarget(workspace, workspaceReal, raw) {
  if (!raw || /[\r\n]/.test(raw) || workspaceReal === null) return null;
  const resolved = path.resolve(path.isAbsolute(raw) ? raw : path.join(workspace, raw));
  const existingReal = realOrNull(resolved);
  if (existingReal !== null) {
    return isPathInside(workspaceReal, existingReal) ? resolved : null;
  }
  const parentReal = realOrNull(path.dirname(resolved));
  if (parentReal === null || !isPathInside(workspaceReal, parentReal)) return null;
  let parentStat;
  try {
    parentStat = fs.statSync(parentReal);
  } catch {
    return null;
  }
  return parentStat.isDirectory() ? resolved : null;
}

// samePath/realOutputPath/outputTargetsCollide now live in lib/paths.js
// (imported above) so the CLI (bin/cws-gate.js) and this Action share exactly
// one collision-detection implementation instead of two that could drift
// apart. See lib/paths.js for the full rationale.

// Appends one "name=value\n" line to the GITHUB_OUTPUT environment file.
// name is always one of this file's own fixed literal strings; value is
// always a number, a boolean, a fixed enum string, or a path already run
// through resolveOutputTarget's CR/LF check - none of them are ever
// legitimately multiline. Refusing outright to append a CR/LF-bearing name
// or value, rather than writing it, closes the classic GITHUB_OUTPUT
// injection vector (an embedded newline forging extra "key=value" lines
// that a later step could misread as its own outputs) as defense in depth,
// without ever throwing - a corrupt/unreachable value here must not crash
// the whole action.
function writeOutput(env, name, value) {
  if (!env.GITHUB_OUTPUT) return; // not running under actions/runner (e.g. tests without it set)
  const str = String(value);
  if (/[\r\n]/.test(name) || /[\r\n]/.test(str)) return;
  fs.appendFileSync(env.GITHUB_OUTPUT, `${name}=${str}\n`);
}

/**
 * @param {NodeJS.ProcessEnv} env
 * @param {{log: Function}} [io]
 * @returns {number} process exit code
 */
function runAction(env, io) {
  const log = (io && io.log) || console.log;

  const targetPath = input(env, 'path') || '.';
  const failOn = input(env, 'fail-on') || 'error';
  const jsonFileInput = input(env, 'json-file');
  const sarifFileInput = input(env, 'sarif-file');

  const workspace = path.resolve(env.GITHUB_WORKSPACE || process.cwd());
  const resolvedTarget = path.resolve(path.isAbsolute(targetPath) ? targetPath : path.join(workspace, targetPath));

  // The path input must stay inside GITHUB_WORKSPACE once both sides are
  // resolved to their *real* location - an absolute path, a "../.."-laden
  // relative path, or a lexically-inside path that is itself a link to
  // somewhere else, all resolve outside and are rejected outright rather
  // than scanned. scan() is then handed the already-real target, so it
  // cannot re-resolve its way back outside on its own. Reasons are always
  // generic (never echoing the rejected path back into the shared report).
  const workspaceReal = realOrNull(workspace);
  const targetReal = realOrNull(resolvedTarget);

  // json-file/sarif-file get the same real-workspace containment treatment
  // as path (see resolveOutputTarget above); null means "requested but
  // rejected" as distinct from "" meaning "not requested at all".
  let jsonFile = jsonFileInput ? resolveOutputTarget(workspace, workspaceReal, jsonFileInput) : null;
  let sarifFile = sarifFileInput ? resolveOutputTarget(workspace, workspaceReal, sarifFileInput) : null;
  const outputTargetInvalid = (jsonFileInput && !jsonFile) || (sarifFileInput && !sarifFile);

  // Both individually valid (see outputTargetsCollide above) but the same
  // real file: neither may be written, so both are collapsed to null here,
  // before either is ever tested by the `if (jsonFile)`/`if (sarifFile)`
  // write gates further down - reusing those same gates to enforce "no file
  // written" for this case exactly as they already do for a rejected target,
  // rather than needing a second, separate no-write branch there.
  const outputTargetsCollided = jsonFile !== null && sarifFile !== null && outputTargetsCollide(jsonFile, sarifFile);
  if (outputTargetsCollided) {
    jsonFile = null;
    sarifFile = null;
  }

  let result;
  let sarifPrefix; // workspace-relative scan root (e.g. "sub/dir"); see renderSarif in lib/report.js
  if (workspaceReal === null || targetReal === null) {
    result = operationalFailure('The path input could not be resolved to an accessible directory.');
  } else if (!isPathInside(workspaceReal, targetReal)) {
    result = operationalFailure('The path input must resolve inside GITHUB_WORKSPACE.');
  } else if (outputTargetInvalid) {
    result = operationalFailure('The json-file/sarif-file input must resolve inside GITHUB_WORKSPACE.');
  } else if (outputTargetsCollided) {
    result = operationalFailure('json-file and sarif-file must not resolve to the same path.');
  } else {
    result = scan(targetReal, { failOn });
    sarifPrefix = path.relative(workspaceReal, targetReal);
  }

  log(renderText(result));

  // Each write is independently caught: a failure here (permission, disk
  // space, a TOCTOU race after the checks above that raises - e.g. the
  // parent vanishing between resolveOutputTarget and this write) must never
  // throw a raw stack out of the action - it degrades to the same generic
  // operational failure as an invalid input (exit code 2), never an
  // uncaught exception (which Node would otherwise report as an unrelated,
  // misleading exit code 1) and never a partial/successful-looking outcome.
  // (A race that swaps the parent for an out-of-workspace link and
  // *succeeds* rather than throwing would not be caught here - accepted
  // residual risk, since nothing else touches this workspace concurrently.)
  let writeFailed = false;
  if (jsonFile) {
    try {
      // JSON stays package-relative - no pathPrefix argument.
      fs.writeFileSync(jsonFile, renderJson(result));
      writeOutput(env, 'json-file', jsonFile);
    } catch {
      writeFailed = true;
    }
  }
  if (sarifFile) {
    try {
      // Only SARIF gets the optional workspace-relative prefix, so its
      // artifact location uris are self-contained repo-root-relative paths
      // ("<sarifPrefix>/<finding path>") usable against the full checkout
      // rather than just the scanned directory - see renderSarif's
      // rootPrefix parameter in lib/report.js. There is no uriBaseId
      // indirection: every uri already resolves the same way for any SARIF
      // consumer.
      fs.writeFileSync(sarifFile, renderSarif(result, sarifPrefix));
      writeOutput(env, 'sarif-file', sarifFile);
    } catch {
      writeFailed = true;
    }
  }

  const finalResult = writeFailed ? operationalFailure('A report file could not be written.') : result;
  // The log above already shows the real scan (so a human reading the
  // Action's own log always sees actual findings, even when a later file
  // write fails); a write failure gets one more generic line here so the
  // log also explains *why* the step exits 2, instead of looking like a
  // clean "Status: complete" run that mysteriously failed.
  if (writeFailed) log(renderText(finalResult));

  writeOutput(env, 'errors', finalResult.summary.errors);
  writeOutput(env, 'warnings', finalResult.summary.warnings);
  writeOutput(env, 'notes', finalResult.summary.notes);
  writeOutput(env, 'findings', finalResult.summary.errors + finalResult.summary.warnings + finalResult.summary.notes);
  writeOutput(env, 'status', finalResult.status);
  writeOutput(env, 'threshold-triggered', finalResult.thresholdTriggered);

  return finalResult.exitCode;
}

/* c8 ignore start */
if (require.main === module) {
  process.exitCode = runAction(process.env);
}
/* c8 ignore stop */

module.exports = { runAction, isPathInside, realOrNull, resolveOutputTarget, writeOutput };
