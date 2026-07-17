'use strict';

// The one shared scanner used by both bin/cws-gate.js (CLI) and
// action/index.js (GitHub Action). Node built-ins only, no network, no
// child processes, no dynamic code execution.

const fs = require('node:fs');
const path = require('node:path');
const rules = require('./rules');
const pkg = require('../package.json');

const DEFAULT_LIMITS = {
  maxFiles: 10000,
  maxTotalBytes: 500 * 1024 * 1024,
  maxFileTextBytes: 5 * 1024 * 1024,
  maxTotalTextBytes: 50 * 1024 * 1024,
  maxFindings: 1000,
};

// Only extensions actually read for content-based rules (HTML script-src,
// JS eval/importScripts). manifest.json is read through a separate direct
// path, not this cache, so ".json" does not need to be listed here.
const TEXT_EXTENSIONS = new Set(['.html', '.htm', '.js', '.mjs', '.cjs']);

const DISCLAIMER =
  'CWS Gate is an independent pre-submission checklist, not a Google review. ' +
  'A clean run never predicts or guarantees Chrome Web Store approval. ' +
  `Policy snapshot date: ${rules.POLICY_AS_OF}.`;

function toPosixRelative(root, absPath) {
  return path.relative(root, absPath).split(path.sep).join('/');
}

function statNoFollow(absPath, onError) {
  try {
    return fs.lstatSync(absPath);
  } catch (err) {
    if (onError) onError(err);
    return null;
  }
}

// Depth-first walk from rootDir. Uses lstat exclusively so symlinks are
// detected and skipped rather than followed; every recursion step descends
// into a child of a directory already known to be inside rootDir, so there
// is no path-escape vector to defend against separately.
function walk(rootDir, limits) {
  const files = [];
  let totalBytes = 0;
  let filesExceeded = false;
  let bytesExceeded = false;
  // Set whenever readdirSync/lstatSync throws for a directory or entry the
  // walk was otherwise about to visit (permission error, deleted mid-scan,
  // etc.). Previously that entry was silently skipped and the walk still
  // reported "complete" - a package whose most sensitive file happened to
  // sit behind an unreadable subdirectory could scan clean. scan() turns
  // this into an operational failure instead, same as filesExceeded/
  // bytesExceeded.
  let traversalError = false;
  let dirsVisited = 0;
  const stack = [rootDir];

  outer: while (stack.length > 0) {
    const dir = stack.pop();
    // Directory visits share the file-count budget: an unbounded number of
    // (near-)empty directories would otherwise never trip any cap at all.
    dirsVisited++;
    if (dirsVisited > limits.maxFiles) {
      filesExceeded = true;
      break outer;
    }
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      traversalError = true;
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const dirent of entries) {
      const absPath = path.join(dir, dirent.name);
      const lst = statNoFollow(absPath, () => {
        traversalError = true;
      });
      if (!lst) continue;
      if (lst.isSymbolicLink()) continue; // never follow symlinks
      if (lst.isDirectory()) {
        stack.push(absPath);
        continue;
      }
      if (!lst.isFile()) continue; // fifo/socket/device: opaque, never read
      if (files.length >= limits.maxFiles) {
        filesExceeded = true;
        break outer;
      }
      if (totalBytes + lst.size > limits.maxTotalBytes) {
        bytesExceeded = true;
        break outer;
      }
      totalBytes += lst.size;
      files.push({ path: toPosixRelative(rootDir, absPath), absPath, size: lst.size });
    }
  }

  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { files, totalBytes, filesExceeded, bytesExceeded, traversalError };
}

function readManifestAt(absPath, maxBytes) {
  let raw;
  try {
    // Re-verify right before reading (not just at the caller's earlier
    // stat): closes most of the stat-then-read TOCTOU window, and gives
    // manifest.json the same size cap every other inspected file gets (it
    // is read outside the normal walk()/getText() cap machinery).
    const st = fs.lstatSync(absPath);
    if (!st.isFile() || st.size > maxBytes) return { ok: false };
    raw = fs.readFileSync(absPath, 'utf8');
  } catch {
    return { ok: false };
  }
  if (raw.indexOf('\u0000') !== -1) {
    return { ok: false }; // NUL byte: treat as binary/unreadable
  }
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1); // strip a UTF-8 BOM, same as Chrome's own manifest reader
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, raw };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, raw };
  }
  return { ok: true, manifest: parsed, raw };
}

// Resolves CWSG001 (missing/unreadable/non-object/invalid JSON) vs CWSG002
// (exactly one top-level wrapper directory holds the real manifest - the
// classic "selected the parent of the extension folder" mistake). Per the
// frozen spec CWS Gate never auto-descends into the wrapper; it only names it.
function resolveManifest(rootDir, limits) {
  const manifestPath = path.join(rootDir, 'manifest.json');
  const st = statNoFollow(manifestPath);
  if (st && st.isFile()) {
    const result = readManifestAt(manifestPath, limits.maxFileTextBytes);
    if (result.ok) return { kind: 'ok', manifest: result.manifest, raw: result.raw };
    return { kind: 'invalid' };
  }

  let rootEntries = [];
  try {
    for (const d of fs.readdirSync(rootDir, { withFileTypes: true })) {
      const est = statNoFollow(path.join(rootDir, d.name));
      if (est && (est.isDirectory() || est.isFile())) {
        rootEntries.push({ name: d.name, isDirectory: est.isDirectory() });
      }
    }
  } catch {
    rootEntries = [];
  }

  if (rootEntries.length === 1 && rootEntries[0].isDirectory) {
    const wrapperManifest = path.join(rootDir, rootEntries[0].name, 'manifest.json');
    const wst = statNoFollow(wrapperManifest);
    if (wst && wst.isFile()) {
      return { kind: 'wrapper', wrapperName: rootEntries[0].name };
    }
  }

  return { kind: 'missing' };
}

function emptySummary() {
  return { errors: 0, warnings: 0, notes: 0, filesScanned: 0, bytesScanned: 0, findingsTruncated: false };
}

function baseResult() {
  return {
    schemaVersion: '1.0.0',
    tool: { name: 'cws-gate', version: pkg.version },
    ruleset: { id: 'validation-beta', version: rules.POLICY_AS_OF, policyAsOf: rules.POLICY_AS_OF },
    privacy: {
      network: 'none',
      filesystemScope: 'selected-directory-only',
      symlinksFollowed: false,
      extractionPerformed: false,
    },
    disclaimer: DISCLAIMER,
  };
}

function operationalFailure(message) {
  return {
    ...baseResult(),
    status: 'incomplete',
    thresholdTriggered: false,
    exitCode: 2,
    summary: emptySummary(),
    findings: [],
    operationalError: message,
  };
}

// Reads a text file that must pass both a per-file cap and a shared
// cross-file total-text budget, treating anything over either cap - or a NUL
// byte, or a stat/read failure - as unreadable. cachedSize is the walk-time
// lstat size (cheap pre-check before touching the file again); textBudget is
// a shared {remaining} counter mutated in place across every call for a
// given scan(). Exported so the "genuine read failure" sub-case (e.g. a file
// that vanishes between the walk's lstat and this read) can be unit-tested
// directly against a path guaranteed not to exist, without needing to race
// the filesystem in a real scan() run.
function readCappedText(absPath, cachedSize, limits, textBudget) {
  if (cachedSize > limits.maxFileTextBytes || cachedSize > textBudget.remaining) {
    return { ok: false };
  }
  let buf;
  try {
    // Re-verify immediately before reading: the walk-time lstat is stale by
    // the time content rules run, so re-check "still a regular file, still
    // under the size cap" right at the read to close most of that window (a
    // swap-to-symlink or grow-past-cap race).
    const freshStat = fs.lstatSync(absPath);
    if (!freshStat.isFile() || freshStat.size > limits.maxFileTextBytes || freshStat.size > textBudget.remaining) {
      return { ok: false };
    }
    buf = fs.readFileSync(absPath);
  } catch {
    return { ok: false };
  }
  if (buf.includes(0)) return { ok: false }; // NUL byte: binary, skip
  textBudget.remaining -= buf.length;
  return { ok: true, text: buf.toString('utf8') };
}

function severityRank(level) {
  const r = rules.SEVERITY_ORDER[level];
  return r === undefined ? 3 : r;
}

function finalize(findings, status, filesScanned, bytesScanned, limits, failOn) {
  findings.sort((a, b) => {
    const sr = severityRank(a.level) - severityRank(b.level);
    if (sr !== 0) return sr;
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    if (a.line !== b.line) return a.line - b.line;
    return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
  });

  let findingsTruncated = false;
  let finalFindings = findings;
  if (findings.length > limits.maxFindings) {
    finalFindings = findings.slice(0, limits.maxFindings);
    findingsTruncated = true;
  }

  const summary = {
    errors: finalFindings.filter((f) => f.level === 'error').length,
    warnings: finalFindings.filter((f) => f.level === 'warning').length,
    notes: finalFindings.filter((f) => f.level === 'note').length,
    filesScanned,
    bytesScanned,
    findingsTruncated,
  };

  const minSeverity = rules.FAIL_ON_MIN_SEVERITY[failOn];
  const thresholdTriggered =
    minSeverity !== null && minSeverity !== undefined && finalFindings.some((f) => severityRank(f.level) <= minSeverity);

  const operational = status === 'incomplete';
  const exitCode = operational ? 2 : thresholdTriggered ? 1 : 0;

  return {
    ...baseResult(),
    status,
    thresholdTriggered,
    exitCode,
    summary,
    findings: finalFindings,
  };
}

/**
 * Scan an unpacked extension directory.
 * @param {string} rootDir - path to the directory to scan.
 * @param {object} [options]
 * @param {'error'|'warn'|'note'|'never'} [options.failOn='error']
 * @param {object} [options.limits] - override caps (test-only seam; never
 *   exposed as a CLI/Action flag, since the frozen rules are not configurable).
 */
function scan(rootDir, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...(options.limits || {}) };
  const failOn = options.failOn || 'error';

  if (!Object.hasOwn(rules.FAIL_ON_MIN_SEVERITY, failOn)) {
    // failOn is a CLI/Action flag value (small enum-like string the caller
    // typed), never data read from the scanned package, so echoing it back
    // does not violate the "no source secrets/absolute paths" guarantee.
    return operationalFailure(`Invalid --fail-on value: ${String(failOn).slice(0, 200)}`);
  }

  // Note: operationalError messages below are deliberately generic (no path
  // interpolation) so the shared report object - rendered identically for
  // JSON/SARIF/text by both the CLI and the Action - never carries the
  // caller's filesystem path. A CLI-only stderr line may echo the user's own
  // argument separately; that is not part of the report.
  let resolvedRoot;
  try {
    resolvedRoot = fs.realpathSync(rootDir);
  } catch {
    return operationalFailure('Directory not found or not accessible.');
  }
  let rootStat;
  try {
    rootStat = fs.statSync(resolvedRoot);
  } catch {
    return operationalFailure('Directory not found or not accessible.');
  }
  if (!rootStat.isDirectory()) {
    return operationalFailure('Path is not a directory.');
  }

  const manifestOutcome = resolveManifest(resolvedRoot, limits);

  if (manifestOutcome.kind === 'wrapper') {
    const findings = [
      rules.makeFinding('CWSG002', {
        message: 'manifest.json was not found at the package root, but exactly one top-level directory directly contains one. Point CWS Gate at that inner directory instead.',
        path: 'manifest.json',
        line: 1,
      }),
    ];
    return finalize(findings, 'complete', 0, 0, limits, failOn);
  }

  const walkResult = walk(resolvedRoot, limits);
  if (walkResult.filesExceeded || walkResult.bytesExceeded) {
    // A structural cap means the walk itself was incomplete, so any findings
    // computed off a partial file list would be untrustworthy - this is a
    // full operational failure (no findings), not a partial result. Unlike
    // this, the maxFindings cap below truncates output volume of an
    // otherwise-complete scan and stays "complete".
    return operationalFailure('The directory is too large to scan completely (file, directory, or byte limit exceeded).');
  }
  if (walkResult.traversalError) {
    // Same "untrustworthy partial result" reasoning as the cap branch above:
    // a directory/entry that could not be read at all must never be
    // silently skipped into an otherwise "complete" result.
    return operationalFailure('The extension directory could not be fully read.');
  }
  const fileSet = new Map(walkResult.files.map((f) => [f.path, f]));
  const findings = [];

  if (manifestOutcome.kind === 'missing') {
    findings.push(
      rules.makeFinding('CWSG001', {
        message: 'manifest.json is missing at the package root.',
        path: 'manifest.json',
        line: 1,
      }),
    );
  } else if (manifestOutcome.kind === 'invalid') {
    findings.push(
      rules.makeFinding('CWSG001', {
        message: 'manifest.json exists but is not valid strict JSON, or its top-level value is not a JSON object.',
        path: 'manifest.json',
        line: 1,
      }),
    );
  } else {
    // A loop, not push(...arr): spreading a huge array as call arguments can
    // overflow V8's argument-count limit on a manifest engineered to produce
    // tens of thousands of findings.
    for (const f of rules.runManifestRules(manifestOutcome.manifest, manifestOutcome.raw, fileSet)) findings.push(f);
  }

  const sandboxPageSet = new Set();
  if (manifestOutcome.kind === 'ok' && manifestOutcome.manifest.sandbox && Array.isArray(manifestOutcome.manifest.sandbox.pages)) {
    for (const p of manifestOutcome.manifest.sandbox.pages) {
      if (typeof p === 'string') sandboxPageSet.add(path.posix.normalize(p.replace(/^\/+/, '')));
    }
  }

  const textBudget = { remaining: limits.maxTotalTextBytes };
  const textCache = new Map();
  // Set whenever a targeted HTML/JS file exists but couldn't be fully read
  // (per-file cap, total text budget, read failure, or NUL/binary content).
  // Content rules only ever see whatever getText() *does* manage to return,
  // so a silently-skipped file would otherwise make the scan look clean
  // instead of incomplete - this flag turns that into an operational failure
  // below rather than a quietly partial "complete" result.
  let contentReadIncomplete = false;
  const getText = (relPath) => {
    if (textCache.has(relPath)) return textCache.get(relPath);
    const file = fileSet.get(relPath);
    if (!file) return null;
    if (!TEXT_EXTENSIONS.has(path.extname(relPath).toLowerCase())) return null;
    const outcome = readCappedText(file.absPath, file.size, limits, textBudget);
    if (!outcome.ok) {
      contentReadIncomplete = true;
      return null;
    }
    textCache.set(relPath, outcome.text);
    return outcome.text;
  };

  for (const f of rules.runContentRules(walkResult.files, sandboxPageSet, getText)) findings.push(f);

  if (contentReadIncomplete) {
    // Same reasoning as the walkResult structural-cap branch above: findings
    // computed with one or more targeted files silently missing from content
    // rules would be untrustworthy, so this is a full operational failure
    // (zero findings), not a partial "complete" result.
    return operationalFailure(
      'A targeted HTML or JavaScript file could not be fully read (per-file size cap, total text budget, read failure, or binary/NUL content); the scan is incomplete rather than partial.',
    );
  }

  return finalize(findings, 'complete', walkResult.files.length, walkResult.totalBytes, limits, failOn);
}

module.exports = { scan, DEFAULT_LIMITS, DISCLAIMER, operationalFailure, readCappedText, walk };
