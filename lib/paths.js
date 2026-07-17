'use strict';

// Shared filesystem-path helpers used by both bin/cws-gate.js (CLI) and
// action/index.js (GitHub Action). Kept in one place so "do these two
// resolved report-output paths collide" has exactly one implementation
// instead of a CLI copy and an Action copy that could silently drift apart.

const fs = require('node:fs');
const path = require('node:path');

// fs.realpathSync follows symlinks *and* Windows junctions to their true
// target. Returns null (never throws) for anything missing or inaccessible;
// callers treat null as "could not be resolved".
function realOrNull(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return null;
  }
}

// True when two already-resolved paths denote the exact same filesystem
// entry, not merely related ones. path.relative(a, b) === '' is already
// platform-native - case-sensitive on POSIX, case-insensitive on Windows -
// so a spelling that differs only by case collides correctly on Windows and
// correctly does not on a case-sensitive POSIX filesystem.
function samePath(a, b) {
  return path.relative(a, b) === '';
}

// Best-effort real path of a resolved report-output target, for collision
// comparison only. When the target already exists (overwriting a prior run's
// report, or an existing symlink/junction alias) this is its full realpath,
// resolving the target itself. When it does not exist yet - the common case
// for a report about to be freshly written - realpathSync cannot resolve the
// target directly (the whole path must exist), so this instead resolves just
// the real *parent* directory and rejoins the target's own basename; that
// still collapses two differently-spelled but identical parent directories -
// e.g. two symlinks/junctions both really pointing at one reports directory
// - down to the same comparison path. Null only when even the parent cannot
// be resolved.
function realOutputPath(resolved) {
  const existingReal = realOrNull(resolved);
  if (existingReal !== null) return existingReal;
  const parentReal = realOrNull(path.dirname(resolved));
  return parentReal === null ? null : path.join(parentReal, path.basename(resolved));
}

// A JSON report target and a SARIF report target (CLI: --json/--sarif;
// Action: json-file/sarif-file inputs) are each resolved independently, but
// two *different* input strings can still name the one physical file: the
// same location spelled relative vs absolute, a case-only difference on a
// case-insensitive filesystem, or two parent directories that are really
// symlink/junction aliases of each other. Left undetected, the second report
// write would silently clobber the first with the *other* format's content
// while the caller still reports both as successfully-written outputs - a
// JSON consumer would receive SARIF bytes (or vice versa) with no error
// anywhere. Checked both lexically and via realOutputPath so neither a
// spelling trick nor a real filesystem alias slips a genuine collision past
// as "two different files". Both arguments must already be resolved
// (absolute) paths.
function outputTargetsCollide(jsonFile, sarifFile) {
  if (samePath(jsonFile, sarifFile)) return true;
  const jsonReal = realOutputPath(jsonFile);
  const sarifReal = realOutputPath(sarifFile);
  return jsonReal !== null && sarifReal !== null && samePath(jsonReal, sarifReal);
}

module.exports = { realOrNull, samePath, realOutputPath, outputTargetsCollide };
