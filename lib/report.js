'use strict';

// Pure renderers over the shared scan() result object (lib/scan.js). No
// filesystem or network access here - text/JSON/SARIF are three views of
// the same data structure, so a bug fixed once is fixed in all three.

const crypto = require('node:crypto');
const rules = require('./rules');

// A scanned package's own file names (f.path) and matched content (folded
// into f.message) are attacker-controlled, not this tool's own text. Strip
// CR/LF/other C0 controls (+ DEL) before interpolating either into a text
// report line - otherwise a file literally named with an embedded newline
// could inject an extra stdout line, including a GitHub Actions
// "::error::"-style workflow command (Actions parses every stdout line for
// that syntax). Replaced with a space, not deleted, so tokens don't fuse.
const CONTROL_CHARS_RE = /[\x00-\x1f\x7f]/g;
function sanitizeLine(value) {
  return String(value).replace(CONTROL_CHARS_RE, ' ');
}

function renderText(result) {
  const lines = [];
  lines.push(`CWS Gate ${result.tool.version} - ${result.ruleset.id} ruleset (policy as of ${result.ruleset.policyAsOf})`);
  lines.push('');

  if (result.operationalError) {
    // operationalError can embed a caller-supplied value (e.g. an invalid
    // --fail-on flag, see lib/scan.js) - the same sanitizeLine() used above
    // for finding.path/finding.message, applied at this single point of
    // truth so every current and future operationalError caller is covered
    // without patching each call site individually.
    lines.push(`ERROR: ${sanitizeLine(result.operationalError)}`);
  } else if (result.findings.length === 0) {
    lines.push('No findings.');
  } else {
    for (const f of result.findings) {
      const safePath = sanitizeLine(f.path);
      const safeMessage = sanitizeLine(f.message);
      lines.push(`[${f.level.toUpperCase()}] ${f.ruleId}  ${safePath}:${f.line}:${f.column}  ${safeMessage}`);
      lines.push(`    fix: ${f.fix}`);
      lines.push(`    policy: ${f.policyUrl} (as of ${f.policyAsOf})`);
    }
  }

  lines.push('');
  if (!result.operationalError) {
    const s = result.summary;
    lines.push(
      `Summary: ${s.errors} error(s), ${s.warnings} warning(s), ${s.notes} note(s) across ` +
        `${s.filesScanned} file(s), ${s.bytesScanned} byte(s) scanned.` +
        (s.findingsTruncated ? ' Findings truncated at the maximum-findings cap.' : ''),
    );
  }
  lines.push(`Status: ${result.status}. Threshold triggered: ${result.thresholdTriggered}.`);
  lines.push('');
  lines.push(result.disclaimer);
  return lines.join('\n') + '\n';
}

function renderJson(result) {
  // exitCode is a process concern (what code the CLI/Action exits with), not
  // report content, so it is intentionally left out of the persisted file.
  const { exitCode, ...report } = result;
  return JSON.stringify(report, null, 2) + '\n';
}

// Deterministic fingerprint: rule id, package-relative path, and detector
// key only - never line/column (a harmless line inserted earlier in the
// file would otherwise reshuffle every fingerprint below it) and never a
// timestamp or random salt, so golden-file tests are reproducible and
// identical findings fingerprint identically run to run. Content-rule
// detectorKeys are already occurrence-unique per file (see contentTag in
// lib/rules.js), so two findings on the same line still fingerprint
// distinctly. Keyed on f.path (never the possibly rootPrefix-rewritten uri
// below), so this fingerprint never moves just because the same package is
// scanned from a different repo-root location.
function fingerprint(f) {
  const key = `${f.ruleId}|${f.path}|${f.detectorKey}`;
  return crypto.createHash('sha256').update(key).digest('hex');
}

// GitHub code scanning's supported alert-identity key. Same content-derived,
// never-line/column contract as fingerprint() above, but keyed on the actual
// SARIF uri emitted for this result (which may carry rootPrefix) so two
// packages scanned from different repo-root locations don't collide on
// GitHub's side either.
function primaryLocationLineHash(ruleId, uri, detectorKey) {
  const key = `${ruleId}|${uri}|${detectorKey}`;
  return crypto.createHash('sha256').update(key).digest('hex');
}

function sarifLevel(level) {
  return level === 'warning' || level === 'note' ? level : 'error';
}

// SARIF's artifactLocation.uri is an RFC 3986 URI reference, not a bare
// filesystem path - a raw space, '#' (a fragment delimiter), '%', or
// non-ASCII byte would produce an invalid or mis-anchored uri. Percent-encode
// segment by segment (never the whole string in one pass) so the '/'
// separators between segments are preserved rather than themselves being
// encoded to "%2F".
function encodeUriPath(relPath) {
  return relPath.split('/').map(encodeURIComponent).join('/');
}

// rootPrefix is an optional repository-root-relative directory prefix (e.g.
// the Action's scanned sub-path within GITHUB_WORKSPACE). Default '' (or no
// argument) means "package-relative", matching pre-existing output
// byte-for-byte: every uri is just the finding's own f.path. When given,
// every uri instead becomes the self-contained repo-root-relative path
// "<rootPrefix>/<f.path>" directly, with no uriBaseId/originalUriBaseIds
// indirection - every SARIF consumer resolves a plain uri the same way,
// which isn't true of optional uriBaseId support. Of the two real callers,
// bin/cws-gate.js calls renderSarif(result) with no second argument (so CLI
// output stays package-relative), while action/index.js passes its scanned
// sub-path within GITHUB_WORKSPACE as rootPrefix (so Action output is
// workspace-relative instead).
function renderSarif(result, rootPrefix) {
  const driverRules = rules.RULES.map((r) => ({
    id: r.id,
    shortDescription: { text: r.title },
    helpUri: r.policyUrl,
    defaultConfiguration: { level: sarifLevel(r.level) },
    properties: { policyAsOf: r.policyAsOf },
  }));

  // Forward slashes, no leading/trailing slash, matching SARIF's URI
  // convention regardless of host OS path separator; '' when no prefix was
  // given, so the uri below reduces to plain f.path unchanged. Percent-encoded
  // once here (not per finding below) since every finding shares one prefix.
  const normalizedPrefix = rootPrefix ? rootPrefix.replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '') : '';
  const encodedPrefix = normalizedPrefix ? encodeUriPath(normalizedPrefix) : '';

  const sarifResults = result.findings.map((f) => {
    // f.path is package-relative and always '/'-separated (see toPosixRelative
    // in lib/scan.js), so it - and the prefix above - only ever need
    // segment-wise percent-encoding, never a host OS separator conversion.
    const encodedPath = encodeUriPath(f.path);
    const uri = encodedPrefix ? `${encodedPrefix}/${encodedPath}` : encodedPath;
    return {
      ruleId: f.ruleId,
      level: sarifLevel(f.level),
      message: { text: f.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            region: { startLine: f.line, startColumn: f.column },
          },
        },
      ],
      partialFingerprints: {
        'cwsGate/v1': fingerprint(f),
        primaryLocationLineHash: primaryLocationLineHash(f.ruleId, uri, f.detectorKey),
      },
    };
  });

  const invocation = { executionSuccessful: !result.operationalError };
  if (result.operationalError) {
    invocation.toolExecutionNotifications = [{ level: 'error', message: { text: result.operationalError } }];
  }

  const run = {
    tool: {
      driver: {
        name: 'cws-gate',
        version: result.tool.version,
        fullDescription: { text: result.disclaimer },
        rules: driverRules,
      },
    },
    invocations: [invocation],
    properties: { disclaimer: result.disclaimer, policyAsOf: result.ruleset.policyAsOf },
    results: sarifResults,
  };

  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [run],
  };
  return JSON.stringify(sarif, null, 2) + '\n';
}

module.exports = { renderText, renderJson, renderSarif };
