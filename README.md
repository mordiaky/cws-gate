# CWS Gate

A dependency-free Node.js CLI and GitHub Action that scans a **local, unpacked**
Chrome Manifest V3 extension directory for common Chrome Web Store
pre-submission issues.

- **Directory-only, beta.** It scans an already-unpacked extension folder. No
  `.zip`/`.crx` parsing or extraction (see [Known omissions](#known-omissions)).
- **Zero dependencies, zero network.** Node.js >=20 built-ins only. Nothing in
  this tool ever makes a network call, and it never uploads your extension.
- **Not a Google review.** CWS Gate is an independent pre-submission
  checklist. A clean run never predicts or guarantees Chrome Web Store
  approval.
- **Policy snapshot: 2026-07-16.** The 16 rules below reflect Chrome's
  published policies as of that date and are frozen for this beta - no
  configuration, no suppressions.

## CLI usage

This package is not yet published; run it from a checkout:

```bash
node bin/cws-gate.js ./my-extension
node bin/cws-gate.js ./my-extension --json report.json --sarif report.sarif --fail-on warn
node bin/cws-gate.js --self-check   # verifies the tool against its own bundled fixtures
```

```
Usage: cws-gate <directory> [options]

  --json <file>       Write a JSON report to <file>.
  --sarif <file>      Write a SARIF 2.1.0 report to <file>.
  --fail-on <level>   error|warn|note|never (default: error).
  --self-check        Run bundled fixtures against expected results and exit.
  --version           Print the tool version.
  --help              Print this message.
```

## GitHub Action usage

```yaml
- uses: mordiaky/cws-gate@v1
  with:
    path: .
    fail-on: error
    json-file: cws-gate-report.json
    sarif-file: cws-gate-report.sarif
```

`path` may be relative or absolute, but its real, symlink/junction-resolved
location must land inside `GITHUB_WORKSPACE` - being absolute does not by
itself fail a path, and being relative does not by itself pass one. Any
path whose resolved target lands outside `GITHUB_WORKSPACE` (directly, via
`..`, or through a link) is rejected with a generic error and exit code 2.
`json-file`/`sarif-file` get the same workspace-containment check as `path`
(and are rejected outright if the value contains a stray CR/LF). CWS Gate
never uploads the SARIF file itself - add a separate
`github/codeql-action/upload-sarif` step if you want that.

## Rules (frozen for this beta)

| ID | Level | Check |
|---|---|---|
| CWSG001 | error | Root `manifest.json` missing, unreadable, non-object, or invalid strict JSON |
| CWSG002 | error | Exactly one top-level wrapper directory contains the manifest (wrong directory selected) |
| CWSG003 | error | `manifest_version` is not `3` |
| CWSG004 | error | `name` missing/empty or over 75 characters (localized `__MSG_*__` exempt) |
| CWSG005 | error | `version` is not 1-4 dot-separated integers, 0-65535, no invalid leading zeros, not all-zero |
| CWSG006 | error | `description` missing or over 132 characters (localized values exempt) |
| CWSG007 | error/note | `icons` missing (error); no 128px icon (note) |
| CWSG008 | error | A manifest-referenced local file is absent or resolves outside the package |
| CWSG009 | error | Manifest V2-only keys present in an MV3 manifest |
| CWSG010 | error | `content_security_policy.extension_pages` script-src allows anything beyond `'self'`, `'none'`, or `'wasm-unsafe-eval'` (nonces and hashes are not honored here either) |
| CWSG011 | warning | Packaged non-sandbox HTML loads a remote or protocol-relative script |
| CWSG012 | warning | JavaScript calls `importScripts(...)` with a literal remote URL |
| CWSG013 | warning | JavaScript contains `eval(` or `new Function(` (regex-based; flagged for manual review) |
| CWSG014 | warning | Broad host permissions (`<all_urls>`, wildcard hosts) request human minimum-scope review |
| CWSG015 | note | A user-data-adjacent permission is a privacy/disclosure reminder, not a necessity verdict |
| CWSG016 | error | `_locales` and `default_locale` are inconsistent |

Every finding carries a policy URL, the policy snapshot date, severity, a
message, and a fix suggestion. No approval score is ever emitted.

## Exit codes and `--fail-on`

- **0** - complete scan, nothing met or exceeded the `--fail-on` threshold.
- **1** - complete scan, at least one finding met or exceeded the `--fail-on`
  threshold.
- **2** - the scan did not complete: bad path, invalid flag, a built-in
  size/file/directory-count limit was hit, (Action only) a rejected
  json-file/sarif-file input, or a report file that could not be written.
  This is always reported as a full failure with no findings, never a
  partial result.

`--fail-on` (CLI) / `fail-on` (Action input): `error` (default), `warn`,
`note`, or `never`. A "pass" means no findings at or above that threshold
were found against this beta's fixed rule set - it is not a signal about
Chrome Web Store approval odds.

## Privacy

- No network access, ever - no telemetry, no update checks, no live policy
  fetches.
- Only the directory you point it at is read. Symlinks inside it are never
  followed, and nothing outside it is touched.
- Reports use package-relative paths only - never your absolute filesystem
  path, username, or environment values.
- Finding messages are generic (rule, field name, file, line) and never echo
  raw manifest values, URLs, host patterns, or file content that might carry
  a secret.

## Known omissions

This beta intentionally does not do all of the following (not a roadmap
promise, just today's honest scope):

- ZIP/CRX parsing or extraction - unpacked directories only.
- Chrome execution, Chrome Web Store APIs, or publish/upload flows.
- AST/dataflow analysis or automatic fixes.
- Obfuscation, malware, license, or general security scanning.
- Store-listing copy, screenshots, or privacy-policy-content validation.
- Approval prediction of any kind.
- Suppressions, exceptions, or configuration - the 16 rules above are frozen.
- Live policy updates, telemetry, or automatic SARIF upload.

## Feedback

Please file a false positive/negative, a missing check you'd want, or
general feedback using this repository's issue template. This validation
beta is free; the fixed rule set and thresholds above are everything that
exists today.

## Validation experiment

This beta is a timeboxed demand test, not a committed roadmap. Starting
from first outreach, the experiment runs for a fixed 48-hour window and is
considered validated only if all four of these are reached:

| Signal | Threshold (within 48 hours) | Directly counted as |
|---|---|---|
| People reached | 10 | Sum of GitHub Traffic daily unique-visitor counts ("Visitors" under Insights -> Traffic) for each full UTC calendar day overlapping the 48-hour window - an approximate proxy, not an exact count (see note below) |
| Real (non-fixture) package runs | 5 | Unique issue authors answering "Yes" to the issue template's real-run question |
| Actionable findings reported | 3 | Unique issue authors answering "Yes" to the issue template's actionable-finding question |
| Explicit "yes" to a future $19 checkout link | 2 | Unique issue authors answering "Yes" to the issue template's launch-link-interest question |

Counting rules, so every signal above is directly countable and never
guessed at: each of the last three signals counts unique issue **authors**,
not issue count or comment count - one response per participant. If the
same person files more than one feedback issue, only their latest issue's
answers count, and a given author counts at most once toward each signal
(duplicates are never summed). The [issue template](.github/ISSUE_TEMPLATE/feedback.yml)
captures those three signals directly as structured dropdown fields.
"People reached" is the one signal not captured by the issue template; it
comes from this repository's own traffic graph, not from issues. GitHub's
Traffic page only exposes unique-visitor counts bucketed by full UTC
calendar day, over a trailing 14-day window - there is no exact 48-hour
rolling-window figure available - so "People reached" is deliberately
measured as the sum of just the full UTC days that overlap the 48-hour
window (never the whole 14-day total) rather than left unmeasured; this is
an approximate, directional proxy, not a precise 48-hour count, and can
double-count the same person as two "unique" visitors if they return on
more than one of those days.

## Planned pricing (not currently for sale)

The core scan is free and will stay free. We're validating demand for a
one-time **$19** "advanced report + policy pack" add-on (e.g. deeper
annotations, a curated policy pack) before building it. There is no
checkout link, no paid tier, and no billing integration anywhere in this
repository right now - if you'd want this, say so in an issue; that's the
only thing being measured at this stage.

## License

MIT - see [LICENSE](./LICENSE).
