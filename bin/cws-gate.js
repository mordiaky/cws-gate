#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const { parseArgs } = require('node:util');
const pkg = require('../package.json');
const { scan } = require('../lib/scan');
const { renderText, renderJson, renderSarif } = require('../lib/report');
const { runSelfCheck } = require('../lib/self-check');

const USAGE = `Usage: cws-gate <directory> [options]

  --json <file>       Write a JSON report to <file>.
  --sarif <file>      Write a SARIF 2.1.0 report to <file>.
  --fail-on <level>   error|warn|note|never (default: error).
  --self-check        Run bundled fixtures against expected results and exit.
  --version           Print the tool version.
  --help              Print this message.

CWS Gate scans a local unpacked Chrome extension directory only (no ZIP/CRX).
It is an independent pre-submission checklist, not a Google review; a clean
run never predicts or guarantees Chrome Web Store approval.`;

/**
 * @param {string[]} argv - argv slice (no node/script entries).
 * @param {{stdout: {write: Function}, stderr: {write: Function}}} [io]
 * @returns {number} process exit code
 */
function main(argv, io) {
  const stdout = (io && io.stdout) || process.stdout;
  const stderr = (io && io.stderr) || process.stderr;

  let values;
  let positionals;
  try {
    ({ values, positionals } = parseArgs({
      args: argv,
      options: {
        json: { type: 'string' },
        sarif: { type: 'string' },
        'fail-on': { type: 'string', default: 'error' },
        'self-check': { type: 'boolean', default: false },
        version: { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
      allowPositionals: true,
    }));
  } catch (err) {
    stderr.write(`${err.message}\n\n${USAGE}\n`);
    return 2;
  }

  if (values.help) {
    stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (values.version) {
    stdout.write(`cws-gate ${pkg.version}\n`);
    return 0;
  }
  if (values['self-check']) {
    const check = runSelfCheck();
    stdout.write(`${check.details.join('\n')}\n`);
    stdout.write(check.ok ? 'self-check: PASS\n' : 'self-check: FAIL\n');
    return check.ok ? 0 : 1;
  }

  const targetDir = positionals[0] || '.';
  const result = scan(targetDir, { failOn: values['fail-on'] });

  stdout.write(renderText(result));

  // These are the caller's own CLI argument values (not data read from the
  // scanned package), so an error naming that path is a normal CLI error, not
  // a report-privacy violation - the shared report object itself never gets
  // this string.
  if (values.json) {
    try {
      fs.writeFileSync(values.json, renderJson(result));
    } catch (err) {
      stderr.write(`Failed to write JSON report: ${err.message}\n`);
      return 2;
    }
  }
  if (values.sarif) {
    try {
      fs.writeFileSync(values.sarif, renderSarif(result));
    } catch (err) {
      stderr.write(`Failed to write SARIF report: ${err.message}\n`);
      return 2;
    }
  }

  return result.exitCode;
}

/* c8 ignore start */
if (require.main === module) {
  process.exitCode = main(process.argv.slice(2), { stdout: process.stdout, stderr: process.stderr });
}
/* c8 ignore stop */

module.exports = { main };
