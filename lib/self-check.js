'use strict';

// `cws-gate --self-check`: runs the scanner against a fast subset of bundled
// fixtures and compares exact results against fixtures/expectations.js (the
// same source of truth the test suite uses). Exits 0 only on an exact match
// across every checked fixture, per the frozen spec's self-check contract.

const { scan } = require('./scan');
const { EXPECTATIONS } = require('../fixtures/expectations');

function findingsMatch(actual, expected) {
  if (actual.length !== expected.length) return false;
  for (let i = 0; i < actual.length; i++) {
    const a = actual[i];
    const e = expected[i];
    if (a.ruleId !== e.ruleId || a.level !== e.level || a.path !== e.path || a.line !== e.line) {
      return false;
    }
  }
  return true;
}

function checkOne(entry) {
  const result = scan(entry.dir);
  const exp = entry.expected;
  const mismatches = [];

  if (result.status !== exp.status) mismatches.push(`status: got ${result.status}, want ${exp.status}`);
  if (result.exitCode !== exp.exitCode) mismatches.push(`exitCode: got ${result.exitCode}, want ${exp.exitCode}`);
  if (result.thresholdTriggered !== exp.thresholdTriggered) {
    mismatches.push(`thresholdTriggered: got ${result.thresholdTriggered}, want ${exp.thresholdTriggered}`);
  }
  for (const key of ['errors', 'warnings', 'notes', 'filesScanned', 'findingsTruncated']) {
    if (result.summary[key] !== exp.summary[key]) {
      mismatches.push(`summary.${key}: got ${result.summary[key]}, want ${exp.summary[key]}`);
    }
  }
  if (!findingsMatch(result.findings, exp.findings)) {
    const got = result.findings.map((f) => ({ ruleId: f.ruleId, level: f.level, path: f.path, line: f.line }));
    mismatches.push(`findings: got ${JSON.stringify(got)}, want ${JSON.stringify(exp.findings)}`);
  }

  return mismatches;
}

function runSelfCheck() {
  const details = [];
  let ok = true;
  for (const [name, entry] of Object.entries(EXPECTATIONS)) {
    if (!entry.selfCheck) continue;
    const mismatches = checkOne(entry);
    if (mismatches.length === 0) {
      details.push(`PASS  ${name}`);
    } else {
      ok = false;
      details.push(`FAIL  ${name}`);
      for (const m of mismatches) details.push(`      ${m}`);
    }
  }
  return { ok, details };
}

module.exports = { runSelfCheck };
