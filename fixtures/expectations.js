'use strict';

// Single source of truth for fixture-driven expected results, consumed by
// both lib/self-check.js (a fast subset, flagged selfCheck: true) and
// test/scan.test.js (the full set). Each finding is checked on
// {ruleId, level, path, line} only - not message text (wording may evolve
// without being a regression) and not bytesScanned (a function of incidental
// file bytes, not a rule-correctness signal). filesScanned IS checked since
// it is a robust, meaningful count.

const path = require('node:path');

function dir(name) {
  return path.join(__dirname, name);
}

const EXPECTATIONS = {
  'good-mv3': {
    dir: dir('good-mv3'),
    selfCheck: true,
    expected: {
      status: 'complete',
      exitCode: 0,
      thresholdTriggered: false,
      summary: { errors: 0, warnings: 0, notes: 0, filesScanned: 7, findingsTruncated: false },
      findings: [],
    },
  },
  'missing-manifest': {
    dir: dir('missing-manifest'),
    selfCheck: true,
    expected: {
      status: 'complete',
      exitCode: 1,
      thresholdTriggered: true,
      summary: { errors: 1, warnings: 0, notes: 0, filesScanned: 2, findingsTruncated: false },
      findings: [{ ruleId: 'CWSG001', level: 'error', path: 'manifest.json', line: 1 }],
    },
  },
  'invalid-json-manifest': {
    dir: dir('invalid-json-manifest'),
    selfCheck: false,
    expected: {
      status: 'complete',
      exitCode: 1,
      thresholdTriggered: true,
      summary: { errors: 1, warnings: 0, notes: 0, filesScanned: 1, findingsTruncated: false },
      findings: [{ ruleId: 'CWSG001', level: 'error', path: 'manifest.json', line: 1 }],
    },
  },
  'non-object-manifest': {
    dir: dir('non-object-manifest'),
    selfCheck: false,
    expected: {
      status: 'complete',
      exitCode: 1,
      thresholdTriggered: true,
      summary: { errors: 1, warnings: 0, notes: 0, filesScanned: 1, findingsTruncated: false },
      findings: [{ ruleId: 'CWSG001', level: 'error', path: 'manifest.json', line: 1 }],
    },
  },
  'nested-wrapper': {
    dir: dir('nested-wrapper'),
    selfCheck: true,
    expected: {
      status: 'complete',
      exitCode: 1,
      thresholdTriggered: true,
      summary: { errors: 1, warnings: 0, notes: 0, filesScanned: 0, findingsTruncated: false },
      findings: [{ ruleId: 'CWSG002', level: 'error', path: 'manifest.json', line: 1 }],
    },
  },
  'bad-mv3': {
    dir: dir('bad-mv3'),
    selfCheck: true,
    expected: {
      status: 'complete',
      exitCode: 1,
      thresholdTriggered: true,
      // CWSG011/CWSG012 are warning-level (regex-based content heuristics
      // never fail the default error gate - see lib/rules.js RULES), so
      // errors/warnings and finding order shifted from their previous
      // error-level counts; notes are unaffected.
      summary: { errors: 5, warnings: 4, notes: 2, filesScanned: 3, findingsTruncated: false },
      findings: [
        { ruleId: 'CWSG008', level: 'error', path: 'manifest.json', line: 1 },
        { ruleId: 'CWSG008', level: 'error', path: 'manifest.json', line: 1 },
        { ruleId: 'CWSG009', level: 'error', path: 'manifest.json', line: 9 },
        { ruleId: 'CWSG010', level: 'error', path: 'manifest.json', line: 19 },
        { ruleId: 'CWSG016', level: 'error', path: 'manifest.json', line: 23 },
        { ruleId: 'CWSG012', level: 'warning', path: 'bg.js', line: 1 },
        { ruleId: 'CWSG013', level: 'warning', path: 'bg.js', line: 2 },
        { ruleId: 'CWSG014', level: 'warning', path: 'manifest.json', line: 22 },
        { ruleId: 'CWSG011', level: 'warning', path: 'popup.html', line: 5 },
        { ruleId: 'CWSG007', level: 'note', path: 'manifest.json', line: 6 },
        { ruleId: 'CWSG015', level: 'note', path: 'manifest.json', line: 21 },
      ],
    },
  },
};

module.exports = { EXPECTATIONS };
