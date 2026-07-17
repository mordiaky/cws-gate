'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { runSelfCheck } = require('../lib/self-check');
const { EXPECTATIONS } = require('../fixtures/expectations');

test('runSelfCheck passes across every fixture marked selfCheck: true', () => {
  const result = runSelfCheck();
  assert.equal(result.ok, true, result.details.join('\n'));
  assert.ok(result.details.length > 0);
});

test('runSelfCheck reports one PASS line per selfCheck fixture, in the order defined', () => {
  const result = runSelfCheck();
  const expectedNames = Object.entries(EXPECTATIONS)
    .filter(([, entry]) => entry.selfCheck)
    .map(([name]) => name);
  assert.ok(expectedNames.length > 0, 'at least one fixture must be marked selfCheck: true');
  assert.deepEqual(result.details, expectedNames.map((name) => `PASS  ${name}`));
});
