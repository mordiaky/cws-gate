'use strict';

// Proves the "no network access" guarantee behaviorally, not just by
// reading the source: patch every network primitive to throw, then run a
// full scan (and the Action wrapper) over a fixture whose own source text
// is full of remote-looking URL literals, and confirm nothing trips.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const dns = require('node:dns');
const { scan } = require('../lib/scan');

const BAD_MV3 = path.join(__dirname, '..', 'fixtures', 'bad-mv3');

function guard(obj, methodNames, moduleName) {
  const originals = {};
  for (const name of methodNames) {
    originals[name] = obj[name];
    obj[name] = () => {
      throw new Error(`network guard tripped: ${moduleName}.${name} was called`);
    };
  }
  return () => {
    for (const name of methodNames) obj[name] = originals[name];
  };
}

function guardNetwork() {
  const restores = [
    guard(http, ['request', 'get'], 'http'),
    guard(https, ['request', 'get'], 'https'),
    guard(net, ['connect', 'createConnection'], 'net'),
    guard(dns, ['lookup', 'resolve'], 'dns'),
  ];
  const originalFetch = global.fetch;
  global.fetch = () => {
    throw new Error('network guard tripped: global fetch was called');
  };
  return () => {
    for (const restore of restores) restore();
    if (originalFetch) global.fetch = originalFetch;
    else delete global.fetch;
  };
}

test('scan() never touches the network, even against fixtures whose source text contains remote URLs', () => {
  const restore = guardNetwork();
  try {
    // bad-mv3 contains literal "https://evil.example.com/..." strings that
    // CWSG011/CWSG012 detect by plain string/regex matching - if the scanner
    // ever "helpfully" tried to fetch one, this test fails.
    const result = scan(BAD_MV3);
    assert.equal(result.status, 'complete');
    assert.ok(result.findings.length > 0, 'the remote-URL findings still come from text matching only');
  } finally {
    restore();
  }
});

test('the GitHub Action wrapper also never touches the network for a normal scan', () => {
  const restore = guardNetwork();
  try {
    const { runAction } = require('../action/index');
    const code = runAction({ 'INPUT_PATH': BAD_MV3, 'INPUT_FAIL-ON': 'never' }, { log: () => {} });
    assert.equal(code, 0);
  } finally {
    restore();
  }
});
