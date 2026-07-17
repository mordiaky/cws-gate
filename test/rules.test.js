'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const rules = require('../lib/rules');

test('isValidVersion accepts and rejects per the frozen format', () => {
  assert.equal(rules.isValidVersion('1.0.0.0'), true);
  assert.equal(rules.isValidVersion('1'), true);
  assert.equal(rules.isValidVersion('65535.65535.65535.65535'), true);
  assert.equal(rules.isValidVersion('0.0.0.0'), false, 'all-zero is rejected');
  assert.equal(rules.isValidVersion('01.0'), false, 'non-zero leading zero is rejected');
  assert.equal(rules.isValidVersion('0'), false, 'a single zero component is all-zero');
  assert.equal(rules.isValidVersion('65536'), false, 'component over 65535 is rejected');
  assert.equal(rules.isValidVersion('1.2.3.4.5'), false, 'more than 4 components is rejected');
  assert.equal(rules.isValidVersion(''), false);
  assert.equal(rules.isValidVersion(undefined), false);
  assert.equal(rules.isValidVersion(3), false, 'must be a string, not a number');
});

test('CWSG003 manifest_version', () => {
  assert.equal(rules.checkManifestVersion({ manifest_version: 3 }, '').length, 0);
  const findings = rules.checkManifestVersion({ manifest_version: 2 }, '{"manifest_version": 2}');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CWSG003');
  assert.equal(findings[0].level, 'error');
});

test('CWSG004 name: missing, overlong, __MSG__ exempt', () => {
  assert.equal(rules.checkName({}, '').length, 1);
  assert.equal(rules.checkName({ name: '' }, '').length, 1);
  assert.equal(rules.checkName({ name: 'a'.repeat(76) }, '').length, 1);
  assert.equal(rules.checkName({ name: 'a'.repeat(75) }, '').length, 0, '75 is the boundary, not over it');
  assert.equal(rules.checkName({ name: '__MSG_appName__' }, '').length, 0);
});

test('CWSG005 version delegates to isValidVersion', () => {
  assert.equal(rules.checkVersion({ version: '1.2.3' }, '').length, 0);
  const findings = rules.checkVersion({ version: '01.2' }, '{"version": "01.2"}');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CWSG005');
});

test('CWSG006 description: missing, overlong, __MSG__ exempt', () => {
  assert.equal(rules.checkDescription({}, '').length, 1);
  assert.equal(rules.checkDescription({ description: 'a'.repeat(133) }, '').length, 1);
  assert.equal(rules.checkDescription({ description: 'a'.repeat(132) }, '').length, 0);
  assert.equal(rules.checkDescription({ description: '__MSG_desc__' }, '').length, 0);
});

test('CWSG007 icons: missing is an error, no-128 is a note', () => {
  const missing = rules.checkIcons({}, '');
  assert.equal(missing.length, 1);
  assert.equal(missing[0].level, 'error');

  const no128 = rules.checkIcons({ icons: { 16: 'a.png' } }, '');
  assert.equal(no128.length, 1);
  assert.equal(no128[0].level, 'note');

  const clean = rules.checkIcons({ icons: { 16: 'a.png', 128: 'b.png' } }, '');
  assert.equal(clean.length, 0);
});

test('CWSG008 file references: absent file, escaping path, exempt forms', () => {
  const fileSet = new Set(['popup.html', 'icons/16.png']);

  const absent = rules.checkFileReferences({ action: { default_popup: 'missing.html' } }, fileSet);
  assert.equal(absent.length, 1);
  assert.match(absent[0].message, /absent from the package/);

  const escaping = rules.checkFileReferences({ action: { default_popup: '../outside.html' } }, fileSet);
  assert.equal(escaping.length, 1);
  assert.match(escaping[0].message, /resolves outside the package/);

  const ok = rules.checkFileReferences({ action: { default_popup: 'popup.html' } }, fileSet);
  assert.equal(ok.length, 0);

  const exemptMsg = rules.checkFileReferences({ action: { default_popup: '__MSG_popup__' } }, fileSet);
  assert.equal(exemptMsg.length, 0);
});

test('CWSG008 flags a remote/absolute-URL reference in a manifest local-file field instead of exempting it', () => {
  const fileSet = new Set(['popup.html']);

  const httpsRef = rules.checkFileReferences({ action: { default_popup: 'https://evil.example.com/popup.html' } }, fileSet);
  assert.equal(httpsRef.length, 1);
  assert.equal(httpsRef[0].ruleId, 'CWSG008');
  assert.equal(httpsRef[0].level, 'error');
  assert.match(httpsRef[0].message, /remote or absolute-URL reference/);
  assert.ok(!httpsRef[0].message.includes('evil.example.com'), 'the raw URL is never echoed back');

  const httpRef = rules.checkFileReferences({ action: { default_popup: 'http://example.com/x.html' } }, fileSet);
  assert.equal(httpRef.length, 1);

  const protocolRelative = rules.checkFileReferences({ action: { default_popup: '//example.com/x.html' } }, fileSet);
  assert.equal(protocolRelative.length, 1, 'a bare protocol-relative reference is also flagged');

  const otherScheme = rules.checkFileReferences({ action: { default_popup: 'chrome-extension://abc/x.html' } }, fileSet);
  assert.equal(otherScheme.length, 1, 'any scheme:// form is flagged, not just http(s)');

  const local = rules.checkFileReferences({ action: { default_popup: 'popup.html' } }, fileSet);
  assert.equal(local.length, 0, 'an ordinary package-relative reference is unaffected');
});

test('CWSG008 web_accessible_resources wildcard existence-check exemption survives the remote-ref change', () => {
  const fileSet = new Set(['manifest.json']);
  const findings = rules.checkFileReferences(
    { web_accessible_resources: [{ resources: ['images/*'], matches: ['<all_urls>'] }] },
    fileSet,
  );
  assert.equal(findings.length, 0, 'a wildcarded WAR entry is still exempt from the existence check');
});

test('CWSG008 a slashless-scheme remote ref (e.g. "https:evil.com/*") in a wildcarded WAR entry is flagged, not silently exempted', () => {
  const fileSet = new Set(['manifest.json']);
  const findings = rules.checkFileReferences(
    { web_accessible_resources: [{ resources: ['https:evil.com/*'], matches: ['<all_urls>'] }] },
    fileSet,
  );
  assert.equal(findings.length, 1, 'the wildcard-existence exemption must not swallow a scheme-prefixed remote ref');
  assert.equal(findings[0].level, 'error');
  assert.match(findings[0].message, /remote or absolute-URL reference/);
});

test('CWSG009 flags each MV2-only key shape', () => {
  assert.equal(rules.checkMv2Keys({ browser_action: {} }, '').length, 1);
  assert.equal(rules.checkMv2Keys({ page_action: {} }, '').length, 1);
  assert.equal(rules.checkMv2Keys({ background: { scripts: ['a.js'] } }, '').length, 1);
  assert.equal(rules.checkMv2Keys({ background: { page: 'a.html' } }, '').length, 1);
  assert.equal(rules.checkMv2Keys({ content_security_policy: "script-src 'self'" }, '').length, 1);
  assert.equal(
    rules.checkMv2Keys({ web_accessible_resources: ['a.js'] }, '').length,
    1,
    'legacy flat-array shape (not objects with resources/matches)',
  );
  assert.equal(
    rules.checkMv2Keys({ web_accessible_resources: [{ resources: ['a.js'], matches: ['<all_urls>'] }] }, '').length,
    0,
    'MV3 object shape is not flagged',
  );
  assert.equal(rules.checkMv2Keys({ background: { service_worker: 'sw.js' } }, '').length, 0);
});

test('CWSG010 extension_pages script-src allow-list', () => {
  const forbidden = rules.checkCsp(
    { content_security_policy: { extension_pages: "script-src 'unsafe-eval' 'self'" } },
    '',
  );
  assert.equal(forbidden.length, 1);
  assert.match(forbidden[0].message, /1 forbidden source/);
  assert.doesNotMatch(forbidden[0].message, /unsafe-eval/, 'the raw forbidden token itself must not be echoed');

  for (const allowed of ["'self'", "'none'", "'wasm-unsafe-eval'"]) {
    assert.equal(
      rules.checkCsp({ content_security_policy: { extension_pages: `script-src ${allowed}` } }, '').length,
      0,
      `${allowed} should be allowed`,
    );
  }

  // MV3 extension_pages is a closed allow-list ('self', 'none', optional
  // 'wasm-unsafe-eval' only); nonces and hashes are real CSP mechanisms on
  // the open web but are not honored here, so they must be forbidden too.
  for (const notHonored of ["'nonce-abc123'", "'sha256-abc123'"]) {
    assert.equal(
      rules.checkCsp({ content_security_policy: { extension_pages: `script-src ${notHonored}` } }, '').length,
      1,
      `${notHonored} is not honored by MV3 extension_pages and must be forbidden`,
    );
  }

  assert.equal(
    rules.checkCsp({ content_security_policy: { extension_pages: "object-src 'self'" } }, '').length,
    0,
    'no script-src directive present means nothing to flag',
  );
});

test('isBroadHostPattern: exact wildcard host and wildcard subdomains both count as broad', () => {
  assert.equal(rules.isBroadHostPattern('<all_urls>'), true);
  assert.equal(rules.isBroadHostPattern('https://*/*'), true);
  assert.equal(rules.isBroadHostPattern('*://*/*'), true);
  assert.equal(rules.isBroadHostPattern('https://example.com/*'), false, 'a specific host is not broad');
  assert.equal(
    rules.isBroadHostPattern('https://*.example.com/*'), true,
    'a wildcard subdomain still grants every subdomain of a site - CWSG014 must warn on it too',
  );
  assert.equal(rules.isBroadHostPattern('wss://*.example.com/*'), true, 'wildcard subdomain, non-http(s) scheme');
});

test('CWSG014 broad host permissions from host_permissions and content_scripts matches', () => {
  const fromHostPermissions = rules.checkBroadPermissions({ host_permissions: ['<all_urls>'] }, '');
  assert.equal(fromHostPermissions.length, 1);
  assert.equal(fromHostPermissions[0].level, 'warning');

  const fromContentScripts = rules.checkBroadPermissions(
    { content_scripts: [{ matches: ['https://*/*'] }] },
    '',
  );
  assert.equal(fromContentScripts.length, 1);

  const scoped = rules.checkBroadPermissions({ host_permissions: ['https://example.com/*'] }, '');
  assert.equal(scoped.length, 0);
});

test('CWSG014 also scans optional_host_permissions and host-pattern entries in optional_permissions', () => {
  const fromOptionalHost = rules.checkBroadPermissions({ optional_host_permissions: ['<all_urls>'] }, '');
  assert.equal(fromOptionalHost.length, 1);
  assert.equal(fromOptionalHost[0].level, 'warning');

  const fromOptionalPermissions = rules.checkBroadPermissions({ optional_permissions: ['https://*/*'] }, '');
  assert.equal(fromOptionalPermissions.length, 1);

  const scoped = rules.checkBroadPermissions({ optional_host_permissions: ['https://example.com/*'] }, '');
  assert.equal(scoped.length, 0);
});

test('CWSG015 sensitive permissions are a reminder, reports a count and never the permission names', () => {
  const mixed = rules.checkSensitivePermissions({ permissions: ['tabs', 'storage'] }, '');
  assert.equal(mixed.length, 1);
  assert.equal(mixed[0].level, 'note');
  assert.match(
    mixed[0].message, /^1 user-data-adjacent permission\(s\) declared/,
    'storage is not in the sensitive set, so only tabs is counted',
  );
  assert.doesNotMatch(mixed[0].message, /tabs/, 'no raw permission name in the message');
  assert.doesNotMatch(mixed[0].message, /storage/, 'no raw permission name in the message');

  const twoSensitive = rules.checkSensitivePermissions({ permissions: ['tabs', 'cookies'] }, '');
  assert.match(
    twoSensitive[0].message, /^2 user-data-adjacent permission\(s\) declared/,
    'the count reflects multiple sensitive hits',
  );

  assert.equal(rules.checkSensitivePermissions({ permissions: ['storage'] }, '').length, 0, 'storage alone is not sensitive');
});

test('CWSG015 also scans optional_permissions for sensitive entries', () => {
  const findings = rules.checkSensitivePermissions({ optional_permissions: ['cookies'] }, '');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].level, 'note');
  assert.match(findings[0].message, /^1 user-data-adjacent permission\(s\) declared/);

  const combined = rules.checkSensitivePermissions({ permissions: ['tabs'], optional_permissions: ['cookies'] }, '');
  assert.match(
    combined[0].message, /^2 user-data-adjacent permission\(s\) declared/,
    'permissions and optional_permissions both count toward the total',
  );
});

test('CWSG016 locale consistency in both directions', () => {
  const noLocalesDir = rules.checkLocaleConsistency({ default_locale: 'en' }, '', new Set());
  assert.equal(noLocalesDir.length, 1);
  assert.match(noLocalesDir[0].message, /no "_locales" directory/);

  const missingFolder = rules.checkLocaleConsistency(
    { default_locale: 'en' }, '', new Set(['_locales/fr/messages.json']),
  );
  assert.equal(missingFolder.length, 1);
  assert.match(missingFolder[0].message, /"default_locale".*folder.*absent/, 'generic wording, never the locale name itself');
  assert.doesNotMatch(missingFolder[0].message, /\ben\b/, 'the "en" locale value must not be echoed');

  const missingMessages = rules.checkLocaleConsistency(
    { default_locale: 'en' }, '', new Set(['_locales/en/other.json']),
  );
  assert.equal(missingMessages.length, 1);
  assert.match(missingMessages[0].message, /messages\.json".*missing/);
  assert.doesNotMatch(missingMessages[0].message, /\ben\b/, 'the "en" locale value must not be echoed');

  const consistent = rules.checkLocaleConsistency(
    { default_locale: 'en' }, '', new Set(['_locales/en/messages.json']),
  );
  assert.equal(consistent.length, 0);

  const noDefaultButHasDir = rules.checkLocaleConsistency({}, '', new Set(['_locales/en/messages.json']));
  assert.equal(noDefaultButHasDir.length, 1);
  assert.match(noDefaultButHasDir[0].message, /no "default_locale"/);

  const neither = rules.checkLocaleConsistency({}, '', new Set());
  assert.equal(neither.length, 0);
});

test('CWSG011 remote/protocol-relative script src, sandbox pages exempt', () => {
  const files = [{ path: 'popup.html' }, { path: 'sandbox.html' }];
  const getText = (p) => {
    if (p === 'popup.html') return '<script src="https://cdn.example.com/a.js"></script><script src="local.js"></script>';
    if (p === 'sandbox.html') return '<script src="//cdn.example.com/a.js"></script>';
    return null;
  };
  const sandboxPageSet = new Set(['sandbox.html']);
  const findings = rules.checkHtmlRemoteScripts(files, sandboxPageSet, getText);
  assert.equal(findings.length, 1, 'only the non-sandbox remote script is flagged');
  assert.equal(findings[0].path, 'popup.html');
  assert.equal(findings[0].level, 'warning', 'CWSG011 is regex-based content heuristics; downgraded so it never fails the default error gate');
  assert.match(findings[0].message, /regex-based; may include false positives; manual review recommended/);
});

test('CWSG012 importScripts with a remote URL literal, local path exempt', () => {
  const files = [{ path: 'bg.js' }];
  const getText = () => 'importScripts("local.js", "https://evil.example.com/x.js");';
  const findings = rules.checkImportScriptsRemote(files, getText);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].level, 'warning', 'CWSG012 is regex-based content heuristics; downgraded so it never fails the default error gate');
  assert.match(findings[0].message, /regex-based; may include false positives; manual review recommended/);
  assert.doesNotMatch(findings[0].message, /evil\.example\.com/, 'the remote URL itself must not be echoed into the message');
});

test('CWSG011 and CWSG012 are warning-level in the frozen RULES metadata', () => {
  assert.equal(rules.RULES_BY_ID.get('CWSG011').level, 'warning');
  assert.equal(rules.RULES_BY_ID.get('CWSG012').level, 'warning');
});

test('CWSG013 eval and new Function, with the regex boundary documented by example', () => {
  const files = [{ path: 'a.js' }];
  assert.equal(rules.checkEvalUsage(files, () => 'eval("x")').length, 1);
  assert.equal(rules.checkEvalUsage(files, () => 'new Function("return 1")').length, 1);
  assert.equal(
    rules.checkEvalUsage(files, () => 'window.eval("x")').length, 1,
    'a "." boundary before eval still matches - documented false-positive risk',
  );
  assert.equal(
    rules.checkEvalUsage(files, () => 'myeval("x")').length, 0,
    'no word boundary before eval inside a longer identifier',
  );
});

test('CWSG010 falls back to default-src when script-src is absent (CSP fallback semantics)', () => {
  const viaDefault = rules.checkCsp({ content_security_policy: { extension_pages: "default-src 'unsafe-eval'" } }, '');
  assert.equal(viaDefault.length, 1, 'default-src governs script loading whenever script-src itself is absent');
  assert.match(viaDefault[0].message, /default-src/);

  const explicitScriptSrcWins = rules.checkCsp(
    { content_security_policy: { extension_pages: "default-src 'unsafe-eval'; script-src 'self'" } },
    '',
  );
  assert.equal(explicitScriptSrcWins.length, 0, 'an explicit, compliant script-src overrides default-src');
});

test('CWSG011 catches a remote script src with leading/trailing whitespace', () => {
  const files = [{ path: 'popup.html' }];
  const getText = () => '<script src="  https://evil.example.com/x.js  "></script>';
  const findings = rules.checkHtmlRemoteScripts(files, new Set(), getText);
  assert.equal(findings.length, 1, 'whitespace around the URL must not bypass the remote-script check');
});

test('CWSG011 catches a slashless remote script src (scheme colon without "//" still resolves absolute/remote per WHATWG)', () => {
  const files = [{ path: 'popup.html' }];
  const getText = () => '<script src="https:evil.example/x.js"></script>';
  const findings = rules.checkHtmlRemoteScripts(files, new Set(), getText);
  assert.equal(findings.length, 1, 'a slashless "https:" src is still a remote load and must be flagged');
});

test('CWSG012 catches a slashless remote importScripts literal (scheme colon without "//" still resolves absolute/remote per WHATWG)', () => {
  const files = [{ path: 'bg.js' }];
  const getText = () => 'importScripts("https:evil.example/x.js");';
  const findings = rules.checkImportScriptsRemote(files, getText);
  assert.equal(findings.length, 1, 'a slashless "https:" literal is still a remote load and must be flagged');
});

test('CWSG011/CWSG012 regression: ordinary local/relative script references still pass clean after the slashless-scheme widening', () => {
  const htmlFiles = [{ path: 'popup.html' }];
  const htmlText = () =>
    '<script src="local.js"></script><script src="./scripts/app.js"></script><script src="../shared/lib.js"></script>';
  assert.equal(
    rules.checkHtmlRemoteScripts(htmlFiles, new Set(), htmlText).length, 0,
    'ordinary package-relative script src values must never be flagged',
  );

  const jsFiles = [{ path: 'bg.js' }];
  const jsText = () => 'importScripts("local.js", "./scripts/app.js", "../shared/lib.js");';
  assert.equal(
    rules.checkImportScriptsRemote(jsFiles, jsText).length, 0,
    'ordinary package-relative importScripts literals must never be flagged',
  );
});

test('CWSG003/CWSG005 messages never crash on a hostile deeply nested manifest_version/version', () => {
  let deep = 'leaf';
  for (let i = 0; i < 50000; i++) deep = [deep];
  assert.doesNotThrow(() => rules.checkManifestVersion({ manifest_version: deep }, ''));
  assert.doesNotThrow(() => rules.checkVersion({ version: deep }, ''));
  const findings = rules.checkManifestVersion({ manifest_version: deep }, '');
  assert.match(findings[0].message, /an array \(length 1\)/, 'containers get a shape summary, never their full nested contents');
});

test('checkBroadPermissions never crashes on a manifest with an oversized host_permissions array', () => {
  const hostPermissions = new Array(300000).fill('https://example.com/*');
  assert.doesNotThrow(() => rules.checkBroadPermissions({ host_permissions: hostPermissions }, ''));
});

test('CWSG008 flags an empty-string manifest reference instead of silently ignoring it', () => {
  const findings = rules.checkFileReferences({ action: { default_popup: '' } }, new Set());
  assert.equal(findings.length, 1, 'an empty string is not a valid file reference and must be flagged, not ignored');
});

test('CWSG008 privacy: an absent-file reference never echoes the secret-like path value', () => {
  const secret = 'sk_live_should_never_leak_via_cwsg008';
  const findings = rules.checkFileReferences({ action: { default_popup: `${secret}.html` } }, new Set());
  assert.equal(findings.length, 1);
  assert.ok(!findings[0].message.includes(secret), 'the referenced value must not appear in the message');
  assert.match(findings[0].message, /absent from the package/);
  assert.match(findings[0].message, /action\.default_popup/, 'the structural field path is retained');
});

test('CWSG010 privacy: a secret-like CSP token is counted but never echoed', () => {
  const secret = 'AKIAsecretvalue1234567890';
  const findings = rules.checkCsp(
    { content_security_policy: { extension_pages: `script-src 'nonce-${secret}'` } },
    '',
  );
  assert.equal(findings.length, 1);
  assert.ok(!findings[0].message.includes(secret), 'the CSP token value must not appear in the message');
  assert.match(findings[0].message, /1 forbidden source/);
});

test('CWSG011 privacy: a secret-like query string on a remote script src is never echoed', () => {
  const secret = 'sk_live_should_never_leak_via_cwsg011';
  const files = [{ path: 'popup.html' }];
  const getText = () => `<script src="https://evil.example.com/x.js?token=${secret}"></script>`;
  const findings = rules.checkHtmlRemoteScripts(files, new Set(), getText);
  assert.equal(findings.length, 1);
  assert.ok(!findings[0].message.includes(secret), 'the script src (and any embedded secret) must not appear in the message');
  assert.match(findings[0].message, /non-package source/);
});

test('CWSG012 privacy: a secret-like query string on a remote importScripts literal is never echoed', () => {
  const secret = 'sk_live_should_never_leak_via_cwsg012';
  const files = [{ path: 'bg.js' }];
  const getText = () => `importScripts("https://evil.example.com/x.js?token=${secret}");`;
  const findings = rules.checkImportScriptsRemote(files, getText);
  assert.equal(findings.length, 1);
  assert.ok(!findings[0].message.includes(secret), 'the URL literal (and any embedded secret) must not appear in the message');
});

test('CWSG014 privacy: a broad host pattern with a secret-like path/query is never echoed', () => {
  const secret = 'sk_live_should_never_leak_via_cwsg014';
  const findings = rules.checkBroadPermissions({ host_permissions: [`https://*/webhook?token=${secret}`] }, '');
  assert.equal(findings.length, 1);
  assert.ok(!findings[0].message.includes(secret), 'the host_permissions pattern (and any embedded secret) must not appear in the message');
  assert.match(findings[0].message, /1 pattern/);
});

test('CWSG008: web_accessible_resources wildcard patterns are exempt from the existence check', () => {
  const fileSet = new Set(['popup.html']);
  const wildcard = rules.checkFileReferences(
    { web_accessible_resources: [{ resources: ['assets/*.png'], matches: ['<all_urls>'] }] },
    fileSet,
  );
  assert.equal(wildcard.length, 0, 'a "*" resource pattern is not existence-checked in beta');

  const nonWildcardStillChecked = rules.checkFileReferences(
    { web_accessible_resources: [{ resources: ['assets/missing.png'], matches: ['<all_urls>'] }] },
    fileSet,
  );
  assert.equal(nonWildcardStillChecked.length, 1, 'a concrete (non-wildcard) missing resource is still flagged');

  const escapingWildcardStillChecked = rules.checkFileReferences(
    { web_accessible_resources: [{ resources: ['../*.png'], matches: ['<all_urls>'] }] },
    fileSet,
  );
  assert.equal(escapingWildcardStillChecked.length, 1, 'the "../" escape check applies regardless of a wildcard');
  assert.match(escapingWildcardStillChecked[0].message, /resolves outside the package/);
});

test('CWSG008: field paths use positional indices, never a user-controlled object key', () => {
  const iconKeyLeak = rules.checkFileReferences({ icons: { sk_live_evil_icon_key: 'missing.png' } }, new Set());
  assert.equal(iconKeyLeak.length, 1);
  assert.ok(!iconKeyLeak[0].message.includes('sk_live_evil_icon_key'), 'the raw icons object key must not leak into the field path');
  assert.match(iconKeyLeak[0].message, /"icons\[0\]"/);

  const actionIconKeyLeak = rules.checkFileReferences(
    { action: { default_icon: { sk_live_evil_icon_key: 'missing.png' } } },
    new Set(),
  );
  assert.equal(actionIconKeyLeak.length, 1);
  assert.ok(!actionIconKeyLeak[0].message.includes('sk_live_evil_icon_key'));
  assert.match(actionIconKeyLeak[0].message, /"action\.default_icon\[0\]"/);

  const overrideKeyLeak = rules.checkFileReferences(
    { chrome_url_overrides: { sk_live_evil_override_key: 'missing.html' } },
    new Set(),
  );
  assert.equal(overrideKeyLeak.length, 1);
  assert.ok(!overrideKeyLeak[0].message.includes('sk_live_evil_override_key'));
  assert.match(overrideKeyLeak[0].message, /"chrome_url_overrides\[0\]"/);
});

test('describeValue: type/length shape only, never the raw value, including plain objects', () => {
  const objectVersion = rules.checkVersion({ version: { evil: 'sk_live_should_never_leak' } }, '');
  assert.match(objectVersion[0].message, /is an object,/);
  assert.ok(!objectVersion[0].message.includes('sk_live_should_never_leak'));

  const nullManifestVersion = rules.checkManifestVersion({ manifest_version: null }, '');
  assert.match(nullManifestVersion[0].message, /is null;/);

  const secret = 'sk_live_should_never_leak_as_a_version_string';
  const stringVersion = rules.checkVersion({ version: secret }, '');
  assert.match(stringVersion[0].message, new RegExp(`a string \\(length ${secret.length}\\)`));
  assert.ok(!stringVersion[0].message.includes(secret));
});

test('CWSG010: CSP directive names and allowed keywords are matched case-insensitively', () => {
  const upperDirective = rules.checkCsp({ content_security_policy: { extension_pages: "Script-Src 'unsafe-eval'" } }, '');
  assert.equal(upperDirective.length, 1, 'a differently-cased directive name must still be recognized');

  const upperDefaultSrc = rules.checkCsp({ content_security_policy: { extension_pages: "DEFAULT-SRC 'unsafe-eval'" } }, '');
  assert.equal(upperDefaultSrc.length, 1, 'default-src fallback must also match case-insensitively');

  const upperAllowedKeyword = rules.checkCsp({ content_security_policy: { extension_pages: "script-src 'SELF'" } }, '');
  assert.equal(upperAllowedKeyword.length, 0, "'SELF' must be recognized as the allowed 'self' keyword");

  const mixedAllowedKeyword = rules.checkCsp(
    { content_security_policy: { extension_pages: "script-src 'Wasm-Unsafe-Eval'" } }, '',
  );
  assert.equal(mixedAllowedKeyword.length, 0, "mixed-case 'wasm-unsafe-eval' must still be allowed");
});

test('CWSG014: a wildcard-subdomain host pattern warns just like an exact wildcard host', () => {
  const subdomain = rules.checkBroadPermissions({ host_permissions: ['https://*.example.com/*'] }, '');
  assert.equal(subdomain.length, 1);
  assert.equal(subdomain[0].level, 'warning');

  const viaContentScripts = rules.checkBroadPermissions(
    { content_scripts: [{ matches: ['https://*.example.com/*'] }] }, '',
  );
  assert.equal(viaContentScripts.length, 1);
});

test('CWSG011: unquoted script src attribute values are matched too', () => {
  const files = [{ path: 'popup.html' }];
  const getText = () => '<script src=https://evil.example.com/a.js></script>';
  const findings = rules.checkHtmlRemoteScripts(files, new Set(), getText);
  assert.equal(findings.length, 1, 'HTML5 permits an unquoted attribute value; it must not bypass the check');
});

test('CWSG011: a remote script src inside an HTML comment is masked out, not flagged', () => {
  const files = [{ path: 'popup.html' }];
  const getText = () => '<!-- <script src="https://evil.example.com/a.js"></script> -->\n<script src="local.js"></script>';
  const findings = rules.checkHtmlRemoteScripts(files, new Set(), getText);
  assert.equal(findings.length, 0, 'a commented-out remote script tag must not fire an error-level rule');
});

test('CWSG011: comment masking preserves line numbers of findings after the comment', () => {
  const files = [{ path: 'popup.html' }];
  const getText = () =>
    '<!-- old:\n<script src="https://old.example.com/a.js"></script>\n-->\n<script src="https://new.example.com/b.js"></script>';
  const findings = rules.checkHtmlRemoteScripts(files, new Set(), getText);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 4, 'the real (uncommented) remote script is on line 4 of the original text');
});

test('maskHtmlComments: same length and newline positions as the input, comment content blanked', () => {
  const text = '<!-- secret sk_live_x\nmore -->\nafter';
  const masked = rules.maskHtmlComments(text);
  assert.equal(masked.length, text.length);
  assert.equal((masked.match(/\n/g) || []).length, (text.match(/\n/g) || []).length);
  assert.ok(!masked.includes('secret'));
  assert.ok(masked.endsWith('\nafter'));
});

test('CWSG012: importScripts inside a // line comment or /* */ block comment is masked out', () => {
  const files = [{ path: 'bg.js' }];
  const lineComment = () => '// importScripts("https://evil.example.com/x.js");\nimportScripts("local.js");';
  assert.equal(rules.checkImportScriptsRemote(files, lineComment).length, 0);

  const blockComment = () => '/* importScripts("https://evil.example.com/x.js"); */\nimportScripts("local.js");';
  assert.equal(rules.checkImportScriptsRemote(files, blockComment).length, 0);
});

test('CWSG012: a remote URL literal (containing "//") is still matched after JS-comment masking', () => {
  const files = [{ path: 'bg.js' }];
  const getText = () => 'importScripts("https://evil.example.com/x.js");';
  const findings = rules.checkImportScriptsRemote(files, getText);
  assert.equal(findings.length, 1, 'the URL string\'s own "//" must not be mistaken for a line comment and eat the call');
});

test('maskJsComments: strings/template literals survive untouched, comments are blanked without changing length', () => {
  const text = 'const u = "http://example.com"; // trailing\n/* block\ncomment */ done';
  const masked = rules.maskJsComments(text);
  assert.equal(masked.length, text.length);
  assert.ok(masked.includes('"http://example.com"'), 'a string literal containing // must survive untouched');
  assert.ok(!masked.includes('trailing'));
  assert.ok(!masked.includes('comment'));
  assert.equal((masked.match(/\n/g) || []).length, (text.match(/\n/g) || []).length);
});

test('CWSG013 (warning-level) intentionally still fires inside comments - unlike CWSG011/012 it is not masked', () => {
  const files = [{ path: 'bg.js' }];
  const findings = rules.checkEvalUsage(files, () => '// eval("x")');
  assert.equal(
    findings.length, 1,
    'CWSG013 is a warning-level heuristic that documents comment/string false positives rather than masking them out',
  );
});

test('CWSG011: two identical-content remote scripts on the same line get different detectorKeys', () => {
  const files = [{ path: 'popup.html' }];
  const getText = () =>
    '<script src="https://evil.example.com/a.js"></script><script src="https://evil.example.com/a.js"></script>';
  const findings = rules.checkHtmlRemoteScripts(files, new Set(), getText);
  assert.equal(findings.length, 2);
  assert.equal(findings[0].line, findings[1].line, 'both matches are on the same line');
  assert.notEqual(findings[0].detectorKey, findings[1].detectorKey, 'same-line duplicates must still get distinct detector keys');
});

test("CWSG011: a harmless line inserted earlier in the file does not change an existing finding's detectorKey", () => {
  const files = [{ path: 'popup.html' }];
  const before = rules.checkHtmlRemoteScripts(
    files, new Set(), () => '<script src="https://evil.example.com/a.js"></script>',
  );
  const after = rules.checkHtmlRemoteScripts(
    files, new Set(),
    () => '<!-- an unrelated line was inserted here -->\n<script src="https://evil.example.com/a.js"></script>',
  );
  assert.equal(before.length, 1);
  assert.equal(after.length, 1);
  assert.notEqual(before[0].line, after[0].line, 'the line number does shift...');
  assert.equal(before[0].detectorKey, after[0].detectorKey, '...but the detectorKey (and therefore SARIF fingerprint) must not');
});

test('detectorKey never contains the raw matched URL/content', () => {
  const secret = 'sk_live_should_never_appear_in_detectorKey';
  const files = [{ path: 'popup.html' }];
  const findings = rules.checkHtmlRemoteScripts(
    files, new Set(), () => `<script src="https://evil.example.com/x.js?token=${secret}"></script>`,
  );
  assert.equal(findings.length, 1);
  assert.ok(
    !findings[0].detectorKey.includes(secret),
    'detectorKey flows verbatim into JSON/SARIF - it must never carry raw content',
  );
});

test('every RULES entry has the fields report.js and self-check depend on', () => {
  for (const r of rules.RULES) {
    assert.equal(typeof r.id, 'string');
    assert.match(r.id, /^CWSG0[01]\d$/);
    assert.ok(['error', 'warning', 'note'].includes(r.level));
    assert.equal(typeof r.title, 'string');
    assert.ok(r.title.length > 0);
    assert.equal(typeof r.policyUrl, 'string');
    assert.ok(r.policyUrl.startsWith('https://'));
    assert.equal(r.policyAsOf, rules.POLICY_AS_OF);
    assert.equal(typeof r.fix, 'string');
  }
  assert.equal(rules.RULES.length, 16);
});
