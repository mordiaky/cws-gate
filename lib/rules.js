'use strict';

// Frozen validation-beta rules (CWSG001-CWSG016). Pure functions only: every
// check here takes already-loaded data (parsed manifest, raw manifest text,
// a file-existence set, or a text-getter) and returns an array of findings.
// No filesystem access happens in this file - that keeps every rule unit
// testable with plain in-memory objects. See ventures/cws-gate/README-less
// design note in scan.js for the CWSG001/002 (manifest presence) logic,
// which needs raw directory-walk info and therefore lives there instead.

const posixPath = require('node:path').posix;
const crypto = require('node:crypto');

const POLICY_AS_OF = '2026-07-16';

const RULES = [
  {
    id: 'CWSG001',
    level: 'error',
    title: 'Root manifest.json missing, unreadable, non-object, or invalid strict JSON',
    policyUrl: 'https://developer.chrome.com/docs/extensions/reference/manifest',
    policyAsOf: POLICY_AS_OF,
    fix: 'Add a valid manifest.json at the package root containing a single top-level JSON object.',
  },
  {
    id: 'CWSG002',
    level: 'error',
    title: 'Exactly one top-level wrapper directory contains the manifest',
    policyUrl: 'https://developer.chrome.com/docs/extensions/reference/manifest',
    policyAsOf: POLICY_AS_OF,
    fix: 'Point the scanner at the directory that directly contains manifest.json, not its parent.',
  },
  {
    id: 'CWSG003',
    level: 'error',
    title: 'manifest_version is not 3',
    policyUrl: 'https://developer.chrome.com/docs/webstore/program-policies/mv3-requirements',
    policyAsOf: POLICY_AS_OF,
    fix: 'Set "manifest_version": 3.',
  },
  {
    id: 'CWSG004',
    level: 'error',
    title: 'name missing/empty or exceeds 75 characters',
    policyUrl: 'https://developer.chrome.com/docs/extensions/reference/manifest/name',
    policyAsOf: POLICY_AS_OF,
    fix: 'Set a non-empty "name" of 75 characters or fewer, or a "__MSG_name__" placeholder backed by _locales.',
  },
  {
    id: 'CWSG005',
    level: 'error',
    title: 'version is not a valid Chrome extension version string',
    policyUrl: 'https://developer.chrome.com/docs/extensions/reference/manifest/version',
    policyAsOf: POLICY_AS_OF,
    fix: 'Use 1-4 dot-separated integers 0-65535 with no leading zeros and at least one nonzero component, e.g. "1.0.0".',
  },
  {
    id: 'CWSG006',
    level: 'error',
    title: 'description missing/empty or exceeds 132 characters',
    policyUrl: 'https://developer.chrome.com/docs/extensions/reference/manifest/description',
    policyAsOf: POLICY_AS_OF,
    fix: 'Set a non-empty "description" of 132 characters or fewer, or a "__MSG_description__" placeholder.',
  },
  {
    id: 'CWSG007',
    level: 'error',
    title: 'icons missing, or no 128px icon present',
    policyUrl: 'https://developer.chrome.com/docs/extensions/reference/manifest/icons',
    policyAsOf: POLICY_AS_OF,
    fix: 'Add an "icons" object; include a 128x128 icon for store-listing quality.',
  },
  {
    id: 'CWSG008',
    level: 'error',
    title: 'Explicit manifest-referenced local file is absent or escapes the package',
    policyUrl: 'https://developer.chrome.com/docs/extensions/reference/manifest',
    policyAsOf: POLICY_AS_OF,
    fix: 'Ensure every manifest-referenced local file exists inside the package and no reference escapes the package root.',
  },
  {
    id: 'CWSG009',
    level: 'error',
    title: 'Manifest V2-only keys present in an MV3 manifest',
    policyUrl: 'https://developer.chrome.com/docs/extensions/develop/migrate/improve-security',
    policyAsOf: POLICY_AS_OF,
    fix: 'Remove Manifest V2-only keys (browser_action, page_action, background.scripts/page, string-form CSP, legacy web_accessible_resources) from an MV3 manifest.',
  },
  {
    id: 'CWSG010',
    level: 'error',
    title: 'extension_pages CSP allows a forbidden script-src value',
    policyUrl: 'https://developer.chrome.com/docs/extensions/develop/migrate/improve-security',
    policyAsOf: POLICY_AS_OF,
    fix: "Restrict content_security_policy.extension_pages script-src to 'self', 'none', or 'wasm-unsafe-eval' only; nonces and hashes are not honored here.",
  },
  // CWSG011/CWSG012 are regex/string matches over comment-masked text, not a
  // real HTML/JS parser - warning, not error, so a false positive here can
  // never fail the default --fail-on error gate. Same reasoning as CWSG013.
  {
    id: 'CWSG011',
    level: 'warning',
    title: 'Non-sandbox HTML references a remote or protocol-relative script',
    policyUrl: 'https://developer.chrome.com/docs/extensions/develop/migrate/improve-security',
    policyAsOf: POLICY_AS_OF,
    fix: 'Host the script locally inside the package and reference it with a package-relative src.',
  },
  {
    id: 'CWSG012',
    level: 'warning',
    title: 'importScripts(...) called with a literal remote URL',
    policyUrl: 'https://developer.chrome.com/docs/extensions/develop/migrate/improve-security',
    policyAsOf: POLICY_AS_OF,
    fix: 'Pass only package-relative paths to importScripts(...).',
  },
  {
    id: 'CWSG013',
    level: 'warning',
    title: 'eval( or new Function( found in JavaScript',
    policyUrl: 'https://developer.chrome.com/docs/extensions/develop/migrate/improve-security',
    policyAsOf: POLICY_AS_OF,
    fix: 'Avoid eval(...) and new Function(...); refactor to static code where practical.',
  },
  {
    id: 'CWSG014',
    level: 'warning',
    title: 'Broad host permission requests minimum-scope review',
    policyUrl: 'https://developer.chrome.com/docs/webstore/program-policies/user-data-faq',
    policyAsOf: POLICY_AS_OF,
    fix: "Scope host permissions as narrowly as the extension's functionality allows.",
  },
  {
    id: 'CWSG015',
    level: 'note',
    title: 'User-data-adjacent permission triggers a privacy/disclosure reminder',
    policyUrl: 'https://developer.chrome.com/docs/webstore/program-policies/user-data-faq',
    policyAsOf: POLICY_AS_OF,
    fix: "Confirm the store listing's privacy disclosures cover this permission's data use.",
  },
  {
    id: 'CWSG016',
    level: 'error',
    title: '_locales and default_locale are inconsistent',
    policyUrl: 'https://developer.chrome.com/docs/extensions/reference/api/i18n',
    policyAsOf: POLICY_AS_OF,
    fix: 'Keep default_locale and _locales/<default_locale>/messages.json present and consistent.',
  },
];

const RULES_BY_ID = new Map(RULES.map((r) => [r.id, r]));

const SEVERITY_ORDER = { error: 0, warning: 1, note: 2 };

// CLI/Action --fail-on values map to the minimum triggering severity.
// "never" has no threshold (null).
const FAIL_ON_MIN_SEVERITY = { error: 0, warn: 1, note: 2, never: null };

const MSG_PLACEHOLDER_RE = /^__MSG_[A-Za-z0-9_@]+__$/;

// ponytail: no JSON-position-tracking parser (that's most of a JSON parser).
// Approximate a finding's line by the first raw-text occurrence of its key;
// good enough for a beta lint, not a byte-exact source map.
function countLines(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

function lineAt(text, index) {
  if (typeof text !== 'string' || index < 0) return 1;
  return countLines(text, index);
}

function lineOfKey(rawText, key) {
  if (typeof rawText !== 'string') return 1;
  const idx = rawText.indexOf(`"${key}"`);
  if (idx === -1) return 1;
  return countLines(rawText, idx);
}

// Renders an arbitrary (possibly hostile: huge, deeply nested) manifest value
// for a finding message without ever recursing into it - JSON.stringify/
// String() on a deeply nested array/object can stack-overflow, so containers
// get a one-line shape summary instead of their full contents.
function describeValue(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (Array.isArray(value)) return `an array (length ${value.length})`;
  if (typeof value === 'object') return 'an object';
  if (typeof value === 'string') return `a string (length ${value.length})`;
  return `a ${typeof value}`;
}

// Hard per-call safety ceiling for the loops below - independent of the
// user-facing maxFindings truncation (lib/scan.js), this just bounds
// worst-case memory/CPU against a single pathological manifest or file
// (e.g. hundreds of thousands of eval( occurrences) before that later
// truncation ever runs.
const MAX_FINDINGS_PER_CHECK = 5000;

function makeFinding(ruleId, opts) {
  const meta = RULES_BY_ID.get(ruleId);
  if (!meta) throw new Error(`Unknown rule id: ${ruleId}`);
  return {
    ruleId,
    level: opts.level || meta.level,
    message: opts.message,
    fix: meta.fix,
    policyUrl: meta.policyUrl,
    policyAsOf: meta.policyAsOf,
    path: opts.path,
    line: opts.line || 1,
    column: opts.column || 1,
    detectorKey: opts.detectorKey || ruleId.toLowerCase(),
  };
}

function isValidVersion(version) {
  if (typeof version !== 'string' || version.length === 0) return false;
  const parts = version.split('.');
  if (parts.length < 1 || parts.length > 4) return false;
  let anyNonZero = false;
  for (const part of parts) {
    if (!/^[0-9]{1,5}$/.test(part)) return false;
    if (part.length > 1 && part[0] === '0') return false;
    const n = Number(part);
    if (n > 65535) return false;
    if (n !== 0) anyNonZero = true;
  }
  return anyNonZero;
}

function checkManifestVersion(manifest, rawText) {
  if (manifest.manifest_version !== 3) {
    return [
      makeFinding('CWSG003', {
        message: `Manifest "manifest_version" is ${describeValue(manifest.manifest_version)}; CWS Gate validates Manifest V3 only.`,
        path: 'manifest.json',
        line: lineOfKey(rawText, 'manifest_version'),
      }),
    ];
  }
  return [];
}

function checkName(manifest, rawText) {
  const name = manifest.name;
  if (typeof name === 'string' && MSG_PLACEHOLDER_RE.test(name)) return [];
  if (typeof name !== 'string' || name.length === 0) {
    return [
      makeFinding('CWSG004', {
        message: 'Manifest "name" is missing or empty.',
        path: 'manifest.json',
        line: lineOfKey(rawText, 'name'),
      }),
    ];
  }
  if (name.length > 75) {
    return [
      makeFinding('CWSG004', {
        message: `Manifest "name" is ${name.length} characters; the limit is 75.`,
        path: 'manifest.json',
        line: lineOfKey(rawText, 'name'),
      }),
    ];
  }
  return [];
}

function checkVersion(manifest, rawText) {
  if (!isValidVersion(manifest.version)) {
    return [
      makeFinding('CWSG005', {
        message: `Manifest "version" is ${describeValue(manifest.version)}, which is not 1-4 dot-separated integers 0-65535 without non-zero leading zeros, with at least one non-zero component.`,
        path: 'manifest.json',
        line: lineOfKey(rawText, 'version'),
      }),
    ];
  }
  return [];
}

function checkDescription(manifest, rawText) {
  const description = manifest.description;
  if (typeof description === 'string' && MSG_PLACEHOLDER_RE.test(description)) return [];
  if (typeof description !== 'string' || description.length === 0) {
    return [
      makeFinding('CWSG006', {
        message: 'Manifest "description" is missing or empty.',
        path: 'manifest.json',
        line: lineOfKey(rawText, 'description'),
      }),
    ];
  }
  if (description.length > 132) {
    return [
      makeFinding('CWSG006', {
        message: `Manifest "description" is ${description.length} characters; the limit is 132.`,
        path: 'manifest.json',
        line: lineOfKey(rawText, 'description'),
      }),
    ];
  }
  return [];
}

function checkIcons(manifest, rawText) {
  const icons = manifest.icons;
  if (!icons || typeof icons !== 'object' || Array.isArray(icons) || Object.keys(icons).length === 0) {
    return [
      makeFinding('CWSG007', {
        message: 'Manifest is missing an "icons" object.',
        path: 'manifest.json',
        line: lineOfKey(rawText, 'icons'),
      }),
    ];
  }
  if (!Object.prototype.hasOwnProperty.call(icons, '128')) {
    return [
      makeFinding('CWSG007', {
        level: 'note',
        message: 'Manifest "icons" has no 128px entry; Chrome Web Store listing quality benefits from one.',
        path: 'manifest.json',
        line: lineOfKey(rawText, 'icons'),
      }),
    ];
  }
  return [];
}

function collectLocalFileReferences(manifest) {
  const refs = [];
  const push = (value, fieldPath) => {
    if (typeof value === 'string') refs.push({ value, fieldPath });
  };
  if (manifest.icons && typeof manifest.icons === 'object' && !Array.isArray(manifest.icons)) {
    // Positional index, not the raw object key: icon "size" keys are
    // conventionally numeric, but nothing enforces that, so a hostile
    // manifest could otherwise leak an arbitrary key string into a finding's
    // field path.
    Object.values(manifest.icons).forEach((value, i) => push(value, `icons[${i}]`));
  }
  if (manifest.action && typeof manifest.action === 'object') {
    push(manifest.action.default_popup, 'action.default_popup');
    const icon = manifest.action.default_icon;
    if (typeof icon === 'string') push(icon, 'action.default_icon');
    else if (icon && typeof icon === 'object') {
      Object.values(icon).forEach((value, i) => push(value, `action.default_icon[${i}]`));
    }
  }
  if (manifest.background && typeof manifest.background.service_worker === 'string') {
    push(manifest.background.service_worker, 'background.service_worker');
  }
  if (typeof manifest.options_page === 'string') push(manifest.options_page, 'options_page');
  if (manifest.options_ui && typeof manifest.options_ui.page === 'string') {
    push(manifest.options_ui.page, 'options_ui.page');
  }
  if (typeof manifest.devtools_page === 'string') push(manifest.devtools_page, 'devtools_page');
  if (manifest.side_panel && typeof manifest.side_panel.default_path === 'string') {
    push(manifest.side_panel.default_path, 'side_panel.default_path');
  }
  if (manifest.sandbox && Array.isArray(manifest.sandbox.pages)) {
    manifest.sandbox.pages.forEach((p, i) => push(p, `sandbox.pages[${i}]`));
  }
  if (Array.isArray(manifest.content_scripts)) {
    manifest.content_scripts.forEach((entry, i) => {
      if (entry && Array.isArray(entry.js)) entry.js.forEach((p, j) => push(p, `content_scripts[${i}].js[${j}]`));
      if (entry && Array.isArray(entry.css)) entry.css.forEach((p, j) => push(p, `content_scripts[${i}].css[${j}]`));
    });
  }
  if (Array.isArray(manifest.web_accessible_resources)) {
    manifest.web_accessible_resources.forEach((entry, i) => {
      if (entry && Array.isArray(entry.resources)) {
        entry.resources.forEach((p, j) => push(p, `web_accessible_resources[${i}].resources[${j}]`));
      }
    });
  }
  if (manifest.declarative_net_request && Array.isArray(manifest.declarative_net_request.rule_resources)) {
    manifest.declarative_net_request.rule_resources.forEach((entry, i) => {
      if (entry && typeof entry.path === 'string') {
        push(entry.path, `declarative_net_request.rule_resources[${i}].path`);
      }
    });
  }
  if (manifest.chrome_url_overrides && typeof manifest.chrome_url_overrides === 'object') {
    // Positional index, not the raw key: keys are conventionally a fixed
    // enum (newtab/history/bookmarks) but nothing enforces that here either.
    Object.values(manifest.chrome_url_overrides).forEach((value, i) => push(value, `chrome_url_overrides[${i}]`));
  }
  return refs;
}

// A manifest local-file field must hold a package-relative path. Matches
// "https://...", "http://...", bare protocol-relative "//host/...", and any
// other "scheme://..." form (e.g. "chrome-extension://..."): all of these
// are remote/absolute, never package-relative, regardless of scheme.
// Matches a leading "scheme:" (any scheme, slash-optional - e.g. "https:evil.com/x"
// is a valid absolute URL per the WHATWG URL spec even without "//") or a leading
// "//" protocol-relative ref. Scheme-required-slashes would miss the former and
// under a wildcard field (web_accessible_resources) that silently exempts on '*'
// alone, that gap becomes a real silent bypass rather than just a wrong message.
const REMOTE_OR_ABSOLUTE_REF_RE = /^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|\/\/)/;
function isRemoteOrAbsoluteFileRef(value) {
  return REMOTE_OR_ABSOLUTE_REF_RE.test(value.trim());
}

function checkFileReferences(manifest, fileSet) {
  const findings = [];
  for (const ref of collectLocalFileReferences(manifest)) {
    const raw = ref.value;
    if (MSG_PLACEHOLDER_RE.test(raw)) continue;
    if (isRemoteOrAbsoluteFileRef(raw)) {
      // Never echo the raw URL back (privacy/no-secret-leakage invariant -
      // see the other CWSG008 messages below for the same convention).
      findings.push(
        makeFinding('CWSG008', {
          message: `Manifest field "${ref.fieldPath}" is a remote or absolute-URL reference; Chrome requires a package-relative path here.`,
          path: 'manifest.json',
          line: 1,
          detectorKey: `cwsg008-${ref.fieldPath}`,
        }),
      );
      if (findings.length >= MAX_FINDINGS_PER_CHECK) break;
      continue;
    }
    const stripped = raw.replace(/^\/+/, '');
    const normalized = posixPath.normalize(stripped);
    if (normalized === '..' || normalized.startsWith('../')) {
      findings.push(
        makeFinding('CWSG008', {
          message: `Manifest field "${ref.fieldPath}" references a local path that resolves outside the package.`,
          path: 'manifest.json',
          line: 1,
          detectorKey: `cwsg008-${ref.fieldPath}`,
        }),
      );
    } else if (raw.includes('*') && ref.fieldPath.startsWith('web_accessible_resources')) {
      // ponytail: beta skips glob expansion for web_accessible_resources
      // wildcards (e.g. "assets/*.png") - Chrome expands these against the
      // real file list at load time and this tool does not reimplement that
      // matcher, so a wildcarded resource entry is exempt from the existence
      // check (never from the "../" escape check above: an escaping pattern
      // escapes for every possible expansion, wildcard or not). Upgrade to
      // real glob matching against fileSet if false negatives on genuinely-
      // missing globbed assets become a problem.
    } else if (!fileSet.has(normalized)) {
      findings.push(
        makeFinding('CWSG008', {
          message: `Manifest field "${ref.fieldPath}" references a local path that is absent from the package.`,
          path: 'manifest.json',
          line: 1,
          detectorKey: `cwsg008-${ref.fieldPath}`,
        }),
      );
    }
    if (findings.length >= MAX_FINDINGS_PER_CHECK) break;
  }
  return findings;
}

function checkMv2Keys(manifest, rawText) {
  const findings = [];
  const flag = (key, message) => {
    findings.push(
      makeFinding('CWSG009', {
        message,
        path: 'manifest.json',
        line: lineOfKey(rawText, key),
        detectorKey: `cwsg009-${key}`,
      }),
    );
  };
  if (manifest.browser_action !== undefined) {
    flag('browser_action', 'Manifest declares "browser_action", a Manifest V2-only key; MV3 uses "action" instead.');
  }
  if (manifest.page_action !== undefined) {
    flag('page_action', 'Manifest declares "page_action", a Manifest V2-only key; MV3 has no replacement.');
  }
  if (manifest.background && typeof manifest.background === 'object') {
    if (Array.isArray(manifest.background.scripts)) {
      flag('scripts', 'Manifest declares "background.scripts", a Manifest V2-only key; MV3 uses "background.service_worker".');
    }
    if (typeof manifest.background.page === 'string') {
      flag('page', 'Manifest declares "background.page", a Manifest V2-only key; MV3 uses "background.service_worker".');
    }
  }
  if (typeof manifest.content_security_policy === 'string') {
    flag(
      'content_security_policy',
      'Manifest "content_security_policy" is a string, the Manifest V2 shape; MV3 requires an object with "extension_pages".',
    );
  }
  if (Array.isArray(manifest.web_accessible_resources) && manifest.web_accessible_resources.some((e) => typeof e === 'string')) {
    flag(
      'web_accessible_resources',
      'Manifest "web_accessible_resources" uses the Manifest V2 flat-array shape; MV3 requires objects with "resources" and "matches".',
    );
  }
  return findings;
}

const ALLOWED_CSP_TOKENS = new Set(["'self'", "'none'", "'wasm-unsafe-eval'"]);

function isForbiddenScriptSrcToken(token) {
  // MV3 extension_pages script-src is a closed allow-list: 'self', 'none',
  // and optionally 'wasm-unsafe-eval' only (Chrome's own docs: "cannot be
  // relaxed beyond this minimum value"). Nonces and hashes are legitimate
  // CSP mechanisms on the open web but are not honored in this context, so
  // they are forbidden here too rather than treated as safe escape hatches.
  // Matching is case-insensitive: CSP keywords are case-insensitive per spec.
  return !ALLOWED_CSP_TOKENS.has(token.toLowerCase());
}

function checkCsp(manifest, rawText) {
  const csp = manifest.content_security_policy;
  if (!csp || typeof csp !== 'object' || typeof csp.extension_pages !== 'string') return [];
  const directives = csp.extension_pages.split(';').map((d) => d.trim());
  // CSP semantics: default-src governs script-src whenever script-src itself
  // is absent, so a policy with only "default-src 'unsafe-eval'" is just as
  // permissive as one with an explicit forbidden script-src. Directive names
  // are case-insensitive per the CSP spec, hence the /i flag.
  const directive =
    directives.find((d) => /^script-src(\s|$)/i.test(d)) || directives.find((d) => /^default-src(\s|$)/i.test(d));
  if (!directive) return [];
  const tokens = directive.split(/\s+/).slice(1);
  const forbidden = [...new Set(tokens.filter(isForbiddenScriptSrcToken))];
  if (forbidden.length === 0) return [];
  const directiveName = directive.split(/\s+/)[0];
  return [
    makeFinding('CWSG010', {
      message: `content_security_policy.extension_pages ${directiveName} allows ${forbidden.length} forbidden source value(s); see the fix guidance for the allowed list.`,
      path: 'manifest.json',
      line: lineOfKey(rawText, 'extension_pages'),
      detectorKey: 'cwsg010-script-src',
    }),
  ];
}

function isBroadHostPattern(pattern) {
  if (pattern === '<all_urls>') return true;
  const m = /^(\*|https?|wss?|ftp):\/\/([^/]+)\//.exec(pattern);
  if (!m) return false;
  const host = m[2];
  // Exact wildcard host ("*") or any wildcard-subdomain host (e.g.
  // "*.example.com") both request the same human minimum-scope review: a
  // subdomain wildcard still grants the extension every current and future
  // subdomain of that domain, which is broad in practice even though it
  // names one registrable domain.
  return host === '*' || host.startsWith('*.');
}

function collectHostPatterns(manifest) {
  const patterns = [];
  // Plain loops, not `patterns.push(...arr)`: spreading a huge array as call
  // arguments can overflow V8's argument-count limit (RangeError) on a
  // manifest with tens of thousands of entries.
  if (Array.isArray(manifest.host_permissions)) {
    for (const p of manifest.host_permissions) patterns.push(p);
  }
  // optional_host_permissions is the same match-pattern shape, just
  // requested at runtime instead of install time - still worth a
  // minimum-scope look.
  if (Array.isArray(manifest.optional_host_permissions)) {
    for (const p of manifest.optional_host_permissions) patterns.push(p);
  }
  if (Array.isArray(manifest.permissions)) {
    for (const p of manifest.permissions) {
      if (typeof p === 'string' && (p === '<all_urls>' || p.includes('://'))) patterns.push(p);
    }
  }
  if (Array.isArray(manifest.optional_permissions)) {
    for (const p of manifest.optional_permissions) {
      if (typeof p === 'string' && (p === '<all_urls>' || p.includes('://'))) patterns.push(p);
    }
  }
  if (Array.isArray(manifest.content_scripts)) {
    for (const entry of manifest.content_scripts) {
      if (entry && Array.isArray(entry.matches)) {
        for (const m of entry.matches) patterns.push(m);
      }
    }
  }
  return patterns.filter((p) => typeof p === 'string');
}

function checkBroadPermissions(manifest, rawText) {
  const broad = [...new Set(collectHostPatterns(manifest).filter(isBroadHostPattern))];
  if (broad.length === 0) return [];
  return [
    makeFinding('CWSG014', {
      message: `Broad host access (${broad.length} pattern(s)) requests human minimum-scope review.`,
      path: 'manifest.json',
      line: lineOfKey(rawText, 'host_permissions'),
      detectorKey: 'cwsg014',
    }),
  ];
}

// Frozen minimal set: each name is explicitly named in the CWS Gate research
// (codex-cws-architecture.md CWS009 example list). Not exhaustive by design
// - CWSG015 is a disclosure reminder, never a necessity verdict.
const SENSITIVE_PERMISSIONS = new Set(['cookies', 'history', 'debugger', 'management', 'nativeMessaging', 'tabs', 'webRequest']);

function checkSensitivePermissions(manifest, rawText) {
  const perms = [];
  if (Array.isArray(manifest.permissions)) {
    for (const p of manifest.permissions) perms.push(p);
  }
  // Same disclosure obligation applies once optional_permissions is
  // actually requested at runtime, so scan it too.
  if (Array.isArray(manifest.optional_permissions)) {
    for (const p of manifest.optional_permissions) perms.push(p);
  }
  const hit = [...new Set(perms.filter((p) => typeof p === 'string' && SENSITIVE_PERMISSIONS.has(p)))];
  if (hit.length === 0) return [];
  return [
    makeFinding('CWSG015', {
      message: `${hit.length} user-data-adjacent permission(s) declared. Confirm the store listing's privacy disclosures cover this use; this is a reminder, not a necessity verdict.`,
      path: 'manifest.json',
      line: lineOfKey(rawText, 'permissions'),
      detectorKey: 'cwsg015',
    }),
  ];
}

function analyzeLocales(fileSet) {
  const folders = new Set();
  const withMessages = new Set();
  for (const relPath of fileSet.keys()) {
    const m = /^_locales\/([^/]+)\/(.*)$/.exec(relPath);
    if (m) {
      folders.add(m[1]);
      if (m[2] === 'messages.json') withMessages.add(m[1]);
    }
  }
  return { folders, withMessages };
}

function checkLocaleConsistency(manifest, rawText, fileSet) {
  const { folders, withMessages } = analyzeLocales(fileSet);
  const hasLocalesDir = folders.size > 0;
  const defaultLocale = manifest.default_locale;
  if (typeof defaultLocale === 'string' && defaultLocale.length > 0) {
    if (!hasLocalesDir) {
      return [
        makeFinding('CWSG016', {
          message: 'Manifest sets "default_locale" but no "_locales" directory exists.',
          path: 'manifest.json',
          line: lineOfKey(rawText, 'default_locale'),
          detectorKey: 'cwsg016-no-locales-dir',
        }),
      ];
    }
    if (!folders.has(defaultLocale)) {
      return [
        makeFinding('CWSG016', {
          message: 'Manifest\'s "default_locale" names a folder that is absent from "_locales/".',
          path: 'manifest.json',
          line: lineOfKey(rawText, 'default_locale'),
          detectorKey: 'cwsg016-missing-folder',
        }),
      ];
    }
    if (!withMessages.has(defaultLocale)) {
      return [
        makeFinding('CWSG016', {
          message: 'The default locale\'s "messages.json" is missing from "_locales/".',
          path: 'manifest.json',
          line: lineOfKey(rawText, 'default_locale'),
          detectorKey: 'cwsg016-missing-messages',
        }),
      ];
    }
    return [];
  }
  if (hasLocalesDir) {
    return [
      makeFinding('CWSG016', {
        message: 'Package has a "_locales" directory but manifest has no "default_locale".',
        path: 'manifest.json',
        line: 1,
        detectorKey: 'cwsg016-missing-default-locale',
      }),
    ];
  }
  return [];
}

function runManifestRules(manifest, rawText, fileSet) {
  return [
    ...checkManifestVersion(manifest, rawText),
    ...checkName(manifest, rawText),
    ...checkVersion(manifest, rawText),
    ...checkDescription(manifest, rawText),
    ...checkIcons(manifest, rawText),
    ...checkFileReferences(manifest, fileSet),
    ...checkMv2Keys(manifest, rawText),
    ...checkCsp(manifest, rawText),
    ...checkBroadPermissions(manifest, rawText),
    ...checkSensitivePermissions(manifest, rawText),
    ...checkLocaleConsistency(manifest, rawText, fileSet),
  ];
}

const HTML_EXT_RE = /\.html?$/i;
const JS_EXT_RE = /\.(m|c)?js$/i;
// Quoted ("..."/'...') or unquoted (HTML5 unquoted-attribute-value syntax:
// no whitespace/quote/backtick/angle-bracket/equals) src values, both.
const SCRIPT_SRC_RE = /<script\b[^>]*\bsrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'`<>=]+))[^>]*>/gi;
const IMPORT_SCRIPTS_RE = /\bimportScripts\s*\(([^)]*)\)/g;
const STRING_LITERAL_RE = /(['"`])((?:\\.|(?!\1).)*)\1/g;
const EVAL_RE = /\beval\s*\(/g;
const NEW_FUNCTION_RE = /\bnew\s+Function\s*\(/g;
const HTML_COMMENT_RE = /<!--[\s\S]*?-->/g;

// Matches "https://…"/"http://…" (slashes present) and bare
// protocol-relative "//host/…", plus the slashless form
// "https:evil.example/x.js" (colon present, "//" optional): per the WHATWG
// URL Standard, http/https are "special" schemes whose URLs are still
// absolute - and therefore remote - even when no "//" follows the colon, so
// a detector that required "://" would miss that legitimate remote-load
// gap. Scheme matching is case-insensitive per spec.
function isRemoteRef(value) {
  // Browsers trim leading/trailing ASCII whitespace (and more) before
  // resolving a URL attribute or importScripts() argument, so " https://…"
  // is still a remote load even though it doesn't start with the scheme.
  const v = value.trim();
  return /^https?:/i.test(v) || v.startsWith('//');
}

// Blanks out HTML comments before content matching, replacing every
// non-newline character (including the <!-- --> delimiters) with a space so
// commented-out markup never false-positives an error-level rule. Masking,
// not stripping: length and newline positions are identical to the input,
// so line numbers computed against the masked text via lineAt/lineOfKey
// match what a reader sees in the original file.
function maskHtmlComments(text) {
  return text.replace(HTML_COMMENT_RE, (m) => m.replace(/[^\n]/g, ' '));
}

// Blanks out // line comments and /* */ block comments before content
// matching, the same masking-not-stripping approach as maskHtmlComments (see
// above) so line numbers stay correct. A minimal single-pass scanner, not a
// full tokenizer: string/template literal contents are skipped over (so a
// URL literal's "//" is never mistaken for a comment start) and backslash
// escapes inside strings are respected, but this does not re-enter "code"
// mode for a template literal's ${...} interpolation (ponytail: real nested
// parsing is most of a JS parser; upgrade if a commented-out call nested
// inside a template interpolation ever needs to be masked too).
function maskJsComments(text) {
  let out = '';
  let i = 0;
  const n = text.length;
  let inString = null;
  while (i < n) {
    const c = text[i];
    if (inString) {
      out += c;
      if (c === '\\' && i + 1 < n) {
        out += text[i + 1];
        i += 2;
        continue;
      }
      if (c === inString) inString = null;
      i++;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      inString = c;
      out += c;
      i++;
      continue;
    }
    if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') {
        out += ' ';
        i++;
      }
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      out += '  ';
      i += 2;
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) {
        out += text[i] === '\n' ? '\n' : ' ';
        i++;
      }
      if (i < n) {
        out += '  ';
        i += 2;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

// Short, stable, non-reversible tag derived from a finding's matched content.
// Used only so a rule's detectorKey varies per distinct occurrence - never
// the raw content itself, since detectorKey flows straight into the JSON/text
// report. A SARIF fingerprint hashes ruleId|path|detectorKey (see report.js),
// so combining this tag with a per-tag occurrence counter (below) makes
// same-line duplicate findings fingerprint differently, while a harmless
// line inserted elsewhere in the file - which changes no match's content or
// relative order - leaves every finding's tag, occurrence count, and
// therefore fingerprint, unchanged.
function contentTag(text) {
  return crypto.createHash('sha256').update(text).digest('hex').slice(0, 16);
}

function checkHtmlRemoteScripts(files, sandboxPageSet, getText) {
  const findings = [];
  for (const file of files) {
    if (!HTML_EXT_RE.test(file.path) || sandboxPageSet.has(file.path)) continue;
    const text = getText(file.path);
    if (text == null) continue;
    const masked = maskHtmlComments(text);
    const seen = new Map();
    SCRIPT_SRC_RE.lastIndex = 0;
    let match;
    while ((match = SCRIPT_SRC_RE.exec(masked))) {
      const src = match[2] !== undefined ? match[2] : match[3] !== undefined ? match[3] : match[4];
      if (isRemoteRef(src)) {
        const tag = contentTag(src);
        const occurrence = seen.get(tag) || 0;
        seen.set(tag, occurrence + 1);
        findings.push(
          makeFinding('CWSG011', {
            message: `"${file.path}" loads a script from a non-package source (regex-based; may include false positives; manual review recommended).`,
            path: file.path,
            line: lineAt(masked, match.index),
            detectorKey: `cwsg011-${tag}-${occurrence}`,
          }),
        );
        if (findings.length >= MAX_FINDINGS_PER_CHECK) return findings;
      }
    }
  }
  return findings;
}

function checkImportScriptsRemote(files, getText) {
  const findings = [];
  for (const file of files) {
    if (!JS_EXT_RE.test(file.path)) continue;
    const text = getText(file.path);
    if (text == null) continue;
    const masked = maskJsComments(text);
    const seen = new Map();
    IMPORT_SCRIPTS_RE.lastIndex = 0;
    let call;
    while ((call = IMPORT_SCRIPTS_RE.exec(masked))) {
      STRING_LITERAL_RE.lastIndex = 0;
      let lit;
      while ((lit = STRING_LITERAL_RE.exec(call[1]))) {
        if (isRemoteRef(lit[2])) {
          const tag = contentTag(lit[2]);
          const occurrence = seen.get(tag) || 0;
          seen.set(tag, occurrence + 1);
          findings.push(
            makeFinding('CWSG012', {
              message: `"${file.path}" calls importScripts(...) with a remote URL literal (regex-based; may include false positives; manual review recommended).`,
              path: file.path,
              line: lineAt(masked, call.index),
              detectorKey: `cwsg012-${tag}-${occurrence}`,
            }),
          );
          if (findings.length >= MAX_FINDINGS_PER_CHECK) return findings;
        }
      }
    }
  }
  return findings;
}

function checkEvalUsage(files, getText) {
  const findings = [];
  for (const file of files) {
    if (!JS_EXT_RE.test(file.path)) continue;
    const text = getText(file.path);
    if (text == null) continue;
    const seen = new Map();
    for (const re of [EVAL_RE, NEW_FUNCTION_RE]) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        const tag = contentTag(m[0]);
        const occurrence = seen.get(tag) || 0;
        seen.set(tag, occurrence + 1);
        findings.push(
          makeFinding('CWSG013', {
            message: `"${file.path}" calls ${m[0].replace(/\s*\($/, '')}(...); flagged for manual review (regex-based match may include false positives inside comments or strings).`,
            path: file.path,
            line: lineAt(text, m.index),
            detectorKey: `cwsg013-${tag}-${occurrence}`,
          }),
        );
        if (findings.length >= MAX_FINDINGS_PER_CHECK) return findings;
      }
    }
  }
  return findings;
}

function runContentRules(files, sandboxPageSet, getText) {
  return [
    ...checkHtmlRemoteScripts(files, sandboxPageSet, getText),
    ...checkImportScriptsRemote(files, getText),
    ...checkEvalUsage(files, getText),
  ];
}

module.exports = {
  RULES,
  RULES_BY_ID,
  SEVERITY_ORDER,
  FAIL_ON_MIN_SEVERITY,
  POLICY_AS_OF,
  MSG_PLACEHOLDER_RE,
  makeFinding,
  isValidVersion,
  lineOfKey,
  lineAt,
  runManifestRules,
  runContentRules,
  // exported individually for focused unit tests
  checkManifestVersion,
  checkName,
  checkVersion,
  checkDescription,
  checkIcons,
  checkFileReferences,
  checkMv2Keys,
  checkCsp,
  checkBroadPermissions,
  checkSensitivePermissions,
  checkLocaleConsistency,
  checkHtmlRemoteScripts,
  checkImportScriptsRemote,
  checkEvalUsage,
  collectLocalFileReferences,
  isBroadHostPattern,
  isForbiddenScriptSrcToken,
  isRemoteOrAbsoluteFileRef,
  maskHtmlComments,
  maskJsComments,
};
