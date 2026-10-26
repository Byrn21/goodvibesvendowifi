#!/usr/bin/env node
/**
 * test-omada.js — isolated diagnostic for the Omada hotspot operator login
 *
 * Performs EXACTLY ONE request: POST /{OMADAC_ID}/api/v2/hotspot/login,
 * built with the same path, body and headers as services/omada.js
 * (operatorLogin → omadaRequest), then prints:
 *
 *   - how each OMADA_* value was resolved (.env vs an already-set env var),
 *   - a non-secret character/length/fingerprint report for the credentials,
 *   - the controller ID the controller itself advertises (compared with
 *     OMADA_OMADAC_ID),
 *   - the exact raw request line, headers and body that were sent,
 *   - the exact raw response status line, headers and body received.
 *
 * Usage (from backend/):
 *   node test-omada.js
 *   node test-omada.js --base-url=https://192.168.0.253
 *   node test-omada.js --omadac-id=1ca11aa28d1af4873797a722198f6d00 --allow-placeholder
 *
 * Flags:
 *   --base-url=<url>     Override OMADA_BASE_URL (useful while it is a placeholder)
 *   --omadac-id=<id>     Override OMADA_OMADAC_ID
 *   --timeout=<ms>       Override OMADA_AUTH_TIMEOUT
 *   --allow-placeholder  Send even if the credentials/base URL look like
 *                        .env.example placeholders (off by default)
 *   --reveal             Print the password in the raw body (off by default;
 *                        every other line stays masked)
 *   --no-origin          Omit Origin/Referer (CSRF-filter probe)
 *   --form               Send name=...&password=... form-encoded instead of
 *                        JSON (the legacy FAQ 2907 PHP sample's shape)
 *   --skip-id-check      Skip the GET that discovers the controller's ID
 *   --help
 *
 * IMPORTANT: the Omada controller counts failed logins per account. Each run
 * is one login attempt — do not loop this script. A lockout also answers with
 * errorCode -30109 even when the password is correct.
 *
 * Exit codes: 0 = login succeeded, 1 = controller rejected the login,
 *             2 = configuration/transport failure (no verdict from controller).
 */

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const dotenv = require('dotenv');

// ── Configuration (same load order as src/server.js) ────────────────────
// server.js loads backend/.env explicitly and dotenv does NOT override
// variables already present in the process environment. That detail matters:
// a stale shell (or system) environment variable silently wins over .env.
const ENV_PATH = path.join(__dirname, '.env');
const KEYS = [
  'OMADA_BASE_URL',
  'OMADA_OMADAC_ID',
  'OMADA_SITE',
  'OMADA_PORTAL_OPERATOR_NAME',
  'OMADA_PORTAL_OPERATOR_PASSWORD',
  'OMADA_AUTH_TIMEOUT',
  'OMADA_TLS_REJECT',
  'OMADA_MOCK',
];

const preexistingKeys = new Set(Object.keys(process.env));
const fileVars = (() => {
  try {
    return dotenv.parse(fs.readFileSync(ENV_PATH));
  } catch (err) {
    console.warn('[env] cannot read ' + ENV_PATH + ': ' + err.message);
    return {};
  }
})();
dotenv.config({ path: ENV_PATH });

// ── CLI ─────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const opts = {
    baseUrl: null,
    omadacId: null,
    timeout: null,
    reveal: false,
    allowPlaceholder: false,
    noOrigin: false,
    form: false,
    skipIdCheck: false,
    help: false,
  };
  for (const arg of argv.slice(2)) {
    if (arg === '--reveal') opts.reveal = true;
    else if (arg === '--allow-placeholder') opts.allowPlaceholder = true;
    else if (arg === '--no-origin') opts.noOrigin = true;
    else if (arg === '--form') opts.form = true;
    else if (arg === '--skip-id-check') opts.skipIdCheck = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg.startsWith('--base-url=')) opts.baseUrl = arg.slice('--base-url='.length);
    else if (arg.startsWith('--omadac-id=')) opts.omadacId = arg.slice('--omadac-id='.length);
    else if (arg.startsWith('--timeout=')) opts.timeout = parseInt(arg.slice('--timeout='.length), 10);
    else {
      console.error('Unknown argument: ' + arg + ' (use --help)');
      process.exit(2);
    }
  }
  return opts;
}

const ARGS = parseArgs(process.argv);

if (ARGS.help) {
  console.log(fs.readFileSync(__filename, 'utf8').split('*/')[0]);
  process.exit(0);
}

// ── Small utilities ─────────────────────────────────────────────────────
const BASE_URL = (ARGS.baseUrl !== null ? ARGS.baseUrl : process.env.OMADA_BASE_URL || '').trim();
const OMADAC_ID = (ARGS.omadacId !== null ? ARGS.omadacId : process.env.OMADA_OMADAC_ID || '').trim();
const SITE = process.env.OMADA_SITE || 'Default';
const OPERATOR_NAME = process.env.OMADA_PORTAL_OPERATOR_NAME || '';
const OPERATOR_PASSWORD = process.env.OMADA_PORTAL_OPERATOR_PASSWORD || '';
const TIMEOUT = Number.isFinite(ARGS.timeout)
  ? ARGS.timeout
  : parseInt(process.env.OMADA_AUTH_TIMEOUT || '10000', 10);
const TLS_REJECT = process.env.OMADA_TLS_REJECT === 'true';

// Mirrors services/omada.js. Tomcat on the controller validates Origin against
// the Host the Cloudflare Tunnel injects (the controller's LAN origin).
const CONTROLLER_ORIGIN = 'https://192.168.0.253:8043';

function section(title) {
  console.log('');
  console.log('=== ' + title + ' ' + '='.repeat(Math.max(0, 60 - title.length))); 
}

function fingerprint(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex').slice(0, 12);
}

function isPlaceholder(value) {
  return /^your[-_]/i.test(String(value || '')) || /example\.com/i.test(String(value || ''));
}

/**
 * Describe a secret without printing it: length, byte length, character
 * classes, whitespace/control characters, JSON-escaping cost, suspicious
 * symbols, and a short SHA-256 fingerprint (to compare the value across
 * environments without revealing it).
 */
function describeSecret(label, value) {
  const str = String(value);
  const chars = Array.from(str);
  const bytes = Buffer.byteLength(str, 'utf8');
  const jsonEscapedLength = JSON.stringify(str).length - 2;

  let letters = 0;
  let digits = 0;
  let symbols = 0;
  let spaces = 0;
  let control = 0;
  let nonAscii = 0;
  for (const ch of chars) {
    const cp = ch.codePointAt(0);
    if (cp < 0x20 || cp === 0x7f) control += 1;
    else if (cp > 0x7e) nonAscii += 1;
    else if (ch === ' ') spaces += 1;
    else if (/[A-Za-z]/.test(ch)) letters += 1;
    else if (/[0-9]/.test(ch)) digits += 1;
    else symbols += 1;
  }

  const present = [];
  for (const ch of ['#', '&', '%', '+', '=', '?', '/', '\\', '"', "'", '`', '$', '{', '}', '[', ']', ':', ';', ',', '|', '<', '>']) {
    if (str.includes(ch)) present.push(ch);
  }

  console.log(label + ':');
  console.log('  length=' + chars.length + ' chars, ' + bytes + ' UTF-8 bytes' +
    ', jsonEscapedLength=' + jsonEscapedLength);
  console.log('  letters=' + letters + ' digits=' + digits + ' symbols=' + symbols +
    ' spaces=' + spaces + ' control=' + control + ' nonAscii=' + nonAscii);
  console.log('  leadingWhitespace=' + (/^\s/.test(str) ? 'YES' : 'no') +
    ' trailingWhitespace=' + (/\s$/.test(str) ? 'YES' : 'no') +
    ' empty=' + (str === '' ? 'YES' : 'no'));
  console.log('  suspiciousSymbols=' + (present.length ? JSON.stringify(present.join('')) : 'none') +
    ' sha256/12=' + fingerprint(str));
  if (control > 0) {
    console.log('  !! contains control characters (newline/tab/BOM) — a password with these can never match');
  }
  if (nonAscii > 0) {
    console.log('  !! contains non-ASCII characters — verify the controller uses the same encoding');
  }
}

/** Resolve a key with provenance: .env file value vs effective process.env. */
function resolveKey(key, override) {
  const fromFile = fileVars[key];
  const fromEnv = process.env[key];
  const effective = override !== null && override !== undefined
    ? override
    : (fromEnv !== undefined ? fromEnv : '');
  const preexisting = preexistingKeys.has(key);
  const differsFromFile = fromFile !== undefined && fromFile !== effective;
  return { key, fromFile, fromEnv, effective, preexisting, differsFromFile };
}

function printProvenance(resolved) {
  const { key, fromFile, fromEnv, effective, preexisting, differsFromFile } = resolved;
  if (preexisting && fromFile !== undefined && differsFromFile) {
    console.log(
      '  !! ' + key + ': an environment variable was ALREADY SET before dotenv ran, so ' +
      'dotenv did NOT override it. The running process uses the environment value, not .env.'
    );
  }
  if (fromFile === undefined) {
    console.log('  !! ' + key + ': not present in ' + ENV_PATH + '; using ' +
      (fromEnv !== undefined ? 'the process environment' : 'the built-in default'));
  }
  if (differsFromFile) {
    console.log('  .env value differs from the effective value (length ' +
      String(fromFile).length + ' vs ' + String(effective).length + ')');
  }
  if (preexisting) {
    console.log('  source: process environment (present before dotenv)');
  } else if (fromFile !== undefined) {
    console.log('  source: ' + path.basename(ENV_PATH));
  } else {
    console.log('  source: default/unset');
  }
}

/** Mask only the password VALUE, leaving the rest of the raw body byte-exact. */
function redactBody(rawBody, secret, formMode) {
  if (ARGS.reveal) return rawBody;
  if (!secret) return rawBody;
  const jsonEscaped = JSON.stringify(secret).slice(1, -1);
  if (!formMode) {
    const marker = '"password":';
    const markerIndex = rawBody.indexOf(marker);
    if (markerIndex !== -1) {
      const start = markerIndex + marker.length;
      if (rawBody.slice(start, start + jsonEscaped.length) === jsonEscaped) {
        return rawBody.slice(0, start) + '"<password ' + secret.length + ' chars>"' +
          rawBody.slice(start + jsonEscaped.length);
      }
    }
  } else {
    const encoded = encodeURIComponent(secret);
    const marker = 'password=';
    const markerIndex = rawBody.indexOf(marker);
    if (markerIndex !== -1) {
      const start = markerIndex + marker.length;
      if (rawBody.slice(start, start + encoded.length) === encoded) {
        return rawBody.slice(0, start) + '<password ' + secret.length + ' chars>' +
          rawBody.slice(start + encoded.length);
      }
    }
  }
  // Fallback: mask any literal occurrence (keeps the output secret-free).
  return rawBody.split(secret).join('<password ' + secret.length + ' chars>');
}

// ── Raw HTTP request with full logging ──────────────────────────────────
function requestOnce({ parsedBase, requestPath, method, headers, body }) {
  return new Promise((resolve) => {
    const isHttps = parsedBase.protocol === 'https:';
    const client = isHttps ? https : http;
    const port = parsedBase.port || (isHttps ? 443 : 80);

    const options = {
      hostname: parsedBase.hostname,
      port,
      path: requestPath,
      method,
      headers,
      rejectUnauthorized: TLS_REJECT,
      timeout: TIMEOUT,
    };

    const startedAt = Date.now();
    const req = client.request(options, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({
          ok: true,
          statusCode: res.statusCode,
          statusMessage: res.statusMessage,
          httpVersion: res.httpVersion,
          rawHeaders: res.rawHeaders,
          body: data,
          elapsedMs: Date.now() - startedAt,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, code: 'OMADA_TIMEOUT', message: 'no response within ' + TIMEOUT + 'ms' });
    });

    req.on('error', (err) => {
      resolve({
        ok: false,
        code: err.code || 'NO_CODE',
        message: err.message,
      });
    });

    if (body) req.write(body);
    req.end();
  });
}

// ── Controller ID discovery (harmless GET) ──────────────────────────────
// /api/v2/pre-login-info answers 302 with Location
// http://HOST/<32-hex-controller-id>/login — the controller tells us its own
// OMADAC ID. Comparing it with OMADA_OMADAC_ID separates "wrong controller
// ID" (HTTP 404 / -1600) from "wrong credentials" (-30109).
async function discoverControllerId(parsedBase) {
  const result = await requestOnce({
    parsedBase,
    requestPath: '/api/v2/pre-login-info',
    method: 'GET',
    headers: { 'Accept': 'application/json' },
    body: null,
  });
  if (!result.ok) return { ok: false, reason: result.code + ': ' + result.message };
  const location = result.rawHeaders.find((h, i, all) => i > 0 && all[i - 1].toLowerCase() === 'location');
  const idMatch = location && location.match(/([0-9a-f]{32})\/(?:login|)/i);
  return {
    ok: true,
    statusCode: result.statusCode,
    location: location || null,
    controllerId: idMatch ? idMatch[1] : null,
  };
}

// ── Main ────────────────────────────────────────────────────────────────
(async () => {
  console.log('Omada hotspot login diagnostic — ' + new Date().toISOString());
  console.log('node ' + process.version + ' on ' + process.platform);
  console.log('This script performs ONE login attempt. Do not loop it: the controller');
  console.log('locks an operator account after repeated failures, and a lockout also');
  console.log('replies -30109 even for the correct password.');

  section('1. Resolved configuration');
  console.log('  .env file: ' + ENV_PATH + ' (' +
    (fs.existsSync(ENV_PATH) ? 'present' : 'MISSING') + ')');
  console.log('  baseUrl: ' + (BASE_URL ? JSON.stringify(BASE_URL) : '(unset)'));
  console.log('  omadacId: ' + (OMADAC_ID ? JSON.stringify(OMADAC_ID) : '(unset)'));
  console.log('  site: ' + JSON.stringify(SITE) +
    (process.env.OMADA_SITE ? '' : ' (default — OMADA_SITE unset)'));
  console.log('  tlsRejectUnauthorized: ' + TLS_REJECT);
  console.log('  timeout: ' + TIMEOUT + 'ms');
  console.log('  mode: ' + (ARGS.form ? 'FORM-ENCODED PROBE' : 'JSON (same as services/omada.js)') +
    (ARGS.noOrigin ? ', no Origin/Referer' : ''));

  const resolvedBase = resolveKey('OMADA_BASE_URL', ARGS.baseUrl);
  const resolvedId = resolveKey('OMADA_OMADAC_ID', ARGS.omadacId);
  const resolvedName = resolveKey('OMADA_PORTAL_OPERATOR_NAME', null);
  const resolvedPassword = resolveKey('OMADA_PORTAL_OPERATOR_PASSWORD', null);

  section('2. Credential shape (values never printed)');
  describeSecret('operator name', OPERATOR_NAME);
  describeSecret('operator password', OPERATOR_PASSWORD);

  section('3. Value provenance');
  printProvenance(resolvedBase);
  printProvenance(resolvedId);
  printProvenance(resolvedName);
  printProvenance(resolvedPassword);

  // ── Fail fast on unusable configuration ──
  section('4. Preflight');
  const problems = [];
  if (!BASE_URL) problems.push('OMADA_BASE_URL is unset (and no --base-url given)');
  if (!OMADAC_ID) problems.push('OMADA_OMADAC_ID is unset (and no --omadac-id given)');
  if (!OPERATOR_NAME) problems.push('OMADA_PORTAL_OPERATOR_NAME is unset/empty');
  if (!OPERATOR_PASSWORD) problems.push('OMADA_PORTAL_OPERATOR_PASSWORD is unset/empty');
  if (process.env.OMADA_MOCK === 'true') {
    console.log('  note: OMADA_MOCK=true — the backend would not call the controller at all');
  }

  let parsedBase = null;
  try {
    parsedBase = new URL(BASE_URL);
    if (!/^https?:$/.test(parsedBase.protocol)) {
      problems.push('OMADA_BASE_URL protocol must be http: or https:');
    }
  } catch (_) {
    problems.push('OMADA_BASE_URL is not a valid URL: ' + JSON.stringify(BASE_URL));
  }

  // The code reads OMADA_PORTAL_OPERATOR_NAME/PASSWORD and nothing else. A value
  // stored under any of these legacy / shortened names is silently ignored, and
  // the controller then receives an empty name/password (-30109).
  const LEGACY_KEYS = [
    'PORTAL_OPERATOR_NAME', 'PORTAL_OPERATOR_PASSWORD',
    'OMADA_USER', 'OMADA_USERNAME', 'OMADA_PASSWORD',
  ];
  for (const key of LEGACY_KEYS) {
    const value = process.env[key] !== undefined ? process.env[key] : fileVars[key];
    if (value !== undefined && value !== '') {
      console.log('  !! ' + key + ' is set, but services/omada.js never reads it —');
      console.log('     the login uses OMADA_PORTAL_OPERATOR_NAME and OMADA_PORTAL_OPERATOR_PASSWORD only.');
    }
  }

  const placeholderFlags = [];
  if (isPlaceholder(BASE_URL)) placeholderFlags.push('OMADA_BASE_URL=' + JSON.stringify(BASE_URL));
  if (isPlaceholder(OMADAC_ID)) placeholderFlags.push('OMADA_OMADAC_ID=' + JSON.stringify(OMADAC_ID));
  if (isPlaceholder(OPERATOR_NAME)) placeholderFlags.push('operator name is the .env.example placeholder');
  if (isPlaceholder(OPERATOR_PASSWORD)) placeholderFlags.push('operator password is the .env.example placeholder');

  if (placeholderFlags.length) {
    console.log('  !! placeholder values detected:');
    placeholderFlags.forEach((p) => console.log('     - ' + p));
    if (!ARGS.allowPlaceholder) {
      console.log('');
      console.log('Refusing to send placeholder credentials. Put the real values in');
      console.log('backend/.env (or the shell environment), or re-run with');
      console.log('--allow-placeholder to confirm the transport path only.');
      process.exit(2);
    }
    console.log('  --allow-placeholder is set: sending them anyway (expected -30109).');
  }

  if (problems.length) {
    problems.forEach((p) => console.log('  !! ' + p));
    console.log('');
    console.log('Aborting: cannot build a login request.');
    process.exit(2);
  }
  console.log('  configuration is complete');

  // ── Controller ID check ──
  if (!ARGS.skipIdCheck) {
    section('5. Controller ID advertised by the controller');
    const discovery = await discoverControllerId(parsedBase);
    if (!discovery.ok) {
      console.log('  could not discover the ID: ' + discovery.reason);
      console.log('  (this is only a cross-check; the login below still runs)');
    } else {
      console.log('  GET /api/v2/pre-login-info -> HTTP ' + discovery.statusCode +
        (discovery.location ? ' location=' + discovery.location : ''));
      if (discovery.controllerId) {
        const match = discovery.controllerId.toLowerCase() === String(OMADAC_ID).toLowerCase();
        console.log('  controller advertises OMADAC ID: ' + discovery.controllerId);
        console.log('  configured OMADA_OMADAC_ID:      ' + OMADAC_ID +
          (match ? '  (match)' : '  (MISMATCH)'));
        if (!match) {
          console.log('  !! a wrong controller ID does NOT produce -30109; it produces');
          console.log('     HTTP 404 {"error":{"code":404}} (or -1600 Unsupported request path).');
        }
      } else {
        console.log('  controller did not expose its ID in a Location header');
      }
    }
  }

  // ── Build the exact request the service builds ──
  section('6. Login request (identical shape to services/omada.js)');
  const requestPath = '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/hotspot/login';
  const body = ARGS.form
    ? 'name=' + encodeURIComponent(OPERATOR_NAME) +
      '&password=' + encodeURIComponent(OPERATOR_PASSWORD)
    : JSON.stringify({ name: OPERATOR_NAME, password: OPERATOR_PASSWORD });

  const headers = {
    // JSON is the documented contract (FAQ 2907 / 132060). The form shape is
    // only available as --form to rule out body encoding as the cause.
    'Content-Type': ARGS.form
      ? 'application/x-www-form-urlencoded'
      : 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Accept': 'application/json',
  };
  if (!ARGS.noOrigin) {
    headers['Origin'] = CONTROLLER_ORIGIN;
    headers['Referer'] = CONTROLLER_ORIGIN + '/';
  }

  const hostHeader = parsedBase.host; // includes the non-default port
  console.log('');
  console.log('> ' + 'POST ' + requestPath + ' HTTP/1.1');
  console.log('> Host: ' + hostHeader);
  for (const [name, value] of Object.entries(headers)) {
    console.log('> ' + name + ': ' + value);
  }
  console.log('>');
  console.log('> ' + redactBody(body, OPERATOR_PASSWORD, ARGS.form));
  console.log('');
  console.log('  body bytes=' + Buffer.byteLength(body) +
    ' sha256/12=' + fingerprint(body));
  console.log('  target=' + parsedBase.protocol + '//' + parsedBase.host + requestPath);
  if (!ARGS.reveal) {
    console.log('  (password value masked in the printed body; re-run with --reveal to see it)');
  }

  // ── Send ──
  section('7. Response');
  const response = await requestOnce({
    parsedBase,
    requestPath,
    method: 'POST',
    headers,
    body,
  });

  if (!response.ok) {
    console.log('TRANSPORT FAILURE: ' + response.code + ' — ' + response.message);
    const hints = {
      ECONNREFUSED: 'nothing is listening on that host/port (or the tunnel is down)',
      ECONNRESET: 'TLS handshake or connection dropped; check OMADA_TLS_REJECT and the tunnel',
      ENOTFOUND: 'DNS lookup failed for the host (placeholder base URL?)',
      ETIMEDOUT: 'no response before the timeout',
      ESOCKETTIMEDOUT: 'socket timed out',
      EPROTO: 'TLS protocol error (self-signed certificate rejected?)',
      DEPTH_ZERO_SELF_SIGNED_CERT: 'self-signed certificate — keep OMADA_TLS_REJECT=false',
      SELF_SIGNED_CERT_IN_CHAIN: 'self-signed certificate — keep OMADA_TLS_REJECT=false',
      UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'untrusted certificate — keep OMADA_TLS_REJECT=false',
      ERR_TLS_CERT_ALTNAME_INVALID: 'certificate hostname does not match OMADA_BASE_URL',
      OMADA_TIMEOUT: 'controller did not answer in time',
    };
    if (hints[response.code]) console.log('  likely cause: ' + hints[response.code]);
    process.exit(2);
  }

  console.log('< HTTP/' + response.httpVersion + ' ' + response.statusCode + ' ' +
    (response.statusMessage || '') + '   (' + response.elapsedMs + 'ms)');
  for (let i = 0; i < response.rawHeaders.length; i += 2) {
    console.log('< ' + response.rawHeaders[i] + ': ' + response.rawHeaders[i + 1]);
  }
  console.log('<');
  console.log('< ' + response.body);

  let parsed = null;
  try {
    parsed = response.body ? JSON.parse(response.body) : null;
  } catch (_) { /* HTML error page or empty body */ }

  // ── Verdict ──
  section('8. Verdict');
  const errorCode = parsed && parsed.errorCode !== undefined ? parsed.errorCode : undefined;
  const setCookie = response.rawHeaders.filter(
    (h, i, all) => i > 0 && all[i - 1].toLowerCase() === 'set-cookie'
  );

  if (response.statusCode === 200 && errorCode === 0) {
    const token = parsed && parsed.result && parsed.result.token;
    console.log('LOGIN SUCCEEDED. The credentials, endpoint and request format are correct.');
    console.log('  result.token present: ' + (token ? 'yes, ' + String(token).length + ' chars' : 'NO') +
      '  fingerprint=' + (token ? fingerprint(token) : '-'));
    console.log('  session cookie(s) set: ' + (setCookie.length ? setCookie.length : 'none'));
    process.exit(0);
  }

  if (response.statusCode === 200 && errorCode === -30109) {
    console.log('RESULT: the controller PARSED and ACCEPTED the request, then rejected the');
    console.log('CREDENTIALS (-30109 "Invalid username or password").');
    console.log('');
    console.log('The endpoint, JSON body, Content-Type and Origin/CSRF handling are correct:');
    console.log('a malformed body or wrong path never produces -30109 (a wrong controller');
    console.log('ID produces HTTP 404, a CSRF/Host mismatch produces HTTP 500).');
    console.log('');
    console.log('Check, in this order:');
    console.log('  1. The values the PROCESS resolved above, not the ones you read in .env.');
    console.log('     If an env var was already set before dotenv ran, .env is ignored.');
    console.log('  2. That these are the HOTSPOT OPERATOR credentials created under');
    console.log('     Hotspot Manager -> Portal Operators, NOT the controller admin login.');
    console.log('     Admin credentials fail here with exactly -30109.');
    console.log('  3. The exact operator username (case-sensitive, no trailing space) and');
    console.log('     password, including one that was re-typed after a controller upgrade.');
    console.log('  4. Lockout: after repeated failures Omada temporarily blocks the account');
    console.log('     and returns -30109 even for the correct password. Wait ~5-15 minutes');
    console.log('     or restart the controller, then try once.');
    console.log('  5. Whether this operator is assigned to the site the guests are on (site=' +
      JSON.stringify(SITE) + ').');
    console.log('');
    console.log('Nothing in services/omada.js can turn a valid password into -30109: the');
    console.log('password is placed in the JSON body with JSON.stringify, which preserves');
    console.log('special characters exactly. What reaches the controller is the value the');
    console.log('process resolved — compare the fingerprint above with the value you expect.');
    process.exit(1);
  }

  if (response.statusCode === 404 || errorCode === -1600) {
    console.log('RESULT: the controller does not know this controller ID / path (HTTP ' +
      response.statusCode + (errorCode !== undefined ? ', errorCode=' + errorCode : '') + ').');
    console.log('Check OMADA_OMADAC_ID against the 32-hex ID in the controller URL:');
    console.log('  https://<controller>/<OMADAC_ID>/login');
    process.exit(1);
  }

  if (response.statusCode === 500 && /<html/i.test(response.body || '')) {
    console.log('RESULT: the controller (Tomcat) rejected the request with an HTML 500.');
    console.log('This is the CSRF filter: Origin/Referer must match the Host the reverse');
    console.log('proxy injects. Port 8043 accessed directly answers this way; the nginx');
    console.log('front (443) and the Cloudflare Tunnel path do not.');
    process.exit(1);
  }

  console.log('RESULT: unexpected response. Status=' + response.statusCode +
    ' errorCode=' + errorCode + '.');
  console.log('This is not the classic invalid-credentials answer; inspect the raw');
  console.log('response above.');
  process.exit(1);
})().catch((err) => {
  console.error('Unexpected diagnostic failure: ' + (err && err.stack ? err.stack : err));
  process.exit(2);
});
