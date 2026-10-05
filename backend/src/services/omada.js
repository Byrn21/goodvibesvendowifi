/**
 * services/omada.js — Omada controller adapter (hotspot portal flow)
 *
 * Implements the Omada hotspot external-portal integration using the
 * controller's hotspot endpoints, cross-verified against three
 * independent implementations (TP-Link FAQ 3231 PHP template,
 * splash-networks/capport, tykeal/homeassistant-captive-portal):
 *
 *   1. Operator login:
 *        POST /{OMADAC_ID}/api/v2/hotspot/login
 *        body: { name, password }   (hotspot portal operator account)
 *        response: { errorCode: 0, result: { token } }
 *      The response also sets a controller session cookie; BOTH the
 *      cookie and the token (sent as the `Csrf-Token` header) must be
 *      attached to every subsequent request.
 *
 *   2. Client authorization (payment-triggered):
 *        POST /{OMADAC_ID}/api/v2/hotspot/extPortal/auth
 *        body: { clientMac, apMac, ssidName, radioId, authType: 4, time }
 *      The `time` unit depends on controller firmware. OMADA_TIME_UNIT
 *      (config/index.js) selects the scaling; default 'ms' matches the
 *      two cross-verified working implementations (FAQ 3231 prose alone
 *      claims microseconds — do not trust the prose over working code).
 *
 *   3. Client de-authorization (pause / expiration):
 *      try POST /{OMADAC_ID}/api/v2/hotspot/extPortal/unauth first
 *      (undocumented), then VERIFY actual revocation, falling back to a
 *      time=1 re-authorization if the client is still authorized.
 *
 * Configuration (from .env):
 *   OMADA_BASE_URL                  — e.g. https://omada-tunnel.example.com
 *   OMADA_OMADAC_ID                 — controller ID (OMADAC ID)
 *   OMADA_SITE                      — site name (default "Default")
 *   OMADA_PORTAL_OPERATOR_NAME      — hotspot portal operator username
 *   OMADA_PORTAL_OPERATOR_PASSWORD  — hotspot portal operator password
 *   OMADA_AUTH_TIMEOUT              — request timeout ms (default 10000)
 *   OMADA_TLS_REJECT                — "true" (default) or "false" (dev only)
 *   OMADA_MOCK                      — "true" to bypass the controller
 */

const https = require('https');
const http = require('http');
const { OMADA_TIME_UNIT } = require('../config');

const BASE_URL   = process.env.OMADA_BASE_URL || '';
const OMADAC_ID  = process.env.OMADA_OMADAC_ID || '';
const SITE       = process.env.OMADA_SITE     || 'Default';
const OPERATOR_NAME = process.env.OMADA_PORTAL_OPERATOR_NAME || '';
const OPERATOR_PASSWORD = process.env.OMADA_PORTAL_OPERATOR_PASSWORD || '';
const TIMEOUT    = parseInt(process.env.OMADA_AUTH_TIMEOUT || '10000', 10);
const TLS_REJECT = process.env.OMADA_TLS_REJECT !== 'false';

// In mock/test mode, simulate controller responses
const MOCK_MODE = process.env.OMADA_MOCK === 'true' || !BASE_URL;

// ── Controller session state (operator login) ──────────────────────────
// Cookie + CSRF token are obtained once via hotspot/login and reused;
// a 401 from the controller invalidates and re-establishes the session.
let sessionCookie = null;
let csrfToken = null;

/**
 * Convert a duration in minutes to the `time` value expected by
 * /hotspot/extPortal/auth, scaled per OMADA_TIME_UNIT.
 *
 * @param {number} minutes
 * @returns {number} time value in the configured unit
 */
function minutesToTime(minutes) {
  const m = Math.max(0, Math.floor(Number(minutes) || 0));
  switch (OMADA_TIME_UNIT) {
    case 's':  return m * 60;
    case 'us': return m * 60 * 1000000;
    case 'ms':
    default:   return m * 60 * 1000;
  }
}

/**
 * Perform hotspot operator login. Establishes the controller session
 * (cookie) and stores the CSRF token from result.token.
 *
 * @returns {Promise<void>} resolves on success, throws on failure
 */
async function operatorLogin() {
  const path = '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/hotspot/login';
  const body = JSON.stringify({ name: OPERATOR_NAME, password: OPERATOR_PASSWORD });

  const response = await omadaRequest(path, 'POST', body, { skipAuth: true });

  if (response.statusCode !== 200 || !response.body || response.body.errorCode !== 0) {
    const err = new Error(
      'Omada hotspot operator login failed: ' +
      (response.body && (response.body.msg || response.body.message) || ('HTTP ' + response.statusCode))
    );
    err.code = 'OMADA_LOGIN_FAILED';
    err.omadaResponse = response.body;
    throw err;
  }

  sessionCookie = response.setCookie || sessionCookie;
  csrfToken = response.body.result && response.body.result.token;
  if (!csrfToken) {
    const err = new Error('Omada hotspot login response missing result.token');
    err.code = 'OMADA_LOGIN_FAILED';
    throw err;
  }
}

/** Invalidate the cached controller session (forces re-login next call). */
function invalidateSession() {
  sessionCookie = null;
  csrfToken = null;
}

/**
 * Ensure a valid controller session exists, logging in if necessary.
 * @returns {Promise<void>}
 */
async function ensureSession() {
  if (!sessionCookie || !csrfToken) {
    await operatorLogin();
  }
}

/**
 * Authenticate a client on the Omada controller via the hotspot
 * external portal API (payment-triggered authorization).
 *
 * @param {Object} ctx
 * @param {string} ctx.clientMac   Client MAC (normalized, required)
 * @param {string} ctx.apMac       AP MAC (required by controller)
 * @param {string} ctx.ssidName    SSID name (required by controller)
 * @param {number} ctx.radioId     Radio ID, typically 0 (required)
 * @param {number} ctx.durationMinutes  Paid duration in minutes
 * @param {string} [ctx.sessionId] Internal session ID (logging only)
 * @returns {Promise<Object>}  { success: true, raw }
 * @throws Error on controller rejection / network failure
 */
async function authenticateClient(ctx) {
  if (MOCK_MODE) return mockAuthenticate(ctx);

  if (!OMADAC_ID) {
    throw configError('OMADA_OMADAC_ID is not configured');
  }

  // Fail loud BEFORE contacting the controller: the extPortal/auth
  // contract requires apMac / ssidName / radioId; callers must never
  // send nulls (webhook guarantees this via MISSING_PORTAL_CONTEXT).
  for (const field of ['clientMac', 'apMac', 'ssidName']) {
    if (!ctx || !ctx[field]) {
      const err = new Error('authenticateClient: missing required field ' + field);
      err.code = 'OMADA_MISSING_FIELD';
      throw err;
    }
  }

  const radioId = Number.isInteger(ctx.radioId) ? ctx.radioId : parseInt(ctx.radioId, 10) || 0;
  const path = '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/hotspot/extPortal/auth';
  const body = JSON.stringify({
    clientMac: ctx.clientMac,
    apMac: ctx.apMac,
    ssidName: ctx.ssidName,
    radioId,
    authType: 4, // hotspot auth type (cross-verified across implementations)
    time: minutesToTime(ctx.durationMinutes),
    site: SITE,
  });

  const response = await withSession(() => omadaRequest(path, 'POST', body));

  if (response.statusCode !== 200 || !response.body || response.body.errorCode !== 0) {
    const err = new Error(
      'Omada extPortal/auth rejected: ' +
      (response.body && (response.body.msg || response.body.message) || ('HTTP ' + response.statusCode))
    );
    err.code = 'OMADA_AUTH_REJECTED';
    err.omadaResponse = response.body;
    throw err;
  }

  console.log(
    '[omada] authorized client ' + ctx.clientMac +
    ' on ssid "' + ctx.ssidName + '" for ' + ctx.durationMinutes + ' min' +
    ' (time=' + minutesToTime(ctx.durationMinutes) + ' ' + OMADA_TIME_UNIT + ')'
  );
  return { success: true, raw: response.body };
}

/**
 * De-authorize a client (pause / expiration).
 *
 * Flow:
 *   1. POST /{omadacId}/api/v2/hotspot/extPortal/unauth  (undocumented — attempt first)
 *   2. Verify actual revocation via the status call (see the NOTE on
 *      queryClientStatus below for its own verification status)
 *      ├─ revoked            → success
 *      ├─ still authorized   → time=1 fallback re-auth, then re-verify
 *      └─ status call failed → WARN "verification unavailable", do NOT
 *         fail the revoke (avoid false failures); deauth_verified=false
 *   3. If STILL authorized after the time=1 fallback → log ERROR and
 *      return { success: false, verified: false } so callers can surface it.
 *
 * @param {Object} ctx
 * @param {string} ctx.clientMac  Client MAC (required)
 * @param {string} [ctx.apMac]    AP MAC
 * @param {string} [ctx.ssidName] SSID name
 * @param {number} [ctx.radioId]  Radio ID (used by the time=1 fallback)
 * @returns {Promise<Object>} { success, verified, path }
 */
async function unauthenticateClient(ctx) {
  if (MOCK_MODE) return mockUnauthenticate(ctx);

  if (!OMADAC_ID) {
    throw configError('OMADA_OMADAC_ID is not configured');
  }
  if (!ctx || !ctx.clientMac) {
    const err = new Error('unauthenticateClient: missing required field clientMac');
    err.code = 'OMADA_MISSING_FIELD';
    throw err;
  }

  // ── Step 1: undocumented unauth endpoint (attempt first) ──
  const unauthPath = '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/hotspot/extPortal/unauth';
  const body = JSON.stringify({
    clientMac: ctx.clientMac,
    apMac: ctx.apMac || '',
    ssidName: ctx.ssidName || '',
    site: SITE,
  });

  let unauthOk = false;
  try {
    const response = await withSession(() => omadaRequest(unauthPath, 'POST', body));
    unauthOk = response.statusCode === 200 && response.body && response.body.errorCode === 0;
    console.log(
      '[omada] extPortal/unauth for ' + ctx.clientMac + ' → ' +
      (unauthOk ? 'accepted' : 'rejected (HTTP ' + response.statusCode + ', errorCode=' +
        (response.body && response.body.errorCode) + ')')
    );
  } catch (err) {
    console.error('[omada] extPortal/unauth request failed for ' + ctx.clientMac + ':', err.message);
  }

  // ── Step 2: verify actual revocation, fall back if needed ──
  const status = await queryClientStatus(ctx).catch(() => null);

  if (status && status.authorized === false) {
    console.log('[omada] unauth verified for ' + ctx.clientMac + ' (client no longer authorized)');
    return { success: true, verified: true, path: 'unauth' };
  }

  if (status && status.authorized === true) {
    console.warn(
      '[omada] controller accepted unauth for ' + ctx.clientMac +
      ' but client is STILL authorized — applying time=1 fallback re-authorize'
    );
    const fallbackOk = await timeOneFallback(ctx);
    const recheck = await queryClientStatus(ctx).catch(() => null);
    if (recheck && recheck.authorized === false) {
      console.log('[omada] time=1 fallback revoked access for ' + ctx.clientMac);
      return { success: true, verified: true, path: 'time=1' };
    }
    console.error(
      '[omada] DEAUTH FAILED — ' + ctx.clientMac + ' retains access after unauth AND time=1 fallback'
    );
    return { success: false, verified: Boolean(recheck), path: fallbackOk ? 'time=1' : 'unauth' };
  }

  // Status query itself failed (endpoint may not exist on this firmware)
  console.warn(
    '[omada] deauth verification unavailable for ' + ctx.clientMac +
    ' — controller status query failed; unauth response was: ' + (unauthOk ? 'accepted' : 'rejected')
  );
  return { success: unauthOk, verified: false, path: 'unauth' };
}

// NOTE: /hotspot/extPortal/session is an UNVERIFIED, UNDOCUMENTED endpoint.
// It appears in third-party implementations (tykeal/homeassistant-captive-portal,
// which wraps it in try/catch precisely because it may not exist on all
// firmware) but is NOT in TP-Link FAQ 3231. Used here only as a best-effort
// post-deauth verification — a failure degrades to a logged warning, never
// to a false "verified" result. Do not treat success as guaranteed behavior.
/**
 * Query whether a client is currently authorized on the controller.
 *
 * @param {Object} ctx  { clientMac, [apMac], [ssidName] }
 * @returns {Promise<Object|null>} { authorized: boolean, remainingTime? } or null
 */
async function queryClientStatus(ctx) {
  const path = '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/hotspot/extPortal/session';
  const body = JSON.stringify({
    clientMac: ctx.clientMac,
    site: SITE,
  });

  const response = await withSession(() => omadaRequest(path, 'POST', body));
  if (response.statusCode !== 200 || !response.body || response.body.errorCode !== 0) {
    return null;
  }
  const data = response.body.result || response.body.data;
  if (!data) return null;
  // Different firmware shapes: authorized flag or remainingTime presence
  const authorized =
    typeof data.authorized === 'boolean'
      ? data.authorized
      : Number(data.remainingTime) > 0;
  return { authorized, remainingTime: data.remainingTime };
}

/**
 * time=1 fallback: re-authorize the client for one unit of time so the
 * controller's own expiry effectively revokes it shortly after.
 *
 * @param {Object} ctx
 * @returns {Promise<boolean>} true if the re-auth was accepted
 */
async function timeOneFallback(ctx) {
  const path = '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/hotspot/extPortal/auth';
  const body = JSON.stringify({
    clientMac: ctx.clientMac,
    apMac: ctx.apMac || '',
    ssidName: ctx.ssidName || '',
    radioId: Number.isInteger(ctx.radioId) ? ctx.radioId : parseInt(ctx.radioId, 10) || 0,
    authType: 4,
    time: 1,
    site: SITE,
  });

  try {
    const response = await withSession(() => omadaRequest(path, 'POST', body));
    const ok = response.statusCode === 200 && response.body && response.body.errorCode === 0;
    console.log('[omada] time=1 fallback for ' + ctx.clientMac + ' → ' + (ok ? 'accepted' : 'rejected'));
    return ok;
  } catch (err) {
    console.error('[omada] time=1 fallback request failed for ' + ctx.clientMac + ':', err.message);
    return false;
  }
}

/**
 * Run a controller request with session handling: ensures login, and on
 * a 401 invalidates the session and retries once with a fresh login.
 *
 * @param {Function} fn  () => omadaRequest(...)
 * @returns {Promise<Object>} omadaRequest response
 */
async function withSession(fn) {
  await ensureSession();
  let response = await fn();
  if (response.statusCode === 401) {
    console.warn('[omada] controller session expired — re-logging in');
    invalidateSession();
    await ensureSession();
    response = await fn();
  }
  return response;
}

/**
 * Configuration error helper.
 * @param {string} message
 * @returns {Error}
 */
function configError(message) {
  const err = new Error(message);
  err.code = 'OMADA_CONFIG_ERROR';
  return err;
}
// ================================================================
// Internal: HTTP request to Omada controller (session-aware)
// ================================================================
function omadaRequest(path, method, body, opts) {
  return new Promise((resolve, reject) => {
    if (!BASE_URL) {
      reject(configError('OMADA_BASE_URL is not configured'));
      return;
    }
    let parsed;
    try {
      parsed = new URL(BASE_URL);
    } catch (err) {
      reject(configError('OMADA_BASE_URL is not a valid URL: ' + BASE_URL));
      return;
    }
    const isHttps = parsed.protocol === 'https:';
    const client = isHttps ? https : http;

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body || ''),
        'Accept': 'application/json',
      },
      rejectUnauthorized: TLS_REJECT,
      timeout: TIMEOUT,
    };

    // Attach controller session (cookie) and CSRF token when present.
    // Login itself (opts.skipAuth) carries no session credentials.
    if (!(opts && opts.skipAuth)) {
      if (sessionCookie) options.headers['Cookie'] = sessionCookie;
      if (csrfToken) options.headers['Csrf-Token'] = csrfToken;
    }

    const req = client.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let parsedBody;
        try {
          parsedBody = data ? JSON.parse(data) : {};
        } catch {
          parsedBody = { raw: data };
        }
        // Capture the controller session cookie for subsequent requests
        const setCookieHeader = res.headers['set-cookie'];
        resolve({
          statusCode: res.statusCode,
          body: parsedBody,
          setCookie: Array.isArray(setCookieHeader) ? setCookieHeader.join('; ') : (setCookieHeader || null),
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      const err = new Error('Omada request timed out after ' + TIMEOUT + 'ms');
      err.code = 'OMADA_TIMEOUT';
      reject(err);
    });

    req.on('error', (err) => {
      if (err.code === 'ECONNRESET' && !req.destroyed) {
        const e = new Error('Omada connection reset');
        e.code = 'OMADA_CONNECTION_ERROR';
        reject(e);
      } else {
        reject(err);
      }
    });

    if (body) req.write(body);
    req.end();
  });
}

// ================================================================
// Mock / test implementation
// ================================================================
function mockAuthenticate(ctx) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      const u = (ctx && ctx.username || '').toUpperCase();
      if (u === 'EXPIRED' || u === 'FAIL' || u === 'INVALID') {
        resolve({ success: false, result: 1, msg: 'invalid voucher (mock)' });
      } else if (u === 'OMADA_ERROR' || u === 'SERVICE_UNAVAILABLE') {
        const err = new Error('Mock Omada controller error');
        err.code = 'OMADA_TIMEOUT';
        reject(err);
      } else {
        resolve({ success: true, result: 0, msg: 'success (mock)' });
      }
    }, 200);
  });
}

function mockUnauthenticate(ctx) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({ success: true, verified: true, result: 0, msg: 'unauth success (mock)' });
    }, 150);
  });
}

// ================================================================
module.exports = {
  authenticateClient,
  unauthenticateClient,
  queryClientStatus,
  // Exposed for testing
  _internal: {
    minutesToTime,
    operatorLogin,
    invalidateSession,
    MOCK_MODE,
    BASE_URL,
    OMADAC_ID,
    SITE,
    TLS_REJECT,
  },
};
