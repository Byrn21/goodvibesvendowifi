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
 *        body: { clientMac, clientIp, apMac, ssidName, radioId, authType: 4,
 *                time, site }
 *      The body carries EXACTLY the fields TP-Link documents for the
 *      external portal server (FAQ 2907 for v4.1.5–4.4.6, FAQ 3231 for
 *      v5.0.15–6.2.0, and the v6.2.10+ guide): authType is 4. The guest's
 *      voucher is deliberately NOT sent to the controller — in external
 *      portal mode the controller never consults its own voucher database;
 *      this backend (the Portal) is the component that verifies the
 *      voucher, and the controller only authorizes the MAC. Adding a `code`
 *      field is outside the documented contract and has been observed to
 *      make some firmware reject the authorization (silent MAC-auth
 *      failure → redirect loop, while the local voucher stays valid).
 *      The `time` unit depends on controller firmware. OMADA_TIME_UNIT
 *      (config/index.js) selects the scaling; default 'ms' matches the
 *      v6.2.10+ guide and the cross-verified working implementations.
 *
 *   3. Client de-authorization (pause / expiration):
 *      try POST /{OMADAC_ID}/api/v2/hotspot/extPortal/unauth first
 *      (undocumented), then VERIFY actual revocation, falling back to a
 *      time=1 re-authorization if the client is still authorized.
 *
 * Configuration (from .env):
 *   OMADA_BASE_URL                  — e.g. https://omada-tunnel.example.com
 *   OMADA_OMADAC_ID                 — controller ID (OMADAC ID)
 *   OMADA_SITE                      — site name (default "Default"); sent in
 *                                     the body of EVERY hotspot call and
 *                                     echoed in the [omada] startup log
 *   OMADA_PORTAL_OPERATOR_NAME      — hotspot portal operator username
 *   OMADA_PORTAL_OPERATOR_PASSWORD  — hotspot portal operator password
 *   OMADA_AUTH_TIMEOUT              — request timeout ms (default 10000)
 *   OMADA_TLS_REJECT                — "true" enforces full cert validation;
 *                                     default "false" accepts the controller's
 *                                     self-signed certificate
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
// OC200/ER605 controllers present a SELF-SIGNED certificate. From a cloud
// backend (Render) the default Node TLS behavior rejects it during the
// handshake, surfacing as an opaque ECONNRESET/EPROTO and failing every
// authorization. Default to accepting it (rejectUnauthorized: false); set
// OMADA_TLS_REJECT=true only when the controller has a publicly-trusted cert.
const TLS_REJECT = process.env.OMADA_TLS_REJECT === 'true';

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
 * @param {string} ctx.clientMac        Client MAC (normalized, required)
 * @param {string} [ctx.clientIp]       Client IP (forwarded to the controller)
 * @param {string} [ctx.apMac]          AP MAC (required for wireless/EAP clients)
 * @param {string} [ctx.ssidName]       SSID name (required for wireless/EAP clients)
 * @param {number} [ctx.radioId]        Radio ID: 0 = 2.4G, 1 = 5G (wireless/EAP)
 * @param {string} [ctx.gatewayMac]     Gateway MAC (required for wired/Gateway clients)
 * @param {string|number} [ctx.vid]     VLAN ID (wired/Gateway clients)
 * @param {number} ctx.durationMinutes  Paid duration in minutes
 * @param {string} [ctx.sessionId] Internal session ID (logging only)
 * @returns {Promise<Object>}  { success: true, raw }
 * @throws Error on controller rejection / network failure
 */
async function authenticateClient(ctx) {
  logResolvedConfig();

  if (MOCK_MODE) return mockAuthenticate(ctx);

  if (!OMADAC_ID) {
    throw configError('OMADA_OMADAC_ID is not configured');
  }

  // Fail loud BEFORE contacting the controller. Omada's extPortal/auth
  // contract is connection-type specific (TP-Link "API and Code Samples
  // for External Portal Server", Controller v6.2.10):
  //   EAP     (wireless): clientMac, clientIp, apMac, ssidName, radioId, time, authType
  //   Gateway (wired)   : clientMac, clientIp, gatewayMac, vid, time, authType
  // Callers must never send an incomplete context — the voucher route reads
  // it from the portal URL and the webhook guarantees it via MISSING_PORTAL_CONTEXT.
  if (!ctx || !ctx.clientMac) {
    throw missingField('clientMac');
  }
  const isGateway = Boolean(ctx.gatewayMac);
  for (const field of (isGateway ? ['gatewayMac'] : ['apMac', 'ssidName'])) {
    if (!ctx[field]) throw missingField(field);
  }

  const radioId = Number.isInteger(ctx.radioId) ? ctx.radioId : parseInt(ctx.radioId, 10) || 0;
  const path = '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/hotspot/extPortal/auth';

  // Forward the SAME connection parameters the controller put in the redirect
  // URL. clientIp is required in BOTH shapes; EAP adds apMac/ssidName/radioId,
  // Gateway adds gatewayMac/vid. `time` is milliseconds and authType is 4.
  const authBody = {
    clientMac: ctx.clientMac,
    clientIp: ctx.clientIp || '',
    authType: 4, // hotspot auth type (cross-verified across implementations)
    time: minutesToTime(ctx.durationMinutes),
    site: SITE,
  };
  // NOTE: ctx.voucherCode is intentionally NOT placed in this body. In
  // external-portal mode the controller only authorizes a MAC and never
  // validates vouchers, and `code` is not part of TP-Link's documented
  // extPortal/auth contract — an unknown field can make some firmware
  // reject the whole authorization. The voucher is still consumed locally
  // (routes/auth.js); it simply never reaches the controller.
  if (isGateway) {
    authBody.gatewayMac = ctx.gatewayMac;
    if (ctx.vid !== undefined && ctx.vid !== null && ctx.vid !== '') {
      authBody.vid = ctx.vid;
    }
  } else {
    authBody.apMac = ctx.apMac;
    authBody.ssidName = ctx.ssidName;
    authBody.radioId = radioId;
  }
  const body = JSON.stringify(authBody);

  // Verbose target log: what the controller is being asked to authorize,
  // on WHICH site. Compare `site=` here with the controller's own Site name
  // and `omadacId=` with the controller's API settings — a mismatch is the
  // usual explanation for an accepted voucher that never unlocks the client.
  console.log(
    '[omada] authenticateClient target — client=' + ctx.clientMac +
    ' connection=' + (isGateway ? 'Gateway' : 'EAP') +
    ' site=' + SITE +
    ' omadacId=' + OMADAC_ID +
    ' url=' + maskHost(BASE_URL) + path
  );

  let response;
  try {
    response = await withSession(() => omadaRequest(path, 'POST', body));
  } catch (netErr) {
    // Network / TLS / timeout — log the EXACT reason for the Render logs,
    // including the body that was sent (connection type / site / time), then
    // rethrow so the route fails closed without consuming the voucher.
    logAuthFailure('extPortal/auth request', netErr, ctx, path, body);
    throw netErr;
  }

  if (response.statusCode !== 200 || !response.body || response.body.errorCode !== 0) {
    const reason =
      (response.body && (response.body.msg || response.body.message)) ||
      ('HTTP ' + response.statusCode);
    console.error(
      '[omada] authenticateClient REJECTED by controller — client=' + ctx.clientMac +
      ' http=' + response.statusCode +
      ' errorCode=' + (response.body && response.body.errorCode) +
      ' reason=' + reason
    );
    console.error('[omada]   full controller response: ' + JSON.stringify(response.body));
    const rejectedSummary = summarizeBody(body);
    console.error(
      '[omada]   sent body: connection=' + rejectedSummary.connection +
      ' site=' + rejectedSummary.site + ' ' + rejectedSummary.text
    );
    const err = new Error('Omada extPortal/auth rejected: ' + reason);
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
  logResolvedConfig();

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
  const fallbackBody = {
    clientMac: ctx.clientMac,
    apMac: ctx.apMac || '',
    ssidName: ctx.ssidName || '',
    radioId: Number.isInteger(ctx.radioId) ? ctx.radioId : parseInt(ctx.radioId, 10) || 0,
    authType: 4,
    time: 1,
    site: SITE,
  };
  // Mirror authenticateClient: the documented body only — no `code` field,
  // so both extPortal/auth calls look alike (see authenticateClient).
  const body = JSON.stringify(fallbackBody);

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

/**
 * Missing-required-field error helper (fail loud before any HTTP call).
 * @param {string} field
 * @returns {Error} with code OMADA_MISSING_FIELD
 */
function missingField(field) {
  const err = new Error('authenticateClient: missing required field ' + field);
  err.code = 'OMADA_MISSING_FIELD';
  return err;
}

// ================================================================
// Diagnostics: verbose Omada auth-failure logging
// ================================================================
// Maps the transport-level error codes Node emits to the most likely cause
// for THIS topology (cloud backend → Cloudflare tunnel → OC200), so a single
// Render log line is actionable without reproducing the failure locally.
const NETWORK_ERROR_HINTS = {
  ECONNREFUSED: 'controller refused the TCP connection (wrong host/port, or the tunnel is down)',
  ECONNRESET: 'connection reset mid-request — usually a dropped TLS handshake; verify OMADA_TLS_REJECT is not true and the tunnel forwards TLS',
  ETIMEDOUT: 'no response before the socket timeout — controller/tunnel unreachable',
  ESOCKETTIMEDOUT: 'socket timed out — controller/tunnel unreachable',
  ENOTFOUND: 'DNS lookup failed for the OMADA_BASE_URL host',
  EAI_AGAIN: 'DNS lookup temporarily failed for the OMADA_BASE_URL host',
  EHOSTUNREACH: 'host unreachable from the backend',
  ENETUNREACH: 'network unreachable from the backend',
  EPROTO: 'TLS protocol error — the self-signed controller cert was likely rejected (set OMADA_TLS_REJECT=false)',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'controller uses a self-signed cert (set OMADA_TLS_REJECT=false)',
  SELF_SIGNED_CERT_IN_CHAIN: 'self-signed cert in the controller chain (set OMADA_TLS_REJECT=false)',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'controller certificate is untrusted (set OMADA_TLS_REJECT=false)',
  CERT_HAS_EXPIRED: 'controller certificate has expired',
  ERR_TLS_CERT_ALTNAME_INVALID: 'controller cert hostname does not match OMADA_BASE_URL',
  OMADA_TIMEOUT: 'controller did not answer within OMADA_AUTH_TIMEOUT ms',
};

/**
 * Body fields that are safe to echo into the logs. Anything NOT in this list
 * is reported as a count only — /hotspot/login carries an operator password
 * and must never leak it into the Render logs.
 */
const LOGGABLE_BODY_FIELDS = [
  'clientMac', 'clientIp', 'apMac', 'ssidName', 'radioId',
  'gatewayMac', 'vid', 'authType', 'time', 'site', 'code',
];

/**
 * Mask a voucher code for logging: `••••12` (last two characters, matching
 * the admin UI's maskVoucherCode). The sent-body line still proves the field
 * was present, without writing a still-usable code into the Render logs —
 * on a FAILED authorization the voucher has deliberately NOT been consumed.
 *
 * @param {string|number} code
 * @returns {string}
 */
function maskCode(code) {
  const cleaned = String(code === undefined || code === null ? '' : code).replace(/\s+/g, '');
  if (!cleaned) return '(empty)';
  if (cleaned.length < 2) return '••••••';
  return '••••' + cleaned.slice(-2);
}

/**
 * Summarize an outgoing Omada request body for the logs: the connection type
 * the body describes, the site it targets, and the whitelisted field values
 * (clientMac/clientIp/apMac/ssidName/radioId/gatewayMac/vid/authType/time/
 * site). Non-whitelisted keys are replaced by a count, so a login body's
 * credentials can never be printed.
 *
 * @param {string} body  The JSON string passed to omadaRequest
 * @returns {{connection: string, site: string, text: string}}
 */
function summarizeBody(body) {
  if (body === undefined || body === null || body === '') {
    return { connection: 'unknown', site: '(unknown)', text: '(body not captured)' };
  }

  let parsed = null;
  try {
    parsed = JSON.parse(body);
  } catch (_) { /* non-JSON body below */ }

  if (!parsed || typeof parsed !== 'object') {
    return { connection: 'unknown', site: '(unknown)', text: '(non-JSON body)' };
  }

  const parts = [];
  for (const field of LOGGABLE_BODY_FIELDS) {
    // `site` is returned separately so callers can print `site=…` once.
    if (field === 'site') continue;
    if (!Object.prototype.hasOwnProperty.call(parsed, field)) continue;
    // The voucher is a live credential until the authorization succeeds —
    // log only its masked form.
    parts.push(field + '=' + (field === 'code' ? maskCode(parsed[field]) : parsed[field]));
  }
  const redacted = Object.keys(parsed).filter((k) => !LOGGABLE_BODY_FIELDS.includes(k));
  const connection = parsed.gatewayMac
    ? 'Gateway'
    : ((parsed.apMac || parsed.ssidName) ? 'EAP' : 'unknown');
  const site = (parsed.site !== undefined && parsed.site !== null)
    ? String(parsed.site)
    : '(none in body)';

  return {
    connection,
    site,
    text: (parts.length ? parts.join(' ') : '(no loggable fields)') +
      (redacted.length ? ' [+' + redacted.length + ' redacted field(s)]' : ''),
  };
}

/**
 * Log the exact failure reason for an extPortal/auth call so it is visible
 * in the Render logs: transport code, a mapped cause hint, the body that was
 * SENT (connection type / site / time / extra fields), the controller's
 * response JSON, and the stack.
 *
 * @param {string} stage  Which step failed (e.g. 'extPortal/auth request')
 * @param {Error}  err    The error thrown by omadaRequest/withSession
 * @param {Object} ctx    The authenticateClient context (for clientMac)
 * @param {string} path   The controller path that was called
 * @param {string} [body] The JSON body that was sent (for the sent-body line)
 */
function logAuthFailure(stage, err, ctx, path, body) {
  const code = (err && err.code) || 'NO_CODE';
  const message = (err && err.message) ? err.message : String(err);
  const clientMac = (ctx && ctx.clientMac) || 'unknown';
  console.error(
    '[omada] authenticateClient FAILED — stage=' + stage +
    ' client=' + clientMac +
    ' path=' + path +
    ' base=' + BASE_URL +
    ' code=' + code +
    ' message=' + message
  );
  const sent = summarizeBody(body);
  console.error(
    '[omada]   sent body: connection=' + sent.connection +
    ' site=' + sent.site + ' ' + sent.text
  );
  const hint = NETWORK_ERROR_HINTS[code];
  if (hint) console.error('[omada]   cause: ' + code + ' -> ' + hint);
  if (err && err.omadaResponse) {
    console.error('[omada]   controller response: ' + JSON.stringify(err.omadaResponse));
  }
  if (err && err.stack) console.error('[omada]   stack: ' + err.stack);
}

// ================================================================
// Diagnostics: resolved configuration + per-request target logging
// ================================================================
// A captive loop is almost always a config mismatch: the extPortal/auth
// call carries the SITE name in its body and targets the OMADAC_ID in its
// path, so if either resolves to a value the controller does not know, the
// authorization silently does nothing. These two logs make the resolved
// values visible in the Render logs so the operator can compare them with
// the controller's own Site / API settings.

let configLogged = false;

/**
 * Mask a URL for logging: keep the scheme + host, drop any userinfo,
 * path, query or fragment. Never echoes credentials embedded in the URL.
 *
 * @param {string} url
 * @returns {string}
 */
function maskHost(url) {
  if (!url) return '(unset)';
  try {
    const u = new URL(url);
    return u.protocol + '//' + u.host;
  } catch (_) {
    return '(invalid URL)'; // never echo an unparseable value verbatim
  }
}

/**
 * Log the resolved, non-secret Omada configuration once per process and
 * warn about values that are missing or still set to the .env.example
 * placeholders — a silent placeholder is the classic cause of a captive
 * loop (every extPortal/auth call misses the intended controller/site).
 *
 * Never prints OMADA_PORTAL_OPERATOR_PASSWORD or any session token.
 *
 * @param {boolean} [force]  Re-log even if already logged this process
 *                           (used by diagnostics/tests).
 */
function logResolvedConfig(force) {
  if (configLogged && !force) return;
  configLogged = true;

  console.log(
    '[omada] resolved config: mock=' + MOCK_MODE +
    ' base=' + maskHost(BASE_URL) +
    ' omadacId=' + (OMADAC_ID || '(unset)') +
    ' site=' + SITE +
    ' siteFromEnv=' + (process.env.OMADA_SITE ? 'yes' : 'NO (defaulted to "' + SITE + '")') +
    ' timeUnit=' + OMADA_TIME_UNIT +
    ' timeout=' + TIMEOUT + 'ms' +
    ' tlsRejectUnauthorized=' + TLS_REJECT +
    ' operator=' + (OPERATOR_NAME || '(unset)')
  );

  if (MOCK_MODE) {
    console.warn(
      '[omada] MOCK MODE — no extPortal/auth call will reach the controller' +
      (BASE_URL ? ' (OMADA_MOCK=true)' : ' (OMADA_BASE_URL is unset)')
    );
    return;
  }

  const problems = [];
  if (!OMADAC_ID) {
    problems.push('OMADA_OMADAC_ID is unset — the request path cannot resolve a controller');
  }
  if (!process.env.OMADA_SITE) {
    problems.push("OMADA_SITE is unset — defaulting to '" + SITE +
      "'; set it to the controller's EXACT site name if the guest SSID lives on another site");
  }
  if (!OPERATOR_NAME || !OPERATOR_PASSWORD) {
    problems.push('OMADA_PORTAL_OPERATOR_NAME/PASSWORD unset — hotspot login will fail');
  }
  if (/example\.com/i.test(BASE_URL) || /your-/i.test(OMADAC_ID)) {
    problems.push('a value is still the .env.example placeholder (base=' +
      maskHost(BASE_URL) + ' omadacId=' + (OMADAC_ID || '(unset)') + ')');
  }
  if (TLS_REJECT) {
    problems.push('OMADA_TLS_REJECT=true — a self-signed OC200 certificate will fail the TLS handshake');
  }

  if (problems.length) {
    console.error('[omada] CONFIG PROBLEMS (' + problems.length + ') — extPortal/auth will likely fail:');
    problems.forEach((p) => console.error('[omada]   - ' + p));
  } else {
    console.log('[omada] config looks complete');
  }
}

/**
 * Log the exact target of an outgoing controller request — the resolved
 * path (which embeds OMADAC_ID) and the `site` value actually placed in the
 * request body — so a Render log line shows what the controller received.
 *
 * The request BODY is never printed: /hotspot/login carries a password.
 *
 * @param {string} method
 * @param {string} path
 * @param {string} body
 * @param {Object} [opts]
 */
function logControllerRequest(method, path, body, opts) {
  const summary = summarizeBody(body);

  console.log(
    '[omada] → ' + method + ' ' + maskHost(BASE_URL) + path +
    ' site=' + summary.site +
    ' omadacId=' + (OMADAC_ID || '(unset)') +
    ' connection=' + summary.connection +
    ' body: ' + summary.text +
    (opts && opts.skipAuth ? ' (login — credentials redacted)' : '')
  );
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

    // Echo the exact resolved target of every controller call (path + site +
    // OMADAC_ID) into the logs, so the Render output shows what was sent.
    logControllerRequest(method, path, body, opts);

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
      // Preserve the ORIGINAL code (ECONNREFUSED / ETIMEDOUT / EPROTO / …) so
      // authenticateClient can log the exact failure reason. ECONNRESET is
      // only annotated — it is the signature of a TLS handshake dropped by
      // the controller or the tunnel.
      if (err.code === 'ECONNRESET' && !req.destroyed) {
        err.omadaConnectionReset = true;
        err.message = 'Omada connection reset (possible dropped TLS handshake) — ' + err.message;
      }
      err.omadaRequestPath = path;
      reject(err);
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
  logResolvedConfig,
  // Exposed for testing
  _internal: {
    minutesToTime,
    operatorLogin,
    invalidateSession,
    logResolvedConfig,
    logControllerRequest,
    logAuthFailure,
    summarizeBody,
    maskCode,
    maskHost,
    MOCK_MODE,
    BASE_URL,
    OMADAC_ID,
    SITE,
    TLS_REJECT,
  },
};
