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
 *      POST /{OMADAC_ID}/api/v2/sites/{siteKey}/hotspot/clients/{MAC}/unauth
 *      on an ADMINISTRATOR session, then VERIFY revocation against the site's
 *      authorized-client records (…/hotspot/authed-records); an /openapi/v1/…
 *      unauth and the authed-record disconnect are tried next. The
 *      undocumented extPortal/unauth (portal operator) is only a LAST RESORT:
 *      many builds answer it with errorCode -1600 "Unsupported request path."
 *      and the guest stays online after expiry. The site routes need the
 *      administrator because they are site-scoped and the portal operator
 *      holds no site privileges.
 *
 *   4. Per-client bandwidth cap (QoS):
 *        PATCH /{OMADAC_ID}/api/v2/sites/{siteKey}/clients/{MAC}/ratelimit
 *        body: { mode: 0, customRateLimit: { upEnable, upUnit, upLimit,
 *                downEnable, downUnit, downLimit } }   (mode 1 = named profile)
 *      This is the same operation the controller's own UI performs and the
 *      same one the Open API exposes as `updateClientRateLimitSetting` — it
 *      is simply reached through the WEB API with an ADMINISTRATOR session
 *      (cookie + Csrf-Token from OMADA_ADMIN_*) instead of an OAuth access
 *      token — the portal operator account has no site/QoS rights. That matters
 *      because the local Open API route needs controller firmware that
 *      supports it (v5.12+) and an Open API application created ON THE
 *      CONTROLLER; on a stock OC200 the OAuth token endpoint can answer
 *      HTTP 500, which used to leave every guest uncapped. A fallback route
 *      under /openapi/v1/... (the Open API router accepting the web session,
 *      exactly as the controller UI calls it) is tried second.
 *
 * TWO CREDENTIAL SETS (never interchangeable):
 *
 *   portal operator (OMADA_PORTAL_OPERATOR_*) — a Hotspot portal operator.
 *     Logs in through /hotspot/login and may ONLY authorize clients on
 *     /hotspot/extPortal/* (its undocumented unauth/session endpoints are
 *     attempted as a fallback). It holds no site privileges, so
 *     GET /users/current returns zero sites and the controller answers the
 *     rate-limit PATCH with a permission error.
 *
 *   administrator (OMADA_ADMIN_*) — a controller administrator account.
 *     Logs in through /login (the controller's own web-UI login) and is the
 *     ONLY account that may read the site list (GET /sites, /users/current),
 *     PATCH a client rate limit, or kick an authorized client off a site
 *     (…/hotspot/clients/{MAC}/unauth). Omada refuses administrator accounts
 *     on the hotspot portal endpoints, which is why both sets are required.
 *
 * Each set keeps its own session (cookie jar + Csrf-Token). Logging in as an
 * administrator must never displace the portal operator session used for
 * extPortal/auth, and vice versa.
 *
 * Configuration (from .env):
 *   OMADA_BASE_URL                  — e.g. https://omada-tunnel.example.com
 *   OMADA_OMADAC_ID                 — controller ID (OMADAC ID)
 *   OMADA_SITE                      — site name (default "Default"); sent in
 *                                     the body of EVERY hotspot call and
 *                                     echoed in the [omada] startup log
 *   OMADA_PORTAL_OPERATOR_NAME      — hotspot portal operator username; used
 *                                     ONLY for /hotspot/login + extPortal/*
 *   OMADA_PORTAL_OPERATOR_PASSWORD  — hotspot portal operator password
 *   OMADA_ADMIN_NAME                — controller administrator username; used
 *                                     ONLY for site queries, QoS PATCHes and
 *                                     client deauthorization
 *   OMADA_ADMIN_PASSWORD            — controller administrator password
 *   OMADA_AUTH_TIMEOUT              — request timeout ms (default 10000)
 *   OMADA_TLS_REJECT                — "true" enforces full cert validation;
 *                                     default "false" accepts the controller's
 *                                     self-signed certificate
 *   OMADA_MOCK                      — "true" to bypass the controller
 *
 * Origin/Referer are NOT derived from OMADA_BASE_URL. The Cloudflare
 * Tunnel's reverse proxy rewrites the Host header to the controller's LAN
 * address, and Tomcat's CSRF filter rejects any request whose Origin does
 * not match it — with an HTTP 500, not a clean 4xx. They are therefore
 * hardcoded to the controller's internal origin (CONTROLLER_ORIGIN below).
 */

const https = require('https');
const http = require('http');
const { OMADA_TIME_UNIT } = require('../config');
const { normalizeMac: normalizeDeviceMac } = require('../utils/device-id');

const BASE_URL   = process.env.OMADA_BASE_URL || '';
const OMADAC_ID  = process.env.OMADA_OMADAC_ID || '';
const SITE       = process.env.OMADA_SITE     || 'Default';
// Portal operator — captive-portal authorization ONLY (/hotspot/login and
// /hotspot/extPortal/*). Never used for site queries or QoS: this account has
// no site privileges, which is why the controller returns 0 sites for it.
const OPERATOR_NAME = process.env.OMADA_PORTAL_OPERATOR_NAME || '';
const OPERATOR_PASSWORD = process.env.OMADA_PORTAL_OPERATOR_PASSWORD || '';

// Controller ADMINISTRATOR — privileged calls ONLY (site list, client
// rate-limit PATCH, and kicking a client off the site). Omada will not accept
// an administrator on the hotspot portal endpoints, so it cannot replace the
// operator credentials above.
const ADMIN_NAME = process.env.OMADA_ADMIN_NAME || '';
const ADMIN_PASSWORD = process.env.OMADA_ADMIN_PASSWORD || '';
const TIMEOUT    = parseInt(process.env.OMADA_AUTH_TIMEOUT || '10000', 10);
// OC200/ER605 controllers present a SELF-SIGNED certificate. From a cloud
// backend (Render) the default Node TLS behavior rejects it during the
// handshake, surfacing as an opaque ECONNRESET/EPROTO and failing every
// authorization. Default to accepting it (rejectUnauthorized: false); set
// OMADA_TLS_REJECT=true only when the controller has a publicly-trusted cert.
const TLS_REJECT = process.env.OMADA_TLS_REJECT === 'true';

// Origin/Referer sent on EVERY controller request. Hardcoded to the
// controller's LAN origin because the Cloudflare Tunnel's reverse proxy
// injects that same value as the Host header; Tomcat compares Origin against
// it and answers HTTP 500 on a mismatch (OMADA_BASE_URL's public hostname
// never matches). Change these if the controller's internal address changes.
const CONTROLLER_ORIGIN  = 'https://192.168.0.253:8043';
const CONTROLLER_REFERER = CONTROLLER_ORIGIN + '/';

// In mock/test mode, simulate controller responses
const MOCK_MODE = process.env.OMADA_MOCK === 'true' || !BASE_URL;

// ── Controller sessions (one per credential set) ───────────────────────
// A controller session is a loose cookie store + the CSRF token returned by
// its login. There is one per credential set, because an administrator login
// and a hotspot portal login are separate accounts with separate privileges:
//
//   portalSession — OMADA_PORTAL_OPERATOR_* (hotspot/login); extPortal/*.
//   adminSession  — OMADA_ADMIN_* (/login); site queries, QoS PATCHes and
//                    kicking a client off the site.
//
// Cookie + CSRF token are obtained once per session and reused; a 401 from the
// controller invalidates and re-establishes THAT session only.
function createSession(label) {
  return { label, cookies: new Map(), csrfToken: null };
}

const portalSession = createSession('portal-operator');
const adminSession = createSession('admin');

// ── Cookie store (loose mode) ──────────────────────────────────────────
// The controller is reached through a Cloudflare Tunnel, so the cookie's
// Domain (the internal OC200 host) and the Host the backend actually calls
// (the public tunnel hostname) differ. A strict RFC 6265 jar rejects such a
// cookie as a domain mismatch and stores nothing, which leaves the login
// cookie off every later request. This store deliberately keeps only the
// name=value pairs and never validates Domain/Path/Secure — the moral
// equivalent of tough-cookie's `looseMode` — so a proxied Set-Cookie is
// always retained and replayed.

/**
 * Absorb Set-Cookie response header(s) into a session's loose cookie store.
 * Attributes (Domain, Path, Secure, HttpOnly, SameSite, …) are ignored.
 *
 * @param {Object} session                portalSession | adminSession
 * @param {string|string[]|null} setCookieHeader  res.headers['set-cookie']
 */
function absorbSetCookie(session, setCookieHeader) {
  if (!setCookieHeader) return;
  const list = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  for (const entry of list) {
    if (typeof entry !== 'string') continue;
    const pair = entry.split(';')[0];
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (!name) continue;
    // An empty value is how the controller clears a cookie (Max-Age=0/Expires past).
    if (!value) session.cookies.delete(name);
    else session.cookies.set(name, value);
  }
}

/**
 * Build the Cookie request header from a session's stored pairs.
 * @param {Object} session  portalSession | adminSession
 * @returns {string|null}
 */
function cookieHeaderValue(session) {
  if (session.cookies.size === 0) return null;
  return Array.from(session.cookies.entries())
    .map(([name, value]) => name + '=' + value)
    .join('; ');
}

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
 * Perform a controller login that establishes a session (cookie jar + CSRF
 * token) for the given credential set.
 *
 * @param {Object} session      portalSession | adminSession
 * @param {string} path         login path (differs per credential set)
 * @param {string} body         JSON credentials body
 * @param {string} label        human-readable account kind for errors
 * @returns {Promise<void>} resolves on success, throws on failure
 */
async function performLogin(session, path, body, label) {
  const response = await omadaRequest(path, 'POST', body, { skipAuth: true, session });

  if (response.statusCode !== 200 || !response.body || response.body.errorCode !== 0) {
    const err = new Error(
      'Omada ' + label + ' login failed: ' +
      (response.body && (response.body.msg || response.body.message) || ('HTTP ' + response.statusCode))
    );
    err.code = 'OMADA_LOGIN_FAILED';
    err.omadaResponse = response.body;
    throw err;
  }

  // The login cookie was already absorbed into this session's loose cookie
  // store by omadaRequest (see absorbSetCookie); only the CSRF token is kept
  // here. It is stored PER SESSION: the two logins return different tokens.
  session.csrfToken = response.body.result && response.body.result.token;
  if (!session.csrfToken) {
    const err = new Error('Omada ' + label + ' login response missing result.token');
    err.code = 'OMADA_LOGIN_FAILED';
    throw err;
  }
}

/**
 * Log in as the hotspot PORTAL OPERATOR.
 * Establishes portalSession (cookie) and stores its CSRF token.
 *
 * This credential set is used ONLY for /hotspot/extPortal/* calls: it has no
 * site privileges, so it cannot read the site list or set bandwidth caps.
 *
 * @returns {Promise<void>} resolves on success, throws on failure
 */
async function operatorLogin() {
  const path = '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/hotspot/login';
  const body = JSON.stringify({ name: OPERATOR_NAME, password: OPERATOR_PASSWORD });
  await performLogin(portalSession, path, body, 'hotspot operator');
}

/**
 * Log in as the controller ADMINISTRATOR through the web-UI login endpoint.
 * Establishes adminSession (cookie) and stores its CSRF token.
 *
 * Administrator rights are required for EVERY privileged call: reading the
 * site list and PATCHing a client rate limit. Omada refuses administrator
 * accounts on the hotspot portal endpoints, hence a separate session.
 *
 * @returns {Promise<void>} resolves on success, throws on failure
 */
async function adminLogin() {
  if (!ADMIN_NAME || !ADMIN_PASSWORD) {
    throw configError(
      'OMADA_ADMIN_NAME / OMADA_ADMIN_PASSWORD are not configured — the site ' +
      'list and bandwidth caps require a controller administrator account ' +
      '(the portal operator has no site/QoS privileges)'
    );
  }
  const path = '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/login';
  const body = JSON.stringify({ username: ADMIN_NAME, password: ADMIN_PASSWORD });
  await performLogin(adminSession, path, body, 'administrator');
}

/**
 * Invalidate one controller session (forcing a re-login on next use).
 * With no argument, both sessions are cleared (per-credential-set invalidation
 * happens on a 401 so the other session's cookie is never thrown away).
 *
 * @param {Object} [session]  portalSession | adminSession
 */
function invalidateSession(session) {
  for (const target of (session ? [session] : [portalSession, adminSession])) {
    target.cookies.clear();
    target.csrfToken = null;
  }
}

/**
 * Ensure a valid controller session exists for a credential set, logging in
 * if it is missing (or unconditionally with { force: true }).
 *
 * @param {Object} session  portalSession | adminSession
 * @param {Object} [opts]   { force } — re-login even when a session exists
 * @returns {Promise<void>}
 */
async function ensureSession(session, opts) {
  const force = Boolean(opts && opts.force);
  if (!force && session.cookies.size > 0 && session.csrfToken) return;
  if (session === adminSession) await adminLogin();
  else await operatorLogin();
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
    response = await requestWithSession(portalSession, path, 'POST', body);
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

// ================================================================
// Deauthorization — kick a client off the controller (ADMIN session)
// ================================================================
// /hotspot/extPortal/unauth is UNDOCUMENTED and many controller builds do not
// serve it: they answer HTTP 200 with errorCode -1600 ("Unsupported request
// path."), the backend logs a rejection, and the guest keeps internet access
// after its voucher expired. The same kick is a SITE operation, so it needs an
// ADMINISTRATOR session — the portal operator holds no site privileges (it is
// the same account that returned 0 sites for the QoS PATCH).
//
// Routes performing the kick, tried in order on adminSession:
//   v2-unauth       — the web-API path the controller UI uses.
//   openapi-session — the Open API router reached with the web session (how the
//                     controller UI itself calls the Open API on a local box).
//   authed-record   — disconnect by the site's own authentication record, for
//                     builds that expose no MAC-level unauth path.
//
// Acceptance is verified from the site's authorized-client records: a MAC with
// no record (or with an expired one) is no longer authorized.
const DEAUTH_ROUTES = [
  {
    name: 'v2-unauth',
    path: (omadacId, siteKey, mac) => '/' + encodeURIComponent(omadacId) +
      '/api/v2/sites/' + encodeURIComponent(siteKey) +
      '/hotspot/clients/' + encodeURIComponent(mac) + '/unauth',
  },
  {
    name: 'openapi-session',
    path: (omadacId, siteKey, mac) => '/openapi/v1/' + encodeURIComponent(omadacId) +
      '/sites/' + encodeURIComponent(siteKey) +
      '/hotspot/clients/' + encodeURIComponent(mac) + '/unauth',
  },
  {
    name: 'authed-record',
    needsRecord: true,
    path: (omadacId, siteKey, mac, recordId) => '/' + encodeURIComponent(omadacId) +
      '/api/v2/sites/' + encodeURIComponent(siteKey) +
      '/hotspot/authed-records/' + encodeURIComponent(recordId) + '/disconnect',
  },
];

// The kick route that last worked (see DEAUTH_ROUTES). Process-local.
let preferredDeauthRoute = null;

/**
 * Describe a controller rejection as one log/error line.
 *
 * @param {{statusCode:number, body:Object}} response
 * @returns {string}
 */
function describeRejection(response) {
  const body = (response && response.body) || {};
  let reason = body.msg || body.message || ('HTTP ' + (response && response.statusCode));
  if (body.errorCode !== undefined) reason += ' (errorCode=' + body.errorCode + ')';
  if (body.errorCode === -1600) reason += ' — this controller build does not serve that path';
  return reason;
}

/**
 * Extract the authorized-client records from a controller response.
 *
 * @param {Object} response omadaRequest result
 * @returns {Array<Object>|null} records, or null when the call did not succeed
 */
function authedRecords(response) {
  if (!response || response.statusCode !== 200 || !response.body || response.body.errorCode !== 0) {
    return null;
  }
  const result = response.body.result;
  if (!result) return null;
  const data = Array.isArray(result) ? result : (result.data || result.records);
  return Array.isArray(data) ? data : null;
}

/**
 * List the site's authorized clients on the ADMINISTRATOR session.
 *
 * @param {string} siteKey
 * @returns {Promise<Array<Object>|null>} null when no route answers
 */
async function listAuthedRecords(siteKey) {
  const paths = [
    '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/sites/' + encodeURIComponent(siteKey) +
      '/hotspot/authed-records?page=1&pageSize=200',
    '/openapi/v1/' + encodeURIComponent(OMADAC_ID) + '/sites/' + encodeURIComponent(siteKey) +
      '/hotspot/authed-records?page=1&pageSize=200',
  ];

  for (const path of paths) {
    try {
      const records = authedRecords(await requestWithSession(adminSession, path, 'GET'));
      if (records) return records;
    } catch (err) {
      console.warn('[omada] authed-records lookup via ' + path + ' failed: ' + err.message);
    }
  }
  return null;
}

/**
 * Find a MAC's authentication record in a records list.
 *
 * @param {Array<Object>|null} records
 * @param {string} clientMac canonical AA:BB:CC:DD:EE:FF
 * @returns {Object|null}
 */
function recordFor(records, clientMac) {
  if (!Array.isArray(records)) return null;
  return records.find((r) => normalizeDeviceMac(r && (r.mac || r.clientMac)) === clientMac) || null;
}

/**
 * Whether an authentication record still grants access.
 *
 * An entry with no validity information counts as authorized (the caller only
 * reaches this with a record the controller returned for the MAC).
 *
 * @param {Object|null} record
 * @returns {boolean}
 */
function isRecordAuthorized(record) {
  if (!record) return false;
  if (typeof record.valid === 'boolean') return record.valid;
  if (typeof record.authorized === 'boolean') return record.authorized;

  const raw = record.end !== undefined
    ? record.end
    : (record.endTime !== undefined ? record.endTime : record.expireTime);
  if (raw !== undefined && raw !== null && raw !== '') {
    const numeric = Number(raw);
    if (Number.isFinite(numeric)) {
      // Some builds report seconds, others milliseconds.
      const at = numeric < 1e11 ? numeric * 1000 : numeric;
      return at > Date.now();
    }
    const parsed = Date.parse(raw);
    if (Number.isFinite(parsed)) return parsed > Date.now();
  }
  return true;
}

/**
 * Whether the controller still authorizes a client on the site.
 *
 * @param {string} siteKey
 * @param {string} clientMac canonical AA:BB:CC:DD:EE:FF
 * @returns {Promise<boolean|null>} null when the record list is unavailable
 */
async function isClientStillAuthorized(siteKey, clientMac) {
  const records = await listAuthedRecords(siteKey);
  if (!records) return null;
  return isRecordAuthorized(recordFor(records, clientMac));
}

/**
 * Kick a client off the controller on the ADMINISTRATOR session.
 *
 * Each route is accepted only after the controller answers errorCode 0 AND the
 * client no longer appears as authorized; a still-authorized client falls
 * through to the next route. The first route that works is remembered.
 *
 * @param {string} clientMac canonical AA:BB:CC:DD:EE:FF
 * @returns {Promise<{success:boolean, verified?:boolean, route?:string, failures?:Array}>}
 * @throws when the administrator login or the site lookup fails
 */
async function deauthenticateClientAsAdmin(clientMac) {
  await ensureSession(adminSession);
  const siteKey = await resolveSiteKey();
  // Path segments carry the hyphen-separated MAC the controller's URLs use.
  const pathMac = clientMac.replace(/:/g, '-');

  const routes = preferredDeauthRoute
    ? [
        ...DEAUTH_ROUTES.filter((r) => r.name === preferredDeauthRoute),
        ...DEAUTH_ROUTES.filter((r) => r.name !== preferredDeauthRoute),
      ]
    : DEAUTH_ROUTES;

  const failures = [];
  for (const route of routes) {
    let recordId = null;
    if (route.needsRecord) {
      const records = await listAuthedRecords(siteKey);
      const record = recordFor(records, clientMac);
      recordId = record && (record.id || record.recordId);
      if (!recordId) {
        failures.push({ route: route.name, reason: 'no authentication record for this MAC' });
        continue;
      }
    }

    const path = route.path(OMADAC_ID, siteKey, pathMac, recordId);

    let response;
    try {
      // POST with an empty JSON object: the action endpoints expect a body,
      // and an empty one keeps the request identical to the controller UI's.
      response = await requestWithSession(adminSession, path, 'POST', '{}');
    } catch (err) {
      failures.push({ route: route.name, reason: err.message });
      console.error('[omada] deauth ' + route.name + ' request failed for ' + clientMac + ': ' + err.message);
      continue;
    }

    if (response.statusCode !== 200 || !response.body || response.body.errorCode !== 0) {
      const reason = describeRejection(response);
      failures.push({ route: route.name, reason });
      console.warn('[omada] deauth ' + route.name + ' rejected for ' + clientMac + ' — ' + reason);
      continue;
    }

    // Accepted — prove it actually revoked access before reporting success.
    const stillAuthorized = await isClientStillAuthorized(siteKey, clientMac);
    if (stillAuthorized === true) {
      failures.push({
        route: route.name,
        reason: 'controller accepted the call but the client is still authorized',
      });
      console.warn(
        '[omada] deauth ' + route.name + ' accepted for ' + clientMac +
        ' but the client is STILL authorized — trying the next route'
      );
      continue;
    }

    preferredDeauthRoute = route.name;
    console.log(
      '[omada] kicked ' + clientMac + ' via ' + route.name + ' (POST ' + path + ')' +
      (stillAuthorized === false ? ' — revocation verified' : ' — not verified (record list unavailable)')
    );
    return { success: true, verified: stillAuthorized === false, route: route.name };
  }

  return { success: false, failures };
}

/**
 * De-authorize a client (pause / expiration).
 *
 * Flow:
 *   1. Kick through the ADMINISTRATOR session (see DEAUTH_ROUTES); a route is
 *      accepted only once the site's authed-records no longer list the MAC.
 *   2. Fall back to the operator's extPortal/unauth (undocumented; answers
 *      errorCode -1600 where unsupported).
 *   3. Verify actual revocation via the status call (see the NOTE on
 *      queryClientStatus below for its own verification status)
 *      ├─ revoked            → success
 *      ├─ still authorized   → time=1 fallback re-auth, then re-verify
 *      └─ status call failed → WARN "verification unavailable", do NOT
 *         fail the revoke (avoid false failures); deauth_verified=false
 *   4. If STILL authorized after the time=1 fallback → log ERROR and
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

  // ── Step 1: privileged kick on the ADMINISTRATOR session ──
  // This is the path that actually disconnects a guest on a build that does
  // not serve extPortal/unauth. A failure here is NOT fatal: the operator
  // endpoint below is still tried, because some firmware serves only that.
  const canonical = normalizeDeviceMac(ctx.clientMac);
  if (canonical && ADMIN_NAME && ADMIN_PASSWORD) {
    try {
      const kicked = await deauthenticateClientAsAdmin(canonical);
      if (kicked.success) {
        console.log(
          '[omada] unauth for ' + canonical + ' → accepted via ' + kicked.route +
          (kicked.verified
            ? ' (revocation verified)'
            : ' (revocation NOT verified — the record list is unavailable)')
        );
        return { success: true, verified: kicked.verified, path: kicked.route };
      }
      console.warn(
        '[omada] administrator deauth for ' + canonical + ' failed on every site route: ' +
        kicked.failures.map((f) => f.route + ': ' + f.reason).join(' | ')
      );
    } catch (err) {
      console.error('[omada] administrator deauth for ' + canonical + ' failed: ' + err.message);
    }
  }

  // ── Step 2: operator extPortal/unauth (fallback for older firmware) ──
  const unauthPath = '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/hotspot/extPortal/unauth';
  const body = JSON.stringify({
    clientMac: ctx.clientMac,
    apMac: ctx.apMac || '',
    ssidName: ctx.ssidName || '',
    site: SITE,
  });

  let unauthOk = false;
  try {
    const response = await requestWithSession(portalSession, unauthPath, 'POST', body);
    unauthOk = response.statusCode === 200 && response.body && response.body.errorCode === 0;
    console.log(
      '[omada] extPortal/unauth for ' + ctx.clientMac + ' → ' +
      (unauthOk ? 'accepted' : 'rejected (HTTP ' + response.statusCode + ', errorCode=' +
        (response.body && response.body.errorCode) + ')')
    );
    if (!unauthOk && response.body && response.body.errorCode === -1600) {
      console.error(
        '[omada] extPortal/unauth is not served by this controller build (errorCode -1600, ' +
        '"Unsupported request path.") — a kick must go through the administrator site routes'
      );
    }
  } catch (err) {
    console.error('[omada] extPortal/unauth request failed for ' + ctx.clientMac + ':', err.message);
  }

  // ── Step 3: verify actual revocation, fall back if needed ──
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

  const response = await requestWithSession(portalSession, path, 'POST', body);
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
    const response = await requestWithSession(portalSession, path, 'POST', body);
    const ok = response.statusCode === 200 && response.body && response.body.errorCode === 0;
    console.log('[omada] time=1 fallback for ' + ctx.clientMac + ' → ' + (ok ? 'accepted' : 'rejected'));
    return ok;
  } catch (err) {
    console.error('[omada] time=1 fallback request failed for ' + ctx.clientMac + ':', err.message);
    return false;
  }
}

/**
 * Run a controller request on a specific credential set's session: ensures
 * that session's login, and on a 401 invalidates and retries once with a
 * fresh login — without touching the other credential set's session.
 *
 * @param {Object} session  portalSession (extPortal/*) | adminSession (QoS, sites)
 * @param {string} path
 * @param {string} method
 * @param {string} [body]
 * @returns {Promise<Object>} omadaRequest response
 */
async function requestWithSession(session, path, method, body) {
  await ensureSession(session);
  let response = await omadaRequest(path, method, body, { session });
  if (response.statusCode === 401) {
    console.warn('[omada] ' + session.label + ' session expired — re-logging in');
    invalidateSession(session);
    await ensureSession(session);
    response = await omadaRequest(path, method, body, { session });
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
    ' operator=' + (OPERATOR_NAME || '(unset)') +
    ' admin=' + (ADMIN_NAME || '(unset)')
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
  if (!ADMIN_NAME || !ADMIN_PASSWORD) {
    problems.push('OMADA_ADMIN_NAME/PASSWORD unset — site queries, bandwidth caps and client deauthorization will fail (expired guests stay online)');
  }
  if (/example\.com/i.test(BASE_URL) || /your-/i.test(OMADAC_ID)) {
    problems.push('a value is still the .env.example placeholder (base=' +
      maskHost(BASE_URL) + ' omadacId=' + (OMADAC_ID || '(unset)') + ')');
  }
  if (TLS_REJECT) {
    problems.push('OMADA_TLS_REJECT=true — a self-signed OC200 certificate will fail the TLS handshake');
  }

  if (problems.length) {
    console.error('[omada] CONFIG PROBLEMS (' + problems.length + ') — Omada calls will likely fail:');
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
  // Which credential set carries this request. Every privileged call (site
  // queries, QoS) passes adminSession explicitly; hotspot calls pass
  // portalSession. The default stays the portal session so an unannotated
  // hotspot call can never accidentally run as the administrator.
  const session = (opts && opts.session) || portalSession;

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
        // Must match the Host the tunnel proxy injects into Tomcat — see
        // CONTROLLER_ORIGIN. Using OMADA_BASE_URL here triggers the CSRF
        // filter's HTTP 500.
        'Origin': CONTROLLER_ORIGIN,
        'Referer': CONTROLLER_REFERER,
        // What the controller's own web UI sends; some non-hotspot endpoints
        // (the v2 client/config routes used for QoS) expect it.
        'Omada-Request-Source': 'web-local',
      },
      rejectUnauthorized: TLS_REJECT,
      timeout: TIMEOUT,
    };

    // Echo the exact resolved target of every controller call (path + site +
    // OMADAC_ID) into the logs, so the Render output shows what was sent.
    logControllerRequest(method, path, body, opts);

    // Attach THIS session's cookie and CSRF token when present. Login itself
    // (opts.skipAuth) carries no session credentials.
    if (!(opts && opts.skipAuth)) {
      const cookie = cookieHeaderValue(session);
      if (cookie) options.headers['Cookie'] = cookie;
      if (session.csrfToken) options.headers['Csrf-Token'] = session.csrfToken;
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
        // Capture the cookie for THIS session only. Stored in loose mode:
        // Domain/Path from the tunneled response are not enforced, so the
        // cookie survives the host mismatch. Keeping the jars separate means
        // an administrator login cannot displace the portal operator cookie.
        const setCookieHeader = res.headers['set-cookie'];
        absorbSetCookie(session, setCookieHeader);
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
// QoS — per-client bandwidth cap through the WEB API (ADMIN session)
// ================================================================
// The cap is not an Open API-only feature: the controller's own UI sets it
// through the v2 web API, authenticated by a session cookie + Csrf-Token. (The
// OAuth/Open API transport this module used to fall back to has been removed —
// it needs firmware that ships the Open API (v5.12+) and an application created
// on the controller, and an OC200 without it answers the token request with
// HTTP 500, leaving every guest uncapped.)
//
// That session MUST belong to a controller ADMINISTRATOR (OMADA_ADMIN_*),
// never to the hotspot portal operator: the operator account has no site
// privileges, so GET /users/current returns 0 sites and the PATCH is refused
// (the exact failure this module used to hit). Omada also refuses admin
// accounts on /hotspot/extPortal/auth, which is why the two sessions exist.
// The cap is therefore applied on a freshly-obtained admin session, while
// guest authorization stays on the portal operator session.

/**
 * Routes performing the same operation, tried in order.
 *
 * `v2`            — the web API path used by the controller UI.
 * `openapi-session` — the Open API router reached with the web session, which
 *                   is how the controller UI itself calls the Open API on a
 *                   local controller ("old authentication style").
 */
const RATE_LIMIT_ROUTES = [
  {
    name: 'v2',
    path: (omadacId, siteKey, mac) => '/' + encodeURIComponent(omadacId) +
      '/api/v2/sites/' + encodeURIComponent(siteKey) +
      '/clients/' + encodeURIComponent(mac) + '/ratelimit',
  },
  {
    name: 'openapi-session',
    path: (omadacId, siteKey, mac) => '/openapi/v1/' + encodeURIComponent(omadacId) +
      '/sites/' + encodeURIComponent(siteKey) +
      '/clients/' + encodeURIComponent(mac) + '/ratelimit',
  },
];

// The route that last worked, so a working controller does not pay for the
// rejected probe on every login. Process-local; a restart simply re-probes.
let preferredRateLimitRoute = null;

// OMADA_SITE (a NAME) → the numeric/hex site key the v2 paths require.
let rateLimitSiteKeyCache = { name: null, key: null };

/**
 * Extract the site list from a controller response. The account's own site
 * list lives on `result.privilege.sites` (GET /users/current); other firmware
 * answers `result.data` / a bare array. Each entry carries the display name
 * plus its identifier (`key`, or `id` on some builds).
 *
 * @param {Object} response omadaRequest result
 * @returns {Array<Object>}
 */
function siteEntries(response) {
  if (!response || response.statusCode !== 200 || !response.body || response.body.errorCode !== 0) {
    return [];
  }
  const result = response.body.result || {};
  const candidates = [
    result.privilege && result.privilege.sites,
    result.data,
    result.sites,
    Array.isArray(result) ? result : null,
  ];
  for (const list of candidates) {
    if (Array.isArray(list) && list.length) return list;
  }
  return [];
}

/**
 * Resolve OMADA_SITE (a name) to the site key/id the v2 client paths embed.
 *
 * Runs on the ADMINISTRATOR session: only an account with site privileges is
 * returned a non-empty site list by GET /users/current (or /sites). Using the
 * portal operator here is what produced "0 sites".
 *
 * Cached per process: the mapping only changes when the controller's site is
 * renamed, and a changed OMADA_SITE invalidates the cache (the cached name no
 * longer matches).
 *
 * @returns {Promise<string>}
 */
async function resolveSiteKey() {
  if (rateLimitSiteKeyCache.name === SITE && rateLimitSiteKeyCache.key) {
    return rateLimitSiteKeyCache.key;
  }

  const endpoints = [
    '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/users/current',
    '/' + encodeURIComponent(OMADAC_ID) + '/api/v2/sites',
  ];

  let sites = [];
  for (const path of endpoints) {
    try {
      const response = await requestWithSession(adminSession, path, 'GET');
      sites = siteEntries(response);
      if (sites.length) break;
    } catch (err) {
      console.warn('[omada/qos] site lookup via ' + path + ' failed: ' + err.message);
    }
  }

  const wanted = String(SITE).trim().toLowerCase();
  const match = sites.find(
    (s) => String(s && s.name != null ? s.name : '').trim().toLowerCase() === wanted
  );
  const key = match && (match.key || match.id || match.siteKey);

  if (!key) {
    const err = new Error(
      'OMADA_SITE "' + SITE + '" did not match any site the controller returned (' +
      sites.length + ' site(s)); the bandwidth cap cannot address a site' +
      (sites.length === 0
        ? ' — 0 sites usually means OMADA_ADMIN_NAME/OMADA_ADMIN_PASSWORD are not a controller administrator (the portal operator has no site privileges)'
        : '')
    );
    err.code = 'OMADA_SITE_NOT_FOUND';
    err.omadaResponse = sites;
    throw err;
  }

  rateLimitSiteKeyCache = { name: SITE, key: String(key) };
  console.log('[omada/qos] resolved OMADA_SITE "' + SITE + '" → siteKey ' + rateLimitSiteKeyCache.key);
  return rateLimitSiteKeyCache.key;
}

/**
 * Normalized error for a controller rejection of the rate-limit call.
 *
 * @param {string} route
 * @param {{statusCode:number, body:Object}} response
 * @returns {Error}
 */
function rateLimitRejected(route, response) {
  const body = (response && response.body) || {};
  const reason = body.msg || body.message || ('HTTP ' + (response && response.statusCode));
  const err = new Error(
    'Omada rate limit (' + route + ') rejected: ' + reason +
    (body.errorCode !== undefined ? ' (errorCode=' + body.errorCode + ')' : '')
  );
  err.code = 'OMADA_QOS_REJECTED';
  err.omadaResponse = body;
  return err;
}

/**
 * The operator's VOUCHER_DEFAULT_* caps — the fallback for every caller with no
 * tier/voucher-specific cap.
 *
 * Both values go through parseInt(..., 10) so a quoted or suffixed value can
 * never reach the controller as a string, and both are range-checked against
 * the 1–1024 ceiling Omada accepts per unit. Down is Mbps (unit 2) and up is
 * Kbps (unit 1) — the units the portal advertises to customers.
 *
 * Throws instead of sending mode 0 with no limits: a guest left uncapped while
 * the logs claim a cap was applied is exactly the silent failure this fallback
 * exists to prevent.
 *
 * @returns {Object} a customRateLimit payload fragment
 */
function defaultRateLimitPayload() {
  const downMbps = parseInt(process.env.VOUCHER_DEFAULT_DOWN_MBPS, 10);
  const upKbps = parseInt(process.env.VOUCHER_DEFAULT_UP_KBPS, 10);

  if (!Number.isInteger(downMbps) || downMbps < 1 || downMbps > 1024) {
    throw configError('VOUCHER_DEFAULT_DOWN_MBPS must be an integer between 1 and 1024 (Mbps)');
  }
  if (!Number.isInteger(upKbps) || upKbps < 1 || upKbps > 1024) {
    throw configError('VOUCHER_DEFAULT_UP_KBPS must be an integer between 1 and 1024 (Kbps)');
  }

  return {
    upEnable: true,
    upUnit: 1,      // 1 = Kbps
    upLimit: upKbps,
    downEnable: true,
    downUnit: 2,    // 2 = Mbps
    downLimit: downMbps,
  };
}

/**
 * Build the PATCH body for the controller's per-client rate-limit call.
 *
 * Accepts the flat shape the payment/session callers use (customRateLimit /
 * mode / rateLimitProfileId) and produces the payload the controller expects:
 * mode 0 = explicit values, mode 1 = a named profile. A caller that passes no
 * customRateLimit (no tier-specific cap) gets the VOUCHER_DEFAULT_* caps, so
 * the fallback lives in one place instead of in every caller.
 *
 * @param {Object} ctx
 * @param {0|1} [ctx.mode=0]                 0 = custom values, 1 = named profile
 * @param {string} [ctx.rateLimitProfileId]  required when mode is 1
 * @param {Object} [ctx.customRateLimit]     mode-0 values; defaults when omitted
 * @returns {{mode:number, customRateLimit?:Object, rateLimitProfileId?:string}}
 */
function buildRateLimitPayload(ctx) {
  const mode = Number(ctx && ctx.mode) === 1 ? 1 : 0;
  const body = { mode };

  if (mode === 1) {
    if (!ctx.rateLimitProfileId) throw missingField('rateLimitProfileId');
    body.rateLimitProfileId = ctx.rateLimitProfileId;
    return body;
  }

  const c = (ctx && ctx.customRateLimit) || defaultRateLimitPayload();
  for (const field of ['upLimit', 'downLimit']) {
    const n = Number(c[field]);
    if (!Number.isInteger(n) || n < 1 || n > 1024) {
      throw configError('customRateLimit.' + field + ' must be an integer between 1 and 1024');
    }
  }

  body.customRateLimit = {
    upEnable: Boolean(c.upEnable),
    upUnit: Number(c.upUnit) === 2 ? 2 : 1,
    upLimit: Number(c.upLimit),
    downEnable: Boolean(c.downEnable),
    downUnit: Number(c.downUnit) === 2 ? 2 : 1,
    downLimit: Number(c.downLimit),
  };

  return body;
}

/**
 * Apply a per-client bandwidth cap through the controller's web API.
 *
 * Privileged operation: it runs on a FRESH administrator session
 * (OMADA_ADMIN_*), obtained at the start of every call, so a stale or
 * operator-level cookie can never reach the PATCH. The portal operator
 * session is deliberately not touched here — guest authorization keeps
 * using it. Both routes perform the same operation; the first accepted one is
 * remembered and tried first afterwards.
 *
 * @param {Object} ctx
 * @param {string} ctx.clientMac  Client MAC, any common format
 * @param {Object} [ctx.payload]  an already-built { mode, customRateLimit } body
 * @param {Object} [ctx.customRateLimit]  mode-0 caps (defaults when omitted)
 * @param {0|1}    [ctx.mode]             0 = custom values (default), 1 = profile
 * @param {string} [ctx.rateLimitProfileId] required when mode is 1
 * @returns {Promise<Object>} { success, clientMac, applied, route, mock? }
 * @throws Error with code OMADA_QOS_REJECTED / OMADA_SITE_NOT_FOUND / OMADA_MOCK…
 */
async function setClientRateLimit(ctx) {
  if (!ctx || !ctx.clientMac) throw missingField('clientMac');

  const canonical = normalizeDeviceMac(ctx.clientMac);
  if (!canonical) {
    const err = new Error('setClientRateLimit: invalid clientMac');
    err.code = 'OMADA_INVALID_MAC';
    throw err;
  }

  // Either an already-built PATCH body ({ payload }) or the flat
  // { customRateLimit } / { mode, rateLimitProfileId } shape. Resolving the
  // default caps here means every caller gets the VOUCHER_DEFAULT_* fallback
  // without having to know the controller's payload format.
  const payload = (ctx.payload && typeof ctx.payload === 'object')
    ? ctx.payload
    : buildRateLimitPayload(ctx);

  if (MOCK_MODE) {
    console.warn('[omada/qos] MOCK MODE — rate limit NOT applied for ' + canonical);
    return { success: true, mock: true, clientMac: canonical, applied: payload, route: 'mock' };
  }
  if (!OMADAC_ID) throw configError('OMADA_OMADAC_ID is not configured');

  // Requirement for every privileged call: log in as the ADMINISTRATOR and
  // use THAT cookie + Csrf-Token. Forced here (not merely "if missing") so a
  // cached session that the controller has since demoted or expired cannot
  // be the one that signs the PATCH. resolveSiteKey() reuses this session.
  await ensureSession(adminSession, { force: true });

  const siteKey = await resolveSiteKey();
  // Path segments carry the hyphen-separated MAC (AA-BB-…) the controller's
  // URLs use; the BODY of a hotspot call uses colons, the path does not.
  const pathMac = canonical.replace(/:/g, '-');
  const body = JSON.stringify(payload);

  const routes = preferredRateLimitRoute
    ? [
        ...RATE_LIMIT_ROUTES.filter((r) => r.name === preferredRateLimitRoute),
        ...RATE_LIMIT_ROUTES.filter((r) => r.name !== preferredRateLimitRoute),
      ]
    : RATE_LIMIT_ROUTES;

  const failures = [];
  for (const route of routes) {
    const path = route.path(OMADAC_ID, siteKey, pathMac);

    let response;
    try {
      // PATCH — the verb the UI uses for a client-config change. Runs on the
      // administrator session established above (fresh admin cookie + token).
      response = await requestWithSession(adminSession, path, 'PATCH', body);
    } catch (err) {
      failures.push({ route: route.name, error: err });
      console.error('[omada/qos] ' + route.name + ' request failed for ' + canonical + ': ' + err.message);
      continue;
    }

    if (response.statusCode === 200 && response.body && response.body.errorCode === 0) {
      preferredRateLimitRoute = route.name;
      console.log(
        '[omada/qos] rate limit applied to ' + canonical +
        ' via ' + route.name + ' (PATCH ' + path + ')'
      );
      return { success: true, clientMac: canonical, applied: payload, route: route.name };
    }

    const rejected = rateLimitRejected(route.name, response);
    failures.push({ route: route.name, error: rejected });
    console.warn('[omada/qos] ' + route.name + ' rejected for ' + canonical + ' — ' + rejected.message);
  }

  const rejectedSomewhere = failures.some((f) => f.error.code === 'OMADA_QOS_REJECTED');
  const err = new Error(
    'Omada bandwidth cap failed for ' + canonical + ' on every local route: ' +
    failures.map((f) => f.route + ': ' + f.error.message).join(' | ')
  );
  err.code = rejectedSomewhere
    ? 'OMADA_QOS_REJECTED'
    : ((failures[0] && failures[0].error.code) || 'OMADA_QOS_FAILED');
  err.attempts = failures.map((f) => ({
    route: f.route,
    code: f.error.code,
    message: f.error.message,
  }));
  throw err;
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
  setClientRateLimit,
  resolveSiteKey,
  logResolvedConfig,
  // Exposed for testing
  _internal: {
    minutesToTime,
    operatorLogin,
    adminLogin,
    ensureSession,
    invalidateSession,
    adminSession: () => adminSession,
    portalSession: () => portalSession,
    RATE_LIMIT_ROUTES,
    DEAUTH_ROUTES,
    deauthenticateClientAsAdmin,
    listAuthedRecords,
    authedRecords,
    recordFor,
    isRecordAuthorized,
    isClientStillAuthorized,
    describeRejection,
    resetDeauthState: () => {
      preferredDeauthRoute = null;
    },
    preferredDeauthRoute: () => preferredDeauthRoute,
    siteEntries,
    rateLimitRejected,
    resetRateLimitState: () => {
      preferredRateLimitRoute = null;
      rateLimitSiteKeyCache = { name: null, key: null };
    },
    preferredRateLimitRoute: () => preferredRateLimitRoute,
    siteKeyCache: () => rateLimitSiteKeyCache,
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
