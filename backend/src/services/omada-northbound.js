/**
 * services/omada-northbound.js — TP-Link Omada Northbound (Cloud) OpenAPI client
 *
 * The CLOUD-hosted counterpart to services/omada.js. Where that module reaches
 * the controller's local hotspot web API (`/{omadacId}/api/v2/hotspot/...`,
 * operator cookie + Csrf-Token), this module talks to the region-specific
 * Omada Cloud Northbound API using **OAuth 2.0 Client Credentials**. That is
 * the right choice when the controller sits behind Carrier-Grade NAT (CGNAT)
 * and cannot be reached inbound: the backend only ever makes outbound HTTPS
 * calls to TP-Link's cloud, which proxies to the controller.
 *
 * All paths, payloads and field names below are taken from the official
 * OpenAPI document served by the region endpoint (`GET /v3/api-docs`), not
 * from blog posts:
 *
 *   1. Access token (NOT part of the OpenAPI document — see the "2.3 Client
 *      mode" section of the online API guide):
 *        POST {base}/openapi/authorize/token?grant_type=client_credentials
 *        body (JSON):  { omadacId, client_id, client_secret }
 *        → { errorCode: 0, msg, result: { accessToken, tokenType,
 *                                          expiresIn, refreshToken } }
 *      Refresh (form-encoded — a JSON body is rejected by real controllers):
 *        POST {base}/openapi/authorize/token?grant_type=refresh_token
 *        body: client_id=…&client_secret=…&refresh_token=…
 *      Every subsequent call carries:   Authorization: AccessToken=<token>
 *      (NOTE the `AccessToken=` prefix — this is NOT a Bearer token.)
 *
 *   2. Authorize a guest by MAC (OpenAPI operationId `authClient`):
 *        POST {base}/openapi/v1/{omadacId}/sites/{siteId}/hotspot/clients/{clientMac}/auth
 *      The MAC path segment must be hyphen-separated: AA-BB-CC-DD-EE-FF.
 *      This endpoint has NO request body — it authorizes the record with the
 *      site's hotspot settings. The session LENGTH is applied separately (3).
 *
 *   3. Unauthorize / "pause" a guest (`cancelAuthClient`):
 *        POST {base}/openapi/v1/{omadacId}/sites/{siteId}/hotspot/clients/{clientMac}/unauth
 *
 *   Supporting calls used to control duration and to verify state:
 *        GET    …/hotspot/authed-records?page=1&pageSize=100   (`getHotspotAuthedClients`)
 *        POST   …/hotspot/authed-records/{id}/period           (`extendHotspotAuthedClient`)
 *        POST   …/hotspot/authed-records/{id}/disconnect       (`disconnectHotspotAuthedClient`)
 *        GET    /openapi/v1/{omadacId}/sites                   (resolve a site NAME → siteId)
 *
 * Configuration (read from process.env AT CALL TIME — no credential is ever
 * baked into a module constant, so a rotated secret takes effect on the next
 * call instead of requiring a restart):
 *   OMADA_NORTHBOUND_BASE_URL   — explicit API host, e.g.
 *                                 https://use1-omada-northbound.tplinkcloud.com
 *   OMADA_NORTHBOUND_REGION     — 'us' | 'eu' | 'ap' — resolves the base URL
 *                                 above when BASE_URL is unset
 *   OMADA_CLIENT_ID             — Open API app Client ID
 *   OMADA_CLIENT_SECRET         — Open API app Client Secret
 *   OMADA_OMADAC_ID             — Omada ID (shared with services/omada.js)
 *   OMADA_SITE_ID               — numeric site ID (NOT the site name)
 *   OMADA_AUTH_TIMEOUT          — request timeout ms (default 10000)
 *   OMADA_NORTHBOUND_MOCK       — 'true' to bypass the cloud entirely
 *
 *   The historical OMADA_NORTHBOUND_CLIENT_ID / OMADA_NORTHBOUND_CLIENT_SECRET
 *   names are still accepted as fallbacks for existing deployments.
 *
 * QoS defaults consumed by setClientRateLimit() (see VOUCHER_DEFAULT_*):
 *   VOUCHER_DEFAULT_DOWN_MBPS   — download cap in Mbps (mode 0 default)
 *   VOUCHER_DEFAULT_UP_KBPS     — upload cap in Kbps (mode 0 default)
 */

'use strict';

const { normalizeMac } = require('../utils/device-id');

// ── Regional API hosts (confirmed: the three published Northbound regions) ──
const REGION_BASE_URLS = {
  us: 'https://use1-omada-northbound.tplinkcloud.com',
  eu: 'https://euw1-omada-northbound.tplinkcloud.com',
  ap: 'https://aps1-omada-northbound.tplinkcloud.com',
};

/**
 * Read a trimmed string from the environment. All configuration flows through
 * this helper so nothing sensitive is captured at module load.
 *
 * @param {string} name
 * @returns {string} '' when unset
 */
function env(name) {
  const value = process.env[name];
  return typeof value === 'string' ? value.trim() : '';
}

/**
 * Resolve the Northbound configuration from process.env.
 *
 * Credential names: OMADA_CLIENT_ID / OMADA_CLIENT_SECRET are canonical; the
 * earlier OMADA_NORTHBOUND_CLIENT_ID / OMADA_NORTHBOUND_CLIENT_SECRET names are
 * accepted as fallbacks so nothing has to be re-provisioned in the dashboard.
 *
 * `mock` mirrors the historical behaviour: an explicit OMADA_NORTHBOUND_MOCK=true
 * OR no base URL at all (nothing could be contacted anyway) bypasses the cloud.
 *
 * @returns {Object} resolved, non-secret configuration
 */
function resolveConfig() {
  const region = env('OMADA_NORTHBOUND_REGION').toLowerCase();
  const baseUrl = (env('OMADA_NORTHBOUND_BASE_URL') || REGION_BASE_URLS[region] || '')
    .replace(/\/+$/, '');
  const timeoutMs = parseInt(env('OMADA_AUTH_TIMEOUT') || '10000', 10);

  return {
    region,
    baseUrl,
    clientId: env('OMADA_CLIENT_ID') || env('OMADA_NORTHBOUND_CLIENT_ID'),
    clientSecret: env('OMADA_CLIENT_SECRET') || env('OMADA_NORTHBOUND_CLIENT_SECRET'),
    omadacId: env('OMADA_OMADAC_ID'),
    siteId: env('OMADA_SITE_ID'),
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 10000,
    mock: env('OMADA_NORTHBOUND_MOCK') === 'true' || !baseUrl,
  };
}

// Refresh the access token this long before it actually expires, so a request
// never races the expiry.
const TOKEN_EXPIRY_BUFFER_MS = 5 * 60 * 1000;

// Controller error codes that mean "the token is no longer usable" — the
// request is retried once on a fresh token.
const TOKEN_ERROR_CODES = new Set([-44112, -44113]);
// Client ID / secret rejected.
const INVALID_CREDENTIALS_CODE = -44106;

// ── Token state (in-process cache) ──────────────────────────────────────
let tokenState = { accessToken: null, refreshToken: null, expiresAt: 0 };
// Single-flight: concurrent callers share one in-flight token request instead
// of stampeding the token endpoint.
let tokenInFlight = null;

/**
 * Minutes → milliseconds for the OpenAPI `period` field (unit: ms).
 *
 * @param {number} minutes
 * @returns {number}
 */
function minutesToMs(minutes) {
  const m = Math.max(0, Math.floor(Number(minutes) || 0));
  return m * 60 * 1000;
}

/**
 * Convert any accepted MAC representation to the hyphen-separated uppercase
 * form the OpenAPI path parameter requires (`AA-BB-CC-DD-EE-FF`).
 *
 * @param {*} value
 * @returns {string|null} null when the input is not a valid MAC
 */
function toApiMac(value) {
  const canonical = normalizeMac(value); // "AA:BB:CC:DD:EE:FF"
  return canonical ? canonical.replace(/:/g, '-') : null;
}

/** Configuration error helper. */
function configError(message) {
  const err = new Error(message);
  err.code = 'OMADA_NORTHBOUND_CONFIG_ERROR';
  return err;
}

/** Mask a URL for logging — keeps scheme + host only. */
function maskHost(url) {
  if (!url) return '(unset)';
  try {
    const u = new URL(url);
    return u.protocol + '//' + u.host;
  } catch (_) {
    return '(invalid URL)';
  }
}

// Signature of the last logged configuration, so a rotated/added value is
// re-logged while an unchanged one is not repeated on every request.
let lastConfigSignature = null;

/**
 * Log the resolved (non-secret) Northbound configuration once per distinct
 * configuration and warn about the values that silently break authorization.
 *
 * @param {boolean} [force]
 */
function logResolvedConfig(force) {
  const cfg = resolveConfig();
  const signature = [cfg.mock, cfg.baseUrl, cfg.region, cfg.omadacId, cfg.siteId, cfg.clientId ? 'id' : ''].join('|');
  if (signature === lastConfigSignature && !force) return;
  lastConfigSignature = signature;

  console.log(
    '[omada-nb] resolved config: mock=' + cfg.mock +
    ' base=' + maskHost(cfg.baseUrl) +
    ' region=' + (cfg.region || '(from base url)') +
    ' omadacId=' + (cfg.omadacId || '(unset)') +
    ' siteId=' + (cfg.siteId || '(unset)') +
    ' timeout=' + cfg.timeoutMs + 'ms' +
    ' clientId=' + (cfg.clientId ? cfg.clientId.slice(0, 6) + '…' : '(unset)')
  );

  if (cfg.mock) {
    console.warn(
      '[omada-nb] MOCK MODE — no OpenAPI call will reach the cloud' +
      (cfg.baseUrl ? ' (OMADA_NORTHBOUND_MOCK=true)' : ' (no base URL configured)')
    );
    return;
  }

  const problems = [];
  if (!cfg.omadacId) problems.push('OMADA_OMADAC_ID is unset');
  if (!cfg.siteId) problems.push('OMADA_SITE_ID is unset — guest auth needs the numeric site ID, not the site name');
  if (!cfg.clientId || !cfg.clientSecret) {
    problems.push('OMADA_CLIENT_ID / OMADA_CLIENT_SECRET unset — the token request will fail with -44106');
  }
  if (problems.length) {
    console.error('[omada-nb] CONFIG PROBLEMS (' + problems.length + '):');
    problems.forEach((p) => console.error('[omada-nb]   - ' + p));
  } else {
    console.log('[omada-nb] config looks complete');
  }
}

// ================================================================
// Transport
// ================================================================

/**
 * Minimal JSON fetch with a hard timeout. Uses the global fetch (Node 18+;
 * this project requires Node >= 22), so no HTTP dependency is added.
 *
 * @param {string} url
 * @param {Object} opts  { method, headers, body }
 * @returns {Promise<{status:number, body:Object}>}
 */
async function httpJson(url, opts) {
  if (typeof fetch !== 'function') {
    throw configError('global fetch is unavailable — Node 18+ is required');
  }

  const timeoutMs = resolveConfig().timeoutMs;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res;
  try {
    res = await fetch(url, {
      method: opts.method || 'GET',
      headers: opts.headers,
      body: opts.body,
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    const timeout = err && (err.name === 'AbortError' || err.code === 'ABORT_ERR');
    const e = new Error(
      timeout
        ? 'Omada Northbound request timed out after ' + timeoutMs + 'ms'
        : 'Omada Northbound request failed: ' + ((err && err.message) || String(err))
    );
    e.code = timeout ? 'OMADA_NORTHBOUND_TIMEOUT' : 'OMADA_NORTHBOUND_NETWORK';
    e.cause = err;
    throw e;
  }
  clearTimeout(timer);

  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch (_) {
    body = { raw: text };
  }
  return { status: res.status, body };
}

// ================================================================
// Step 1 — Authentication (OAuth 2.0 Client Credentials)
// ================================================================

/**
 * Request a token pair from /openapi/authorize/token.
 *
 * @param {'client_credentials'|'refresh_token'} grantType
 * @returns {Promise<Object>} the parsed `result` object
 */
async function requestToken(grantType) {
  const cfg = resolveConfig();

  // Fail loud BEFORE the round trip: a missing credential would otherwise come
  // back as an opaque -44106 from the controller.
  if (!cfg.baseUrl) {
    throw configError('OMADA_NORTHBOUND_BASE_URL (or OMADA_NORTHBOUND_REGION) is not configured');
  }
  if (!cfg.omadacId) throw configError('OMADA_OMADAC_ID is not configured');
  if (!cfg.clientId || !cfg.clientSecret) {
    throw configError('OMADA_CLIENT_ID / OMADA_CLIENT_SECRET are not configured');
  }

  const url = cfg.baseUrl + '/openapi/authorize/token?grant_type=' + grantType;

  // client_credentials is documented with a JSON body. The refresh_token grant
  // is only accepted form-encoded — a JSON body returns errorCode -1001 on real
  // controllers.
  const isRefresh = grantType === 'refresh_token';
  const headers = isRefresh
    ? { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }
    : { 'Content-Type': 'application/json', Accept: 'application/json' };

  const body = isRefresh
    ? new URLSearchParams({
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        refresh_token: tokenState.refreshToken || '',
      }).toString()
    : JSON.stringify({
        omadacId: cfg.omadacId,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
      });

  console.log('[omada-nb] → POST ' + maskHost(cfg.baseUrl) + '/openapi/authorize/token?grant_type=' + grantType);

  const { status, body: res } = await httpJson(url, { method: 'POST', headers, body });

  if (status !== 200 || !res || res.errorCode !== 0) {
    const code = res && res.errorCode;
    const err = new Error(
      'Omada Northbound token request failed (' + grantType + '): ' +
      ((res && (res.msg || res.message)) || 'HTTP ' + status) +
      (code === INVALID_CREDENTIALS_CODE
        ? ' — the Client ID / Client Secret were rejected; recreate the Open API app if the secret was lost'
        : '')
    );
    err.code = 'OMADA_NORTHBOUND_TOKEN_FAILED';
    err.omadaResponse = res;
    throw err;
  }

  const result = res.result || {};
  if (!result.accessToken) {
    const err = new Error('Omada Northbound token response missing result.accessToken');
    err.code = 'OMADA_NORTHBOUND_TOKEN_FAILED';
    err.omadaResponse = res;
    throw err;
  }

  tokenState = {
    accessToken: result.accessToken,
    refreshToken: result.refreshToken || tokenState.refreshToken,
    // expiresIn is in SECONDS (7200 for the access token).
    expiresAt: Date.now() + (Number(result.expiresIn) || 7200) * 1000,
  };

  console.log(
    '[omada-nb] token acquired via ' + grantType +
    ' — expiresIn=' + (result.expiresIn || 7200) + 's' +
    ' refreshToken=' + (tokenState.refreshToken ? 'yes' : 'no')
  );

  return result;
}

/** Single-flight token acquisition (refresh first, then client_credentials). */
async function acquireToken(force) {
  if (!force && tokenState.refreshToken) {
    try {
      return await requestToken('refresh_token');
    } catch (err) {
      console.warn('[omada-nb] refresh_token grant failed (' + err.message + ') — falling back to client_credentials');
    }
  }
  return requestToken('client_credentials');
}

/**
 * Return a valid access token, refreshing when it is missing or close to
 * expiry. Concurrent callers share a single in-flight request.
 *
 * @param {Object} [opts]
 * @param {boolean} [opts.force] bypass the cache (used after a token error)
 * @returns {Promise<string>}
 */
async function getOmadaToken(opts) {
  const force = Boolean(opts && opts.force);

  if (!force && tokenState.accessToken && Date.now() < tokenState.expiresAt - TOKEN_EXPIRY_BUFFER_MS) {
    return tokenState.accessToken;
  }
  if (resolveConfig().mock) return 'mock-access-token';

  if (!tokenInFlight) {
    tokenInFlight = acquireToken(force).finally(() => { tokenInFlight = null; });
  }
  const result = await tokenInFlight;
  return result.accessToken;
}

/** Drop the cached token (forces a fresh grant on the next call). */
function invalidateToken() {
  tokenState = { accessToken: null, refreshToken: null, expiresAt: 0 };
}

/**
 * Authenticated OpenAPI call: attaches `Authorization: AccessToken=<token>`,
 * parses the JSON envelope and transparently re-authenticates once when the
 * controller reports an expired/invalid token (-44112 / -44113).
 *
 * @param {string} path   e.g. /openapi/v1/{omadacId}/sites/{siteId}/…
 * @param {Object} [opts] { method, query, body }
 * @returns {Promise<Object>} the parsed envelope { errorCode, msg, result }
 */
async function apiRequest(path, opts) {
  const cfg = resolveConfig();
  const o = opts || {};
  const method = o.method || 'GET';
  const query = o.query ? '?' + new URLSearchParams(o.query).toString() : '';
  const payload = o.body === undefined ? undefined : JSON.stringify(o.body);

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const token = await getOmadaToken({ force: attempt > 0 });
    const headers = { Accept: 'application/json', Authorization: 'AccessToken=' + token };
    if (payload !== undefined) headers['Content-Type'] = 'application/json';

    console.log('[omada-nb] → ' + method + ' ' + maskHost(cfg.baseUrl) + path + query);

    const { status, body } = await httpJson(cfg.baseUrl + path + query, { method, headers, body: payload });

    if (status === 200 && body && TOKEN_ERROR_CODES.has(body.errorCode) && attempt === 0) {
      console.warn('[omada-nb] controller reported token error ' + body.errorCode + ' — re-authenticating and retrying');
      invalidateToken();
      continue;
    }

    return { status, body };
  }

  // Unreachable: attempt 1 always returns.
  const err = new Error('Omada Northbound request failed after token refresh');
  err.code = 'OMADA_NORTHBOUND_TOKEN_FAILED';
  throw err;
}

/** Throw a normalized error when an OpenAPI envelope is not errorCode 0. */
function assertOk(response, action) {
  const body = response.body;
  if (response.status === 200 && body && body.errorCode === 0) return body;

  const reason = (body && (body.msg || body.message)) || ('HTTP ' + response.status);
  const err = new Error('Omada Northbound ' + action + ' rejected: ' + reason);
  err.code = 'OMADA_NORTHBOUND_REJECTED';
  err.omadaResponse = body;
  throw err;
}

// ================================================================
// Step 2 — Authorize a guest (operationId `authClient`)
// ================================================================

/**
 * Authorize a guest by MAC on a site.
 *
 * The endpoint itself takes NO body: it authorizes the client against the
 * site's hotspot configuration. Pass `durationMinutes` to also apply an
 * explicit session length — the controller exposes that as a SEPARATE call
 * (`extendHotspotAuthedClient`), so it is done here by extending the auth
 * record immediately after a successful authorization.
 *
 * @param {Object} ctx
 * @param {string} ctx.clientMac             Client MAC, any common format
 * @param {number} [ctx.durationMinutes]     Paid session length (minutes)
 * @param {string} [ctx.siteId]              Overrides OMADA_SITE_ID
 * @returns {Promise<Object>} { success, clientMac, authRecordId, periodMs }
 */
async function authorizeGuest(ctx) {
  logResolvedConfig();

  const mac = toApiMac(ctx && ctx.clientMac);
  if (!mac) {
    const err = new Error('authorizeGuest: missing or invalid clientMac');
    err.code = 'OMADA_NORTHBOUND_INVALID_MAC';
    throw err;
  }

  const cfg = resolveConfig();

  if (cfg.mock) {
    return { success: true, clientMac: mac, authRecordId: 'mock-record', periodMs: minutesToMs(ctx.durationMinutes) };
  }

  const siteId = (ctx && ctx.siteId) || cfg.siteId;
  if (!cfg.omadacId) throw configError('OMADA_OMADAC_ID is not configured');
  if (!siteId) throw configError('OMADA_SITE_ID is not configured (the numeric site ID, not the site name)');

  const path = '/openapi/v1/' + encodeURIComponent(cfg.omadacId) +
    '/sites/' + encodeURIComponent(siteId) +
    '/hotspot/clients/' + encodeURIComponent(mac) + '/auth';

  const body = assertOk(await apiRequest(path, { method: 'POST' }), 'authClient (authorize ' + mac + ')');
  console.log('[omada-nb] authorized ' + mac + ' on site ' + siteId);

  // Optional session length. The auth call itself carries no duration, so the
  // freshly-created record is looked up and its period set explicitly.
  let authRecordId = null;
  let periodMs = null;
  if (Number(ctx.durationMinutes) > 0) {
    periodMs = minutesToMs(ctx.durationMinutes);
    try {
      const record = await findAuthRecordByMac(mac, siteId);
      if (record && record.id) {
        authRecordId = record.id;
        await extendClientPeriod({ recordId: record.id, periodMs, siteId });
        console.log('[omada-nb] set session period for ' + mac + ' to ' + periodMs + 'ms (record ' + record.id + ')');
      } else {
        console.warn(
          '[omada-nb] could not find the auth record for ' + mac +
          ' — the controller default period applies; verify the site default hotspot duration'
        );
      }
    } catch (err) {
      // Authorization already succeeded, so a failed extension must not be
      // reported as an auth failure — surface it for the caller to retry.
      console.error('[omada-nb] authorization succeeded but extending the period failed for ' + mac + ': ' + err.message);
      periodMs = null;
    }
  }

  return { success: true, clientMac: mac, authRecordId, periodMs, raw: body };
}

// ================================================================
// Step 3 — Unauthorize / pause a guest (operationId `cancelAuthClient`)
// ================================================================

/**
 * Terminate a guest session. Use this to implement "Pause": the client is cut
 * off from the network and its auth record stops accruing time.
 *
 * @param {Object} ctx
 * @param {string} ctx.clientMac
 * @param {string} [ctx.siteId]
 * @returns {Promise<Object>} { success, clientMac }
 */
async function pauseGuest(ctx) {
  logResolvedConfig();

  const mac = toApiMac(ctx && ctx.clientMac);
  if (!mac) {
    const err = new Error('pauseGuest: missing or invalid clientMac');
    err.code = 'OMADA_NORTHBOUND_INVALID_MAC';
    throw err;
  }

  const cfg = resolveConfig();

  if (cfg.mock) return { success: true, clientMac: mac };

  const siteId = (ctx && ctx.siteId) || cfg.siteId;
  if (!cfg.omadacId) throw configError('OMADA_OMADAC_ID is not configured');
  if (!siteId) throw configError('OMADA_SITE_ID is not configured');

  const path = '/openapi/v1/' + encodeURIComponent(cfg.omadacId) +
    '/sites/' + encodeURIComponent(siteId) +
    '/hotspot/clients/' + encodeURIComponent(mac) + '/unauth';

  assertOk(await apiRequest(path, { method: 'POST' }), 'cancelAuthClient (unauthorize ' + mac + ')');
  console.log('[omada-nb] unauthorized ' + mac + ' on site ' + siteId);

  return { success: true, clientMac: mac };
}

// ================================================================
// Supporting calls
// ================================================================

/**
 * List the site's authentication records (authorized + expired).
 *
 * @param {Object} [opts] { page=1, pageSize=100, siteId }
 * @returns {Promise<Array<Object>>} records with id, mac, ip, authType,
 *          start, end, valid, download, upload, …
 */
async function getAuthedRecords(opts) {
  const cfg = resolveConfig();
  const o = opts || {};
  const siteId = o.siteId || cfg.siteId;
  if (!cfg.omadacId) throw configError('OMADA_OMADAC_ID is not configured');
  if (!siteId) throw configError('OMADA_SITE_ID is not configured');

  const path = '/openapi/v1/' + encodeURIComponent(cfg.omadacId) +
    '/sites/' + encodeURIComponent(siteId) + '/hotspot/authed-records';

  const body = assertOk(
    await apiRequest(path, {
      method: 'GET',
      query: { page: o.page || 1, pageSize: o.pageSize || 100 },
    }),
    'getHotspotAuthedClients'
  );

  return (body.result && body.result.data) || [];
}

/**
 * Find the authentication record for a MAC (case-insensitive, any MAC format).
 *
 * @param {string} clientMac
 * @param {string} [siteId]
 * @returns {Promise<Object|null>}
 */
async function findAuthRecordByMac(clientMac, siteId) {
  const wanted = toApiMac(clientMac);
  if (!wanted) return null;
  const records = await getAuthedRecords({ siteId, page: 1, pageSize: 200 });
  return records.find((r) => toApiMac(r.mac) === wanted) || null;
}

/**
 * Extend an authentication record's valid period (operationId
 * `extendHotspotAuthedClient`). `period` is milliseconds and must be within
 * 60000 … 86400000000000.
 *
 * @param {Object} ctx
 * @param {string} ctx.recordId
 * @param {number} ctx.periodMs
 * @param {string} [ctx.siteId]
 * @returns {Promise<Object>} { success, recordId, periodMs }
 */
async function extendClientPeriod(ctx) {
  const cfg = resolveConfig();
  const siteId = (ctx && ctx.siteId) || cfg.siteId;
  if (!cfg.omadacId) throw configError('OMADA_OMADAC_ID is not configured');
  if (!siteId) throw configError('OMADA_SITE_ID is not configured');
  if (!ctx || !ctx.recordId) {
    const err = new Error('extendClientPeriod: missing recordId');
    err.code = 'OMADA_NORTHBOUND_MISSING_FIELD';
    throw err;
  }

  const periodMs = Math.floor(Number(ctx.periodMs));
  if (!Number.isFinite(periodMs) || periodMs < 60000 || periodMs > 86400000000000) {
    const err = new Error('extendClientPeriod: periodMs must be between 60000 and 86400000000000');
    err.code = 'OMADA_NORTHBOUND_INVALID_PERIOD';
    throw err;
  }

  if (cfg.mock) return { success: true, recordId: ctx.recordId, periodMs };

  const path = '/openapi/v1/' + encodeURIComponent(cfg.omadacId) +
    '/sites/' + encodeURIComponent(siteId) +
    '/hotspot/authed-records/' + encodeURIComponent(ctx.recordId) + '/period';

  assertOk(await apiRequest(path, { method: 'POST', body: { period: periodMs } }), 'extendHotspotAuthedClient');

  return { success: true, recordId: ctx.recordId, periodMs };
}

/**
 * Resolve the default bandwidth caps from the environment.
 *
 * VOUCHER_DEFAULT_DOWN_MBPS is a Mbps value (OpenAPI `downUnit` 2) and
 * VOUCHER_DEFAULT_UP_KBPS a Kbps value (`upUnit` 1) — the units the portal
 * advertises to customers. Both go through parseInt(..., 10) so a quoted or
 * suffixed value can never reach the JSON payload as a string, and both are
 * range-checked against the 1–1024 ceiling the OpenAPI documents.
 *
 * @returns {Object} a customRateLimit payload fragment
 */
function defaultRateLimit() {
  const downMbps = parseInt(env('VOUCHER_DEFAULT_DOWN_MBPS'), 10);
  const upKbps = parseInt(env('VOUCHER_DEFAULT_UP_KBPS'), 10);

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
 * Apply a bandwidth (QoS) limit to a client (operationId
 * `updateClientRateLimitSetting`).
 *
 * The guest-auth call itself carries no QoS fields — bandwidth is set on the
 * client by this SEPARATE call, either from a named profile (mode 1) or as
 * explicit upload/download values (mode 0).
 *
 * @param {Object} ctx
 * @param {string} ctx.clientMac
 * @param {string} [ctx.siteId]
 * @param {0|1} [ctx.mode=0]  0 = custom values, 1 = named profile
 * @param {string} [ctx.rateLimitProfileId]  required when mode is 1
 * @param {Object} [ctx.customRateLimit]     mode-0 values. When omitted, the
 *                                           VOUCHER_DEFAULT_UP_KBPS /
 *                                           VOUCHER_DEFAULT_DOWN_MBPS defaults
 *                                           are applied instead.
 * @param {boolean} ctx.customRateLimit.upEnable
 * @param {1|2}     ctx.customRateLimit.upUnit    1 = Kbps, 2 = Mbps
 * @param {number}  ctx.customRateLimit.upLimit   1–1024
 * @param {boolean} ctx.customRateLimit.downEnable
 * @param {1|2}     ctx.customRateLimit.downUnit
 * @param {number}  ctx.customRateLimit.downLimit 1–1024
 * @returns {Promise<Object>} { success, clientMac, applied }
 */
async function setClientRateLimit(ctx) {
  const mac = toApiMac(ctx && ctx.clientMac);
  if (!mac) {
    const err = new Error('setClientRateLimit: missing or invalid clientMac');
    err.code = 'OMADA_NORTHBOUND_INVALID_MAC';
    throw err;
  }
  const cfg = resolveConfig();
  const siteId = (ctx && ctx.siteId) || cfg.siteId;
  if (!cfg.omadacId) throw configError('OMADA_OMADAC_ID is not configured');
  if (!siteId) throw configError('OMADA_SITE_ID is not configured');

  const mode = Number(ctx.mode) === 1 ? 1 : 0;
  const body = { mode };

  if (mode === 1) {
    if (!ctx.rateLimitProfileId) {
      const err = new Error('setClientRateLimit: rateLimitProfileId is required when mode is 1');
      err.code = 'OMADA_NORTHBOUND_MISSING_FIELD';
      throw err;
    }
    body.rateLimitProfileId = ctx.rateLimitProfileId;
  } else {
    // No explicit limits supplied → fall back to the operator-configured
    // voucher defaults (already parsed to integers by defaultRateLimit()).
    const c = ctx.customRateLimit || defaultRateLimit();
    for (const field of ['upLimit', 'downLimit']) {
      const n = Number(c[field]);
      if (!Number.isInteger(n) || n < 1 || n > 1024) {
        const err = new Error('setClientRateLimit: ' + field + ' must be an integer between 1 and 1024');
        err.code = 'OMADA_NORTHBOUND_INVALID_LIMIT';
        throw err;
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
  }

  if (cfg.mock) return { success: true, clientMac: mac, applied: body };

  const path = '/openapi/v1/' + encodeURIComponent(cfg.omadacId) +
    '/sites/' + encodeURIComponent(siteId) +
    '/clients/' + encodeURIComponent(mac) + '/ratelimit';

  assertOk(await apiRequest(path, { method: 'PATCH', body }), 'updateClientRateLimitSetting');
  console.log('[omada-nb] applied rate limit (mode ' + mode + ') to ' + mac);

  return { success: true, clientMac: mac, applied: body };
}

/**
 * Resolve the site list — used once during setup to obtain the numeric siteId.
 *
 * @returns {Promise<Array<{siteId:string,name:string}>>}
 */
async function listSites() {
  const cfg = resolveConfig();
  if (!cfg.omadacId) throw configError('OMADA_OMADAC_ID is not configured');
  if (cfg.mock) return [{ siteId: 'mock-site', name: 'Default' }];

  const body = assertOk(
    await apiRequest('/openapi/v1/' + encodeURIComponent(cfg.omadacId) + '/sites', { method: 'GET' }),
    'listSites'
  );
  return (body.result && body.result.data) || [];
}

// Earlier names, kept so any existing caller keeps working. New code should use
// getOmadaToken / authorizeGuest / pauseGuest.
const getAccessToken = getOmadaToken;
const authorizeClient = authorizeGuest;
const unauthorizeClient = pauseGuest;

module.exports = {
  // Steps
  getOmadaToken,
  authorizeGuest,
  pauseGuest,
  // Back-compat aliases
  getAccessToken,
  authorizeClient,
  unauthorizeClient,
  // Supporting calls
  extendClientPeriod,
  setClientRateLimit,
  getAuthedRecords,
  findAuthRecordByMac,
  listSites,
  logResolvedConfig,
  // Exposed for testing
  _internal: {
    REGION_BASE_URLS,
    TOKEN_EXPIRY_BUFFER_MS,
    TOKEN_ERROR_CODES,
    minutesToMs,
    toApiMac,
    maskHost,
    env,
    resolveConfig,
    defaultRateLimit,
    invalidateToken,
    requestToken,
    apiRequest,
    assertOk,
    tokenState: () => tokenState,
    setTokenState: (next) => { tokenState = next; },
  },
};
