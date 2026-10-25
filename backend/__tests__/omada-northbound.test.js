/**
 * __tests__/omada-northbound.test.js — unit tests for
 * services/omada-northbound.js
 *
 * No request leaves the process: node:https.request is stubbed, so these tests
 * assert the exact request contract the Northbound OpenAPI requires —
 * the token URL/grant/body, the `Authorization: AccessToken=` header, the
 * hyphen-separated MAC path segment, and the empty body of the auth/unauth
 * calls — plus the base-URL/TLS rules for a LAN controller.
 *
 * Covers:
 *   - MAC formatting (AA:BB:CC:DD:EE:FF → AA-BB-CC-DD-EE-FF) and validation
 *   - client_credentials token request: URL, JSON body, token caching
 *   - refresh_token grant: form-encoded body
 *   - automatic re-auth + single retry on errorCode -44112
 *   - authorizeClient: path, POST, no body
 *   - authorizeClient + durationMinutes: auth → records lookup → period
 *   - unauthorizeClient: path, POST, no body
 *   - extendClientPeriod: payload + range validation
 *   - fail-loud validation before any HTTP call
 */

'use strict';

process.env.OMADA_NORTHBOUND_BASE_URL = 'https://use1-omada-northbound.tplinkcloud.com';
// Canonical credential names (OMADA_NORTHBOUND_CLIENT_* are only fallbacks).
process.env.OMADA_CLIENT_ID = 'test-client-id';
process.env.OMADA_CLIENT_SECRET = 'test-client-secret';
delete process.env.OMADA_NORTHBOUND_CLIENT_ID;
delete process.env.OMADA_NORTHBOUND_CLIENT_SECRET;
process.env.OMADA_OMADAC_ID = 'TESTOMADAC123';
// The Northbound client resolves the site by NAME (OMADA_SITE) to its numeric
// ID via GET /sites; OMADA_SITE_ID is no longer read.
process.env.OMADA_SITE = 'Default';
delete process.env.OMADA_SITE_ID;
// Voucher QoS defaults (Mbps down / Kbps up).
process.env.VOUCHER_DEFAULT_DOWN_MBPS = '10';
process.env.VOUCHER_DEFAULT_UP_KBPS = '512';
delete process.env.OMADA_NORTHBOUND_MOCK;

const https = require('https');
const { EventEmitter } = require('events');

const nb = require('../src/services/omada-northbound');
const { _internal } = nb;

// Shared fixtures.
const SITE_ID = '6918c72f0abcdef123456789';
const TOKEN_RESPONSE = { errorCode: 0, result: { accessToken: 'tok-1', expiresIn: 7200 } };
const SITES_RESPONSE = { errorCode: 0, result: { data: [{ siteId: SITE_ID, name: 'Default' }] } };

// ── https.request stub ──────────────────────────────────────
// services/omada-northbound.js requests through node:https (not fetch) so it
// can relax certificate verification for a self-signed LAN controller.
const realHttpsRequest = https.request;
let calls = [];
let queue = [];

/** Queue one response for the next HTTP call. */
function queueJson(status, body) {
  queue.push({ status, body });
}

function installTransport() {
  calls = [];
  queue = [];
  https.request = jest.fn((url, opts, callback) => {
    const options = opts || {};
    const entry = {
      url,
      method: options.method || 'GET',
      headers: options.headers || {},
      body: undefined,
      tlsVerify: options.rejectUnauthorized,
    };
    calls.push(entry);

    const req = new EventEmitter();
    // Capture the payload exactly as the module passed it (undefined = none).
    req.write = (chunk) => { entry.body = chunk; };
    req.end = () => {
      const next = queue.shift() || { status: 200, body: { errorCode: 0 } };
      const res = new EventEmitter();
      res.statusCode = next.status;
      res.headers = {};
      res.setEncoding = () => {};
      setImmediate(() => {
        callback(res);
        res.emit('data', JSON.stringify(next.body));
        res.emit('end');
      });
    };
    req.destroy = () => {};
    return req;
  });
}

beforeEach(() => {
  installTransport();
  _internal.invalidateToken();
  _internal.resetSiteId();
});

afterAll(() => {
  https.request = realHttpsRequest;
});

// ================================================================
// MAC handling
// ================================================================
describe('toApiMac', () => {
  test('converts every common MAC format to AA-BB-CC-DD-EE-FF', () => {
    expect(_internal.toApiMac('aa:bb:cc:dd:ee:ff')).toBe('AA-BB-CC-DD-EE-FF');
    expect(_internal.toApiMac('AA-BB-CC-DD-EE-FF')).toBe('AA-BB-CC-DD-EE-FF');
    expect(_internal.toApiMac('aabbccddeeff')).toBe('AA-BB-CC-DD-EE-FF');
    expect(_internal.toApiMac('AABB.CCDD.EEFF')).toBe('AA-BB-CC-DD-EE-FF');
  });

  test('returns null for invalid input', () => {
    expect(_internal.toApiMac('')).toBeNull();
    expect(_internal.toApiMac('not-a-mac')).toBeNull();
    expect(_internal.toApiMac(null)).toBeNull();
  });
});

describe('minutesToMs', () => {
  test('scales minutes to milliseconds', () => {
    expect(_internal.minutesToMs(1)).toBe(60000);
    expect(_internal.minutesToMs(60)).toBe(3600000);
  });

  test('clamps invalid input to 0', () => {
    expect(_internal.minutesToMs(undefined)).toBe(0);
    expect(_internal.minutesToMs(-5)).toBe(0);
  });
});

// ================================================================
// Step 1 — token
// ================================================================
describe('getAccessToken (client credentials)', () => {
  test('POSTs the documented URL, grant_type and JSON body', async () => {
    queueJson(200, {
      errorCode: 0,
      msg: 'success',
      result: { accessToken: 'tok-1', tokenType: 'access_token', expiresIn: 7200, refreshToken: 'ref-1' },
    });

    const token = await nb.getAccessToken();
    expect(token).toBe('tok-1');

    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe('POST');
    expect(calls[0].url).toBe(
      'https://use1-omada-northbound.tplinkcloud.com/openapi/authorize/token?grant_type=client_credentials'
    );
    expect(calls[0].headers['Content-Type']).toBe('application/json');
    expect(JSON.parse(calls[0].body)).toEqual({
      omadacId: 'TESTOMADAC123',
      client_id: 'test-client-id',
      client_secret: 'test-client-secret',
    });
  });

  test('caches the token — a second call does not re-request', async () => {
    queueJson(200, { errorCode: 0, result: { accessToken: 'tok-1', expiresIn: 7200, refreshToken: 'ref-1' } });
    await nb.getAccessToken();
    await nb.getAccessToken();
    expect(calls).toHaveLength(1);
  });

  test('uses the form-encoded refresh_token grant when a refresh token exists', async () => {
    _internal.setTokenState({ accessToken: 'old', refreshToken: 'ref-1', expiresAt: Date.now() - 1000 });
    queueJson(200, { errorCode: 0, result: { accessToken: 'tok-2', expiresIn: 7200, refreshToken: 'ref-2' } });

    const token = await nb.getAccessToken();
    expect(token).toBe('tok-2');
    expect(calls[0].url).toContain('grant_type=refresh_token');
    expect(calls[0].headers['Content-Type']).toBe('application/x-www-form-urlencoded');
    expect(calls[0].body).toContain('client_id=test-client-id');
    expect(calls[0].body).toContain('refresh_token=ref-1');
  });

  test('surfaces invalid credentials (-44106) with a clear error', async () => {
    queueJson(200, { errorCode: -44106, msg: 'The Client Id or Client Secret is invalid' });
    await expect(nb.getAccessToken()).rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_TOKEN_FAILED' });
  });
});

describe('apiRequest auth handling', () => {
  test('sends Authorization: AccessToken=<token>', async () => {
    queueJson(200, { errorCode: 0, result: { accessToken: 'tok-1', expiresIn: 7200 } });
    queueJson(200, { errorCode: 0, result: {} });

    await nb.listSites();

    expect(calls).toHaveLength(2);
    expect(calls[1].headers.Authorization).toBe('AccessToken=tok-1');
    expect(calls[1].url).toBe(
      'https://use1-omada-northbound.tplinkcloud.com/openapi/v1/TESTOMADAC123/sites'
    );
  });

  test('re-authenticates and retries once on errorCode -44112', async () => {
    _internal.setTokenState({ accessToken: 'stale', refreshToken: null, expiresAt: Date.now() + 3600000 });
    queueJson(200, { errorCode: -44112, msg: 'token expired' });          // first attempt
    queueJson(200, { errorCode: 0, result: { accessToken: 'fresh', expiresIn: 7200 } }); // re-auth
    queueJson(200, { errorCode: 0, result: { data: [] } });               // retry

    const sites = await nb.listSites();
    expect(sites).toEqual([]);
    expect(calls).toHaveLength(3);
    expect(calls[1].url).toContain('grant_type=client_credentials');
    expect(calls[2].headers.Authorization).toBe('AccessToken=fresh');
  });
});

// ================================================================
// Step 2 — authorize
// ================================================================
describe('authorizeClient (authClient)', () => {
  test('POSTs to the hyphenated-MAC auth path with no request body', async () => {
    queueJson(200, TOKEN_RESPONSE);                       // token
    queueJson(200, SITES_RESPONSE);                       // GET /sites (OMADA_SITE lookup)
    queueJson(200, { errorCode: 0, msg: 'success' });      // auth

    const result = await nb.authorizeClient({ clientMac: 'aa:bb:cc:dd:ee:ff' });

    expect(result.success).toBe(true);
    expect(calls[1].url).toContain('/sites');              // resolved before the auth call
    expect(calls[2].method).toBe('POST');
    expect(calls[2].url).toBe(
      'https://use1-omada-northbound.tplinkcloud.com/openapi/v1/TESTOMADAC123' +
      '/sites/6918c72f0abcdef123456789/hotspot/clients/AA-BB-CC-DD-EE-FF/auth'
    );
    expect(calls[2].body).toBeUndefined();
    expect(calls[2].headers['Content-Type']).toBeUndefined();
  });

  test('with durationMinutes: authorizes, finds the record, then sets the period', async () => {
    queueJson(200, TOKEN_RESPONSE);                       // token
    queueJson(200, SITES_RESPONSE);                       // GET /sites (OMADA_SITE lookup)
    queueJson(200, { errorCode: 0, msg: 'success' });      // auth
    queueJson(200, { errorCode: 0, result: { data: [{ id: 'rec-1', mac: 'AA-BB-CC-DD-EE-FF' }] } }); // records
    queueJson(200, { errorCode: 0, msg: 'success' });      // period

    const result = await nb.authorizeClient({ clientMac: 'AA-BB-CC-DD-EE-FF', durationMinutes: 30 });

    expect(result.authRecordId).toBe('rec-1');
    expect(result.periodMs).toBe(30 * 60 * 1000);

    const periodCall = calls[4];
    expect(periodCall.method).toBe('POST');
    expect(periodCall.url).toBe(
      'https://use1-omada-northbound.tplinkcloud.com/openapi/v1/TESTOMADAC123' +
      '/sites/6918c72f0abcdef123456789/hotspot/authed-records/rec-1/period'
    );
    expect(JSON.parse(periodCall.body)).toEqual({ period: 1800000 });
  });

  test('rejects an invalid MAC before any HTTP call', async () => {
    await expect(nb.authorizeClient({ clientMac: 'nope' }))
      .rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_INVALID_MAC' });
    expect(calls).toHaveLength(0);
  });

  test('throws a normalized error when the controller rejects the authorization', async () => {
    queueJson(200, TOKEN_RESPONSE);
    queueJson(200, SITES_RESPONSE);
    queueJson(200, { errorCode: -1, msg: 'client not found' });

    await expect(nb.authorizeClient({ clientMac: 'AA:BB:CC:DD:EE:FF' }))
      .rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_REJECTED' });
  });
});

// ================================================================
// Step 3 — unauthorize / pause
// ================================================================
describe('unauthorizeClient (cancelAuthClient)', () => {
  test('POSTs to the unauth path with no request body', async () => {
    queueJson(200, TOKEN_RESPONSE);
    queueJson(200, SITES_RESPONSE);
    queueJson(200, { errorCode: 0, msg: 'success' });

    const result = await nb.unauthorizeClient({ clientMac: 'aa:bb:cc:dd:ee:ff' });

    expect(result).toEqual({ success: true, clientMac: 'AA-BB-CC-DD-EE-FF' });
    expect(calls[2].method).toBe('POST');
    expect(calls[2].url).toBe(
      'https://use1-omada-northbound.tplinkcloud.com/openapi/v1/TESTOMADAC123' +
      '/sites/6918c72f0abcdef123456789/hotspot/clients/AA-BB-CC-DD-EE-FF/unauth'
    );
    expect(calls[2].body).toBeUndefined();
  });
});

// ================================================================
// Supporting calls
// ================================================================
describe('getAuthedRecords / findAuthRecordByMac', () => {
  test('requests the paginated authed-records endpoint and matches MACs loosely', async () => {
    queueJson(200, TOKEN_RESPONSE);
    queueJson(200, SITES_RESPONSE);
    queueJson(200, {
      errorCode: 0,
      result: { totalRows: 1, currentPage: 1, currentSize: 200, data: [{ id: 'rec-9', mac: 'AA-BB-CC-DD-EE-FF', valid: true }] },
    });

    const record = await nb.findAuthRecordByMac('aabbccddeeff');

    expect(record.id).toBe('rec-9');
    expect(calls[2].url).toContain('/hotspot/authed-records?page=1&pageSize=200');
  });
});

describe('getOmadaToken / authorizeGuest / pauseGuest (canonical names)', () => {
  test('exports the requested names and keeps the earlier ones as aliases', () => {
    expect(typeof nb.getOmadaToken).toBe('function');
    expect(typeof nb.authorizeGuest).toBe('function');
    expect(typeof nb.pauseGuest).toBe('function');

    expect(nb.getAccessToken).toBe(nb.getOmadaToken);
    expect(nb.authorizeClient).toBe(nb.authorizeGuest);
    expect(nb.unauthorizeClient).toBe(nb.pauseGuest);
  });

  test('reads the credentials from process.env at call time (no restart needed)', async () => {
    const original = process.env.OMADA_CLIENT_ID;
    try {
      process.env.OMADA_CLIENT_ID = 'rotated-client-id';
      queueJson(200, { errorCode: 0, result: { accessToken: 'tok-rot', expiresIn: 7200 } });

      await nb.getOmadaToken();

      expect(JSON.parse(calls[0].body).client_id).toBe('rotated-client-id');
    } finally {
      process.env.OMADA_CLIENT_ID = original;
    }
  });

  test('falls back to the OMADA_NORTHBOUND_CLIENT_* names when the canonical ones are unset', async () => {
    const id = process.env.OMADA_CLIENT_ID;
    const secret = process.env.OMADA_CLIENT_SECRET;
    delete process.env.OMADA_CLIENT_ID;
    try {
      process.env.OMADA_NORTHBOUND_CLIENT_ID = 'legacy-client-id';
      queueJson(200, { errorCode: 0, result: { accessToken: 'tok-legacy', expiresIn: 7200 } });

      await nb.getOmadaToken();

      expect(JSON.parse(calls[0].body).client_id).toBe('legacy-client-id');
    } finally {
      delete process.env.OMADA_NORTHBOUND_CLIENT_ID;
      process.env.OMADA_CLIENT_ID = id;
      process.env.OMADA_CLIENT_SECRET = secret;
    }
  });

  test('fails loud before any HTTP call when a credential is missing', async () => {
    const id = process.env.OMADA_CLIENT_ID;
    delete process.env.OMADA_CLIENT_ID;
    try {
      await expect(nb.getOmadaToken())
        .rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_CONFIG_ERROR' });
      expect(calls).toHaveLength(0);
    } finally {
      process.env.OMADA_CLIENT_ID = id;
    }
  });
});

describe('setClientRateLimit (updateClientRateLimitSetting)', () => {
  test('applies the VOUCHER_DEFAULT_* caps as NUMBERS when no limits are passed', async () => {
    queueJson(200, TOKEN_RESPONSE);
    queueJson(200, SITES_RESPONSE);
    queueJson(200, { errorCode: 0, msg: 'success' });

    await nb.setClientRateLimit({ clientMac: 'aa:bb:cc:dd:ee:ff' });

    expect(calls[2].method).toBe('PATCH');
    const payload = JSON.parse(calls[2].body);
    expect(payload).toEqual({
      mode: 0,
      customRateLimit: {
        upEnable: true,
        upUnit: 1,        // Kbps
        upLimit: 512,     // VOUCHER_DEFAULT_UP_KBPS
        downEnable: true,
        downUnit: 2,      // Mbps
        downLimit: 10,    // VOUCHER_DEFAULT_DOWN_MBPS
      },
    });
    // parseInt(..., 10) — never strings, which the controller rejects.
    expect(typeof payload.customRateLimit.upLimit).toBe('number');
    expect(typeof payload.customRateLimit.downLimit).toBe('number');
  });

  test('rejects out-of-range/default-less VOUCHER_DEFAULT_* values before any HTTP call', async () => {
    const down = process.env.VOUCHER_DEFAULT_DOWN_MBPS;
    const up = process.env.VOUCHER_DEFAULT_UP_KBPS;
    try {
      process.env.VOUCHER_DEFAULT_DOWN_MBPS = 'fast';
      await expect(nb.setClientRateLimit({ clientMac: 'AA:BB:CC:DD:EE:FF' }))
        .rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_CONFIG_ERROR' });

      process.env.VOUCHER_DEFAULT_DOWN_MBPS = '10';
      process.env.VOUCHER_DEFAULT_UP_KBPS = '99999';
      await expect(nb.setClientRateLimit({ clientMac: 'AA:BB:CC:DD:EE:FF' }))
        .rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_CONFIG_ERROR' });

      expect(calls).toHaveLength(0);
    } finally {
      process.env.VOUCHER_DEFAULT_DOWN_MBPS = down;
      process.env.VOUCHER_DEFAULT_UP_KBPS = up;
    }
  });

  test('PATCHes the client ratelimit path with a custom-limit body', async () => {
    queueJson(200, TOKEN_RESPONSE);
    queueJson(200, SITES_RESPONSE);
    queueJson(200, { errorCode: 0, msg: 'success' });

    await nb.setClientRateLimit({
      clientMac: 'aa:bb:cc:dd:ee:ff',
      customRateLimit: { upEnable: true, upUnit: 1, upLimit: 512, downEnable: true, downUnit: 2, downLimit: 10 },
    });

    expect(calls[2].method).toBe('PATCH');
    expect(calls[2].url).toBe(
      'https://use1-omada-northbound.tplinkcloud.com/openapi/v1/TESTOMADAC123' +
      '/sites/6918c72f0abcdef123456789/clients/AA-BB-CC-DD-EE-FF/ratelimit'
    );
    expect(JSON.parse(calls[2].body)).toEqual({
      mode: 0,
      customRateLimit: { upEnable: true, upUnit: 1, upLimit: 512, downEnable: true, downUnit: 2, downLimit: 10 },
    });
  });

  test('supports profile mode and requires the profile id', async () => {
    await expect(nb.setClientRateLimit({ clientMac: 'AA-BB-CC-DD-EE-FF', mode: 1 }))
      .rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_MISSING_FIELD' });
  });

  test('rejects out-of-range custom limits before any HTTP call', async () => {
    await expect(nb.setClientRateLimit({
      clientMac: 'AA-BB-CC-DD-EE-FF',
      customRateLimit: { upEnable: true, upLimit: 5000, downEnable: true, downLimit: 10 },
    })).rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_INVALID_LIMIT' });
    expect(calls).toHaveLength(0);
  });
});

// ================================================================
// QoS routing — web API first, Open API as the fallback
// ================================================================
describe('QoS transport routing (OMADA_QOS_METHOD)', () => {
  const omadaLocal = require('../src/services/omada');
  let localSpy;

  beforeEach(() => {
    // A local controller is configured WITH an administrator account, so
    // 'auto' may use the web-API route (it needs site/QoS rights).
    process.env.OMADA_BASE_URL = 'https://192.168.0.253:8043';
    process.env.OMADA_MOCK = 'false';
    process.env.OMADA_ADMIN_NAME = 'controller-admin';
    process.env.OMADA_ADMIN_PASSWORD = 'admin-secret';
    delete process.env.OMADA_QOS_METHOD;
    _internal.resetLocalQosBlock();
    localSpy = jest.spyOn(omadaLocal, 'setClientRateLimit');
  });

  afterEach(() => {
    localSpy.mockRestore();
    delete process.env.OMADA_QOS_METHOD;
    delete process.env.OMADA_BASE_URL;
    delete process.env.OMADA_MOCK;
    delete process.env.OMADA_ADMIN_NAME;
    delete process.env.OMADA_ADMIN_PASSWORD;
    _internal.resetLocalQosBlock();
  });

  test('auto applies the cap through the web API without any Open API call', async () => {
    localSpy.mockResolvedValue({ success: true, clientMac: 'AA-BB-CC-DD-EE-FF', applied: {}, route: 'v2' });

    const result = await nb.setClientRateLimit({ clientMac: 'aa:bb:cc:dd:ee:ff' });

    expect(result.method).toBe('local');
    expect(result.route).toBe('v2');
    expect(localSpy).toHaveBeenCalledTimes(1);
    // The payload handed to the web API is the same documented shape.
    expect(localSpy.mock.calls[0][0]).toEqual({
      clientMac: 'AA-BB-CC-DD-EE-FF',
      payload: {
        mode: 0,
        customRateLimit: {
          upEnable: true, upUnit: 1, upLimit: 512,
          downEnable: true, downUnit: 2, downLimit: 10,
        },
      },
    });
    expect(calls).toHaveLength(0); // no token request, no PATCH through Open API
  });

  test('auto falls back to the Open API when the controller rejects the web-API route', async () => {
    const rejected = Object.assign(new Error('Omada rate limit (v2) rejected: no permission'), {
      code: 'OMADA_QOS_REJECTED',
    });
    localSpy.mockRejectedValue(rejected);

    queueJson(200, TOKEN_RESPONSE);
    queueJson(200, SITES_RESPONSE);
    queueJson(200, { errorCode: 0, msg: 'success' }); // PATCH ratelimit

    const result = await nb.setClientRateLimit({ clientMac: 'AA-BB-CC-DD-EE-FF' });

    expect(result.method).toBe('openapi');
    expect(calls.some((c) => c.url.endsWith('/clients/AA-BB-CC-DD-EE-FF/ratelimit'))).toBe(true);
    // The unusable local route is parked so later logins skip it.
    expect(_internal.localQosBlockedUntil()).toBeGreaterThan(Date.now());
  });

  test('a parked local route is skipped until the backoff expires', async () => {
    localSpy.mockRejectedValue(Object.assign(new Error('no permission'), { code: 'OMADA_QOS_REJECTED' }));
    queueJson(200, TOKEN_RESPONSE);
    queueJson(200, SITES_RESPONSE);
    queueJson(200, { errorCode: 0 });
    await nb.setClientRateLimit({ clientMac: 'AA-BB-CC-DD-EE-FF' });
    expect(localSpy).toHaveBeenCalledTimes(1);

    localSpy.mockClear();
    queueJson(200, { errorCode: 0 }); // PATCH, token + site are cached
    const second = await nb.setClientRateLimit({ clientMac: 'AA-BB-CC-DD-EE-FF' });

    expect(second.method).toBe('openapi');
    expect(localSpy).not.toHaveBeenCalled();
  });

  test('OMADA_QOS_METHOD=local never touches the Open API', async () => {
    process.env.OMADA_QOS_METHOD = 'local';
    localSpy.mockRejectedValue(Object.assign(new Error('nope'), { code: 'OMADA_QOS_REJECTED' }));

    await expect(nb.setClientRateLimit({ clientMac: 'AA-BB-CC-DD-EE-FF' }))
      .rejects.toMatchObject({ code: 'OMADA_QOS_REJECTED' });

    expect(calls).toHaveLength(0);
  });

  test('OMADA_QOS_METHOD=openapi never uses the web API', async () => {
    process.env.OMADA_QOS_METHOD = 'openapi';
    queueJson(200, TOKEN_RESPONSE);
    queueJson(200, SITES_RESPONSE);
    queueJson(200, { errorCode: 0 });

    const result = await nb.setClientRateLimit({ clientMac: 'AA-BB-CC-DD-EE-FF' });

    expect(result.method).toBe('openapi');
    expect(localSpy).not.toHaveBeenCalled();
  });

  test('a transport that is in mock mode does not mask a configured one', async () => {
    // Northbound itself is unconfigured (mock) but the local controller is not.
    const previous = process.env.OMADA_NORTHBOUND_BASE_URL;
    delete process.env.OMADA_NORTHBOUND_BASE_URL;
    delete process.env.OMADA_NORTHBOUND_REGION;
    localSpy.mockResolvedValue({ success: true, clientMac: 'AA-BB-CC-DD-EE-FF', applied: {}, route: 'v2' });
    try {
      const result = await nb.setClientRateLimit({ clientMac: 'AA-BB-CC-DD-EE-FF' });
      expect(result.method).toBe('local');
      expect(result.mock).toBeUndefined();
    } finally {
      process.env.OMADA_NORTHBOUND_BASE_URL = previous;
    }
  });
});

describe('extendClientPeriod', () => {
  test('validates the 60s–1000000day range before calling the API', async () => {
    await expect(nb.extendClientPeriod({ recordId: 'r1', periodMs: 1000 }))
      .rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_INVALID_PERIOD' });
    expect(calls).toHaveLength(0);
  });

  test('requires a recordId', async () => {
    await expect(nb.extendClientPeriod({ periodMs: 60000 }))
      .rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_MISSING_FIELD' });
  });
});

// ================================================================
// Site resolution — OMADA_SITE name → numeric site ID
// ================================================================
// ================================================================
// Base URL → controller port + TLS verification
// ================================================================
describe('base URL and TLS for a LAN controller', () => {
  const CLOUD_URL = 'https://use1-omada-northbound.tplinkcloud.com';

  function withBaseUrl(value, fn) {
    const previous = process.env.OMADA_NORTHBOUND_BASE_URL;
    process.env.OMADA_NORTHBOUND_BASE_URL = value;
    return Promise.resolve()
      .then(fn)
      .finally(() => { process.env.OMADA_NORTHBOUND_BASE_URL = previous; });
  }

  test('a LAN base URL without a port inherits the controller Open API port 8043', () => {
    expect(_internal.normalizeBaseUrl('https://192.168.0.253')).toBe('https://192.168.0.253:8043');
    expect(_internal.normalizeBaseUrl('https://controller.local')).toBe('https://controller.local:8043');
    expect(_internal.normalizeBaseUrl('http://127.0.0.1')).toBe('http://127.0.0.1:8043');
  });

  test('an explicit port and a public host are left untouched', () => {
    expect(_internal.normalizeBaseUrl('https://192.168.0.253:8443')).toBe('https://192.168.0.253:8443');
    expect(_internal.normalizeBaseUrl(CLOUD_URL)).toBe(CLOUD_URL);
    expect(_internal.normalizeBaseUrl('https://omada.example.com')).toBe('https://omada.example.com');
  });

  test('sends the token request to the controller port and accepts its self-signed certificate', async () => {
    await withBaseUrl('https://192.168.0.253', async () => {
      queueJson(200, TOKEN_RESPONSE);
      await nb.getOmadaToken();

      expect(calls[0].url).toBe(
        'https://192.168.0.253:8043/openapi/authorize/token?grant_type=client_credentials'
      );
      // A LAN controller certificate can never chain to a public CA.
      expect(calls[0].tlsVerify).toBe(false);
    });
  });

  test('keeps certificate verification ON for the public Cloud API host', async () => {
    queueJson(200, TOKEN_RESPONSE);
    await nb.getOmadaToken();

    expect(calls[0].url).toBe(CLOUD_URL + '/openapi/authorize/token?grant_type=client_credentials');
    expect(calls[0].tlsVerify).toBe(true);
  });

  test('honours an explicit OMADA_NORTHBOUND_TLS_REJECT', async () => {
    process.env.OMADA_NORTHBOUND_TLS_REJECT = 'false';
    try {
      queueJson(200, TOKEN_RESPONSE);
      await nb.getOmadaToken();
      expect(calls[0].tlsVerify).toBe(false);
    } finally {
      delete process.env.OMADA_NORTHBOUND_TLS_REJECT;
    }
  });
});

describe('OMADA_SITE resolution', () => {
  test('resolves the site name to its numeric ID and caches it across calls', async () => {
    queueJson(200, TOKEN_RESPONSE);                    // token
    queueJson(200, SITES_RESPONSE);                    // GET /sites (name → ID)
    queueJson(200, { errorCode: 0, msg: 'success' });  // auth #1
    await nb.authorizeGuest({ clientMac: 'AA:BB:CC:DD:EE:FF' });

    // Second call: the site ID (and token) are cached — only the auth goes out.
    queueJson(200, { errorCode: 0, msg: 'success' });  // auth #2
    await nb.authorizeGuest({ clientMac: 'AA:BB:CC:DD:EE:FF' });

    const siteListCalls = calls.filter((c) => /\/sites(\?|$)/.test(c.url));
    expect(siteListCalls).toHaveLength(1);
    expect(calls[2].url).toContain('/sites/' + SITE_ID + '/hotspot/clients/AA-BB-CC-DD-EE-FF/auth');
  });

  test('matches the configured name case-insensitively', async () => {
    process.env.OMADA_SITE = 'dEfAuLt';
    try {
      queueJson(200, TOKEN_RESPONSE);
      queueJson(200, SITES_RESPONSE);
      queueJson(200, { errorCode: 0, msg: 'success' });

      await nb.authorizeGuest({ clientMac: 'AA:BB:CC:DD:EE:FF' });

      expect(calls[2].url).toContain('/sites/' + SITE_ID + '/');
    } finally {
      process.env.OMADA_SITE = 'Default';
    }
  });

  test('throws OMADA_NORTHBOUND_SITE_NOT_FOUND when no site matches the name', async () => {
    process.env.OMADA_SITE = 'Nonexistent';
    try {
      queueJson(200, TOKEN_RESPONSE);
      queueJson(200, { errorCode: 0, result: { data: [{ siteId: 'other', name: 'Guest' }] } });

      await expect(nb.authorizeGuest({ clientMac: 'AA:BB:CC:DD:EE:FF' }))
        .rejects.toMatchObject({ code: 'OMADA_NORTHBOUND_SITE_NOT_FOUND' });
    } finally {
      process.env.OMADA_SITE = 'Default';
    }
  });
});
