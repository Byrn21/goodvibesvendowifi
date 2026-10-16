/**
 * __tests__/omada-northbound.test.js — unit tests for
 * services/omada-northbound.js
 *
 * The Omada Cloud is never contacted: global fetch is stubbed, so these tests
 * assert the exact request contract the Northbound OpenAPI requires —
 * the token URL/grant/body, the `Authorization: AccessToken=` header, the
 * hyphen-separated MAC path segment, and the empty body of the auth/unauth
 * calls.
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
process.env.OMADA_SITE_ID = '6918c72f0abcdef123456789';
// Voucher QoS defaults (Mbps down / Kbps up).
process.env.VOUCHER_DEFAULT_DOWN_MBPS = '10';
process.env.VOUCHER_DEFAULT_UP_KBPS = '512';
delete process.env.OMADA_NORTHBOUND_MOCK;

const nb = require('../src/services/omada-northbound');
const { _internal } = nb;

// ── fetch stub ──────────────────────────────────────────────
const realFetch = global.fetch;
let calls = [];
let queue = [];

/** Queue one response for the next fetch call. */
function queueJson(status, body) {
  queue.push({ status, body });
}

function installFetch() {
  calls = [];
  queue = [];
  global.fetch = jest.fn(async (url, opts) => {
    const entry = { url, method: (opts && opts.method) || 'GET', headers: (opts && opts.headers) || {}, body: opts && opts.body };
    calls.push(entry);
    const next = queue.shift() || { status: 200, body: { errorCode: 0 } };
    return {
      status: next.status,
      text: async () => JSON.stringify(next.body),
    };
  });
}

beforeEach(() => {
  installFetch();
  _internal.invalidateToken();
});

afterAll(() => {
  global.fetch = realFetch;
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
    queueJson(200, { errorCode: 0, result: { accessToken: 'tok-1', expiresIn: 7200 } }); // token
    queueJson(200, { errorCode: 0, msg: 'success' });                                     // auth

    const result = await nb.authorizeClient({ clientMac: 'aa:bb:cc:dd:ee:ff' });

    expect(result.success).toBe(true);
    expect(calls[1].method).toBe('POST');
    expect(calls[1].url).toBe(
      'https://use1-omada-northbound.tplinkcloud.com/openapi/v1/TESTOMADAC123' +
      '/sites/6918c72f0abcdef123456789/hotspot/clients/AA-BB-CC-DD-EE-FF/auth'
    );
    expect(calls[1].body).toBeUndefined();
    expect(calls[1].headers['Content-Type']).toBeUndefined();
  });

  test('with durationMinutes: authorizes, finds the record, then sets the period', async () => {
    queueJson(200, { errorCode: 0, result: { accessToken: 'tok-1', expiresIn: 7200 } }); // token
    queueJson(200, { errorCode: 0, msg: 'success' });                                     // auth
    queueJson(200, { errorCode: 0, result: { data: [{ id: 'rec-1', mac: 'AA-BB-CC-DD-EE-FF' }] } }); // records
    queueJson(200, { errorCode: 0, msg: 'success' });                                     // period

    const result = await nb.authorizeClient({ clientMac: 'AA-BB-CC-DD-EE-FF', durationMinutes: 30 });

    expect(result.authRecordId).toBe('rec-1');
    expect(result.periodMs).toBe(30 * 60 * 1000);

    const periodCall = calls[3];
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
    queueJson(200, { errorCode: 0, result: { accessToken: 'tok-1', expiresIn: 7200 } });
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
    queueJson(200, { errorCode: 0, result: { accessToken: 'tok-1', expiresIn: 7200 } });
    queueJson(200, { errorCode: 0, msg: 'success' });

    const result = await nb.unauthorizeClient({ clientMac: 'aa:bb:cc:dd:ee:ff' });

    expect(result).toEqual({ success: true, clientMac: 'AA-BB-CC-DD-EE-FF' });
    expect(calls[1].method).toBe('POST');
    expect(calls[1].url).toBe(
      'https://use1-omada-northbound.tplinkcloud.com/openapi/v1/TESTOMADAC123' +
      '/sites/6918c72f0abcdef123456789/hotspot/clients/AA-BB-CC-DD-EE-FF/unauth'
    );
    expect(calls[1].body).toBeUndefined();
  });
});

// ================================================================
// Supporting calls
// ================================================================
describe('getAuthedRecords / findAuthRecordByMac', () => {
  test('requests the paginated authed-records endpoint and matches MACs loosely', async () => {
    queueJson(200, { errorCode: 0, result: { accessToken: 'tok-1', expiresIn: 7200 } });
    queueJson(200, {
      errorCode: 0,
      result: { totalRows: 1, currentPage: 1, currentSize: 200, data: [{ id: 'rec-9', mac: 'AA-BB-CC-DD-EE-FF', valid: true }] },
    });

    const record = await nb.findAuthRecordByMac('aabbccddeeff');

    expect(record.id).toBe('rec-9');
    expect(calls[1].url).toContain('/hotspot/authed-records?page=1&pageSize=200');
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
    queueJson(200, { errorCode: 0, result: { accessToken: 'tok-1', expiresIn: 7200 } });
    queueJson(200, { errorCode: 0, msg: 'success' });

    await nb.setClientRateLimit({ clientMac: 'aa:bb:cc:dd:ee:ff' });

    expect(calls[1].method).toBe('PATCH');
    const payload = JSON.parse(calls[1].body);
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
    queueJson(200, { errorCode: 0, result: { accessToken: 'tok-1', expiresIn: 7200 } });
    queueJson(200, { errorCode: 0, msg: 'success' });

    await nb.setClientRateLimit({
      clientMac: 'aa:bb:cc:dd:ee:ff',
      customRateLimit: { upEnable: true, upUnit: 1, upLimit: 512, downEnable: true, downUnit: 2, downLimit: 10 },
    });

    expect(calls[1].method).toBe('PATCH');
    expect(calls[1].url).toBe(
      'https://use1-omada-northbound.tplinkcloud.com/openapi/v1/TESTOMADAC123' +
      '/sites/6918c72f0abcdef123456789/clients/AA-BB-CC-DD-EE-FF/ratelimit'
    );
    expect(JSON.parse(calls[1].body)).toEqual({
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
