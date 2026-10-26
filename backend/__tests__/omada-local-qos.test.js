/**
 * __tests__/omada-local-qos.test.js — bandwidth cap through the controller's
 * WEB API (services/omada.js → setClientRateLimit)
 *
 * The Open API route needs a controller with Open API (v5.12+) and an Open API
 * application created on the controller; a stock OC200 answers the OAuth token
 * request with HTTP 500 and every guest stayed uncapped. The same operation
 * (`updateClientRateLimitSetting`) is available through the controller web API,
 * but ONLY to a controller ADMINISTRATOR: the hotspot portal operator account
 * returns 0 sites and cannot set rate limits.
 *
 * Covers:
 *   - a FRESH administrator login (OMADA_ADMIN_*) → site key resolution →
 *     PATCH …/clients/{MAC}/ratelimit with the exact body, Csrf-Token, cookie
 *     and Omada-Request-Source header
 *   - the administrator and portal operator sessions stay separate
 *   - missing administrator credentials fail loud before any PATCH
 *   - fallback to the /openapi/v1/… route (admin session) when the v2 route is
 *     rejected
 *   - the route that worked is remembered
 *   - OMADA_SITE → site key resolution (privilege.sites, then /sites)
 *   - a site the controller does not know fails loud, before any cap call
 *   - mock mode never touches the network
 */

'use strict';

process.env.OMADA_MOCK = 'false';
process.env.OMADA_BASE_URL = 'https://192.168.0.253:8043';
process.env.OMADA_OMADAC_ID = 'TESTOMADAC123';
process.env.OMADA_SITE = 'Default';
process.env.OMADA_PORTAL_OPERATOR_NAME = 'vendo_byron';
process.env.OMADA_PORTAL_OPERATOR_PASSWORD = 'operator-secret';
// Privileged calls run as a controller administrator, never the operator.
process.env.OMADA_ADMIN_NAME = 'controller-admin';
process.env.OMADA_ADMIN_PASSWORD = 'admin-secret';

const https = require('https');
const omada = require('../src/services/omada');

const MAC = 'AA:BB:CC:DD:EE:FF';
const SITE_KEY = 'site-key-1';
const PATCH_V2 = '/TESTOMADAC123/api/v2/sites/' + SITE_KEY + '/clients/AA-BB-CC-DD-EE-FF/ratelimit';
const PATCH_OPENAPI = '/openapi/v1/TESTOMADAC123/sites/' + SITE_KEY + '/clients/AA-BB-CC-DD-EE-FF/ratelimit';

const PAYLOAD = {
  mode: 0,
  customRateLimit: {
    upEnable: true, upUnit: 1, upLimit: 512,
    downEnable: true, downUnit: 2, downLimit: 10,
  },
};

// ── https transport stub ────────────────────────────────────
const realRequest = https.request;
let calls = [];
let queue = [];

/** Queue one controller response. */
function queueResponse(statusCode, body, headers) {
  queue.push({ statusCode, body, headers });
}

function installTransport() {
  calls = [];
  queue = [];
  https.request = (options, callback) => {
    const entry = {
      method: options.method,
      path: options.path,
      headers: options.headers || {},
      body: undefined,
    };
    calls.push(entry);

    const { EventEmitter } = require('events');
    const req = new EventEmitter();
    req.write = (chunk) => { entry.body = String(chunk); };
    req.destroy = () => {};
    req.end = () => {
      const next = queue.shift() || { statusCode: 200, body: { errorCode: 0 }, headers: {} };
      const res = new EventEmitter();
      res.statusCode = next.statusCode;
      res.headers = next.headers || {};
      setImmediate(() => {
        callback(res);
        res.emit('data', Buffer.from(JSON.stringify(next.body)));
        res.emit('end');
      });
    };
    return req;
  };
}

/** admin login + site lookup responses (the two calls before every cap attempt). */
function queueSession(sitesBody) {
  queueResponse(200, { errorCode: 0, result: { token: 'admin-csrf' } }, {
    'set-cookie': ['TPOMADA_SESSIONID=admin123; Path=/; HttpOnly'],
  });
  queueResponse(200, sitesBody || {
    errorCode: 0,
    result: { privilege: { sites: [{ name: 'Default', key: SITE_KEY }] } },
  });
}

function patchCalls() {
  return calls.filter((c) => c.method === 'PATCH');
}

beforeEach(() => {
  installTransport();
  omada._internal.invalidateSession();
  omada._internal.resetRateLimitState();
});

afterAll(() => {
  https.request = realRequest;
});

describe('local web-API rate limit', () => {
  test('PATCHes the v2 client ratelimit route on a fresh administrator session', async () => {
    queueSession();
    queueResponse(200, { errorCode: 0, msg: 'Success' });

    const result = await omada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD });

    expect(result).toMatchObject({ success: true, route: 'v2' });
    expect(result.applied).toEqual(PAYLOAD);

    // 0: administrator /login, 1: users/current (site key), 2: the cap itself.
    expect(calls[0].path).toBe('/TESTOMADAC123/api/v2/login');
    expect(JSON.parse(calls[0].body)).toEqual({
      username: 'controller-admin',
      password: 'admin-secret',
    });
    // The login itself must carry no session credentials.
    expect(calls[0].headers.Cookie).toBeUndefined();
    expect(calls[1].path).toBe('/TESTOMADAC123/api/v2/users/current');

    // The PORTAL OPERATOR account must never authenticate a privileged call.
    expect(calls.some((c) => c.path.includes('/hotspot/login'))).toBe(false);

    const patch = calls[2];
    expect(patch.method).toBe('PATCH');
    expect(patch.path).toBe(PATCH_V2);
    expect(JSON.parse(patch.body)).toEqual(PAYLOAD);
    expect(patch.headers['Csrf-Token']).toBe('admin-csrf');
    expect(patch.headers.Cookie).toContain('TPOMADA_SESSIONID=admin123');
    expect(patch.headers['Omada-Request-Source']).toBe('web-local');
    expect(patch.headers.Origin).toBe('https://192.168.0.253:8043');
    expect(patch.headers.Referer).toBe('https://192.168.0.253:8043/');
  });

  test('re-logs in as the administrator before each cap (fresh session cookie)', async () => {
    queueSession();
    queueResponse(200, { errorCode: 0 });
    await omada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD });

    const before = calls.length;
    queueSession();
    queueResponse(200, { errorCode: 0 });
    await omada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD });

    // Each cap starts with a NEW admin login, then reuses the cached site key.
    expect(calls.length).toBe(before + 2);
    expect(calls[before].path).toBe('/TESTOMADAC123/api/v2/login');
    expect(calls[before + 1].method).toBe('PATCH');
  });

  test('keeps the portal operator session separate from the administrator session', async () => {
    // Portal operator login + guest authorization (hotspot endpoints).
    queueResponse(200, { errorCode: 0, result: { token: 'portal-csrf' } }, {
      'set-cookie': ['TPOMADA_SESSIONID=portal123; Path=/; HttpOnly'],
    });
    queueResponse(200, { errorCode: 0 });
    // Administrator login + site lookup + cap.
    queueSession();
    queueResponse(200, { errorCode: 0 });

    await omada.authenticateClient({
      clientMac: MAC,
      apMac: 'AA:AA:AA:AA:AA:AA',
      ssidName: 'GuestWiFi',
      radioId: 0,
      durationMinutes: 30,
    });

    expect(calls[0].path).toBe('/TESTOMADAC123/api/v2/hotspot/login');
    expect(JSON.parse(calls[0].body)).toEqual({ name: 'vendo_byron', password: 'operator-secret' });
    expect(calls[1].path).toBe('/TESTOMADAC123/api/v2/hotspot/extPortal/auth');
    expect(calls[1].headers['Csrf-Token']).toBe('portal-csrf');

    await omada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD });

    expect(calls[2].path).toBe('/TESTOMADAC123/api/v2/login');
    const patch = calls[4];
    expect(patch.method).toBe('PATCH');
    expect(patch.headers['Csrf-Token']).toBe('admin-csrf');
    expect(patch.headers.Cookie).toContain('admin123');
    expect(patch.headers.Cookie).not.toContain('portal123');

    // The administrator login did not displace the portal session: a second
    // authorization still uses the portal cookie and token, with no new login.
    queueResponse(200, { errorCode: 0 });
    await omada.authenticateClient({
      clientMac: MAC,
      apMac: 'AA:AA:AA:AA:AA:AA',
      ssidName: 'GuestWiFi',
      radioId: 0,
      durationMinutes: 30,
    });
    expect(calls[5].path).toBe('/TESTOMADAC123/api/v2/hotspot/extPortal/auth');
    expect(calls[5].headers['Csrf-Token']).toBe('portal-csrf');
    expect(calls[5].headers.Cookie).toContain('portal123');
    expect(calls[5].headers.Cookie).not.toContain('admin123');
  });

  test('fails loud without administrator credentials (never uses the operator)', async () => {
    jest.resetModules();
    const savedName = process.env.OMADA_ADMIN_NAME;
    const savedPassword = process.env.OMADA_ADMIN_PASSWORD;
    delete process.env.OMADA_ADMIN_NAME;
    delete process.env.OMADA_ADMIN_PASSWORD;
    try {
      const fresh = require('../src/services/omada');
      await expect(fresh.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD }))
        .rejects.toMatchObject({ code: 'OMADA_CONFIG_ERROR' });
      expect(calls).toHaveLength(0);
    } finally {
      process.env.OMADA_ADMIN_NAME = savedName;
      process.env.OMADA_ADMIN_PASSWORD = savedPassword;
      delete require.cache[require.resolve('../src/services/omada')];
    }
  });

  test('falls back to the OpenAPI route on the web session when v2 is rejected', async () => {
    queueSession();
    queueResponse(200, { errorCode: -1200, msg: 'no permission' }); // v2 rejected
    queueResponse(200, { errorCode: 0, msg: 'Success' });          // openapi accepted

    const result = await omada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD });

    expect(result.route).toBe('openapi-session');
    expect(patchCalls().map((c) => c.path)).toEqual([PATCH_V2, PATCH_OPENAPI]);
    // The fallback still authenticates with the admin session, never an OAuth token.
    expect(calls[3].headers.Authorization).toBeUndefined();
    expect(calls[3].headers['Csrf-Token']).toBe('admin-csrf');
  });

  test('remembers the route that worked and tries it first next time', async () => {
    queueSession();
    queueResponse(200, { errorCode: -1200, msg: 'no permission' });
    queueResponse(200, { errorCode: 0 });
    await omada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD });

    expect(omada._internal.preferredRateLimitRoute()).toBe('openapi-session');

    const before = calls.length;
    // A fresh admin login is made for the second cap; the site key is cached.
    queueResponse(200, { errorCode: 0, result: { token: 'admin-csrf-2' } }, {
      'set-cookie': ['TPOMADA_SESSIONID=admin456; Path=/'],
    });
    queueResponse(200, { errorCode: 0 });
    const second = await omada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD });

    expect(second.route).toBe('openapi-session');
    // The site key is cached but the admin session is refreshed, so the cap is
    // a login followed by the PATCH — straight to the remembered route.
    expect(calls.length).toBe(before + 2);
    expect(calls[before].path).toBe('/TESTOMADAC123/api/v2/login');
    expect(calls[before + 1].path).toBe(PATCH_OPENAPI);
  });

  test('resolves the site key from /sites when /users/current is not available', async () => {
    queueResponse(200, { errorCode: 0, result: { token: 'admin-csrf' } }, {
      'set-cookie': ['TPOMADA_SESSIONID=admin123; Path=/'],
    });
    queueResponse(200, { errorCode: -1200, msg: 'no privilege' });                    // users/current
    queueResponse(200, { errorCode: 0, result: { data: [{ id: 'S2', name: 'Default' }] } }); // /sites
    queueResponse(200, { errorCode: 0 });

    const result = await omada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD });

    expect(result.route).toBe('v2');
    expect(patchCalls()[0].path).toContain('/sites/S2/clients/AA-BB-CC-DD-EE-FF/ratelimit');
  });

  test('throws OMADA_SITE_NOT_FOUND without attempting a cap when the site name is unknown', async () => {
    queueSession({ errorCode: 0, result: { privilege: { sites: [{ name: 'Other', key: 'k9' }] } } });

    await expect(omada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD }))
      .rejects.toMatchObject({ code: 'OMADA_SITE_NOT_FOUND' });

    expect(patchCalls()).toHaveLength(0);
  });

  test('surfaces both routes and the controller reason when every route is rejected', async () => {
    queueSession();
    queueResponse(200, { errorCode: -1200, msg: 'no permission' });
    queueResponse(200, { errorCode: -44001, msg: 'invalid parameter' });

    let caught = null;
    try {
      await omada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD });
    } catch (err) {
      caught = err;
    }

    expect(caught).toMatchObject({ code: 'OMADA_QOS_REJECTED' });
    expect(caught.attempts).toHaveLength(2);
    expect(caught.attempts.map((a) => a.route)).toEqual(['v2', 'openapi-session']);
    expect(caught.message).toContain('no permission');
    expect(caught.message).toContain('invalid parameter');
    expect(patchCalls()).toHaveLength(2);
  });

  test('builds the payload from the VOUCHER_DEFAULT_* caps when none is given', async () => {
    const savedDown = process.env.VOUCHER_DEFAULT_DOWN_MBPS;
    const savedUp = process.env.VOUCHER_DEFAULT_UP_KBPS;
    process.env.VOUCHER_DEFAULT_DOWN_MBPS = '10';
    process.env.VOUCHER_DEFAULT_UP_KBPS = '512';
    try {
      queueSession();
      queueResponse(200, { errorCode: 0, msg: 'Success' });

      const result = await omada.setClientRateLimit({ clientMac: MAC });

      expect(result.applied).toEqual({
        mode: 0,
        customRateLimit: {
          upEnable: true, upUnit: 1, upLimit: 512,
          downEnable: true, downUnit: 2, downLimit: 10,
        },
      });
      expect(JSON.parse(patchCalls()[0].body)).toEqual(result.applied);
    } finally {
      if (savedDown === undefined) delete process.env.VOUCHER_DEFAULT_DOWN_MBPS;
      else process.env.VOUCHER_DEFAULT_DOWN_MBPS = savedDown;
      if (savedUp === undefined) delete process.env.VOUCHER_DEFAULT_UP_KBPS;
      else process.env.VOUCHER_DEFAULT_UP_KBPS = savedUp;
    }
  });

  test('rejects an unusable VOUCHER_DEFAULT_* fallback before any HTTP call', async () => {
    const savedDown = process.env.VOUCHER_DEFAULT_DOWN_MBPS;
    delete process.env.VOUCHER_DEFAULT_DOWN_MBPS;
    try {
      await expect(omada.setClientRateLimit({ clientMac: MAC }))
        .rejects.toMatchObject({ code: 'OMADA_CONFIG_ERROR' });
      expect(calls).toHaveLength(0);
    } finally {
      if (savedDown !== undefined) process.env.VOUCHER_DEFAULT_DOWN_MBPS = savedDown;
    }
  });

  test('mock mode reports mock without touching the controller', async () => {
    jest.resetModules();
    const previousBase = process.env.OMADA_BASE_URL;
    process.env.OMADA_MOCK = 'true';
    try {
      const mockedOmada = require('../src/services/omada');
      const result = await mockedOmada.setClientRateLimit({ clientMac: MAC, payload: PAYLOAD });

      expect(result).toMatchObject({ success: true, mock: true, route: 'mock' });
      expect(calls).toHaveLength(0);
    } finally {
      process.env.OMADA_MOCK = 'false';
      process.env.OMADA_BASE_URL = previousBase;
    }
  });
});
