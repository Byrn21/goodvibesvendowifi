/**
 * __tests__/omada-local-deauth.test.js — kicking a client off the controller
 * through the site web API (services/omada.js → unauthenticateClient)
 *
 * /hotspot/extPortal/unauth is undocumented; some controller builds answer
 * HTTP 200 with errorCode -1600 ("Unsupported request path."), the kick is
 * logged as a rejection and the guest keeps internet access after its voucher
 * expired. The same operation is a SITE operation, so it runs on the
 * ADMINISTRATOR session (OMADA_ADMIN_*), exactly like the bandwidth cap.
 *
 * Covers:
 *   - the v2 kick route on a fresh admin session (cookie + Csrf-Token, MAC
 *     path segment, no portal login at all) and revocation verification from
 *     the site's authed-records
 *   - the /openapi/v1 … session route when the v2 route answers -1600
 *   - an accepted route that leaves the client authorized falling through
 *   - "verified" only when the record list proves the MAC is gone
 *   - the operator extPortal/unauth fallback when no site route works
 *   - no administrator credentials ⇒ the operator path only
 *   - the route that worked is remembered
 *   - record-validity parsing (boolean flag, seconds, milliseconds, none)
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
const V2_UNAUTH = '/TESTOMADAC123/api/v2/sites/' + SITE_KEY + '/hotspot/clients/AA-BB-CC-DD-EE-FF/unauth';
const OPENAPI_UNAUTH = '/openapi/v1/TESTOMADAC123/sites/' + SITE_KEY + '/hotspot/clients/AA-BB-CC-DD-EE-FF/unauth';
const V2_RECORDS = '/TESTOMADAC123/api/v2/sites/' + SITE_KEY + '/hotspot/authed-records?page=1&pageSize=200';
const OPENAPI_RECORDS = '/openapi/v1/TESTOMADAC123/sites/' + SITE_KEY + '/hotspot/authed-records?page=1&pageSize=200';

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

/** Administrator login + site lookup (the two calls before every kick). */
function queueAdminSession() {
  queueResponse(200, { errorCode: 0, result: { token: 'admin-csrf' } }, {
    'set-cookie': ['TPOMADA_SESSIONID=admin123; Path=/; HttpOnly'],
  });
  queueResponse(200, {
    errorCode: 0,
    result: { privilege: { sites: [{ name: 'Default', key: SITE_KEY }] } },
  });
}

const UNSUPPORTED = { errorCode: -1600, msg: 'Unsupported request path.' };

function paths() {
  return calls.map((c) => c.method + ' ' + c.path);
}

beforeEach(() => {
  installTransport();
  omada._internal.invalidateSession();
  omada._internal.resetDeauthState();
  omada._internal.resetRateLimitState();
});

afterAll(() => {
  https.request = realRequest;
});

describe('administrator-session deauthorization', () => {
  test('kicks the client through the v2 site route on the admin session and verifies it', async () => {
    queueAdminSession();
    queueResponse(200, { errorCode: 0, msg: 'Success' });          // POST …/unauth
    queueResponse(200, { errorCode: 0, result: { data: [] } });    // authed-records: MAC gone

    const result = await omada.unauthenticateClient({ clientMac: MAC });

    expect(result).toMatchObject({ success: true, verified: true, path: 'v2-unauth' });
    expect(paths()).toEqual([
      'POST /TESTOMADAC123/api/v2/login',
      'GET /TESTOMADAC123/api/v2/users/current',
      'POST ' + V2_UNAUTH,
      'GET ' + V2_RECORDS,
    ]);

    // The kick carries the ADMIN cookie + Csrf-Token …
    const kick = calls[2];
    expect(kick.headers['Csrf-Token']).toBe('admin-csrf');
    expect(kick.headers.Cookie).toContain('TPOMADA_SESSIONID=admin123');
    expect(kick.headers['Omada-Request-Source']).toBe('web-local');

    // … and the portal operator is never involved.
    expect(calls.some((c) => c.path.includes('/hotspot/login'))).toBe(false);
    expect(calls.some((c) => c.path.includes('/extPortal/'))).toBe(false);
  });

  test('falls back to the /openapi/v1 site route when v2 answers -1600', async () => {
    queueAdminSession();
    queueResponse(200, UNSUPPORTED);                               // v2 route absent
    queueResponse(200, { errorCode: 0 });                          // openapi route accepted
    queueResponse(200, UNSUPPORTED);                               // records v2 absent
    queueResponse(200, UNSUPPORTED);                               // records openapi absent

    const result = await omada.unauthenticateClient({ clientMac: MAC });

    // Accepted, but nothing proves the client is gone.
    expect(result).toMatchObject({ success: true, verified: false, path: 'openapi-session' });
    expect(paths()).toContain('POST ' + V2_UNAUTH);
    expect(paths()).toContain('POST ' + OPENAPI_UNAUTH);
    expect(calls[3].headers['Csrf-Token']).toBe('admin-csrf');
    expect(calls.some((c) => c.path.includes('/extPortal/'))).toBe(false);
  });

  test('an accepted kick that leaves the client authorized tries the next route', async () => {
    queueAdminSession();
    queueResponse(200, { errorCode: 0 });                          // v2 accepted …
    queueResponse(200, {                                            // … but MAC still valid
      errorCode: 0,
      result: { data: [{ id: 'rec-1', mac: 'AA-BB-CC-DD-EE-FF', valid: true }] },
    });
    queueResponse(200, { errorCode: 0 });                          // openapi route accepted
    queueResponse(200, { errorCode: 0, result: { data: [] } });    // now the MAC is gone

    const result = await omada.unauthenticateClient({ clientMac: MAC });

    expect(result).toMatchObject({ success: true, verified: true, path: 'openapi-session' });
    expect(omada._internal.preferredDeauthRoute()).toBe('openapi-session');
  });

  test('disconnects by authentication record when no client-level route exists', async () => {
    queueAdminSession();
    queueResponse(200, UNSUPPORTED);                               // v2 unauth absent
    queueResponse(200, UNSUPPORTED);                               // openapi unauth absent
    queueResponse(200, {                                           // authed-records
      errorCode: 0,
      result: { data: [{ id: 'rec-9', mac: 'aa:bb:cc:dd:ee:ff', valid: true }] },
    });
    queueResponse(200, { errorCode: 0 });                          // …/authed-records/rec-9/disconnect
    queueResponse(200, { errorCode: 0, result: { data: [] } });    // verification

    const result = await omada.unauthenticateClient({ clientMac: MAC });

    expect(result).toMatchObject({ success: true, verified: true, path: 'authed-record' });
    expect(paths()).toContain(
      'POST /TESTOMADAC123/api/v2/sites/' + SITE_KEY + '/hotspot/authed-records/rec-9/disconnect'
    );
  });

  test('remembers the kick route that worked', async () => {
    queueAdminSession();
    queueResponse(200, { errorCode: 0 });
    queueResponse(200, { errorCode: 0, result: { data: [] } });
    await omada.unauthenticateClient({ clientMac: MAC });

    const before = calls.length;
    // Force a logout: the site key is cached, so only a new admin login, the
    // remembered kick route and its verification remain.
    omada._internal.invalidateSession();
    queueResponse(200, { errorCode: 0, result: { token: 'admin-csrf-2' } }, {
      'set-cookie': ['TPOMADA_SESSIONID=admin456; Path=/'],
    });
    queueResponse(200, { errorCode: 0 });
    queueResponse(200, { errorCode: 0, result: { data: [] } });

    const second = await omada.unauthenticateClient({ clientMac: MAC });

    expect(second).toMatchObject({ success: true, path: 'v2-unauth' });
    expect(paths().slice(before)).toEqual([
      'POST /TESTOMADAC123/api/v2/login',
      'POST ' + V2_UNAUTH,
      'GET ' + V2_RECORDS,
    ]);
  });

  test('falls back to the operator extPortal/unauth when no site route works', async () => {
    queueAdminSession();
    queueResponse(200, UNSUPPORTED);                               // v2 unauth
    queueResponse(200, UNSUPPORTED);                               // openapi unauth
    queueResponse(200, UNSUPPORTED);                               // records v2
    queueResponse(200, UNSUPPORTED);                               // records openapi
    // Operator fallback: portal login, unauth accepted, status says revoked.
    queueResponse(200, { errorCode: 0, result: { token: 'portal-csrf' } }, {
      'set-cookie': ['TPOMADA_SESSIONID=portal123; Path=/'],
    });
    queueResponse(200, { errorCode: 0 });
    queueResponse(200, { errorCode: 0, result: { authorized: false } });

    const result = await omada.unauthenticateClient({ clientMac: MAC });

    expect(result).toMatchObject({ success: true, verified: true, path: 'unauth' });
    const portalLogin = calls.find((c) => c.path.endsWith('/api/v2/hotspot/login'));
    expect(JSON.parse(portalLogin.body)).toEqual({
      name: 'vendo_byron',
      password: 'operator-secret',
    });
    // The operator session was never handed the administrator cookie.
    const portalUnauth = calls.find((c) => c.path.includes('/extPortal/unauth'));
    expect(portalUnauth.headers.Cookie).toContain('portal123');
    expect(portalUnauth.headers.Cookie).not.toContain('admin123');
  });

  test('never uses the administrator routes without administrator credentials', async () => {
    jest.resetModules();
    const savedName = process.env.OMADA_ADMIN_NAME;
    const savedPassword = process.env.OMADA_ADMIN_PASSWORD;
    delete process.env.OMADA_ADMIN_NAME;
    delete process.env.OMADA_ADMIN_PASSWORD;
    try {
      const fresh = require('../src/services/omada');
      queueResponse(200, { errorCode: 0, result: { token: 'portal-csrf' } }, {
        'set-cookie': ['TPOMADA_SESSIONID=portal123; Path=/'],
      });
      queueResponse(200, { errorCode: 0 });
      queueResponse(200, { errorCode: 0, result: { authorized: false } });

      const result = await fresh.unauthenticateClient({ clientMac: MAC });

      expect(result).toMatchObject({ success: true, verified: true, path: 'unauth' });
      expect(calls[0].path).toBe('/TESTOMADAC123/api/v2/hotspot/login');
      expect(calls.some((c) => c.path.includes('/api/v2/login'))).toBe(false);
      expect(calls.some((c) => c.path.includes('/ratelimit'))).toBe(false);
    } finally {
      process.env.OMADA_ADMIN_NAME = savedName;
      process.env.OMADA_ADMIN_PASSWORD = savedPassword;
      delete require.cache[require.resolve('../src/services/omada')];
    }
  });
});

describe('record validity', () => {
  test('reads the boolean flag first', () => {
    expect(omada._internal.isRecordAuthorized({ valid: true })).toBe(true);
    expect(omada._internal.isRecordAuthorized({ valid: false })).toBe(false);
    expect(omada._internal.isRecordAuthorized({ authorized: false })).toBe(false);
  });

  test('accepts seconds, milliseconds and ISO end times', () => {
    const now = Date.now();
    expect(omada._internal.isRecordAuthorized({ end: Math.floor((now + 60000) / 1000) })).toBe(true);
    expect(omada._internal.isRecordAuthorized({ end: Math.floor((now - 60000) / 1000) })).toBe(false);
    expect(omada._internal.isRecordAuthorized({ end: now + 60000 })).toBe(true);
    expect(omada._internal.isRecordAuthorized({ end: now - 60000 })).toBe(false);
    expect(omada._internal.isRecordAuthorized({ end: new Date(now + 60000).toISOString() })).toBe(true);
  });

  test('a missing record means "not authorized"; a record without validity data stays authorized', () => {
    expect(omada._internal.isRecordAuthorized(null)).toBe(false);
    expect(omada._internal.isRecordAuthorized({ id: 'rec-1' })).toBe(true);
  });

  test('matches a MAC in any format', () => {
    const records = [{ mac: 'aa-bb-cc-dd-ee-ff' }, { mac: '11:22:33:44:55:66' }];
    expect(omada._internal.recordFor(records, 'AA:BB:CC:DD:EE:FF')).toBe(records[0]);
    expect(omada._internal.recordFor(records, '99:99:99:99:99:99')).toBeNull();
  });
});
