/**
 * __tests__/omada.test.js — unit tests for services/omada.js
 *
 * Covers:
 *   - minutesToTime scaling for all OMADA_TIME_UNIT values
 *   - authenticateClient: fail-loud validation before any HTTP call,
 *     extPortal/auth body shape, session cookie + Csrf-Token headers
 *   - operator login: token/cookie capture, error paths
 *   - unauthenticateClient: unauth → verify → time=1 fallback chain
 *   - 401 session-expiry retry (one re-login then retry)
 *   - Mock mode preserved
 *   - Resolved-config + per-request target logging (site / OMADAC id)
 */

process.env.OMADA_MOCK = 'false';
process.env.OMADA_BASE_URL = 'https://omada-test.example.com';
process.env.OMADA_OMADAC_ID = 'TESTOMADAC123';
process.env.OMADA_SITE = 'Default';
process.env.OMADA_PORTAL_OPERATOR_NAME = 'portal-operator';
process.env.OMADA_PORTAL_OPERATOR_PASSWORD = 'portal-secret';
process.env.OMADA_TIME_UNIT = 'ms';

const omada = require('../src/services/omada');
const { _internal } = omada;

// HTTPS transport mock: stub https.request at the socket level
const https = require('https');

function mockHttpTransport(handler) {
  const originalRequest = https.request;
  https.request = function (options, cb) {
    const { EventEmitter } = require('events');
    const req = new EventEmitter();
    req.options = options;
    req.written = [];
    req.write = (chunk) => req.written.push(String(chunk));
    req.end = () => { req.ended = true; };
    req.destroy = () => { /* no-op in mock */ };
    handler(options, req, cb);
    return req;
  };
  return function uninstall() {
    https.request = originalRequest;
  };
}

/** Respond with an Omada JSON payload through the mocked transport. */
function respondJson(req, cb, statusCode, body, headers) {
  const { PassThrough } = require('stream');
  const res = new PassThrough();
  res.statusCode = statusCode;
  res.headers = headers || {};
  const payload = Buffer.from(JSON.stringify(body));
  cb(res);
  res.emit('data', payload);
  res.emit('end');
}

beforeEach(() => {
  _internal.invalidateSession();
});

// ================================================================
// minutesToTime
// ================================================================
describe('minutesToTime (OMADA_TIME_UNIT scaling)', () => {
  test('scales minutes to milliseconds by default (ms unit)', () => {
    expect(_internal.minutesToTime(5)).toBe(5 * 60 * 1000);
    expect(_internal.minutesToTime(60)).toBe(60 * 60 * 1000);
    expect(_internal.minutesToTime(1)).toBe(60 * 1000);
  });

  test('floors and clamps invalid/negative input to 0', () => {
    expect(_internal.minutesToTime(0)).toBe(0);
    expect(_internal.minutesToTime(-10)).toBe(0);
    expect(_internal.minutesToTime(2.9)).toBe(2 * 60 * 1000);
    expect(_internal.minutesToTime('abc')).toBe(0);
    expect(_internal.minutesToTime(undefined)).toBe(0);
  });
});

// ================================================================
// Mock mode preserved
// ================================================================
describe('mock mode preserved', () => {
  const ORIGINAL_MOCK = process.env.OMADA_MOCK;

  test('authenticateClient resolves via mock when OMADA_MOCK=true', async () => {
    jest.resetModules();
    process.env.OMADA_MOCK = 'true';
    delete require.cache[require.resolve('../src/services/omada')];
    const mockOmada = require('../src/services/omada');

    const result = await mockOmada.authenticateClient({ clientMac: 'AA:BB:CC:DD:EE:FF', durationMinutes: 30 });
    expect(result.success).toBe(true);
    expect(result.msg).toContain('mock');
    process.env.OMADA_MOCK = ORIGINAL_MOCK;
    delete require.cache[require.resolve('../src/services/omada')];
  });

  test('unauthenticateClient returns verified:true via mock', async () => {
    jest.resetModules();
    process.env.OMADA_MOCK = 'true';
    delete require.cache[require.resolve('../src/services/omada')];
    const mockOmada = require('../src/services/omada');

    const result = await mockOmada.unauthenticateClient({ clientMac: 'AA:BB:CC:DD:EE:FF' });
    expect(result.success).toBe(true);
    expect(result.verified).toBe(true);
    process.env.OMADA_MOCK = ORIGINAL_MOCK;
    delete require.cache[require.resolve('../src/services/omada')];
  });
});

// ================================================================
// authenticateClient — fail-loud validation + request shape
// ================================================================
describe('authenticateClient (extPortal/auth)', () => {
  test('throws OMADA_MISSING_FIELD when apMac is absent — no HTTP call', async () => {
    let httpCalled = false;
    const uninstall = mockHttpTransport(() => { httpCalled = true; });
    try {
      await expect(
        omada.authenticateClient({ clientMac: 'AA:BB:CC:DD:EE:FF', ssidName: 'S', durationMinutes: 30 })
      ).rejects.toMatchObject({ code: 'OMADA_MISSING_FIELD' });
      expect(httpCalled).toBe(false); // fail loud BEFORE the controller is touched
    } finally {
      uninstall();
    }
  });

  test('throws OMADA_MISSING_FIELD when ssidName is absent — no HTTP call', async () => {
    let httpCalled = false;
    const uninstall = mockHttpTransport(() => { httpCalled = true; });
    try {
      await expect(
        omada.authenticateClient({ clientMac: 'AA:BB:CC:DD:EE:FF', apMac: 'AA:AA:AA:AA:AA:AA', durationMinutes: 30 })
      ).rejects.toMatchObject({ code: 'OMADA_MISSING_FIELD' });
      expect(httpCalled).toBe(false);
    } finally {
      uninstall();
    }
  });

  test('sends correct endpoint, cookie and Csrf-Token headers', async () => {
    let callIndex = 0;
    const captured = [];
    const uninstall = mockHttpTransport((options, req, cb) => {
      captured.push(options);
      callIndex += 1;
      if (callIndex === 1) {
        respondJson(req, cb, 200, { errorCode: 0, result: { token: 'csrf-token-123' } }, {
          'set-cookie': ['TPOMADA_SESSION=abc123'],
        });
      } else {
        respondJson(req, cb, 200, { errorCode: 0, msg: 'success' });
      }
    });
    try {
      const result = await omada.authenticateClient({
        clientMac: 'AA:BB:CC:DD:EE:FF',
        apMac: 'AA:AA:AA:AA:AA:AA',
        ssidName: 'GuestWiFi',
        radioId: 0,
        durationMinutes: 30,
      });
      expect(result.success).toBe(true);

      // Login call: correct path
      expect(captured[0].path).toBe('/TESTOMADAC123/api/v2/hotspot/login');
      // Auth call: correct path + session headers
      const authOpts = captured[1];
      expect(authOpts.path).toBe('/TESTOMADAC123/api/v2/hotspot/extPortal/auth');
      expect(authOpts.headers['Csrf-Token']).toBe('csrf-token-123');
      expect(authOpts.headers['Cookie']).toContain('TPOMADA_SESSION=abc123');
    } finally {
      uninstall();
    }
  });

  test('time field is scaled to milliseconds for a 30-minute auth', async () => {
    let authReq = null;
    const uninstall = mockHttpTransport((options, req, cb) => {
      // Distinguish by path (robust against call-ordering assumptions).
      // NOTE: the handler runs BEFORE req.write() is invoked by
      // omadaRequest, so the body is read from the captured request
      // object AFTER the await completes, not inside the handler.
      if (options.path.includes('/extPortal/auth')) {
        authReq = req;
        respondJson(req, cb, 200, { errorCode: 0 });
        return;
      }
      respondJson(req, cb, 200, { errorCode: 0, result: { token: 'tok' } }, { 'set-cookie': ['S=1'] });
    });
    try {
      await omada.authenticateClient({
        clientMac: 'AA:BB:CC:DD:EE:FF',
        apMac: 'AA:AA:AA:AA:AA:AA',
        ssidName: 'GuestWiFi',
        radioId: 0,
        durationMinutes: 30,
      });
      expect(authReq).not.toBeNull();
      const authBody = JSON.parse(authReq.written[0] || '{}');
      expect(authBody.time).toBe(30 * 60 * 1000); // ms (cross-verified unit)
      expect(authBody.authType).toBe(4);
      expect(authBody.clientMac).toBe('AA:BB:CC:DD:EE:FF');
      expect(authBody.apMac).toBe('AA:AA:AA:AA:AA:AA');
      expect(authBody.ssidName).toBe('GuestWiFi');
      expect(authBody.radioId).toBe(0);
    } finally {
      uninstall();
    }
  });

  test('throws OMADA_AUTH_REJECTED when controller returns non-zero errorCode', async () => {
    let callIndex = 0;
    const uninstall = mockHttpTransport((options, req, cb) => {
      callIndex += 1;
      if (callIndex === 1) {
        respondJson(req, cb, 200, { errorCode: 0, result: { token: 'tok' } }, { 'set-cookie': ['S=1'] });
      } else {
        respondJson(req, cb, 200, { errorCode: 12, msg: 'client not found' });
      }
    });
    try {
      await expect(
        omada.authenticateClient({
          clientMac: 'AA:BB:CC:DD:EE:FF', apMac: 'AA:AA:AA:AA:AA:AA',
          ssidName: 'S', radioId: 0, durationMinutes: 30,
        })
      ).rejects.toMatchObject({ code: 'OMADA_AUTH_REJECTED' });
    } finally {
      uninstall();
    }
  });

  test('includes clientIp and the full EAP connection context in the auth body', async () => {
    let authReq = null;
    const uninstall = mockHttpTransport((options, req, cb) => {
      if (options.path.includes('/extPortal/auth')) {
        authReq = req;
        respondJson(req, cb, 200, { errorCode: 0 });
        return;
      }
      respondJson(req, cb, 200, { errorCode: 0, result: { token: 'tok' } }, { 'set-cookie': ['S=1'] });
    });
    try {
      await omada.authenticateClient({
        clientMac: 'AA:BB:CC:DD:EE:FF',
        clientIp: '192.168.1.50',
        apMac: 'AA:AA:AA:AA:AA:AA',
        ssidName: 'GuestWiFi',
        radioId: 1,
        durationMinutes: 30,
      });
      const authBody = JSON.parse(authReq.written[0] || '{}');
      expect(authBody.clientIp).toBe('192.168.1.50');
      expect(authBody.radioId).toBe(1); // 5 GHz preserved, not defaulted to 0
      expect(authBody.apMac).toBe('AA:AA:AA:AA:AA:AA');
      expect(authBody.ssidName).toBe('GuestWiFi');
      expect(authBody.gatewayMac).toBeUndefined();
    } finally {
      uninstall();
    }
  });

  test('builds a Gateway-shaped body (gatewayMac + vid, no apMac) for wired clients', async () => {
    let authReq = null;
    const uninstall = mockHttpTransport((options, req, cb) => {
      if (options.path.includes('/extPortal/auth')) {
        authReq = req;
        respondJson(req, cb, 200, { errorCode: 0 });
        return;
      }
      respondJson(req, cb, 200, { errorCode: 0, result: { token: 'tok' } }, { 'set-cookie': ['S=1'] });
    });
    try {
      await omada.authenticateClient({
        clientMac: 'AA:BB:CC:DD:EE:FF',
        clientIp: '10.0.0.7',
        gatewayMac: 'GG:GG:GG:GG:GG:GG',
        vid: 20,
        durationMinutes: 15,
      });
      const authBody = JSON.parse(authReq.written[0] || '{}');
      expect(authBody.gatewayMac).toBe('GG:GG:GG:GG:GG:GG');
      expect(authBody.vid).toBe(20);
      expect(authBody.authType).toBe(4);
      expect(authBody.apMac).toBeUndefined();
      expect(authBody.ssidName).toBeUndefined();
    } finally {
      uninstall();
    }
  });

  test('throws OMADA_MISSING_FIELD for a wired client with neither apMac nor gatewayMac', async () => {
    await expect(
      omada.authenticateClient({ clientMac: 'AA:BB:CC:DD:EE:FF', durationMinutes: 15 })
    ).rejects.toMatchObject({ code: 'OMADA_MISSING_FIELD' });
  });
});

// ================================================================
// operator login
// ================================================================
describe('operator login', () => {
  test('throws OMADA_LOGIN_FAILED on bad credentials', async () => {
    const uninstall = mockHttpTransport((options, req, cb) => {
      respondJson(req, cb, 200, { errorCode: 1, msg: 'invalid credentials' });
    });
    try {
      await expect(_internal.operatorLogin()).rejects.toMatchObject({ code: 'OMADA_LOGIN_FAILED' });
    } finally {
      uninstall();
    }
  });

  test('throws OMADA_LOGIN_FAILED when response lacks result.token', async () => {
    const uninstall = mockHttpTransport((options, req, cb) => {
      respondJson(req, cb, 200, { errorCode: 0, result: {} });
    });
    try {
      await expect(_internal.operatorLogin()).rejects.toMatchObject({ code: 'OMADA_LOGIN_FAILED' });
    } finally {
      uninstall();
    }
  });
});

// ================================================================
// 401 session-expiry retry
// ================================================================
describe('session expiry retry', () => {
  test('retries once after a 401 (fresh login), then succeeds', async () => {
    let callIndex = 0;
    let authCalls = 0;
    const uninstall = mockHttpTransport((options, req, cb) => {
      callIndex += 1;
      if (callIndex === 1) {
        respondJson(req, cb, 200, { errorCode: 0, result: { token: 'tok1' } }, { 'set-cookie': ['S=1'] });
      } else if (callIndex === 2) {
        authCalls += 1;
        respondJson(req, cb, 401, { errorCode: -1, msg: 'session expired' });
      } else if (callIndex === 3) {
        respondJson(req, cb, 200, { errorCode: 0, result: { token: 'tok2' } }, { 'set-cookie': ['S=2'] });
      } else {
        authCalls += 1;
        respondJson(req, cb, 200, { errorCode: 0 });
      }
    });
    try {
      const result = await omada.authenticateClient({
        clientMac: 'AA:BB:CC:DD:EE:FF', apMac: 'AA:AA:AA:AA:AA:AA',
        ssidName: 'S', radioId: 0, durationMinutes: 30,
      });
      expect(result.success).toBe(true);
      expect(authCalls).toBe(2); // exactly one retry
    } finally {
      uninstall();
    }
  });
});

// ================================================================
// unauthenticateClient — verify + fallback chain
// ================================================================
describe('unauthenticateClient (unauth → verify → time=1 fallback)', () => {
  function chainHandler(script) {
    let i = 0;
    return function (options, req, cb) {
      const step = script[Math.min(i, script.length - 1)];
      i += 1;
      step(options, req, cb);
    };
  }
  const loginOk = (req, cb) =>
    respondJson(req, cb, 200, { errorCode: 0, result: { token: 'tok' } }, { 'set-cookie': ['S=1'] });

  test('verified revocation: unauth accepted + session query says not authorized', async () => {
    const uninstall = mockHttpTransport(chainHandler([
      (o, req, cb) => loginOk(req, cb),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0 }),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0, result: { authorized: false } }),
    ]));
    try {
      const result = await omada.unauthenticateClient({ clientMac: 'AA:BB:CC:DD:EE:FF' });
      expect(result).toMatchObject({ success: true, verified: true, path: 'unauth' });
    } finally {
      uninstall();
    }
  });

  test('time=1 fallback when client still authorized after unauth', async () => {
    const uninstall = mockHttpTransport(chainHandler([
      (o, req, cb) => loginOk(req, cb),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0 }),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0, result: { authorized: true } }),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0 }),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0, result: { authorized: false } }),
    ]));
    try {
      const result = await omada.unauthenticateClient({ clientMac: 'AA:BB:CC:DD:EE:FF' });
      expect(result).toMatchObject({ success: true, verified: true, path: 'time=1' });
    } finally {
      uninstall();
    }
  });

  test('returns success:false when client STILL authorized after time=1 fallback', async () => {
    const uninstall = mockHttpTransport(chainHandler([
      (o, req, cb) => loginOk(req, cb),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0 }),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0, result: { authorized: true } }),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0 }),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0, result: { authorized: true } }),
    ]));
    try {
      const result = await omada.unauthenticateClient({ clientMac: 'AA:BB:CC:DD:EE:FF' });
      expect(result.success).toBe(false);
    } finally {
      uninstall();
    }
  });

  test('degrades gracefully when the undocumented session endpoint is missing (HTTP 404)', async () => {
    const uninstall = mockHttpTransport(chainHandler([
      (o, req, cb) => loginOk(req, cb),
      (o, req, cb) => respondJson(req, cb, 200, { errorCode: 0 }),
      (o, req, cb) => respondJson(req, cb, 404, { errorCode: -1 }),
    ]));
    try {
      const result = await omada.unauthenticateClient({ clientMac: 'AA:BB:CC:DD:EE:FF' });
      // unauth was accepted → success true, but NOT verified (no status proof)
      expect(result).toMatchObject({ success: true, verified: false, path: 'unauth' });
    } finally {
      uninstall();
    }
  });

  test('throws OMADA_MISSING_FIELD when clientMac is absent — no HTTP call', async () => {
    let httpCalled = false;
    const uninstall = mockHttpTransport(() => { httpCalled = true; });
    try {
      await expect(omada.unauthenticateClient({})).rejects.toMatchObject({ code: 'OMADA_MISSING_FIELD' });
      expect(httpCalled).toBe(false);
    } finally {
      uninstall();
    }
  });
});

// ================================================================
// resolved config + per-request target logging
// ================================================================
describe('Omada site / OMADAC id logging', () => {
  test('logResolvedConfig echoes base, omadacId, site and TLS mode', () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      _internal.logResolvedConfig(true);
      const line = logSpy.mock.calls
        .map((c) => c.join(' '))
        .find((l) => l.includes('[omada] resolved config'));
      expect(line).toBeDefined();
      expect(line).toContain('base=https://omada-test.example.com');
      expect(line).toContain('omadacId=TESTOMADAC123');
      expect(line).toContain('site=Default');
      expect(line).toContain('siteFromEnv=yes');
      expect(line).toContain('tlsRejectUnauthorized=false');
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
    }
  });

  test('logResolvedConfig never prints the operator password', () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      _internal.logResolvedConfig(true);
      const everything = [...logSpy.mock.calls, ...errSpy.mock.calls]
        .map((c) => c.join(' '))
        .join('\n');
      expect(everything).not.toContain('portal-secret');
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
    }
  });

  test('logResolvedConfig flags an unset OMADA_SITE and a placeholder omadacId', () => {
    const saved = {
      site: process.env.OMADA_SITE,
      id: process.env.OMADA_OMADAC_ID,
    };
    jest.resetModules();
    delete process.env.OMADA_SITE;
    process.env.OMADA_OMADAC_ID = 'your-omadac-id';
    delete require.cache[require.resolve('../src/services/omada')];
    const fresh = require('../src/services/omada');

    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      fresh.logResolvedConfig();
      const errText = errSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(errText).toContain('CONFIG PROBLEMS');
      expect(errText).toContain('OMADA_SITE is unset');
      expect(errText).toContain('placeholder');
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
      process.env.OMADA_SITE = saved.site;
      process.env.OMADA_OMADAC_ID = saved.id;
      delete require.cache[require.resolve('../src/services/omada')];
    }
  });

  test('authenticateClient logs the site + OMADAC id actually sent (password never logged)', async () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const uninstall = mockHttpTransport((options, req, cb) => {
      if (options.path.includes('/extPortal/auth')) {
        respondJson(req, cb, 200, { errorCode: 0 });
        return;
      }
      respondJson(req, cb, 200, { errorCode: 0, result: { token: 'tok' } }, { 'set-cookie': ['S=1'] });
    });
    try {
      await omada.authenticateClient({
        clientMac: 'AA:BB:CC:DD:EE:FF',
        apMac: 'AA:AA:AA:AA:AA:AA',
        ssidName: 'GuestWiFi',
        radioId: 0,
        durationMinutes: 30,
      });

      const lines = logSpy.mock.calls.map((c) => c.join(' '));

      // Explicit auth-target line: the site and controller the client is
      // being authorized against.
      const target = lines.find((l) => l.includes('authenticateClient target'));
      expect(target).toBeDefined();
      expect(target).toContain('site=Default');
      expect(target).toContain('omadacId=TESTOMADAC123');
      expect(target).toContain('connection=EAP');

      // Per-request line for the actual extPortal/auth call.
      const authCall = lines.find(
        (l) => l.includes('→ POST') && l.includes('/TESTOMADAC123/api/v2/hotspot/extPortal/auth')
      );
      expect(authCall).toBeDefined();
      expect(authCall).toContain('site=Default');

      // Login request is logged but redacted.
      const loginCall = lines.find((l) => l.includes('/hotspot/login'));
      expect(loginCall).toBeDefined();
      expect(loginCall).toContain('credentials redacted');
      expect(lines.join('\n')).not.toContain('portal-secret');
    } finally {
      uninstall();
      logSpy.mockRestore();
    }
  });

  test('maskHost keeps scheme+host and drops credentials/path', () => {
    expect(_internal.maskHost('https://omada-test.example.com:8443/api?x=1')).toBe(
      'https://omada-test.example.com:8443'
    );
    expect(_internal.maskHost('')).toBe('(unset)');
    expect(_internal.maskHost('not a url')).toBe('(invalid URL)');
  });
});
