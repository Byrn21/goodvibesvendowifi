/**
 * __tests__/session-token.test.js
 *
 * The status page used to identify a returning device by its request address,
 * which only works when that address is the LAN address the portal landing
 * beacon captured. Behind a tunnel, or with Wi-Fi Assist / a proxy browser
 * routing HTTP over LTE, req.ip is a PUBLIC carrier address (124.217.x.x) that
 * matches no portal_client_context row — so /api/session/status answered
 * 502 MISSING_PORTAL_CONTEXT even for a guest physically on the SSID.
 *
 * The fix is a signed session token delivered as an HttpOnly cookie (and
 * echoed as `statusToken` / ?token=). These tests pin down:
 *
 *   - POST /api/auth issues it, and the token is opaque (not the session id)
 *   - GET /api/session/status resolves the session from the token ALONE, with
 *     no query string and no portal context for the caller's address
 *   - a tampered / expired / stale token falls through to the old behaviour
 *     instead of erroring
 *   - a fresh ?sessionId= still outranks an older cookie
 *   - ?mac= keeps working
 *
 * Patterns follow backend/__tests__/auth-resume.test.js.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-session-token-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = ''; // mock Omada: no real controller call
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';
process.env.PAUSE_ENABLED = 'true';
// A fixed secret so a token issued by one request validates in the next.
process.env.PORTAL_SESSION_SECRET = 'test-portal-session-secret';

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const sessionService = require('../src/services/session');
const { issueSessionToken, verifySessionToken } = require('../src/utils/session-token');

const MAC = 'AA:BB:CC:DD:EE:FF';
const LAN_IP = '192.168.0.42';
/** A carrier address: never present in portal_client_context. */
const PUBLIC_IP = '124.217.33.184';

async function applySchema() {
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'db', 'schema.sql'),
    'utf8'
  );
  await getDb().exec(schema);
}

/** An unredeemed voucher ready for POST /api/auth. */
async function seedVoucher(code, type = 'standard') {
  await getDb().run(
    `INSERT INTO vouchers (code, type, duration_minutes, state)
     VALUES (?, ?, 60, 'active')`,
    [code, type]
  );
}

/** A recorded session for `mac`, active unless `expire` is set. */
async function seedSession(sessionId, mac = MAC, expire = false) {
  await sessionService.recordSession({
    sessionId,
    clientMac: mac,
    clientIp: LAN_IP,
    apMac: 'AA:AA:AA:AA:AA:AA',
    ssidName: 'GoodVibesVendoWifi',
    duration: 60,
    voucherUsed: '111111',
    voucherType: 'standard',
    totalDurationSeconds: 3600,
  });
  if (expire) await sessionService.expireSession(sessionId, 'time_expired');
}

/** The `portal_session=...` pair, and the full Set-Cookie line. */
function readSetCookie(res) {
  const lines = res.headers['set-cookie'] || [];
  const line = lines.find((c) => c.indexOf('portal_session=') === 0);
  if (!line) return null;
  const pair = line.split(';')[0];
  return {
    line,
    header: pair,
    value: pair.slice('portal_session='.length),
    attributes: line.slice(pair.length + 1),
  };
}

/** GET /api/session/status from a carrier/tunnel address. */
function statusFrom(ip, options = {}) {
  let req = request(app).get('/api/session/status' + (options.query || ''));
  if (ip) req = req.set('X-Forwarded-For', ip);
  if (options.cookie) req = req.set('Cookie', options.cookie);
  return req;
}

beforeAll(async () => {
  await applySchema();
});

afterAll(async () => {
  await closeDb();
  try {
    fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
  } catch (err) {
    // best-effort cleanup
  }
});

beforeEach(async () => {
  await getDb().exec(
    'DELETE FROM sessions; DELETE FROM vouchers; DELETE FROM portal_client_context;'
  );
});

describe('session token', () => {
  test('is opaque: neither the session id nor a guessable value', () => {
    const token = issueSessionToken('sess_opaque_1');
    expect(token).toBeTruthy();
    expect(token).not.toBe('sess_opaque_1');
    expect(token).not.toContain('sess_opaque_1');
  });

  test('round-trips the session id it was issued for', () => {
    const token = issueSessionToken('sess_roundtrip');
    expect(verifySessionToken(token).sessionId).toBe('sess_roundtrip');
  });

  test('a tampered signature is rejected', () => {
    const token = issueSessionToken('sess_tamper');
    const tampered = token.slice(0, -2) + (token.endsWith('aa') ? 'bb' : 'aa');
    expect(verifySessionToken(tampered)).toBeNull();
  });

  test('a token past its own expiry is rejected', async () => {
    const token = issueSessionToken('sess_short', 1);
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(verifySessionToken(token)).toBeNull();
  });

  test('garbage is rejected without throwing', () => {
    for (const bad of ['', 'null', 'a.b.c', 'only-one-part', '!!!.???']) {
      expect(verifySessionToken(bad)).toBeNull();
    }
  });
});

describe('POST /api/auth — session cookie', () => {
  test('issues an HttpOnly cookie for the session it just authorized', async () => {
    await seedVoucher('111111');

    const res = await request(app)
      .post('/api/auth')
      .send({
        voucher: '111111',
        clientMac: MAC,
        clientIp: LAN_IP,
        apMac: 'AA:AA:AA:AA:AA:AA',
        ssidName: 'GoodVibesVendoWifi',
        termsAccepted: true,
      });

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBeTruthy();

    const cookie = readSetCookie(res);
    expect(cookie).not.toBeNull();
    // Opaque: the cookie never carries the raw session id.
    expect(cookie.value).not.toBe(res.body.sessionId);
    expect(cookie.value).not.toContain(res.body.sessionId);
    expect(verifySessionToken(cookie.value).sessionId).toBe(res.body.sessionId);

    expect(cookie.attributes).toMatch(/HttpOnly/i);
    expect(cookie.attributes).toMatch(/SameSite=Lax/i);
    expect(cookie.attributes).toMatch(/Path=\//);
    // Plain-HTTP LAN flow: a Secure cookie would be dropped by the browser.
    expect(cookie.attributes).not.toMatch(/Secure/i);

    // The same token is echoed for cookie-blocked browsers.
    expect(res.body.statusToken).toBe(cookie.value);
  });

  test('marks the cookie Secure when the request arrived over HTTPS', async () => {
    await seedVoucher('222222');

    const res = await request(app)
      .post('/api/auth')
      .set('X-Forwarded-Proto', 'https')
      .send({
        voucher: '222222',
        clientMac: MAC,
        clientIp: LAN_IP,
        apMac: 'AA:AA:AA:AA:AA:AA',
        ssidName: 'GoodVibesVendoWifi',
        termsAccepted: true,
      });

    expect(res.status).toBe(200);
    expect(readSetCookie(res).attributes).toMatch(/Secure/i);
  });
});

describe('GET /api/session/status — cookie identity beats the address lookup', () => {
  test('resolves the session from the cookie alone with no portal context', async () => {
    await seedSession('sess_cookie_hit');

    // The guest is on the SSID but their HTTP goes over LTE: the backend sees
    // a public carrier address that no portal context row can match.
    const before = await getDb().getOne(
      'SELECT COUNT(*) AS n FROM portal_client_context WHERE client_ip = ?',
      [PUBLIC_IP]
    );
    expect(before.n).toBe(0);

    const token = issueSessionToken('sess_cookie_hit');
    const res = await statusFrom(PUBLIC_IP, { cookie: 'portal_session=' + token });

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe('sess_cookie_hit');
    expect(res.body.state).toBe('active');
    expect(res.body.statusToken).toBeTruthy();
    // The window slides on every successful resolve.
    expect(readSetCookie(res)).not.toBeNull();
  });

  test('accepts the same token as ?token= (localStorage transport)', async () => {
    await seedSession('sess_token_query');
    const token = issueSessionToken('sess_token_query');

    const res = await statusFrom(PUBLIC_IP, {
      query: '?token=' + encodeURIComponent(token),
    });

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe('sess_token_query');
  });

  test('a tampered cookie falls back to MISSING_PORTAL_CONTEXT, never a 5xx', async () => {
    await seedSession('sess_tampered');

    const token = issueSessionToken('sess_tampered');
    const res = await statusFrom(PUBLIC_IP, {
      cookie: 'portal_session=' + token.slice(0, -2) + 'aa',
    });

    expect(res.status).toBe(502);
    expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');
  });

  test('an expired token is ignored', async () => {
    await seedSession('sess_expired_token');
    const token = issueSessionToken('sess_expired_token', 1);
    await new Promise((resolve) => setTimeout(resolve, 5));

    const res = await statusFrom(PUBLIC_IP, { cookie: 'portal_session=' + token });

    expect(res.status).toBe(502);
    expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');
  });

  test('a token naming a session that no longer exists is ignored', async () => {
    const token = issueSessionToken('sess_deleted');

    const res = await statusFrom(PUBLIC_IP, { cookie: 'portal_session=' + token });

    expect(res.status).toBe(502);
    expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');
  });

  test('a fresh ?sessionId= outranks an older cookie', async () => {
    await seedSession('sess_old_pass', MAC, true);   // yesterday's pass
    await seedSession('sess_new_pass', MAC);          // just bought

    const oldToken = issueSessionToken('sess_old_pass');
    const res = await statusFrom(PUBLIC_IP, {
      query: '?sessionId=sess_new_pass',
      cookie: 'portal_session=' + oldToken,
    });

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe('sess_new_pass');
    expect(res.body.state).toBe('active');
  });

  test('an expired cookie session still reports "expired" (not "not found")', async () => {
    await seedSession('sess_dead_pass', MAC, true);
    const token = issueSessionToken('sess_dead_pass');

    const res = await statusFrom(PUBLIC_IP, { cookie: 'portal_session=' + token });

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('expired');
    expect(res.body.remainingSeconds).toBe(0);
  });

  test('?mac= keeps working when no token is present', async () => {
    await seedSession('sess_mac_only', MAC);

    const res = await statusFrom(PUBLIC_IP, {
      query: '?mac=' + encodeURIComponent(MAC),
    });

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe('sess_mac_only');
  });
});
