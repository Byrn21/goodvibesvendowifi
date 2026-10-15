/**
 * __tests__/auth-resume.test.js
 *
 * Covers the "login with an existing voucher" re-login path of POST /api/auth.
 * State lives on the SESSION row, so a re-login with an already-'used' voucher
 * must:
 *   - for a still-ACTIVE session on the SAME device: replay the Omada auth for
 *     the remaining time and return a NORMAL success (success.html), never an
 *     "already active" error;
 *   - for a still-'paused' Premium session: resume it from the frozen time;
 *   - only ever from the SAME device the voucher was bound to (anti-sharing),
 * while Standard vouchers (continuous, never paused) and fully-expired
 * vouchers return clear errors.
 *
 * Patterns follow backend/__tests__/session-pause-authz.test.js.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-auth-resume-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = ''; // mock Omada: no real controller call
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';
process.env.PAUSE_ENABLED = 'true';

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const sessionService = require('../src/services/session');

const MAC = 'AA:BB:CC:DD:EE:FF';
const OTHER_MAC = '11:22:33:44:55:66';

async function applySchema() {
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'db', 'schema.sql'),
    'utf8'
  );
  await getDb().exec(schema);
}

/** Insert a voucher row already spent by `mac` (state 'used'). */
async function seedUsedVoucher(code, type, mac) {
  await getDb().run(
    `INSERT INTO vouchers (code, type, duration_minutes, state, used_by_mac, used_at)
     VALUES (?, ?, 60, 'used', ?, CURRENT_TIMESTAMP)`,
    [code, type, mac]
  );
}

/** Create a Premium session for `code` and pause it (freezes remaining time). */
async function seedPausedPremiumSession(sessionId, code, mac) {
  await sessionService.recordSession({
    sessionId,
    clientMac: mac,
    clientIp: '10.0.0.5',
    apMac: 'AA:AA:AA:AA:AA:AA',
    ssidName: 'GuestWiFi',
    duration: 60,
    voucherUsed: code,
    voucherType: 'premium',
    totalDurationSeconds: 3600,
  });
  await sessionService.pauseSession(sessionId);
}

function authRequest(body) {
  return request(app).post('/api/auth').send(Object.assign({
    clientMac: MAC,
    clientIp: '10.0.0.5',
    apMac: 'AA:AA:AA:AA:AA:AA',
    ssidName: 'GuestWiFi',
    termsAccepted: true,
  }, body));
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
  await getDb().exec('DELETE FROM sessions; DELETE FROM vouchers;');
});

describe('POST /api/auth — Premium pause/resume re-login', () => {
  test('matching MAC resumes the paused session, keeps its id and remaining time', async () => {
    await seedUsedVoucher('654321', 'premium', MAC);
    await seedPausedPremiumSession('sess_resume_ok', '654321', MAC);

    const res = await authRequest({ voucher: '654321' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.resumed).toBe(true);
    expect(res.body.sessionId).toBe('sess_resume_ok');
    expect(res.body.redirectUrl).toContain('status.html');
    expect(res.body.session.voucherType).toBe('premium');
    expect(res.body.session.remainingSeconds).toBeGreaterThan(3500);

    const after = await sessionService.getSession('sess_resume_ok');
    expect(after.state).toBe('active');
    expect(after.pausedAt).toBeNull();
    expect(new Date(after.expiresAt).getTime()).toBeGreaterThan(Date.now());
  });

  test('a different MAC is rejected (anti-sharing) and the session stays paused', async () => {
    await seedUsedVoucher('654322', 'premium', MAC);
    await seedPausedPremiumSession('sess_resume_other', '654322', MAC);

    const res = await authRequest({ voucher: '654322', clientMac: OTHER_MAC });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('VOUCHER_DEVICE_MISMATCH');

    const after = await sessionService.getSession('sess_resume_other');
    expect(after.state).toBe('paused');
  });

  test('a still-active Standard session on the same device reauthorizes (no 403)', async () => {
    await seedUsedVoucher('111111', 'standard', MAC);
    await sessionService.recordSession({
      sessionId: 'sess_std_live',
      clientMac: MAC,
      duration: 60,
      voucherUsed: '111111',
      voucherType: 'standard',
    });

    const res = await authRequest({ voucher: '111111' });

    // Standard plans cannot PAUSE, but a still-ACTIVE session on the SAME
    // device is re-authorized for its remaining time so the guest reconnects
    // without a new voucher — this is the seamless-reconnect fix.
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.resumed).toBeUndefined();
    expect(res.body.sessionId).toBe('sess_std_live');
    expect(res.body.session.state).toBe('active');
    expect(res.body.session.remainingSeconds).toBeGreaterThan(3500);

    // The session kept running: not paused, not reset, still active.
    const after = await sessionService.getSession('sess_std_live');
    expect(after.state).toBe('active');
  });

  test('a PAUSED Standard session is still rejected (pause is Premium-only)', async () => {
    await seedUsedVoucher('555555', 'standard', MAC);
    await sessionService.recordSession({
      sessionId: 'sess_std_paused',
      clientMac: MAC,
      duration: 60,
      voucherUsed: '555555',
      voucherType: 'standard',
    });
    // A Standard session should never reach 'paused' via the API; force the
    // state directly to prove the resume branch guards on voucher type.
    await getDb().run(
      `UPDATE sessions SET state = 'paused', remaining_seconds = 1800, expires_at = NULL
       WHERE session_id = ?`,
      ['sess_std_paused']
    );

    const res = await authRequest({ voucher: '555555' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('STANDARD_CONTINUOUS');
    expect(res.body.error).toMatch(/continuously/i);
  });

  test('a Premium voucher whose time fully expired reports Voucher expired', async () => {
    await seedUsedVoucher('222222', 'premium', MAC);
    await sessionService.recordSession({
      sessionId: 'sess_prem_dead',
      clientMac: MAC,
      duration: 60,
      voucherUsed: '222222',
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });
    await sessionService.expireSession('sess_prem_dead', 'time_expired');

    const res = await authRequest({ voucher: '222222' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('EXPIRED_VOUCHER');
    expect(res.body.error).toMatch(/expired/i);
  });

  test('a still-active session on the SAME device re-authorizes and returns normal success', async () => {
    await seedUsedVoucher('333333', 'premium', MAC);
    await sessionService.recordSession({
      sessionId: 'sess_prem_live',
      clientMac: MAC,
      duration: 60,
      voucherUsed: '333333',
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });

    const res = await authRequest({
      voucher: '333333',
      redirectUrl: 'https://example.com/welcome',
    });

    // Normal success shape (NOT an error) and NO `resumed` flag, so the portal
    // routes to success.html exactly like a fresh voucher.
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.resumed).toBeUndefined();
    expect(res.body.sessionId).toBe('sess_prem_live');
    expect(res.body.redirectUrl).toBe('https://example.com/welcome');
    expect(res.body.session.state).toBe('active');
    // Remaining time is derived from the session's own expiry (~3600s, not 0).
    expect(res.body.session.remainingSeconds).toBeGreaterThan(3500);

    // The session kept running: not paused, not reset, still active.
    const after = await sessionService.getSession('sess_prem_live');
    expect(after.state).toBe('active');
  });

  test('a still-active session on a DIFFERENT device is rejected (anti-sharing)', async () => {
    await seedUsedVoucher('333444', 'premium', MAC);
    await sessionService.recordSession({
      sessionId: 'sess_prem_live_other',
      clientMac: MAC,
      duration: 60,
      voucherUsed: '333444',
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });

    const res = await authRequest({ voucher: '333444', clientMac: OTHER_MAC });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('VOUCHER_DEVICE_MISMATCH');
  });

  test('a used voucher with no session row falls back to USED_VOUCHER', async () => {
    await seedUsedVoucher('444444', 'premium', MAC);

    const res = await authRequest({ voucher: '444444' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('USED_VOUCHER');
  });
});

describe('POST /api/session/reauthorize — MAC-based silent reconnect', () => {
  test('re-authorizes the newest active session for a MAC', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_reau_active',
      clientMac: MAC,
      clientIp: '10.0.0.5',
      apMac: 'AA:AA:AA:AA:AA:AA',
      ssidName: 'GuestWiFi',
      duration: 60,
      voucherType: 'standard',
    });

    const res = await request(app)
      .post('/api/session/reauthorize')
      .send({ clientMac: MAC, apMac: 'AA:AA:AA:AA:AA:AA', ssidName: 'GuestWiFi', radioId: 0 });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.active).toBe(true);
    expect(res.body.sessionId).toBe('sess_reau_active');
    expect(res.body.remainingSeconds).toBeGreaterThan(3500);
  });

  test('returns 404 { active: false } when no live session exists for the MAC', async () => {
    const res = await request(app)
      .post('/api/session/reauthorize')
      .send({ clientMac: OTHER_MAC });

    expect(res.status).toBe(404);
    expect(res.body.active).toBe(false);
  });

  test('rejects a missing/invalid clientMac with 400', async () => {
    const missing = await request(app).post('/api/session/reauthorize').send({});
    expect(missing.status).toBe(400);

    const invalid = await request(app)
      .post('/api/session/reauthorize')
      .send({ clientMac: 'not-a-mac' });
    expect(invalid.status).toBe(400);
    expect(invalid.body.code).toBe('INVALID_MAC');
  });

  test('does not re-authorize an expired session', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_reau_expired',
      clientMac: MAC,
      duration: 60,
    });
    await sessionService.expireSession('sess_reau_expired', 'time_expired');

    const res = await request(app)
      .post('/api/session/reauthorize')
      .send({ clientMac: MAC });

    expect(res.status).toBe(404);
    expect(res.body.active).toBe(false);
  });
});

describe('GET /api/session/status?voucher= — offline status checker', () => {
  test('reports remaining time for a live session created by the voucher', async () => {
    await seedUsedVoucher('111111', 'standard', MAC);
    await sessionService.recordSession({
      sessionId: 'sess_status_active',
      clientMac: MAC,
      duration: 60,
      voucherUsed: '111111',
      voucherType: 'standard',
    });

    const res = await request(app).get('/api/session/status?voucher=111111');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.active).toBe(true);
    expect(res.body.state).toBe('active');
    expect(res.body.sessionId).toBe('sess_status_active');
    expect(res.body.remainingSeconds).toBeGreaterThan(3500);
  });

  test('reports the frozen remaining time for a paused session', async () => {
    await seedUsedVoucher('222222', 'premium', MAC);
    await seedPausedPremiumSession('sess_status_paused', '222222', MAC);

    const res = await request(app).get('/api/session/status?voucher=222222');

    expect(res.status).toBe(200);
    expect(res.body.active).toBe(true);
    expect(res.body.state).toBe('paused');
    expect(res.body.remainingSeconds).toBeGreaterThan(3500);
  });

  test('reports an unused voucher as active with its full duration', async () => {
    await getDb().run(
      `INSERT INTO vouchers (code, type, duration_minutes, state)
       VALUES ('333333', 'standard', 180, 'active')`
    );

    const res = await request(app).get('/api/session/status?voucher=333333');

    expect(res.status).toBe(200);
    expect(res.body.active).toBe(true);
    expect(res.body.state).toBe('unused');
    expect(res.body.remainingSeconds).toBe(180 * 60);
  });

  test('reports EXPIRED for a used voucher whose session has elapsed', async () => {
    await seedUsedVoucher('444444', 'standard', MAC);
    await sessionService.recordSession({
      sessionId: 'sess_status_done',
      clientMac: MAC,
      duration: 60,
      voucherUsed: '444444',
    });
    await sessionService.expireSession('sess_status_done', 'time_expired');

    const res = await request(app).get('/api/session/status?voucher=444444');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.active).toBe(false);
    expect(res.body.error).toBe('EXPIRED');
    expect(res.body.remainingSeconds).toBe(0);
  });

  test('reports EXPIRED for a used voucher with no session row at all', async () => {
    await seedUsedVoucher('555555', 'standard', MAC);

    const res = await request(app).get('/api/session/status?voucher=555555');

    expect(res.status).toBe(200);
    expect(res.body.active).toBe(false);
    expect(res.body.error).toBe('EXPIRED');
  });

  test('returns 404 when the voucher code does not exist', async () => {
    const res = await request(app).get('/api/session/status?voucher=999999');

    expect(res.status).toBe(404);
    expect(res.body.active).toBe(false);
    expect(res.body.code).toBe('VOUCHER_NOT_FOUND');
  });

  test('rejects a malformed voucher code with 400', async () => {
    const res = await request(app).get('/api/session/status?voucher=abc');

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_VOUCHER_FORMAT');
  });

  test('reports EXPIRED for a voucher past its own expiry date', async () => {
    await getDb().run(
      `INSERT INTO vouchers (code, type, duration_minutes, state, expires_at)
       VALUES ('777777', 'standard', 60, 'active', '2020-01-01T00:00:00.000Z')`
    );

    const res = await request(app).get('/api/session/status?voucher=777777');

    expect(res.status).toBe(200);
    expect(res.body.active).toBe(false);
    expect(res.body.error).toBe('EXPIRED');

    // The lazy sweep marks the row 'expired', matching validateVoucher().
    const row = await getDb().getOne(`SELECT state FROM vouchers WHERE code = '777777'`);
    expect(row.state).toBe('expired');
  });

  test('still serves the sessionId path unchanged', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_status_byid',
      clientMac: MAC,
      duration: 60,
    });

    const res = await request(app).get('/api/session/status?sessionId=sess_status_byid');

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe('sess_status_byid');
    expect(res.body.state).toBe('active');
  });
});
