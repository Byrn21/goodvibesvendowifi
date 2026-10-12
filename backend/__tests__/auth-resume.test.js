/**
 * __tests__/auth-resume.test.js
 *
 * Covers the "login with an existing voucher" (Premium pause/resume) path of
 * POST /api/auth. Pause state lives on the SESSION row, so a re-login with an
 * already-'used' voucher must:
 *   - resume only a still-'paused' Premium session,
 *   - only from the SAME device the voucher was bound to (anti-sharing),
 *   - hand back the original sessionId + remaining time,
 * while Standard vouchers (continuous, never paused) and fully-expired
 * Premium vouchers return clear errors.
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

  test('Standard vouchers run continuously and cannot be resumed', async () => {
    await seedUsedVoucher('111111', 'standard', MAC);
    await sessionService.recordSession({
      sessionId: 'sess_std_used',
      clientMac: MAC,
      duration: 60,
      voucherUsed: '111111',
      voucherType: 'standard',
    });

    const res = await authRequest({ voucher: '111111' });

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

  test('an already-active session reports ALREADY_ACTIVE', async () => {
    await seedUsedVoucher('333333', 'premium', MAC);
    await sessionService.recordSession({
      sessionId: 'sess_prem_live',
      clientMac: MAC,
      duration: 60,
      voucherUsed: '333333',
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });

    const res = await authRequest({ voucher: '333333' });

    expect(res.status).toBe(409);
    expect(res.body.code).toBe('ALREADY_ACTIVE');
  });

  test('a used voucher with no session row falls back to USED_VOUCHER', async () => {
    await seedUsedVoucher('444444', 'premium', MAC);

    const res = await authRequest({ voucher: '444444' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('USED_VOUCHER');
  });
});
