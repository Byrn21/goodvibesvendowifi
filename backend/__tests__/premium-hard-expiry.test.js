/**
 * __tests__/premium-hard-expiry.test.js
 *
 * Covers the Premium "hard expiry": a Premium pass may be paused and resumed as
 * often as the guest likes, but it is VOID once PREMIUM_HARD_EXPIRY_HOURS
 * (default 72 h) have passed since the session was created — however much
 * frozen time is still on it.
 *
 * Verified here:
 *   - session creation stamps absolute_expires_at for Premium (and only for
 *     Premium), counted from creation;
 *   - repeated pause/resume cycles all succeed and never move that deadline;
 *   - pause and resume are refused with 410 HARD_EXPIRED once it has passed,
 *     even with plenty of remaining/frozen time;
 *   - GET /api/session/status reports state 'expired', remainingSeconds 0 and
 *     the absolute_expires_at value;
 *   - Standard sessions carry no deadline and are unaffected (they are strictly
 *     continuous and end when their active time runs out);
 *   - there is no separate pause-validity window: a Premium pass may stay
 *     paused right up to its hard deadline.
 *
 * Patterns follow backend/__tests__/session-pause-authz.test.js:
 *   - Temp SQLite database created before requiring db/client.js
 *   - Schema applied via schema.sql
 *   - supertest with the Express app exported from src/server.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Environment setup MUST happen before requiring any backend modules
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-hard-expiry-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';
// Pause/resume are gated on this flag; enable them so the hard-expiry rules
// are what the requests below exercise.
process.env.PAUSE_ENABLED = 'true';

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const sessionService = require('../src/services/session');
const { PREMIUM_HARD_EXPIRY_HOURS } = require('../src/config');

const HOUR_MS = 60 * 60 * 1000;
const MAC = 'aa:bb:cc:dd:ee:ff';

async function applySchema() {
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'db', 'schema.sql'),
    'utf8'
  );
  await getDb().exec(schema);
}

/** The raw absolute_expires_at column for a session, as stored. */
async function absoluteExpiresAtOf(sessionId) {
  const row = await getDb().getOne(
    'SELECT absolute_expires_at FROM sessions WHERE session_id = ?',
    [sessionId]
  );
  return row ? row.absolute_expires_at : undefined;
}

/** Move a session's absolute deadline into the past, as if 72 h had elapsed. */
async function forceHardExpiry(sessionId, msAgo = HOUR_MS) {
  const past = new Date(Date.now() - msAgo).toISOString();
  await getDb().run(
    'UPDATE sessions SET absolute_expires_at = ? WHERE session_id = ?',
    [past, sessionId]
  );
  return past;
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

describe('Premium hard expiry — session creation', () => {
  test('the configured window is 72 hours', () => {
    expect(PREMIUM_HARD_EXPIRY_HOURS).toBe(72);
  });

  test('a Premium session is stored with an absolute deadline 72 h out', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_prem_create',
      clientMac: MAC,
      duration: 1440,
      voucherType: 'premium',
      totalDurationSeconds: 86400,
    });

    const stored = await absoluteExpiresAtOf('sess_prem_create');
    expect(stored).toBeTruthy();

    const delta = new Date(stored).getTime() - Date.now();
    expect(delta).toBeGreaterThan(71.5 * HOUR_MS);
    expect(delta).toBeLessThanOrEqual(72 * HOUR_MS + 5000);

    const session = await sessionService.getSession('sess_prem_create');
    expect(session.absoluteExpiresAt).toBeTruthy();
    expect(sessionService.isHardExpired(session)).toBe(false);
  });

  test('a Standard session is stored with no absolute deadline', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_std_create',
      clientMac: MAC,
      duration: 60,
      voucherType: 'standard',
      totalDurationSeconds: 3600,
    });

    // Strictly continuous: no hard deadline, so a long Standard voucher is
    // never cut short. It ends when its active time runs out.
    expect(await absoluteExpiresAtOf('sess_std_create')).toBeNull();

    const session = await sessionService.getSession('sess_std_create');
    expect(session.absoluteExpiresAt).toBeFalsy();
    expect(sessionService.isHardExpired(session)).toBe(false);
  });
});

describe('Premium hard expiry — unlimited pauses inside the window', () => {
  test('a Premium guest can pause and resume repeatedly, and the deadline never moves', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_prem_multi',
      clientMac: MAC,
      duration: 1440,
      voucherType: 'premium',
      totalDurationSeconds: 86400,
    });

    const deadlineBefore = await absoluteExpiresAtOf('sess_prem_multi');

    for (let cycle = 0; cycle < 3; cycle++) {
      const paused = await request(app)
        .post('/api/session/pause')
        .send({ sessionId: 'sess_prem_multi' });
      expect(paused.status).toBe(200);
      expect(paused.body.state).toBe('paused');

      const resumed = await request(app)
        .post('/api/session/resume')
        .send({ sessionId: 'sess_prem_multi' });
      expect(resumed.status).toBe(200);
      expect(resumed.body.state).toBe('active');
    }

    const after = await sessionService.getSession('sess_prem_multi');
    expect(after.state).toBe('active');
    // Pausing protects the guest's minutes; it must never extend the pass.
    expect(await absoluteExpiresAtOf('sess_prem_multi')).toBe(deadlineBefore);
  });

  test('a pass resumes however long it has been paused, while its hard deadline is ahead', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_prem_long_pause',
      clientMac: MAC,
      duration: 1440,
      voucherType: 'premium',
      totalDurationSeconds: 86400,
    });

    // Longer than the removed 168 h pause-validity window: only the absolute
    // deadline may end a paused pass, so this must still resume.
    await getDb().run(
      `UPDATE sessions SET state = 'paused', paused_at = ?, remaining_seconds = 3600, expires_at = NULL
        WHERE session_id = ?`,
      [new Date(Date.now() - 200 * HOUR_MS).toISOString(), 'sess_prem_long_pause']
    );

    const res = await request(app)
      .post('/api/session/resume')
      .send({ sessionId: 'sess_prem_long_pause' });

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('active');
  });

  test('a Standard session still cannot pause at all', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_std_pause',
      clientMac: MAC,
      duration: 60,
      voucherType: 'standard',
      totalDurationSeconds: 3600,
    });

    const res = await request(app)
      .post('/api/session/pause')
      .send({ sessionId: 'sess_std_pause' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('PREMIUM_ONLY');
  });
});

describe('Premium hard expiry — past the deadline', () => {
  test('an active Premium session cannot pause and is expired', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_prem_active_late',
      clientMac: MAC,
      duration: 1440,
      voucherType: 'premium',
      totalDurationSeconds: 86400,
    });
    await forceHardExpiry('sess_prem_active_late');

    const res = await request(app)
      .post('/api/session/pause')
      .send({ sessionId: 'sess_prem_active_late' });

    expect(res.status).toBe(410);
    expect(res.body.success).toBe(false);
    expect(res.body.code).toBe('HARD_EXPIRED');

    const row = await getDb().getOne(
      'SELECT state, expire_reason FROM sessions WHERE session_id = ?',
      ['sess_prem_active_late']
    );
    expect(row.state).toBe('expired');
    expect(row.expire_reason).toBe('hard_expired');
  });

  test('a paused Premium session cannot resume, even with frozen time left', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_prem_paused_late',
      clientMac: MAC,
      duration: 1440,
      voucherType: 'premium',
      totalDurationSeconds: 86400,
    });

    // Pause while still inside the window, then let the hard deadline pass.
    const paused = await request(app)
      .post('/api/session/pause')
      .send({ sessionId: 'sess_prem_paused_late' });
    expect(paused.status).toBe(200);

    const frozenRow = await getDb().getOne(
      'SELECT remaining_seconds FROM sessions WHERE session_id = ?',
      ['sess_prem_paused_late']
    );
    expect(frozenRow.remaining_seconds).toBeGreaterThan(0); // plenty of time "left"

    await forceHardExpiry('sess_prem_paused_late');

    const res = await request(app)
      .post('/api/session/resume')
      .send({ sessionId: 'sess_prem_paused_late' });

    expect(res.status).toBe(410);
    expect(res.body.code).toBe('HARD_EXPIRED');

    const row = await getDb().getOne(
      'SELECT state, expire_reason, remaining_seconds FROM sessions WHERE session_id = ?',
      ['sess_prem_paused_late']
    );
    expect(row.state).toBe('expired');
    expect(row.expire_reason).toBe('hard_expired');
    // The frozen seconds are untouched — the pass is simply void.
    expect(row.remaining_seconds).toBe(frozenRow.remaining_seconds);
  });

  test('getSession() reports a hard-expired paused session as expired', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_prem_service_late',
      clientMac: MAC,
      duration: 1440,
      voucherType: 'premium',
      totalDurationSeconds: 86400,
    });
    await getDb().run(
      `UPDATE sessions SET state = 'paused', paused_at = ?, remaining_seconds = 3600, expires_at = NULL
        WHERE session_id = ?`,
      [new Date().toISOString(), 'sess_prem_service_late']
    );
    await forceHardExpiry('sess_prem_service_late');

    const session = await sessionService.getSession('sess_prem_service_late');
    expect(session.state).toBe('expired');
  });
});

describe('Premium hard expiry — ?mac= status lookup', () => {
  test('falls back to the most recent expired session instead of 404ing', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_mac_expired',
      clientMac: MAC,
      duration: 60,
      voucherType: 'standard',
      totalDurationSeconds: 3600,
    });
    await getDb().run(
      `UPDATE sessions SET state = 'expired', expire_reason = 'time_expired', expired_at = ?
        WHERE session_id = ?`,
      [new Date().toISOString(), 'sess_mac_expired']
    );

    const res = await request(app).get('/api/session/status?mac=' + encodeURIComponent(MAC));

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe('sess_mac_expired');
    expect(res.body.state).toBe('expired');
    expect(res.body.remainingSeconds).toBe(0);
    expect(res.body.expire_reason).toBe('time_expired');
    expect(res.body.expireReason).toBe('time_expired');
  });

  test('reports a hard-expired pass by MAC with the reason and deadline', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_mac_hard',
      clientMac: MAC,
      duration: 1440,
      voucherType: 'premium',
      totalDurationSeconds: 86400,
    });
    await getDb().run(
      `UPDATE sessions SET state = 'paused', paused_at = ?, remaining_seconds = 3600, expires_at = NULL
        WHERE session_id = ?`,
      [new Date().toISOString(), 'sess_mac_hard']
    );
    const past = await forceHardExpiry('sess_mac_hard');

    const res = await request(app).get('/api/session/status?mac=' + encodeURIComponent(MAC));

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('expired');
    expect(res.body.expire_reason).toBe('hard_expired');
    expect(res.body.expireReason).toBe('hard_expired');
    expect(new Date(res.body.absolute_expires_at).getTime()).toBe(new Date(past).getTime());
  });

  test('a still-live session wins over an older expired one', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_mac_old',
      clientMac: MAC,
      duration: 60,
      voucherType: 'standard',
      totalDurationSeconds: 3600,
    });
    await getDb().run(
      `UPDATE sessions SET state = 'expired', expire_reason = 'time_expired'
        WHERE session_id = ?`,
      ['sess_mac_old']
    );
    await sessionService.recordSession({
      sessionId: 'sess_mac_live',
      clientMac: MAC,
      duration: 60,
      voucherType: 'standard',
      totalDurationSeconds: 3600,
    });

    const res = await request(app).get('/api/session/status?mac=' + encodeURIComponent(MAC));

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe('sess_mac_live');
    expect(res.body.state).toBe('active');
  });

  test('a device that never had a session still gets 404', async () => {
    const res = await request(app).get('/api/session/status?mac=11:22:33:44:55:66');
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('SESSION_NOT_FOUND');
  });
});

describe('Premium hard expiry — status payload', () => {
  test('a live Premium session reports absolute_expires_at and canPause', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_prem_status_live',
      clientMac: MAC,
      duration: 1440,
      voucherType: 'premium',
      totalDurationSeconds: 86400,
    });

    const res = await request(app).get('/api/session/status?sessionId=sess_prem_status_live');

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('active');
    expect(res.body.canPause).toBe(true);
    expect(res.body.absolute_expires_at).toBeTruthy();
    // Same value in both spellings, and roughly 72 h out.
    expect(new Date(res.body.absoluteExpiresAt).getTime())
      .toBe(new Date(res.body.absolute_expires_at).getTime());
    expect(new Date(res.body.absolute_expires_at).getTime() - Date.now())
      .toBeGreaterThan(71.5 * HOUR_MS);
  });

  test('a hard-expired paused Premium session reports expired with zero remaining', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_prem_status_dead',
      clientMac: MAC,
      duration: 1440,
      voucherType: 'premium',
      totalDurationSeconds: 86400,
    });
    await getDb().run(
      `UPDATE sessions SET state = 'paused', paused_at = ?, remaining_seconds = 5400, expires_at = NULL
        WHERE session_id = ?`,
      [new Date().toISOString(), 'sess_prem_status_dead']
    );
    const past = await forceHardExpiry('sess_prem_status_dead');

    const res = await request(app).get('/api/session/status?sessionId=sess_prem_status_dead');

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('expired');
    expect(res.body.remainingSeconds).toBe(0); // 5400 frozen seconds are void
    expect(res.body.canPause).toBe(false);
    expect(res.body.canResume).toBe(false);
    expect(new Date(res.body.absolute_expires_at).getTime()).toBe(new Date(past).getTime());
  });

  test('a Standard session reports no absolute_expires_at', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_std_status',
      clientMac: MAC,
      duration: 60,
      voucherType: 'standard',
      totalDurationSeconds: 3600,
    });

    const res = await request(app).get('/api/session/status?sessionId=sess_std_status');

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('active');
    // Absent (null) for every non-premium tier, which is what keeps the
    // status page's hard-expiry notice hidden for them.
    expect(res.body.absolute_expires_at).toBeNull();
    expect(res.body.absoluteExpiresAt).toBeNull();
    expect(res.body.canPause).toBe(false);
  });
});
