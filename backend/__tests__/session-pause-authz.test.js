/**
 * __tests__/session-pause-authz.test.js
 *
 * Verifies the SECURITY boundary of POST /api/session/pause: the endpoint must
 * reject any session whose plan tier is not pausable (i.e. Standard), even if
 * a client bypasses the portal UI and posts the request directly.
 *
 * Patterns follow backend/__tests__/voucher-code.test.js:
 *   - Temp SQLite database created before requiring db/client.js
 *   - Schema applied via schema.sql
 *   - supertest with the Express app exported from src/server.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Environment setup MUST happen before requiring any backend modules
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-pause-authz-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';
// The pause route is gated on this flag; enable it so the plan-tier check
// (the behaviour under test) is what rejects the request.
process.env.PAUSE_ENABLED = 'true';

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const sessionService = require('../src/services/session');

async function applySchema() {
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'db', 'schema.sql'),
    'utf8'
  );
  await getDb().exec(schema);
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

describe('POST /api/session/pause — plan-tier authorization', () => {
  test('Standard plan is rejected with 403 PREMIUM_ONLY and stays active', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_std_route',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
      voucherType: 'standard',
      totalDurationSeconds: 3600,
    });

    const res = await request(app)
      .post('/api/session/pause')
      .send({ sessionId: 'sess_std_route' });

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.code).toBe('PREMIUM_ONLY');

    // The rejected request must not have paused the session.
    const after = await sessionService.getSession('sess_std_route');
    expect(after.state).toBe('active');
  });

  test('Premium plan pauses successfully (positive control)', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_prem_route',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });

    const res = await request(app)
      .post('/api/session/pause')
      .send({ sessionId: 'sess_prem_route' });

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('paused');

    const after = await sessionService.getSession('sess_prem_route');
    expect(after.state).toBe('paused');
  });

  test('missing sessionId is rejected with 400', async () => {
    const res = await request(app).post('/api/session/pause').send({});
    expect(res.status).toBe(400);
  });
});

describe('Premium pause is not a one-shot allowance', () => {
  test('pause → resume → pause again, driven by the status payload canPause values', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_cycle',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });

    const active = await request(app).get('/api/session/status?sessionId=sess_cycle');
    expect(active.body.state).toBe('active');
    expect(active.body.canPause).toBe(true);
    expect(active.body.remainingSeconds).toBeGreaterThan(0);

    const firstPause = await request(app)
      .post('/api/session/pause')
      .send({ sessionId: 'sess_cycle' });
    expect(firstPause.status).toBe(200);
    expect(firstPause.body.state).toBe('paused');

    const paused = await request(app).get('/api/session/status?sessionId=sess_cycle');
    expect(paused.body.state).toBe('paused');
    expect(paused.body.canPause).toBe(false);
    expect(paused.body.canResume).toBe(true);

    const resumed = await request(app)
      .post('/api/session/resume')
      .send({ sessionId: 'sess_cycle' });
    expect(resumed.status).toBe(200);
    expect(resumed.body.state).toBe('active');

    // The payload must offer Pause again — nothing was consumed by the first one.
    const activeAgain = await request(app).get('/api/session/status?sessionId=sess_cycle');
    expect(activeAgain.body.state).toBe('active');
    expect(activeAgain.body.canPause).toBe(true);
    expect(activeAgain.body.canResume).toBe(false);

    const secondPause = await request(app)
      .post('/api/session/pause')
      .send({ sessionId: 'sess_cycle' });
    expect(secondPause.status).toBe(200);
    expect(secondPause.body.state).toBe('paused');

    const frozen = await getDb().getOne(
      'SELECT state, remaining_seconds FROM sessions WHERE session_id = ?',
      ['sess_cycle']
    );
    expect(frozen.state).toBe('paused');
    expect(frozen.remaining_seconds).toBeGreaterThan(0);
  });

  test('canPause stays true with under a minute left', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_short_pause',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });
    await getDb().run(
      'UPDATE sessions SET expires_at = ? WHERE session_id = ?',
      [new Date(Date.now() + 30 * 1000).toISOString(), 'sess_short_pause']
    );

    const res = await request(app).get('/api/session/status?sessionId=sess_short_pause');
    expect(res.body.state).toBe('active');
    expect(res.body.remainingSeconds).toBeLessThanOrEqual(30);
    // No "only enough time left" gate: the capability belongs to the plan.
    expect(res.body.canPause).toBe(true);

    const pause = await request(app)
      .post('/api/session/pause')
      .send({ sessionId: 'sess_short_pause' });
    expect(pause.status).toBe(200);
  });

  test('the schema stores no consumed-pause flag to honour', async () => {
    const cols = await getDb().query('PRAGMA table_info(sessions)');
    const names = cols.map((c) => c.name);
    expect(names).not.toContain('can_pause');
    expect(names).not.toContain('used_pause');
  });
});

describe('POST /api/session/pause — the frozen timer', () => {
  async function rowOf(sessionId) {
    return getDb().getOne(
      'SELECT state, remaining_seconds, expires_at FROM sessions WHERE session_id = ?',
      [sessionId]
    );
  }

  test('pause stores the remaining seconds and halts expires_at', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_freeze',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });

    const res = await request(app)
      .post('/api/session/pause')
      .send({ sessionId: 'sess_freeze' });

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('paused');

    const row = await rowOf('sess_freeze');
    expect(row.state).toBe('paused');
    // expires_at is cleared, so the frozen value is the only source of truth.
    expect(row.expires_at).toBeNull();
    // A one-hour session paused immediately has ~3600 s left, not 0.
    expect(row.remaining_seconds).toBeGreaterThan(3590);
    expect(row.remaining_seconds).toBeLessThanOrEqual(3600);
    expect(res.body.remainingSeconds).toBe(row.remaining_seconds);
  });

  test('GET /status returns that stored value verbatim and never drains it', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_frozen_status',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });

    await request(app)
      .post('/api/session/pause')
      .send({ sessionId: 'sess_frozen_status' });

    const stored = (await rowOf('sess_frozen_status')).remaining_seconds;

    const first = await request(app).get('/api/session/status?sessionId=sess_frozen_status');
    expect(first.status).toBe(200);
    expect(first.body.state).toBe('paused');
    expect(first.body.remainingSeconds).toBe(stored);
    expect(first.body.expiresAt).toBeNull();

    // Repeated polling reads the same frozen value — the paused countdown is
    // the database's remaining_seconds, not a clock-derived one.
    const second = await request(app).get('/api/session/status?sessionId=sess_frozen_status');
    expect(second.body.remainingSeconds).toBe(stored);
  });
});
