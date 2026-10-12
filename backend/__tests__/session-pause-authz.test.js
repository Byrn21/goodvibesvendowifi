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
