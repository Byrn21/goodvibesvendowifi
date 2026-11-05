/**
 * __tests__/session-expire.test.js
 *
 * Covers the authorization boundary of POST /api/session/expire: the endpoint
 * cuts a guest offline immediately, so it is operator-only. A guest holds a
 * sessionId (it is in their URL) and must not be able to end a session with it.
 *
 * Verified here:
 *   - no admin key            -> 401 UNAUTHORIZED, session untouched;
 *   - wrong admin key         -> 401 UNAUTHORIZED, session untouched;
 *   - key in x-admin-key      -> 200, session expired ('admin_expired');
 *   - key in the JSON body    -> 200 (internal callers that already POST JSON);
 *   - the guard runs BEFORE the sessionId is validated, so an unauthenticated
 *     caller cannot probe which ids exist;
 *   - an authenticated caller that omits sessionId still gets its 400.
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
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-expire-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = ''; // mock Omada: no real controller call
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const sessionService = require('../src/services/session');
const { ADMIN_API_KEY } = require('../src/config');

const MAC = 'aa:bb:cc:dd:ee:ff';

async function applySchema() {
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'db', 'schema.sql'),
    'utf8'
  );
  await getDb().exec(schema);
}

/** Create a live session, as if the guest had just redeemed a voucher. */
async function seedSession(sessionId, voucherType = 'standard') {
  await sessionService.recordSession({
    sessionId,
    clientMac: MAC,
    duration: 60,
    voucherType,
    totalDurationSeconds: 3600,
  });
}

/** The stored state/expire_reason for a session. */
async function rowOf(sessionId) {
  return getDb().getOne(
    'SELECT state, expire_reason FROM sessions WHERE session_id = ?',
    [sessionId]
  );
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

describe('POST /api/session/expire — admin authorization', () => {
  test('the configured key is the one the deployment env supplied', () => {
    expect(ADMIN_API_KEY).toBe('test-admin-key');
  });

  test('no admin key is rejected with 401 and the session keeps running', async () => {
    await seedSession('sess_expire_nokey');

    const res = await request(app)
      .post('/api/session/expire')
      .send({ sessionId: 'sess_expire_nokey' });

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(res.body.code).toBe('UNAUTHORIZED');

    // Nothing was expired: the guest still has their time.
    const row = await rowOf('sess_expire_nokey');
    expect(row.state).toBe('active');
    expect(row.expire_reason).toBeNull();
  });

  test('a wrong admin key is rejected with 401 and the session keeps running', async () => {
    await seedSession('sess_expire_badkey');

    const res = await request(app)
      .post('/api/session/expire')
      .set('x-admin-key', 'not-the-admin-key')
      .send({ sessionId: 'sess_expire_badkey' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('UNAUTHORIZED');

    const row = await rowOf('sess_expire_badkey');
    expect(row.state).toBe('active');
  });

  test('a wrong key supplied in the body is rejected too', async () => {
    await seedSession('sess_expire_badbody');

    const res = await request(app)
      .post('/api/session/expire')
      .send({ sessionId: 'sess_expire_badbody', adminKey: 'not-the-admin-key' });

    expect(res.status).toBe(401);
    expect((await rowOf('sess_expire_badbody')).state).toBe('active');
  });

  test('the guard runs before sessionId validation (no id probing)', async () => {
    const res = await request(app).post('/api/session/expire').send({});

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('UNAUTHORIZED');
  });

  test('the x-admin-key header expires the session', async () => {
    await seedSession('sess_expire_ok');

    const res = await request(app)
      .post('/api/session/expire')
      .set('x-admin-key', 'test-admin-key')
      .send({ sessionId: 'sess_expire_ok' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.state).toBe('expired');

    const row = await rowOf('sess_expire_ok');
    expect(row.state).toBe('expired');
    expect(row.expire_reason).toBe('admin_expired');
  });

  test('the body adminKey is accepted for internal callers', async () => {
    await seedSession('sess_expire_body');

    const res = await request(app)
      .post('/api/session/expire')
      .send({ sessionId: 'sess_expire_body', adminKey: 'test-admin-key' });

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('expired');
    expect((await rowOf('sess_expire_body')).expire_reason).toBe('admin_expired');
  });

  test('an authenticated caller that omits sessionId still gets 400', async () => {
    const res = await request(app)
      .post('/api/session/expire')
      .set('x-admin-key', 'test-admin-key')
      .send({});

    expect(res.status).toBe(400);
  });

  test('an authenticated caller gets 404 for an unknown session', async () => {
    const res = await request(app)
      .post('/api/session/expire')
      .set('x-admin-key', 'test-admin-key')
      .send({ sessionId: 'sess_does_not_exist' });

    expect(res.status).toBe(404);
  });
});
