/**
 * __tests__/webhook.test.js
 * Integration tests for routes/webhook.js POST /api/webhooks/macrodroid
 *
 * The webhook is now DECOUPLED from the Omada controller and from the client
 * MAC address: it only records the payment as an 'unclaimed' webhook_events
 * row that the customer reconciles later via POST /api/payment/claim.
 *
 * Tests cover:
 *   - 401 missing / invalid secret (constant-time comparison path)
 *   - 400 invalid/missing amount, ref_no
 *   - 200 success: an 'unclaimed' webhook_events row is written
 *   - mac_address is ignored / not required (no MAC validation)
 *   - 409 duplicate ref_no (pre-check SELECT + UNIQUE constraint backstop)
 *   - no sessions are created and Omada is never contacted
 *
 * Patterns follow backend/__tests__/admin.test.js:
 *   - Temp SQLite database created before requiring db/client.js
 *   - Schema applied via schema.sql
 *   - supertest with Express app exported from src/server.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Environment setup MUST happen before requiring any backend modules
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-webhook-test-'));
const TEST_DB_PATH = path.join(TEST_DB_DIR, 'test.db');

process.env.DATABASE_URL = 'sqlite:' + TEST_DB_PATH;
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';          // forces mock mode in omada.js
process.env.OMADA_MOCK = 'true';
process.env.MACRODROID_WEBHOOK_SECRET = 'test-webhook-secret-abc123';
process.env.MACRODROID_PESOS_PER_MINUTE = '10';
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';

// Require the Express app AFTER env is set
const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const omadaService = require('../src/services/omada');

const SECRET = 'test-webhook-secret-abc123';

function payload(overrides = {}) {
  return Object.assign(
    { secret_token: SECRET, amount: 50, ref_no: 'REF-' + Math.random().toString(36).slice(2, 10) },
    overrides
  );
}

// --- Lifecycle ---

beforeAll(async () => {
  const schema = fs.readFileSync(path.join(__dirname, '..', 'src', 'db', 'schema.sql'), 'utf8');
  await getDb().exec(schema);
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
  await getDb().exec('DELETE FROM sessions; DELETE FROM webhook_events; DELETE FROM portal_client_context;');
  jest.restoreAllMocks();
});

// --- Tests ---

describe('POST /api/webhooks/macrodroid', () => {

  test('401 when secret_token is missing', async () => {
    const res = await request(app).post('/api/webhooks/macrodroid').send({ amount: 50, ref_no: 'R1' });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('MISSING_SECRET');
  });

  test('401 when secret_token is wrong', async () => {
    const res = await request(app).post('/api/webhooks/macrodroid').send(payload({ secret_token: 'wrong-secret' }));
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('INVALID_SECRET');
  });

  test('400 when amount is missing or non-positive', async () => {
    for (const bad of [undefined, 0, -5, 'abc']) {
      const body = payload();
      if (bad === undefined) delete body.amount; else body.amount = bad;
      const res = await request(app).post('/api/webhooks/macrodroid').send(body);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_AMOUNT');
    }
  });

  test('400 when ref_no is missing or too long', async () => {
    const noRef = payload(); delete noRef.ref_no;
    const res1 = await request(app).post('/api/webhooks/macrodroid').send(noRef);
    expect(res1.status).toBe(400);
    expect(res1.body.code).toBe('INVALID_REF_NO');

    const longRef = payload({ ref_no: 'x'.repeat(65) });
    const res2 = await request(app).post('/api/webhooks/macrodroid').send(longRef);
    expect(res2.status).toBe(400);
    expect(res2.body.code).toBe('INVALID_REF_NO');
  });

  test('200 success: records an unclaimed webhook_events row (minimal body)', async () => {
    const ref = 'REF-SUCCESS-1';
    const res = await request(app).post('/api/webhooks/macrodroid').send(payload({ amount: 50, ref_no: ref }));
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true });

    const event = await getDb().getOne('SELECT * FROM webhook_events WHERE ref_no = ?', [ref]);
    expect(event).toBeDefined();
    expect(event.status).toBe('unclaimed');
    expect(Number(event.amount)).toBe(50);
    expect(event.event_id).toMatch(/^evt_/);
  });

  test('does not require a mac_address and creates no session (decoupled)', async () => {
    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });
    const ref = 'REF-NO-MAC-1';
    try {
      const res = await request(app).post('/api/webhooks/macrodroid').send({
        secret_token: SECRET, amount: 100, ref_no: ref, // no mac_address at all
      });
      expect(res.status).toBe(200);

      const event = await getDb().getOne('SELECT status FROM webhook_events WHERE ref_no = ?', [ref]);
      expect(event.status).toBe('unclaimed');

      const sessions = await getDb().query('SELECT session_id FROM sessions WHERE ref_no = ?', [ref]);
      expect(sessions.length).toBe(0);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  test('ignores an invalid mac_address instead of rejecting it', async () => {
    const ref = 'REF-BAD-MAC-1';
    const res = await request(app).post('/api/webhooks/macrodroid').send(
      payload({ ref_no: ref, mac_address: 'not-a-mac' })
    );
    expect(res.status).toBe(200);
    const event = await getDb().getOne('SELECT status FROM webhook_events WHERE ref_no = ?', [ref]);
    expect(event.status).toBe('unclaimed');
  });

  test('409 duplicate ref_no is rejected before any new write', async () => {
    const ref = 'REF-DUP-1';
    const first = await request(app).post('/api/webhooks/macrodroid').send(payload({ ref_no: ref }));
    expect(first.status).toBe(200);

    const dup = await request(app).post('/api/webhooks/macrodroid').send(payload({ ref_no: ref }));
    expect(dup.status).toBe(409);
    expect(dup.body.code).toBe('DUPLICATE_REF_NO');

    const events = await getDb().query('SELECT id FROM webhook_events WHERE ref_no = ?', [ref]);
    expect(events.length).toBe(1);
  });
});
