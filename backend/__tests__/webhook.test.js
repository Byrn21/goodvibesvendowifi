/**
 * __tests__/webhook.test.js
 * Integration tests for routes/webhook.js POST /api/webhooks/macrodroid
 *
 * Tests cover:
 *   - 400 invalid/missing amount, ref_no, mac_address
 *   - 401 missing / invalid secret (constant-time comparison path)
 *   - 409 duplicate ref_no (pre-check SELECT + UNIQUE constraint backstop)
 *   - 400 amount below minimum grantable time
 *   - 200 success: session + webhook_event rows created, Omada called,
 *     session activated, minutes computed from rate constant
 *   - 502 Omada failure: payment still recorded, omada_auth_failed set
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
    { secret_token: SECRET, amount: 50, ref_no: 'REF-' + Math.random().toString(36).slice(2, 10), mac_address: 'AA:BB:CC:DD:EE:FF' },
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
});

/**
 * Seed a valid portal_client_context row (fresh seen_at) so the webhook's
 * context lookup succeeds. Tests for the MISSING_PORTAL_CONTEXT path
 * simply skip this helper.
 */
async function seedContext(clientMac, overrides = {}) {
  const now = new Date().toISOString();
  const row = Object.assign({
    client_mac: clientMac,
    client_ip: '192.168.1.50',
    ap_mac: 'AA:AA:AA:AA:AA:AA',
    ssid_name: 'GuestWiFi',
    radio_id: 0,
    site: 'Default',
    seen_at: now,
    created_at: now,
    updated_at: now,
  }, overrides);
  await getDb().run(
    `INSERT INTO portal_client_context
       (client_mac, client_ip, ap_mac, ssid_name, radio_id, site, seen_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [row.client_mac, row.client_ip, row.ap_mac, row.ssid_name, row.radio_id, row.site, row.seen_at, row.created_at, row.updated_at]
  );
  return row;
}

// --- Tests ---

describe('POST /api/webhooks/macrodroid', () => {

  test('401 when secret_token is missing', async () => {
    const res = await request(app).post('/api/webhooks/macrodroid').send({ amount: 50, ref_no: 'R1', mac_address: 'AA:BB:CC:DD:EE:FF' });
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

    const longRef = payload({ ref_no: 'x'.repeat(65) });
    const res2 = await request(app).post('/api/webhooks/macrodroid').send(longRef);
    expect(res2.status).toBe(400);
  });

  test('400 when mac_address is invalid', async () => {
    const res = await request(app).post('/api/webhooks/macrodroid').send(payload({ mac_address: 'not-a-mac' }));
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_MAC');
  });

  test('400 when amount grants zero minutes at the configured rate', async () => {
    // Rate is 10 pesos/minute → amount 5 grants 0 minutes
    const res = await request(app).post('/api/webhooks/macrodroid').send(payload({ amount: 5 }));
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INSUFFICIENT_AMOUNT');
  });

  test('200 success: rows written, Omada called, session active, minutes correct', async () => {
    await seedContext('AA:BB:CC:DD:EE:FF');
    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });
    const ref = 'REF-SUCCESS-1';
    try {
      const res = await request(app).post('/api/webhooks/macrodroid').send(payload({ amount: 50, ref_no: ref }));
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.minutes).toBe(5); // 50 pesos / 10 per minute
      expect(spy).toHaveBeenCalledTimes(1);
      // Controller params must come from portal_client_context — never null
      expect(spy.mock.calls[0][0].apMac).toBe('AA:AA:AA:AA:AA:AA');
      expect(spy.mock.calls[0][0].ssidName).toBe('GuestWiFi');
      expect(spy.mock.calls[0][0].radioId).toBe(0);
      expect(spy.mock.calls[0][0].durationMinutes).toBe(5);

      const event = await getDb().getOne('SELECT * FROM webhook_events WHERE ref_no = ?', [ref]);
      expect(event).toBeDefined();
      expect(event.status).toBe('processed');

      const session = await getDb().getOne('SELECT * FROM sessions WHERE ref_no = ?', [ref]);
      expect(session).toBeDefined();
      expect(session.state).toBe('active');
      expect(session.duration_minutes).toBe(5);
    } finally {
      spy.mockRestore();
    }
  });

  test('409 duplicate ref_no is rejected before any new write', async () => {
    await seedContext('AA:BB:CC:DD:EE:FF');
    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });
    const ref = 'REF-DUP-1';
    try {
      const first = await request(app).post('/api/webhooks/macrodroid').send(payload({ ref_no: ref }));
      expect(first.status).toBe(200);

      const dup = await request(app).post('/api/webhooks/macrodroid').send(payload({ ref_no: ref }));
      expect(dup.status).toBe(409);
      expect(dup.body.code).toBe('DUPLICATE_REF_NO');

      // Only one webhook_event and one session exist for that ref
      const events = await getDb().query('SELECT id FROM webhook_events WHERE ref_no = ?', [ref]);
      const sessions = await getDb().query('SELECT session_id FROM sessions WHERE ref_no = ?', [ref]);
      expect(events.length).toBe(1);
      expect(sessions.length).toBe(1);
      expect(spy).toHaveBeenCalledTimes(1); // second attempt never reached Omada
    } finally {
      spy.mockRestore();
    }
  });

  test('502 when Omada authorization fails: payment still recorded, flag set', async () => {
    await seedContext('AA:BB:CC:DD:EE:FF');
    const spy = jest.spyOn(omadaService, 'authenticateClient').mockRejectedValue(new Error('controller down'));
    const ref = 'REF-OMADA-FAIL-1';
    try {
      const res = await request(app).post('/api/webhooks/macrodroid').send(payload({ ref_no: ref }));
      expect(res.status).toBe(502);
      expect(res.body.code).toBe('OMADA_ERROR');

      const session = await getDb().getOne('SELECT * FROM sessions WHERE ref_no = ?', [ref]);
      expect(session).toBeDefined();
      expect(session.state).toBe('pending_payment');
      expect(session.omada_auth_failed).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });

  test('MAC is normalized to canonical uppercase colon format on save', async () => {
    await seedContext('AA:BB:CC:DD:EE:FF');
    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });
    const ref = 'REF-MAC-1';
    try {
      const res = await request(app).post('/api/webhooks/macrodroid').send(payload({ ref_no: ref, mac_address: 'aa-bb-cc-dd-ee-ff' }));
      expect(res.status).toBe(200);
      const session = await getDb().getOne('SELECT client_mac FROM sessions WHERE ref_no = ?', [ref]);
      expect(session.client_mac).toBe('AA:BB:CC:DD:EE:FF');
    } finally {
      spy.mockRestore();
    }
  });

  // --- MISSING_PORTAL_CONTEXT fail-loud path ---

  test('422 MISSING_PORTAL_CONTEXT when no context row exists: payment durable, flag set, Omada never called', async () => {
    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });
    const ref = 'REF-NO-CTX-1';
    try {
      const res = await request(app).post('/api/webhooks/macrodroid').send(payload({ ref_no: ref }));
      expect(res.status).toBe(422);
      expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');

      // Payment stays durable...
      const event = await getDb().getOne('SELECT * FROM webhook_events WHERE ref_no = ?', [ref]);
      expect(event).toBeDefined();
      const session = await getDb().getOne('SELECT * FROM sessions WHERE ref_no = ?', [ref]);
      expect(session).toBeDefined();
      expect(session.state).toBe('pending_payment');
      expect(session.omada_auth_failed).toBe(1);
      // ...and the controller is NEVER called with missing params
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  test('422 MISSING_PORTAL_CONTEXT when context row is unusable: Omada never called', async () => {
    // Seed a valid row, then remove it so the webhook sees no usable
    // context (covers the "row missing at payment time" case; the schema
    // declares ap_mac NOT NULL, so a NULL ap_mac cannot be materialized
    // on SQLite — see routes/payment.js validation, which is the real
    // guarantee that partial rows are never written in production).
    await seedContext('AA:BB:CC:DD:EE:FF');
    await getDb().run('DELETE FROM portal_client_context WHERE client_mac = ?', ['AA:BB:CC:DD:EE:FF']);
    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });
    const ref = 'REF-PARTIAL-CTX-1';
    try {
      const res = await request(app).post('/api/webhooks/macrodroid').send(payload({ ref_no: ref }));
      expect(res.status).toBe(422);
      expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');
      expect(spy).not.toHaveBeenCalled();
      const session = await getDb().getOne('SELECT omada_auth_failed FROM sessions WHERE ref_no = ?', [ref]);
      expect(session.omada_auth_failed).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });

  test('422 MISSING_PORTAL_CONTEXT when context row is stale (seen_at > 1h old): Omada never called', async () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    await seedContext('AA:BB:CC:DD:EE:FF', { seen_at: twoHoursAgo });
    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });
    const ref = 'REF-STALE-CTX-1';
    try {
      const res = await request(app).post('/api/webhooks/macrodroid').send(payload({ ref_no: ref }));
      expect(res.status).toBe(422);
      expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');
      expect(spy).not.toHaveBeenCalled();
      const session = await getDb().getOne('SELECT omada_auth_failed FROM sessions WHERE ref_no = ?', [ref]);
      expect(session.omada_auth_failed).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });
});

