/**
 * __tests__/admin-claims.test.js
 * Integration tests for the pending-claims dashboard routes in admin.js:
 *   GET  /api/admin/claims/pending
 *   POST /api/admin/claims/approve
 *   POST /api/admin/claims/reject
 *
 * Auth model under test: the `x-admin-password` header matched against
 * process.env.ADMIN_PASSWORD, failing closed when unset.
 *
 * Follows the setup pattern of __tests__/admin.test.js: temp SQLite DB,
 * schema applied before requiring db/client.js, supertest against the
 * Express app exported from src/server.js.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Environment setup MUST happen before requiring any backend modules.
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-claims-test-'));
const TEST_DB_PATH = path.join(TEST_DB_DIR, 'test.db');

process.env.DATABASE_URL = 'sqlite:' + TEST_DB_PATH;
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.ADMIN_USERNAME = 'admin';
process.env.ADMIN_PASSWORD = 'test-admin-password';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = ''; // mock mode
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const omadaService = require('../src/services/omada');

const PASSWORD = 'test-admin-password';
const CLIENT_MAC = 'AA:BB:CC:DD:EE:01';
const AP_MAC = '11:22:33:44:55:66';
const SSID = 'GoodVibes-Guest';

// ── Helpers ──────────────────────────────────────────────────────────────

async function applySchema() {
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'db', 'schema.sql'),
    'utf8'
  );
  await getDb().exec(schema);
}

async function seedContext(opts) {
  const o = opts || {};
  await getDb().run(
    `INSERT INTO portal_client_context
       (client_mac, client_ip, ap_mac, ssid_name, radio_id, site, seen_at)
     VALUES (?, ?, ?, ?, ?, 'Default', ?)`,
    [
      o.clientMac || CLIENT_MAC,
      o.clientIp === undefined ? '10.0.0.50' : o.clientIp,
      o.apMac === undefined ? AP_MAC : o.apMac,
      o.ssid === undefined ? SSID : o.ssid,
      o.radioId === undefined ? 0 : o.radioId,
      new Date().toISOString(),
    ]
  );
}

async function seedClaim(opts) {
  const o = opts || {};
  const refNo = o.refNo || '1234567890123';
  const sessionId = o.sessionId || ('sess_' + refNo);
  const clientMac = o.clientMac || CLIENT_MAC;
  const createdAt = o.createdAt || new Date().toISOString();

  await getDb().run(
    `INSERT INTO webhook_events
       (event_id, ref_no, session_id, provider, event_type, amount, status, processed_at)
     VALUES (?, ?, ?, 'manual_claim', 'manual_reference_submitted', ?, ?, ?)`,
    ['evt_' + refNo, refNo, sessionId, o.amount === undefined ? null : o.amount,
      o.status || 'pending', createdAt]
  );

  if (o.withSession !== false) {
    await getDb().run(
      `INSERT INTO sessions
         (session_id, client_mac, ref_no, client_ip, ap_mac, ssid_name,
          duration_minutes, voucher_type, state, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 60, 'paid', ?, ?, ?)`,
      [sessionId, clientMac, refNo, '10.0.0.50', AP_MAC, SSID,
        o.sessionState || 'pending_verification', createdAt, createdAt]
    );
  }
  return { refNo, sessionId, clientMac };
}

async function getClaim(refNo) {
  return getDb().getOne('SELECT * FROM webhook_events WHERE ref_no = ?', [refNo]);
}
async function getSession(sessionId) {
  return getDb().getOne('SELECT * FROM sessions WHERE session_id = ?', [sessionId]);
}

// ── Lifecycle ────────────────────────────────────────────────────────────

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
  await getDb().exec('DELETE FROM sessions; DELETE FROM webhook_events; DELETE FROM portal_client_context;');
  jest.restoreAllMocks();
});

// ── Auth ─────────────────────────────────────────────────────────────────

describe('claims dashboard auth (x-admin-password)', () => {
  test('rejects a request with no password header (401)', async () => {
    const res = await request(app).get('/api/admin/claims/pending');
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('rejects a request with the wrong password (401)', async () => {
    const res = await request(app)
      .get('/api/admin/claims/pending')
      .set('x-admin-password', 'nope');
    expect(res.status).toBe(401);
  });

  test('does NOT accept the API key as the dashboard password', async () => {
    const res = await request(app)
      .get('/api/admin/claims/pending')
      .set('x-admin-password', 'test-admin-key');
    expect(res.status).toBe(401);
  });

  test('fails CLOSED when ADMIN_PASSWORD is unset', async () => {
    const saved = process.env.ADMIN_PASSWORD;
    delete process.env.ADMIN_PASSWORD;
    try {
      const res = await request(app)
        .get('/api/admin/claims/pending')
        .set('x-admin-password', 'anything');
      expect(res.status).toBe(401);
      expect(res.body.code).toBe('ADMIN_NOT_CONFIGURED');
    } finally {
      process.env.ADMIN_PASSWORD = saved;
    }
  });

  test('accepts the correct password (200)', async () => {
    const res = await request(app)
      .get('/api/admin/claims/pending')
      .set('x-admin-password', PASSWORD);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('existing API-key routes still work unchanged (regression)', async () => {
    const res = await request(app)
      .get('/api/admin/me')
      .set('X-API-Key', 'test-admin-key');
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('admin');
  });
});

// ── GET /claims/pending ──────────────────────────────────────────────────

describe('GET /api/admin/claims/pending', () => {
  test('returns pending claims with client_mac joined from sessions, newest first', async () => {
    await seedContext();
    await seedClaim({ refNo: '111111', createdAt: '2026-01-01T00:00:00.000Z', sessionId: 'sess_111111' });
    await seedClaim({ refNo: '222222', createdAt: '2026-02-01T00:00:00.000Z', sessionId: 'sess_222222' });

    const res = await request(app)
      .get('/api/admin/claims/pending')
      .set('x-admin-password', PASSWORD);

    expect(res.status).toBe(200);
    expect(res.body.claims).toHaveLength(2);
    expect(res.body.claims[0].ref_no).toBe('222222'); // newest first
    expect(res.body.claims[1].ref_no).toBe('111111');
    expect(res.body.claims[0].client_mac).toBe(CLIENT_MAC);
    expect(res.body.claims[0].timestamp).toBeTruthy();
  });

  test('excludes processed and rejected claims', async () => {
    await seedContext();
    await seedClaim({ refNo: '333333', status: 'pending' });
    await seedClaim({ refNo: '444444', status: 'processed' });
    await seedClaim({ refNo: '555555', status: 'rejected' });

    const res = await request(app)
      .get('/api/admin/claims/pending')
      .set('x-admin-password', PASSWORD);

    const refs = res.body.claims.map(c => c.ref_no);
    expect(refs).toEqual(['333333']);
  });

  test('includes amount when present (null for manual claims)', async () => {
    await seedContext();
    await seedClaim({ refNo: '666666', amount: 5000 });
    await seedClaim({ refNo: '777777', amount: null });

    const res = await request(app)
      .get('/api/admin/claims/pending')
      .set('x-admin-password', PASSWORD);

    const byRef = {};
    res.body.claims.forEach(c => { byRef[c.ref_no] = c; });
    expect(byRef['666666'].amount).toBe(5000);
    expect(byRef['777777'].amount).toBeNull();
  });
});

// ── POST /claims/approve ─────────────────────────────────────────────────

describe('POST /api/admin/claims/approve', () => {
  test('returns 400 when ref_no is missing', async () => {
    const res = await request(app)
      .post('/api/admin/claims/approve')
      .set('x-admin-password', PASSWORD)
      .send({ client_mac: CLIENT_MAC });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('MISSING_REF_NO');
  });

  test('returns 400 when client_mac is missing or invalid', async () => {
    const res = await request(app)
      .post('/api/admin/claims/approve')
      .set('x-admin-password', PASSWORD)
      .send({ ref_no: '111111', client_mac: 'not-a-mac' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('MISSING_CLIENT_MAC');
  });

  test('returns 404 when the claim does not exist', async () => {
    const res = await request(app)
      .post('/api/admin/claims/approve')
      .set('x-admin-password', PASSWORD)
      .send({ ref_no: '999999', client_mac: CLIENT_MAC });
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('CLAIM_NOT_FOUND');
  });

  test('returns 404 and leaves the claim pending when portal context is missing', async () => {
    // No seedContext()
    const { refNo } = await seedClaim({ refNo: '101010' });

    const res = await request(app)
      .post('/api/admin/claims/approve')
      .set('x-admin-password', PASSWORD)
      .send({ ref_no: refNo, client_mac: CLIENT_MAC });

    expect(res.status).toBe(404);
    expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');

    const claim = await getClaim(refNo);
    expect(claim.status).toBe('pending');
  });

  test('returns 502 on Omada failure and leaves claim + session unchanged (retryable)', async () => {
    await seedContext();
    const { refNo, sessionId } = await seedClaim({ refNo: '121212' });

    jest.spyOn(omadaService, 'authenticateClient')
      .mockRejectedValue(Object.assign(new Error('boom'), { code: 'OMADA_TIMEOUT' }));

    const res = await request(app)
      .post('/api/admin/claims/approve')
      .set('x-admin-password', PASSWORD)
      .send({ ref_no: refNo, client_mac: CLIENT_MAC });

    expect(res.status).toBe(502);
    expect(res.body.code).toBe('OMADA_ERROR');

    const claim = await getClaim(refNo);
    expect(claim.status).toBe('pending'); // still visible / retryable
    const session = await getSession(sessionId);
    expect(session.state).toBe('pending_verification'); // state untouched
    expect(Number(session.omada_auth_failed)).toBe(1);   // diagnostic flag only
  });

  test('approves: calls Omada with the exact ctx shape, activates the session and marks the claim processed', async () => {
    await seedContext();
    const { refNo, sessionId } = await seedClaim({ refNo: '131313' });

    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });

    const res = await request(app)
      .post('/api/admin/claims/approve')
      .set('x-admin-password', PASSWORD)
      .send({ ref_no: refNo, client_mac: CLIENT_MAC });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.expires_at).toBeTruthy();

    // ctx shape must match the existing payment/webhook callers exactly
    expect(spy).toHaveBeenCalledTimes(1);
    const ctx = spy.mock.calls[0][0];
    expect(ctx).toEqual({
      clientMac: CLIENT_MAC,
      clientIp: '10.0.0.50',
      apMac: AP_MAC,
      ssidName: SSID,
      radioId: 0,
      durationMinutes: 60, // default fallback (amount is NULL)
      sessionId,
    });

    const claim = await getClaim(refNo);
    expect(claim.status).toBe('processed');

    const session = await getSession(sessionId);
    expect(session.state).toBe('active');
    expect(session.started_at).toBeTruthy();
    expect(session.expires_at).toBeTruthy();
  });

  test('uses the claim amount for duration when present', async () => {
    await seedContext();
    // PESOS_PER_MINUTE defaults to 10 → amount 120 = 12 minutes.
    const { refNo, sessionId } = await seedClaim({ refNo: '141414', amount: 120 });

    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });

    const res = await request(app)
      .post('/api/admin/claims/approve')
      .set('x-admin-password', PASSWORD)
      .send({ ref_no: refNo, client_mac: CLIENT_MAC });

    expect(res.status).toBe(200);
    expect(spy.mock.calls[0][0].durationMinutes).toBe(12);
    expect((await getSession(sessionId)).state).toBe('active');
  });

  test('returns 409 for a claim that was already handled', async () => {
    await seedContext();
    const { refNo } = await seedClaim({ refNo: '151515', status: 'processed' });

    const res = await request(app)
      .post('/api/admin/claims/approve')
      .set('x-admin-password', PASSWORD)
      .send({ ref_no: refNo, client_mac: CLIENT_MAC });

    expect(res.status).toBe(409);
    expect(res.body.code).toBe('CLAIM_NOT_PENDING');
  });
});

// ── POST /claims/reject ──────────────────────────────────────────────────

describe('POST /api/admin/claims/reject', () => {
  test('returns 400 when ref_no is missing', async () => {
    const res = await request(app)
      .post('/api/admin/claims/reject')
      .set('x-admin-password', PASSWORD)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('MISSING_REF_NO');
  });

  test('returns 404 when there is no pending claim for the reference', async () => {
    const res = await request(app)
      .post('/api/admin/claims/reject')
      .set('x-admin-password', PASSWORD)
      .send({ ref_no: '888888' });
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('CLAIM_NOT_FOUND');
  });

  test('rejects a pending claim', async () => {
    await seedContext();
    const { refNo } = await seedClaim({ refNo: '161616' });

    const res = await request(app)
      .post('/api/admin/claims/reject')
      .set('x-admin-password', PASSWORD)
      .send({ ref_no: refNo });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect((await getClaim(refNo)).status).toBe('rejected');
  });

  test('a rejected claim no longer appears in the pending list', async () => {
    await seedContext();
    const { refNo } = await seedClaim({ refNo: '171717' });

    await request(app)
      .post('/api/admin/claims/reject')
      .set('x-admin-password', PASSWORD)
      .send({ ref_no: refNo });

    const list = await request(app)
      .get('/api/admin/claims/pending')
      .set('x-admin-password', PASSWORD);
    expect(list.body.claims.map(c => c.ref_no)).not.toContain(refNo);
  });
});
