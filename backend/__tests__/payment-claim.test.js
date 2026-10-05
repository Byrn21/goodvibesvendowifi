/**
 * __tests__/payment-claim.test.js
 * Integration tests for:
 *   POST /api/payment/claim   (routes/payment.js)
 *   GET  /api/session/status?mac=...  (routes/session.js)
 *
 * Patterns follow backend/__tests__/webhook.test.js:
 *   - Temp SQLite database created before requiring db/client.js
 *   - Schema applied via schema.sql
 *   - supertest against the Express app exported from src/server.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-claim-test-'));
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

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const omadaService = require('../src/services/omada');

const MAC = 'AA:BB:CC:DD:EE:FF';

async function seedContext(clientMac = MAC, overrides = {}) {
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

async function seedProcessedEvent(refNo, sessionId, amount = 50) {
  await getDb().run(
    `INSERT INTO webhook_events (event_id, ref_no, session_id, provider, event_type, amount, status)
     VALUES (?, ?, ?, 'macrodroid', 'payment_received', ?, 'processed')`,
    ['evt_' + sessionId, refNo, sessionId, amount]
  );
}

async function seedSession(sessionId, refNo, state, clientMac = MAC, durationMinutes = 5) {
  const now = new Date().toISOString();
  await getDb().run(
    `INSERT INTO sessions
       (session_id, client_mac, ref_no, duration_minutes, voucher_type, state, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'paid', ?, ?, ?)`,
    [sessionId, clientMac, refNo, durationMinutes, state, now, now]
  );
}

beforeAll(async () => {
  const schema = fs.readFileSync(path.join(__dirname, '..', 'src', 'db', 'schema.sql'), 'utf8');
  await getDb().exec(schema);
});

afterAll(async () => {
  await closeDb();
  try {
    fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
  } catch (err) { /* best-effort cleanup */ }
});

beforeEach(async () => {
  await getDb().exec('DELETE FROM sessions; DELETE FROM webhook_events; DELETE FROM portal_client_context;');
});

describe('POST /api/payment/claim', () => {
  test('400 when ref_no is missing / non-numeric', async () => {
    for (const bad of ['', '123', 'abcd123456'] ) {
      const res = await request(app).post('/api/payment/claim').send({ ref_no: bad, client_mac: MAC });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_REF_NO');
    }
  });

  test('400 when client_mac is invalid', async () => {
    const res = await request(app).post('/api/payment/claim').send({ ref_no: '1234567890123', client_mac: 'nope' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_CLIENT_MAC');
  });

  test('unknown ref_no is stored pending (not an error) and returns pending', async () => {
    const ref = '1234567890123';
    const res = await request(app).post('/api/payment/claim').send({ ref_no: ref, client_mac: MAC });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.pending).toBe(true);
    expect(res.body.code).toBe('PENDING_VERIFICATION');

    const event = await getDb().getOne('SELECT * FROM webhook_events WHERE ref_no = ?', [ref]);
    expect(event).toBeDefined();
    expect(event.status).toBe('pending');
    expect(event.provider).toBe('manual_claim');

    const session = await getDb().getOne('SELECT * FROM sessions WHERE ref_no = ?', [ref]);
    expect(session).toBeDefined();
    expect(session.state).toBe('pending_verification');
    expect(session.client_mac).toBe(MAC);
  });

  test('repeated claim of the same ref is idempotent (one event row)', async () => {
    const ref = '1234567890124';
    const first = await request(app).post('/api/payment/claim').send({ ref_no: ref, client_mac: MAC });
    const second = await request(app).post('/api/payment/claim').send({ ref_no: ref, client_mac: MAC });
    expect(first.body.pending).toBe(true);
    expect(second.body.pending).toBe(true);

    const events = await getDb().query('SELECT id FROM webhook_events WHERE ref_no = ?', [ref]);
    const sessions = await getDb().query('SELECT session_id FROM sessions WHERE ref_no = ?', [ref]);
    expect(events.length).toBe(1);
    expect(sessions.length).toBe(1);
  });

  test('processed webhook_event triggers Omada authorization and activates session', async () => {
    await seedContext();
    await seedProcessedEvent('1234567890125', 'sess_claim1', 50);
    await seedSession('sess_claim1', '1234567890125', 'pending_payment');

    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });
    try {
      const res = await request(app).post('/api/payment/claim')
        .send({ ref_no: '1234567890125', client_mac: MAC });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.minutes).toBe(5);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0][0].apMac).toBe('AA:AA:AA:AA:AA:AA');
      expect(spy.mock.calls[0][0].ssidName).toBe('GuestWiFi');
      expect(spy.mock.calls[0][0].radioId).toBe(0);

      const session = await getDb().getOne('SELECT * FROM sessions WHERE ref_no = ?', ['1234567890125']);
      expect(session.state).toBe('active');
      expect(session.omada_auth_failed).toBe(0);
    } finally {
      spy.mockRestore();
    }
  });

  test('processed event with an already-active session does not re-authorize', async () => {
    await seedContext();
    await seedProcessedEvent('1234567890126', 'sess_claim2', 50);
    await seedSession('sess_claim2', '1234567890126', 'active');

    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });
    try {
      const res = await request(app).post('/api/payment/claim')
        .send({ ref_no: '1234567890126', client_mac: MAC });
      expect(res.status).toBe(200);
      expect(res.body.alreadyActive).toBe(true);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  test('422 MISSING_PORTAL_CONTEXT when context is absent — never calls Omada', async () => {
    await seedProcessedEvent('1234567890127', 'sess_claim3', 50);
    await seedSession('sess_claim3', '1234567890127', 'pending_payment');

    const spy = jest.spyOn(omadaService, 'authenticateClient').mockResolvedValue({ success: true });
    try {
      const res = await request(app).post('/api/payment/claim')
        .send({ ref_no: '1234567890127', client_mac: MAC });
      expect(res.status).toBe(422);
      expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  test('502 when Omada rejects: session flagged omada_auth_failed', async () => {
    await seedContext();
    await seedProcessedEvent('1234567890128', 'sess_claim4', 50);
    await seedSession('sess_claim4', '1234567890128', 'pending_payment');

    const spy = jest.spyOn(omadaService, 'authenticateClient').mockRejectedValue(new Error('controller down'));
    try {
      const res = await request(app).post('/api/payment/claim')
        .send({ ref_no: '1234567890128', client_mac: MAC });
      expect(res.status).toBe(502);
      expect(res.body.code).toBe('OMADA_ERROR');
      const session = await getDb().getOne('SELECT omada_auth_failed FROM sessions WHERE ref_no = ?', ['1234567890128']);
      expect(session.omada_auth_failed).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('GET /api/payment/methods', () => {
  test('returns gcash/maya/qrph with empty defaults when env is unset', async () => {
    const keys = ['GCASH_NAME', 'GCASH_NUMBER', 'GCASH_QR_B64',
      'MAYA_NAME', 'MAYA_NUMBER', 'MAYA_QR_B64',
      'QRPH_NAME', 'QRPH_NUMBER', 'QRPH_QR_B64'];
    const saved = {};
    keys.forEach((k) => { saved[k] = process.env[k]; delete process.env[k]; });
    try {
      const res = await request(app).get('/api/payment/methods');
      expect(res.status).toBe(200);
      expect(res.headers['cache-control']).toBe('no-store');

      ['gcash', 'maya', 'qrph'].forEach((id) => {
        expect(res.body[id]).toBeDefined();
        expect(res.body[id].qrImage).toBe('');
        expect(res.body[id].accountName).toBe('');
        expect(res.body[id].accountNumber).toBe('');
        expect(Array.isArray(res.body[id].instructions)).toBe(true);
        expect(res.body[id].instructions.length).toBeGreaterThan(0);
      });
      expect(res.body.gcash.name).toBe('GCash');
      expect(res.body.maya.name).toBe('Maya');
      expect(res.body.qrph.name).toBe('QR Ph');
    } finally {
      keys.forEach((k) => { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; });
    }
  });

  test('serves receiver details / QR images from environment variables', async () => {
    const saved = {};
    const set = {
      GCASH_NAME: 'Store GCash', GCASH_NUMBER: '+639000000000',
      GCASH_QR_B64: 'data:image/png;base64,AAAA',
      MAYA_NAME: 'Store Maya', MAYA_NUMBER: '+639111111111',
      MAYA_QR_B64: 'data:image/png;base64,BBBB',
      QRPH_NAME: 'Store QRPh', QRPH_NUMBER: '+639222222222',
      QRPH_QR_B64: 'data:image/png;base64,CCCC',
    };
    Object.keys(set).forEach((k) => {
      saved[k] = process.env[k];
      process.env[k] = set[k];
    });
    try {
      const res = await request(app).get('/api/payment/methods');
      expect(res.status).toBe(200);
      expect(res.body.gcash).toMatchObject({
        accountName: 'Store GCash', accountNumber: '+639000000000', qrImage: 'data:image/png;base64,AAAA',
      });
      expect(res.body.maya).toMatchObject({
        accountName: 'Store Maya', accountNumber: '+639111111111', qrImage: 'data:image/png;base64,BBBB',
      });
      expect(res.body.qrph).toMatchObject({
        accountName: 'Store QRPh', accountNumber: '+639222222222', qrImage: 'data:image/png;base64,CCCC',
      });
    } finally {
      Object.keys(set).forEach((k) => {
        if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
      });
    }
  });

  test('is reachable without authentication', async () => {
    const res = await request(app).get('/api/payment/methods');
    expect(res.status).toBe(200);
    expect(res.body.gcash.name).toBe('GCash');
  });
});

describe('GET /api/session/status?mac=', () => {
  test('returns the active session for a device MAC (any case/format)', async () => {
    await seedSession('sess_status1', null, 'active', MAC, 60);
    const res = await request(app).get('/api/session/status?mac=aa-bb-cc-dd-ee-ff');
    expect(res.status).toBe(200);
    expect(res.body.state).toBe('active');
    expect(res.body.sessionId).toBe('sess_status1');
  });

  test('returns 404 when no session exists for the MAC', async () => {
    const res = await request(app).get('/api/session/status?mac=11:22:33:44:55:66');
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('SESSION_NOT_FOUND');
  });

  test('returns a pending_verification session (so the client keeps polling)', async () => {
    await seedSession('sess_status2', null, 'pending_verification', MAC, 60);
    const res = await request(app).get('/api/session/status?mac=' + encodeURIComponent(MAC));
    expect(res.status).toBe(200);
    expect(res.body.state).toBe('pending_verification');
  });

  test('still supports the existing sessionId lookup', async () => {
    await seedSession('sess_status3', null, 'active', MAC, 60);
    const res = await request(app).get('/api/session/status?sessionId=sess_status3');
    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe('sess_status3');
  });
});
