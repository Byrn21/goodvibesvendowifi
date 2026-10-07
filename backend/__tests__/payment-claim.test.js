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

const MAC = 'AA:BB:CC:DD:EE:FF';

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
  await getDb().exec('DELETE FROM sessions; DELETE FROM vouchers; DELETE FROM webhook_events; DELETE FROM portal_client_context;');
});

describe('POST /api/payment/claim', () => {
  // Seed an 'unclaimed' webhook_events row (what the MacroDroid webhook writes).
  async function seedUnclaimed(refNo, amountPesos) {
    await getDb().run(
      `INSERT INTO webhook_events (event_id, ref_no, amount, status)
       VALUES (?, ?, ?, 'unclaimed')`,
      ['evt_' + refNo, refNo, amountPesos]
    );
  }

  // Seed a voucher whose price is INTEGER CENTAVOS (P50.00 = 5000).
  async function seedVoucher(code, priceCentavos, state = 'active', assignedRef = null) {
    await getDb().run(
      `INSERT INTO vouchers (code, type, duration_minutes, price, state, assigned_ref_no)
       VALUES (?, 'standard', 60, ?, ?, ?)`,
      [code, priceCentavos, state, assignedRef]
    );
  }

  test('400 when ref_suffix is missing or not exactly 4 digits', async () => {
    for (const bad of ['', '123', '12345', 'abcd', undefined]) {
      const res = await request(app).post('/api/payment/claim').send({ ref_suffix: bad });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_REF_SUFFIX');
    }
  });

  test('404 when no unclaimed payment ends with the suffix', async () => {
    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '9999' });
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('PAYMENT_NOT_FOUND');
    expect(res.body.error).toMatch(/not found or already claimed/i);
  });

  test('200: converts Pesos to centavos and claims the matching voucher + event together', async () => {
    await seedUnclaimed('REF-ABC1234', 50);                     // 50 pesos = 5000 centavos
    await seedVoucher('111111', 5000);                          // must be chosen
    await seedVoucher('222222', 5000, 'active', 'REF-OLD0001'); // already assigned -> skip

    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '1234' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.voucherCode).toBe('111111');
    expect(res.body.ref_no).toBe('REF-ABC1234');

    const voucher = await getDb().getOne('SELECT * FROM vouchers WHERE code = ?', ['111111']);
    expect(voucher.state).toBe('claimed');
    expect(voucher.assigned_ref_no).toBe('REF-ABC1234');

    const event = await getDb().getOne('SELECT * FROM webhook_events WHERE ref_no = ?', ['REF-ABC1234']);
    expect(event.status).toBe('claimed');
  });

  test('404 NO_VOUCHER_AVAILABLE when no active voucher has the exact centavo price', async () => {
    await seedUnclaimed('REF-XYZ5678', 50); // -> 5000 centavos
    await seedVoucher('333333', 50);        // a Peso/centavo mismatch must NOT match

    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '5678' });
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('NO_VOUCHER_AVAILABLE');

    // Nothing was mutated.
    const voucher = await getDb().getOne('SELECT state, assigned_ref_no FROM vouchers WHERE code = ?', ['333333']);
    expect(voucher.state).toBe('active');
    expect(voucher.assigned_ref_no).toBe(null);
    const event = await getDb().getOne('SELECT status FROM webhook_events WHERE ref_no = ?', ['REF-XYZ5678']);
    expect(event.status).toBe('unclaimed');
  });

  test('a payment can only be claimed once - the second attempt consumes no extra voucher', async () => {
    await seedUnclaimed('REF-DBL0001', 50);
    await seedVoucher('444444', 5000);
    await seedVoucher('555555', 5000);

    const first = await request(app).post('/api/payment/claim').send({ ref_suffix: '0001' });
    expect(first.status).toBe(200);
    expect(first.body.voucherCode).toBe('444444');

    const second = await request(app).post('/api/payment/claim').send({ ref_suffix: '0001' });
    expect(second.status).toBe(404);
    expect(second.body.code).toBe('PAYMENT_NOT_FOUND');

    const active = await getDb().getOne(
      "SELECT COUNT(*) AS c FROM vouchers WHERE state = 'active' AND assigned_ref_no IS NULL"
    );
    expect(Number(active.c)).toBe(1);
  });

  test('matches the newest unclaimed payment when several share the suffix', async () => {
    await seedUnclaimed('REF-ONE1234', 50);
    await seedUnclaimed('REF-TWO1234', 50);
    await seedVoucher('666666', 5000);

    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '1234' });
    expect(res.status).toBe(200);
    expect(res.body.ref_no).toBe('REF-TWO1234');
  });

  test('a claimed voucher connects through the existing /api/auth flow (Connect Now)', async () => {
    await seedUnclaimed('REF-CH1234', 50);
    await seedVoucher('777777', 5000);

    const claim = await request(app).post('/api/payment/claim').send({ ref_suffix: '1234' });
    expect(claim.status).toBe(200);
    expect(claim.body.voucherCode).toBe('777777');

    const auth = await request(app).post('/api/auth').send({
      voucher: claim.body.voucherCode,
      clientMac: MAC,
      apMac: 'AA:AA:AA:AA:AA:AA',
      ssidName: 'GuestWiFi',
      termsAccepted: true,
    });
    expect(auth.status).toBe(200);
    expect(auth.body.success).toBe(true);

    const voucher = await getDb().getOne('SELECT state, used_by_mac FROM vouchers WHERE code = ?', ['777777']);
    expect(voucher.state).toBe('used');
    expect(voucher.used_by_mac).toBe(MAC);
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
