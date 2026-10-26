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

// The Omada cloud client is replaced wholesale: no fetch, no credentials, and
// deterministic control over the authorization / QoS outcome.
jest.mock('../src/services/omada-northbound', () => ({
  authorizeGuest: jest.fn(),
  setClientRateLimit: jest.fn(),
}));
const omadaNorthbound = require('../src/services/omada-northbound');

// The authorized path waits a real 2000 ms for the cloud indexer.
jest.setTimeout(20000);

const MAC = 'AA:BB:CC:DD:EE:FF';
const MOBILE = '09171234567';

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
  jest.clearAllMocks();
  omadaNorthbound.authorizeGuest.mockResolvedValue({ success: true, clientMac: MAC, authRecordId: 'rec-claim' });
  omadaNorthbound.setClientRateLimit.mockResolvedValue({ success: true, clientMac: MAC });
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

  // Seed a voucher whose price is INTEGER CENTAVOS (P50.00 = 5000) and whose
  // duration_minutes is a plain INTEGER number of minutes (1 = one minute,
  // 60 = one hour).
  async function seedVoucher(code, priceCentavos, state = 'active', assignedRef = null, durationMinutes = 60) {
    await getDb().run(
      `INSERT INTO vouchers (code, type, duration_minutes, price, state, assigned_ref_no)
       VALUES (?, 'standard', ?, ?, ?, ?)`,
      [code, durationMinutes, priceCentavos, state, assignedRef]
    );
  }

  test('400 when ref_suffix is missing or not exactly 4 digits', async () => {
    for (const bad of ['', '123', '12345', 'abcd', undefined]) {
      const res = await request(app).post('/api/payment/claim').send({ ref_suffix: bad, mobile_number: MOBILE });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_REF_SUFFIX');
    }
  });

  test('404 when no unclaimed payment ends with the suffix', async () => {
    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '9999', mobile_number: MOBILE });
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('PAYMENT_NOT_FOUND');
    expect(res.body.error).toMatch(/not found or already claimed/i);
  });

  test('200: converts Pesos to centavos and claims the matching voucher + event together', async () => {
    await seedUnclaimed('REF-ABC1234', 50);                     // 50 pesos = 5000 centavos
    await seedVoucher('111111', 5000);                          // must be chosen
    await seedVoucher('222222', 5000, 'active', 'REF-OLD0001'); // already assigned -> skip

    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '1234', mobile_number: MOBILE });
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

    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '5678', mobile_number: MOBILE });
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

    const first = await request(app).post('/api/payment/claim').send({ ref_suffix: '0001', mobile_number: MOBILE });
    expect(first.status).toBe(200);
    expect(first.body.voucherCode).toBe('444444');

    const second = await request(app).post('/api/payment/claim').send({ ref_suffix: '0001', mobile_number: MOBILE });
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

    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '1234', mobile_number: MOBILE });
    expect(res.status).toBe(200);
    expect(res.body.ref_no).toBe('REF-TWO1234');
  });

  test('a claimed voucher connects through the existing /api/auth flow (Connect Now)', async () => {
    await seedUnclaimed('REF-CH1234', 50);
    await seedVoucher('777777', 5000);

    const claim = await request(app).post('/api/payment/claim').send({ ref_suffix: '1234', mobile_number: MOBILE });
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

  // ── mobile_number (required by the SMS flow) ──────────────────────────

  test('400 when mobile_number is missing or not an 11-digit 09 number', async () => {
    await seedUnclaimed('REF-MOB0001', 50);
    await seedVoucher('888888', 5000);

    for (const bad of [undefined, '', '0917123456', '091712345678', '99171234567', '0917-123-4567']) {
      const res = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0001', mobile_number: bad });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_MOBILE_NUMBER');
    }

    // None of the rejected attempts consumed anything.
    const event = await getDb().getOne('SELECT status, mobile_number FROM webhook_events WHERE ref_no = ?', ['REF-MOB0001']);
    expect(event.status).toBe('unclaimed');
    expect(event.mobile_number).toBe(null);
  });

  test('saves mobile_number on the payment it reconciled', async () => {
    await seedUnclaimed('REF-MOB0002', 50);
    await seedVoucher('818181', 5000);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0002', mobile_number: MOBILE });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const event = await getDb().getOne('SELECT status, mobile_number FROM webhook_events WHERE ref_no = ?', ['REF-MOB0002']);
    expect(event.status).toBe('claimed');
    expect(event.mobile_number).toBe(MOBILE);
  });

  // ── Direct MAC authorization ──────────────────────────────────────────

  test('authorizes the MAC through the Omada cloud (authorized:true + QoS)', async () => {
    await seedUnclaimed('REF-AUTH0001', 50);   // 50 pesos -> 5 minutes at the old amount rate
    // The voucher's own duration is 30 minutes, which must win over the 5 the
    // amount alone would imply.
    await seedVoucher('828282', 5000, 'active', null, 30);

    const startedAt = Date.now();
    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC, ap_mac: 'AA:AA:AA:AA:AA:AA' });
    const elapsed = Date.now() - startedAt;

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.authorized).toBe(true);
    expect(res.body.message).toBe('Device authorized');
    expect(res.body.minutes).toBe(30);
    expect(res.body.qosApplied).toBe(true);
    // The voucher is still returned so the ledger and a manual fallback survive.
    expect(res.body.voucherCode).toBe('828282');
    expect(res.body.ref_no).toBe('REF-AUTH0001');

    expect(omadaNorthbound.authorizeGuest).toHaveBeenCalledWith({ clientMac: MAC, durationMinutes: 30 });
    // 50 is not a premium amount, so no explicit limits are passed.
    expect(omadaNorthbound.setClientRateLimit).toHaveBeenCalledWith({ clientMac: MAC });

    // ...and the QoS call happens AFTER the authorization, with the full
    // cloud indexing delay in between (not skipped).
    expect(omadaNorthbound.authorizeGuest.mock.invocationCallOrder[0])
      .toBeLessThan(omadaNorthbound.setClientRateLimit.mock.invocationCallOrder[0]);
    expect(elapsed).toBeGreaterThanOrEqual(2000);
  });

  test('applies the premium caps when the amount is a premium tier price', async () => {
    const savedDown = process.env.PREMIUM_DOWN_MBPS;
    const savedUp = process.env.PREMIUM_UP_KBPS;
    process.env.PREMIUM_DOWN_MBPS = '50';
    process.env.PREMIUM_UP_KBPS = '1024';
    try {
      await seedUnclaimed('REF-PREM0001', 25);   // premium amount
      await seedVoucher('838383', 2500, 'active', null, 45);

      const res = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC });

      expect(res.status).toBe(200);
      expect(res.body.authorized).toBe(true);
      expect(omadaNorthbound.authorizeGuest).toHaveBeenCalledWith({ clientMac: MAC, durationMinutes: 45 });
      expect(omadaNorthbound.setClientRateLimit).toHaveBeenCalledWith({
        clientMac: MAC,
        customRateLimit: {
          upEnable: true, upUnit: 1, upLimit: 1024,
          downEnable: true, downUnit: 2, downLimit: 50,
        },
      });
    } finally {
      if (savedDown === undefined) delete process.env.PREMIUM_DOWN_MBPS; else process.env.PREMIUM_DOWN_MBPS = savedDown;
      if (savedUp === undefined) delete process.env.PREMIUM_UP_KBPS; else process.env.PREMIUM_UP_KBPS = savedUp;
    }
  });

  test('a failed rate limit does not fail the claim (authorized:true + qosApplied:false)', async () => {
    omadaNorthbound.setClientRateLimit.mockRejectedValue(new Error('ratelimit 500'));
    await seedUnclaimed('REF-QOS0001', 50);
    await seedVoucher('848484', 5000);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC });

    // The guest is online, so the claim is still a success.
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.authorized).toBe(true);
    expect(res.body.qosApplied).toBe(false);
    expect(res.body.qosError).toBe('ratelimit 500');
  });

  test('502 OMADA_AUTH_FAILED consumes NOTHING — the same reference still claims on the retry', async () => {
    // The first attempt is rejected by Omada (e.g. the client is not yet
    // associated on the controller); the retry succeeds.
    omadaNorthbound.authorizeGuest.mockRejectedValueOnce(new Error('cloud 503'));
    await seedUnclaimed('REF-FAIL0001', 50);
    await seedVoucher('858585', 5000);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC });

    expect(res.status).toBe(502);
    expect(res.body.success).toBe(false);
    expect(res.body.authorized).toBe(false);
    expect(res.body.code).toBe('OMADA_AUTH_FAILED');
    expect(res.body.error).toMatch(/tap claim again/i);
    // No code was issued, because nothing was consumed.
    expect(res.body.voucherCode).toBeUndefined();

    // The QoS step is skipped entirely when the guest never got online.
    expect(omadaNorthbound.setClientRateLimit).not.toHaveBeenCalled();

    const untouchedVoucher = await getDb().getOne('SELECT state, assigned_ref_no FROM vouchers WHERE code = ?', ['858585']);
    expect(untouchedVoucher.state).toBe('active');
    expect(untouchedVoucher.assigned_ref_no).toBeNull();
    const untouchedEvent = await getDb().getOne('SELECT status, mobile_number FROM webhook_events WHERE ref_no = ?', ['REF-FAIL0001']);
    expect(untouchedEvent.status).toBe('unclaimed');
    expect(untouchedEvent.mobile_number).toBeNull();

    // The SECOND attempt with the same 4 digits is a real retry — not the
    // 'Payment not found or already claimed' dead end this route used to hit.
    const retry = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC });

    expect(retry.status).toBe(200);
    expect(retry.body.success).toBe(true);
    expect(retry.body.authorized).toBe(true);
    expect(retry.body.voucherCode).toBe('858585');
    expect(retry.body.ref_no).toBe('REF-FAIL0001');
    expect(retry.body.minutes).toBe(60);

    const voucher = await getDb().getOne('SELECT state, assigned_ref_no FROM vouchers WHERE code = ?', ['858585']);
    expect(voucher.state).toBe('claimed');
    expect(voucher.assigned_ref_no).toBe('REF-FAIL0001');
    const event = await getDb().getOne('SELECT status, mobile_number FROM webhook_events WHERE ref_no = ?', ['REF-FAIL0001']);
    expect(event.status).toBe('claimed');
    expect(event.mobile_number).toBe(MOBILE);
  });

  test('without a client_mac the claim still succeeds, with authorized:false and no Omada call', async () => {
    await seedUnclaimed('REF-NOM0001', 50);
    await seedVoucher('868686', 5000);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.authorized).toBe(false);
    expect(res.body.voucherCode).toBe('868686');
    expect(res.body.authError).toMatch(/no client_mac/i);
    expect(omadaNorthbound.authorizeGuest).not.toHaveBeenCalled();
  });

  test('400 when client_mac is present but malformed', async () => {
    await seedUnclaimed('REF-BAD0001', 50);
    await seedVoucher('878787', 5000);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: 'not-a-mac' });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_CLIENT_MAC');
  });

  // ── MacroDroid SMS webhook ────────────────────────────────────────────

  describe('MacroDroid SMS webhook', () => {
    const SMS_URL = 'https://macrodroid.example.com/sms';
    const realFetch = global.fetch;
    let savedUrl;
    let savedBase;

    beforeEach(() => {
      savedUrl = process.env.MACRODROID_SMS_WEBHOOK_URL;
      savedBase = process.env.BASE_URL;
    });

    afterEach(() => {
      global.fetch = realFetch;
      if (savedUrl === undefined) delete process.env.MACRODROID_SMS_WEBHOOK_URL;
      else process.env.MACRODROID_SMS_WEBHOOK_URL = savedUrl;
      if (savedBase === undefined) delete process.env.BASE_URL;
      else process.env.BASE_URL = savedBase;
    });

    test('POSTs target_number + voucher_code to MACRODROID_SMS_WEBHOOK_URL', async () => {
      process.env.MACRODROID_SMS_WEBHOOK_URL = SMS_URL;
      process.env.BASE_URL = 'https://goodvibes.example.com/';
      const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      global.fetch = fetchMock;

      await seedUnclaimed('REF-SMS0001', 50);
      await seedVoucher('898989', 5000);

      const res = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC });
      expect(res.status).toBe(200);

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0];
      // No request body: every value travels in the URL query string so the
      // MacroDroid variable whitelist can extract it.
      expect(init.body).toBeUndefined();
      expect(init.method).toBe('POST');

      const parsed = new URL(url);
      expect(parsed.origin + parsed.pathname).toBe(SMS_URL);
      expect(Object.fromEntries(parsed.searchParams)).toEqual({
        target_number: MOBILE,
        voucher_code: '898989',
        ref_suffix: '0001',
        ref_no: 'REF-SMS0001',
        authorized: 'true',
        // The seeded voucher is a 1-HOUR (60-minute) plan; the amount alone
        // would have implied 5, so this proves the voucher duration is used.
        minutes: '60',
        status_link: 'https://goodvibes.example.com/status.html',
      });
    });

    test('appends the parameters when MACRODROID_SMS_WEBHOOK_URL already has a query string', async () => {
      process.env.MACRODROID_SMS_WEBHOOK_URL = SMS_URL + '?secret=abc';
      delete process.env.BASE_URL;
      const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      global.fetch = fetchMock;

      // P5 at the 10-pesos-per-minute rate is 0 whole minutes, so a
      // value derived from the amount would arrive as minutes=0 (the reported
      // bug). The voucher's own duration is 1 minute and must be reported as
      // exactly 1 — a plain integer in minutes, not milliseconds.
      await seedUnclaimed('REF-SMS0004', 5);
      await seedVoucher('929292', 500, 'active', null, 1);

      const res = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0004', mobile_number: MOBILE, client_mac: MAC });
      expect(res.status).toBe(200);
      expect(res.body.minutes).toBe(1);
      expect(omadaNorthbound.authorizeGuest).toHaveBeenCalledWith({ clientMac: MAC, durationMinutes: 1 });

      const [url] = fetchMock.mock.calls[0];
      const parsed = new URL(url);
      expect(parsed.searchParams.get('secret')).toBe('abc');
      expect(parsed.searchParams.get('target_number')).toBe(MOBILE);
      expect(parsed.searchParams.get('voucher_code')).toBe('929292');
      expect(parsed.searchParams.get('minutes')).toBe('1');
      // BASE_URL is unset, so status_link must be absent rather than "undefined".
      expect(parsed.searchParams.has('status_link')).toBe(false);
    });

    test('does not call the SMS webhook when MACRODROID_SMS_WEBHOOK_URL is unset', async () => {
      delete process.env.MACRODROID_SMS_WEBHOOK_URL;
      const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      global.fetch = fetchMock;

      await seedUnclaimed('REF-SMS0002', 50);
      await seedVoucher('909090', 5000);

      const res = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0002', mobile_number: MOBILE, client_mac: MAC });
      expect(res.status).toBe(200);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    test('a failing SMS webhook does not fail the claim', async () => {
      process.env.MACRODROID_SMS_WEBHOOK_URL = SMS_URL;
      global.fetch = jest.fn().mockRejectedValue(new Error('sms endpoint unreachable'));

      await seedUnclaimed('REF-SMS0003', 50);
      await seedVoucher('919191', 5000);

      const res = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0003', mobile_number: MOBILE, client_mac: MAC });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.authorized).toBe(true);
    });
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
