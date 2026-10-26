/**
 * __tests__/payment-claim.test.js
 * Integration tests for:
 *   POST /api/payment/claim   (routes/payment.js)
 *   GET  /api/session/status          (routes/session.js; ?mac=, ?sessionId= and
 *                                      the no-identifier device lookup by IP)
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
// The claim route's own limiter caps at 30/15 min in production; this suite
// exercises more claims than that (every branch plus the idempotent retries).
process.env.CLAIM_RATE_LIMIT_MAX = '10000';

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');

// The controller client is replaced wholesale: no fetch, no credentials, and
// deterministic control over the authorization / QoS outcome. The rest of the
// module stays real so server startup and the session service keep working.
jest.mock('../src/services/omada', () => Object.assign(
  {},
  jest.requireActual('../src/services/omada'),
  { authenticateClient: jest.fn(), setClientRateLimit: jest.fn() }
));
const omadaService = require('../src/services/omada');

// The authorized path waits a real 2000 ms for the cloud indexer.
jest.setTimeout(20000);

const MAC = 'AA:BB:CC:DD:EE:FF';
const MOBILE = '09171234567';
const AP_MAC = 'AA:AA:AA:AA:AA:AA';
const SSID = 'GoodVibesVendoWifi';
const CLIENT_IP = '10.0.0.5';

/**
 * The controller context the device gets by landing on the captive portal
 * (POST /api/payment/context). extPortal/auth cannot be called without it, so
 * every authorized claim in this suite depends on this row.
 */
async function seedPortalContext(clientMac = MAC) {
  const now = new Date().toISOString();
  await getDb().run(
    `INSERT INTO portal_client_context
       (client_mac, client_ip, ap_mac, ssid_name, radio_id, site, seen_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, 0, 'Default', ?, ?, ?)`,
    [clientMac, CLIENT_IP, AP_MAC, SSID, now, now, now]
  );
}

const AUTH_CTX = {
  clientMac: MAC,
  clientIp: CLIENT_IP,
  apMac: AP_MAC,
  ssidName: SSID,
  radioId: 0,
};

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
  // Let any bandwidth-cap timer scheduled after a claim response finish before
  // the database and the console are torn down.
  await new Promise((resolve) => setTimeout(resolve, 2100));
  await closeDb();
  try {
    fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
  } catch (err) { /* best-effort cleanup */ }
});

beforeEach(async () => {
  await getDb().exec('DELETE FROM sessions; DELETE FROM vouchers; DELETE FROM webhook_events; DELETE FROM portal_client_context;');
  await seedPortalContext();
  jest.clearAllMocks();
  omadaService.authenticateClient.mockResolvedValue({ success: true, verified: true, result: 0 });
  omadaService.setClientRateLimit.mockResolvedValue({ success: true, clientMac: MAC });
});

/**
 * The bandwidth cap is applied 2000 ms AFTER the claim response has been sent
 * (Omada needs that long to index the new auth record). Draining the delay makes
 * assertions on setClientRateLimit deterministic and keeps the timer inside the
 * test that scheduled it.
 */
async function flushQosDelay() {
  await new Promise((resolve) => setTimeout(resolve, 2100));
}

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

  test('a payment can only be claimed once - the same customer\'s retry gets the SAME voucher back', async () => {
    await seedUnclaimed('REF-DBL0001', 50);
    await seedVoucher('444444', 5000);
    await seedVoucher('555555', 5000);

    const first = await request(app).post('/api/payment/claim').send({ ref_suffix: '0001', mobile_number: MOBILE });
    expect(first.status).toBe(200);
    expect(first.body.voucherCode).toBe('444444');
    expect(first.body.alreadyClaimed).toBeUndefined();

    // The first response may never have reached the phone. Same digits + same
    // number replays the voucher that payment already produced — no second
    // voucher is consumed and the answer is a 200, not "already claimed".
    const retry = await request(app).post('/api/payment/claim').send({ ref_suffix: '0001', mobile_number: MOBILE });
    expect(retry.status).toBe(200);
    expect(retry.body.success).toBe(true);
    expect(retry.body.alreadyClaimed).toBe(true);
    expect(retry.body.authorized).toBe(false);
    expect(retry.body.voucherCode).toBe('444444');
    expect(retry.body.ref_no).toBe('REF-DBL0001');
    expect(retry.body.minutes).toBe(60);   // the seeded voucher's duration

    // A different number must not be told anything about someone else's payment.
    const stranger = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: '09170000000' });
    expect(stranger.status).toBe(404);
    expect(stranger.body.code).toBe('PAYMENT_NOT_FOUND');
    expect(stranger.body.voucherCode).toBeUndefined();
    expect(stranger.body.alreadyClaimed).toBeUndefined();

    // Exactly one voucher was consumed, and the other is still on the shelf.
    const active = await getDb().getOne(
      "SELECT COUNT(*) AS c FROM vouchers WHERE state = 'active' AND assigned_ref_no IS NULL"
    );
    expect(Number(active.c)).toBe(1);
    const claimed = await getDb().getOne(
      "SELECT COUNT(*) AS c FROM vouchers WHERE state = 'claimed' AND assigned_ref_no = 'REF-DBL0001'"
    );
    expect(Number(claimed.c)).toBe(1);
  });

  test('a claimed payment with no stored mobile number cannot be replayed by guessing', async () => {
    // Legacy row: claimed before the number was saved, so there is nothing to
    // compare a retry against. It must keep answering the generic 404 rather
    // than leaking a voucher code to whoever knows the last 4 digits.
    await getDb().run(
      `INSERT INTO webhook_events (event_id, ref_no, amount, status, mobile_number)
       VALUES (?, ?, ?, 'claimed', NULL)`,
      ['evt_legacy', 'REF-LEG0001', 50]
    );
    await seedVoucher('959595', 5000, 'claimed', 'REF-LEG0001');

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE });
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('PAYMENT_NOT_FOUND');
    expect(res.body.voucherCode).toBeUndefined();
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

  test('authorizes the MAC through the controller web API (authorized:true + QoS)', async () => {
    await seedUnclaimed('REF-AUTH0001', 50);   // 50 pesos -> 5 minutes at the old amount rate
    // The voucher's own duration is 30 minutes, which must win over the 5 the
    // amount alone would imply.
    await seedVoucher('828282', 5000, 'active', null, 30);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC, ap_mac: 'AA:AA:AA:AA:AA:AA' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.authorized).toBe(true);
    expect(res.body.message).toBe('Device authorized');
    expect(res.body.minutes).toBe(30);
    // The voucher is still returned so the ledger and a manual fallback survive.
    expect(res.body.voucherCode).toBe('828282');
    expect(res.body.ref_no).toBe('REF-AUTH0001');

    expect(omadaService.authenticateClient).toHaveBeenCalledWith({
      ...AUTH_CTX,
      durationMinutes: 30,
    });

    // The response must NOT wait for the 2000 ms pre-QoS delay: the claim is
    // answered first, then the cap is applied (otherwise a slow tail is a window
    // in which a committed claim's response can be lost).
    expect(omadaService.setClientRateLimit).not.toHaveBeenCalled();

    await flushQosDelay();

    // 50 is not a premium amount, so no explicit limits are passed...
    expect(omadaService.setClientRateLimit).toHaveBeenCalledWith({ clientMac: MAC });
    // ...and it happens AFTER the authorization, with the full pre-QoS delay
    // in between (not skipped).
    expect(omadaService.authenticateClient.mock.invocationCallOrder[0])
      .toBeLessThan(omadaService.setClientRateLimit.mock.invocationCallOrder[0]);
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
      expect(omadaService.authenticateClient).toHaveBeenCalledWith({
        ...AUTH_CTX,
        durationMinutes: 45,
      });

      await flushQosDelay();

      expect(omadaService.setClientRateLimit).toHaveBeenCalledWith({
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

  test('a failed rate limit does not fail the already-sent claim', async () => {
    omadaService.setClientRateLimit.mockRejectedValue(new Error('ratelimit 500'));
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    await seedUnclaimed('REF-QOS0001', 50);
    await seedVoucher('848484', 5000);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC });

    // The guest is online, so the claim is still a success. The cap runs after
    // the response, so its outcome is not part of the body.
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.authorized).toBe(true);
    expect(res.body.qosApplied).toBeUndefined();
    expect(res.body.qosError).toBeUndefined();

    await flushQosDelay();

    // The rejection was caught and logged, not thrown after the response.
    expect(omadaService.setClientRateLimit).toHaveBeenCalledWith({ clientMac: MAC });
    expect(
      errorSpy.mock.calls.some((args) => String(args[0]).includes('rate limit failed'))
    ).toBe(true);
    errorSpy.mockRestore();
  });

  test('502 OMADA_AUTH_FAILED consumes NOTHING — the same reference still claims on the retry', async () => {
    // The first attempt is rejected by Omada (e.g. the client is not yet
    // associated on the controller); the retry succeeds.
    omadaService.authenticateClient.mockRejectedValueOnce(new Error('controller 503'));
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
    expect(omadaService.setClientRateLimit).not.toHaveBeenCalled();

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

    // Drain the cap timer the successful retry scheduled.
    await flushQosDelay();

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
    expect(omadaService.authenticateClient).not.toHaveBeenCalled();
  });

  test('502 when client_mac is present but the device never landed on the portal', async () => {
    // extPortal/auth is connection-type specific: without the AP/SSID/radio
    // context there is nothing to authorize with, so the claim fails loud and
    // consumes nothing.
    await getDb().exec('DELETE FROM portal_client_context;');
    await seedUnclaimed('REF-NOCTX0001', 50);
    await seedVoucher('878788', 5000);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC });

    expect(res.status).toBe(502);
    expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');
    expect(res.body.error).toMatch(/open the wi-fi portal page/i);
    expect(omadaService.authenticateClient).not.toHaveBeenCalled();
    expect(omadaService.setClientRateLimit).not.toHaveBeenCalled();

    // Nothing was consumed, so the same reference can be claimed after the
    // device reloads the portal page.
    const voucher = await getDb().getOne('SELECT state FROM vouchers WHERE code = ?', ['878788']);
    expect(voucher.state).toBe('active');
    const event = await getDb().getOne('SELECT status FROM webhook_events WHERE ref_no = ?', ['REF-NOCTX0001']);
    expect(event.status).toBe('unclaimed');
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
      expect(omadaService.authenticateClient).toHaveBeenCalledWith({
        ...AUTH_CTX,
        durationMinutes: 1,
      });

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

    test('an idempotent retry does not text again and does not authorize again', async () => {
      process.env.MACRODROID_SMS_WEBHOOK_URL = SMS_URL;
      const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      global.fetch = fetchMock;

      await seedUnclaimed('REF-SMS0005', 50);
      await seedVoucher('939393', 5000);

      const first = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0005', mobile_number: MOBILE, client_mac: MAC });
      expect(first.status).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(1);

      const retry = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0005', mobile_number: MOBILE, client_mac: MAC });
      expect(retry.status).toBe(200);
      expect(retry.body.alreadyClaimed).toBe(true);
      expect(retry.body.voucherCode).toBe('939393');

      // The code was already texted once; a replay must not text or authorize
      // again (which would extend the session for free).
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(omadaService.authenticateClient).toHaveBeenCalledTimes(1);

      // Let the first claim's bandwidth cap finish before the test ends.
      await flushQosDelay();
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

// ── MAC-direct status (no identifier in the request at all) ────────────
// status.html polls GET /api/session/status with no query string; the backend
// maps the request address to the MAC captured by the portal landing beacon.
describe('GET /api/session/status — device identified by request IP', () => {
  test('returns the device\'s session when no identifier is supplied', async () => {
    await seedSession('sess_status_ip', null, 'active', MAC, 60);

    const res = await request(app)
      .get('/api/session/status')
      .set('X-Forwarded-For', CLIENT_IP);

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe('sess_status_ip');
    expect(res.body.clientMac).toBe(MAC);
    expect(res.body.state).toBe('active');
    expect(typeof res.body.remainingSeconds).toBe('number');
  });

  test('matches an IPv4-mapped request address (dual-stack listener)', async () => {
    await seedSession('sess_status_ip6', null, 'active', MAC, 60);

    const res = await request(app)
      .get('/api/session/status')
      .set('X-Forwarded-For', '::ffff:' + CLIENT_IP);

    expect(res.status).toBe(200);
    expect(res.body.sessionId).toBe('sess_status_ip6');
  });

  test('502 MISSING_PORTAL_CONTEXT when the request IP never landed on the portal', async () => {
    // No portal_client_context row for this address: the device cannot be
    // identified, and that is reported explicitly — never as "session gone".
    await getDb().exec('DELETE FROM portal_client_context;');

    const res = await request(app)
      .get('/api/session/status')
      .set('X-Forwarded-For', '10.0.0.99');

    expect(res.status).toBe(502);
    expect(res.body.success).toBe(false);
    expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');
    expect(res.body.error).toMatch(/open the wi-fi portal page/i);
  });

  test('404 SESSION_NOT_FOUND when the device is known but has no session', async () => {
    const res = await request(app)
      .get('/api/session/status')
      .set('X-Forwarded-For', CLIENT_IP);

    expect(res.status).toBe(404);
    expect(res.body.code).toBe('SESSION_NOT_FOUND');
    expect(res.body.clientMac).toBe(MAC);
  });
});
