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
// This harness emulates a reverse proxy by sending X-Forwarded-For; trust the
// single hop explicitly (production defaults to trusting none).
process.env.TRUST_PROXY_HOPS = '1';
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
const { verifySessionToken } = require('../src/utils/session-token');

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
async function seedPortalContext(clientMac = MAC, clientIp = CLIENT_IP) {
  const now = new Date().toISOString();
  await getDb().run(
    `INSERT INTO portal_client_context
       (client_mac, client_ip, ap_mac, ssid_name, radio_id, site, seen_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, 0, 'Default', ?, ?, ?)`,
    [clientMac, clientIp, AP_MAC, SSID, now, now, now]
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
  await getDb().exec('DELETE FROM sessions; DELETE FROM vouchers; DELETE FROM webhook_events; DELETE FROM portal_client_context; DELETE FROM claim_attempts;');
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
  async function seedUnclaimed(refNo, amountPesos, mobile = MOBILE) {
    await getDb().run(
      `INSERT INTO webhook_events (event_id, ref_no, amount, status, mobile_number)
       VALUES (?, ?, ?, 'unclaimed', ?)`,
      ['evt_' + refNo, refNo, amountPesos, mobile]
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

  test('200: converts Pesos to centavos and generates a voucher bound to the payment', async () => {
    await seedUnclaimed('REF-ABC1234', 50); // 50 pesos = 5000 centavos

    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '1234', mobile_number: MOBILE });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.voucherCode).toMatch(/^\d{6}$/);
    expect(res.body.ref_no).toBe('REF-ABC1234');

    const voucher = await getDb().getOne('SELECT * FROM vouchers WHERE code = ?', [res.body.voucherCode]);
    expect(voucher.type).toBe('standard');
    expect(voucher.price).toBe(5000);
    // ₱50 is not a catalog price, so the operator's 10-peso/minute rate applies.
    expect(voucher.duration_minutes).toBe(5);
    expect(voucher.state).toBe('claimed');
    expect(voucher.assigned_ref_no).toBe('REF-ABC1234');

    const event = await getDb().getOne('SELECT * FROM webhook_events WHERE ref_no = ?', ['REF-ABC1234']);
    expect(event.status).toBe('claimed');
  });

  test('generates the advertised plan duration and tier for a catalog price', async () => {
    await seedUnclaimed('REF-PLAN0025', 25); // ₱25 = 5-hour premium plan

    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '0025', mobile_number: MOBILE });
    expect(res.status).toBe(200);
    expect(res.body.voucherCode).toMatch(/^\d{6}$/);
    expect(res.body.minutes).toBe(300);

    const voucher = await getDb().getOne('SELECT * FROM vouchers WHERE code = ?', [res.body.voucherCode]);
    expect(voucher.type).toBe('premium');
    expect(voucher.duration_minutes).toBe(300);
  });

  test('generates digital inventory even when the shelf is empty, without touching printed stock', async () => {
    await seedUnclaimed('REF-XYZ5678', 50); // -> 5000 centavos
    await seedVoucher('333333', 50);        // printed stock at a different price

    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '5678', mobile_number: MOBILE });
    expect(res.status).toBe(200);
    expect(res.body.voucherCode).toMatch(/^\d{6}$/);
    expect(res.body.voucherCode).not.toBe('333333');

    const generated = await getDb().getOne(
      'SELECT price, state, assigned_ref_no FROM vouchers WHERE code = ?',
      [res.body.voucherCode]
    );
    expect(generated.price).toBe(5000);
    expect(generated.state).toBe('claimed');
    expect(generated.assigned_ref_no).toBe('REF-XYZ5678');

    // The pre-printed voucher is untouched: claims no longer consume stock.
    const printed = await getDb().getOne('SELECT state, assigned_ref_no FROM vouchers WHERE code = ?', ['333333']);
    expect(printed.state).toBe('active');
    expect(printed.assigned_ref_no).toBe(null);
  });

  test('a payment can only be claimed once - the same customer\'s retry gets the SAME voucher back', async () => {
    await seedUnclaimed('REF-DBL0001', 50);

    const first = await request(app).post('/api/payment/claim').send({ ref_suffix: '0001', mobile_number: MOBILE });
    expect(first.status).toBe(200);
    expect(first.body.voucherCode).toMatch(/^\d{6}$/);
    expect(first.body.alreadyClaimed).toBeUndefined();
    const issuedCode = first.body.voucherCode;

    // The first response may never have reached the phone. Same digits + same
    // number replays the voucher that payment already produced — no second
    // voucher is consumed and the answer is a 200, not "already claimed".
    const retry = await request(app).post('/api/payment/claim').send({ ref_suffix: '0001', mobile_number: MOBILE });
    expect(retry.status).toBe(200);
    expect(retry.body.success).toBe(true);
    expect(retry.body.alreadyClaimed).toBe(true);
    expect(retry.body.authorized).toBe(false);
    expect(retry.body.voucherCode).toBe(issuedCode);
    expect(retry.body.ref_no).toBe('REF-DBL0001');
    expect(retry.body.minutes).toBe(5);   // the generated voucher's duration

    // A different number must not be told anything about someone else's payment.
    const stranger = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: '09170000000' });
    expect(stranger.status).toBe(404);
    expect(stranger.body.code).toBe('PAYMENT_NOT_FOUND');
    expect(stranger.body.voucherCode).toBeUndefined();
    expect(stranger.body.alreadyClaimed).toBeUndefined();

    // Exactly one voucher was generated and claimed for this payment.
    const total = await getDb().getOne('SELECT COUNT(*) AS c FROM vouchers');
    expect(Number(total.c)).toBe(1);
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

  test('concurrent claims for the same amount generate distinct vouchers', async () => {
    await seedUnclaimed('REF-CONC0001', 50);
    await seedUnclaimed('REF-CONC0002', 50);

    // Hold both requests inside the Omada call: by then each must already own a
    // DIFFERENT reserved voucher, which is the race the old flow lost.
    let releaseAuth;
    const authGate = new Promise((resolve) => { releaseAuth = resolve; });
    omadaService.authenticateClient.mockImplementation(async () => {
      await authGate;
      return { success: true, verified: true, result: 0 };
    });

    const claim = (suffix) => request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: suffix, mobile_number: MOBILE, client_mac: MAC });

    const first = claim('0001');
    const second = claim('0002');
    await new Promise((resolve) => setTimeout(resolve, 100));
    releaseAuth();

    const [a, b] = await Promise.all([first, second]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const codes = [a.body.voucherCode, b.body.voucherCode];
    codes.forEach((code) => expect(code).toMatch(/^\d{6}$/));
    expect(new Set(codes).size).toBe(2);

    const claimed = await getDb().query(
      'SELECT code, state, assigned_ref_no FROM vouchers ORDER BY code'
    );
    expect(claimed).toHaveLength(2);
    expect(claimed.map((v) => v.state)).toEqual(['claimed', 'claimed']);
    expect(new Set(claimed.map((v) => v.assigned_ref_no)).size).toBe(2);

    await flushQosDelay();
  });

  test('matches the newest unclaimed payment when several share the suffix', async () => {
    await seedUnclaimed('REF-ONE1234', 50);
    await seedUnclaimed('REF-TWO1234', 50);

    const res = await request(app).post('/api/payment/claim').send({ ref_suffix: '1234', mobile_number: MOBILE });
    expect(res.status).toBe(200);
    expect(res.body.ref_no).toBe('REF-TWO1234');
  });

  test('a claimed voucher connects through the existing /api/auth flow (Connect Now)', async () => {
    await seedUnclaimed('REF-CH1234', 50);

    const claim = await request(app).post('/api/payment/claim').send({ ref_suffix: '1234', mobile_number: MOBILE });
    expect(claim.status).toBe(200);
    expect(claim.body.voucherCode).toMatch(/^\d{6}$/);
    const issuedCode = claim.body.voucherCode;

    const auth = await request(app).post('/api/auth').send({
      voucher: claim.body.voucherCode,
      clientMac: MAC,
      apMac: 'AA:AA:AA:AA:AA:AA',
      ssidName: 'GuestWiFi',
      termsAccepted: true,
    });
    expect(auth.status).toBe(200);
    expect(auth.body.success).toBe(true);

    const voucher = await getDb().getOne('SELECT state, used_by_mac FROM vouchers WHERE code = ?', [issuedCode]);
    expect(voucher.state).toBe('used');
    expect(voucher.used_by_mac).toBe(MAC);
  });

  // ── mobile_number (required by the SMS flow) ──────────────────────────

  test('400 when mobile_number is missing or not an 11-digit 09 number', async () => {
    await seedUnclaimed('REF-MOB0001', 50);

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
    expect(event.mobile_number).toBe(MOBILE);
  });

  test('backfills mobile_number on a legacy payment it reconciled', async () => {
    await seedUnclaimed('REF-MOB0002', 50, null);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0002', mobile_number: MOBILE });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const event = await getDb().getOne('SELECT status, mobile_number FROM webhook_events WHERE ref_no = ?', ['REF-MOB0002']);
    expect(event.status).toBe('claimed');
    expect(event.mobile_number).toBe(MOBILE);
  });

  // ── C-02 regressions ─────────────────────────────────────────────────

  test('C-02: a claim with the wrong mobile number does not reveal the voucher', async () => {
    await seedUnclaimed('REF-SEC0001', 50);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: '09180000000' });

    expect(res.status).toBe(404);
    expect(res.body.code).toBe('PAYMENT_NOT_FOUND');
    expect(res.body.voucherCode).toBeUndefined();
    expect(res.body.ref_no).toBeUndefined();

    // Nothing was consumed and the ownership binding is untouched.
    const event = await getDb().getOne(
      'SELECT status, mobile_number FROM webhook_events WHERE ref_no = ?',
      ['REF-SEC0001']
    );
    expect(event.status).toBe('unclaimed');
    expect(event.mobile_number).toBe(MOBILE);

    const vouchers = await getDb().getOne('SELECT COUNT(*) AS c FROM vouchers');
    expect(Number(vouchers.c)).toBe(0);
  });

  test('C-02: the 6th failed claim for a suffix is locked even when X-Forwarded-For rotates', async () => {
    for (let i = 1; i <= 5; i++) {
      const res = await request(app)
        .post('/api/payment/claim')
        .set('X-Forwarded-For', '10.0.0.' + i)
        .send({ ref_suffix: '7777', mobile_number: MOBILE });
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('PAYMENT_NOT_FOUND');
    }

    const locked = await request(app)
      .post('/api/payment/claim')
      .set('X-Forwarded-For', '10.0.0.6')
      .send({ ref_suffix: '7777', mobile_number: MOBILE });

    expect(locked.status).toBe(429);
    expect(locked.body.code).toBe('CLAIM_SUFFIX_LOCKED');
    expect(Number(locked.headers['retry-after'])).toBeGreaterThan(0);
  });

  // ── Direct MAC authorization ──────────────────────────────────────────

  test('authorizes the MAC through the controller web API (authorized:true + QoS)', async () => {
    await seedUnclaimed('REF-AUTH0001', 5); // ₱5 = the 1-hour standard plan

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC, ap_mac: 'AA:AA:AA:AA:AA:AA' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.authorized).toBe(true);
    expect(res.body.message).toBe('Device authorized');
    expect(res.body.minutes).toBe(60);
    // The voucher is still returned so the ledger and a manual fallback survive.
    expect(res.body.voucherCode).toMatch(/^\d{6}$/);
    expect(res.body.ref_no).toBe('REF-AUTH0001');

    expect(omadaService.authenticateClient).toHaveBeenCalledWith({
      ...AUTH_CTX,
      durationMinutes: 60,
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

  // ── Which device does the claim authorize? ────────────────────────────
  // The portal arrives through a cloud tunnel, so req.ip is the tunnel's public
  // address and the landing beacon's LAN address never matches it. The MAC the
  // page POSTs is therefore the authoritative identity; the address lookup is
  // only the LAN-direct fallback.

  test('an explicit client_mac wins over the device at the request address', async () => {
    const OTHER_MAC = '11:22:33:44:55:66';
    const OTHER_IP = '10.0.0.6';
    // The request address belongs to a DIFFERENT device: trusting it would
    // authorize the wrong guest.
    await seedPortalContext(OTHER_MAC, OTHER_IP);
    await seedUnclaimed('REF-PICK0001', 5);

    const res = await request(app)
      .post('/api/payment/claim')
      .set('X-Forwarded-For', CLIENT_IP)          // the address of MAC, not OTHER_MAC
      .send({
        ref_suffix: '0001',
        mobile_number: MOBILE,
        client_mac: '11-22-33-44-55-66',           // dashed + lowercase: must be sanitized
      });

    expect(res.status).toBe(200);
    expect(res.body.authorized).toBe(true);
    // Sanitized to the canonical form before it reaches extPortal/auth.
    expect(omadaService.authenticateClient).toHaveBeenCalledWith({
      clientMac: OTHER_MAC,
      clientIp: OTHER_IP,
      apMac: AP_MAC,
      ssidName: SSID,
      radioId: 0,
      durationMinutes: 60,
    });

    const session = await getDb().getOne(
      'SELECT client_mac, client_ip FROM sessions ORDER BY id DESC LIMIT 1'
    );
    expect(session.client_mac).toBe(OTHER_MAC);
    expect(session.client_ip).toBe(OTHER_IP);
  });

  test('authorizes an explicit MAC even when the request address has no portal context (cloud tunnel)', async () => {
    // The deployment case: the request arrives from the tunnel's public
    // address, which no portal_client_context row can match, while the guest's
    // own context is stored under its LAN address.
    await seedUnclaimed('REF-PICK0004', 5);

    const res = await request(app)
      .post('/api/payment/claim')
      .set('X-Forwarded-For', '203.0.113.9')     // tunnel egress: unknown to the DB
      .send({ ref_suffix: '0004', mobile_number: MOBILE, client_mac: MAC });

    expect(res.status).toBe(200);
    expect(res.body.authorized).toBe(true);
    expect(omadaService.authenticateClient).toHaveBeenCalledWith({
      ...AUTH_CTX,
      durationMinutes: 60,
    });

    const session = await getDb().getOne('SELECT client_mac FROM sessions ORDER BY id DESC LIMIT 1');
    expect(session.client_mac).toBe(MAC);
  });

  test('falls back to the device at the request address when the body has no MAC', async () => {
    await seedUnclaimed('REF-PICK0002', 5); // 1-hour plan

    const res = await request(app)
      .post('/api/payment/claim')
      .set('X-Forwarded-For', CLIENT_IP)
      .send({ ref_suffix: '0002', mobile_number: MOBILE });

    expect(res.status).toBe(200);
    expect(res.body.authorized).toBe(true);
    expect(omadaService.authenticateClient).toHaveBeenCalledWith({
      ...AUTH_CTX,
      durationMinutes: 60,
    });

    const session = await getDb().getOne(
      'SELECT client_mac FROM sessions ORDER BY id DESC LIMIT 1'
    );
    expect(session.client_mac).toBe(MAC);
  });

  test('a malformed explicit MAC is rejected before any controller call', async () => {
    await seedUnclaimed('REF-PICK0003', 5);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0003', mobile_number: MOBILE, client_mac: 'not-a-mac' });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_CLIENT_MAC');
    expect(omadaService.authenticateClient).not.toHaveBeenCalled();
  });

  test('records the granted session so the status page can report time', async () => {
    await seedUnclaimed('REF-SESS0001', 5); // 1-hour plan

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC });

    expect(res.status).toBe(200);
    expect(res.body.authorized).toBe(true);

    const session = await getDb().getOne(
      'SELECT * FROM sessions WHERE client_mac = ? ORDER BY id DESC LIMIT 1',
      [MAC]
    );
    expect(session).toBeTruthy();
    // Same id shape as the voucher-login route (/api/auth).
    expect(session.session_id).toMatch(/^sess_[0-9a-f]{16}$/);
    expect(session.state).toBe('active');
    expect(session.duration_minutes).toBe(60);
    expect(session.voucher_used).toBe(res.body.voucherCode);
    expect(session.voucher_type).toBe('standard');
    // The controller context the authorization used travels with the session.
    expect(session.client_ip).toBe(CLIENT_IP);
    expect(session.ap_mac).toBe(AP_MAC);
    expect(session.ssid_name).toBe(SSID);
    expect(session.total_duration_seconds).toBe(60 * 60);
    expect(new Date(session.expires_at).getTime() - new Date(session.started_at).getTime())
      .toBe(60 * 60 * 1000);

    // The point of the row: the MAC-direct status lookup now resolves it.
    const status = await request(app).get('/api/session/status?mac=' + encodeURIComponent(MAC));
    expect(status.status).toBe(200);
    expect(status.body.sessionId).toBe(session.session_id);
    expect(status.body.state).toBe('active');
    expect(status.body.remainingSeconds).toBeGreaterThan(59 * 60);
  });

  test('records the generated voucher tier, duration and bandwidth snapshot', async () => {
    await seedUnclaimed('REF-SESS0002', 25); // ₱25 = 5-hour premium plan

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0002', mobile_number: MOBILE, client_mac: MAC });
    expect(res.body.authorized).toBe(true);

    const voucher = await getDb().getOne(
      'SELECT type, duration_minutes, down_kbps, up_kbps FROM vouchers WHERE code = ?',
      [res.body.voucherCode]
    );
    expect(voucher.type).toBe('premium');
    expect(voucher.duration_minutes).toBe(300);
    // No per-voucher caps on generated rows: the premium tier defaults apply.
    expect(voucher.down_kbps).toBeNull();
    expect(voucher.up_kbps).toBeNull();

    const session = await getDb().getOne(
      `SELECT voucher_type, down_kbps, up_kbps, duration_minutes
         FROM sessions WHERE client_mac = ?`,
      [MAC]
    );
    // Stored lowercased, so pause/resume and the QoS rules agree on the tier.
    expect(session.voucher_type).toBe('premium');
    // 50 Mbps down is snapshotted in Kbps (50 * 1024); 1024 Kbps up stays Kbps.
    expect(session.down_kbps).toBe(51200);
    expect(session.up_kbps).toBe(1024);
    expect(session.duration_minutes).toBe(300);
  });

  test('records no session when the claim could not authorize the device', async () => {
    await seedUnclaimed('REF-SESS0003', 50);

    // No client_mac: the voucher is claimed but nothing is connected.
    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0003', mobile_number: MOBILE });

    expect(res.status).toBe(200);
    expect(res.body.authorized).toBe(false);

    const sessions = await getDb().getOne('SELECT COUNT(*) AS n FROM sessions');
    expect(sessions.n).toBe(0);
  });

  test('applies the premium caps when the amount is a premium tier price', async () => {
    const savedDown = process.env.PREMIUM_DOWN_MBPS;
    const savedUp = process.env.PREMIUM_UP_KBPS;
    process.env.PREMIUM_DOWN_MBPS = '50';
    process.env.PREMIUM_UP_KBPS = '1024';
    try {
      await seedUnclaimed('REF-PREM0001', 25);   // premium amount

      const res = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC });

      expect(res.status).toBe(200);
      expect(res.body.authorized).toBe(true);
      expect(omadaService.authenticateClient).toHaveBeenCalledWith({
        ...AUTH_CTX,
        durationMinutes: 300,
      });

      await flushQosDelay();

      expect(omadaService.setClientRateLimit).toHaveBeenCalledWith({
        clientMac: MAC,
        customRateLimit: {
          upEnable: true, upUnit: 2, upLimit: 1,
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

    // The generated reservation was discarded, so no phantom digital stock
    // is left behind for a claim that was never authorized.
    const untouchedVoucher = await getDb().getOne('SELECT COUNT(*) AS c FROM vouchers');
    expect(Number(untouchedVoucher.c)).toBe(0);
    const untouchedEvent = await getDb().getOne('SELECT status, mobile_number FROM webhook_events WHERE ref_no = ?', ['REF-FAIL0001']);
    expect(untouchedEvent.status).toBe('unclaimed');
    expect(untouchedEvent.mobile_number).toBe(MOBILE);

    // The SECOND attempt with the same 4 digits is a real retry — not the
    // 'Payment not found or already claimed' dead end this route used to hit.
    const retry = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE, client_mac: MAC });

    expect(retry.status).toBe(200);
    expect(retry.body.success).toBe(true);
    expect(retry.body.authorized).toBe(true);
    expect(retry.body.voucherCode).toMatch(/^\d{6}$/);
    expect(retry.body.ref_no).toBe('REF-FAIL0001');
    expect(retry.body.minutes).toBe(5);

    // Drain the cap timer the successful retry scheduled.
    await flushQosDelay();

    const voucher = await getDb().getOne(
      'SELECT state, assigned_ref_no FROM vouchers WHERE code = ?',
      [retry.body.voucherCode]
    );
    expect(voucher.state).toBe('claimed');
    expect(voucher.assigned_ref_no).toBe('REF-FAIL0001');
    const event = await getDb().getOne('SELECT status, mobile_number FROM webhook_events WHERE ref_no = ?', ['REF-FAIL0001']);
    expect(event.status).toBe('claimed');
    expect(event.mobile_number).toBe(MOBILE);
  });

  test('without a client_mac the claim still succeeds, with authorized:false and no Omada call', async () => {
    await seedUnclaimed('REF-NOM0001', 50);

    const res = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '0001', mobile_number: MOBILE });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.authorized).toBe(false);
    expect(res.body.voucherCode).toMatch(/^\d{6}$/);
    expect(res.body.authError).toMatch(/no client_mac/i);
    expect(omadaService.authenticateClient).not.toHaveBeenCalled();
  });

  test('502 when client_mac is present but the device never landed on the portal', async () => {
    // extPortal/auth is connection-type specific: without the AP/SSID/radio
    // context there is nothing to authorize with, so the claim fails loud and
    // consumes nothing.
    await getDb().exec('DELETE FROM portal_client_context;');
    await seedUnclaimed('REF-NOCTX0001', 50);

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
    const voucher = await getDb().getOne('SELECT COUNT(*) AS c FROM vouchers');
    expect(Number(voucher.c)).toBe(0);
    const event = await getDb().getOne('SELECT status FROM webhook_events WHERE ref_no = ?', ['REF-NOCTX0001']);
    expect(event.status).toBe('unclaimed');
  });

  test('400 when client_mac is present but malformed', async () => {
    await seedUnclaimed('REF-BAD0001', 50);

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

      await seedUnclaimed('REF-SMS0001', 5); // 1-hour plan

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

      const params = Object.fromEntries(parsed.searchParams);
      const statusLink = params.status_link;
      delete params.status_link;

      expect(params).toEqual({
        target_number: MOBILE,
        voucher_code: res.body.voucherCode,
        ref_suffix: '0001',
        ref_no: 'REF-SMS0001',
        authorized: 'true',
        // The seeded voucher is a 1-HOUR (60-minute) plan; the amount alone
        // would have implied 5, so this proves the voucher duration is used.
        minutes: '60',
      });

      // The texted link must identify the session on its own: it is opened on
      // mobile data, on another origin, where no cookie/localStorage exists.
      const link = new URL(statusLink);
      expect(link.origin + link.pathname).toBe('https://goodvibes.example.com/status.html');
      const token = link.searchParams.get('token');
      expect(token).toBeTruthy();
      expect(verifySessionToken(token).sessionId).toBe(res.body.sessionId);
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
      await seedUnclaimed('REF-SMS0004', 1);

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
      expect(parsed.searchParams.get('voucher_code')).toBe(res.body.voucherCode);
      expect(parsed.searchParams.get('minutes')).toBe('1');
      // BASE_URL is unset, so status_link must be absent rather than "undefined".
      expect(parsed.searchParams.has('status_link')).toBe(false);
    });

    test('does not call the SMS webhook when MACRODROID_SMS_WEBHOOK_URL is unset', async () => {
      delete process.env.MACRODROID_SMS_WEBHOOK_URL;
      const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      global.fetch = fetchMock;

      await seedUnclaimed('REF-SMS0002', 50);

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

      const first = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0005', mobile_number: MOBILE, client_mac: MAC });
      expect(first.status).toBe(200);
      const issuedCode = first.body.voucherCode;
      expect(fetchMock).toHaveBeenCalledTimes(1);

      const retry = await request(app)
        .post('/api/payment/claim')
        .send({ ref_suffix: '0005', mobile_number: MOBILE, client_mac: MAC });
      expect(retry.status).toBe(200);
      expect(retry.body.alreadyClaimed).toBe(true);
      expect(retry.body.voucherCode).toBe(issuedCode);

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

  test('rejects a malformed MAC with 400 INVALID_MAC', async () => {
    // The tunnel fallback sends whatever MAC was saved on the page, so a
    // corrupted value must be refused explicitly instead of quietly reported
    // as "no session".
    for (const bad of ['not-a-mac', 'aa:bb:cc:dd:ee', 'aa:bb:cc:dd:ee:ff:00']) {
      const res = await request(app).get('/api/session/status?mac=' + encodeURIComponent(bad));
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_MAC');
    }
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
