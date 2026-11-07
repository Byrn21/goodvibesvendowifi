/**
 * __tests__/payment-claim-verify.test.js
 *
 * MacroDroid screen-scrape verification of a claim that has no recorded
 * payment webhook:
 *
 *   POST /api/payment/claim                     → 202 pending + GET /verify
 *   POST /api/webhooks/macrodroid/verify-result → verified / failed
 *   GET  /api/payment/claim/status              → pending → verified → claimed
 *
 * Follows the harness in payment-claim.test.js: temp SQLite database created
 * before requiring db/client.js, schema applied from schema.sql, supertest
 * against the app exported by src/server.js.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-claim-verify-test-'));
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
process.env.CLAIM_RATE_LIMIT_MAX = '10000';
// The verification channel under test. Without an IP the route keeps its
// original 404 — that behaviour is covered by payment-claim.test.js.
process.env.MACRODROID_IP = '192.168.1.50';
process.env.MACRODROID_WEBHOOK_PORT = '8080';

const request = require('supertest');

// The route fires GET /verify at the MacroDroid handset. Nothing may leave the
// test process, so global fetch is replaced wholesale.
const fetchMock = jest.fn(() => Promise.resolve({ ok: true, status: 200 }));
global.fetch = fetchMock;

const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');

jest.mock('../src/services/omada', () => Object.assign(
  {},
  jest.requireActual('../src/services/omada'),
  { authenticateClient: jest.fn(), setClientRateLimit: jest.fn() }
));
const omadaService = require('../src/services/omada');

jest.setTimeout(20000);

const MAC = 'AA:BB:CC:DD:EE:FF';
const MOBILE = '09171234567';
const AP_MAC = 'AA:AA:AA:AA:AA:AA';
const SSID = 'GoodVibesVendoWifi';
const CLIENT_IP = '10.0.0.5';
const SECRET = 'test-webhook-secret-abc123';
const VERIFY_URL = 'http://192.168.1.50:8080/verify?ref=1234&mac=' + encodeURIComponent(MAC);

async function seedPortalContext() {
  const now = new Date().toISOString();
  await getDb().run(
    `INSERT INTO portal_client_context
       (client_mac, client_ip, ap_mac, ssid_name, radio_id, site, seen_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, 0, 'Default', ?, ?, ?)`,
    [MAC, CLIENT_IP, AP_MAC, SSID, now, now, now]
  );
}

async function seedVoucher(code = 'WIFI-CLAIM-001', priceCentavos = 5000, durationMinutes = 60) {
  await getDb().run(
    `INSERT INTO vouchers (code, type, duration_minutes, price, state)
     VALUES (?, 'standard', ?, ?, 'active')`,
    [code, durationMinutes, priceCentavos]
  );
}

beforeAll(async () => {
  const schema = fs.readFileSync(path.join(__dirname, '..', 'src', 'db', 'schema.sql'), 'utf8');
  await getDb().exec(schema);
});

afterAll(async () => {
  // Let the post-claim bandwidth-cap timer finish before teardown.
  await new Promise((resolve) => setTimeout(resolve, 2100));
  await closeDb();
  try {
    fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
  } catch (err) { /* best-effort cleanup */ }
});

beforeEach(async () => {
  await getDb().exec(
    'DELETE FROM sessions; DELETE FROM vouchers; DELETE FROM webhook_events;' +
    ' DELETE FROM portal_client_context; DELETE FROM pending_claims;' +
    ' DELETE FROM claim_attempts;'
  );
  await seedPortalContext();
  jest.clearAllMocks();
  fetchMock.mockClear();
  fetchMock.mockImplementation(() => Promise.resolve({ ok: true, status: 200 }));
  omadaService.authenticateClient.mockResolvedValue({ success: true, verified: true, result: 0 });
  omadaService.setClientRateLimit.mockResolvedValue({ success: true, clientMac: MAC });
});

async function startPendingClaim(overrides) {
  const body = Object.assign(
    { ref_suffix: '1234', mobile_number: MOBILE, client_mac: MAC },
    overrides || {}
  );
  return request(app).post('/api/payment/claim').send(body);
}

describe('POST /api/payment/claim — pending MacroDroid verification', () => {
  test('an unmatched claim is parked and the handset is asked to read the receipt', async () => {
    const res = await startPendingClaim({ tier: 'premium' });

    expect(res.status).toBe(202);
    expect(res.body.success).toBe(true);
    expect(res.body.pending).toBe(true);
    expect(res.body.state).toBe('pending');
    expect(res.body.claimId).toMatch(/^clm_[a-z0-9]{16}$/);
    expect(res.body.retryAfterMs).toBe(3000);
    expect(new Date(res.body.expiresAt).getTime()).toBeGreaterThan(Date.now());

    // The pending state holds everything needed to finish the claim later.
    const row = await getDb().getOne('SELECT * FROM pending_claims WHERE claim_id = ?', [res.body.claimId]);
    expect(row.ref_suffix).toBe('1234');
    expect(row.client_mac).toBe(MAC);
    expect(row.mobile_number).toBe(MOBILE);
    expect(row.requested_tier).toBe('premium');
    expect(row.state).toBe('pending');

    // Exactly one GET, in the documented format, with no request body.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(VERIFY_URL, expect.objectContaining({ method: 'GET' }));
  });

  test('a retry with the same digits reuses the open claim instead of starting a second scrape', async () => {
    const first = await startPendingClaim();
    const second = await startPendingClaim();

    expect(second.status).toBe(202);
    expect(second.body.claimId).toBe(first.body.claimId);

    const count = await getDb().getOne('SELECT COUNT(*) AS c FROM pending_claims');
    expect(Number(count.c)).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test('a requested tier that is not sold is not stored', async () => {
    const res = await startPendingClaim({ tier: 'platinum' });
    const row = await getDb().getOne('SELECT requested_tier FROM pending_claims WHERE claim_id = ?', [res.body.claimId]);
    expect(row.requested_tier).toBe(null);
  });

  test('an already-claimed payment is still replayed, never sent to MacroDroid', async () => {
    // A committed claim: the same mobile number proves the retry is genuine.
    await seedVoucher('WIFI-REPLAY-001');
    await getDb().run(
      `INSERT INTO webhook_events (event_id, ref_no, amount, status, mobile_number)
       VALUES ('evt_replay', 'REF-REPLAY1234', 50, 'claimed', ?)`,
      [MOBILE]
    );
    await getDb().run(
      `UPDATE vouchers SET state = 'claimed', assigned_ref_no = 'REF-REPLAY1234' WHERE code = 'WIFI-REPLAY-001'`
    );

    const res = await startPendingClaim({ ref_suffix: '1234' });

    expect(res.status).toBe(200);
    expect(res.body.alreadyClaimed).toBe(true);
    expect(res.body.voucherCode).toBe('WIFI-REPLAY-001');
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('GET /api/payment/claim/status', () => {
  test('reports pending, then verified, then claimed across the whole flow', async () => {
    await seedVoucher('WIFI-FLOW-001');

    const started = await startPendingClaim();
    const claimId = started.body.claimId;

    let status = await request(app).get('/api/payment/claim/status').query({ claimId });
    expect(status.status).toBe(200);
    expect(status.body).toMatchObject({
      success: true,
      claimId,
      state: 'pending',
      ref_suffix: '1234',
    });
    expect(status.headers['cache-control']).toBe('no-store');

    // MacroDroid read the receipt.
    const verified = await request(app)
      .post('/api/webhooks/macrodroid/verify-result')
      .send({ secret_token: SECRET, status: 'verified', ref_code: '1234', ref_no: 'REF-SCRAPE1234', amount: 50 });
    expect(verified.status).toBe(200);
    expect(verified.body.state).toBe('verified');

    status = await request(app).get('/api/payment/claim/status').query({ claimId });
    expect(status.body.state).toBe('verified');
    expect(status.body.ref_no).toBe('REF-SCRAPE1234');
    expect(status.body.amount).toBe(50);

    // The portal repeats the normal claim, which converts the recorded payment.
    const claimed = await request(app)
      .post('/api/payment/claim')
      .send({ ref_suffix: '1234', mobile_number: MOBILE, client_mac: MAC });
    expect(claimed.status).toBe(200);
    expect(claimed.body.authorized).toBe(true);
    expect(claimed.body.voucherCode).toBe('WIFI-FLOW-001');

    status = await request(app).get('/api/payment/claim/status').query({ claimId });
    expect(status.body.state).toBe('claimed');
    expect(status.body.voucherCode).toBe('WIFI-FLOW-001');
    expect(status.body.minutes).toBe(60);

    const row = await getDb().getOne('SELECT state FROM pending_claims WHERE claim_id = ?', [claimId]);
    expect(row.state).toBe('claimed');

    // The authorization only happened once, on the converted claim.
    expect(omadaService.authenticateClient).toHaveBeenCalledTimes(1);
  });

  test('a payment already claimed by ANOTHER number is not shown as claimed', async () => {
    await seedVoucher('WIFI-OTHER-001');
    await getDb().run(
      `INSERT INTO webhook_events (event_id, ref_no, amount, status, mobile_number)
       VALUES ('evt_other', 'REF-OTHERS9999', 50, 'claimed', '09170000000')`
    );
    await getDb().run(
      `UPDATE vouchers SET state = 'claimed', assigned_ref_no = 'REF-OTHERS9999' WHERE code = 'WIFI-OTHER-001'`
    );

    const started = await startPendingClaim({ ref_suffix: '9999' });
    await request(app)
      .post('/api/webhooks/macrodroid/verify-result')
      .send({ secret_token: SECRET, status: 'verified', ref_code: '9999', ref_no: 'REF-OTHERS9999', amount: 50 });

    const status = await request(app)
      .get('/api/payment/claim/status')
      .query({ claimId: started.body.claimId });

    expect(status.body.state).toBe('verified');
    expect(status.body.voucherCode).toBeUndefined();
  });

  test('an unknown claim id is a 404; a malformed one is a 400', async () => {
    const unknown = await request(app)
      .get('/api/payment/claim/status')
      .query({ claimId: 'clm_0123456789abcdef' });
    expect(unknown.status).toBe(404);
    expect(unknown.body.code).toBe('CLAIM_NOT_FOUND');

    const malformed = await request(app).get('/api/payment/claim/status').query({ claimId: 'nope' });
    expect(malformed.status).toBe(400);
    expect(malformed.body.code).toBe('INVALID_CLAIM_ID');
  });

  test('a claim past its deadline is reported (and stored) as expired', async () => {
    const past = new Date(Date.now() - 60000).toISOString();
    await getDb().run(
      `INSERT INTO pending_claims
         (claim_id, ref_suffix, client_mac, mobile_number, requested_tier, state, created_at, updated_at, expires_at)
       VALUES ('clm_expired00000001', '1234', ?, ?, NULL, 'pending', ?, ?, ?)`,
      [MAC, MOBILE, past, past, past]
    );

    const res = await request(app)
      .get('/api/payment/claim/status')
      .query({ claimId: 'clm_expired00000001' });
    expect(res.body.state).toBe('expired');

    const row = await getDb().getOne("SELECT state FROM pending_claims WHERE claim_id = 'clm_expired00000001'");
    expect(row.state).toBe('expired');
  });
});

describe('POST /api/webhooks/macrodroid/verify-result', () => {
  test('requires the shared secret', async () => {
    const started = await startPendingClaim();

    const res = await request(app)
      .post('/api/webhooks/macrodroid/verify-result')
      .send({ secret_token: 'wrong', status: 'verified', ref_code: '1234', ref_no: 'REF-X', amount: 50 });
    expect(res.status).toBe(401);

    const row = await getDb().getOne('SELECT state FROM pending_claims WHERE claim_id = ?', [started.body.claimId]);
    expect(row.state).toBe('pending');
  });

  test('a verified result records the payment as unclaimed and marks the claim verified', async () => {
    const started = await startPendingClaim();

    const res = await request(app)
      .post('/api/webhooks/macrodroid/verify-result')
      .send({
        secret_token: SECRET,
        status: 'verified',
        ref: '1234',              // alias for ref_code
        ref_no: 'REF-SCRAPE5678',
        amount: '50.00',
        tier: 'premium',
      });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      success: true,
      claimId: started.body.claimId,
      state: 'verified',
      ref_no: 'REF-SCRAPE5678',
      amount: 50,
    });

    const event = await getDb().getOne("SELECT * FROM webhook_events WHERE ref_no = 'REF-SCRAPE5678'");
    expect(event.status).toBe('unclaimed');
    expect(Number(event.amount)).toBe(50);

    const row = await getDb().getOne('SELECT * FROM pending_claims WHERE claim_id = ?', [started.body.claimId]);
    expect(row.state).toBe('verified');
    expect(row.ref_no).toBe('REF-SCRAPE5678');
    expect(row.requested_tier).toBe('premium');
  });

  test('a failed result ends the verification without recording a payment', async () => {
    const started = await startPendingClaim();

    const res = await request(app)
      .post('/api/webhooks/macrodroid/verify-result')
      .send({ secret_token: SECRET, status: 'failed', ref_code: '1234', reason: 'No matching receipt on screen' });

    expect(res.status).toBe(200);
    expect(res.body.state).toBe('failed');

    const events = await getDb().getOne('SELECT COUNT(*) AS c FROM webhook_events');
    expect(Number(events.c)).toBe(0);

    const status = await request(app)
      .get('/api/payment/claim/status')
      .query({ claimId: started.body.claimId });
    expect(status.body.state).toBe('failed');
    expect(status.body.reason).toBe('No matching receipt on screen');
  });

  test('a verified result without a reference or amount is rejected', async () => {
    const started = await startPendingClaim();

    const noRef = await request(app)
      .post('/api/webhooks/macrodroid/verify-result')
      .send({ secret_token: SECRET, status: 'verified', ref_code: '1234', amount: 50 });
    expect(noRef.status).toBe(400);
    expect(noRef.body.code).toBe('INVALID_REF_NO');

    const noAmount = await request(app)
      .post('/api/webhooks/macrodroid/verify-result')
      .send({ secret_token: SECRET, status: 'verified', ref_code: '1234', ref_no: 'REF-NOAMT' });
    expect(noAmount.status).toBe(400);
    expect(noAmount.body.code).toBe('INVALID_AMOUNT');

    const row = await getDb().getOne('SELECT state FROM pending_claims WHERE claim_id = ?', [started.body.claimId]);
    expect(row.state).toBe('pending');
  });

  test('a result for a claim whose window has closed is refused', async () => {
    const past = new Date(Date.now() - 60000).toISOString();
    await getDb().run(
      `INSERT INTO pending_claims
         (claim_id, ref_suffix, client_mac, mobile_number, requested_tier, state, created_at, updated_at, expires_at)
       VALUES ('clm_late00000000001', '4321', ?, ?, NULL, 'pending', ?, ?, ?)`,
      [MAC, MOBILE, past, past, past]
    );

    const res = await request(app)
      .post('/api/webhooks/macrodroid/verify-result')
      .send({ secret_token: SECRET, status: 'verified', ref_code: '4321', ref_no: 'REF-LATE', amount: 50 });

    expect(res.status).toBe(410);
    expect(res.body.code).toBe('PENDING_CLAIM_EXPIRED');
  });

  test('an echoed MAC scopes the answer when two claims share the same digits', async () => {
    const MAC2 = 'BB:BB:BB:BB:BB:BB';
    const first = await startPendingClaim();
    const second = await startPendingClaim({ client_mac: MAC2, mobile_number: '09180000000' });

    // Without a MAC the callback would pick the newest claim — the wrong device.
    const res = await request(app)
      .post('/api/webhooks/macrodroid/verify-result')
      .send({
        secret_token: SECRET,
        status: 'verified',
        ref_code: '1234',
        ref_no: 'REF-MAC-SCOPED',
        amount: 50,
        client_mac: MAC2,
      });

    expect(res.status).toBe(200);
    expect(res.body.claimId).toBe(second.body.claimId);

    const firstRow = await getDb().getOne('SELECT state FROM pending_claims WHERE claim_id = ?', [first.body.claimId]);
    expect(firstRow.state).toBe('pending');
  });

  test('a result for digits the portal never asked about is a 404', async () => {
    const res = await request(app)
      .post('/api/webhooks/macrodroid/verify-result')
      .send({ secret_token: SECRET, status: 'verified', ref_code: '9876', ref_no: 'REF-GHOST', amount: 50 });

    expect(res.status).toBe(404);
    expect(res.body.code).toBe('PENDING_CLAIM_NOT_FOUND');
  });
});
