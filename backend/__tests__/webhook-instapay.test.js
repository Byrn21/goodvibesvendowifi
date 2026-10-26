/**
 * __tests__/webhook-instapay.test.js
 * Integration tests for routes/webhook.js POST /api/webhooks/instapay
 *
 * The controller web API is mocked (services/omada), so these tests assert
 * the CONTRACT OF THE HANDLER rather than HTTP details:
 *   - 401 missing / invalid secret (constant-time comparison path)
 *   - 400 invalid payment_method, client_mac, amount, ref_no, amount too small
 *   - 409 duplicate ref_no (pre-check SELECT + UNIQUE constraint backstop)
 *   - 502 when authenticateClient fails — and setClientRateLimit is NEVER called
 *   - 502 MISSING_PORTAL_CONTEXT when the device never landed on the portal
 *     (extPortal/auth is connection-type specific, so there is nothing to send)
 *   - 200 success: authenticateClient → (>= 2000 ms) → setClientRateLimit, in
 *     that exact order, with the rate limit called WITHOUT explicit limits so
 *     the service falls back to VOUCHER_DEFAULT_*
 *   - tiered QoS: each premium amount (PREMIUM_AMOUNTS_PESOS, default
 *     25/45/80) passes PREMIUM_DOWN_MBPS / PREMIUM_UP_KBPS as integers; every
 *     other amount (and a premium amount with unset/out-of-range premium caps)
 *     uses the default VOUCHER_DEFAULT_* path
 *   - a failed rate limit is tolerated (200 + qosApplied:false), because the
 *     guest is already online
 *
 * Patterns follow backend/__tests__/webhook.test.js:
 *   - Temp SQLite database created before requiring db/client.js
 *   - Schema applied via schema.sql
 *   - supertest against the Express app exported from src/server.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Environment setup MUST happen before requiring any backend modules
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-instapay-test-'));
const TEST_DB_PATH = path.join(TEST_DB_DIR, 'test.db');

process.env.DATABASE_URL = 'sqlite:' + TEST_DB_PATH;
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';          // keeps the local controller path in mock mode
process.env.OMADA_MOCK = 'true';
process.env.MACRODROID_PESOS_PER_MINUTE = '10';
process.env.INSTAPAY_WEBHOOK_SECRET = 'instapay-test-secret';
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';

// The controller client is replaced wholesale: no fetch, no credentials needed.
// The rest of the module stays real so server startup (logResolvedConfig) and
// the session service keep working.
jest.mock('../src/services/omada', () => Object.assign(
  {},
  jest.requireActual('../src/services/omada'),
  { authenticateClient: jest.fn(), setClientRateLimit: jest.fn() }
));

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const omadaService = require('../src/services/omada');

// The handler waits a real 2000 ms, so allow more than the 5 s default.
jest.setTimeout(20000);

const SECRET = 'instapay-test-secret';
const MAC = 'AA:BB:CC:DD:EE:FF';
const AUTH_INDEX_DELAY_MS = 2000;
const AP_MAC = 'AA:AA:AA:AA:AA:AA';
const SSID = 'GoodVibesVendoWifi';
const CLIENT_IP = '10.0.0.5';

// The controller context a device gets by landing on the captive portal
// (POST /api/payment/context). extPortal/auth cannot be called without it.
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

function payload(overrides = {}) {
  return Object.assign(
    {
      secret_token: SECRET,
      payment_method: 'instapay',
      client_mac: MAC,
      amount: 50,
      ref_no: 'IP-' + Math.random().toString(36).slice(2, 10),
    },
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
  await getDb().exec(
    'DELETE FROM webhook_events; DELETE FROM sessions; DELETE FROM portal_client_context;'
  );
  await seedPortalContext();
  jest.clearAllMocks();
  omadaService.authenticateClient.mockResolvedValue({
    success: true, verified: true, result: 0, msg: 'auth success (test)',
  });
  omadaService.setClientRateLimit.mockResolvedValue({ success: true, clientMac: MAC });
});

// --- Tests ---

describe('POST /api/webhooks/instapay — validation', () => {

  test('401 when secret_token is missing or wrong', async () => {
    const missing = payload(); delete missing.secret_token;
    const res1 = await request(app).post('/api/webhooks/instapay').send(missing);
    expect(res1.status).toBe(401);
    expect(res1.body.code).toBe('MISSING_SECRET');

    const res2 = await request(app).post('/api/webhooks/instapay').send(payload({ secret_token: 'nope' }));
    expect(res2.status).toBe(401);
    expect(res2.body.code).toBe('INVALID_SECRET');

    expect(omadaService.authenticateClient).not.toHaveBeenCalled();
  });

  test('400 for an unsupported payment_method', async () => {
    const res = await request(app).post('/api/webhooks/instapay').send(payload({ payment_method: 'gcash' }));
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_PAYMENT_METHOD');
  });

  test('400 when client_mac is missing or malformed', async () => {
    const missing = payload(); delete missing.client_mac;
    const res1 = await request(app).post('/api/webhooks/instapay').send(missing);
    expect(res1.status).toBe(400);
    expect(res1.body.code).toBe('INVALID_CLIENT_MAC');

    const res2 = await request(app).post('/api/webhooks/instapay').send(payload({ client_mac: 'not-a-mac' }));
    expect(res2.status).toBe(400);
    expect(res2.body.code).toBe('INVALID_CLIENT_MAC');
  });

  test('400 for a missing/invalid amount or ref_no', async () => {
    const badAmount = payload(); delete badAmount.amount;
    const res1 = await request(app).post('/api/webhooks/instapay').send(badAmount);
    expect(res1.status).toBe(400);
    expect(res1.body.code).toBe('INVALID_AMOUNT');

    const badRef = payload({ ref_no: 'x'.repeat(65) });
    const res2 = await request(app).post('/api/webhooks/instapay').send(badRef);
    expect(res2.status).toBe(400);
    expect(res2.body.code).toBe('INVALID_REF_NO');
  });

  test('400 when the amount buys no whole minute', async () => {
    const res = await request(app).post('/api/webhooks/instapay').send(payload({ amount: 5 }));
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('AMOUNT_TOO_SMALL');
    expect(omadaService.authenticateClient).not.toHaveBeenCalled();
  });

  test('409 duplicate ref_no is rejected before any new write', async () => {
    const ref = 'IP-DUP-1';
    const first = await request(app).post('/api/webhooks/instapay').send(payload({ ref_no: ref }));
    expect(first.status).toBe(200);

    const dup = await request(app).post('/api/webhooks/instapay').send(payload({ ref_no: ref }));
    expect(dup.status).toBe(409);
    expect(dup.body.code).toBe('DUPLICATE_REF_NO');

    const events = await getDb().query('SELECT id FROM webhook_events WHERE ref_no = ?', [ref]);
    expect(events.length).toBe(1);
  });
});

describe('POST /api/webhooks/instapay — Omada sequence', () => {

  test('502 when authenticateClient fails: no rate limit, event flagged auth_failed', async () => {
    omadaService.authenticateClient.mockRejectedValue(new Error('controller unreachable'));
    const ref = 'IP-AUTHFAIL-1';

    const res = await request(app).post('/api/webhooks/instapay').send(payload({ ref_no: ref }));

    expect(res.status).toBe(502);
    expect(res.body.code).toBe('OMADA_AUTH_FAILED');
    expect(omadaService.setClientRateLimit).not.toHaveBeenCalled();

    const event = await getDb().getOne('SELECT status FROM webhook_events WHERE ref_no = ?', [ref]);
    expect(event.status).toBe('auth_failed');
  });

  test('502 MISSING_PORTAL_CONTEXT when the device never landed on the portal', async () => {
    await getDb().exec('DELETE FROM portal_client_context;');
    const ref = 'IP-NOCTX-1';

    const res = await request(app).post('/api/webhooks/instapay').send(payload({ ref_no: ref }));

    expect(res.status).toBe(502);
    expect(res.body.code).toBe('MISSING_PORTAL_CONTEXT');
    expect(res.body.error).toMatch(/has not loaded the wi-fi portal/i);
    expect(omadaService.authenticateClient).not.toHaveBeenCalled();
    expect(omadaService.setClientRateLimit).not.toHaveBeenCalled();

    const event = await getDb().getOne('SELECT status FROM webhook_events WHERE ref_no = ?', [ref]);
    expect(event.status).toBe('auth_failed');
  });

  test('success: authenticateClient → 2000 ms wait → setClientRateLimit, then 200', async () => {
    const ref = 'IP-SUCCESS-1';

    const startedAt = Date.now();
    const res = await request(app).post('/api/webhooks/instapay').send(payload({
      ref_no: ref,
      payment_method: 'PESONET', // uppercase must normalize
      amount: 50,
    }));
    const elapsed = Date.now() - startedAt;

    // 200 and the reported payload
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      success: true,
      clientMac: MAC,
      minutes: 5,                    // 50 / MACRODROID_PESOS_PER_MINUTE (10)
      // The web API authorize call returns no cloud auth-record id.
      authRecordId: null,
      qosApplied: true,
    });

    // The guest was authorized for the paid time, on the context captured at
    // portal landing...
    expect(omadaService.authenticateClient).toHaveBeenCalledWith({
      ...AUTH_CTX,
      durationMinutes: 5,
    });

    // ...the QoS call ran AFTER it, with no explicit limits so the service
    // applies VOUCHER_DEFAULT_DOWN_MBPS / VOUCHER_DEFAULT_UP_KBPS...
    expect(omadaService.setClientRateLimit).toHaveBeenCalledWith({ clientMac: MAC });
    expect(omadaService.authenticateClient.mock.invocationCallOrder[0])
      .toBeLessThan(omadaService.setClientRateLimit.mock.invocationCallOrder[0]);

    // ...and the gap between them is the full indexing delay (not skipped).
    expect(elapsed).toBeGreaterThanOrEqual(AUTH_INDEX_DELAY_MS);

    // Payment durability + status
    const event = await getDb().getOne('SELECT * FROM webhook_events WHERE ref_no = ?', [ref]);
    expect(event.status).toBe('authorized');
    expect(event.provider).toBe('pesonet');
    expect(event.event_type).toBe('payment.completed');
    expect(Number(event.amount)).toBe(50);
  });

  test('a failed rate limit does not fail the payment (200 + qosApplied:false)', async () => {
    omadaService.setClientRateLimit.mockRejectedValue(new Error('ratelimit 500'));
    const ref = 'IP-QOSFAIL-1';

    const res = await request(app).post('/api/webhooks/instapay').send(payload({ ref_no: ref, payment_method: 'pesonet' }));

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.qosApplied).toBe(false);
    expect(res.body.qosError).toBe('ratelimit 500');

    // The guest is online, so the event is still marked authorized.
    const event = await getDb().getOne('SELECT status FROM webhook_events WHERE ref_no = ?', [ref]);
    expect(event.status).toBe('authorized');
  });

  test('honours an explicit duration_minutes over the computed one', async () => {
    const res = await request(app).post('/api/webhooks/instapay').send(
      payload({ amount: 50, duration_minutes: 120 })
    );
    expect(res.status).toBe(200);
    expect(res.body.minutes).toBe(120);
    expect(omadaService.authenticateClient).toHaveBeenCalledWith({
      ...AUTH_CTX,
      durationMinutes: 120,
    });
  });
});

describe('POST /api/webhooks/instapay — tiered QoS', () => {
  const PREMIUM_ENV = ['PREMIUM_AMOUNTS_PESOS', 'PREMIUM_DOWN_MBPS', 'PREMIUM_UP_KBPS'];
  let saved;

  beforeEach(() => {
    saved = {};
    for (const name of PREMIUM_ENV) saved[name] = process.env[name];
    delete process.env.PREMIUM_AMOUNTS_PESOS; // exercise the DEFAULT list
    process.env.PREMIUM_DOWN_MBPS = '50';
    process.env.PREMIUM_UP_KBPS = '1024';
  });

  afterEach(() => {
    for (const name of PREMIUM_ENV) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  });

  const PREMIUM_CAPS = {
    upEnable: true,
    upUnit: 1,        // Kbps
    upLimit: 1024,    // PREMIUM_UP_KBPS
    downEnable: true,
    downUnit: 2,      // Mbps
    downLimit: 50,    // PREMIUM_DOWN_MBPS
  };

  test.each([25, 45, 80])(
    'applies the PREMIUM_* caps (as integers) for the default premium amount %i',
    async (amount) => {
      const res = await request(app).post('/api/webhooks/instapay').send(payload({ amount }));

      expect(res.status).toBe(200);
      expect(res.body.qosApplied).toBe(true);
      expect(omadaService.setClientRateLimit).toHaveBeenCalledWith({
        clientMac: MAC,
        customRateLimit: PREMIUM_CAPS,
      });

      // parseInt(..., 10) — the controller rejects strings in the limit fields.
      const arg = omadaService.setClientRateLimit.mock.calls[0][0];
      expect(typeof arg.customRateLimit.upLimit).toBe('number');
      expect(typeof arg.customRateLimit.downLimit).toBe('number');
    }
  );

  test('a non-premium amount falls back to the VOUCHER_DEFAULT_* path (no explicit limits)', async () => {
    const res = await request(app).post('/api/webhooks/instapay').send(payload({ amount: 30 }));

    expect(res.status).toBe(200);
    expect(omadaService.setClientRateLimit).toHaveBeenCalledWith({ clientMac: MAC });
  });

  test('PREMIUM_AMOUNTS_PESOS overrides the default premium list', async () => {
    process.env.PREMIUM_AMOUNTS_PESOS = '15, 99';

    const premium = await request(app).post('/api/webhooks/instapay').send(payload({ amount: 99 }));
    expect(premium.status).toBe(200);
    expect(omadaService.setClientRateLimit).toHaveBeenLastCalledWith(
      expect.objectContaining({ clientMac: MAC, customRateLimit: PREMIUM_CAPS })
    );

    // 80 is a DEFAULT premium amount, but the override list replaces the default.
    const fallback = await request(app).post('/api/webhooks/instapay').send(payload({ amount: 80 }));
    expect(fallback.status).toBe(200);
    expect(omadaService.setClientRateLimit).toHaveBeenLastCalledWith({ clientMac: MAC });
  });

  test('falls back to the default premium amounts when PREMIUM_AMOUNTS_PESOS is empty', async () => {
    process.env.PREMIUM_AMOUNTS_PESOS = '   ';
    const res = await request(app).post('/api/webhooks/instapay').send(payload({ amount: 25 }));

    expect(res.status).toBe(200);
    expect(omadaService.setClientRateLimit).toHaveBeenCalledWith(
      expect.objectContaining({ clientMac: MAC, customRateLimit: PREMIUM_CAPS })
    );
  });

  test('falls back to VOUCHER_DEFAULT_* when the premium caps are unset', async () => {
    delete process.env.PREMIUM_DOWN_MBPS;
    delete process.env.PREMIUM_UP_KBPS;
    const res = await request(app).post('/api/webhooks/instapay').send(payload({ amount: 80 }));

    expect(res.status).toBe(200);
    expect(omadaService.setClientRateLimit).toHaveBeenCalledWith({ clientMac: MAC });
  });

  test('falls back to VOUCHER_DEFAULT_* when a premium cap is out of range', async () => {
    process.env.PREMIUM_DOWN_MBPS = 'not-a-number';
    const res = await request(app).post('/api/webhooks/instapay').send(payload({ amount: 80 }));

    expect(res.status).toBe(200);
    expect(omadaService.setClientRateLimit).toHaveBeenCalledWith({ clientMac: MAC });
  });
});
