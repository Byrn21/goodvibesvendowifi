/**
 * __tests__/payment-methods.test.js
 * Integration tests for the admin-controlled payment method availability:
 *
 *   GET  /api/payment/methods         (public, captive portal)
 *   GET  /api/admin/payment-methods   (auth)
 *   PUT  /api/admin/payment-methods/:key (auth)
 *
 * Covers:
 *   - every method defaults to enabled (freshly migrated database)
 *   - a disabled method is reported as enabled:false to the guest portal
 *     while every other method keeps working
 *   - re-enabling restores it
 *   - re-applying schema.sql (npm run db:migrate) does NOT reset an admin's
 *     choice — the seed is INSERT ... ON CONFLICT DO NOTHING
 *   - 401 without a token/API key on both admin routes
 *   - 400 for an unknown method key and for a non-boolean `enabled`
 *   - custom logos: upload, public exposure as logoBase64, preservation across a
 *     toggle, clearing with null, and rejection of bad/oversized/SVG values
 *   - a ~100 kB logo is accepted (the body-limit exception in server.js works)
 *
 * Patterns follow backend/__tests__/admin.test.js:
 *   - Temp SQLite database created before requiring db/client.js
 *   - Schema applied via schema.sql
 *   - supertest against the Express app exported from src/server.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Environment setup MUST happen before requiring any backend modules
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-payment-methods-test-'));
const TEST_DB_PATH = path.join(TEST_DB_DIR, 'test.db');

process.env.DATABASE_URL = 'sqlite:' + TEST_DB_PATH;
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');

const VALID_KEY = 'test-admin-key';

const SCHEMA_PATH = path.join(__dirname, '..', 'src', 'db', 'schema.sql');

async function applySchema() {
  await getDb().exec(fs.readFileSync(SCHEMA_PATH, 'utf8'));
}

/** Availability as the guest portal sees it: { gcash: true, maya: false, … }. */
async function publicAvailability() {
  const res = await request(app).get('/api/payment/methods');
  expect(res.status).toBe(200);
  const availability = {};
  ['gcash', 'maya', 'qrph'].forEach((key) => {
    availability[key] = res.body[key].enabled;
  });
  return availability;
}

function setEnabled(key, body, auth = true) {
  const req = request(app).put('/api/admin/payment-methods/' + key);
  if (auth) req.set('X-API-Key', VALID_KEY);
  return req.send(body);
}

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

// Every test starts from "all methods enabled, no custom logo".
beforeEach(async () => {
  await getDb().run('UPDATE payment_methods SET is_active = 1, logo_base64 = NULL');
});

describe('GET /api/payment/methods — availability defaults', () => {
  test('reports every method as enabled on a freshly migrated database', async () => {
    const availability = await publicAvailability();
    expect(availability).toEqual({ gcash: true, maya: true, qrph: true });
  });

  test('still serves receiver details alongside the enabled flag', async () => {
    const saved = process.env.GCASH_NAME;
    process.env.GCASH_NAME = 'Store GCash';
    try {
      const res = await request(app).get('/api/payment/methods');
      expect(res.status).toBe(200);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.body.gcash).toMatchObject({ name: 'GCash', enabled: true, accountName: 'Store GCash' });
    } finally {
      if (saved === undefined) delete process.env.GCASH_NAME;
      else process.env.GCASH_NAME = saved;
    }
  });
});

describe('PUT /api/admin/payment-methods/:key — toggling', () => {
  test('disables one method without touching the others', async () => {
    const res = await setEnabled('maya', { enabled: false });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.method).toMatchObject({ key: 'maya', enabled: false });

    // The response carries the whole list, which is what the admin UI renders.
    const maya = res.body.methods.find((m) => m.key === 'maya');
    const gcash = res.body.methods.find((m) => m.key === 'gcash');
    expect(maya.enabled).toBe(false);
    expect(gcash.enabled).toBe(true);

    expect(await publicAvailability()).toEqual({ gcash: true, maya: false, qrph: true });
  });

  test('re-enables a disabled method', async () => {
    await setEnabled('maya', { enabled: false });
    const res = await setEnabled('maya', { enabled: true });
    expect(res.status).toBe(200);
    expect(res.body.method).toMatchObject({ key: 'maya', enabled: true });
    expect(await publicAvailability()).toEqual({ gcash: true, maya: true, qrph: true });
  });

  test('persists through a schema re-apply (the seed never overwrites a choice)', async () => {
    await setEnabled('qrph', { enabled: false });

    // What `npm run db:migrate` does on every deploy: apply schema.sql again.
    await applySchema();

    expect(await publicAvailability()).toEqual({ gcash: true, maya: true, qrph: false });
  });

  test('accepts a mixed-case method key', async () => {
    const res = await setEnabled('GCash', { enabled: false });
    expect(res.status).toBe(200);
    expect(res.body.method.key).toBe('gcash');
    expect(await publicAvailability()).toEqual({ gcash: false, maya: true, qrph: true });
  });
});

describe('PUT /api/admin/payment-methods/:key — validation', () => {
  test('rejects an unknown method key with 400', async () => {
    const res = await setEnabled('paypal', { enabled: false });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('UNKNOWN_PAYMENT_METHOD');
  });

  test('rejects a non-boolean enabled value with 400', async () => {
    const res = await setEnabled('gcash', { enabled: 'false' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_ENABLED_VALUE');

    // A string "false" must not have been applied as a truthy value.
    expect((await publicAvailability()).gcash).toBe(true);
  });

  test('rejects an explicit non-boolean with 400 (and reports what to send instead)', async () => {
    const res = await setEnabled('gcash', { enabled: 1 });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_ENABLED_VALUE');
  });
});

describe('PUT /api/admin/payment-methods/:key — custom Base64 logo', () => {
  // A valid 1x1 PNG, the shape the admin panel uploads after resizing.
  const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

  test('stores a logo and exposes it to the portal as logoBase64', async () => {
    const res = await setEnabled('gcash', { logoBase64: PNG });
    expect(res.status).toBe(200);
    expect(res.body.method).toMatchObject({ key: 'gcash', logoBase64: PNG });

    const portal = await request(app).get('/api/payment/methods');
    expect(portal.status).toBe(200);
    expect(portal.body.gcash.logoBase64).toBe(PNG);
    // Untouched methods still carry an explicit null, never undefined.
    expect(portal.body.maya.logoBase64).toBeNull();
    expect(portal.body.qrph.logoBase64).toBeNull();
  });

  test('accepts logo_base64 as an alias for the same field', async () => {
    const res = await setEnabled('maya', { logo_base64: PNG });
    expect(res.status).toBe(200);
    expect(res.body.method.logoBase64).toBe(PNG);
  });

  test('a logo upload does not change the availability switch', async () => {
    await setEnabled('gcash', { enabled: false });
    const res = await setEnabled('gcash', { logoBase64: PNG });
    expect(res.status).toBe(200);
    expect(res.body.method).toMatchObject({ enabled: false, logoBase64: PNG });
    expect(await publicAvailability()).toEqual({ gcash: false, maya: true, qrph: true });
  });

  test('a toggle does not wipe an uploaded logo', async () => {
    await setEnabled('gcash', { logoBase64: PNG });
    await setEnabled('gcash', { enabled: false });
    const res = await setEnabled('gcash', { enabled: true });
    expect(res.status).toBe(200);
    expect(res.body.method).toMatchObject({ enabled: true, logoBase64: PNG });
  });

  test('null clears the custom logo', async () => {
    await setEnabled('gcash', { logoBase64: PNG });
    const res = await setEnabled('gcash', { logoBase64: null });
    expect(res.status).toBe(200);
    expect(res.body.method.logoBase64).toBeNull();
    expect((await request(app).get('/api/payment/methods')).body.gcash.logoBase64).toBeNull();
  });

  test('rejects a non-data-URI value with 400 INVALID_LOGO', async () => {
    const res = await setEnabled('gcash', { logoBase64: 'assets/images/gcash.png' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_LOGO');
    expect((await request(app).get('/api/payment/methods')).body.gcash.logoBase64).toBeNull();
  });

  test('rejects an SVG data URI (script-capable image format)', async () => {
    const res = await setEnabled('gcash', { logoBase64: 'data:image/svg+xml;base64,PHN2Zy8+' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_LOGO');
  });

  test('rejects a logo larger than the 200 kB cap', async () => {
    const tooBig = 'data:image/png;base64,' + 'A'.repeat(210 * 1024);
    const res = await setEnabled('gcash', { logoBase64: tooBig });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_LOGO');
  });

  test('accepts a ~100 kB logo — the route gets a larger body limit than the 16 kB default', async () => {
    // Without the routed body-limit exception in server.js this request dies with
    // 413 before the route ever runs.
    const big = 'data:image/png;base64,' + 'A'.repeat(100 * 1024);
    const res = await setEnabled('gcash', { logoBase64: big });
    expect(res.status).toBe(200);
    expect(res.body.method.logoBase64).toBe(big);
  });

  test('rejects a request with neither enabled nor logoBase64', async () => {
    const res = await setEnabled('gcash', {});
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('NOTHING_TO_UPDATE');
  });
});

describe('admin payment-method routes require authentication', () => {
  test('GET is 401 without a token', async () => {
    const res = await request(app).get('/api/admin/payment-methods');
    expect(res.status).toBe(401);
  });

  test('PUT is 401 without a token', async () => {
    const res = await setEnabled('gcash', { enabled: false }, false);
    expect(res.status).toBe(401);
    // Nothing changed.
    expect((await publicAvailability()).gcash).toBe(true);
  });

  test('GET returns the states for an authenticated admin', async () => {
    const res = await request(app)
      .get('/api/admin/payment-methods')
      .set('X-API-Key', VALID_KEY);
    expect(res.status).toBe(200);
    expect(res.body.methods).toHaveLength(3);
    expect(res.body.methods.map((m) => m.key)).toEqual(['gcash', 'maya', 'qrph']);
    res.body.methods.forEach((m) => expect(typeof m.enabled).toBe('boolean'));
    res.body.methods.forEach((m) => expect('logoBase64' in m).toBe(true));
  });
});
