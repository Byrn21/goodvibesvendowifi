/**
 * __tests__/voucher-qos.test.js
 *
 * Covers bandwidth (QoS) capping for VOUCHER login — the gap that let a guest
 * who redeemed a voucher run at the router's full speed:
 *
 *   - vouchers.down_kbps / up_kbps are validated, stored and snapshotted onto
 *     the session when POST /api/auth authorizes the client;
 *   - the cap is applied through the documented Omada call
 *     (omadaNorthbound.setClientRateLimit via applyClientRateLimit), NOT by
 *     adding non-spec fields to the extPortal/auth body;
 *   - the voucher's own caps win, premium falls back to PREMIUM_*, standard
 *     falls back to the VOUCHER_DEFAULT_* service defaults;
 *   - a failed cap never fails the login (the guest is already online);
 *   - a re-login with a still-active voucher re-applies the stored caps;
 *   - the admin API accepts/returns the caps and rejects a half-configured pair.
 *
 * Patterns follow backend/__tests__/auth-omada-passthrough.test.js: temp SQLite
 * database created before requiring db/client.js, schema applied via
 * schema.sql, supertest against the app exported from src/server.js.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-voucher-qos-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';        // mock hotspot controller
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';
process.env.PREMIUM_DOWN_MBPS = '50';
process.env.PREMIUM_UP_KBPS = '1024';

const request = require('supertest');
const XLSX = require('xlsx');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const omada = require('../src/services/omada');
const omadaNorthbound = require('../src/services/omada-northbound');
const {
  resolveVoucherRateLimit,
  normalizeBandwidthKbps,
  toRateLimitUnit,
} = require('../src/utils/qos');

const MAC = 'AA:BB:CC:DD:EE:FF';
const ADMIN = { 'X-API-Key': 'test-admin-key' };

async function applySchema() {
  await getDb().exec(
    fs.readFileSync(path.join(__dirname, '..', 'src', 'db', 'schema.sql'), 'utf8')
  );
}

async function seedVoucher(code, type = 'standard', downKbps = null, upKbps = null) {
  await getDb().run(
    `INSERT INTO vouchers (code, type, duration_minutes, price, down_kbps, up_kbps, state)
     VALUES (?, ?, 60, 0, ?, ?, 'active')`,
    [code, type, downKbps, upKbps]
  );
}

function authRequest(body) {
  return request(app).post('/api/auth').send(Object.assign({
    clientMac: MAC,
    clientIp: '10.0.0.5',
    apMac: 'AA:AA:AA:AA:AA:AA',
    ssidName: 'GoodVibesVendoWifi',
    termsAccepted: true,
  }, body));
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

beforeEach(async () => {
  await getDb().exec('DELETE FROM sessions; DELETE FROM vouchers;');
  jest.spyOn(omada, 'authenticateClient').mockResolvedValue({ success: true, raw: {} });
  jest.spyOn(omadaNorthbound, 'applyClientRateLimit')
    .mockResolvedValue({ success: true, mocked: false, retried: false });
});

afterEach(() => {
  jest.restoreAllMocks();
});

// ── Units: voucher → customRateLimit ────────────────────────────────────────
describe('resolveVoucherRateLimit — voucher caps → Omada payload values', () => {
  test('converts Kbps caps, using Mbps above 1024 Kbps', () => {
    expect(resolveVoucherRateLimit({ downKbps: 20000, upKbps: 5000, voucherType: 'standard' }))
      .toEqual({
        upEnable: true, upUnit: 2, upLimit: 5,
        downEnable: true, downUnit: 2, downLimit: 20,
      });
  });

  test('keeps small caps in Kbps (≤1024 stays unit 1)', () => {
    expect(resolveVoucherRateLimit({ downKbps: 512, upKbps: 512 })).toEqual({
      upEnable: true, upUnit: 1, upLimit: 512,
      downEnable: true, downUnit: 1, downLimit: 512,
    });
  });

  test('a 5 Mbps cap is sent as 5000 Kbps-equivalent (unit 2, limit 5)', () => {
    expect(toRateLimitUnit(5000)).toEqual({ unit: 2, limit: 5 });
    expect(toRateLimitUnit(1000)).toEqual({ unit: 1, limit: 1000 });
  });

  test('falls back to PREMIUM_* for a premium voucher with no explicit caps', () => {
    expect(resolveVoucherRateLimit({ voucherType: 'premium' })).toEqual({
      upEnable: true, upUnit: 1, upLimit: 1024,
      downEnable: true, downUnit: 2, downLimit: 50,
    });
  });

  test('returns undefined for a standard voucher with no explicit caps (service defaults)', () => {
    expect(resolveVoucherRateLimit({ voucherType: 'standard' })).toBeUndefined();
  });

  test('a half-configured pair is ignored rather than capping one direction only', () => {
    expect(resolveVoucherRateLimit({ downKbps: 20000, upKbps: null, voucherType: 'standard' }))
      .toBeUndefined();
  });

  test('rejects out-of-range / non-integer caps', () => {
    expect(normalizeBandwidthKbps(0)).toBeNull();
    expect(normalizeBandwidthKbps(-5)).toBeNull();
    expect(normalizeBandwidthKbps(1.5)).toBeNull();
    expect(normalizeBandwidthKbps(1024001)).toBeNull();
    expect(normalizeBandwidthKbps('fast')).toBeNull();
    expect(normalizeBandwidthKbps(5000)).toBe(5000);
    expect(resolveVoucherRateLimit({ downKbps: 'fast', upKbps: 5000 })).toBeUndefined();
  });
});

// ── Route: POST /api/auth applies the voucher's cap ────────────────────────
describe('POST /api/auth — applies the voucher bandwidth cap', () => {
  test('applies the voucher caps and snapshots them onto the session', async () => {
    await seedVoucher('654321', 'standard', 20000, 5000);

    const res = await authRequest({ voucher: '654321' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.qosApplied).toBe(true);

    expect(omadaNorthbound.applyClientRateLimit).toHaveBeenCalledTimes(1);
    expect(omadaNorthbound.applyClientRateLimit).toHaveBeenCalledWith({
      clientMac: MAC,
      customRateLimit: {
        upEnable: true, upUnit: 2, upLimit: 5,
        downEnable: true, downUnit: 2, downLimit: 20,
      },
    });

    const session = await getDb().getOne(
      'SELECT down_kbps, up_kbps FROM sessions WHERE session_id = ?',
      [res.body.sessionId]
    );
    expect(session.down_kbps).toBe(20000);
    expect(session.up_kbps).toBe(5000);
  });

  test('a standard voucher without caps asks for the service default caps', async () => {
    await seedVoucher('111222', 'standard');

    const res = await authRequest({ voucher: '111222' });

    expect(res.status).toBe(200);
    expect(omadaNorthbound.applyClientRateLimit).toHaveBeenCalledWith({ clientMac: MAC });
  });

  test('a premium voucher without caps uses the premium tier caps', async () => {
    await seedVoucher('333444', 'premium');

    await authRequest({ voucher: '333444' });

    expect(omadaNorthbound.applyClientRateLimit).toHaveBeenCalledWith({
      clientMac: MAC,
      customRateLimit: {
        upEnable: true, upUnit: 1, upLimit: 1024,
        downEnable: true, downUnit: 2, downLimit: 50,
      },
    });
  });

  test('a failed cap does NOT fail the login and is reported in the response', async () => {
    await seedVoucher('555666', 'standard', 10000, 2000);
    omadaNorthbound.applyClientRateLimit.mockRejectedValueOnce(
      new Error('OMADA_NORTHBOUND_REJECTED: 404')
    );

    const res = await authRequest({ voucher: '555666' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.qosApplied).toBe(false);
    expect(res.body.qosError).toContain('OMADA_NORTHBOUND_REJECTED');

    // The session was still recorded, so the guest can see their session.
    const session = await getDb().getOne(
      'SELECT state FROM sessions WHERE session_id = ?',
      [res.body.sessionId]
    );
    expect(session.state).toBe('active');
  });

  test('a re-login with a still-active voucher re-applies the SESSION caps', async () => {
    await seedVoucher('777888', 'premium', 30000, 10000);
    const first = await authRequest({ voucher: '777888' });
    expect(first.status).toBe(200);

    // The voucher cap is changed after the fact; the live session must keep
    // the cap it was created with.
    await getDb().run('UPDATE vouchers SET down_kbps = 1000, up_kbps = 1000 WHERE code = ?', ['777888']);
    omadaNorthbound.applyClientRateLimit.mockClear();

    const second = await authRequest({ voucher: '777888' });

    expect(second.status).toBe(200);
    expect(second.body.sessionId).toBe(first.body.sessionId);
    expect(omadaNorthbound.applyClientRateLimit).toHaveBeenCalledWith({
      clientMac: MAC,
      customRateLimit: {
        upEnable: true, upUnit: 2, upLimit: 10,
        downEnable: true, downUnit: 2, downLimit: 30,
      },
    });
  });
});

// ── Admin API: setting the caps ─────────────────────────────────────────────
describe('Admin voucher caps', () => {
  test('creates a voucher with caps and lists them', async () => {
    const created = await request(app)
      .post('/api/admin/vouchers')
      .set(ADMIN)
      .send({ type: 'standard', durationMinutes: 60, quantity: 1, downKbps: 20000, upKbps: 5000 });

    expect(created.status).toBe(201);
    const code = created.body.created[0];

    const list = await request(app).get('/api/admin/vouchers').set(ADMIN);
    const row = list.body.vouchers.find((v) => v.code === code);
    expect(row.down_kbps).toBe(20000);
    expect(row.up_kbps).toBe(5000);
  });

  test('rejects a half-configured cap pair on create', async () => {
    const res = await request(app)
      .post('/api/admin/vouchers')
      .set(ADMIN)
      .send({ type: 'standard', durationMinutes: 60, downKbps: 20000 });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/together/);
  });

  test('rejects out-of-range caps on create', async () => {
    const res = await request(app)
      .post('/api/admin/vouchers')
      .set(ADMIN)
      .send({ type: 'standard', durationMinutes: 60, downKbps: 5000000, upKbps: 5000 });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Kbps/);
  });

  test('updates caps and clears them with null/null', async () => {
    await seedVoucher('901234', 'standard', 5000, 1000);
    const row = await getDb().getOne('SELECT id FROM vouchers WHERE code = ?', ['901234']);

    const set = await request(app)
      .put('/api/admin/vouchers/' + row.id)
      .set(ADMIN)
      .send({ downKbps: 50000, upKbps: 20000 });
    expect(set.status).toBe(200);

    let after = await getDb().getOne('SELECT down_kbps, up_kbps FROM vouchers WHERE id = ?', [row.id]);
    expect(after.down_kbps).toBe(50000);
    expect(after.up_kbps).toBe(20000);

    const clear = await request(app)
      .put('/api/admin/vouchers/' + row.id)
      .set(ADMIN)
      .send({ downKbps: null, upKbps: null });
    expect(clear.status).toBe(200);

    after = await getDb().getOne('SELECT down_kbps, up_kbps FROM vouchers WHERE id = ?', [row.id]);
    expect(after.down_kbps).toBeNull();
    expect(after.up_kbps).toBeNull();
  });

  test('imports optional Download/Upload (Kbps) columns', async () => {
    const sheet = XLSX.utils.aoa_to_sheet([
      ['ID', 'Code', 'Type', 'Duration', 'Price', 'Download (Kbps)', 'Upload (Kbps)'],
      [1, '121212', 'standard', 60, '₱50.00', 20000, 5000],
      [2, '343434', 'premium', 120, '₱100.00', '', ''],
    ]);
    const book = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(book, sheet, 'Vouchers');
    const buffer = XLSX.write(book, { bookType: 'xlsx', type: 'buffer' });

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set(ADMIN)
      .attach('file', buffer, 'vouchers.xlsx');

    expect(res.status).toBe(200);
    expect(res.body.summary.inserted).toBe(2);

    const capped = await getDb().getOne(
      'SELECT down_kbps, up_kbps FROM vouchers WHERE code = ?',
      ['121212']
    );
    expect(capped.down_kbps).toBe(20000);
    expect(capped.up_kbps).toBe(5000);

    const uncapped = await getDb().getOne(
      'SELECT down_kbps, up_kbps FROM vouchers WHERE code = ?',
      ['343434']
    );
    expect(uncapped.down_kbps).toBeNull();
    expect(uncapped.up_kbps).toBeNull();
  });
});
