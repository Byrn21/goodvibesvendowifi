/**
 * __tests__/voucher-code.test.js
 * Tests for the shared 6-digit voucher code rule:
 *   - utils/voucher-code.js helper (normalize + validate)
 *   - POST /api/auth route: 400 on non-6-digit codes before any DB/Omada work
 *
 * Patterns follow backend/__tests__/admin.test.js:
 *   - Temp SQLite database created before requiring db/client.js
 *   - Schema applied via schema.sql
 *   - supertest with Express app exported from src/server.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Environment setup MUST happen before requiring any backend modules
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-vcode-test-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const {
  VOUCHER_CODE_PATTERN,
  VOUCHER_CODE_MESSAGE,
  normalizeVoucherCode,
  validateVoucherCodeFormat,
} = require('../src/utils/voucher-code');

async function applySchema() {
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'db', 'schema.sql'),
    'utf8'
  );
  await getDb().exec(schema);
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

// --- Helper unit tests ---

describe('utils/voucher-code.js', () => {
  test('VOUCHER_CODE_PATTERN matches exactly 6 digits', () => {
    expect(VOUCHER_CODE_PATTERN.test('123456')).toBe(true);
    expect(VOUCHER_CODE_PATTERN.test('12345')).toBe(false);
    expect(VOUCHER_CODE_PATTERN.test('1234567')).toBe(false);
    expect(VOUCHER_CODE_PATTERN.test('12345a')).toBe(false);
    expect(VOUCHER_CODE_PATTERN.test('')).toBe(false);
  });

  test('VOUCHER_CODE_MESSAGE is the user-facing message', () => {
    expect(VOUCHER_CODE_MESSAGE).toBe('Voucher code must be exactly 6 digits.');
  });

  test('normalizeVoucherCode strips non-digits and trims', () => {
    expect(normalizeVoucherCode('  123456  ')).toBe('123456');
    expect(normalizeVoucherCode('123-456')).toBe('123456');
    expect(normalizeVoucherCode('123 456')).toBe('123456');
    expect(normalizeVoucherCode('12a345')).toBe('12345');
    expect(normalizeVoucherCode(null)).toBe('');
    expect(normalizeVoucherCode(undefined)).toBe('');
    expect(normalizeVoucherCode(123456)).toBe('123456');
  });

  test('validateVoucherCodeFormat accepts 6-digit values', () => {
    const r = validateVoucherCodeFormat('123456');
    expect(r.ok).toBe(true);
    expect(r.value).toBe('123456');
  });

  test('validateVoucherCodeFormat rejects 5-digit, 8-digit, and non-numeric values', () => {
    for (const bad of ['12345', '1234567', '12345a', 'abcdef', '']) {
      const r = validateVoucherCodeFormat(bad);
      expect(r.ok).toBe(false);
      expect(r.message).toBe(VOUCHER_CODE_MESSAGE);
    }
  });
});

// --- Route-level tests (format gate runs before DB/Omada) ---

describe('POST /api/auth — voucher code format gate', () => {
  const BASE_BODY = {
    clientMac: 'aa:bb:cc:dd:ee:ff',
    clientIp: '192.168.1.105',
    termsAccepted: true,
  };

  beforeEach(async () => {
    await getDb().exec('DELETE FROM sessions; DELETE FROM vouchers; DELETE FROM webhook_events;');
  });

  test('returns 400 for 5-digit code', async () => {
    const res = await request(app)
      .post('/api/auth')
      .send({ ...BASE_BODY, voucher: '12345' });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toBe('Voucher code must be exactly 6 digits.');
    expect(res.body.code).toBe('INVALID_INPUT');
  });

  test('returns 400 for 8-digit code', async () => {
    const res = await request(app)
      .post('/api/auth')
      .send({ ...BASE_BODY, voucher: '12345678' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Voucher code must be exactly 6 digits.');
  });

  test('returns 400 for letter-containing code', async () => {
    const res = await request(app)
      .post('/api/auth')
      .send({ ...BASE_BODY, voucher: 'WIFI-ABCD-1234' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Voucher code must be exactly 6 digits.');
  });

  test('returns 400 for punctuation-only code', async () => {
    const res = await request(app)
      .post('/api/auth')
      .send({ ...BASE_BODY, voucher: '--  --' });
    expect(res.status).toBe(400);
  });

  test('returns 400 for missing voucher', async () => {
    const res = await request(app)
      .post('/api/auth')
      .send(BASE_BODY);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Voucher is required.');
  });

  test('6-digit code passes the format gate (reaches voucher lookup, not the 400 format branch)', async () => {
    // No voucher seeded -> should NOT be the format 400; expect the
    // not-found/invalid path instead (401 or 5xx from Omada-less env).
    const res = await request(app)
      .post('/api/auth')
      .send({ ...BASE_BODY, voucher: '654321' });
    expect(res.status).not.toBe(400);
    expect(res.body.error).not.toBe('Voucher code must be exactly 6 digits.');
  });

  test('6-digit code with surrounding junk is normalized before lookup', async () => {
    // Seed a real 6-digit voucher, then send it padded with non-digits.
    // It must be found (not an "not recognized" error from a padded lookup).
    await getDb().run(
      'INSERT INTO vouchers (code, type, duration_minutes, price, state) VALUES (?, ?, ?, ?, ?)',
      ['654321', 'standard', 60, 0, 'active']
    );
    const res = await request(app)
      .post('/api/auth')
      .send({ ...BASE_BODY, voucher: ' 654-321 ' });
    // Omada is not configured in the test env, so the flow may fail later —
    // but the voucher itself must have been recognized.
    expect(res.body.error).not.toBe('Voucher code must be exactly 6 digits.');
    if (res.body && res.body.error) {
      expect(String(res.body.error)).not.toMatch(/not recognized/i);
    }
  });
});
