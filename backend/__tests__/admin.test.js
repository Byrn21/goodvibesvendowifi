/**
 * __tests__/admin.test.js
 * Integration tests for admin.js DELETE /api/admin/vouchers/:id route
 *
 * Tests cover:
 *   - 200 success: DELETE existing voucher with valid API key
 *   - 404 not found: DELETE non-existent voucher with valid API key
 *   - 401 missing token: DELETE without Authorization / X-API-Key header
 *   - 401 invalid token: DELETE with invalid API key
 *   - SQL injection safety: DELETE with crafted ID uses parameterized query
 *
 * Patterns follow backend/__tests__/session.test.js:
 *   - Temp SQLite database created before requiring db/client.js
 *   - Schema applied via schema.sql
 *   - Seed data inserted in beforeEach
 *   - supertest with Express app exported from src/server.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Environment setup MUST happen before requiring any backend modules
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-admin-test-'));
const TEST_DB_PATH = path.join(TEST_DB_DIR, 'test.db');

process.env.DATABASE_URL = 'sqlite:' + TEST_DB_PATH;
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';

// Require the Express app AFTER env is set
const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');


const VALID_KEY = 'test-admin-key';
const INVALID_KEY = 'invalid-key';

// --- Helpers ---

async function applySchema() {
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'db', 'schema.sql'),
    'utf8'
  );
  await getDb().exec(schema);
}

async function seedVoucher(code, type, durationMinutes, price, state) {
  return getDb().run(
    'INSERT INTO vouchers (code, type, duration_minutes, price, state) VALUES (?, ?, ?, ?, ?)',
    [code, type, durationMinutes, price, state]
  );
}

async function seedVouchers() {
  await seedVoucher('WIFI-TEST-001', 'standard', 60, 3500, 'active');
  await seedVoucher('WIFI-PREMIUM', 'premium', 120, 9000, 'active');
  await seedVoucher('WIFI-USED', 'standard', 60, 3500, 'used');
}

async function getVoucherId(code) {
  const row = await getDb().getOne('SELECT id FROM vouchers WHERE code = ?', [code]);
  return row ? row.id : null;
}

// --- Lifecycle ---

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
  await getDb().exec('DELETE FROM sessions; DELETE FROM vouchers; DELETE FROM webhook_events;');
  await seedVouchers();
});

// --- Tests ---

describe('DELETE /api/admin/vouchers/:id — Voucher Deletion', () => {

  test('returns 200 + success when deleting an existing voucher with valid API key', async () => {
    const voucherId = await getVoucherId('WIFI-TEST-001');
    expect(voucherId).toBeTruthy();

    const res = await request(app)
      .delete('/api/admin/vouchers/' + voucherId)
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    // Verify voucher was actually deleted from DB
    const deleted = await getDb().getOne('SELECT id FROM vouchers WHERE id = ?', [voucherId]);
    expect(deleted).toBeUndefined();
  });

  test('returns 404 when deleting a non-existent voucher', async () => {
    const res = await request(app)
      .delete('/api/admin/vouchers/99999')
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toBe('Voucher not found');
  });

  test('returns 401 when no API key or Authorization header is provided', async () => {
    const res = await request(app)
      .delete('/api/admin/vouchers/1');

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toMatch(/Unauthorized/i);
  });

  test('returns 401 when an invalid API key is provided', async () => {
    const res = await request(app)
      .delete('/api/admin/vouchers/1')
      .set('X-API-Key', INVALID_KEY);

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toMatch(/Unauthorized/i);
  });

  test('returns 401 when an invalid Bearer token', async () => {
    const res = await request(app)
      .delete('/api/admin/vouchers/1')
      .set('Authorization', 'Bearer fake-token');

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('parametrized query prevents SQL injection via :id route parameter', async () => {
    const injectionId = "1 OR 1=1; DROP TABLE vouchers; --";

    const res = await request(app)
      .delete('/api/admin/vouchers/' + encodeURIComponent(injectionId))
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(404);

    // Verify the vouchers table still exists (injection was prevented)
    const voucherCount = await getDb().getOne('SELECT COUNT(*) as count FROM vouchers');
    expect(voucherCount.count).toBe(3);
  });

  test('parametrized query prevents UNION-based injection', async () => {
    const injectionId = "1; SELECT * FROM admin_users; --";

    const res = await request(app)
      .delete('/api/admin/vouchers/' + encodeURIComponent(injectionId))
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);

    const voucherCount = await getDb().getOne('SELECT COUNT(*) as count FROM vouchers');
    expect(voucherCount.count).toBe(3);
  });

  test('Bearer token with valid API key authenticates successfully', async () => {
    const voucherId = await getVoucherId('WIFI-PREMIUM');
    expect(voucherId).toBeTruthy();

    const res = await request(app)
      .delete('/api/admin/vouchers/' + voucherId)
      .set('Authorization', 'Bearer ' + VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const deleted = await getDb().getOne('SELECT id FROM vouchers WHERE id = ?', [voucherId]);
    expect(deleted).toBeUndefined();
  });

  test('does not delete vouchers when ID contains SQL comment characters', async () => {
    const voucherId = await getVoucherId('WIFI-TEST-001');
    expect(voucherId).toBeTruthy();

    const res = await request(app)
      .delete('/api/admin/vouchers/' + voucherId + ' --')
      .set('X-API-Key', VALID_KEY);

    // The trailing comment characters make the ID not match
    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);

        // Original voucher should still exist
    const voucher = await getDb().getOne('SELECT id FROM vouchers WHERE id = ?', [voucherId]);
    expect(voucher).toBeTruthy();
  });
});

describe('GET /api/admin/me — Admin Info', () => {
  test('returns 200 + username with valid API key', async () => {
    const res = await request(app)
      .get('/api/admin/me')
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.username).toBe('admin');
  });

  test('returns 200 + username with valid Bearer token', async () => {
    const res = await request(app)
      .get('/api/admin/me')
      .set('Authorization', 'Bearer ' + VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.username).toBe('admin');
  });

  test('returns 401 when no API key or Authorization header is provided', async () => {
    const res = await request(app)
      .get('/api/admin/me');

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });
});

describe('POST /api/admin/vouchers/import — Voucher Import', () => {
  const XLSX = require('xlsx');

  function buildCsv(headers, rows) {
    // RFC 4180: quote any field that contains a comma so values like
    // "₱1,250.50" survive as a single cell (real spreadsheets do this).
    const esc = v => {
      const s = String(v == null ? '' : v);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const lines = [headers.map(esc).join(',')];
    rows.forEach(row => {
      lines.push(headers.map(h => esc(row[h])).join(','));
    });
    return Buffer.from(lines.join('\n'), 'utf8');
  }

  function buildXlsx(headers, rows) {
    const wsData = [headers].concat(
      rows.map(r => headers.map(h => r[h]))
    );
    const ws = XLSX.utils.aoa_to_sheet(wsData);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Vouchers');
    const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'buffer' });
    return wbout;
  }

  test('accepts CSV with correct ID,Code,Type,Duration,Price columns and imports vouchers', async () => {
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [
        { ID: 1, Code: '111111', Type: 'standard', Duration: 60, Price: '50.00' },
        { ID: 2, Code: '222222', Type: 'premium',  Duration: 120, Price: '100.00' },
      ]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'test.csv');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.summary.inserted).toBe(2);
  });

  test('accepts XLSX with correct columns including ID', async () => {
    const xlsxBuf = buildXlsx(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [
        { ID: 1, Code: '333333', Type: 'standard', Duration: 60, Price: 3500 },
        { ID: 2, Code: '444444', Type: 'premium',  Duration: 120, Price: 9000 },
      ]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', xlsxBuf, 'test.xlsx');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.summary.inserted).toBe(2);
  });

  test('returns 400 when ID column is missing', async () => {
    const csv = buildCsv(
      ['Code', 'Type', 'Duration', 'Price'],
      [{ Code: '555555', Type: 'standard', Duration: 60, Price: '50.00' }]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'bad.csv');

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toContain('Missing required columns');
  });

  test('returns 400 when ID contains non-numeric values', async () => {
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [{ ID: 'abc', Code: '666666', Type: 'standard', Duration: 60, Price: '50.00' }]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'bad_ids.csv');

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toContain('column "ID" has invalid value');
  });

  test('accepts CSV with currency-formatted prices and blank IDs (reproduces the NaN price bug)', async () => {
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [{ ID: '', Code: '888888', Type: 'standard', Duration: 60, Price: '₱1,500.00' }]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'currency.csv');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.summary.inserted).toBe(1);
    expect(res.body.summary.autoId).toBe(1);
  });

  test('returns 400 listing row, column and value when Price is not a number', async () => {
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [{ ID: 3, Code: '999999', Type: 'standard', Duration: 60, Price: 'abc' }]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'bad_price.csv');

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toContain('Row 2');
    expect(res.body.error).toContain('column "Price"');
    expect(res.body.error).toContain('abc');
  });

  test('returns 401 without API key', async () => {
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [{ ID: 1, Code: '777777', Type: 'standard', Duration: 60, Price: '50.00' }]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .attach('file', csv, 'nontest.csv');

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('stores peso formats as exact centavos: ₱50.00->5000, 100->10000, ₱1,250.50->125050, PHP 75->7500', async () => {
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [
        { ID: '', Code: '101010', Type: 'standard', Duration: 60, Price: '₱50.00' },
        { ID: '', Code: '202020', Type: 'standard', Duration: 60, Price: '100' },
        { ID: '', Code: '303030', Type: 'premium',  Duration: 60, Price: '₱1,250.50' },
        { ID: '', Code: '404040', Type: 'standard', Duration: 60, Price: 'PHP 75' },
      ]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'peso.csv');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const list = await request(app)
      .get('/api/admin/vouchers')
      .set('X-API-Key', VALID_KEY);
    const byCode = {};
    list.body.vouchers.forEach(v => { byCode[v.code] = v.price; });
    expect(byCode['101010']).toBe(5000);   // ₱50.00 -> 5000 centavos
    expect(byCode['202020']).toBe(10000);  // 100 pesos -> 10000 centavos
    expect(byCode['303030']).toBe(125050); // ₱1,250.50 -> 125050 centavos
    expect(byCode['404040']).toBe(7500);   // PHP 75 -> 7500 centavos
  });

  test('rejects negative prices with a row-level error', async () => {
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [{ ID: 1, Code: '515151', Type: 'standard', Duration: 60, Price: '-5' }]
    );
    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'neg.csv');
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('negative');
  });

  test('rejects empty prices with a row-level error', async () => {
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [{ ID: 1, Code: '525252', Type: 'standard', Duration: 60, Price: '' }]
    );
    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'emptyprice.csv');
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('column "Price"');
  });

  test('delete-all resets the ID sequence so the next import starts at 1', async () => {
    const del = await request(app)
      .post('/api/admin/vouchers/delete-all')
      .set('X-API-Key', VALID_KEY);
    expect(del.status).toBe(200);
    expect(del.body.success).toBe(true);
    expect(del.body.idsReset).toBe(true);

    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [
        { ID: '', Code: '606060', Type: 'standard', Duration: 60, Price: '10' },
        { ID: '', Code: '707070', Type: 'standard', Duration: 60, Price: '20' },
      ]
    );
    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'afterreset.csv');
    expect(res.status).toBe(200);

    const list = await request(app)
      .get('/api/admin/vouchers')
      .set('X-API-Key', VALID_KEY);
    const ids = list.body.vouchers.map(v => v.id).sort((a, b) => a - b);
    expect(ids).toEqual([1, 2]);
  });

  test('partial deletes keep remaining IDs and never reset while the table is non-empty', async () => {
    // beforeEach re-seeds 3 vouchers; capture their actual IDs first.
    const before = await request(app)
      .get('/api/admin/vouchers')
      .set('X-API-Key', VALID_KEY);
    const idsBefore = before.body.vouchers.map(v => v.id).sort((a, b) => a - b);
    expect(idsBefore.length).toBe(3);

    // Delete one of them — the remaining two must keep their original IDs
    // and the sequence must NOT reset while the table is still non-empty.
    const del = await request(app)
      .delete('/api/admin/vouchers/' + idsBefore[1])
      .set('X-API-Key', VALID_KEY);
    expect(del.status).toBe(200);
    expect(del.body.success).toBe(true);
    expect(del.body.idsReset).toBe(false);

    const after = await request(app)
      .get('/api/admin/vouchers')
      .set('X-API-Key', VALID_KEY);
    const idsAfter = after.body.vouchers.map(v => v.id).sort((a, b) => a - b);
    expect(idsAfter).toEqual([idsBefore[0], idsBefore[2]]);

    // A NEW voucher gets the next sequential ID, not a reused one.
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [{ ID: '', Code: '808080', Type: 'standard', Duration: 60, Price: '30' }]
    );
    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'third.csv');
    expect(res.status).toBe(200);

    const final = await request(app)
      .get('/api/admin/vouchers')
      .set('X-API-Key', VALID_KEY);
    const idsFinal = final.body.vouchers.map(v => v.id).sort((a, b) => a - b);
    expect(idsFinal).toContain(Math.max(...idsBefore) + 1);
    expect(idsFinal.length).toBe(3);
  });
});
