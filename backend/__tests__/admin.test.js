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

  test('imported vouchers are claim-compatible: assigned_ref_no NULL and price in centavos', async () => {
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [{ ID: '', Code: '909090', Type: 'standard', Duration: 60, Price: '50.00' }]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'claim-compatible.csv');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const row = await getDb().getOne(
      'SELECT price, state, assigned_ref_no FROM vouchers WHERE code = ?',
      ['909090']
    );
    expect(row.price).toBe(5000);           // P50.00 stored as exactly 5000 centavos
    expect(row.state).toBe('active');
    expect(row.assigned_ref_no).toBe(null); // free to be claimed by the new flow
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

describe('GET /api/admin/transactions — Recent Transactions', () => {

  // 17 events ordered 1..17 (chronological, second resolution); every 3rd is
  // claimed and has a matching voucher linked by assigned_ref_no.
  async function seedWebhookEvents() {
    for (let i = 1; i <= 17; i++) {
      const ref = 'REF' + String(i).padStart(3, '0');
      const claimed = i % 3 === 0;
      const ss = String(i).padStart(2, '0');
      await getDb().run(
        'INSERT INTO webhook_events (event_id, ref_no, amount, status, processed_at) VALUES (?, ?, ?, ?, ?)',
        ['evt_' + i, ref, 20 + i, claimed ? 'claimed' : 'unclaimed', '2026-10-01 00:00:' + ss]
      );
      if (claimed) {
        await getDb().run(
          'INSERT INTO vouchers (code, type, duration_minutes, price, state, assigned_ref_no) VALUES (?, ?, ?, ?, ?, ?)',
          [String(300000 + i), 'standard', 60, 2000, 'claimed', ref]
        );
      }
    }
  }

  test('returns 401 without valid credentials', async () => {
    const res = await request(app).get('/api/admin/transactions');
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('returns the exact response shape with defaults (page 1, limit 15), ordered by processed_at DESC', async () => {
    await seedWebhookEvents();
    const res = await request(app)
      .get('/api/admin/transactions')
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(200);
    expect(Object.keys(res.body).sort()).toEqual(['pagination', 'transactions']);
    expect(Object.keys(res.body.pagination).sort()).toEqual(['currentPage', 'totalPages']);
    expect(res.body.pagination).toEqual({ currentPage: 1, totalPages: 2 });
    expect(res.body.transactions).toHaveLength(15);
    expect(res.body.transactions[0].event_id).toBe('evt_17');
    expect(res.body.transactions[14].event_id).toBe('evt_3');
    expect(Object.keys(res.body.transactions[0]).sort()).toEqual(
      ['amount', 'code', 'event_id', 'processed_at', 'ref_no', 'status'].sort()
    );
  });

  test('paginates using a separate count query (page 2 holds the remainder)', async () => {
    await seedWebhookEvents();
    const res = await request(app)
      .get('/api/admin/transactions?page=2')
      .set('X-API-Key', VALID_KEY);

    expect(res.body.transactions).toHaveLength(2);
    expect(res.body.pagination).toEqual({ currentPage: 2, totalPages: 2 });
    expect(res.body.transactions[0].event_id).toBe('evt_2');
  });

  test('honours a custom limit', async () => {
    await seedWebhookEvents();
    const res = await request(app)
      .get('/api/admin/transactions?page=2&limit=5')
      .set('X-API-Key', VALID_KEY);

    expect(res.body.transactions).toHaveLength(5);
    expect(res.body.pagination.totalPages).toBe(4);
    expect(res.body.transactions[0].event_id).toBe('evt_12');
  });

  test('LEFT JOIN exposes the voucher code for claimed refs and null for unclaimed', async () => {
    await seedWebhookEvents();
    const res = await request(app)
      .get('/api/admin/transactions?limit=100')
      .set('X-API-Key', VALID_KEY);

    const byId = {};
    res.body.transactions.forEach(t => { byId[t.event_id] = t; });
    expect(byId['evt_15'].status).toBe('claimed');   // 15 % 3 === 0
    expect(byId['evt_15'].code).toBe('300015');
    expect(byId['evt_15'].amount).toBe(35);          // amount stays in Pesos
    expect(byId['evt_16'].status).toBe('unclaimed');
    expect(byId['evt_16'].code).toBeNull();
  });

  test('falls back to defaults on invalid page/limit and caps limit at 100', async () => {
    await seedWebhookEvents();
    const bad = await request(app)
      .get('/api/admin/transactions?page=0&limit=-3')
      .set('X-API-Key', VALID_KEY);
    expect(bad.body.pagination.currentPage).toBe(1);
    expect(bad.body.transactions).toHaveLength(15);

    const capped = await request(app)
      .get('/api/admin/transactions?limit=99999')
      .set('X-API-Key', VALID_KEY);
    expect(capped.body.transactions).toHaveLength(17);
  });

  test('returns an empty page with totalPages 1 when there are no transactions', async () => {
    const res = await request(app)
      .get('/api/admin/transactions')
      .set('X-API-Key', VALID_KEY);

    expect(res.body.transactions).toEqual([]);
    expect(res.body.pagination).toEqual({ currentPage: 1, totalPages: 1 });
  });
});

describe('DELETE /api/admin/transactions — Clear Transaction Logs', () => {

  async function seedWebhookEvents(count) {
    for (let i = 1; i <= count; i++) {
      await getDb().run(
        'INSERT INTO webhook_events (event_id, ref_no, amount, status, processed_at) VALUES (?, ?, ?, ?, ?)',
        ['evt_del_' + i, 'DELREF' + i, 20 + i, 'unclaimed', '2026-10-01 00:00:' + String(i).padStart(2, '0')]
      );
    }
  }

  test('returns 401 without valid credentials', async () => {
    const res = await request(app).delete('/api/admin/transactions');
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('deletes all webhook events and reports how many were removed', async () => {
    await seedWebhookEvents(3);
    const res = await request(app)
      .delete('/api/admin/transactions')
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deleted).toBe(3);

    const remaining = await getDb().getOne('SELECT COUNT(*) AS count FROM webhook_events');
    expect(parseInt(remaining.count, 10)).toBe(0);
  });

  test('is safe to call when the log is already empty', async () => {
    const res = await request(app)
      .delete('/api/admin/transactions')
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.deleted).toBe(0);
  });

  test('leaves the GET table empty and paginated at 1 page afterwards', async () => {
    await seedWebhookEvents(4);
    await request(app).delete('/api/admin/transactions').set('X-API-Key', VALID_KEY);

    const res = await request(app)
      .get('/api/admin/transactions')
      .set('X-API-Key', VALID_KEY);
    expect(res.body.transactions).toEqual([]);
    expect(res.body.pagination).toEqual({ currentPage: 1, totalPages: 1 });
  });
});

describe('GET /api/admin/stats — Dashboard statistics', () => {

  async function seedSession({ sessionId, state, voucherType }) {
    await getDb().run(
      `INSERT INTO sessions (session_id, client_mac, voucher_type, state, duration_minutes)
       VALUES (?, ?, ?, ?, ?)`,
      [sessionId, 'AA:BB:CC:DD:EE:' + sessionId.slice(-2), voucherType || 'standard', state, 60]
    );
  }

  test('counts the seeded vouchers and no sessions initially', async () => {
    const res = await request(app).get('/api/admin/stats').set('X-API-Key', VALID_KEY);
    expect(res.status).toBe(200);
    expect(res.body.stats.totalVouchers).toBe(3);
    expect(res.body.stats.totalSessions).toBe(0);
  });

  test('does not report a ghost total for a lone terminal (expired) session', async () => {
    await seedSession({ sessionId: 'sess-exp-01', state: 'expired' });
    const res = await request(app).get('/api/admin/stats').set('X-API-Key', VALID_KEY);
    expect(res.body.stats.totalSessions).toBe(0);
    expect(res.body.stats.activeSessions).toBe(0);
    expect(res.body.stats.pausedSessions).toBe(0);
    expect(res.body.stats.premiumSessions).toBe(0);
  });

  test('total matches Active + Paused + Premium for disjoint live sessions', async () => {
    await seedSession({ sessionId: 'sess-act-01', state: 'active', voucherType: 'standard' });
    await seedSession({ sessionId: 'sess-pau-01', state: 'paused', voucherType: 'standard' });
    await seedSession({ sessionId: 'sess-pre-01', state: 'expired', voucherType: 'premium' });

    const res = await request(app).get('/api/admin/stats').set('X-API-Key', VALID_KEY);
    const s = res.body.stats;
    expect(s.activeSessions).toBe(1);
    expect(s.pausedSessions).toBe(1);
    expect(s.premiumSessions).toBe(1);
    expect(s.totalSessions).toBe(3);
  });

  test('counts a premium session that is also active only once', async () => {
    await seedSession({ sessionId: 'sess-act-02', state: 'active', voucherType: 'premium' });
    const res = await request(app).get('/api/admin/stats').set('X-API-Key', VALID_KEY);
    const s = res.body.stats;
    expect(s.activeSessions).toBe(1);
    expect(s.premiumSessions).toBe(1);
    expect(s.totalSessions).toBe(1);
  });
});
