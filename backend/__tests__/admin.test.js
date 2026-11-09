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
  await getDb().exec(
    'DELETE FROM sessions; DELETE FROM vouchers; DELETE FROM webhook_events; DELETE FROM app_settings;'
  );
  await seedVouchers();
});

// --- Tests ---

describe('POST /api/admin/login — bounded token store', () => {
  test('keeps only the most recent tokens and evicts the oldest', async () => {
    let firstToken = null;
    let lastToken = null;

    // 105 logins against a 100-token cap: the first 5 must be evicted.
    for (let i = 0; i < 105; i++) {
      const res = await request(app)
        .post('/api/admin/login')
        .send({ username: 'admin', password: VALID_KEY });
      expect(res.status).toBe(200);
      if (i === 0) firstToken = res.body.token;
      lastToken = res.body.token;
    }

    // The newest token still authenticates.
    const ok = await request(app)
      .get('/api/admin/me')
      .set('Authorization', 'Bearer ' + lastToken);
    expect(ok.status).toBe(200);

    // The oldest token has been evicted by the cap.
    const evicted = await request(app)
      .get('/api/admin/me')
      .set('Authorization', 'Bearer ' + firstToken);
    expect(evicted.status).toBe(401);
  });
});

// ── C-01: empty-string login bypass ───────────────────────────────────────
// Regression cover for the admin authentication bypass: an unset
// ADMIN_PASSWORD used to resolve to '' and match an empty body password,
// minting a full admin bearer token in production.
describe('POST /api/admin/login — credential validation (C-01)', () => {
  const { safeEqual } = require('../src/utils/safe-compare');
  const config = require('../src/config');

  test('resolves a non-empty admin password so a login is always compared against a real secret', () => {
    expect(config.ADMIN_PASSWORD).toBeTruthy();
    expect(config.ADMIN_PASSWORD).not.toBe('');
  });

  test('returns 401 for an empty-string password and issues no token', async () => {
    const res = await request(app)
      .post('/api/admin/login')
      .send({ username: 'admin', password: '' });

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(res.body.token).toBeUndefined();
  });

  test('returns 401 when the password field is missing entirely', async () => {
    const res = await request(app)
      .post('/api/admin/login')
      .send({ username: 'admin' });

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(res.body.token).toBeUndefined();
  });

  test('returns 401 when the username field is missing or empty', async () => {
    const missing = await request(app)
      .post('/api/admin/login')
      .send({ password: VALID_KEY });
    expect(missing.status).toBe(401);

    const empty = await request(app)
      .post('/api/admin/login')
      .send({ username: '', password: VALID_KEY });
    expect(empty.status).toBe(401);
  });

  test('returns 401 for a whitespace-only password', async () => {
    const res = await request(app)
      .post('/api/admin/login')
      .send({ username: 'admin', password: '   ' });

    expect(res.status).toBe(401);
    expect(res.body.token).toBeUndefined();
  });

  test('returns 401 for non-string credentials instead of coercing them', async () => {
    const numeric = await request(app)
      .post('/api/admin/login')
      .send({ username: 'admin', password: 12345 });
    expect(numeric.status).toBe(401);

    const object = await request(app)
      .post('/api/admin/login')
      .send({ username: 'admin', password: { toString: () => VALID_KEY } });
    expect(object.status).toBe(401);
  });

  test('still issues a token for the configured credentials', async () => {
    const res = await request(app)
      .post('/api/admin/login')
      .send({ username: 'admin', password: VALID_KEY });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(typeof res.body.token).toBe('string');
  });

  test('safeEqual never treats two blank credentials as a match', () => {
    expect(safeEqual('', '')).toBe(false);
    expect(safeEqual('   ', '   ')).toBe(false);
    expect(safeEqual(null, null)).toBe(false);
    expect(safeEqual(undefined, '')).toBe(false);
    expect(safeEqual('', 'test-admin-key')).toBe(false);
  });

  test('safeEqual matches identical values and rejects everything else', () => {
    expect(safeEqual('test-admin-key', 'test-admin-key')).toBe(true);
    expect(safeEqual('test-admin-key', 'test-admin-kez')).toBe(false);
    expect(safeEqual('test-admin-key', 'test-admin-key ')).toBe(false);
    expect(safeEqual('short', 'a-much-longer-value')).toBe(false);
  });
});

describe('config — production startup assertion (C-01)', () => {
  const { spawnSync } = require('child_process');
  const CONFIG_PATH = path.join(__dirname, '..', 'src', 'config');

  /** Run a snippet in a child process with exactly the given admin env. */
  function runWith(env, script) {
    return spawnSync(process.execPath, ['-e', script], {
      env: Object.assign({}, process.env, env),
      encoding: 'utf8',
    });
  }

  test('refuses to load in production when no admin credential is configured', () => {
    const result = runWith(
      { NODE_ENV: 'production', ADMIN_API_KEY: '', ADMIN_PASSWORD: '' },
      'require(' + JSON.stringify(CONFIG_PATH) + '); process.exit(0);'
    );

    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/Refusing to start in production/);
    expect(result.stderr).toMatch(/ADMIN_API_KEY/);
  });

  test('loads in production when ADMIN_API_KEY is set and falls back ADMIN_PASSWORD to it', () => {
    const result = runWith(
      { NODE_ENV: 'production', ADMIN_API_KEY: 'prod-admin-key', ADMIN_PASSWORD: '' },
      'const c = require(' + JSON.stringify(CONFIG_PATH) + ');' +
      'c.assertAdminCredentials();' +
      'process.exit(c.ADMIN_PASSWORD === "prod-admin-key" && c.ADMIN_API_KEY === "prod-admin-key" ? 0 : 3);'
    );

    expect(result.status).toBe(0);
  });

  test('treats a whitespace-only secret as unset in production', () => {
    const result = runWith(
      { NODE_ENV: 'production', ADMIN_API_KEY: '   ', ADMIN_PASSWORD: '   ' },
      'require(' + JSON.stringify(CONFIG_PATH) + '); process.exit(0);'
    );

    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/Refusing to start in production/);
  });

  test('does not throw outside production (development keeps the dev default)', () => {
    const result = runWith(
      { NODE_ENV: 'development', ADMIN_API_KEY: '', ADMIN_PASSWORD: '' },
      'const c = require(' + JSON.stringify(CONFIG_PATH) + ');' +
      'c.assertAdminCredentials();' +
      'process.exit(c.ADMIN_PASSWORD ? 0 : 3);'
    );

    expect(result.status).toBe(0);
  });
});

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

  test('preserves a leading zero in a CSV Code cell (text "012345" stays "012345")', async () => {
    const csv = buildCsv(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [{ ID: '', Code: '012345', Type: 'standard', Duration: 60, Price: '50.00' }]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', csv, 'leading-zero.csv');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const row = await getDb().getOne('SELECT code FROM vouchers WHERE code = ?', ['012345']);
    expect(row).toBeTruthy();
    expect(row.code).toBe('012345');
  });

  test('rebuilds an XLSX Code cell whose leading zero was dropped by numeric storage (12345 -> "012345")', async () => {
    // A real spreadsheet stores "012345" as the NUMBER 12345, so by the time
    // the file reaches us the zero is already gone; the padStart failsafe must
    // restore exactly 6 digits instead of rejecting the import as invalid.
    const xlsxBuf = buildXlsx(
      ['ID', 'Code', 'Type', 'Duration', 'Price'],
      [{ ID: '', Code: 12345, Type: 'standard', Duration: 60, Price: '50.00' }]
    );

    const res = await request(app)
      .post('/api/admin/vouchers/import')
      .set('X-API-Key', VALID_KEY)
      .attach('file', xlsxBuf, 'numeric-code.xlsx');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.summary.inserted).toBe(1);

    const row = await getDb().getOne('SELECT code FROM vouchers WHERE code = ?', ['012345']);
    expect(row).toBeTruthy();
    expect(row.code).toBe('012345');
  });
});

describe('DELETE /api/admin/transactions — Clear Transaction Logs', () => {

  async function seedWebhookEvents(count, status = 'claimed') {
    for (let i = 1; i <= count; i++) {
      await getDb().run(
        'INSERT INTO webhook_events (event_id, ref_no, amount, status, processed_at) VALUES (?, ?, ?, ?, ?)',
        ['evt_del_' + i, 'DELREF' + i, 20 + i, status, '2026-10-01 00:00:' + String(i).padStart(2, '0')]
      );
    }
  }

  async function seedSession({ sessionId, state, paymentAmount = 0, createdAt = null }) {
    // SQLite/PostgreSQL-compatible UTC text so the baseline comparison is stable.
    const created = createdAt || new Date().toISOString().slice(0, 19).replace('T', ' ');
    await getDb().run(
      `INSERT INTO sessions (session_id, client_mac, voucher_type, state, duration_minutes, payment_amount, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [sessionId, 'AA:BB:CC:DD:EE:' + sessionId.slice(-2), 'standard', state, 60, paymentAmount, created]
    );
  }

  test('returns 401 without valid credentials', async () => {
    const res = await request(app).delete('/api/admin/transactions');
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('deletes terminal webhook events and reports how many were removed', async () => {
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

  test('preserves unclaimed payments that a guest may still claim', async () => {
    await seedWebhookEvents(2, 'unclaimed');
    const res = await request(app)
      .delete('/api/admin/transactions')
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.deleted).toBe(0);

    const remaining = await getDb().getOne('SELECT COUNT(*) AS count FROM webhook_events');
    expect(parseInt(remaining.count, 10)).toBe(2);
  });

  test('deletes only terminal sessions, preserves live guests, and resets the cards', async () => {
    await seedWebhookEvents(2);
    // Backdated: these rows existed before the dashboard reset baseline.
    const beforeReset = '2026-10-01 00:00:00';
    await seedSession({ sessionId: 'sess-exp-01', state: 'expired', paymentAmount: 2500, createdAt: beforeReset });
    await seedSession({ sessionId: 'sess-fail-01', state: 'payment_failed', paymentAmount: 1000, createdAt: beforeReset });
    await seedSession({ sessionId: 'sess-act-01', state: 'active', paymentAmount: 3000, createdAt: beforeReset });
    await seedSession({ sessionId: 'sess-pau-01', state: 'paused', paymentAmount: 5000, createdAt: beforeReset });
    // A printed (cash) voucher redeemed before the baseline: revenue is counted
    // from the vouchers that were actually sold, not from session rows.
    await getDb().run(
      `INSERT INTO vouchers (code, type, duration_minutes, price, state, used_by_mac, used_at, created_at)
       VALUES ('CASH-REV-1', 'standard', 60, 11500, 'used', 'AA:BB:CC:DD:EE:FF', ?, ?)`,
      [beforeReset, beforeReset]
    );

    const beforeStats = await request(app)
      .get('/api/admin/stats')
      .set('X-API-Key', VALID_KEY);
    expect(beforeStats.body.stats.totalSessions).toBe(2);
    expect(beforeStats.body.stats.activeSessions).toBe(1);
    expect(beforeStats.body.stats.pausedSessions).toBe(1);
    expect(beforeStats.body.stats.cashRevenue).toBe(11500);
    expect(beforeStats.body.stats.digitalRevenue).toBe(0);
    expect(beforeStats.body.stats.totalRevenue).toBe(11500);

    const res = await request(app)
      .delete('/api/admin/transactions')
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deletedSessions).toBe(2);
    expect(res.body.preservedSessions).toBe(2);
    expect(res.body.statsResetAt).toBeTruthy();

    const remaining = await getDb().query('SELECT state FROM sessions ORDER BY state');
    expect(remaining.map((row) => row.state)).toEqual(['active', 'paused']);

    const afterStats = await request(app)
      .get('/api/admin/stats')
      .set('X-API-Key', VALID_KEY);
    expect(afterStats.body.stats.totalSessions).toBe(0);
    expect(afterStats.body.stats.pausedSessions).toBe(0);
    expect(afterStats.body.stats.totalRevenue).toBe(0);
    // Active Sessions is a live count, unaffected by the baseline.
    expect(afterStats.body.stats.activeSessions).toBe(1);
  });

  test('counts sessions created after the reset baseline', async () => {
    const reset = await request(app)
      .delete('/api/admin/transactions')
      .set('X-API-Key', VALID_KEY);
    expect(reset.status).toBe(200);

    // Created after the reset, so they belong to the new reporting window.
    await seedSession({ sessionId: 'sess-new-act', state: 'active', paymentAmount: 3000 });
    await seedSession({ sessionId: 'sess-new-pau', state: 'paused', paymentAmount: 2000 });
    // A digital voucher generated after the baseline.
    await getDb().run(
      `INSERT INTO vouchers (code, type, duration_minutes, price, state, assigned_ref_no)
       VALUES ('123456', 'standard', 60, 5000, 'claimed', 'REF-AFTER-RESET')`
    );

    const res = await request(app).get('/api/admin/stats').set('X-API-Key', VALID_KEY);
    const s = res.body.stats;
    expect(s.totalSessions).toBe(2);
    expect(s.activeSessions).toBe(1);
    expect(s.pausedSessions).toBe(1);
    expect(s.cashRevenue).toBe(0);
    expect(s.digitalRevenue).toBe(5000);
    expect(s.totalRevenue).toBe(5000);
  });

  test('is safe to call when the log is already empty', async () => {
    const res = await request(app)
      .delete('/api/admin/transactions')
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.deleted).toBe(0);
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

  test('splits revenue into redeemed cash vouchers and generated digital vouchers', async () => {
    // Printed stock: only redeemed rows count; unsold sheets are not revenue.
    await getDb().run(
      `INSERT INTO vouchers (code, type, duration_minutes, price, state, used_by_mac, used_at)
       VALUES ('CASH-USED', 'standard', 60, 3500, 'used', 'AA:BB:CC:DD:EE:FF', CURRENT_TIMESTAMP)`
    );
    await getDb().run(
      `INSERT INTO vouchers (code, type, duration_minutes, price, state)
       VALUES ('CASH-UNSOLD', 'standard', 60, 9999, 'active')`
    );
    // Digital inventory only exists because a payment was received.
    await getDb().run(
      `INSERT INTO vouchers (code, type, duration_minutes, price, state, assigned_ref_no)
       VALUES ('654321', 'premium', 300, 2500, 'claimed', 'REF-DIGITAL1')`
    );

    const res = await request(app).get('/api/admin/stats').set('X-API-Key', VALID_KEY);
    const s = res.body.stats;
    expect(s.cashRevenue).toBe(3500);
    expect(s.digitalRevenue).toBe(2500);
    expect(s.totalRevenue).toBe(6000);
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

describe('GET /api/admin/transactions/history + /export — Settled payments', () => {

  // A settled payment as the two flows write it: a webhook_events row plus the
  // session it paid for (linked by payment_event_id), and — for the claim
  // flow — a voucher linked by assigned_ref_no.
  async function seedPayment({
    n,
    status = 'claimed',
    amountPesos = 50,
    mobile = '09171234567',
    voucherCode = null,
    paymentCentavos = 5000,
    processedAt = null,
  }) {
    const ref = 'HISTREF' + String(n).padStart(3, '0');
    const eventId = 'evt_hist_' + n;

    await getDb().run(
      'INSERT INTO webhook_events (event_id, ref_no, amount, mobile_number, status, processed_at) VALUES (?, ?, ?, ?, ?, ?)',
      [eventId, ref, amountPesos, mobile, status, processedAt || ('2026-10-02 00:00:' + String(n).padStart(2, '0'))]
    );

    if (voucherCode) {
      await getDb().run(
        'INSERT INTO vouchers (code, type, duration_minutes, price, state, assigned_ref_no) VALUES (?, ?, ?, ?, ?, ?)',
        [voucherCode, 'standard', 60, amountPesos * 100, 'claimed', ref]
      );
    }

    await getDb().run(
      `INSERT INTO sessions (session_id, client_mac, voucher_type, state, duration_minutes,
                             payment_amount, payment_event_id, voucher_used, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ['sess_hist_' + n, 'AA:BB:CC:DD:EE:0' + (n % 10), 'standard', 'active', 60,
        paymentCentavos, eventId, voucherCode, '2026-10-02 00:00:00']
    );

    return { ref, eventId };
  }

  test('both endpoints require valid credentials', async () => {
    const history = await request(app).get('/api/admin/transactions/history');
    expect(history.status).toBe(401);
    const exportRes = await request(app).get('/api/admin/transactions/export');
    expect(exportRes.status).toBe(401);
  });

  test('returns only settled payments, newest first, with guest, voucher and centavo amount', async () => {
    await seedPayment({ n: 1, status: 'claimed', amountPesos: 50, voucherCode: '300001' });
    await seedPayment({ n: 2, status: 'authorized', amountPesos: 20, voucherCode: null, paymentCentavos: 2000 });
    await seedPayment({ n: 3, status: 'unclaimed', amountPesos: 99, voucherCode: null, paymentCentavos: 9900 });
    await seedPayment({ n: 4, status: 'auth_failed', amountPesos: 30, voucherCode: null, paymentCentavos: 3000 });
    // No session row: the amount must fall back to webhook_events.amount * 100.
    await getDb().run(
      'INSERT INTO webhook_events (event_id, ref_no, amount, mobile_number, status, processed_at) VALUES (?, ?, ?, ?, ?, ?)',
      ['evt_hist_5', 'HISTREF005', 35, '09170000005', 'claimed', '2026-10-02 00:00:05']
    );

    const res = await request(app)
      .get('/api/admin/transactions/history')
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.transactions).toHaveLength(3);
    expect(res.body.pagination).toEqual({ currentPage: 1, totalPages: 1 });
    expect(res.body.transactions[0].event_id).toBe('evt_hist_5');
    expect(res.body.transactions.map((t) => t.event_id)).not.toContain('evt_hist_3');
    expect(res.body.transactions.map((t) => t.event_id)).not.toContain('evt_hist_4');

    const byId = {};
    res.body.transactions.forEach((t) => { byId[t.event_id] = t; });

    expect(Object.keys(byId.evt_hist_1).sort()).toEqual(
      ['amount_centavos', 'assigned_ref_no', 'event_id', 'mobile_number', 'processed_at', 'ref_no', 'status', 'voucher_code'].sort()
    );
    expect(byId.evt_hist_1.ref_no).toBe('HISTREF001');
    expect(byId.evt_hist_1.assigned_ref_no).toBe('HISTREF001');
    expect(byId.evt_hist_1.mobile_number).toBe('09171234567');
    expect(byId.evt_hist_1.voucher_code).toBe('300001');
    expect(Number(byId.evt_hist_1.amount_centavos)).toBe(5000);
    expect(Number(byId.evt_hist_5.amount_centavos)).toBe(3500);
    expect(byId.evt_hist_2.voucher_code).toBeNull();
    expect(byId.evt_hist_2.assigned_ref_no).toBeNull();
  });

  test('paginates the history table', async () => {
    for (let i = 1; i <= 5; i++) {
      await seedPayment({ n: i, amountPesos: 60, paymentCentavos: 6000 });
    }

    const res = await request(app)
      .get('/api/admin/transactions/history?page=2&limit=2')
      .set('X-API-Key', VALID_KEY);

    expect(res.body.pagination).toEqual({ currentPage: 2, totalPages: 3 });
    expect(res.body.transactions).toHaveLength(2);
  });

  test('exports settled payments as a CSV attachment with amounts converted to pesos', async () => {
    await seedPayment({ n: 1, status: 'claimed', amountPesos: 50, voucherCode: '300001', paymentCentavos: 5000 });
    await seedPayment({ n: 2, status: 'unclaimed', amountPesos: 99, paymentCentavos: 9900 });

    const res = await request(app)
      .get('/api/admin/transactions/export')
      .set('X-API-Key', VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/csv/);
    expect(res.headers['content-disposition']).toBe('attachment; filename="transactions.csv"');

    const lines = res.text.replace(/^\uFEFF/, '').trim().split('\r\n');
    expect(lines[0]).toBe('Date,Ref No,Assigned Ref,Mobile,Voucher,Amount');
    expect(lines).toHaveLength(2);

    const cols = lines[1].split(',');
    expect(cols[1]).toBe('HISTREF001');
    expect(cols[2]).toBe('HISTREF001');
    expect(cols[3]).toBe('09171234567');
    expect(cols[4]).toBe('300001');
    expect(cols[5]).toBe('50.00');
  });

  test('filters the history to unclaimed / failed payments for support', async () => {
    await seedPayment({ n: 1, status: 'claimed', amountPesos: 50 });
    await seedPayment({ n: 2, status: 'authorized', amountPesos: 20 });
    await seedPayment({ n: 3, status: 'unclaimed', amountPesos: 99 });
    await seedPayment({ n: 4, status: 'auth_failed', amountPesos: 30 });

    const completed = await request(app)
      .get('/api/admin/transactions/history?filter=completed')
      .set('X-API-Key', VALID_KEY);
    expect(completed.body.filter).toBe('completed');
    expect(completed.body.transactions).toHaveLength(2);

    const unclaimed = await request(app)
      .get('/api/admin/transactions/history?filter=unclaimed')
      .set('X-API-Key', VALID_KEY);
    expect(unclaimed.body.filter).toBe('unclaimed');
    expect(unclaimed.body.pagination).toEqual({ currentPage: 1, totalPages: 1 });
    expect(unclaimed.body.transactions.map((t) => t.status).sort()).toEqual(['auth_failed', 'unclaimed']);

    // Missing or unknown values fall back to the default view.
    const fallback = await request(app)
      .get('/api/admin/transactions/history?filter=bogus')
      .set('X-API-Key', VALID_KEY);
    expect(fallback.body.filter).toBe('completed');
    expect(fallback.body.transactions).toHaveLength(2);
  });

  test('exports only the selected filter', async () => {
    await seedPayment({ n: 1, status: 'claimed', amountPesos: 50 });
    await seedPayment({ n: 2, status: 'unclaimed', amountPesos: 99 });

    const res = await request(app)
      .get('/api/admin/transactions/export?filter=unclaimed')
      .set('X-API-Key', VALID_KEY);

    const lines = res.text.replace(/^\uFEFF/, '').trim().split('\r\n');
    expect(lines[0]).toBe('Date,Ref No,Assigned Ref,Mobile,Voucher,Amount');
    expect(lines).toHaveLength(2);
    expect(lines[1].split(',')[1]).toBe('HISTREF002');
  });
});

describe('POST /api/admin/vouchers/bulk — Voucher Print Studio', () => {
  test('previews unique codes, then saves the same batch on confirm', async () => {
    const preview = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({ type: 'standard', quantity: 25, preview: true });

    expect(preview.status).toBe(200);
    expect(preview.body.success).toBe(true);
    expect(preview.body.codes).toHaveLength(25);
    expect(new Set(preview.body.codes).size).toBe(25);
    preview.body.codes.forEach((code) => expect(code).toMatch(/^\d{6}$/));

    const placeholders = preview.body.codes.map(() => '?').join(', ');
    const before = await getDb().query(
      `SELECT code FROM vouchers WHERE code IN (${placeholders})`,
      preview.body.codes
    );
    expect(before).toHaveLength(0);

    const saved = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({ type: 'standard', quantity: 25, preview: false, codes: preview.body.codes });
    expect(saved.status).toBe(201);
    expect(saved.body).toEqual({ success: true });

    const rows = await getDb().query(
      `SELECT code, type, duration_minutes, state FROM vouchers WHERE code IN (${placeholders})`,
      preview.body.codes
    );
    expect(rows).toHaveLength(25);
    expect(rows.every((row) =>
      row.type === 'standard' &&
      row.duration_minutes === 60 &&
      row.state === 'active'
    )).toBe(true);
  });

  test('stores the premium tier, accepts 500, and rejects quantities outside 1–500', async () => {
    const preview = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({ type: 'premium', quantity: 2, preview: true });

    expect(preview.status).toBe(200);
    expect(preview.body.codes).toHaveLength(2);

    const ok = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({ type: 'premium', quantity: 2, preview: false, codes: preview.body.codes });
    expect(ok.status).toBe(201);

    const rows = await getDb().query(
      'SELECT type FROM vouchers WHERE code IN (?, ?)',
      preview.body.codes
    );
    expect(rows).toHaveLength(2);
    expect(rows.every((row) => row.type === 'premium')).toBe(true);

    const maxPreview = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({ type: 'standard', quantity: 500, preview: true });
    expect(maxPreview.status).toBe(200);
    expect(maxPreview.body.codes).toHaveLength(500);

    const maxSave = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({ type: 'standard', quantity: 500, preview: false, codes: maxPreview.body.codes });
    expect(maxSave.status).toBe(201);

    for (const quantity of [0, 501, 1.5]) {
      const bad = await request(app)
        .post('/api/admin/vouchers/bulk')
        .set('X-API-Key', VALID_KEY)
        .send({ type: 'standard', quantity, preview: true });
      expect(bad.status).toBe(400);
      expect(bad.body.success).toBe(false);
    }
  });

  test('stores a custom duration and a peso price in centavos', async () => {
    const preview = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({ type: 'standard', quantity: 3, duration: 1440, price: 75.5, preview: true });

    expect(preview.status).toBe(200);
    expect(preview.body.codes).toHaveLength(3);

    const res = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({
        type: 'standard',
        quantity: 3,
        duration: 1440,
        price: 75.5,
        preview: false,
        codes: preview.body.codes,
      });
    expect(res.status).toBe(201);

    const placeholders = preview.body.codes.map(() => '?').join(', ');
    const rows = await getDb().query(
      `SELECT duration_minutes, price FROM vouchers WHERE code IN (${placeholders})`,
      preview.body.codes
    );
    expect(rows).toHaveLength(3);
    expect(rows.every((row) => row.duration_minutes === 1440 && row.price === 7550)).toBe(true);

    const dynamicPreview = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({ type: 'standard', quantity: 1, duration: 90, price: '', preview: true });
    expect(dynamicPreview.status).toBe(200);
    expect(dynamicPreview.body.codes).toHaveLength(1);

    const dynamic = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({
        type: 'standard',
        quantity: 1,
        duration: 90,
        price: '',
        preview: false,
        codes: dynamicPreview.body.codes,
      });
    expect(dynamic.status).toBe(201);
    const dynamicRow = await getDb().getOne(
      'SELECT duration_minutes, price FROM vouchers WHERE code = ?',
      [dynamicPreview.body.codes[0]]
    );
    expect(dynamicRow.duration_minutes).toBe(90);
    expect(dynamicRow.price).toBeNull();
  });

  test('rejects invalid duration and price values', async () => {
    for (const payload of [
      { type: 'standard', quantity: 1, duration: 0 },
      { type: 'standard', quantity: 1, duration: 1.5 },
      { type: 'standard', quantity: 1, duration: 'sixty' },
      { type: 'standard', quantity: 1, price: -1 },
      { type: 'standard', quantity: 1, price: 'not-a-price' },
    ]) {
      const res = await request(app)
        .post('/api/admin/vouchers/bulk')
        .set('X-API-Key', VALID_KEY)
        .send(payload);
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    }
  });

  test('preview generates collision-checked codes without saving them', async () => {
    const res = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({ type: 'standard', quantity: 10, preview: true });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.codes).toHaveLength(10);
    expect(new Set(res.body.codes).size).toBe(10);
    res.body.codes.forEach((code) => expect(code).toMatch(/^\d{6}$/));

    const rows = await getDb().query(
      'SELECT code FROM vouchers WHERE code IN (' + res.body.codes.map(() => '?').join(', ') + ')',
      res.body.codes
    );
    expect(rows).toHaveLength(0);
  });

  test('confirm saves the exact previewed codes with the previewed settings', async () => {
    const preview = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({ type: 'premium', quantity: 3, duration: 1440, price: 75.5, preview: true });

    expect(preview.status).toBe(200);
    expect(preview.body.codes).toHaveLength(3);

    const saved = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({
        type: 'premium',
        quantity: 3,
        duration: 1440,
        price: 75.5,
        preview: false,
        codes: preview.body.codes,
      });

    expect(saved.status).toBe(201);
    expect(saved.body).toEqual({ success: true });

    const placeholders = preview.body.codes.map(() => '?').join(', ');
    const rows = await getDb().query(
      `SELECT code, type, duration_minutes, price, state FROM vouchers WHERE code IN (${placeholders})`,
      preview.body.codes
    );
    expect(rows).toHaveLength(3);
    expect(rows.every((row) =>
      row.type === 'premium' &&
      row.duration_minutes === 1440 &&
      row.price === 7550 &&
      row.state === 'active'
    )).toBe(true);

    const duplicate = await request(app)
      .post('/api/admin/vouchers/bulk')
      .set('X-API-Key', VALID_KEY)
      .send({
        type: 'premium',
        quantity: 3,
        duration: 1440,
        price: 75.5,
        preview: false,
        codes: preview.body.codes,
      });
    expect(duplicate.status).toBe(409);
    expect(duplicate.body.success).toBe(false);
  });

  test('confirm rejects malformed, duplicate, or wrong-length code batches', async () => {
    const badBatches = [
      ['123456', '123456'],
      ['12345', '123457'],
      [123456, 123457],
      ['123456'],
    ];

    for (const codes of badBatches) {
      const res = await request(app)
        .post('/api/admin/vouchers/bulk')
        .set('X-API-Key', VALID_KEY)
        .send({ type: 'standard', quantity: 2, preview: false, codes });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    }

    const rows = await getDb().query('SELECT code FROM vouchers WHERE code IN (?, ?)', ['123456', '123457']);
    expect(rows).toHaveLength(0);
  });

  test('requires authentication', async () => {
    const res = await request(app)
      .post('/api/admin/vouchers/bulk')
      .send({ type: 'standard', quantity: 1, preview: true });

    expect(res.status).toBe(401);
  });
});
