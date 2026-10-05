/**
 * routes/admin.js — Admin management API
 *
 * All endpoints require an API key passed in the `X-API-Key` header,
 * or a valid login session token passed in the `Authorization: Bearer` header,
 * matching process.env.ADMIN_API_KEY.
 *
 * Endpoints:
 *   POST   /api/admin/login      — Authenticate and receive a session token
 *   GET    /api/admin/me         — Get current admin username
 *   GET    /api/admin/vouchers   — List all vouchers
 *   POST   /api/admin/vouchers   — Create a new voucher
 *   PUT    /api/admin/vouchers/:id — Update a voucher
 *   DELETE /api/admin/vouchers/:id — Delete a voucher
 *   GET    /api/admin/sessions   — List active sessions
 *   POST   /api/admin/sessions/:id/expire — Force-expire a session
 *   GET    /api/admin/stats      — Dashboard statistics
 */

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const router = express.Router();
const { getDb } = require('../db/client');
const { expireSession } = require('../services/session');
const { parsePriceToCentavos } = require('../utils/price');

const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || ADMIN_API_KEY;
const VALID_TOKENS = new Set();

// Middleware: require bearer token or API key
function requireAuth(req, res, next) {
  const provided = req.headers['authorization']?.replace(/^Bearer\s+/i, '') || req.headers['x-api-key'];
  if (!provided) {
    return res.status(401).json({ success: false, error: 'Unauthorized — valid token or API key required.' });
  }
  // Accept either a valid session token or the admin API key
  if (VALID_TOKENS.has(provided) || (ADMIN_API_KEY && provided === ADMIN_API_KEY)) {
    return next();
  }
  return res.status(401).json({ success: false, error: 'Unauthorized — valid token or API key required.' });
}

// Login endpoint (before requireAuth)
router.post('/login', (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      const token = require('crypto').randomBytes(32).toString('hex');
      VALID_TOKENS.add(token);
      return res.json({ success: true, token, expiresIn: 8 * 3600 });
    }
    return res.status(401).json({ success: false, error: 'Invalid credentials.' });
  } catch (err) {
    next(err);
  }
});

router.use(requireAuth);

// Get current admin info (requires valid session token or API key)
router.get('/me', (req, res) => {
  res.json({
    success: true,
    username: ADMIN_USERNAME,
  });
});


// List all vouchers
router.get('/vouchers', async (req, res, next) => {
  try {
    const db = getDb();
    const rows = await db.query(`
      SELECT id, code, type, duration_minutes, price, state, used_by_mac, used_at,
             created_at, expires_at
      FROM vouchers
      ORDER BY created_at DESC
    `);
        res.json({ success: true, vouchers: rows });
  } catch (err) {
    next(err);
  }
});

// Create a new voucher
router.post('/vouchers', async (req, res, next) => {
  try {
    const {
      type = 'standard',
      durationMinutes = 60,
      price = null,
      quantity = 1,
      expiresAt = null,
      prefix = 'WIFI',
    } = req.body;

    if (type !== 'standard' && type !== 'premium') {
      return res.status(400).json({ success: false, error: 'type must be "standard" or "premium"' });
    }
    if (!durationMinutes || durationMinutes < 1) {
      return res.status(400).json({ success: false, error: 'durationMinutes is required and must be positive' });
    }
    if (price !== undefined && price !== null && (!Number.isInteger(price) || price < 0)) {
      return res.status(400).json({ success: false, error: 'price must be a non-negative integer number of centavos (50.00 pesos = 5000)' });
    }

    const db = getDb();
    const created = [];

    for (let i = 0; i < Math.min(quantity, 100); i++) {
      const code = `${prefix}-${uuidv4().replace(/-/g, '').slice(0, 12).toUpperCase()}`;
      await db.run(`
        INSERT INTO vouchers (code, type, duration_minutes, price, state, expires_at)
        VALUES (?, ?, ?, ?, 'active', ?)
      `, [code, type, durationMinutes, price, expiresAt]);
      created.push(code);
    }

    res.status(201).json({ success: true, created });
  } catch (err) {
    next(err);
  }
});

// Update a voucher
router.put('/vouchers/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const { state, type, durationMinutes, price, expiresAt } = req.body;

    const db = getDb();
    const fields = [];
    const params = [];

    if (state !== undefined) {
      fields.push('state = ?');
      params.push(state);
    }
    if (type !== undefined) {
      fields.push('type = ?');
      params.push(type);
    }
    if (durationMinutes !== undefined) {
      fields.push('duration_minutes = ?');
      params.push(durationMinutes);
    }
    if (price !== undefined) {
      fields.push('price = ?');
      params.push(price);
    }
    if (expiresAt !== undefined) {
      fields.push('expires_at = ?');
      params.push(expiresAt);
    }

    if (fields.length === 0) {
      return res.status(400).json({ success: false, error: 'No fields to update' });
    }

    params.push(id);
    const result = await db.run(`
      UPDATE vouchers SET ${fields.join(', ')} WHERE id = ?
    `, params);

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Voucher not found' });
    }

    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// Reset the vouchers ID sequence so the next insert starts at 1.
// SAFE: sessions reference vouchers by CODE (sessions.voucher_used) and no
// foreign key references vouchers.id, so resetting IDs never breaks links.
async function resetVoucherIdSequence(db) {
  try {
    if (db._driver === 'pg') {
      // PostgreSQL: schema converts AUTOINCREMENT to an identity column
      await db.run('ALTER TABLE vouchers ALTER COLUMN id RESTART WITH 1');
      return true;
    }
    // SQLite: the AUTOINCREMENT counter lives in sqlite_sequence
    const seqTable = await db.getOne(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'"
    );
    if (!seqTable) return true; // fresh table - sequence already starts at 1
    await db.run("DELETE FROM sqlite_sequence WHERE name = 'vouchers'");
    return true;
  } catch (err) {
    console.error('[admin] Could not reset voucher ID sequence:', err.message);
    return false;
  }
}

// Delete a voucher. When this empties the table, the auto-increment sequence
// is reset so the next import starts again at ID 1. Partial deletes never
// renumber the remaining rows.
router.delete('/vouchers/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const db = getDb();
    const result = await db.run('DELETE FROM vouchers WHERE id = ?', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Voucher not found' });
    }
    const remaining = await db.getOne('SELECT COUNT(*) AS count FROM vouchers');
    const isEmpty = !remaining || parseInt(remaining.count, 10) === 0;
    const idsReset = isEmpty ? await resetVoucherIdSequence(db) : false;
    res.json({
      success: true,
      idsReset,
      message: idsReset
        ? 'Voucher deleted. Table is now empty - ID sequence reset (next voucher starts at ID 1).'
        : undefined,
    });
  } catch (err) {
    next(err);
  }
});

// Delete ALL vouchers and reset the ID sequence (one-shot cleanup endpoint).
// Sessions are linked to vouchers by code, not ID, so this never breaks them.
// A failure here returns a specific, non-leaking message (never the generic
// "An internal error occurred." from the global handler) so sequence-reset
// problems on PostgreSQL are diagnosable.
router.post('/vouchers/delete-all', async (req, res, next) => {
  const db = getDb();
  try {
    const countRow = await db.getOne('SELECT COUNT(*) AS count FROM vouchers');
    const before = parseInt(countRow?.count || 0, 10);

    if (before > 0) {
      await db.run('DELETE FROM vouchers');
    }
    let idsReset = false;
    try {
      idsReset = await resetVoucherIdSequence(db);
    } catch (seqErr) {
      console.error('[admin] Voucher ID sequence reset failed:', seqErr.message);
      // Rows are already deleted - report success but flag the sequence problem.
      const refRow = await db.getOne('SELECT COUNT(DISTINCT voucher_used) AS count FROM sessions WHERE voucher_used IS NOT NULL');
      const sessionRefs = parseInt(refRow?.count || 0, 10);
      return res.json({
        success: true,
        deleted: before,
        idsReset: false,
        message: `Deleted ${before} voucher(s). ` +
          'WARNING: the ID sequence could NOT be reset (see server logs) - the next import may not start at ID 1.',
        note: sessionRefs > 0
          ? `${sessionRefs} session record(s) reference deleted voucher codes. Sessions are linked by code, not by ID, so they remain valid.`
          : undefined,
      });
    }

    const refRow = await db.getOne('SELECT COUNT(DISTINCT voucher_used) AS count FROM sessions WHERE voucher_used IS NOT NULL');
    const sessionRefs = parseInt(refRow?.count || 0, 10);

    res.json({
      success: true,
      deleted: before,
      idsReset,
      message: `Deleted ${before} voucher(s). ` +
        (idsReset
          ? 'ID sequence reset - the next import starts again at ID 1.'
          : 'WARNING: the ID sequence could NOT be reset (see server logs).'),
      note: sessionRefs > 0
        ? `${sessionRefs} session record(s) reference deleted voucher codes. Sessions are linked by code, not by ID, so they remain valid - no foreign key errors occurred.`
        : undefined,
    });
  } catch (err) {
    console.error('[admin] delete-all failed:', err.message);
    // Send a specific error instead of falling through to the generic handler.
    // 503 signals a database-level problem; no partial state is exposed.
    return res.status(503).json({
      success: false,
      error: 'Failed to delete all vouchers: a database error occurred (' +
        (err.code || err.message || 'unknown').slice(0, 120) +
        '). No vouchers were deleted or the deletion was incomplete - check the server logs and try again.',
    });
  }
});

// List sessions (active/paused)
router.get('/sessions', async (req, res, next) => {
  try {
    const db = getDb();
    const rows = await db.query(`
      SELECT session_id, client_mac, client_ip, voucher_type, duration_minutes,
             total_duration_seconds, state, started_at, expires_at, paused_at,
             remaining_seconds, voucher_used, payment_amount, created_at
      FROM sessions
      WHERE state IN ('active', 'paused', 'pending', 'pending_payment')
      ORDER BY created_at DESC
      LIMIT 100
    `);
    res.json({ success: true, sessions: rows });
  } catch (err) {
    next(err);
  }
});

// Force-expire a session
router.post('/sessions/:id/expire', async (req, res, next) => {
  try {
    const { id } = req.params;
    const session = await expireSession(id, 'admin_expired');
    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }
    res.json({ success: true, state: 'expired' });
  } catch (err) {
    next(err);
  }
});

// Import vouchers from CSV/XLSX file
const multer = require('multer');
const XLSX = require('xlsx');

// Memory storage only — files are never written to disk
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

router.post('/vouchers/import', upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }

    // Parse the file
    const workbook = XLSX.read(req.file.buffer, { type: 'buffer', codepage: 65001 });
    const sheetName = workbook.SheetNames[0];
    if (!sheetName) {
      return res.status(400).json({ success: false, error: 'Invalid file: no sheets found' });
    }

    const worksheet = workbook.Sheets[sheetName];
    // defval keeps blank cells as '' so every data row has all columns present;
    // sheet_to_json treats the first sheet row as the header, so the header row is skipped automatically.
    const parsedRows = XLSX.utils.sheet_to_json(worksheet, { defval: '' });

    // Skip any completely empty rows (all cells blank).
    // Preserve the real spreadsheet row number (__rowNum__, 0-based incl. header) for error messages.
    const dataRows = parsedRows
      .map(row => ({ row, rowNum: row.__rowNum__ }))
      .filter(({ row }) => {
        const values = Object.values(row);
        return values.some(v => v !== undefined && v !== null && String(v).trim() !== '');
      });

    if (dataRows.length === 0) {
      return res.status(400).json({ success: false, error: 'File contains no data rows' });
    }

    // Validate required columns
    const requiredColumns = ['ID', 'Code', 'Type', 'Duration', 'Price'];
    const headers = Object.keys(dataRows[0].row).filter(h => h !== '__rowNum__');
    const missingColumns = requiredColumns.filter(col => !headers.includes(col));

    if (missingColumns.length > 0) {
      return res.status(400).json({
        success: false,
        error: `Missing required columns: ${missingColumns.join(', ')}`,
      });
    }

    // ---- Validate EVERY row before inserting anything ----
    // Collect all problems so the admin sees the full list (row + column + value)
    // instead of a generic 500 from a bad value reaching the database.
    const errors = [];
    let autoIdCount = 0;
    const validRows = [];

    for (const { row, rowNum } of dataRows) {
      // Excel row number (header = row 1, so data starts at row 2)
      const excelRow = (rowNum || 0) + 1;

      // --- ID: plain integer; blank/missing -> auto-generated by the DB ---
      const rawId = row.ID;
      const idStr = rawId === undefined || rawId === null ? '' : String(rawId).trim();
      if (idStr === '') {
        // Missing ID: auto-generate a sequential ID (leave the column out of the INSERT)
        autoIdCount++;
      } else {
        const parsedId = parseInt(idStr, 10);
        if (isNaN(parsedId)) {
          errors.push(`Row ${excelRow}: column "ID" has invalid value "${idStr}" (expected a whole number)`);
        }
      }

      // --- Code: exactly 6 numeric digits ---
      const rawCode = row.Code;
      const codeStr = rawCode === undefined || rawCode === null ? '' : String(rawCode).trim();
      if (!/^\d{6}$/.test(codeStr)) {
        errors.push(`Row ${excelRow}: column "Code" has invalid value "${codeStr}" (must be exactly 6 numeric digits)`);
      }

      // --- Type: plain text, must be standard or premium ---
      const rawType = row.Type;
      const typeStr = rawType === undefined || rawType === null ? '' : String(rawType).trim().toLowerCase();
      if (typeStr !== 'standard' && typeStr !== 'premium') {
        errors.push(`Row ${excelRow}: column "Type" has invalid value "${typeStr}" (must be "standard" or "premium")`);
      }

      // --- Duration: plain text parsed as integer, required, must be positive ---
      const rawDuration = row.Duration;
      const durationStr = rawDuration === undefined || rawDuration === null ? '' : String(rawDuration).trim();
      const parsedDuration = parseInt(durationStr, 10);
      if (durationStr === '' || isNaN(parsedDuration) || parsedDuration < 1) {
        errors.push(`Row ${excelRow}: column "Duration" has invalid value "${durationStr}" (expected a positive whole number of minutes)`);
      }

      // --- Price: one shared parser, human format -> integer centavos ---
      // STORAGE RULE: vouchers.price is INTEGER centavos (₱50.00 = 5000).
      const rawPrice = row.Price;
      const priceStr = rawPrice === undefined || rawPrice === null ? '' : String(rawPrice).trim();
      const priceResult = parsePriceToCentavos(rawPrice);
      if (!priceResult.ok) {
        const reasons = {
          empty: 'a price is required (e.g. ₱50.00)',
          negative: 'price cannot be negative',
          invalid: 'expected a price like 50, 50.50, ₱50.00, or PHP 1,250.00',
          too_large: 'price is too large',
        };
        errors.push(`Row ${excelRow}: column "Price" has invalid value "${priceStr}" (${reasons[priceResult.reason]})`);
      }
      if (errors.length === 0) {
        validRows.push({ code: codeStr, type: typeStr, duration: parsedDuration, price: priceResult.ok ? priceResult.centavos : null });
      }
    }

    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        error: `Import failed — no vouchers were imported. ${errors.join('; ')}`,
      });
    }

    // ---- All rows valid: insert into database ----
    // The ID column is intentionally never inserted: blank IDs auto-generate a
    // sequential ID via the table AUTOINCREMENT primary key, and explicitly
    // inserting the CSV ID could collide with existing vouchers.
    const db = getDb();
    let inserted = 0;
    let updated = 0;
    let skipped = 0;

    for (const v of validRows) {
      // Check if voucher already exists
      const existing = await db.getOne('SELECT id FROM vouchers WHERE code = ?', [v.code]);

      if (existing) {
        // Update existing voucher
        await db.run(
          'UPDATE vouchers SET type = ?, duration_minutes = ?, price = ? WHERE code = ?',
          [v.type, v.duration, v.price, v.code]
        );
        updated++;
      } else {
        // Insert new voucher
        await db.run(
          'INSERT INTO vouchers (code, type, duration_minutes, price, state) VALUES (?, ?, ?, ?, ?)',
          [v.code, v.type, v.duration, v.price, 'active']
        );
        inserted++;
      }
    }

    res.json({
      success: true,
      message: `Imported ${inserted} new, updated ${updated}, skipped ${skipped} voucher(s)` +
        (autoIdCount > 0 ? ` (${autoIdCount} auto-generated ID${autoIdCount === 1 ? '' : 's'})` : ''),
      summary: { inserted, updated, skipped, total: validRows.length, autoId: autoIdCount },
    });
  } catch (err) {
    next(err);
  }
});

// Dashboard statistics
router.get('/stats', async (req, res, next) => {
  try {
    const db = getDb();

    const totalVouchers = await db.getOne('SELECT COUNT(*) as count FROM vouchers');
    const activeVouchers = await db.getOne("SELECT COUNT(*) as count FROM vouchers WHERE state = 'active'");
    const usedVouchers = await db.getOne("SELECT COUNT(*) as count FROM vouchers WHERE state = 'used'");
    const totalSessions = await db.getOne('SELECT COUNT(*) as count FROM sessions');
    const activeSessions = await db.getOne("SELECT COUNT(*) as count FROM sessions WHERE state = 'active'");
    const pausedSessions = await db.getOne("SELECT COUNT(*) as count FROM sessions WHERE state = 'paused'")
    const totalRevenueRow = await db.getOne("SELECT SUM(payment_amount) as total FROM sessions WHERE payment_amount IS NOT NULL")
    const premiumSessions = await db.getOne("SELECT COUNT(*) as count FROM sessions WHERE voucher_type = 'premium'")

    res.json({
      success: true,
      stats: {
        totalVouchers: parseInt(totalVouchers?.count || 0, 10),
        activeVouchers: parseInt(activeVouchers?.count || 0, 10),
        usedVouchers: parseInt(usedVouchers?.count || 0, 10),
        totalSessions: parseInt(totalSessions?.count || 0, 10),
        activeSessions: parseInt(activeSessions?.count || 0, 10),
        pausedSessions: parseInt(pausedSessions?.count || 0, 10),
        totalRevenue: parseInt(totalRevenueRow?.total || 0, 10),
        premiumSessions: parseInt(premiumSessions?.count || 0, 10),
      },
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

