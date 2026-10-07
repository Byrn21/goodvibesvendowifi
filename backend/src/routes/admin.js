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
 *
 * Pending-claim dashboard (all routes require the `x-admin-password` header,
 * matched against process.env.ADMIN_PASSWORD; fail closed when unset):
 *   GET    /api/admin/claims/pending     — List manual payment claims awaiting review
 *   POST   /api/admin/claims/approve     — Authorize the device and process the claim
 *   POST   /api/admin/claims/reject      — Mark a claim rejected
 */

const express = require('express');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const router = express.Router();
const { getDb } = require('../db/client');
const { expireSession } = require('../services/session');
const { parsePriceToCentavos } = require('../utils/price');
const { normalizeMac } = require('../utils/device-id');
const { computeMinutesFromAmount } = require('../utils/duration');
const omadaService = require('../services/omada');

// Duration granted when a claim's amount is missing/unrecognized (manual
// claims are written with amount = NULL by POST /api/payment/claim). Kept as
// a named constant — never a magic number inline.
const DEFAULT_CLAIM_DURATION_MINUTES = 60;

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

// ── Pending-claims dashboard (x-admin-password auth) ───────────────────
// Separate from the API-key/token auth above so the existing /api/admin/*
// routes and their tests are untouched. Applied to EVERY claims route via
// router.use(...).

/** Constant-time string comparison (avoids leaking the password by timing). */
function safeEqualPassword(a, b) {
  const bufA = Buffer.from(String(a || ''), 'utf8');
  const bufB = Buffer.from(String(b || ''), 'utf8');
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(Buffer.alloc(32), Buffer.alloc(32));
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Require the `x-admin-password` header to match process.env.ADMIN_PASSWORD.
 * FAIL CLOSED: when ADMIN_PASSWORD is unset, every request is rejected 401
 * (the dashboard is never reachable without an explicit configured secret).
 */
function requireAdminPassword(req, res, next) {
  const configured = process.env.ADMIN_PASSWORD || '';
  if (!configured) {
    return res.status(401).json({
      success: false,
      error: 'Admin dashboard is not configured. Set ADMIN_PASSWORD on the server.',
      code: 'ADMIN_NOT_CONFIGURED',
    });
  }
  const provided = req.headers['x-admin-password'];
  if (typeof provided !== 'string' || !safeEqualPassword(provided, configured)) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized — invalid admin password.',
      code: 'UNAUTHORIZED',
    });
  }
  return next();
}

const claimsRouter = express.Router();
claimsRouter.use(requireAdminPassword);

// GET /api/admin/claims/pending — claims waiting for manual review, newest
// first. webhook_events has no client_mac column, so the submitting device is
// joined from the sessions row created at claim time (same session_id).
//
// NOTE: `status = 'pending'` is the only pending value this codebase writes
// (see POST /api/payment/claim). The spec mentioned 'pending_claim', but that
// string does not exist anywhere in the codebase, so it is intentionally not
// included rather than inventing an unverified status.
claimsRouter.get('/pending', async (req, res, next) => {
  try {
    const db = getDb();
    const rows = await db.query(`
      SELECT w.ref_no       AS ref_no,
             w.session_id   AS session_id,
             w.status       AS status,
             w.amount       AS amount,
             w.processed_at AS event_at,
             s.client_mac   AS client_mac,
             s.created_at   AS session_created_at
      FROM webhook_events w
      LEFT JOIN sessions s ON s.session_id = w.session_id
      WHERE w.status = 'pending'
      ORDER BY COALESCE(s.created_at, w.processed_at) DESC
    `);

    const claims = rows.map(r => ({
      ref_no: r.ref_no,
      client_mac: r.client_mac || null,
      timestamp: r.session_created_at || r.event_at || null,
      amount: r.amount,
      session_id: r.session_id || null,
    }));

    return res.json({ success: true, claims });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/claims/approve — { ref_no, client_mac }
// Order matters: resolve context and authorize on the controller FIRST, then
// persist. A controller failure therefore leaves the claim pending (retryable)
// and the session untouched.
claimsRouter.post('/approve', async (req, res, next) => {
  try {
    const body = req.body || {};
    const refNo = typeof body.ref_no === 'string' ? body.ref_no.trim() : '';
    if (!refNo) {
      return res.status(400).json({ success: false, error: 'ref_no is required.', code: 'MISSING_REF_NO' });
    }
    const clientMac = normalizeMac(body.client_mac);
    if (!clientMac) {
      return res.status(400).json({
        success: false,
        error: 'client_mac is required and must be a valid MAC address.',
        code: 'MISSING_CLIENT_MAC',
      });
    }

    const db = getDb();

    // (a) The claim must exist and still be pending.
    const claim = await db.getOne('SELECT * FROM webhook_events WHERE ref_no = ? LIMIT 1', [refNo]);
    if (!claim) {
      return res.status(404).json({
        success: false,
        error: 'No claim found for reference ' + refNo + '.',
        code: 'CLAIM_NOT_FOUND',
      });
    }
    if (claim.status !== 'pending') {
      return res.status(409).json({
        success: false,
        error: 'Claim is not pending (current status: ' + claim.status + ').',
        code: 'CLAIM_NOT_PENDING',
      });
    }

    // Session linked to the claim (its client_mac is authoritative).
    const session =
      (await db.getOne('SELECT * FROM sessions WHERE session_id = ? LIMIT 1', [claim.session_id])) ||
      (await db.getOne('SELECT * FROM sessions WHERE ref_no = ? LIMIT 1', [refNo]));
    if (!session) {
      return res.status(404).json({
        success: false,
        error: 'No session is linked to this claim.',
        code: 'SESSION_NOT_FOUND',
      });
    }
    if (session.client_mac && session.client_mac !== clientMac) {
      return res.status(400).json({
        success: false,
        error: 'client_mac does not match the device that submitted this claim.',
        code: 'CLIENT_MAC_MISMATCH',
      });
    }

    // (a) Controller context captured at portal landing.
    const ctx = await db.getOne(
      'SELECT client_ip, ap_mac, ssid_name, radio_id FROM portal_client_context WHERE client_mac = ?',
      [clientMac]
    );
    if (!ctx || !ctx.ap_mac || !ctx.ssid_name || ctx.radio_id === null || ctx.radio_id === undefined) {
      return res.status(404).json({
        success: false,
        error: 'No portal context found for this device. Have the customer re-open the captive portal page, then retry.',
        code: 'MISSING_PORTAL_CONTEXT',
      });
    }

    // (b) Duration from the claim's amount, else the named default.
    const fromAmount = computeMinutesFromAmount(claim.amount);
    const durationMinutes = fromAmount > 0 ? fromAmount : DEFAULT_CLAIM_DURATION_MINUTES;
    const sessionId = session.session_id || claim.session_id;

    // (c) Authorize on the controller BEFORE writing — a failure is retryable.
    try {
      await omadaService.authenticateClient({
        clientMac,
        clientIp: ctx.client_ip || '',
        apMac: ctx.ap_mac,
        ssidName: ctx.ssid_name,
        radioId: ctx.radio_id,
        durationMinutes,
        sessionId,
      });
    } catch (omadaErr) {
      console.error('[admin/claims] Omada auth failed for ref ' + refNo + ':', omadaErr.message);
      // Diagnostic flag only — claim status and session state are left
      // unchanged so the operator can retry this claim.
      await db.run(
        'UPDATE sessions SET omada_auth_failed = 1, updated_at = ? WHERE session_id = ?',
        [new Date().toISOString(), sessionId]
      );
      return res.status(502).json({
        success: false,
        error: 'Controller authorization failed. The claim was left pending — please retry.',
        code: 'OMADA_ERROR',
      });
    }

    // (d) Persist: activate the session, then flip the claim to the existing
    // 'processed' status. Session-first keeps a failed second write retryable
    // (the claim stays visible) rather than hiding an inactive session.
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + durationMinutes * 60 * 1000).toISOString();

    await db.run(
      `UPDATE sessions
         SET state = 'active', started_at = COALESCE(started_at, ?),
             expires_at = ?, omada_auth_failed = 0, updated_at = ?
       WHERE session_id = ?`,
      [now, expiresAt, now, sessionId]
    );
    await db.run(
      `UPDATE webhook_events SET status = 'processed', processed_at = ? WHERE ref_no = ?`,
      [now, refNo]
    );

    console.log('[admin/claims] approved ref ' + refNo + ' for ' + clientMac + ' (' + durationMinutes + ' min)');
    // (e) Success.
    return res.json({
      success: true,
      expires_at: expiresAt,
      session_id: sessionId,
      duration_minutes: durationMinutes,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/claims/reject — { ref_no }
claimsRouter.post('/reject', async (req, res, next) => {
  try {
    const body = req.body || {};
    const refNo = typeof body.ref_no === 'string' ? body.ref_no.trim() : '';
    if (!refNo) {
      return res.status(400).json({ success: false, error: 'ref_no is required.', code: 'MISSING_REF_NO' });
    }

    const db = getDb();
    const result = await db.run(
      "UPDATE webhook_events SET status = 'rejected', processed_at = ? WHERE ref_no = ? AND status = 'pending'",
      [new Date().toISOString(), refNo]
    );
    if (!result || result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        error: 'No pending claim found for reference ' + refNo + '.',
        code: 'CLAIM_NOT_FOUND',
      });
    }

    console.log('[admin/claims] rejected ref ' + refNo);
    return res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// Mounted BEFORE requireAuth so the password-protected claims routes are
// reachable without an API key / bearer token.
router.use('/claims', claimsRouter);

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
      SELECT id, code, type, duration_minutes, price, state, assigned_ref_no,
             used_by_mac, used_at, created_at, expires_at
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

