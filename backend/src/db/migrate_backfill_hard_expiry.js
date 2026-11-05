/**
 * db/migrate_backfill_hard_expiry.js — one-shot backfill: Premium hard deadline
 *
 * `absolute_expires_at` was added to `sessions` after Premium passes were
 * already in use, so rows created before that column existed carry NULL — and
 * both the lazy enforcement in services/session.js (isHardExpired) and the
 * expiration worker skip NULL. Those passes never hard-expire.
 *
 * This writes the deadline each such row should always have had:
 *
 *     COALESCE(started_at, created_at) + PREMIUM_HARD_EXPIRY_HOURS
 *
 * Only live rows are touched (`state IN ('active','paused')`): expired rows are
 * terminal, and rewriting their history would change what the admin reports
 * show. Rows whose anchor is already further back than the window are still
 * backfilled — the resulting deadline lands in the past, so the next
 * enforcement sweep expires them, which is the correct outcome for a pass that
 * was already void.
 *
 * Idempotent: rows that already have a deadline are not selected again.
 *
 * Dual-mode (SQLite / PostgreSQL) through db/client.js, like the other
 * migrations in this directory.
 *
 * Run with: node src/db/migrate_backfill_hard_expiry.js
 */

require('dotenv').config();
const { getDb, closeDb, parseUtcTimestamp } = require('./client');
const { PREMIUM_HARD_EXPIRY_HOURS } = require('../config');

const WINDOW_MS = PREMIUM_HARD_EXPIRY_HOURS * 60 * 60 * 1000;

const SELECT_SQL = `
  SELECT session_id, started_at, created_at
    FROM sessions
   WHERE voucher_type = 'premium'
     AND absolute_expires_at IS NULL
     AND state IN ('active', 'paused')
   ORDER BY id
`;

const UPDATE_SQL = `
  UPDATE sessions
     SET absolute_expires_at = ?
   WHERE session_id = ?
     AND absolute_expires_at IS NULL
`;

/**
 * Resolve a stored timestamp to epoch milliseconds as UTC.
 *
 * PostgreSQL returns a Date (client.js pins the parser to UTC); SQLite returns
 * the stored text, which is either the app's ISO string or CURRENT_TIMESTAMP's
 * bare "YYYY-MM-DD HH:mm:ss" form — parsed as UTC by parseUtcTimestamp so the
 * host timezone cannot shift the deadline.
 *
 * @param {Date|string|null} value
 * @returns {number|null} epoch ms, or null when the value is missing/unparsable
 */
function toAnchorMs(value) {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) {
    const t = value.getTime();
    return Number.isFinite(t) ? t : null;
  }
  const text = String(value).trim();
  if (!text) return null;
  const parsed = parseUtcTimestamp(text);
  const t = parsed instanceof Date ? parsed.getTime() : Number(parsed);
  return Number.isFinite(t) ? t : null;
}

async function run() {
  const db = getDb();
  console.log(`[migrate_backfill_hard_expiry] starting (driver: ${db._driver})`);
  console.log(`[migrate_backfill_hard_expiry] window: ${PREMIUM_HARD_EXPIRY_HOURS} h from started_at (fallback created_at)`);

  const rows = await db.query(SELECT_SQL, []);
  console.log(`[migrate_backfill_hard_expiry] ${rows.length} premium row(s) with no deadline`);

  if (rows.length === 0) {
    console.log('[migrate_backfill_hard_expiry] nothing to backfill');
    return { scanned: 0, updated: 0, skipped: 0, alreadyPast: 0 };
  }

  const now = Date.now();
  let updated = 0;
  let skipped = 0;
  let alreadyPast = 0;

  await db.transaction(async tx => {
    for (const row of rows) {
      const anchorMs = toAnchorMs(row.started_at) ?? toAnchorMs(row.created_at);
      if (anchorMs === null) {
        // Neither timestamp survives — cannot derive a deadline, so leave the
        // row alone rather than inventing one. Visible in the summary.
        console.warn(`[migrate_backfill_hard_expiry]   ! ${row.session_id}: no started_at/created_at — skipped`);
        skipped += 1;
        continue;
      }

      const deadlineMs = anchorMs + WINDOW_MS;
      const deadline = new Date(deadlineMs).toISOString();

      await tx.run(UPDATE_SQL, [deadline, row.session_id]);
      updated += 1;
      if (deadlineMs <= now) alreadyPast += 1;
    }
  });

  console.log(`[migrate_backfill_hard_expiry] backfilled ${updated} row(s)`);
  if (alreadyPast > 0) {
    console.log(`[migrate_backfill_hard_expiry]   ${alreadyPast} of them are already past the window — the next enforcement sweep will expire them`);
  }
  if (skipped > 0) {
    console.warn(`[migrate_backfill_hard_expiry]   ${skipped} row(s) skipped (missing anchor timestamp)`);
  }

  return { scanned: rows.length, updated, skipped, alreadyPast };
}

if (require.main === module) {
  run()
    .then(result => {
      console.log(`[migrate_backfill_hard_expiry] done: ${JSON.stringify(result)}`);
      return closeDb();
    })
    .catch(err => {
      console.error('[migrate_backfill_hard_expiry] FAILED:', err.message);
      process.exit(1);
    });
}

module.exports = { run };
