/**
 * db/migrate_add_ref_no.js — standalone migration: add ref_no columns
 *
 * Adds a UNIQUE ref_no column to:
 *   - webhook_events (payment reference number from MacroDroid webhook —
 *     primary duplicate-payment guard)
 *   - sessions (denormalized reference for traceability)
 *
 * Idempotent: safe to run multiple times. Detects whether each column
 * already exists before altering the table.
 *
 * Dual-mode:
 *   - SQLite: columns added via ALTER TABLE; unique enforcement via
 *     CREATE UNIQUE INDEX (partial index on non-NULL values).
 *   - PostgreSQL: same ALTER TABLE / CREATE UNIQUE INDEX statements —
 *     both are valid PostgreSQL syntax as written.
 *
 * Run with: node src/db/migrate_add_ref_no.js
 * (requires DATABASE_URL to be set, or defaults to local SQLite)
 */

require('dotenv').config();
const { getDb, closeDb } = require('./client');

async function columnExists(db, table, column) {
  const isPg = db._driver === 'pg';
  const rows = isPg
    ? await db.query(
        `SELECT column_name FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`,
        [table, column]
      )
    : await db.query(`PRAGMA table_info(${table})`, []);
  if (isPg) return rows.length > 0;
  return rows.some(r => r.name === column);
}

async function addRefNoColumn(db, table) {
  if (await columnExists(db, table, 'ref_no')) {
    console.log(`[migrate_add_ref_no] ${table}.ref_no already exists — skipping`);
    return;
  }
  console.log(`[migrate_add_ref_no] adding ref_no to ${table} ...`);
  await db.exec(`ALTER TABLE ${table} ADD COLUMN ref_no VARCHAR(64)`);
}

async function createUniqueIndex(db, table, indexName) {
  const isPg = db._driver === 'pg';
  // Partial unique index — valid on both SQLite (3.8.0+) and PostgreSQL.
  // For SQLite this is the primary enforcement (in addition to any UNIQUE
  // column constraint); for PostgreSQL it is the sole enforcement since
  // ALTER TABLE ADD COLUMN cannot carry a UNIQUE constraint portably.
  const sql = `CREATE UNIQUE INDEX IF NOT EXISTS ${indexName} ON ${table}(ref_no) WHERE ref_no IS NOT NULL`;
  try {
    await db.exec(sql);
    console.log(`[migrate_add_ref_no] unique index ${indexName} created`);
  } catch (err) {
    if (err.code === '42P07' || String(err.message || '').includes('already exists')) {
      console.log(`[migrate_add_ref_no] index ${indexName} already exists — skipping`);
      return;
    }
    throw err;
  }
}

async function run() {
  const db = getDb();
  const driver = db._driver;
  console.log(`[migrate_add_ref_no] starting (driver: ${driver})`);

  await addRefNoColumn(db, 'webhook_events');
  await addRefNoColumn(db, 'sessions');

  await createUniqueIndex(db, 'webhook_events', 'idx_webhook_events_ref_no');
  await createUniqueIndex(db, 'sessions', 'idx_sessions_ref_no');

  console.log('[migrate_add_ref_no] done');
  await closeDb();
}

if (require.main === module) {
  run().catch(err => {
    console.error('[migrate_add_ref_no] FAILED:', err.message);
    process.exit(1);
  });
}

module.exports = { run };
