/**
 * db/migrate_add_voucher_ref.js — standalone migration:
 * add vouchers.assigned_ref_no
 *
 * Adds `assigned_ref_no` to the vouchers table. The pre-generated voucher
 * claim architecture stores the FULL payment reference number on the voucher
 * once it is claimed (the customer only enters the last 4 digits, so the
 * full ref lives here for auditing / traceability).
 *
 * Idempotent: safe to run multiple times. It first checks whether the column
 * (and even the table) already exists, and it also swallows "column already
 * exists" errors as a second line of defence. SQLite has no
 * `ADD COLUMN IF NOT EXISTS`, so the existence check is the portable guard.
 *
 * Dual-mode:
 *   - SQLite: ALTER TABLE ADD COLUMN (checked via PRAGMA table_info).
 *   - PostgreSQL: same ALTER TABLE statement (checked via
 *     information_schema.columns), which is valid PostgreSQL syntax.
 *
 * On a fresh database the vouchers table does not exist yet; schema.sql
 * creates it WITH this column, so run() becomes a no-op instead of failing.
 *
 * Run with: node src/db/migrate_add_voucher_ref.js
 * (requires DATABASE_URL to be set, or defaults to local SQLite)
 *
 * It is also invoked automatically on boot from src/server.js and from the
 * full migration runner src/db/migrate.js. run() therefore does NOT close the
 * shared connection — only the CLI entry point does.
 */

require('dotenv').config();
const { getDb, closeDb } = require('./client');

const TABLE = 'vouchers';
const COLUMN = 'assigned_ref_no';
const COLUMN_TYPE = 'VARCHAR(64)';

/**
 * Does `table` exist in the current schema?
 * @param {Object} db
 * @param {string} table
 * @returns {Promise<boolean>}
 */
async function tableExists(db, table) {
  const isPg = db._driver === 'pg';
  const rows = isPg
    ? await db.query(
        `SELECT 1 FROM information_schema.tables
          WHERE table_name = $1 AND table_schema = current_schema()`,
        [table]
      )
    : await db.query(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`,
        [table]
      );
  return rows.length > 0;
}

/**
 * Does `column` exist on `table`?
 * @param {Object} db
 * @param {string} table
 * @param {string} column
 * @returns {Promise<boolean>}
 */
async function columnExists(db, table, column) {
  const isPg = db._driver === 'pg';
  const rows = isPg
    ? await db.query(
        `SELECT column_name FROM information_schema.columns
          WHERE table_name = $1 AND column_name = $2 AND table_schema = current_schema()`,
        [table, column]
      )
    : await db.query(`PRAGMA table_info(${table})`, []);
  if (isPg) return rows.length > 0;
  return rows.some(r => r.name === column);
}

/**
 * Add vouchers.assigned_ref_no when missing.
 * @param {Object} db
 * @returns {Promise<boolean>} true when the column was added this run
 */
async function addAssignedRefColumn(db) {
  if (!(await tableExists(db, TABLE))) {
    console.log(`[migrate_add_voucher_ref] ${TABLE} table does not exist yet — schema.sql will create it with the column`);
    return false;
  }
  if (await columnExists(db, TABLE, COLUMN)) {
    console.log(`[migrate_add_voucher_ref] ${TABLE}.${COLUMN} already exists — skipping`);
    return false;
  }

  console.log(`[migrate_add_voucher_ref] adding ${COLUMN} to ${TABLE} ...`);
  try {
    await db.exec(`ALTER TABLE ${TABLE} ADD COLUMN ${COLUMN} ${COLUMN_TYPE}`);
  } catch (err) {
    // PostgreSQL 42701 / message match: duplicate column — already added
    // (e.g. a concurrent boot). Treat as success rather than failing startup.
    if (err.code === '42701' || (err.message && err.message.includes('already exists'))) {
      console.log(`[migrate_add_voucher_ref] ${TABLE}.${COLUMN} already exists — skipping`);
      return false;
    }
    throw err;
  }
  return true;
}

async function run() {
  const db = getDb();
  console.log(`[migrate_add_voucher_ref] starting (driver: ${db._driver})`);
  const added = await addAssignedRefColumn(db);
  console.log(`[migrate_add_voucher_ref] done${added ? ' (column added)' : ' (no changes)'}`);
}

if (require.main === module) {
  run()
    .then(() => closeDb())
    .catch(err => {
      console.error('[migrate_add_voucher_ref] FAILED:', err.message);
      process.exit(1);
    });
}

module.exports = { run };
