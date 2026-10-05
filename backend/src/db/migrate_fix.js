/**
 * db/migrate_fix.js — Column-level migration for existing databases
 *
 * Ensures all columns defined in schema.sql exist on existing tables.
 * This is necessary because CREATE TABLE IF NOT EXISTS won't add
 * columns to tables that already exist in production databases.
 *
 * Columns are added using ALTER TABLE ... ADD COLUMN (plain types —
 * see the constraint notes on the column lists below). Idempotent:
 * a second run finds no missing columns and changes nothing.
 *
 * IMPORTANT: this runs BEFORE schema.sql is applied (see migrate.js)
 * so that statements in schema.sql which reference newer columns
 * (e.g. the ref_no partial unique indexes) never hit PostgreSQL
 * 42703 "column does not exist".
 */

const { getDb, closeDb } = require('./client');

// Columns that may be missing from older production databases
// Derived from schema.sql — sessions table
const SESSIONS_COLUMNS = [
  // session_id: indexed in schema.sql (idx_sessions_session_id), so it must
  // exist before Phase 2 or that index fails with 42703. NOT NULL needs a
  // DEFAULT for ALTER TABLE on populated tables.
  { name: 'session_id', type: "VARCHAR(32) NOT NULL DEFAULT ''", after: 'id' },
  // ref_no: added for the MacroDroid webhook duplicate-payment guard.
  // UNIQUE enforcement comes from the partial unique index in schema.sql
  // (ALTER TABLE ADD COLUMN cannot carry a UNIQUE constraint portably).
  { name: 'ref_no', type: 'VARCHAR(64)', after: 'client_mac' },
  { name: 'client_ip', type: 'VARCHAR(45)', after: 'client_mac' },
  { name: 'ap_mac', type: 'VARCHAR(32)', after: 'client_ip' },
  { name: 'ssid_name', type: 'VARCHAR(64)', after: 'ap_mac' },
  { name: 'voucher_type', type: "VARCHAR(16) DEFAULT 'standard'", after: 'duration_minutes' },
  { name: 'total_duration_seconds', type: 'INTEGER', after: 'voucher_type' },
  { name: 'started_at', type: 'TIMESTAMP', after: 'total_duration_seconds' },
  { name: 'expires_at', type: 'TIMESTAMP', after: 'started_at' },
  { name: 'paused_at', type: 'TIMESTAMP', after: 'expires_at' },
  { name: 'remaining_seconds', type: 'INTEGER', after: 'paused_at' },
  { name: 'state', type: "VARCHAR(16) NOT NULL DEFAULT 'pending'", after: 'remaining_seconds' },
  { name: 'voucher_used', type: 'VARCHAR(32)', after: 'state' },
  { name: 'provider_session_id', type: 'VARCHAR(128)', after: 'voucher_used' },
  { name: 'payment_event_id', type: 'VARCHAR(128)', after: 'provider_session_id' },
  { name: 'payment_amount', type: 'INTEGER', after: 'payment_event_id' },
  { name: 'payment_method', type: 'VARCHAR(32)', after: 'payment_amount' },
  { name: 'omada_auth_failed', type: 'BOOLEAN DEFAULT FALSE', after: 'payment_method' },
  { name: 'expire_reason', type: 'VARCHAR(32)', after: 'omada_auth_failed' },
  { name: 'expired_at', type: 'TIMESTAMP', after: 'expire_reason' },
  { name: 'created_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP', after: 'expired_at' },
  { name: 'updated_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP', after: 'created_at' },
];

// Columns that may be missing from older production databases
// Derived from schema.sql — vouchers table
const VOUCHERS_COLUMNS = [
  { name: 'type', type: "VARCHAR(16) NOT NULL DEFAULT 'standard'", after: 'code' },
  { name: 'duration_minutes', type: 'INTEGER NOT NULL DEFAULT 60', after: 'type' },
  { name: 'price', type: 'INTEGER', after: 'duration_minutes' },
  { name: 'state', type: "VARCHAR(16) NOT NULL DEFAULT 'active'", after: 'price' },
  { name: 'used_by_mac', type: 'VARCHAR(32)', after: 'state' },
  { name: 'used_at', type: 'TIMESTAMP', after: 'used_by_mac' },
  { name: 'created_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP', after: 'used_at' },
  { name: 'expires_at', type: 'TIMESTAMP', after: 'created_at' },
];

// Columns that may be missing from older production databases
// Derived from schema.sql — webhook_events table.
//
// Constraint note: ALTER TABLE ADD COLUMN cannot add UNIQUE columns on
// SQLite and cannot add NOT NULL without a DEFAULT on populated tables,
// so these are plain types. Uniqueness for event_id / ref_no on legacy
// tables is enforced by the indexes in schema.sql (and by the original
// column constraints on any table old enough to lack them entirely —
// all historical schema versions defined event_id with UNIQUE).
//
// Legacy width note: the initial schema defined event_id as VARCHAR(64)
// vs. VARCHAR(128) today. ADD COLUMN cannot widen an existing column,
// but real event IDs are far below 64 chars, so this is harmless.
const WEBHOOK_EVENTS_COLUMNS = [
  { name: 'event_id', type: 'VARCHAR(128)', after: 'id' },
  { name: 'ref_no', type: 'VARCHAR(64)', after: 'event_id' },
  { name: 'session_id', type: 'VARCHAR(32)', after: 'ref_no' },
  { name: 'provider', type: 'VARCHAR(16)', after: 'session_id' },
  { name: 'event_type', type: 'VARCHAR(64)', after: 'provider' },
  { name: 'amount', type: 'INTEGER', after: 'event_type' },
  { name: 'status', type: 'VARCHAR(16)', after: 'amount' },
  { name: 'processed_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP', after: 'status' },
];

/**
 * Check if a column exists in a given table.
 * @param {Object} db - Database connection
 * @param {string} tableName - Table name
 * @param {string} columnName - Column name
 * @returns {Promise<boolean>}
 */
async function columnExists(db, tableName, columnName) {
  try {
    // PostgreSQL — table_schema guard prevents false positives if a
    // same-named table exists in another schema (e.g. pg_temp).
    if (db._driver === 'pg') {
      const result = await db.query(
        `SELECT 1 FROM information_schema.columns
         WHERE table_name = ? AND column_name = ? AND table_schema = current_schema()`,
        [tableName, columnName]
      );
      return result.length > 0;
    }
    // SQLite
    const cols = db._sqliteDb.prepare(`PRAGMA table_info(${tableName})`).all();
    return cols.some(col => col.name === columnName);
  } catch (err) {
    // If the table doesn't exist, PRAGMA returns nothing; treat as no columns
    return false;
  }
}

/**
 * Get list of existing columns in a table.
 * @param {Object} db - Database connection
 * @param {string} tableName - Table name
 * @returns {Promise<string[]>}
 */
async function getExistingColumns(db, tableName) {
  try {
    if (db._driver === 'pg') {
      const rows = await db.query(
        `SELECT column_name FROM information_schema.columns
         WHERE table_name = ? AND table_schema = current_schema()`,
        [tableName]
      );
      return rows.map(r => r.column_name);
    }
    const cols = db._sqliteDb.prepare(`PRAGMA table_info(${tableName})`).all();
    return cols.map(c => c.name);
  } catch (err) {
    return [];
  }
}

/**
 * Reconcile a table's columns against the expected list.
 *
 * Adds any missing columns via ALTER TABLE ADD COLUMN (plain types —
 * see the constraint notes on the column lists above). Idempotent:
 * a second run finds no missing columns and changes nothing.
 *
 * @param {Object} db - Database connection
 * @param {string} tableName - Table name
 * @param {Array<{name: string, type: string}>} expectedColumns
 */
async function reconcileTable(db, tableName, expectedColumns) {
  const existing = await getExistingColumns(db, tableName);
  if (existing.length === 0) {
    // Table doesn't exist yet — schema.sql CREATE TABLE will handle it
    console.log(`[migrate_fix] ${tableName} table not found — CREATE TABLE will handle it.`);
    return;
  }

  const missing = expectedColumns.filter(c => !existing.includes(c.name));
  if (missing.length === 0) {
    console.log(`[migrate_fix] All ${tableName} columns up to date.`);
    return;
  }

  console.log(`[migrate_fix] Adding ${missing.length} missing column(s) to ${tableName}...`);
  for (const col of missing) {
    try {
      await db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${col.name} ${col.type}`);
      console.log(`[migrate_fix]   + ${col.name} (${col.type})`);
    } catch (err) {
      // PostgreSQL 42701 / message match: duplicate column — already added
      if (err.code === '42701' || (err.message && err.message.includes('already exists'))) {
        console.log(`[migrate_fix]   ✓ ${col.name} already exists`);
        continue;
      }
      console.warn(`[migrate_fix]   ! ${col.name}: ${err.message}`);
    }
  }
  console.log(`[migrate_fix] ${tableName} table columns updated successfully.`);
}

/**
 * Main migration: ensure all expected columns and tables exist.
 *
 * Runs BEFORE schema.sql is applied (see migrate.js) so that statements
 * in schema.sql which reference newer columns (e.g. the ref_no unique
 * indexes) never hit PostgreSQL 42703 "column does not exist".
 */
async function fixMissingColumns() {
  const db = getDb();

  // --- Sessions table ---
  await reconcileTable(db, 'sessions', SESSIONS_COLUMNS);

  // --- Vouchers table ---
  await reconcileTable(db, 'vouchers', VOUCHERS_COLUMNS);

  // --- Webhook events table ---
  // (ref_no, amount, status, processed_at may all be missing on legacy DBs —
  //  the webhook INSERT and its duplicate-payment guard need every one.)
  await reconcileTable(db, 'webhook_events', WEBHOOK_EVENTS_COLUMNS);

  // --- Portal client context table (new — ensure it exists on old DBs) ---
  try {
    const createSql = `
      CREATE TABLE IF NOT EXISTS portal_client_context (
          client_mac  VARCHAR(32) PRIMARY KEY,
          client_ip   VARCHAR(45),
          ap_mac      VARCHAR(32) NOT NULL,
          ssid_name   VARCHAR(64) NOT NULL,
          radio_id    INTEGER NOT NULL DEFAULT 0,
          site        VARCHAR(64) NOT NULL DEFAULT 'Default',
          seen_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`;
    await db.exec(createSql);
    console.log('[migrate_fix] portal_client_context table ready.');
  } catch (err) {
    console.warn('[migrate_fix] portal_client_context creation skipped:', err.message);
  }
}

// Allow running standalone
if (require.main === module) {
  fixMissingColumns()
    .then(() => {
      console.log('[migrate_fix] Migration check complete.');
      return closeDb();
    })
    .catch(err => {
      console.error('[migrate_fix] Migration failed:', err.message);
      process.exit(1);
    });
}

module.exports = { fixMissingColumns, columnExists, getExistingColumns, reconcileTable };
