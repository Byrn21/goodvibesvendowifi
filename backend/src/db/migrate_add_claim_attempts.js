/**
 * db/migrate_add_claim_attempts.js — standalone migration:
 * create the claim_attempts table
 *
 * POST /api/payment/claim budgets failed attempts per reference suffix so a
 * 4-digit guess cannot be brute-forced from rotating IPs. The budget lives in
 * this table; a database created before the table existed must get it before
 * the claim route can count anything.
 *
 * Idempotent: `CREATE TABLE IF NOT EXISTS` is valid on SQLite and PostgreSQL,
 * so a fresh database (where schema.sql already created the table) and a
 * booted production database are both safe.
 *
 * Run with: node src/db/migrate_add_claim_attempts.js
 * (requires DATABASE_URL to be set, or defaults to local SQLite)
 *
 * Also invoked automatically on boot from src/server.js. run() therefore does
 * NOT close the shared connection — only the CLI entry point does.
 */

require('dotenv').config();
const { getDb, closeDb } = require('./client');

/**
 * Create the claim_attempts table when it is missing.
 *
 * @param {Object} db
 * @returns {Promise<boolean>} true when this run created the table
 */
async function createClaimAttemptsTable(db) {
  const isPg = db._driver === 'pg';
  const existing = isPg
    ? await db.query(
        `SELECT 1 FROM information_schema.tables
          WHERE table_name = 'claim_attempts' AND table_schema = current_schema()`
      )
    : await db.query(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'claim_attempts'`
      );

  if (existing.length > 0) {
    console.log('[migrate_add_claim_attempts] claim_attempts already exists — skipping');
    return false;
  }

  console.log('[migrate_add_claim_attempts] creating claim_attempts ...');
  await db.exec(`
    CREATE TABLE IF NOT EXISTS claim_attempts (
      ref_suffix        VARCHAR(8) NOT NULL PRIMARY KEY,
      failed_count      INTEGER NOT NULL DEFAULT 0,
      window_started_at TIMESTAMP,
      last_attempt_at   TIMESTAMP,
      last_client_ip    VARCHAR(45)
    )
  `);
  return true;
}

async function run() {
  const db = getDb();
  console.log(`[migrate_add_claim_attempts] starting (driver: ${db._driver})`);
  const created = await createClaimAttemptsTable(db);
  console.log(`[migrate_add_claim_attempts] done${created ? ' (table created)' : ' (no changes)'}`);
}

if (require.main === module) {
  run()
    .then(() => closeDb())
    .catch(err => {
      console.error('[migrate_add_claim_attempts] FAILED:', err.message);
      process.exit(1);
    });
}

module.exports = { run };
