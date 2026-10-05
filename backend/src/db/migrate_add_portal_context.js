/**
 * db/migrate_add_portal_context.js — standalone migration:
 * create the portal_client_context table
 *
 * Stores the controller context (AP MAC, SSID, radio ID) captured when a
 * client lands on the captive portal page, so a later payment webhook can
 * authorize that client on the controller without the client being online
 * at payment time.
 *
 * ASSUMPTION (documented, per plan): this deployment is single-controller,
 * single-site. The lookup key is client_mac alone; the `site` column is
 * recorded for future collision detection only (if a second site is ever
 * added, two different sites for one MAC become visible in the data and
 * the migration path stays additive).
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS — safe to run multiple times.
 *
 * Run with: node src/db/migrate_add_portal_context.js
 */

require('dotenv').config();
const { getDb, closeDb } = require('./client');

const CREATE_TABLE_SQL = `
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

async function run() {
  const db = getDb();
  const driver = db._driver;
  console.log(`[migrate_add_portal_context] starting (driver: ${driver})`);

  await db.exec(CREATE_TABLE_SQL);
  console.log('[migrate_add_portal_context] portal_client_context table ready');

  console.log('[migrate_add_portal_context] done');
  await closeDb();
}

if (require.main === module) {
  run().catch(err => {
    console.error('[migrate_add_portal_context] FAILED:', err.message);
    process.exit(1);
  });
}

module.exports = { run };
