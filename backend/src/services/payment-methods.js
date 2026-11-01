/**
 * services/payment-methods.js — Payment method availability state
 *
 * The captive portal can offer three e-wallet methods (GCash, Maya, QR Ph).
 * Their receiver details and QR images come from the environment (see
 * routes/payment.js); whether each one is OFFERED at all is stored in the
 * `payment_methods` table so an admin can toggle it without a redeploy.
 *
 * This module is the single source of truth for both sides:
 *   - routes/payment.js  → GET /api/payment/methods   (public, guest portal)
 *   - routes/admin.js    → GET/PUT /api/admin/payment-methods (auth)
 *
 * Both callers therefore agree on the method keys, the display names, the
 * defaults, and the boolean normalization for SQLite (1/0) vs PostgreSQL
 * (true/false).
 */

const { getDb } = require('../db/client');

// Kept in the same order the portal renders the tiles.
const PAYMENT_METHODS = [
  { key: 'gcash', name: 'GCash' },
  { key: 'maya', name: 'Maya' },
  { key: 'qrph', name: 'QR Ph' },
];

const METHOD_KEYS = PAYMENT_METHODS.map((m) => m.key);

/**
 * Is `key` one of the methods this deployment supports?
 * @param {*} key
 * @returns {boolean}
 */
function isKnownMethod(key) {
  return typeof key === 'string' && METHOD_KEYS.includes(key);
}

/**
 * Normalize a stored is_active value.
 *
 * SQLite has no boolean type and returns 1/0; PostgreSQL returns true/false.
 * A NULL or unreadable value is treated as ENABLED, matching the "no row means
 * enabled" default — a payment option must never disappear because of a
 * misread value.
 *
 * @param {*} value
 * @returns {boolean}
 */
function isActiveValue(value) {
  if (value === null || value === undefined) return true;
  if (typeof value === 'boolean') return value;
  return Number(value) === 1;
}

/**
 * Bind value for the is_active column.
 *
 * better-sqlite3 refuses JS booleans as bind parameters, while PostgreSQL
 * refuses an integer for a BOOLEAN column. The driver decides the form.
 *
 * @param {boolean} enabled
 * @returns {boolean|number}
 */
function toBindValue(enabled) {
  const db = getDb();
  return db._driver === 'pg' ? !!enabled : (enabled ? 1 : 0);
}

/**
 * Read the availability of every supported method.
 *
 * Always returns one entry per method in PAYMENT_METHODS order. A method with
 * no row (or a database that predates the `payment_methods` table) is ENABLED:
 * this route is what the captive portal needs before a guest can pay, so a
 * missing table must not take the payment page down — it is logged and every
 * method stays on the menu.
 *
 * @returns {Promise<Array<{key: string, name: string, enabled: boolean, updatedAt: string|null}>>}
 */
async function listPaymentMethodStates() {
  let rows = [];
  try {
    rows = await getDb().query(
      'SELECT method_key, display_name, is_active, updated_at FROM payment_methods'
    );
  } catch (err) {
    // Most likely: `npm run db:migrate` has not been run since this table was
    // added. Degrade to "everything enabled" instead of breaking the portal.
    console.error(
      '[payment-methods] could not read payment_methods (' +
      ((err && err.message) || String(err)) +
      ') — defaulting every method to enabled'
    );
    rows = [];
  }

  const byKey = new Map();
  rows.forEach((row) => {
    if (row && row.method_key) byKey.set(row.method_key, row);
  });

  return PAYMENT_METHODS.map((method) => {
    const row = byKey.get(method.key);
    return {
      key: method.key,
      name: method.name,
      enabled: row ? isActiveValue(row.is_active) : true,
      updatedAt: (row && row.updated_at) || null,
    };
  });
}

/**
 * Convenience view of listPaymentMethodStates(): { gcash: true, maya: false, … }.
 * @returns {Promise<Record<string, boolean>>}
 */
async function getPaymentMethodAvailability() {
  const states = await listPaymentMethodStates();
  const availability = {};
  states.forEach((state) => { availability[state.key] = state.enabled; });
  return availability;
}

/**
 * Enable or disable one method.
 *
 * UPSERT so a database whose seed never ran (or a future method added to this
 * file but not to schema.sql's seed) still ends up with a real row. The caller
 * is responsible for validating that `key` is known.
 *
 * @param {string} key method key ('gcash' | 'maya' | 'qrph')
 * @param {boolean} enabled
 * @returns {Promise<{key: string, name: string, enabled: boolean, updatedAt: string|null}>}
 */
async function setPaymentMethodActive(key, enabled) {
  const method = PAYMENT_METHODS.find((m) => m.key === key);
  if (!method) {
    const err = new Error('Unknown payment method: ' + String(key));
    err.code = 'UNKNOWN_PAYMENT_METHOD';
    throw err;
  }

  const now = new Date().toISOString();
  await getDb().run(
    `INSERT INTO payment_methods (method_key, display_name, is_active, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT (method_key) DO UPDATE SET
       display_name = excluded.display_name,
       is_active    = excluded.is_active,
       updated_at   = excluded.updated_at`,
    [method.key, method.name, toBindValue(enabled), now]
  );

  console.log(
    '[payment-methods] ' + method.key + ' is now ' + (enabled ? 'ENABLED' : 'DISABLED')
  );

  return { key: method.key, name: method.name, enabled: !!enabled, updatedAt: now };
}

module.exports = {
  PAYMENT_METHODS,
  METHOD_KEYS,
  isKnownMethod,
  isActiveValue,
  listPaymentMethodStates,
  getPaymentMethodAvailability,
  setPaymentMethodActive,
};
