/**
 * services/payment-methods.js — Payment method availability state
 *
 * The captive portal can offer four methods: the GCash, Maya and QR Ph
 * e-wallets plus cash. Their receiver details and QR images come from the
 * environment (see routes/payment.js); whether each one is OFFERED at all is
 * stored in the `payment_methods` table so an admin can toggle it without a
 * redeploy. Cash has no QR/receiver data — it is claimed with a counter
 * voucher — but its tile is toggled and branded exactly like the e-wallets.
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
  { key: 'cash', name: 'Cash' },
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
 * `logoBase64` is the admin-uploaded data URI, or null when the method still
 * uses its bundled asset. It is passed through verbatim — the value was
 * validated on the way in (routes/admin.js) and is re-assigned to an <img>
 * `src` by the portal (assets/portal.js).
 *
 * @returns {Promise<Array<{key: string, name: string, enabled: boolean, logoBase64: string|null, updatedAt: string|null}>>}
 */
async function listPaymentMethodStates() {
  let rows = [];
  try {
    rows = await getDb().query(
      'SELECT method_key, display_name, is_active, logo_base64, updated_at FROM payment_methods'
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
      logoBase64: row && row.logo_base64 ? String(row.logo_base64) : null,
      updatedAt: (row && row.updated_at) || null,
    };
  });
}

/**
 * Update one method's availability and/or custom logo.
 *
 * Only the fields actually supplied are changed: a toggle request therefore
 * cannot wipe an uploaded logo, and a logo upload cannot flip a method that
 * the admin had switched off. The other field is carried over from the current
 * row (defaults: enabled, no logo) and the whole row is then UPSERTed, so a
 * database whose seed never ran still ends up with a real row.
 *
 * `logoBase64` must already have been validated by the caller
 * (routes/admin.js). Pass `null` to clear it and fall back to the bundled asset.
 *
 * @param {string} key method key ('gcash' | 'maya' | 'qrph' | 'cash')
 * @param {{enabled?: boolean, logoBase64?: string|null}} updates
 * @returns {Promise<{key: string, name: string, enabled: boolean, logoBase64: string|null, updatedAt: string|null}>}
 */
async function updatePaymentMethod(key, updates = {}) {
  const method = PAYMENT_METHODS.find((m) => m.key === key);
  if (!method) {
    const err = new Error('Unknown payment method: ' + String(key));
    err.code = 'UNKNOWN_PAYMENT_METHOD';
    throw err;
  }

  const hasEnabled = typeof updates.enabled === 'boolean';
  const hasLogo = Object.prototype.hasOwnProperty.call(updates, 'logoBase64');
  if (!hasEnabled && !hasLogo) {
    const err = new Error('Nothing to update: send enabled and/or logoBase64.');
    err.code = 'NOTHING_TO_UPDATE';
    throw err;
  }

  const db = getDb();
  const current = await db.getOne(
    'SELECT is_active, logo_base64 FROM payment_methods WHERE method_key = ?',
    [method.key]
  );

  const nextEnabled = hasEnabled
    ? updates.enabled
    : (current ? isActiveValue(current.is_active) : true);
  const nextLogo = hasLogo
    ? (updates.logoBase64 ? String(updates.logoBase64) : null)
    : ((current && current.logo_base64) ? String(current.logo_base64) : null);

  const now = new Date().toISOString();
  await db.run(
    `INSERT INTO payment_methods (method_key, display_name, is_active, logo_base64, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (method_key) DO UPDATE SET
       display_name = excluded.display_name,
       is_active    = excluded.is_active,
       logo_base64  = excluded.logo_base64,
       updated_at   = excluded.updated_at`,
    [method.key, method.name, toBindValue(nextEnabled), nextLogo, now]
  );

  if (hasEnabled) {
    console.log(
      '[payment-methods] ' + method.key + ' is now ' + (nextEnabled ? 'ENABLED' : 'DISABLED')
    );
  }
  if (hasLogo) {
    console.log(
      '[payment-methods] ' + method.key + ' logo ' +
      (nextLogo ? 'updated (' + nextLogo.length + ' chars)' : 'reset to the bundled asset')
    );
  }

  return {
    key: method.key,
    name: method.name,
    enabled: !!nextEnabled,
    logoBase64: nextLogo,
    updatedAt: now,
  };
}

module.exports = {
  PAYMENT_METHODS,
  METHOD_KEYS,
  isKnownMethod,
  isActiveValue,
  listPaymentMethodStates,
  updatePaymentMethod,
};
