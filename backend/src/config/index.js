/**
 * src/config/index.js — Centralized configuration constants
 *
 * Holds business-tuning values and Omada integration settings in one
 * place. Values documented as BUSINESS CONSTANTS are intentionally NOT
 * env-configurable: they are business decisions, not infrastructure
 * knobs (the operator tunes them by editing this file, same as the
 * payment rate below).
 */

// ── Payment rate ────────────────────────────────────────────────────────
// BUSINESS CONSTANT: minutes of Wi-Fi time granted per whole unit of
// currency received in a MacroDroid payment webhook.
// Example: amount 50 at 10 pesos/minute → 5 minutes granted.
// Read from MACRODROID_PESOS_PER_MINUTE so deployments can tune it via
// .env without a code change; falls back to the documented default.
const PESOS_PER_MINUTE = parseInt(process.env.MACRODROID_PESOS_PER_MINUTE || '10', 10);

// ── Digital plan catalog ────────────────────────────────────────────────
// The plans the captive portal advertises (config/config.js → plans, rendered
// by index.html). A digital claim arrives as the plan's price in Pesos, so this
// mapping is what lets the backend issue a voucher with the duration and tier
// the guest actually bought instead of a generic code. It lives here because
// config/config.js is a browser-only bundle (window.CONFIG) and cannot be
// required by Node.
//
// Keep this in sync with config/config.js when a plan is added or repriced.
const DIGITAL_PLAN_CATALOG = Object.freeze([
  { priceCentavos: 500,   durationMinutes: 60,    type: 'standard' }, // ₱5   — 1 hour
  { priceCentavos: 1000,  durationMinutes: 180,   type: 'standard' }, // ₱10  — 3 hours
  { priceCentavos: 2000,  durationMinutes: 720,   type: 'standard' }, // ₱20  — 12 hours
  { priceCentavos: 3000,  durationMinutes: 1440,  type: 'standard' }, // ₱30  — 24 hours
  { priceCentavos: 12000, durationMinutes: 10080, type: 'standard' }, // ₱120 — 7 days
  { priceCentavos: 35000, durationMinutes: 43200, type: 'standard' }, // ₱350 — 30 days
  { priceCentavos: 2500,  durationMinutes: 300,   type: 'premium'  }, // ₱25  — 5 hours
  { priceCentavos: 4500,  durationMinutes: 720,   type: 'premium'  }, // ₱45  — 12 hours
  { priceCentavos: 8000,  durationMinutes: 1440,  type: 'premium'  }, // ₱80  — 24 hours
]);

/**
 * Resolve the voucher a digital payment should generate.
 *
 * Catalog prices map to the exact plan the portal sold. Any other amount (a
 * legacy MacroDroid transfer, an operator's custom price) falls back to the
 * operator's pesos-per-minute rate so the claim is never refused just because
 * the price is not on the published menu.
 *
 * @param {number|string} amountPesos amount received, in Pesos
 * @returns {{durationMinutes: number, type: 'standard'|'premium'}}
 */
function resolveDigitalVoucherPlan(amountPesos) {
  const centavos = Math.round(Number(amountPesos) * 100);
  const plan = DIGITAL_PLAN_CATALOG.find((p) => p.priceCentavos === centavos);
  if (plan) return { durationMinutes: plan.durationMinutes, type: plan.type };

  const units = Math.floor(Number(amountPesos));
  const minutes = Number.isFinite(units) && units > 0
    ? Math.floor(units / PESOS_PER_MINUTE)
    : 0;
  return { durationMinutes: Math.max(1, minutes || 1), type: 'standard' };
}

// ── Environment ─────────────────────────────────────────────────────────
// Resolved once, at require time. NODE_ENV=production is the only mode that
// applies the fail-closed rules below.
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

/**
 * Read an operator secret from the environment.
 *
 * A missing, empty or whitespace-only value is treated as UNSET (a copy-paste
 * slip, or `ADMIN_API_KEY=` left blank in .env), never as a credential. The
 * value itself is NOT trimmed: if an operator really configured surrounding
 * whitespace, the string compared at login is the string they configured.
 *
 * @param {*} value
 * @returns {string} the secret, or '' when unset/blank
 */
function readSecret(value) {
  const raw = typeof value === 'string' ? value : '';
  return raw.trim() === '' ? '' : raw;
}

// ── Admin API key ───────────────────────────────────────────────────────
// ENV-CONFIGURABLE: the operator credential for internal endpoints a guest must
// never reach (POST /api/session/expire, which cuts a paying session offline).
// The development default is applied ONLY outside production: with
// NODE_ENV=production and no ADMIN_API_KEY the value is empty, so every guard
// that consumes it refuses instead of shipping a known key that any guest could
// replay. A production process in that state is stopped outright by
// assertAdminCredentials() below. Set ADMIN_API_KEY in the deployment env.
const ADMIN_API_KEY = readSecret(process.env.ADMIN_API_KEY)
  || (IS_PRODUCTION ? '' : 'dev_admin_key');

// ── Admin login password ────────────────────────────────────────────────
// ENV-CONFIGURABLE: the credential behind POST /api/admin/login (which mints a
// bearer token for the admin panel). An explicit ADMIN_PASSWORD wins; otherwise
// it falls back to ADMIN_API_KEY, the documented single-credential behaviour.
//
// This lives HERE, beside ADMIN_API_KEY, for one reason: every consumer must
// resolve one identical value at process start. It used to be read straight
// from process.env inside routes/admin.js, which is how an unset password
// became the empty string and matched an empty login password.
const ADMIN_PASSWORD = readSecret(process.env.ADMIN_PASSWORD) || ADMIN_API_KEY;

/**
 * assertAdminCredentials — refuse to run production with no operator credential.
 *
 * Fail-closed at the process level rather than at the login form: a production
 * process with neither ADMIN_API_KEY nor ADMIN_PASSWORD must not reach the
 * point where it serves /api/admin at all. Called at module load, so a
 * misconfigured start-up throws before Express listens.
 *
 * Development and test are unaffected (the dev default above applies).
 *
 * @returns {void}
 * @throws {Error} code ADMIN_CREDENTIALS_MISSING in production
 */
function assertAdminCredentials() {
  if (!IS_PRODUCTION) return;

  const missing = [];
  if (!ADMIN_API_KEY) missing.push('ADMIN_API_KEY');
  if (!ADMIN_PASSWORD) missing.push('ADMIN_PASSWORD');
  if (missing.length === 0) return;

  const err = new Error(
    '[config] Refusing to start in production: ' + missing.join(' and ') +
    ' resolved to an empty string. Set ADMIN_API_KEY (and optionally ' +
    'ADMIN_PASSWORD) in the environment or backend/.env. An empty operator ' +
    'credential is not a valid configuration — it must never be the value a ' +
    'login is compared against.'
  );
  err.code = 'ADMIN_CREDENTIALS_MISSING';
  throw err;
}

assertAdminCredentials();

// ── Portal context staleness ────────────────────────────────────────────
// BUSINESS CONSTANT (intentionally NOT env-configurable, consistent with
// the payment rate above): how long a portal_client_context row captured
// at portal landing stays valid for payment authorization. A row older
// than this is treated as MISSING by the payment webhook (fail-loud
// MISSING_PORTAL_CONTEXT path) — the client must re-open the captive
// portal page to refresh it. One hour balances "stale AP association"
// against "customer took a while between landing and paying".
const PORTAL_CONTEXT_MAX_AGE_MS = 60 * 60 * 1000; // 1 hour

// ── Premium hard expiry ────────────────────────────────────────────────
// BUSINESS CONSTANT (intentionally NOT env-configurable, same reasoning as
// the values above): how long a Premium pass may exist AT ALL — 7 days from
// purchase, counted from the moment its session was created. Premium guests
// get unlimited pause/resume — pausing protects their purchased minutes — but
// the pass is void once this window closes, however much frozen time it still
// holds, so a cheap pass cannot be kept alive indefinitely. A full week keeps
// the published "1 week validity to pause" promise (index.html).
const PREMIUM_HARD_EXPIRY_HOURS = 168;

// ── Pending payment verification ───────────────────────────────────────
// BUSINESS CONSTANT: how long a claim waiting on MacroDroid screen-scraping
// stays open. The customer is sitting on a spinner the whole time, so this is
// deliberately short: long enough for the macro to open the e-wallet, find the
// receipt and answer, short enough that a powered-off handset does not leave
// the claim "pending" for the rest of the day. An expired claim is reported as
// `expired` by GET /api/payment/claim/status and the customer can retry.
const PENDING_CLAIM_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ── MacroDroid screen-scrape verification ──────────────────────────────
// ENV-CONFIGURABLE: the LAN address of the Android handset running the
// MacroDroid "verify payment" macro. When a claim cannot be matched to a
// recorded webhook event, the backend asks that handset to open the e-wallet
// app and read the receipt:
//
//   GET http://<MACRODROID_IP>:<MACRODROID_WEBHOOK_PORT>/verify?ref=1234&mac=AA:BB:...
//
// MACRODROID_IP is empty by default, which DISABLES the channel: a claim with
// no recorded payment keeps answering the original 404 instead of leaving the
// customer waiting for a phone that was never configured.
// MACRODROID_WEBHOOK_PORT defaults to 8080; an unparsable or out-of-range
// value falls back to that default rather than turning the channel off.
const DEFAULT_MACRODROID_WEBHOOK_PORT = 8080;
const MACRODROID_IP = String(process.env.MACRODROID_IP || '').trim();
const MACRODROID_WEBHOOK_PORT = (() => {
  const raw = process.env.MACRODROID_WEBHOOK_PORT;
  if (raw === undefined || String(raw).trim() === '') return DEFAULT_MACRODROID_WEBHOOK_PORT;
  const parsed = parseInt(raw, 10);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535
    ? parsed
    : DEFAULT_MACRODROID_WEBHOOK_PORT;
})();

/**
 * Build the MacroDroid verification URL for a pending claim.
 *
 * The macro reads `ref` (the last 4 digits the customer typed) and `mac` (the
 * device to authorize) straight out of the query string — there is no request
 * body, matching the SMS webhook convention. Both values are encoded.
 *
 * @param {string} ref 4-digit reference suffix
 * @param {string} [mac] canonical client MAC, empty when unknown
 * @returns {string|null} null when MACRODROID_IP is not configured
 */
function macroDroidVerifyUrl(ref, mac) {
  if (!MACRODROID_IP) return null;
  const params = new URLSearchParams();
  params.append('ref', String(ref));
  params.append('mac', String(mac || ''));
  return 'http://' + MACRODROID_IP + ':' + MACRODROID_WEBHOOK_PORT + '/verify?' + params.toString();
}

// ── Omada extPortal auth time unit ──────────────────────────────────────
// ENV-CONFIGURABLE EXCEPTION — this is the ONE value kept in .env, and
// that is deliberate: the correct unit for the `time` field of
// POST /{omadacId}/api/v2/hotspot/extPortal/auth depends on controller
// FIRMWARE, which varies by deployment. Evidence:
//   - TP-Link FAQ 3231 prose claims microseconds,
//   - splash-networks/capport and tykeal/homeassistant-captive-portal
//     (two independent working implementations) both use milliseconds.
// Default 'ms' matches the cross-verified working implementations;
// 'us' or 's' are available if a specific controller proves to differ.
const OMADA_TIME_UNIT = (process.env.OMADA_TIME_UNIT || 'ms').toLowerCase();

module.exports = {
  IS_PRODUCTION,
  ADMIN_API_KEY,
  ADMIN_PASSWORD,
  assertAdminCredentials,
  PESOS_PER_MINUTE,
  DIGITAL_PLAN_CATALOG,
  resolveDigitalVoucherPlan,
  PORTAL_CONTEXT_MAX_AGE_MS,
  PREMIUM_HARD_EXPIRY_HOURS,
  OMADA_TIME_UNIT,
  PENDING_CLAIM_TTL_MS,
  MACRODROID_IP,
  MACRODROID_WEBHOOK_PORT,
  macroDroidVerifyUrl,
};