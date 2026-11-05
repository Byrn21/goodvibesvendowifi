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
  PESOS_PER_MINUTE,
  PORTAL_CONTEXT_MAX_AGE_MS,
  PREMIUM_HARD_EXPIRY_HOURS,
  OMADA_TIME_UNIT,
  PENDING_CLAIM_TTL_MS,
  MACRODROID_IP,
  MACRODROID_WEBHOOK_PORT,
  macroDroidVerifyUrl,
};