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
  OMADA_TIME_UNIT,
};