'use strict';

/**
 * utils/qos.js — single source of truth for amount → bandwidth-tier resolution.
 *
 * Shared by the two routes that authorize a paying device directly:
 *   - POST /api/webhooks/instapay (routes/webhook.js)
 *   - POST /api/payment/claim     (routes/payment.js)
 *
 * The bandwidth cap depends on the payment amount:
 *   amount ∈ PREMIUM_AMOUNTS_PESOS (default 25, 45, 80) → PREMIUM_DOWN_MBPS /
 *                                                         PREMIUM_UP_KBPS
 *   every other amount                                  → undefined, which makes
 *                                                         setClientRateLimit()
 *                                                         apply the operator's
 *                                                         VOUCHER_DEFAULT_*
 *                                                         defaults
 *
 * Units mirror services/omada-northbound.js: down is Mbps (downUnit 2) and up
 * is Kbps (upUnit 1).
 *
 * The plan tier itself comes from vouchers.type ('standard' | 'premium'). It is
 * never trusted verbatim: normalizeVoucherType() trims/lowercases it first, so a
 * row holding 'Premium'/'PREMIUM'/' premium ' still resolves to the premium
 * tier instead of silently falling back to the standard defaults.
 */

// Premium plan prices (Pesos) used when PREMIUM_AMOUNTS_PESOS is unset.
// Mirrors the portal's premium tier (5h = P25, 12h = P45, 24h = P80).
const DEFAULT_PREMIUM_AMOUNTS_PESOS = [25, 45, 80];

// Upper bound for a per-voucher cap: 1 Gbps expressed in Kbps. Omada's
// customRateLimit is 1–1024 PER UNIT, so 1 024 000 Kbps (= 1024 Mbps) is the
// real ceiling once the value is converted (see toRateLimitUnit).
const MAX_BANDWIDTH_KBPS = 1024000;

/**
 * normalizeBandwidthKbps — validate a per-voucher bandwidth value.
 *
 * Stored values are always Kbps (the unit the Omada payload ultimately wants),
 * so "5 Mbps" is 5000. Rejects non-integers, zero, negatives and anything above
 * MAX_BANDWIDTH_KBPS, which keeps a bad admin/import value from reaching the
 * controller.
 *
 * @param {*} value
 * @returns {number|null} the integer Kbps value, or null when invalid
 */
function normalizeBandwidthKbps(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > MAX_BANDWIDTH_KBPS) return null;
  return n;
}

/**
 * toRateLimitUnit — express a Kbps cap as an Omada customRateLimit {unit, limit}.
 *
 * Omada accepts unit 1 = Kbps and unit 2 = Mbps, each with a 1–1024 limit, so a
 * cap that fits in Kbps travels as-is and a larger one (e.g. 5000 Kbps = 5 Mbps)
 * is converted to Mbps instead of being rejected. Rounding is used because the
 * controller only takes whole Mbps above 1 Mbps.
 *
 * @param {number} kbps validated integer Kbps
 * @returns {{unit: 1|2, limit: number}}
 */
function toRateLimitUnit(kbps) {
  if (kbps <= 1024) return { unit: 1, limit: kbps }; // Kbps
  return { unit: 2, limit: Math.round(kbps / 1000) };  // Mbps
}

/**
 * normalizeVoucherType — canonical plan tier for a vouchers.type value.
 *
 * The tier decides the bandwidth cap (and whether Pause/Resume is allowed), so
 * it must not depend on how the row was typed. Rows entered by hand in Supabase
 * or imported from another system can hold 'premium', 'Premium', 'PREMIUM' or
 * ' premium '; trimming/lowercasing here makes every one of them the same tier.
 * An empty/absent value is 'standard' (the column default).
 *
 * @param {*} value
 * @returns {string} the lowercased tier, or 'standard'
 */
function normalizeVoucherType(value) {
  if (value === undefined || value === null) return 'standard';
  const tier = String(value).trim().toLowerCase();
  return tier || 'standard';
}

/**
 * isPremiumVoucherType — true when a vouchers.type value is the premium tier.
 * Case- and whitespace-insensitive; the single check used by the QoS and
 * pause/resume rules so they can never disagree about a plan.
 *
 * @param {*} value
 * @returns {boolean}
 */
function isPremiumVoucherType(value) {
  return normalizeVoucherType(value) === 'premium';
}

/**
 * resolvePremiumDown — premium DOWNLOAD cap as an Omada {unit, limit}.
 *
 * PREMIUM_DOWN_MBPS is the documented variable (1–1024 Mbps). Deployments that
 * configure the premium cap in Kbps instead — PREMIUM_DOWN_KBPS, mirroring
 * PREMIUM_UP_KBPS/VOUCHER_DEFAULT_UP_KBPS — are honoured too, converted to the
 * unit Omada accepts. Without this alias a PREMIUM_DOWN_KBPS-only deployment
 * silently lost the premium tier and capped premium guests at the standard
 * VOUCHER_DEFAULT_* speed.
 *
 * @returns {{unit: 1|2, limit: number}|undefined}
 */
function resolvePremiumDown() {
  const downMbps = parseInt(process.env.PREMIUM_DOWN_MBPS, 10);
  if (Number.isInteger(downMbps) && downMbps >= 1 && downMbps <= 1024) {
    return { unit: 2, limit: downMbps }; // Mbps
  }

  const downKbps = normalizeBandwidthKbps(process.env.PREMIUM_DOWN_KBPS);
  if (downKbps) return toRateLimitUnit(downKbps);

  return undefined;
}

/**
 * resolvePremiumRateLimit — the PREMIUM_* operator caps as a customRateLimit.
 *
 * Download comes from PREMIUM_DOWN_MBPS (or its PREMIUM_DOWN_KBPS alias), upload
 * from PREMIUM_UP_KBPS. Returns undefined when either surviving value is unset
 * or out of range, which makes setClientRateLimit() fall back to the
 * VOUCHER_DEFAULT_* caps so a premium guest is still capped rather than left
 * unlimited — callers log that fallback (see applySessionRateLimit) so a
 * misnamed variable does not masquerade as a standard voucher.
 *
 * @returns {Object|undefined}
 */
function resolvePremiumRateLimit() {
  const down = resolvePremiumDown();
  const upKbps = parseInt(process.env.PREMIUM_UP_KBPS, 10);
  if (!down) return undefined;
  if (!Number.isInteger(upKbps) || upKbps < 1 || upKbps > 1024) return undefined;

  return {
    upEnable: true,
    upUnit: 1,      // 1 = Kbps
    upLimit: upKbps,
    downEnable: true,
    downUnit: down.unit,
    downLimit: down.limit,
  };
}

/**
 * resolveVoucherRateLimit — bandwidth cap for a REDEEMED voucher.
 *
 * This is the voucher-login counterpart of resolveCustomRateLimit() (which is
 * amount-based, for the direct payment flows). Resolution order:
 *
 *   1. Explicit per-voucher caps (vouchers.down_kbps / up_kbps) when present
 *      and valid — these are the caps the operator set on that code.
 *   2. Premium tier → PREMIUM_DOWN_MBPS / PREMIUM_UP_KBPS.
 *   3. Anything else → undefined, so setClientRateLimit() applies the
 *      operator's VOUCHER_DEFAULT_DOWN_MBPS / VOUCHER_DEFAULT_UP_KBPS.
 *
 * Caps are all-or-nothing: when only one of the two per-voucher values is
 * usable the pair is ignored and the tier rules apply, so a half-configured row
 * can never leave one direction unlimited.
 *
 * @param {Object} [voucher]
 * @param {number|string} [voucher.downKbps] download cap in Kbps
 * @param {number|string} [voucher.upKbps]   upload cap in Kbps
 * @param {string} [voucher.voucherType]     'standard' | 'premium'
 * @returns {Object|undefined} customRateLimit payload, or undefined for defaults
 */
function resolveVoucherRateLimit(voucher) {
  const downKbps = normalizeBandwidthKbps(voucher && voucher.downKbps);
  const upKbps = normalizeBandwidthKbps(voucher && voucher.upKbps);

  if (downKbps && upKbps) {
    const down = toRateLimitUnit(downKbps);
    const up = toRateLimitUnit(upKbps);
    return {
      upEnable: true,
      upUnit: up.unit,
      upLimit: up.limit,
      downEnable: true,
      downUnit: down.unit,
      downLimit: down.limit,
    };
  }

  if (isPremiumVoucherType(voucher && voucher.voucherType)) {
    return resolvePremiumRateLimit();
  }

  return undefined;
}

/**
 * Resolve the set of payment amounts (Pesos) treated as the premium tier.
 *
 * PREMIUM_AMOUNTS_PESOS is a comma-separated list, e.g. "25,45,80". Each
 * entry is parsed with parseInt(..., 10); non-integer or non-positive entries
 * are dropped so a typo cannot silently widen the tier. When the variable is
 * unset (or yields no valid entries) the DEFAULT_PREMIUM_AMOUNTS_PESOS list is
 * used instead.
 *
 * @returns {number[]} premium amounts in Pesos
 */
function resolvePremiumAmountsPesos() {
  const raw = process.env.PREMIUM_AMOUNTS_PESOS;
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return DEFAULT_PREMIUM_AMOUNTS_PESOS.slice();
  }

  const parsed = String(raw)
    .split(',')
    .map((part) => parseInt(part.trim(), 10))
    .filter((n) => Number.isInteger(n) && n > 0);

  return parsed.length ? parsed : DEFAULT_PREMIUM_AMOUNTS_PESOS.slice();
}

/**
 * Resolve the mode-0 custom QoS limits for a payment amount.
 *
 * A payment whose amount is one of the PREMIUM_AMOUNTS_PESOS values
 * (default 25, 45, 80) is a premium purchase and gets PREMIUM_DOWN_MBPS /
 * PREMIUM_UP_KBPS. Every other amount returns undefined, which makes
 * setClientRateLimit() apply the operator's VOUCHER_DEFAULT_DOWN_MBPS /
 * VOUCHER_DEFAULT_UP_KBPS defaults.
 *
 * The premium values are parsed with parseInt(..., 10) — the controller rejects
 * a STRING in upLimit/downLimit — and range-checked against the 1–1024 ceiling
 * the OpenAPI documents. When either premium value is unset or out of range, the
 * premium path falls back to the VOUCHER_DEFAULT_* defaults too, so a premium
 * guest is still capped rather than left unlimited.
 *
 * @param {number|string} amount payment amount in Pesos
 * @returns {Object|undefined} a customRateLimit payload, or undefined to use
 *                             the service defaults
 */
function resolveCustomRateLimit(amount) {
  const premiumAmounts = resolvePremiumAmountsPesos();
  if (!premiumAmounts.includes(Number(amount))) {
    return undefined;
  }

  return resolvePremiumRateLimit();
}

module.exports = {
  DEFAULT_PREMIUM_AMOUNTS_PESOS,
  MAX_BANDWIDTH_KBPS,
  normalizeVoucherType,
  isPremiumVoucherType,
  normalizeBandwidthKbps,
  toRateLimitUnit,
  resolvePremiumAmountsPesos,
  resolvePremiumRateLimit,
  resolveCustomRateLimit,
  resolveVoucherRateLimit,
};
