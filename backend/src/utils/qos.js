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
 * resolvePremiumRateLimit — the PREMIUM_* operator caps as a customRateLimit.
 *
 * Returns undefined when either premium value is unset or out of range, which
 * makes setClientRateLimit() fall back to the VOUCHER_DEFAULT_* caps so a
 * premium guest is still capped rather than left unlimited.
 *
 * @returns {Object|undefined}
 */
function resolvePremiumRateLimit() {
  const downMbps = parseInt(process.env.PREMIUM_DOWN_MBPS, 10);
  const upKbps = parseInt(process.env.PREMIUM_UP_KBPS, 10);
  if (!Number.isInteger(downMbps) || downMbps < 1 || downMbps > 1024) return undefined;
  if (!Number.isInteger(upKbps) || upKbps < 1 || upKbps > 1024) return undefined;

  return {
    upEnable: true,
    upUnit: 1,      // 1 = Kbps
    upLimit: upKbps,
    downEnable: true,
    downUnit: 2,    // 2 = Mbps
    downLimit: downMbps,
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

  if (voucher && voucher.voucherType === 'premium') {
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
  normalizeBandwidthKbps,
  toRateLimitUnit,
  resolvePremiumAmountsPesos,
  resolvePremiumRateLimit,
  resolveCustomRateLimit,
  resolveVoucherRateLimit,
};
