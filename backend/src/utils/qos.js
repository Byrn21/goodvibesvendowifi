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

module.exports = {
  DEFAULT_PREMIUM_AMOUNTS_PESOS,
  resolvePremiumAmountsPesos,
  resolveCustomRateLimit,
};
