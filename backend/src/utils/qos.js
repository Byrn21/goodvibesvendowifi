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
 * Units match the customRateLimit the controller's web API accepts (see
 * services/omada.js → setClientRateLimit): unit 1 = Kbps, unit 2 = Mbps, and
 * the unit is chosen per value by toRateLimitUnit() — see KBPS_PER_MBPS below.
 *
 * The plan tier itself comes from vouchers.type ('standard' | 'premium'). It is
 * never trusted verbatim: normalizeVoucherType() trims/lowercases it first, so a
 * row holding 'Premium'/'PREMIUM'/' premium ' still resolves to the premium
 * tier instead of silently falling back to the standard defaults.
 */

// Premium plan prices (Pesos) used when PREMIUM_AMOUNTS_PESOS is unset.
// Mirrors the portal's premium tier (5h = P25, 12h = P45, 24h = P80).
const DEFAULT_PREMIUM_AMOUNTS_PESOS = [25, 45, 80];

// Premium caps used when the PREMIUM_* variables are unset or out of range.
// These are the values documented in backend/.env.example, so a deployment
// whose .env predates premium QoS no longer silently caps premium guests at
// VOUCHER_DEFAULT_* (standard) speed: a premium plan always resolves to
// integers, and the fallback is logged once per process.
const DEFAULT_PREMIUM_DOWN_MBPS = 50;
const DEFAULT_PREMIUM_UP_KBPS = 1024;

// Ceiling for PREMIUM_UP_KBPS, in Kbps — the same 100000 the standard tier's
// VOUCHER_DEFAULT_UP_KBPS uses (services/omada.js → MAX_DEFAULT_UP_KBPS). It is
// deliberately NOT the 1–1024 Omada applies PER UNIT: the configured value is
// Kbps, and toRateLimitUnit() sends 1024 Kbps and above as whole Mbps, so
// PREMIUM_UP_KBPS=5120 is a valid 5 Mbps upload cap. The old 1–1024 check
// treated it as invalid and fell back to the 1 Mbps default, silently
// throttling a legitimate premium upload by 5x.
const MAX_PREMIUM_UP_KBPS = 100000;

// One warning per missing variable, not one per guest.
const warnedPremiumDefaults = new Set();

// One warning per clamped value, not one per premium guest.
const warnedPremiumClamps = new Set();

/**
 * Warn once that a built-in premium default was used for `name`.
 *
 * @param {string} name environment variable that was missing/invalid
 * @param {*} used the value that was substituted
 */
function warnPremiumDefault(name, used) {
  if (warnedPremiumDefaults.has(name)) return;
  warnedPremiumDefaults.add(name);
  console.warn(
    '[qos] ' + name + ' is unset or out of range — using the built-in premium default ' +
    String(used) + '. Set it in backend/.env to control the premium tier.'
  );
}

// One Mbps is 1024 Kbps as far as the controller is concerned, and this is the
// ONLY conversion factor in the QoS code. Using 1000 in one direction and 1024
// in the other made a snapshot round-trip drift (50 Mbps → 50000 Kbps →
// 49 Mbps), which a re-auth/resume then replayed onto the guest.
const KBPS_PER_MBPS = 1024;

// Upper bound for a per-voucher cap: 1 Gbps expressed in Kbps. Omada's
// customRateLimit is 1–1024 PER UNIT, so 1 048 576 Kbps (= 1024 Mbps) is the
// real ceiling once the value is converted (see toRateLimitUnit).
const MAX_BANDWIDTH_KBPS = KBPS_PER_MBPS * 1024;

// A persisted cap below this is not a usable guest speed (it is slower than a
// dial-up line) and is the fingerprint of a Mbps value that was stored as if it
// were Kbps. Such rows are healed on read — see repairLegacyBandwidthKbps.
const LEGACY_KBPS_FLOOR = 64;

// One warning per value, not one per guest.
const warnedLegacyRepairs = new Set();
const warnedRoundedCaps = new Set();

/**
 * normalizeBandwidthKbps — validate a per-voucher bandwidth value.
 *
 * Stored values are always Kbps (the unit the Omada payload ultimately wants),
 * so "5 Mbps" is 5120 (5 × 1024). Rejects non-integers, zero, negatives and anything above
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
 * Omada accepts unit 1 = Kbps and unit 2 = Mbps, each with a 1–1024 limit, so
 * 1–1023 Kbps travels as-is and anything from 1024 Kbps up (e.g. 5000 Kbps =
 * 5 Mbps) is converted to Mbps instead of being rejected. Rounding up is used
 * because the controller only takes whole Mbps above 1 Mbps.
 *
 * @param {number} kbps validated integer Kbps
 * @returns {{unit: 1|2, limit: number}}
 */
function toRateLimitUnit(kbps) {
  if (!Number.isInteger(kbps) || kbps < 1) {
    throw new RangeError('toRateLimitUnit expects a positive integer Kbps value');
  }

  // Fits in the 1–1023 Kbps range Omada accepts on unit 1: send it verbatim.
  // 1024 itself is a clean multiple of the factor below and travels as Mbps.
  if (kbps < KBPS_PER_MBPS) return { unit: 1, limit: kbps };

  const mbps = kbps / KBPS_PER_MBPS;
  if (Number.isInteger(mbps)) return { unit: 2, limit: mbps };

  // Above 1024 Kbps unit 1 cannot express the value, so the controller only
  // ever sees whole Mbps: rounding is unavoidable. Round UP, never down, so a
  // cap is never applied below what the operator configured (30000 Kbps, i.e.
  // a 30 Mbps plan written in Kbps, becomes 30 Mbps rather than 29). Say so
  // once, because the applied cap then differs from the stored one (5000 Kbps
  // → 5 Mbps = 5120 Kbps).
  const rounded = Math.max(1, Math.ceil(mbps));
  const key = kbps + '->' + rounded;
  if (!warnedRoundedCaps.has(key)) {
    warnedRoundedCaps.add(key);
    console.warn(
      '[qos] ' + kbps + ' Kbps is above 1024 and not a whole number of Mbps — ' +
      'the controller will apply ' + rounded + ' Mbps (' + (rounded * KBPS_PER_MBPS) + ' Kbps).'
    );
  }
  return { unit: 2, limit: rounded };
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
function repairLegacyBandwidthKbps(value) {
  const kbps = normalizeBandwidthKbps(value);
  if (kbps === null) return null;
  if (kbps >= LEGACY_KBPS_FLOOR) return kbps;

  // Below the floor this was a Mbps value stored in a Kbps column (the
  // pre-standardisation bug). Heal it on read: active guests whose session row
  // says "1" must be re-authorized at 1 Mbps, not cut off at 1 Kbps.
  const repaired = kbps * KBPS_PER_MBPS;
  if (repaired > MAX_BANDWIDTH_KBPS) return kbps;

  const key = String(kbps);
  if (!warnedLegacyRepairs.has(key)) {
    warnedLegacyRepairs.add(key);
    console.warn(
      '[qos] persisted bandwidth cap ' + kbps + ' is below ' + LEGACY_KBPS_FLOOR +
      ' Kbps — reading it as ' + kbps + ' Mbps (' + repaired + ' Kbps).' +
      ' Re-save the voucher/session to store the Kbps value explicitly.'
    );
  }
  return repaired;
}

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

  // Neither variable is usable: keep the premium tier premium instead of
  // letting the guest fall through to the standard VOUCHER_DEFAULT_* cap.
  warnPremiumDefault('PREMIUM_DOWN_MBPS', DEFAULT_PREMIUM_DOWN_MBPS);
  return { unit: 2, limit: DEFAULT_PREMIUM_DOWN_MBPS }; // Mbps
}

/**
 * resolvePremiumRateLimit — the PREMIUM_* operator caps as a customRateLimit.
 *
 * Download comes from PREMIUM_DOWN_MBPS (or its PREMIUM_DOWN_KBPS alias), upload
 * from PREMIUM_UP_KBPS (1–MAX_PREMIUM_UP_KBPS Kbps). A dimension that is unset
 * or not a number falls back to the built-in DEFAULT_PREMIUM_* value (the
 * numbers .env.example documents) with a one-time warning, so this NEVER
 * returns undefined: a premium plan always resolves to integers and cannot
 * silently drop to the standard VOUCHER_DEFAULT_* speed. An upload value above
 * the ceiling is clamped to the ceiling (also warned once) instead of being
 * thrown back to the 1 Mbps default.
 *
 * Every limit returned here is a plain integer in the 1–1024 range Omada
 * accepts per unit — never a string such as 'default'.
 *
 * @returns {Object|undefined}
 */
function resolvePremiumRateLimit() {
  const down = resolvePremiumDown();

  let upKbps = parseInt(process.env.PREMIUM_UP_KBPS, 10);
  if (!Number.isInteger(upKbps) || upKbps < 1) {
    warnPremiumDefault('PREMIUM_UP_KBPS', DEFAULT_PREMIUM_UP_KBPS);
    upKbps = DEFAULT_PREMIUM_UP_KBPS;
  } else if (upKbps > MAX_PREMIUM_UP_KBPS) {
    // Above the ceiling: clamp to the ceiling, never down to the default. A
    // large-but-configured value must not be silently reduced to 1 Mbps.
    const key = String(upKbps);
    if (!warnedPremiumClamps.has(key)) {
      warnedPremiumClamps.add(key);
      console.warn(
        '[qos] PREMIUM_UP_KBPS=' + upKbps + ' is above the ' + MAX_PREMIUM_UP_KBPS +
        ' Kbps ceiling — clamping to ' + MAX_PREMIUM_UP_KBPS + ' Kbps.'
      );
    }
    upKbps = MAX_PREMIUM_UP_KBPS;
  }

  // Upload goes through the same unit rule as everything else: 512 Kbps stays
  // unit 1, while the 1024 Kbps default becomes unit 2 / limit 1 (1 Mbps).
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
  // These values come from vouchers.down_kbps / sessions.down_kbps, so a row
  // written before the unit fix still holds Mbps integers. Reading it through
  // repairLegacyBandwidthKbps() restores the intended speed without an
  // operator having to edit the database.
  const downKbps = repairLegacyBandwidthKbps(voucher && voucher.downKbps);
  const upKbps = repairLegacyBandwidthKbps(voucher && voucher.upKbps);

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

/**
 * rateLimitToKbps — express a customRateLimit payload as integer Kbps.
 *
 * Sessions store their bandwidth snapshot in Kbps (the unit vouchers.down_kbps
 * / up_kbps use), while a resolved payload may carry either Kbps (unit 1) or
 * Mbps (unit 2). Snapshotting the RESOLVED integers is what makes a re-auth or
 * a resume replay exactly the cap the guest was granted, instead of resolving
 * the tier again from environment variables that may have changed since.
 *
 * @param {{upUnit?:number, upLimit?:number, downUnit?:number, downLimit?:number}|undefined} rateLimit
 * @returns {{downKbps:number|null, upKbps:number|null}}
 */
function rateLimitToKbps(rateLimit) {
  if (!rateLimit) return { downKbps: null, upKbps: null };

  const toKbps = (unit, limit) => {
    const value = Number(limit);
    if (!Number.isInteger(value) || value < 1) return null;
    return Number(unit) === 2 ? value * KBPS_PER_MBPS : value;
  };

  return {
    downKbps: toKbps(rateLimit.downUnit, rateLimit.downLimit),
    upKbps: toKbps(rateLimit.upUnit, rateLimit.upLimit),
  };
}

module.exports = {
  DEFAULT_PREMIUM_AMOUNTS_PESOS,
  DEFAULT_PREMIUM_DOWN_MBPS,
  DEFAULT_PREMIUM_UP_KBPS,
  MAX_PREMIUM_UP_KBPS,
  KBPS_PER_MBPS,
  LEGACY_KBPS_FLOOR,
  rateLimitToKbps,
  repairLegacyBandwidthKbps,
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
