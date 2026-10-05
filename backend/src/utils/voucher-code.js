'use strict';

/**
 * utils/voucher-code.js — single source of truth for voucher code format.
 *
 * RULE: Every voucher code is exactly 6 numeric digits (e.g. 123456).
 * The same rule must be enforced on the frontend (config/config.js and
 * assets/portal.js) and on the backend (routes/auth.js). If the rule ever
 * changes, update all three places together.
 */

// Exactly 6 numeric digits
const VOUCHER_CODE_PATTERN = /^\d{6}$/;
const VOUCHER_CODE_MESSAGE = 'Voucher code must be exactly 6 digits.';

/**
 * Normalize a human-entered voucher code: trim whitespace and strip
 * every non-digit character (spaces, dashes, letters, etc.).
 * "123 456" -> "123456", "123-456" -> "123456", " 123456 " -> "123456"
 *
 * @param {*} value
 * @returns {string}
 */
function normalizeVoucherCode(value) {
  return String(value == null ? '' : value)
    .trim()
    .replace(/\D/g, '');
}

/**
 * Validate a voucher code against the shared 6-digit rule.
 * Expects an already-normalized value (see normalizeVoucherCode).
 *
 * @param {string} normalizedCode
 * @returns {{ok: true, value: string} | {ok: false, message: string}}
 */
function validateVoucherCodeFormat(normalizedCode) {
  if (typeof normalizedCode === 'string' && VOUCHER_CODE_PATTERN.test(normalizedCode)) {
    return { ok: true, value: normalizedCode };
  }
  return { ok: false, message: VOUCHER_CODE_MESSAGE };
}

module.exports = {
  VOUCHER_CODE_PATTERN,
  VOUCHER_CODE_MESSAGE,
  normalizeVoucherCode,
  validateVoucherCodeFormat,
};
