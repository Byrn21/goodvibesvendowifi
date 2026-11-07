'use strict';

/**
 * utils/mobile.js — single source of truth for customer/payer mobile numbers.
 *
 * The number is a CREDENTIAL now, not just an SMS destination: the webhook
 * records the number the payment came from, and POST /api/payment/claim only
 * releases that payment to a caller who supplies the same number. Both sides
 * must therefore normalise identically, or a legitimate customer is locked out
 * of a payment they own.
 *
 * Canonical form is the one the portal collects and the SMS flow expects:
 * 11 digits starting with 09 (e.g. 09171234567).
 */

/** Canonical PH mobile: exactly 11 digits starting with 09. */
const MOBILE_RE = /^09\d{9}$/;

/**
 * Normalize a mobile number coming from an external system (the MacroDroid
 * receipt reader) into canonical 09XXXXXXXXX form.
 *
 * Accepts the shapes an automation is likely to forward: `09171234567`,
 * `9171234567`, `+639171234567`, `639171234567`, and values with spaces,
 * dashes or parentheses. Anything that is not a PH mobile returns '' — callers
 * must treat that as "no number supplied", never as a match.
 *
 * NOTE: POST /api/payment/claim deliberately does NOT use this lenient form on
 * its request body — it keeps the strict MOBILE_RE check so a customer cannot
 * accidentally bind a typo'd number.
 *
 * @param {*} value
 * @returns {string} canonical number, or '' when not a valid PH mobile
 */
function normalizeMobile(value) {
  if (value === null || value === undefined) return '';

  let digits = String(value).replace(/\D/g, '');

  // +63 / 63 country code → local 0 prefix.
  if (digits.length === 12 && digits.indexOf('63') === 0) {
    digits = '0' + digits.slice(2);
  } else if (digits.length === 10 && digits.charAt(0) === '9') {
    // Number stored without the trunk 0 (9171234567).
    digits = '0' + digits;
  }

  return MOBILE_RE.test(digits) ? digits : '';
}

module.exports = {
  MOBILE_RE,
  normalizeMobile,
};
