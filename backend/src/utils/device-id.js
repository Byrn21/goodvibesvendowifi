'use strict';

/**
 * utils/device-id.js — single source of truth for device identifier format.
 *
 * RULE: MAC addresses are stored and compared as UPPERCASE pairs separated
 * by colons (e.g. "AA:BB:CC:DD:EE:FF"). The same helper MUST be used at
 * save time (routes/auth.js, services/session.js) and at lookup time so a
 * device saved as "aa-bb-cc-dd-ee-ff" is always found as "AA:BB:CC:DD:EE:FF".
 *
 * Accepted input formats:
 *   "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabbccddeeff", "AABB.CCDD.EEFF"
 */

/**
 * normalizeMac — convert any common MAC representation to the canonical
 * uppercase colon-separated form. Returns null when the input does not
 * contain exactly 12 hex digits.
 *
 * @param {*} value
 * @returns {string|null}
 */
function normalizeMac(value) {
  if (value == null) return null;
  const cleaned = String(value).replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  if (cleaned.length !== 12) return null;
  return cleaned.match(/.{2}/g).join(':');
}

/**
 * isSameMac — compare two MAC strings in any format after normalization.
 * Either side being empty/invalid yields false.
 *
 * @param {*} a
 * @param {*} b
 * @returns {boolean}
 */
function isSameMac(a, b) {
  const na = normalizeMac(a);
  const nb = normalizeMac(b);
  return Boolean(na) && Boolean(nb) && na === nb;
}

module.exports = {
  normalizeMac,
  isSameMac,
};
