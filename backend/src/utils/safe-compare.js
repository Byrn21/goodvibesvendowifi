'use strict';

/**
 * utils/safe-compare.js — constant-time comparison for operator credentials.
 *
 * One helper for every secret comparison (ADMIN_API_KEY, ADMIN_PASSWORD), so an
 * admin guard can never be a plain `===` again while the rest of the codebase
 * uses `crypto.timingSafeEqual`.
 *
 * Two rules make this safe to use as a CREDENTIAL comparator:
 *
 *   1. A blank operand NEVER matches. `crypto.timingSafeEqual(Buffer.alloc(0),
 *      Buffer.alloc(0))` returns TRUE, so the naive wrapper makes '' === '' a
 *      successful compare — which is exactly how an unconfigured deployment
 *      turned an empty login password into a valid admin token. Whitespace-only
 *      values are rejected too, matching config/index.js's readSecret(), which
 *      treats "   " as an unset secret rather than a credential.
 *   2. Length mismatches return false after a dummy comparison, so the time
 *      taken does not reveal whether the supplied value is a prefix of the
 *      configured one.
 */

const crypto = require('crypto');

// Fixed-size buffer used to keep the "reject" path's timing flat. Its contents
// are irrelevant: the result is always false.
const FLAT_TIMING_DUMMY = Buffer.alloc(32);

/**
 * Compare two credential strings without leaking their contents through timing.
 *
 * Accepts any value; non-strings are coerced, and null/undefined/blank are
 * treated as "no credential" (never a match). Non-blank values are compared
 * byte-for-byte WITHOUT trimming, so a configured secret containing spaces
 * must be supplied exactly.
 *
 * @param {*} a
 * @param {*} b
 * @returns {boolean} true only when both are non-blank and byte-identical
 */
function safeEqual(a, b) {
  const left = a === null || a === undefined ? '' : String(a);
  const right = b === null || b === undefined ? '' : String(b);

  if (!left.trim() || !right.trim()) {
    crypto.timingSafeEqual(FLAT_TIMING_DUMMY, FLAT_TIMING_DUMMY);
    return false;
  }

  const given = Buffer.from(left, 'utf8');
  const want = Buffer.from(right, 'utf8');

  if (given.length !== want.length) {
    crypto.timingSafeEqual(FLAT_TIMING_DUMMY, FLAT_TIMING_DUMMY);
    return false;
  }

  return crypto.timingSafeEqual(given, want);
}

module.exports = {
  safeEqual,
};
