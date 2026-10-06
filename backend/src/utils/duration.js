'use strict';

/**
 * utils/duration.js — single source of truth for amount → session duration.
 *
 * Minutes of Wi-Fi time granted per whole unit of currency received, using
 * the business rate in config/index.js (PESOS_PER_MINUTE). Shared by the
 * payment webhook/claim paths and the admin claims dashboard so the mapping
 * is defined exactly once.
 *
 * @param {number|string} amount
 * @returns {number} whole minutes granted, or 0 when the amount is
 *                   missing/unrecognized/too small
 */

const { PESOS_PER_MINUTE } = require('../config');

function computeMinutesFromAmount(amount) {
  // Whole units of currency → whole minutes (floor). Zero/negative → 0.
  const units = Math.floor(Number(amount));
  if (!isFinite(units) || units <= 0) return 0;
  return Math.floor(units / PESOS_PER_MINUTE);
}

module.exports = { computeMinutesFromAmount };
