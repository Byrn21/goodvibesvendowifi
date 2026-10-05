'use strict';

/**
 * utils/price.js - single source of truth for money handling.
 *
 * STORAGE RULE (used everywhere - import, API, dashboard, display):
 *   Every monetary amount in the database is an INTEGER number of
 *   centavos (1 peso = 100 centavos). PHP 50.00 is stored as 5000.
 *
 * Conversion between human input and centavos happens exactly once, HERE.
 * Never multiply or divide prices anywhere else in the codebase.
 */

const MAX_CENTAVOS = 999999999; // P9,999,999.99 sanity guard

/**
 * Parse a human-entered price into integer centavos.
 *
 * Accepted formats:
 *   50, "50", "50.00", "50.5", "PHP50.00", "PHP 1,250.50", "1,250.00",
 *   "PHP 50", "php50", "php 1,250.50", "1.250,50" (European decimal comma),
 *   and raw numbers (numeric cells from XLSX).
 *
 * @param {number|string} value
 * @returns {{ok: true, centavos: number}
 *           | {ok: false, reason: 'empty'|'negative'|'invalid'|'too_large'}}
 */
function parsePriceToCentavos(value) {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return { ok: false, reason: 'invalid' };
    if (value < 0) return { ok: false, reason: 'negative' };
    return { ok: true, centavos: Math.round(value * 100) };
  }

  if (value === undefined || value === null) return { ok: false, reason: 'empty' };

  let s = String(value).trim();
  if (s === '') return { ok: false, reason: 'empty' };

  // European-style decimal comma first, e.g. "1.250,50" -> "1250.50"
  if (/^\d{1,3}(\.\d{3})+,\d+$/.test(s)) {
    s = s.replace(/\./g, '').replace(/,/, '.');
  }

  // Strip currency prefix/symbol, thousands separators, and all whitespace
  // (regular, non-breaking, narrow no-break). The decimal POINT is preserved.
  s = s
    .replace(/php/gi, '')
    .replace(/\u20B1/g, '') // peso sign
    .replace(/[\s\u00A0\u202F]/g, '')
    .replace(/,/g, '');

  if (s === '') return { ok: false, reason: 'empty' };
  if (s.indexOf('-') !== -1) return { ok: false, reason: 'negative' };
  if (!/^(\d+(\.\d*)?|\.\d+)$/.test(s)) return { ok: false, reason: 'invalid' };

  const centavos = Math.round(parseFloat(s) * 100);
  if (centavos > MAX_CENTAVOS) return { ok: false, reason: 'too_large' };
  return { ok: true, centavos };
}

/**
 * Format integer centavos as a peso string, e.g. 125050 -> "PHP1,250.50".
 * Server-side mirror of the browser-side formatPrice() - keep both in sync.
 */
function centavosToPesoString(centavos) {
  const pesos = (Number(centavos) || 0) / 100;
  return '\u20B1' + pesos.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

module.exports = { parsePriceToCentavos, centavosToPesoString };
