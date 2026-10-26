/**
 * utils/portal-context.js — the controller connection context captured when a
 * device lands on the captive portal page.
 *
 * Guest authorization runs through services/omada.js (authenticateClient) on
 * the controller's own web API, and Omada's extPortal/auth contract is
 * connection-type specific:
 *   EAP     (wireless): clientMac + clientIp + apMac + ssidName + radioId
 *   Gateway (wired)   : clientMac + clientIp + gatewayMac + vid
 *
 * POST /api/payment/context (the landing beacon) stores the EAP triple per
 * client MAC in portal_client_context. This helper is the single read path for
 * the flows that authorize a device outside POST /api/auth (the payment claim
 * and the InstaPay / PESONet webhook), so they can never disagree about what a
 * "known" client is.
 *
 * Staleness: a row older than PORTAL_CONTEXT_MAX_AGE_MS is reported as MISSING
 * (fail loud, code MISSING_PORTAL_CONTEXT) — a stale AP/SSID association would
 * otherwise surface as a controller rejection that reads like a credentials
 * problem, and the client can fix a missing context by reloading the portal.
 */

'use strict';

const { getDb } = require('../db/client');
const { PORTAL_CONTEXT_MAX_AGE_MS } = require('../config');
const { normalizeMac } = require('./device-id');

/** Max radio id the controller accepts (see POST /api/payment/context). */
const MAX_RADIO_ID = 255;

/**
 * Build the fail-loud error for an unusable context.
 *
 * @param {string} clientMac canonical MAC
 * @param {string} reason    what is missing/stale, phrased for the operator log
 * @returns {Error} code MISSING_PORTAL_CONTEXT
 */
function missingContext(clientMac, reason) {
  const err = new Error(
    'No usable portal context for ' + clientMac + ' — ' + reason +
    '. The device must load the captive portal page once (POST /api/payment/context)' +
    ' before it can be authorized through the controller web API.'
  );
  err.code = 'MISSING_PORTAL_CONTEXT';
  return err;
}

/**
 * Parse a stored timestamp to epoch milliseconds.
 *
 * seen_at is written as an ISO string by POST /api/payment/context, but rows
 * created by the table default are SQLite's CURRENT_TIMESTAMP
 * ("YYYY-MM-DD HH:MM:SS", UTC, no zone marker) — V8 would read that as LOCAL
 * time, so a bare value gets an explicit Z before parsing.
 *
 * @param {*} value
 * @returns {number} epoch ms, or NaN when unparseable
 */
function parseSeenAt(value) {
  if (value instanceof Date) return value.getTime();
  const text = String(value || '').trim();
  if (!text) return NaN;
  const hasZone = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(text);
  return Date.parse(hasZone ? text : text.replace(' ', 'T') + 'Z');
}

/**
 * Load the controller connection context for a client MAC.
 *
 * @param {string} clientMac any accepted MAC representation
 * @returns {Promise<{clientMac: string, clientIp: string, apMac: string,
 *                    ssidName: string, radioId: number, seenAt: string}>}
 * @throws {Error} code MISSING_PORTAL_CONTEXT when no fresh row exists
 */
async function loadPortalContext(clientMac) {
  const mac = normalizeMac(clientMac);
  if (!mac) throw missingContext(String(clientMac || '(none)'), 'the client MAC is not valid');

  const row = await getDb().getOne(
    `SELECT client_ip, ap_mac, ssid_name, radio_id, seen_at
       FROM portal_client_context
      WHERE client_mac = ?`,
    [mac]
  );

  if (!row) {
    throw missingContext(mac, 'the device has not landed on the captive portal yet');
  }

  const seenMs = parseSeenAt(row.seen_at);
  if (Number.isFinite(seenMs) && Date.now() - seenMs > PORTAL_CONTEXT_MAX_AGE_MS) {
    throw missingContext(
      mac,
      'the captured context is older than ' + Math.round(PORTAL_CONTEXT_MAX_AGE_MS / 60000) + ' min'
    );
  }

  const apMac = normalizeMac(row.ap_mac) || '';
  const ssidName = String(row.ssid_name || '').trim();
  if (!apMac || !ssidName) {
    throw missingContext(mac, 'the stored context has no AP MAC / SSID');
  }

  const parsedRadioId = parseInt(row.radio_id, 10);
  const radioId = Number.isInteger(parsedRadioId) && parsedRadioId >= 0 && parsedRadioId <= MAX_RADIO_ID
    ? parsedRadioId
    : 0;

  return {
    clientMac: mac,
    clientIp: String(row.client_ip || '').trim(),
    apMac,
    ssidName,
    radioId,
    seenAt: row.seen_at,
  };
}

module.exports = {
  loadPortalContext,
  parseSeenAt,
};
