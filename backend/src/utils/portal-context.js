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
 * It is also the lookup used by the MAC-direct status flow: the beacon records
 * the client's address as well, so GET /api/session/status can map a request IP
 * to its device (resolveClientMacByIp) when no voucher / session id is carried
 * in the URL.
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
 * Canonicalize an address for comparison with portal_client_context.client_ip.
 *
 * The landing beacon stores whatever the controller reported as clientIp — on
 * this deployment a plain LAN IPv4 address such as "10.0.0.5". Express reports
 * the same peer as "::ffff:10.0.0.5" on a dual-stack listener, so the
 * IPv4-mapped prefix is stripped before matching; an IPv6 zone suffix
 * ("fe80::1%eth0") is not part of the address either.
 *
 * @param {*} value
 * @returns {string} the address to match, or '' when none can be determined
 */
function normalizeClientIp(value) {
  const text = String(value == null ? '' : value).trim();
  if (!text) return '';
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(text);
  if (mapped) return mapped[1];
  return text.replace(/%.+$/, '');
}

/**
 * Build the fail-loud error for a request IP that maps to no device.
 *
 * Same code as missingContext(): the caller (GET /api/session/status) reports
 * MISSING_PORTAL_CONTEXT either way, because both mean "this device has not
 * loaded the captive portal, so it cannot be identified".
 *
 * @param {string} clientIp the request IP (or '(none)')
 * @param {string} reason   what is missing, phrased for the operator log
 * @returns {Error} code MISSING_PORTAL_CONTEXT
 */
function missingContextForIp(clientIp, reason) {
  const err = new Error(
    'No usable portal context for client IP ' + clientIp + ' — ' + reason +
    '. The device must load the captive portal page once (POST /api/payment/context)' +
    ' before it can be identified by its address.'
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

/**
 * Resolve the client MAC behind a request IP — the MAC-direct identification
 * used by GET /api/session/status.
 *
 * The status page polls with NO voucher, session id or MAC in its URL: a guest
 * who was authorized directly by MAC has nothing to carry over, so the device
 * is identified by the address it reached the portal from. That address is
 * exactly what the landing beacon stored in client_ip.
 *
 * Staleness: unlike loadPortalContext (which feeds an authorization), this is
 * read-only identification for DISPLAYING a session, so a row older than
 * PORTAL_CONTEXT_MAX_AGE_MS is still used — a guest checking their remaining
 * time an hour after landing is the normal case — and reported through
 * `stale` so the caller can log it. Only a genuinely missing row (never landed
 * on the portal) is MISSING_PORTAL_CONTEXT.
 *
 * @param {string} clientIp the request IP (req.ip)
 * @returns {Promise<{clientMac: string, seenAt: *, stale: boolean}>}
 * @throws {Error} code MISSING_PORTAL_CONTEXT when no row matches the address
 */
async function resolveClientMacByIp(clientIp) {
  const ip = normalizeClientIp(clientIp);
  if (!ip) {
    throw missingContextForIp('(none)', 'the request IP address could not be determined');
  }

  const row = await getDb().getOne(
    `SELECT client_mac, seen_at
       FROM portal_client_context
      WHERE client_ip = ?
      ORDER BY seen_at DESC LIMIT 1`,
    [ip]
  );

  const mac = row ? normalizeMac(row.client_mac) : null;
  if (!mac) {
    throw missingContextForIp(ip, 'no device has loaded the captive portal from that address');
  }

  const seenMs = parseSeenAt(row.seen_at);
  const stale = Number.isFinite(seenMs) && Date.now() - seenMs > PORTAL_CONTEXT_MAX_AGE_MS;

  return { clientMac: mac, seenAt: row.seen_at, stale };
}

module.exports = {
  loadPortalContext,
  parseSeenAt,
  normalizeClientIp,
  resolveClientMacByIp,
};
