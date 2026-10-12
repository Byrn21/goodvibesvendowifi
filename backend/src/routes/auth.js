/**
 * routes/auth.js — POST /api/auth
 *
 * Flow:
 *   1. Validate input (voucher, client context)
 *   2. Validate voucher against database
 *   3. Call Omada extPortal/auth via omadaService
 *   4. Store session in DB
 *   5. Return success + redirect URL to frontend
 */

const express = require('express');
const router = express.Router();
const omadaService = require('../services/omada');
const { validateVoucher, consumeVoucher, recordSession } = require('../services/session');
const { normalizeVoucherCode, validateVoucherCodeFormat } = require('../utils/voucher-code');
const { normalizeMac: normalizeDeviceMac } = require('../utils/device-id');
const { getDb } = require('../db/client');
const { v4: uuidv4 } = require('uuid');

// POST /api/auth
router.post('/', async (req, res, next) => {
  try {
        const {
      voucher,
      clientMac,
      clientIp,
      apMac,
      gatewayMac,
      ssidName,
      vid,
      radioId: rawRadioId,
      redirectUrl,
      termsAccepted,
      voucherType,
    } = req.body;

    // ── Input validation ────────────────────────────────────
    if (!voucher || typeof voucher !== 'string' || !voucher.trim()) {
      return res.status(400).json({ success: false, error: 'Voucher is required.', code: 'INVALID_INPUT' });
    }

    // ── Voucher code format: exactly 6 numeric digits ───────
    // Normalizes ("123 456" -> "123456") then enforces ^\d{6}$ so an
    // 8-digit or non-numeric code is rejected with 400 even if the
    // frontend validation is bypassed.
    const normalizedVoucher = normalizeVoucherCode(voucher);
    const formatResult = validateVoucherCodeFormat(normalizedVoucher);
    if (!formatResult.ok) {
      return res.status(400).json({
        success: false,
        error: formatResult.message,
        code: 'INVALID_INPUT',
      });
    }

    // MAC address normalization and validation (shared helper —
    // canonical format: uppercase, colon-separated, e.g. AA:BB:CC:DD:EE:FF)
    const normalizedMac = normalizeDeviceMac(clientMac || '');
    if (clientMac && !normalizedMac) {
      return res.status(400).json({ success: false, error: 'Invalid client MAC address.', code: 'INVALID_MAC' });
    }

    // AP / gateway MACs are the identifiers Omada put in the portal URL and
    // expects back in the extPortal/auth body, so send them in the same
    // canonical form (uppercase, colon-separated). Invalid values are passed
    // through unchanged (Omada rejects them) rather than 400'ing here.
    const normalizedApMac = apMac ? (normalizeDeviceMac(apMac) || String(apMac).trim()) : '';
    const normalizedGatewayMac = gatewayMac ? (normalizeDeviceMac(gatewayMac) || String(gatewayMac).trim()) : '';

    // Validate client IP format (basic)
    if (clientIp && !/^\d+\.\d+\.\d+\.\d+$/.test(clientIp)) {
      return res.status(400).json({ success: false, error: 'Invalid client IP.', code: 'INVALID_IP' });
    }

    // Validate redirect URL (prevent open-redirect)
    if (redirectUrl && !isAllowedRedirect(redirectUrl)) {
      return res.status(400).json({ success: false, error: 'Invalid redirect URL.', code: 'INVALID_REDIRECT' });
    }

    // Terms check
    if (!termsAccepted) {
      return res.status(400).json({ success: false, error: 'Terms acceptance required.', code: 'TERMS_REQUIRED' });
    }

    const sessionId = 'sess_' + uuidv4().replace(/-/g, '').slice(0, 16);

    // ── Free voucher validation ─────────────────────────────
    const voucherResult = await validateVoucher(normalizedVoucher, normalizedMac);
    if (!voucherResult.valid) {
      return res.status(401).json({
        success: false,
        error: voucherResult.message || 'Invalid voucher.',
        code: voucherResult.code || 'INVALID_VOUCHER',
      });
    }

    const duration = voucherResult.duration || 60; // minutes
    const voucherTypeResolved = voucherResult.type || voucherType || 'standard';

    // ── Call Omada extPortal/auth ──────────────────────────
    // The portal URL already carries the controller's connection context
    // (radioId, gatewayMac, vid, ...). Prefer the radioId submitted by the
    // form; fall back to the portal_client_context captured at landing, then 0.
    let radioId = null;
    if (rawRadioId !== undefined && rawRadioId !== null && String(rawRadioId).trim() !== '') {
      const parsedRadioId = parseInt(rawRadioId, 10);
      if (!Number.isInteger(parsedRadioId) || parsedRadioId < 0 || parsedRadioId > 255) {
        return res.status(400).json({ success: false, error: 'Invalid radioId.', code: 'INVALID_INPUT' });
      }
      radioId = parsedRadioId;
    }
    if (radioId === null) {
      try {
        const ctxRow = await getDb().getOne(
          'SELECT radio_id FROM portal_client_context WHERE client_mac = ?',
          [normalizedMac]
        );
        if (ctxRow && ctxRow.radio_id !== null && ctxRow.radio_id !== undefined) {
          radioId = ctxRow.radio_id;
        }
      } catch (_) { /* context table may not exist yet in legacy DBs — default 0 */ }
    }
    if (radioId === null) radioId = 0;

    // ── Call Omada extPortal/auth (strict, fail-closed) ────
    // The controller is the ONLY authority on whether this client is really
    // authorized. If the call throws, OR resolves without an explicit
    // success flag, we abort WITHOUT consuming the voucher and WITHOUT
    // recording a session — otherwise the guest loses their code while the
    // portal reports success and the network stays locked (the captive loop).
    let omadaResult;
    try {
      omadaResult = await omadaService.authenticateClient({
        clientMac: normalizedMac,
        clientIp: clientIp || '',
        apMac: normalizedApMac,
        gatewayMac: normalizedGatewayMac,
        vid: vid !== undefined && vid !== null ? String(vid).trim() : '',
        ssidName: ssidName || '',
        radioId,
        durationMinutes: duration,
        sessionId,
        // The guest's voucher travels with the authorization request so the
        // controller receives it alongside authType=4 (see services/omada.js).
        voucherCode: normalizedVoucher,
      });
    } catch (omadaErr) {
      console.error(
        '[auth] Omada extPortal/auth threw for client ' + normalizedMac +
        ' (voucher ' + normalizedVoucher + '): ' +
        (omadaErr && omadaErr.code ? omadaErr.code : 'NO_CODE') +
        ' — ' + (omadaErr && omadaErr.message ? omadaErr.message : String(omadaErr))
      );
      if (omadaErr && omadaErr.omadaResponse) {
        console.error('[auth] Omada response body: ' + JSON.stringify(omadaErr.omadaResponse));
      }
      if (omadaErr && omadaErr.stack) {
        console.error('[auth] Omada stack: ' + omadaErr.stack);
      }
      // Voucher deliberately left UNCONSUMED — the client was never authorized.
      return res.status(502).json({
        success: false,
        error: 'Authentication server did not accept the request.',
        code: 'OMADA_ERROR',
      });
    }

    // A resolved call is trusted ONLY when it reports success === true. A
    // falsy/missing flag means the controller did not definitively authorize
    // the client, so treat it exactly like a thrown error (fail closed).
    if (!omadaResult || omadaResult.success !== true) {
      console.error(
        '[auth] Omada returned a non-success result for client ' + normalizedMac +
        ' (voucher ' + normalizedVoucher + '): ' + JSON.stringify(omadaResult)
      );
      return res.status(502).json({
        success: false,
        error: 'Authentication server did not accept the request.',
        code: 'OMADA_ERROR',
      });
    }

    // ── Consume the voucher + record the session ATOMICALLY ──
    // The controller just authorized the client through its external-portal
    // path (authType 4) — a BYPASS: Omada keeps no record of our voucher, its
    // voucher list is decoupled from ours, and its response cannot tell us
    // whether the code was spent. This database is therefore the only source
    // of truth, and it must move from "voucher active" to "voucher used +
    // session recorded" in a SINGLE transaction — if either write landed
    // alone the guest would either lose a still-valid code (voucher burned,
    // no session) or hold a session no row accounts for.
    //
    // consumeVoucher's `state IN ('active','claimed')` guard keeps this
    // race-safe: it returns false, changing nothing, when another request
    // already took the code.
    let voucherConsumed = false;
    try {
      voucherConsumed = await getDb().transaction(async (tx) => {
        const consumed = await consumeVoucher(normalizedVoucher, normalizedMac, tx);
        if (!consumed) return false; // lost the race — nothing written
        await recordSession({
          sessionId,
          clientMac: normalizedMac,
          clientIp: clientIp || '',
          apMac: apMac || '',
          ssidName: ssidName || '',
          duration,        // minutes
          voucherUsed: normalizedVoucher,
          voucherType: voucherTypeResolved,
        }, tx);
        return true;
      });
    } catch (txErr) {
      // Rolled back, so the voucher is still redeemable — ask for a retry
      // instead of reporting the code as spent.
      console.error(
        '[auth] local state write failed for voucher ' + maskVoucher(normalizedVoucher) +
        ' (client ' + normalizedMac + '): ' + (txErr && txErr.message) +
        ' — transaction rolled back; voucher left UNCONSUMED'
      );
      return res.status(500).json({
        success: false,
        error: 'Could not save your session. Please try again with the same voucher.',
        code: 'SESSION_WRITE_FAILED',
      });
    }
    if (!voucherConsumed) {
      console.error(
        '[auth] voucher ' + maskVoucher(normalizedVoucher) + ' was already consumed concurrently; ' +
        'client ' + normalizedMac + ' was authorized on Omada but no session was recorded.'
      );
      return res.status(409).json({
        success: false,
        error: 'This voucher is no longer available.',
        code: 'VOUCHER_NOT_AVAILABLE',
      });
    }

    const finalRedirectUrl = redirectUrl
      || voucherResult.redirectUrl
      || process.env.DEFAULT_REDIRECT_URL
      || 'https://www.google.com';

    // ── Explicit success log: the Omada response AND the local lock ──
    // `omadaEchoedVoucher` is computed rather than assumed — the controller
    // answers {"errorCode":0} with no voucher in it, which is the evidence
    // that the voucher was resolved locally (bypass) and that its voucher list
    // is decoupled from ours.
    const omadaRawText = (omadaResult && omadaResult.raw) ? JSON.stringify(omadaResult.raw) : '';
    console.log(
      '[auth] authorization SUCCESS (controller bypass, voucher resolved locally) —' +
      ' client=' + normalizedMac +
      ' session=' + sessionId +
      ' ssid="' + (ssidName || '') + '"' +
      ' duration=' + duration + 'min' +
      ' voucher=' + maskVoucher(normalizedVoucher) +
      ' localState=voucher:used+session:recorded' +
      ' omadaEchoedVoucher=' + (omadaRawText ? omadaRawText.includes(normalizedVoucher) : false) +
      ' omadaResponse=' + (omadaRawText || '(empty)')
    );

    return res.json({
      success: true,
      message: 'Authentication successful.',
      sessionId,
      redirectUrl: finalRedirectUrl,
      // Expose minimal session info (not secrets)
            session: {
        state: 'active',
        remainingSeconds: duration * 60,
        voucherType: voucherTypeResolved,
      },
    });

  } catch (err) {
    next(err);
  }
});

// ── Helpers ──────────────────────────────────────────────────
// MAC normalization uses the shared utils/device-id.js helper so the
// saved format (uppercase, colon-separated) always matches lookups.

/**
 * Mask a voucher code for logs: `••••12` (last two digits), matching the admin
 * UI's maskVoucherCode and services/omada.js. A code stays a live credential
 * until the authorization is committed, so it never goes to the logs raw.
 *
 * @param {string} code
 * @returns {string}
 */
function maskVoucher(code) {
  const cleaned = String(code === undefined || code === null ? '' : code).replace(/\s+/g, '');
  if (!cleaned) return '(empty)';
  return cleaned.length < 2 ? '••••••' : '••••' + cleaned.slice(-2);
}

function isAllowedRedirect(url) {
  if (!url) return true; // No redirect is fine
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    if (u.hostname === 'localhost' || u.hostname === '127.0.0.1') return true;
    const allowed = (process.env.ALLOWED_REDIRECT_DOMAINS || '')
      .split(',')
      .map(s => s.trim().toLowerCase())
      .filter(Boolean);
    if (allowed.length === 0) return true; // Empty allowlist = open
    return allowed.some(d =>
      u.hostname === d || u.hostname.endsWith('.' + d)
    );
  } catch { return false; }
}

module.exports = router;
