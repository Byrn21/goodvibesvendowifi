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
const { validateVoucher, recordSession } = require('../services/session');
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
      ssidName,
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
    // radioId is not sent by the voucher form; pull it from the
    // portal_client_context captured at portal landing (defaults to 0).
    let radioId = 0;
    try {
      const ctxRow = await getDb().getOne(
        'SELECT radio_id FROM portal_client_context WHERE client_mac = ?',
        [normalizedMac]
      );
      if (ctxRow && ctxRow.radio_id !== null && ctxRow.radio_id !== undefined) {
        radioId = ctxRow.radio_id;
      }
    } catch (_) { /* context table may not exist yet in legacy DBs — default 0 */ }

    let omadaResult;
    try {
      omadaResult = await omadaService.authenticateClient({
        clientMac: normalizedMac,
        clientIp: clientIp || '',
        apMac: apMac || '',
        ssidName: ssidName || '',
        radioId,
        durationMinutes: duration,
        sessionId,
      });
    } catch (omadaErr) {
      console.error('[Omada auth error]', omadaErr.message);
      // Return a generic error — don't leak Omada details
      return res.status(502).json({
        success: false,
        error: 'Authentication server did not accept the request.',
        code: 'OMADA_ERROR',
      });
    }

    // ── Record session in DB ───────────────────────────────
    const finalRedirectUrl = redirectUrl
      || voucherResult.redirectUrl
      || process.env.DEFAULT_REDIRECT_URL
      || 'https://www.google.com';

    await recordSession({
      sessionId,
      clientMac: normalizedMac,
      clientIp: clientIp || '',
      apMac: apMac || '',
      ssidName: ssidName || '',
      duration,        // minutes
      voucherUsed: normalizedVoucher,
      voucherType: voucherTypeResolved,
    });

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
