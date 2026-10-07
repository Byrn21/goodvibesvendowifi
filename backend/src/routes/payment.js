/**
 * routes/payment.js — POST /api/payment/context
 *
 * Captures the Omada controller context (AP MAC, SSID, radio ID) when a
 * client lands on the captive portal page. The context row is later read by
 * GET /api/auth (radio_id) and by the session/admin layers so a device can
 * be authorized via /hotspot/extPortal/auth.
 *
 * This endpoint is UNAUTHENTICATED by design (the client has not paid or
 * authenticated yet), so it is protected by:
 *   - Strict input validation (MAC format, field lengths, radio_id range)
 *   - A dedicated per-IP rate limiter (stricter than the global apiLimiter)
 *
 * Called by assets/portal.js as a fire-and-forget beacon on portal landing;
 * seen_at is refreshed on every page load, which keeps the context fresh
 * within the PORTAL_CONTEXT_MAX_AGE_MS staleness window.
 */

const express = require('express');
const router = express.Router();
const { rateLimit } = require('express-rate-limit');
const { getDb } = require('../db/client');
const { normalizeMac } = require('../utils/device-id');
const SITE = process.env.OMADA_SITE || 'Default';

// ── Per-IP rate limiter (stricter than the global apiLimiter) ──────────
// This endpoint is unauthenticated and write-capable, so abusive or
// accidental hammering (e.g. a portal page in a refresh loop) must be
// throttled independently. Legitimate traffic is one beacon per page load.
const contextLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,                  // 30 beacons per IP per window is generous for real usage
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests. Try again later.', code: 'RATE_LIMITED' },
});

// Manual reference-number claims are also unauthenticated and write-capable —
// the same generous-for-humans, hostile-to-abuse budget applies. (The global
// apiLimiter is layered on top.)
const claimLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests. Try again later.', code: 'RATE_LIMITED' },
});

// ── Validation helpers ──────────────────────────────────────────────────
const MAC_RE = /^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/;

/**
 * Validate and normalize a MAC address. Accepts common variants
 * (aa-bb-cc-dd-ee-ff, aabbccddeeff, with/without colons) by delegating to
 * normalizeMac(), then verifying the canonical colon format.
 * @param {string} value
 * @returns {string|null} canonical MAC or null when invalid
 */
function parseMac(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const normalized = normalizeMac(value);
  return normalized && MAC_RE.test(normalized) ? normalized : null;
}

function isValidSsid(value) {
  return typeof value === 'string' && value.trim().length >= 1 && value.trim().length <= 64;
}

function parseRadioId(value) {
  const n = typeof value === 'number' ? value : parseInt(value, 10);
  return Number.isInteger(n) && n >= 0 && n <= 255 ? n : null;
}

function isValidIp(value) {
  return typeof value === 'string' && value.trim().length <= 45;
}

// ── Route ───────────────────────────────────────────────────────────────
router.post('/context', contextLimiter, async (req, res, next) => {
  try {
    const body = req.body || {};

    // client_mac — required, must be a well-formed MAC
    const clientMac = parseMac(body.client_mac);
    if (!clientMac) {
      return res.status(400).json({
        success: false,
        error: 'client_mac is required and must be a valid MAC address.',
        code: 'INVALID_CLIENT_MAC',
      });
    }

    // ap_mac — required, must be a well-formed MAC
    const apMac = parseMac(body.ap_mac);
    if (!apMac) {
      return res.status(400).json({
        success: false,
        error: 'ap_mac is required and must be a valid MAC address.',
        code: 'INVALID_AP_MAC',
      });
    }

    // ssid_name — required, 1–64 chars (matches schema column width)
    if (!isValidSsid(body.ssid_name)) {
      return res.status(400).json({
        success: false,
        error: 'ssid_name is required and must be 1-64 characters.',
        code: 'INVALID_SSID_NAME',
      });
    }
    const ssidName = body.ssid_name.trim();

    // radio_id — required, integer 0–255 (controller sends radioId=0)
    const radioId = parseRadioId(body.radio_id);
    if (radioId === null) {
      return res.status(400).json({
        success: false,
        error: 'radio_id is required and must be an integer between 0 and 255.',
        code: 'INVALID_RADIO_ID',
      });
    }

    // client_ip — optional, length-capped
    if (body.client_ip !== undefined && !isValidIp(body.client_ip)) {
      return res.status(400).json({
        success: false,
        error: 'client_ip must be a string of at most 45 characters.',
        code: 'INVALID_CLIENT_IP',
      });
    }
    const clientIp = body.client_ip ? String(body.client_ip).trim() : null;

    // ── Upsert (SQLite + PostgreSQL compatible) ───────────────────────
    // INSERT ... ON CONFLICT(client_mac) DO UPDATE is valid on SQLite
    // 3.24+ and all supported PostgreSQL versions.
    const now = new Date().toISOString();
    await getDb().run(
      `INSERT INTO portal_client_context
         (client_mac, client_ip, ap_mac, ssid_name, radio_id, site, seen_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(client_mac) DO UPDATE SET
         client_ip = excluded.client_ip,
         ap_mac    = excluded.ap_mac,
         ssid_name = excluded.ssid_name,
         radio_id  = excluded.radio_id,
         site      = excluded.site,
         seen_at   = excluded.seen_at,
         updated_at = excluded.updated_at`,
      [clientMac, clientIp, apMac, ssidName, radioId, SITE, now, now, now]
    );

    console.log('[payment/context] captured context for ' + clientMac + ' (ap ' + apMac + ', ssid "' + ssidName + '")');
    return res.json({ success: true, code: 'CONTEXT_CAPTURED' });
  } catch (err) {
    next(err);
  }
});

// ── Payment method configuration ────────────────────────────────────────
/**
 * GET /api/payment/methods
 *
 * Serves the receiver details and QR images for the supported e-wallets so
 * that no sensitive payment information (account names, account numbers,
 * QR images) is hard-coded in the frontend. Values are read from the
 * environment so operators can rotate them without a code change; every
 * value falls back to an empty string when unset.
 *
 * The *_QR_B64 variables hold complete data URI strings
 * (e.g. data:image/png;base64,iVBORw0KGgo...), which the portal assigns
 * directly to the <img> src.
 *
 * UNAUTHENTICATED by design: the captive portal must fetch this before the
 * client has been authorized. The payload is read-only and the QR it exposes
 * is exactly what the customer is meant to scan; it grants no access on its
 * own, so a rate limiter would only risk breaking the captive flow.
 */
function envOrEmpty(name) {
  const value = process.env[name];
  return typeof value === 'string' ? value : '';
}

function buildPaymentMethods() {
  return {
    gcash: {
      name: 'GCash',
      qrImage: envOrEmpty('GCASH_QR_B64'),
      accountName: envOrEmpty('GCASH_NAME'),
      accountNumber: envOrEmpty('GCASH_NUMBER'),
      instructions: [
        'Open your GCash app.',
        "Tap 'Scan QR'.",
        'Scan the code above.',
        'Pay the exact amount.',
        "After paying, tap 'Claim Voucher' and enter the last 4 digits of your reference number.",
      ],
    },
    maya: {
      name: 'Maya',
      qrImage: envOrEmpty('MAYA_QR_B64'),
      accountName: envOrEmpty('MAYA_NAME'),
      accountNumber: envOrEmpty('MAYA_NUMBER'),
      instructions: [
        'Open your Maya app.',
        "Tap 'Scan to Pay'.",
        'Scan the code above.',
        'Pay the exact amount.',
        "After paying, tap 'Claim Voucher' and enter the last 4 digits of your reference number.",
      ],
    },
    qrph: {
      name: 'QR Ph',
      qrImage: envOrEmpty('QRPH_QR_B64'),
      accountName: envOrEmpty('QRPH_NAME'),
      accountNumber: envOrEmpty('QRPH_NUMBER'),
      instructions: [
        'Open any supported banking app, GCash, or Maya.',
        "Tap 'Scan QR'.",
        'Scan the QR Ph code above.',
        'Pay the exact amount.',
        "After paying, tap 'Claim Voucher' and enter the last 4 digits of your reference number.",
      ],
    },
  };
}

router.get('/methods', (req, res) => {
  // Payment details are configurable and mostly static, but never cache them
  // in shared/proxy storage in case an operator rotates them mid-deploy.
  res.set('Cache-Control', 'no-store');
  return res.json(buildPaymentMethods());
});

// ── Centralized voucher claim ───────────────────────────────────────────
/**
 * POST /api/payment/claim
 *
 * The customer has paid (MacroDroid intercepted the e-wallet confirmation
 * and POSTed it to /api/webhooks/macrodroid, creating an 'unclaimed'
 * webhook_events row) and now claims the matching pre-imported voucher by
 * entering the LAST 4 DIGITS of their reference number.
 *
 * Body: { ref_suffix }  — exactly 4 digits
 *
 * Behaviour (all inside ONE transaction):
 *   1. Find the newest 'unclaimed' webhook_events row whose ref_no ends
 *      with ref_suffix → 404 'Payment not found or already claimed'.
 *   2. Convert the recorded amount from PESOS to CENTAVOS (webhook_events
 *      stores Pesos; vouchers.price stores centavos — never assume they match).
 *   3. Find one 'active', unassigned voucher whose price matches those
 *      centavos → 404 'No voucher available for this amount'.
 *   4. Atomically mark the voucher 'claimed' (recording the FULL ref_no in
 *      assigned_ref_no) AND the event 'claimed'. Any failure rolls BOTH
 *      back, so a voucher is never claimed without its event (or vice versa).
 *
 * Returns 200 with { success, voucherCode, ref_no }. The frontend injects
 * voucherCode into the existing /api/auth voucher flow to connect.
 */

/** Build a typed HTTP error (thrown to roll back the claim transaction). */
function httpError(status, code, message) {
  const err = new Error(message);
  err.status = status;
  err.code = code;
  return err;
}

router.post('/claim', claimLimiter, async (req, res, next) => {
  try {
    const body = req.body || {};
    const refSuffix = typeof body.ref_suffix === 'string' ? body.ref_suffix.trim() : '';

    // The customer enters the last 4 digits of their payment reference.
    if (!/^\d{4}$/.test(refSuffix)) {
      return res.status(400).json({
        success: false,
        error: 'ref_suffix is required and must be the last 4 digits of your reference number.',
        code: 'INVALID_REF_SUFFIX',
      });
    }

    const db = getDb();

    let claim;
    try {
      claim = await db.transaction(async (tx) => {
        const event = await tx.getOne(
          `SELECT ref_no, amount FROM webhook_events
            WHERE status = 'unclaimed' AND ref_no LIKE ?
            ORDER BY id DESC LIMIT 1`,
          ['%' + refSuffix]
        );
        if (!event) throw httpError(404, 'PAYMENT_NOT_FOUND', 'Payment not found or already claimed.');

        // CRITICAL: webhook_events.amount is Pesos; vouchers.price is centavos.
        const amountCentavos = Math.round(Number(event.amount) * 100);

        const voucher = await tx.getOne(
          `SELECT id, code FROM vouchers
            WHERE state = 'active' AND assigned_ref_no IS NULL AND price = ?
            ORDER BY id ASC LIMIT 1`,
          [amountCentavos]
        );
        if (!voucher) {
          throw httpError(404, 'NO_VOUCHER_AVAILABLE', 'No voucher is available for this amount. Please contact support.');
        }

        // Conditional update guards against a concurrent claim taking the
        // voucher between the SELECT and this UPDATE.
        const voucherUpdate = await tx.run(
          `UPDATE vouchers
              SET state = 'claimed', assigned_ref_no = ?
            WHERE id = ? AND state = 'active' AND assigned_ref_no IS NULL`,
          [event.ref_no, voucher.id]
        );
        if (voucherUpdate.rowCount === 0) {
          throw httpError(404, 'NO_VOUCHER_AVAILABLE', 'No voucher is available for this amount. Please contact support.');
        }

        const eventUpdate = await tx.run(
          `UPDATE webhook_events
              SET status = 'claimed', processed_at = ?
            WHERE ref_no = ? AND status = 'unclaimed'`,
          [new Date().toISOString(), event.ref_no]
        );
        if (eventUpdate.rowCount === 0) {
          // Another request claimed this payment first — roll the voucher back.
          throw httpError(404, 'PAYMENT_NOT_FOUND', 'Payment not found or already claimed.');
        }

        return { voucherCode: voucher.code, refNo: event.ref_no };
      });
    } catch (err) {
      if (err.code === 'PAYMENT_NOT_FOUND' || err.code === 'NO_VOUCHER_AVAILABLE') {
        return res.status(err.status || 404).json({ success: false, error: err.message, code: err.code });
      }
      throw err;
    }

    console.log('[payment/claim] claimed voucher ' + claim.voucherCode + ' for ref ' + claim.refNo);
    return res.json({ success: true, voucherCode: claim.voucherCode, ref_no: claim.refNo });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
