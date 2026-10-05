/**
 * routes/payment.js — POST /api/payment/context
 *
 * Captures the Omada controller context (AP MAC, SSID, radio ID) when a
 * client lands on the captive portal page. The payment webhook later reads
 * this row (portal_client_context table) to authorize the client via
 * /hotspot/extPortal/auth — the client does not need to be online at
 * payment time.
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
const { v4: uuidv4 } = require('uuid');
const { getDb } = require('../db/client');
const { normalizeMac } = require('../utils/device-id');
const omadaService = require('../services/omada');
const { PESOS_PER_MINUTE } = require('../config');
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
        "Tap 'I Already Paid'.",
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
        "Tap 'I Already Paid'.",
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
        "Tap 'I Already Paid'.",
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

// ── Manual payment claim ────────────────────────────────────────────────
/**
 * POST /api/payment/claim
 *
 * Manual fallback for the payment QR flow: the customer types the reference
 * number from their e-wallet receipt when the automatic SMS detection is
 * slow or has not happened yet.
 *
 * Body: { ref_no, client_mac }
 *
 * Behaviour:
 *   1. If MacroDroid already recorded a PROCESSED webhook_event for ref_no,
 *      the matching payment exists but the device may not have been
 *      authorized (e.g. the webhook hit MISSING_PORTAL_CONTEXT). Manually
 *      trigger the Omada authorization now and return success.
 *   2. If ref_no is unknown, save it as a PENDING event linked to
 *      ref_no + client_mac for later human verification and return a
 *      pending response (never an error).
 *   3. If the same reference was already claimed, respond pending again
 *      (idempotent).
 */
function computeMinutesFromAmount(amount) {
  const units = Math.floor(Number(amount));
  if (!isFinite(units) || units <= 0) return 0;
  return Math.floor(units / PESOS_PER_MINUTE);
}

router.post('/claim', claimLimiter, async (req, res, next) => {
  try {
    const body = req.body || {};

    // Reference numbers are numeric (GCash/Maya 13-digit refs). Accept 6–64
    // digits so real webhook references are never rejected.
    const refNo = typeof body.ref_no === 'string' ? body.ref_no.trim() : '';
    if (!/^\d{6,64}$/.test(refNo)) {
      return res.status(400).json({
        success: false,
        error: 'ref_no is required and must be 6-64 digits.',
        code: 'INVALID_REF_NO',
      });
    }

    const clientMac = parseMac(body.client_mac);
    if (!clientMac) {
      return res.status(400).json({
        success: false,
        error: 'client_mac is required and must be a valid MAC address.',
        code: 'INVALID_CLIENT_MAC',
      });
    }

    const db = getDb();
    const event = await db.getOne(
      'SELECT * FROM webhook_events WHERE ref_no = ? LIMIT 1',
      [refNo]
    );

    // ── Case 3: already registered as a pending manual claim ──────────
    if (event && event.status !== 'processed') {
      return res.json({
        success: true,
        pending: true,
        code: 'PENDING_VERIFICATION',
        sessionId: event.session_id || null,
        message: "Thanks! We're verifying your reference number manually. This may take a few minutes.",
      });
    }

    // ── Case 1: MacroDroid already caught the matching SMS ────────────
    if (event && event.status === 'processed') {
      let session = await db.getOne(
        'SELECT * FROM sessions WHERE ref_no = ? LIMIT 1',
        [refNo]
      );

      // Already authorized — nothing more to do.
      if (session && session.state === 'active') {
        return res.json({
          success: true,
          alreadyActive: true,
          code: 'ALREADY_ACTIVE',
          sessionId: session.session_id,
          message: 'This device is already connected.',
        });
      }

      const durationMinutes = (session && Number(session.duration_minutes)) ||
        computeMinutesFromAmount(event.amount);
      if (!durationMinutes || durationMinutes <= 0) {
        return res.status(400).json({
          success: false,
          error: 'The recorded payment is too small to grant any time.',
          code: 'INSUFFICIENT_AMOUNT',
        });
      }

      // Controller context is created on the portal landing / modal open.
      const ctx = await db.getOne(
        'SELECT * FROM portal_client_context WHERE client_mac = ?',
        [clientMac]
      );
      if (!ctx || !ctx.ap_mac || !ctx.ssid_name || ctx.radio_id === null || ctx.radio_id === undefined) {
        return res.status(422).json({
          success: false,
          error: 'Portal context is missing or stale. Please re-open the portal page and try again.',
          code: 'MISSING_PORTAL_CONTEXT',
        });
      }

      const sessionId = (session && session.session_id) ||
        ('sess_' + uuidv4().replace(/-/g, '').slice(0, 16));

      try {
        await omadaService.authenticateClient({
          clientMac,
          clientIp: ctx.client_ip || '',
          apMac: ctx.ap_mac,
          ssidName: ctx.ssid_name,
          radioId: ctx.radio_id,
          durationMinutes,
          sessionId,
        });
      } catch (omadaErr) {
        console.error('[payment/claim] Omada auth failed for ref ' + refNo + ':', omadaErr.message);
        if (session) {
          await db.run(
            'UPDATE sessions SET omada_auth_failed = 1, updated_at = ? WHERE session_id = ?',
            [new Date().toISOString(), sessionId]
          );
        }
        return res.status(502).json({
          success: false,
          error: 'Controller authorization failed. Please try again.',
          code: 'OMADA_ERROR',
        });
      }

      const now = new Date().toISOString();
      const expiresAt = new Date(Date.now() + durationMinutes * 60 * 1000).toISOString();
      if (session) {
        await db.run(
          `UPDATE sessions
             SET state = 'active', started_at = COALESCE(started_at, ?),
                 expires_at = ?, omada_auth_failed = 0, updated_at = ?
           WHERE session_id = ?`,
          [now, expiresAt, now, sessionId]
        );
      } else {
        await db.run(
          `INSERT INTO sessions
             (session_id, client_mac, ref_no, client_ip, ap_mac, ssid_name,
              duration_minutes, voucher_type, started_at, expires_at, state, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'paid', ?, ?, 'active', ?, ?)`,
          [sessionId, clientMac, refNo, ctx.client_ip || '', ctx.ap_mac, ctx.ssid_name,
            durationMinutes, now, expiresAt, now, now]
        );
        await db.run(
          'UPDATE webhook_events SET session_id = ? WHERE ref_no = ?',
          [sessionId, refNo]
        );
      }

      console.log('[payment/claim] manually authorized ' + clientMac + ' for ref ' + refNo +
        ' (' + durationMinutes + ' min)');
      return res.json({
        success: true,
        code: 'AUTHORIZED',
        sessionId,
        minutes: durationMinutes,
        message: 'Payment verified. You are now connected.',
      });
    }

    // ── Case 2: unknown reference → store pending for human verification ──
    const sessionId = 'sess_' + uuidv4().replace(/-/g, '').slice(0, 16);
    const eventId = 'evt_' + uuidv4().replace(/-/g, '').slice(0, 16);
    const now = new Date().toISOString();

    try {
      await db.run(
        `INSERT INTO webhook_events (event_id, ref_no, session_id, provider, event_type, amount, status)
         VALUES (?, ?, ?, 'manual_claim', 'manual_reference_submitted', NULL, 'pending')`,
        [eventId, refNo, sessionId]
      );
    } catch (err) {
      // Concurrent duplicate claim — fall back to the existing pending row.
      if (err.code === '23505' || err.code === 'SQLITE_CONSTRAINT') {
        const existing = await db.getOne(
          'SELECT session_id FROM webhook_events WHERE ref_no = ? LIMIT 1',
          [refNo]
        );
        return res.json({
          success: true,
          pending: true,
          code: 'PENDING_VERIFICATION',
          sessionId: (existing && existing.session_id) || sessionId,
          message: "Thanks! We're verifying your reference number manually. This may take a few minutes.",
        });
      }
      throw err;
    }

    try {
      await db.run(
        `INSERT INTO sessions
           (session_id, client_mac, ref_no, duration_minutes, voucher_type, state, created_at, updated_at)
         VALUES (?, ?, ?, 60, 'paid', 'pending_verification', ?, ?)`,
        [sessionId, clientMac, refNo, now, now]
      );
    } catch (err) {
      if (!(err.code === '23505' || err.code === 'SQLITE_CONSTRAINT')) throw err;
      // sessions.ref_no already exists — reuse that session for the link.
      const existingSession = await db.getOne(
        'SELECT session_id FROM sessions WHERE ref_no = ? LIMIT 1',
        [refNo]
      );
      if (existingSession && existingSession.session_id) {
        await db.run(
          'UPDATE webhook_events SET session_id = ? WHERE ref_no = ?',
          [existingSession.session_id, refNo]
        );
        return res.json({
          success: true,
          pending: true,
          code: 'PENDING_VERIFICATION',
          sessionId: existingSession.session_id,
          message: "Thanks! We're verifying your reference number manually. This may take a few minutes.",
        });
      }
    }

    console.log('[payment/claim] pending manual verification for ' + clientMac + ' ref ' + refNo);
    return res.json({
      success: true,
      pending: true,
      code: 'PENDING_VERIFICATION',
      sessionId,
      message: "Thanks! We're verifying your reference number manually. This may take a few minutes.",
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
