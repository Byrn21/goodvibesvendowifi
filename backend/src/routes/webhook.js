/**
 * routes/webhook.js — POST /api/webhooks/macrodroid
 *
 * Receives a payment notification from MacroDroid after an e-wallet
 * payment completes, grants Wi-Fi time based on the amount paid, and
 * authorizes the paying device on the Omada controller.
 *
 * Request body:
 *   { secret_token, amount, ref_no, mac_address }
 *
 * Flow (order matters):
 *   1. Validate presence/format of all fields
 *   2. Constant-time secret comparison → 401 on mismatch
 *   3. DB-level duplicate rejection on ref_no → 409
 *   4. Compute minutes granted from MACRODROID_PESOS_PER_MINUTE
 *   5. Record webhook_events + pending session (DB writes first)
 *   6. Call Omada authenticateClient → 502 on controller error
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const omadaService = require('../services/omada');
const { getDb } = require('../db/client');
const { normalizeMac } = require('../utils/device-id');
const { v4: uuidv4 } = require('uuid');

// ── Rate constant (named + documented, per audit plan) ─────────────────
// Minutes of Wi-Fi time granted per whole unit of currency received.
// Now centralized in src/config/index.js alongside other business
// constants (PORTAL_CONTEXT_MAX_AGE_MS, OMADA_TIME_UNIT).
const { PESOS_PER_MINUTE, PORTAL_CONTEXT_MAX_AGE_MS } = require('../config');

/**
 * Constant-time string comparison — avoids leaking the secret through
 * response timing on prefix mismatches.
 */
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a || ''), 'utf8');
  const bufB = Buffer.from(String(b || ''), 'utf8');
  if (bufA.length !== bufB.length) {
    // Still do a comparison of equal-length dummies to keep timing flat
    crypto.timingSafeEqual(Buffer.alloc(32), Buffer.alloc(32));
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function computeMinutes(amount) {
  // Whole units of currency → whole minutes (floor). Zero/negative → 0.
  const units = Math.floor(Number(amount));
  if (!isFinite(units) || units <= 0) return 0;
  return Math.floor(units / PESOS_PER_MINUTE);
}

// ── Route ───────────────────────────────────────────────────────────────

router.post('/macrodroid', async (req, res, next) => {
  try {
    const { secret_token, amount, ref_no, mac_address } = req.body || {};

    // 1. Field presence / format validation
    if (!secret_token || typeof secret_token !== 'string') {
      return res.status(401).json({ success: false, error: 'Missing secret_token.', code: 'MISSING_SECRET' });
    }
    if (amount === undefined || amount === null || !isFinite(Number(amount)) || Number(amount) <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid amount.', code: 'INVALID_AMOUNT' });
    }
    if (!ref_no || typeof ref_no !== 'string' || ref_no.trim().length === 0 || ref_no.length > 64) {
      return res.status(400).json({ success: false, error: 'Invalid ref_no.', code: 'INVALID_REF_NO' });
    }
    const normalizedMac = normalizeMac(mac_address);
    if (!normalizedMac) {
      return res.status(400).json({ success: false, error: 'Invalid mac_address.', code: 'INVALID_MAC' });
    }

    // 2. Constant-time secret check
    const expected = process.env.MACRODROID_WEBHOOK_SECRET || '';
    if (!expected || !safeEqual(secret_token, expected)) {
      return res.status(401).json({ success: false, error: 'Invalid secret.', code: 'INVALID_SECRET' });
    }

    const db = getDb();
    const refNo = ref_no.trim();

    // 3. DB-level duplicate rejection on ref_no (before any writes)
    const existing = await db.getOne(
      'SELECT 1 FROM webhook_events WHERE ref_no = ? LIMIT 1',
      [refNo]
    );
    if (existing) {
      return res.status(409).json({ success: false, error: 'Duplicate payment reference.', code: 'DUPLICATE_REF_NO' });
    }

    // 4. Compute time allocation
    const minutes = computeMinutes(amount);
    if (minutes <= 0) {
      return res.status(400).json({ success: false, error: 'Amount too small to grant any time.', code: 'INSUFFICIENT_AMOUNT' });
    }

    const eventId = 'evt_' + uuidv4().replace(/-/g, '').slice(0, 16);
    const sessionId = 'sess_' + uuidv4().replace(/-/g, '').slice(0, 16);
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + minutes * 60 * 1000).toISOString();
    // 5. DB writes first — webhook event + pending session.
    // The UNIQUE constraint on webhook_events.ref_no is the authoritative
    // duplicate guard; a race that slips past the SELECT lands here.
    try {
      await db.run(
        `INSERT INTO webhook_events (event_id, ref_no, session_id, provider, event_type, amount, status)
         VALUES (?, ?, ?, 'macrodroid', 'payment_received', ?, 'processed')`,
        [eventId, refNo, sessionId, Math.floor(Number(amount))]
      );
    } catch (err) {
      if (err.code === '23505' || err.code === 'SQLITE_CONSTRAINT') {
        return res.status(409).json({ success: false, error: 'Duplicate payment reference.', code: 'DUPLICATE_REF_NO' });
      }
      throw err;
    }

    await db.run(
      `INSERT INTO sessions (
        session_id, client_mac, ref_no, duration_minutes, voucher_type,
        started_at, expires_at, state, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'paid', ?, ?, 'pending_payment', ?, ?)`,
      [sessionId, normalizedMac, refNo, minutes, now, expiresAt, now, now]
    );

    // 6. Resolve portal client context (AP/SSID/radio captured at portal
    // landing by POST /api/payment/context), then authorize on the controller.
    // Fail loud: missing / partial / stale context are ALL treated as missing —
    // authenticateClient is never called with null controller params.
    //
    // Operational note (MISSING_PORTAL_CONTEXT):
    //   - The payment is durable (webhook_events + sessions rows exist) and the
    //     session is flagged omada_auth_failed = 1 (visible in the admin panel).
    //   - This route responds 422 (NOT 502) — retrying cannot succeed; the
    //     CUSTOMER-side fix is to re-open the captive portal page (which
    //     refreshes context via the landing beacon) and pay again with a new
    //     ref_no. The failed session never activated, so no time is consumed.
    //   - MacroDroid's HTTP Request action has a failure branch on non-2xx:
    //     configure it to show a phone notification ("payment failed: customer
    //     must reopen portal") so the operator notices immediately.
    //   - Log tag MISSING_PORTAL_CONTEXT is greppable for auditing.
    const contextRow = await db.getOne(
      `SELECT client_ip, ap_mac, ssid_name, radio_id, site, seen_at
         FROM portal_client_context WHERE client_mac = ?`,
      [normalizedMac]
    );

    let contextReason = null;
    if (!contextRow) {
      contextReason = 'no portal_client_context row for ' + normalizedMac;
    } else if (!contextRow.ap_mac || !contextRow.ssid_name || contextRow.radio_id === null || contextRow.radio_id === undefined) {
      contextReason = 'partial context row (ap_mac/ssid_name/radio_id missing) for ' + normalizedMac;
    } else {
      const ageMs = Date.now() - new Date(contextRow.seen_at).getTime();
      if (ageMs > PORTAL_CONTEXT_MAX_AGE_MS) {
        contextReason = 'context stale (age ' + Math.floor(ageMs / 1000) + 's > max ' +
          Math.floor(PORTAL_CONTEXT_MAX_AGE_MS / 1000) + 's) for ' + normalizedMac;
      }
    }

    if (contextReason) {
      console.error('[webhook/macrodroid] MISSING_PORTAL_CONTEXT for ' + normalizedMac + ' ref ' + refNo + ': ' + contextReason);
      await db.run(
        `UPDATE sessions SET omada_auth_failed = 1, updated_at = ? WHERE session_id = ?`,
        [new Date().toISOString(), sessionId]
      );
      return res.status(422).json({
        success: false,
        error: 'Payment recorded but portal context (AP/SSID/radio) is missing or stale. ' +
               'Client must re-open the captive portal page and pay again.',
        code: 'MISSING_PORTAL_CONTEXT',
      });
    }

    // 7. Omada authorization call (after DB writes — payment record is
    // durable even if the controller call fails; admin can retry)
    try {
      await omadaService.authenticateClient({
        clientMac: normalizedMac,
        clientIp: contextRow.client_ip || '',
        apMac: contextRow.ap_mac,
        ssidName: contextRow.ssid_name,
        radioId: contextRow.radio_id,
        durationMinutes: minutes,
        sessionId,
      });
    } catch (omadaErr) {
      console.error('[webhook/macrodroid] Omada auth failed for ref ' + refNo + ':', omadaErr.message);
      await db.run(
        `UPDATE sessions SET omada_auth_failed = 1, updated_at = ? WHERE session_id = ?`,
        [new Date().toISOString(), sessionId]
      );
      return res.status(502).json({
        success: false,
        error: 'Payment recorded but controller authorization failed.',
        code: 'OMADA_ERROR',
      });
    }

    await db.run(
      `UPDATE sessions SET state = 'active', updated_at = ? WHERE session_id = ?`,
      [new Date().toISOString(), sessionId]
    );

    return res.json({ success: true, message: 'Payment accepted, session activated.', sessionId, minutes });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

