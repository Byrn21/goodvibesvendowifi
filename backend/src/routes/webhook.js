/**
 * routes/webhook.js — POST /api/webhooks/macrodroid
 *
 * Receives a payment notification from MacroDroid after an e-wallet
 * payment completes and records it as an UNCLAIMED voucher entitlement.
 *
 * This route is deliberately decoupled from the Omada controller and from
 * the client's MAC address: the customer claims the voucher later from the
 * captive portal by entering the last 4 digits of their reference number
 * (see POST /api/payment/claim). No device context is captured here.
 *
 * Request body:
 *   { secret_token, amount, ref_no }
 *   (mac_address, if still sent by MacroDroid, is ignored.)
 *
 * Flow (order matters):
 *   1. Validate presence/format of all fields
 *   2. Constant-time secret comparison → 401 on mismatch
 *   3. DB-level duplicate rejection on ref_no → 409
 *   4. Insert webhook_events row with status = 'unclaimed'
 *
 * UNITS: webhook_events.amount is stored in standard Pesos (e.g. 50 or
 * 50.50), matching the MacroDroid payload. vouchers.price is integer
 * centavos. The Pesos → centavos conversion happens ONCE, in the claim
 * route — never assume the units match.
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { getDb } = require('../db/client');
const { v4: uuidv4 } = require('uuid');

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

// ── Route ───────────────────────────────────────────────────────────────

router.post('/macrodroid', async (req, res, next) => {
  try {
    const { secret_token, amount, ref_no } = req.body || {};

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

    // 2. Constant-time secret check
    const expected = process.env.MACRODROID_WEBHOOK_SECRET || '';
    if (!expected || !safeEqual(secret_token, expected)) {
      return res.status(401).json({ success: false, error: 'Invalid secret.', code: 'INVALID_SECRET' });
    }

    const db = getDb();
    const refNo = ref_no.trim();

    // 3. DB-level duplicate rejection on ref_no (before any write).
    // The UNIQUE constraint on webhook_events.ref_no is the authoritative
    // guard; a race that slips past the SELECT lands in the catch below.
    const existing = await db.getOne(
      'SELECT 1 FROM webhook_events WHERE ref_no = ? LIMIT 1',
      [refNo]
    );
    if (existing) {
      return res.status(409).json({ success: false, error: 'Duplicate payment reference.', code: 'DUPLICATE_REF_NO' });
    }

    // 4. Record the unclaimed entitlement. The claim route later reconciles
    // it against a pre-imported voucher of the matching price.
    const eventId = 'evt_' + uuidv4().replace(/-/g, '').slice(0, 16);
    try {
      await db.run(
        `INSERT INTO webhook_events (event_id, ref_no, amount, status)
         VALUES (?, ?, ?, 'unclaimed')`,
        [eventId, refNo, Number(amount)]
      );
    } catch (err) {
      if (err.code === '23505' || err.code === 'SQLITE_CONSTRAINT') {
        return res.status(409).json({ success: false, error: 'Duplicate payment reference.', code: 'DUPLICATE_REF_NO' });
      }
      throw err;
    }

    return res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
