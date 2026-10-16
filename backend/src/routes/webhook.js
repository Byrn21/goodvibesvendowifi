/**
 * routes/webhook.js — payment webhooks
 *
 *   POST /api/webhooks/macrodroid — records an UNCLAIMED voucher entitlement
 *   POST /api/webhooks/instapay   — authorizes the paying device directly via
 *                                   the Omada cloud (InstaPay / PESONet)
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
const omadaNorthbound = require('../services/omada-northbound');
const { normalizeMac } = require('../utils/device-id');
const { computeMinutesFromAmount } = require('../utils/duration');

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

// ================================================================
// InstaPay / PESONet — direct (non-voucher) authorization
// ================================================================
/**
 * POST /api/webhooks/instapay
 *
 * Example handler for a completed InstaPay / PESONet bank transfer. Unlike the
 * MacroDroid route above (which records an entitlement the customer claims
 * later), this flow authorizes the paying device immediately, through the
 * Omada CLOUD Northbound API — no voucher and no inbound reachability to the
 * controller required.
 *
 * Body:
 *   { secret_token, payment_method: 'instapay'|'pesonet', client_mac,
 *     amount, ref_no, duration_minutes? }
 *
 * Unauthenticated by design (the bank's/automation's callback cannot log in),
 * so it is gated on the shared webhook secret compared in constant time.
 *
 * ── WHY THE THREE STEPS BELOW ARE IN THIS ORDER — DO NOT REORDER ──────────
 * authorizeGuest() creates the authentication record on the controller, but the
 * cloud does not index that new record instantly. Calling setClientRateLimit()
 * (a PATCH on /clients/{mac}/ratelimit) in the same tick races the indexer and
 * the controller answers as if the client did not exist yet, so the bandwidth
 * cap is silently never applied. Waiting AUTHORIZE_INDEX_DELAY_MS (exactly
 * 2000 ms) between the two calls is what makes the QoS step reliable.
 *
 * Failure policy: a failed authorization is a 502 (nothing was granted), but a
 * failed rate limit is NOT fatal — the guest is already online, so the response
 * reports `qosApplied: false` for a retry instead of pretending the payment
 * failed.
 *
 * ── TIERED QoS ─────────────────────────────────────────────────────────────
 * The bandwidth cap depends on the payment amount:
 *   amount ∈ PREMIUM_AMOUNTS_PESOS (default 25, 45, 80) → PREMIUM_DOWN_MBPS /
 *                                                         PREMIUM_UP_KBPS
 *   every other amount                                  → VOUCHER_DEFAULT_DOWN_MBPS /
 *                                                         VOUCHER_DEFAULT_UP_KBPS
 * See resolvePremiumAmountsPesos() / resolveCustomRateLimit() for the
 * parsing and range rules.
 */
const AUTHORIZE_INDEX_DELAY_MS = 2000;
const PAYMENT_METHODS = new Set(['instapay', 'pesonet']);

/** Promise-based sleep — keeps the 2000 ms wait awaitable inside the handler. */
function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Premium plan prices (Pesos) used when PREMIUM_AMOUNTS_PESOS is unset.
// Mirrors the portal's premium tier (5h = P25, 12h = P45, 24h = P80).
const DEFAULT_PREMIUM_AMOUNTS_PESOS = [25, 45, 80];

/**
 * Resolve the set of payment amounts (Pesos) treated as the premium tier.
 *
 * PREMIUM_AMOUNTS_PESOS is a comma-separated list, e.g. "25,45,80". Each
 * entry is parsed with parseInt(..., 10); non-integer or non-positive entries
 * are dropped so a typo cannot silently widen the tier. When the variable is
 * unset (or yields no valid entries) the DEFAULT_PREMIUM_AMOUNTS_PESOS list is
 * used instead.
 *
 * @returns {number[]} premium amounts in Pesos
 */
function resolvePremiumAmountsPesos() {
  const raw = process.env.PREMIUM_AMOUNTS_PESOS;
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return DEFAULT_PREMIUM_AMOUNTS_PESOS.slice();
  }

  const parsed = String(raw)
    .split(',')
    .map((part) => parseInt(part.trim(), 10))
    .filter((n) => Number.isInteger(n) && n > 0);

  return parsed.length ? parsed : DEFAULT_PREMIUM_AMOUNTS_PESOS.slice();
}

/**
 * Resolve the mode-0 custom QoS limits for a payment amount.
 *
 * A payment whose amount is one of the PREMIUM_AMOUNTS_PESOS values
 * (default 25, 45, 80) is a premium purchase and gets PREMIUM_DOWN_MBPS /
 * PREMIUM_UP_KBPS. Every other amount returns undefined, which makes
 * setClientRateLimit() apply the operator's VOUCHER_DEFAULT_DOWN_MBPS /
 * VOUCHER_DEFAULT_UP_KBPS defaults.
 *
 * The premium values are parsed with parseInt(..., 10) — the controller rejects
 * a STRING in upLimit/downLimit — and range-checked against the 1–1024 ceiling
 * the OpenAPI documents. When either premium value is unset or out of range, the
 * premium path falls back to the VOUCHER_DEFAULT_* defaults too, so a premium
 * guest is still capped rather than left unlimited.
 *
 * Units mirror the Omada service: down is Mbps (downUnit 2) and up is Kbps
 * (upUnit 1).
 *
 * @param {number|string} amount payment amount in Pesos
 * @returns {Object|undefined} a customRateLimit payload, or undefined to use
 *                             the service defaults
 */
function resolveCustomRateLimit(amount) {
  const premiumAmounts = resolvePremiumAmountsPesos();
  if (!premiumAmounts.includes(Number(amount))) {
    return undefined;
  }

  const downMbps = parseInt(process.env.PREMIUM_DOWN_MBPS, 10);
  const upKbps = parseInt(process.env.PREMIUM_UP_KBPS, 10);
  if (!Number.isInteger(downMbps) || downMbps < 1 || downMbps > 1024) return undefined;
  if (!Number.isInteger(upKbps) || upKbps < 1 || upKbps > 1024) return undefined;

  return {
    upEnable: true,
    upUnit: 1,      // 1 = Kbps
    upLimit: upKbps,
    downEnable: true,
    downUnit: 2,    // 2 = Mbps
    downLimit: downMbps,
  };
}

router.post('/instapay', async (req, res, next) => {
  try {
    const body = req.body || {};
    const { secret_token, amount, ref_no, client_mac, duration_minutes } = body;

    // 1. Shared-secret check (constant time, same helper as the MacroDroid
    //    route). INSTAPAY_WEBHOOK_SECRET is optional; MACRODROID_WEBHOOK_SECRET
    //    is the fallback so this route works without extra configuration.
    if (!secret_token || typeof secret_token !== 'string') {
      return res.status(401).json({ success: false, error: 'Missing secret_token.', code: 'MISSING_SECRET' });
    }
    const expectedSecret = process.env.INSTAPAY_WEBHOOK_SECRET || process.env.MACRODROID_WEBHOOK_SECRET || '';
    if (!expectedSecret || !safeEqual(secret_token, expectedSecret)) {
      return res.status(401).json({ success: false, error: 'Invalid secret.', code: 'INVALID_SECRET' });
    }

    // 2. payment_method — only the two supported rails are accepted.
    const paymentMethod = String(body.payment_method || '').trim().toLowerCase();
    if (!PAYMENT_METHODS.has(paymentMethod)) {
      return res.status(400).json({
        success: false,
        error: 'payment_method must be "instapay" or "pesonet".',
        code: 'INVALID_PAYMENT_METHOD',
      });
    }

    // 3. The paying device — required here (we authorize it directly), unlike
    //    the decoupled MacroDroid route. normalizeMac() accepts any common
    //    format and yields the canonical AA:BB:CC:DD:EE:FF.
    const clientMac = normalizeMac(client_mac);
    if (!clientMac) {
      return res.status(400).json({
        success: false,
        error: 'client_mac is required and must be a valid MAC address.',
        code: 'INVALID_CLIENT_MAC',
      });
    }

    // 4. amount / ref_no — same rules as the MacroDroid route.
    if (amount === undefined || amount === null || !isFinite(Number(amount)) || Number(amount) <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid amount.', code: 'INVALID_AMOUNT' });
    }
    if (!ref_no || typeof ref_no !== 'string' || ref_no.trim().length === 0 || ref_no.length > 64) {
      return res.status(400).json({ success: false, error: 'Invalid ref_no.', code: 'INVALID_REF_NO' });
    }

    // 5. Granted time: an explicit duration_minutes wins, otherwise the same
    //    amount → minutes rate the rest of the app uses.
    const minutes = Number.isInteger(Number(duration_minutes)) && Number(duration_minutes) > 0
      ? Math.floor(Number(duration_minutes))
      : computeMinutesFromAmount(amount);
    if (minutes <= 0) {
      return res.status(400).json({
        success: false,
        error: 'amount is below the minimum chargeable amount.',
        code: 'AMOUNT_TOO_SMALL',
      });
    }

    const db = getDb();
    const refNo = ref_no.trim();

    // Duplicate guard BEFORE any write (UNIQUE index on ref_no is the backstop).
    const existing = await db.getOne('SELECT 1 FROM webhook_events WHERE ref_no = ? LIMIT 1', [refNo]);
    if (existing) {
      return res.status(409).json({ success: false, error: 'Duplicate payment reference.', code: 'DUPLICATE_REF_NO' });
    }

    // 6. Record the payment FIRST, so a cloud/Omada failure never loses the
    //    customer's money. status starts 'unclaimed' and is only advanced to
    //    'authorized' once the guest is actually online (which also keeps this
    //    event out of the voucher-claim pool).
    const eventId = 'evt_' + uuidv4().replace(/-/g, '').slice(0, 16);
    try {
      await db.run(
        `INSERT INTO webhook_events (event_id, ref_no, amount, status, provider, event_type)
         VALUES (?, ?, ?, 'unclaimed', ?, 'payment.completed')`,
        [eventId, refNo, Number(amount), paymentMethod]
      );
    } catch (err) {
      if (err.code === '23505' || err.code === 'SQLITE_CONSTRAINT') {
        return res.status(409).json({ success: false, error: 'Duplicate payment reference.', code: 'DUPLICATE_REF_NO' });
      }
      throw err;
    }

    // ── THE SEQUENCE ────────────────────────────────────────────────────
    // (a) Authorize the guest on the Omada cloud.
    let auth;
    try {
      auth = await omadaNorthbound.authorizeGuest({
        clientMac,
        durationMinutes: minutes,
      });
    } catch (err) {
      await db.run(
        `UPDATE webhook_events SET status = 'auth_failed', processed_at = ? WHERE ref_no = ?`,
        [new Date().toISOString(), refNo]
      );
      console.error(
        '[webhook/instapay] authorization failed for ' + clientMac + ' (ref ' + refNo + '): ' + err.message
      );
      return res.status(502).json({
        success: false,
        error: 'Payment received but Wi-Fi authorization failed. Please contact support.',
        code: 'OMADA_AUTH_FAILED',
      });
    }
    console.log(
      '[webhook/instapay] authorized ' + clientMac + ' for ' + minutes + 'min (' +
      paymentMethod + ', ref ' + refNo + ')'
    );

    // (b) Wait exactly 2000 ms so the cloud indexes the new auth record.
    await delay(AUTHORIZE_INDEX_DELAY_MS);

    // (c) Apply the bandwidth caps. A premium purchase (amount is one of
    //     PREMIUM_AMOUNTS_PESOS) gets the PREMIUM_DOWN_MBPS / PREMIUM_UP_KBPS
    //     limits; every other amount passes no explicit limits so the service
    //     applies VOUCHER_DEFAULT_DOWN_MBPS / VOUCHER_DEFAULT_UP_KBPS.
    let qosApplied = true;
    let qosError = null;
    try {
      const customRateLimit = resolveCustomRateLimit(amount);
      await omadaNorthbound.setClientRateLimit(
        customRateLimit ? { clientMac, customRateLimit } : { clientMac }
      );
      console.log(
        '[webhook/instapay] rate limit applied to ' + clientMac +
        (customRateLimit ? ' (premium tier)' : ' (default tier)')
      );
    } catch (err) {
      qosApplied = false;
      qosError = err.message;
      // The guest is already authorized — a failed cap must not be reported as
      // a failed payment. Surface it so the operator can re-apply it.
      console.error('[webhook/instapay] authorized but rate limit failed for ' + clientMac + ': ' + err.message);
    }

    await db.run(
      `UPDATE webhook_events SET status = 'authorized', processed_at = ? WHERE ref_no = ?`,
      [new Date().toISOString(), refNo]
    );

    return res.json({
      success: true,
      clientMac,
      minutes,
      authRecordId: auth.authRecordId || null,
      qosApplied,
      ...(qosApplied ? {} : { qosError }),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
