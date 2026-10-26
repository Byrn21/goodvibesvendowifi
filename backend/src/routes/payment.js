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
const { computeMinutesFromAmount } = require('../utils/duration');
const { resolveCustomRateLimit } = require('../utils/qos');
const omadaNorthbound = require('../services/omada-northbound');
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

// ── Mobile number (PH format) ───────────────────────────────────────────
// An 11-digit Philippine mobile number: 09 followed by 9 digits. This is the
// same rule the portal enforces client-side, restated here because it decides
// whether the customer can be texted the code they paid for — a value the
// client must never be trusted to guarantee.
const MOBILE_RE = /^09\d{9}$/;

// The Omada cloud does not index a brand-new auth record instantly, so a QoS
// PATCH sent in the same tick races the indexer and is silently dropped (the
// same constraint documented on the InstaPay route). Exactly 2000 ms.
const AUTHORIZE_INDEX_DELAY_MS = 2000;

/** Promise-based sleep — keeps the index wait awaitable inside the handler. */
function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * fireSmsWebhook — hand the claimed voucher to MacroDroid so it can text the
 * customer their code.
 *
 * Deliberately NOT awaited: the claim is already committed and the code is
 * already on its way to the caller, so an unreachable or slow SMS endpoint must
 * never turn a successful claim into an error response. Failures are logged
 * (without the destination number — that is customer PII and does not belong in
 * application logs).
 *
 * Every field travels in the URL query string (there is NO request body), so a
 * MacroDroid macro can pull the values straight out of the request URL for its
 * variable whitelist. Undefined/null fields are omitted entirely rather than
 * serialised as "undefined"/"null".
 *
 * @param {Object} payload fields to encode into the query string
 */
function fireSmsWebhook(payload) {
  const baseUrl = process.env.MACRODROID_SMS_WEBHOOK_URL;
  if (!baseUrl) return;
  try {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(payload)) {
      if (value === undefined || value === null) continue;
      params.append(key, String(value));
    }
    // Keep any query string the operator already configured on the endpoint
    // (e.g. ?secret=abc) and append ours after it.
    const separator = !baseUrl.includes('?') ? '?' : /[?&]$/.test(baseUrl) ? '' : '&';
    const url = baseUrl + separator + params.toString();

    fetch(url, {
      method: 'POST',
    }).then((res) => {
      if (res && res.ok) {
        console.log('[payment/claim] SMS webhook accepted for ref ' + payload.ref_no);
      } else {
        console.error('[payment/claim] SMS webhook returned HTTP ' + (res && res.status) + ' for ref ' + payload.ref_no);
      }
    }).catch((err) => {
      console.error('[payment/claim] SMS webhook failed for ref ' + payload.ref_no + ': ' + (err && err.message));
    });
  } catch (err) {
    // A synchronous throw (e.g. a malformed MACRODROID_SMS_WEBHOOK_URL) must
    // not escape into the response path either.
    console.error('[payment/claim] SMS webhook could not be dispatched for ref ' + payload.ref_no + ': ' + (err && err.message));
  }
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
 * Body: { ref_suffix, mobile_number, client_mac?, ap_mac? }
 *   ref_suffix    — exactly 4 digits (the last 4 of the customer's receipt)
 *   mobile_number — 11-digit PH mobile (09XXXXXXXXX); REQUIRED
 *   client_mac    — the device to authorize. Optional: without it the claim
 *                   still succeeds, it just is not auto-connected
 *   ap_mac        — recorded for traceability only; the cloud authorize call
 *                   is keyed on the client MAC alone
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
 * Once the claim is committed, the paying device is authorized DIRECTLY
 * through the Omada cloud — authorizeGuest → 2000 ms index wait →
 * setClientRateLimit — so the customer does not have to type a code at all.
 *
 * `minutes` is the claimed voucher's own `duration_minutes` (a plain integer,
 * already in minutes) — never a value derived from the payment amount, which
 * cannot know whether the voucher was a 1-minute or a 1-hour plan.
 *
 * Returns:
 *   200 { success: true, authorized: true, message: 'Device authorized',
 *         voucherCode, ref_no, minutes, qosApplied }
 *   200 { success: true, authorized: false, voucherCode, ref_no, minutes,
 *         authError }  — no client_mac was supplied, or the claimed voucher
 *                          carries no usable duration. The code is still
 *                          returned so the customer can connect manually.
 *   502 { success: false, authorized: false, code: 'OMADA_AUTH_FAILED',
 *         voucherCode, ref_no }  — Omada refused. The claim is deliberately
 *                          NOT rolled back: the customer's entitlement is
 *                          kept and the code is returned for a manual connect.
 *
 * voucherCode is still returned even when the device is authorized — it keeps
 * the payment↔voucher ledger intact and gives a manual fallback, so the portal
 * can stop SHOWING it without the backend losing the audit trail.
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

    // mobile_number — required: it is the only way the customer can be texted
    // the code they just paid for, so a claim without it would leave them with
    // a voucher they have no way to discover.
    const mobileNumber = typeof body.mobile_number === 'string' ? body.mobile_number.trim() : '';
    if (!MOBILE_RE.test(mobileNumber)) {
      return res.status(400).json({
        success: false,
        error: 'mobile_number is required and must be an 11-digit Philippine mobile number (e.g. 09171234567).',
        code: 'INVALID_MOBILE_NUMBER',
      });
    }

    // client_mac — required for the DIRECT AUTHORIZATION below, but not for the
    // claim itself. An older portal build, or a device whose Omada context
    // never reached the beacon, still gets its voucher code; it simply is not
    // auto-connected. A malformed value is still a client bug worth a 400.
    const clientMac = parseMac(body.client_mac);
    if (body.client_mac !== undefined && body.client_mac !== null && body.client_mac !== '' && !clientMac) {
      return res.status(400).json({
        success: false,
        error: 'client_mac must be a valid MAC address.',
        code: 'INVALID_CLIENT_MAC',
      });
    }

    // ap_mac — recorded for traceability in the logs only. The Omada CLOUD
    // authorize call is keyed on the client MAC alone, unlike the local
    // extPortal/auth path which needs the AP/SSID/radio triple.
    const apMac = parseMac(body.ap_mac);

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

        // duration_minutes is the voucher's ENTITLEMENT: it is the number of
        // minutes the customer actually bought (e.g. 1 for a 1-minute voucher,
        // 60 for a 1-hour voucher), stored as a plain integer. It is NOT
        // milliseconds and must never be divided by 60000 — it is already the
        // exact total-minutes value the session, Omada and the SMS report.
        const voucher = await tx.getOne(
          `SELECT id, code, duration_minutes FROM vouchers
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
              SET status = 'claimed', mobile_number = ?, processed_at = ?
            WHERE ref_no = ? AND status = 'unclaimed'`,
          [mobileNumber, new Date().toISOString(), event.ref_no]
        );
        if (eventUpdate.rowCount === 0) {
          // Another request claimed this payment first — roll the voucher back.
          throw httpError(404, 'PAYMENT_NOT_FOUND', 'Payment not found or already claimed.');
        }

        return {
          voucherCode: voucher.code,
          refNo: event.ref_no,
          amount: Number(event.amount),
          durationMinutes: voucher.duration_minutes,
        };
      });
    } catch (err) {
      if (err.code === 'PAYMENT_NOT_FOUND' || err.code === 'NO_VOUCHER_AVAILABLE') {
        return res.status(err.status || 404).json({ success: false, error: err.message, code: err.code });
      }
      throw err;
    }

    // ── Direct MAC authorization (Omada cloud) ───────────────────────────
    // The claim above is ALREADY COMMITTED, so the customer's payment is
    // reconciled to a voucher no matter what Omada does next. That is
    // deliberate: an authorization failure must never also cost them the
    // entitlement their money bought (it is reported as authorized:false, with
    // the code still returned so they can connect manually).
    // The granted time comes from the VOUCHER's duration_minutes — the thing
    // that was actually sold — not from the amount. Deriving it from the amount
    // rounded a 1-minute voucher down to 0 when its price was below one whole
    // PESOS_PER_MINUTE unit, and reported 5 minutes for a 1-hour voucher.
    // duration_minutes is already an integer number of minutes, so it is used
    // as-is; the amount-derived rate is only a fallback for a voucher row with
    // no usable duration.
    const voucherMinutes = Math.floor(Number(claim.durationMinutes));
    const minutes = Number.isFinite(voucherMinutes) && voucherMinutes > 0
      ? voucherMinutes
      : computeMinutesFromAmount(claim.amount);
    let authAttempted = false;
    let authorized = false;
    let authError = null;
    let qosApplied = null;
    let qosError = null;

    if (clientMac && minutes > 0) {
      authAttempted = true;
      try {
        await omadaNorthbound.authorizeGuest({ clientMac, durationMinutes: minutes });
        authorized = true;
        console.log(
          '[payment/claim] authorized ' + clientMac + ' for ' + minutes + 'min' +
          ' (ref ' + claim.refNo + ', ap ' + (apMac || 'unknown') + ')'
        );
      } catch (err) {
        authError = err && err.message ? err.message : String(err);
        console.error(
          '[payment/claim] authorization failed for ' + clientMac +
          ' (ref ' + claim.refNo + '): ' + authError
        );
      }
    } else if (clientMac) {
      authError = 'amount is below the minimum chargeable amount';
    } else {
      authError = 'no client_mac was supplied with the claim';
    }

    // The SMS is dispatched as soon as the authorization OUTCOME is known but
    // BEFORE the QoS index wait below (the long pole), so the customer is texted
    // about 2 s sooner. It reports whether the device was authorized; the
    // bandwidth cap applied afterwards is not part of the customer's message.
    //
    // NOTE ON THE QUERY PARAMETERS: `voucher_code` carries the REAL 6-digit voucher code
    // (the thing the customer needs), not the 4-digit ref_suffix — `ref_suffix`
    // is included separately for correlation. Both are present, so a MacroDroid
    // macro expecting either key works.
    fireSmsWebhook({
      target_number: mobileNumber,
      voucher_code: claim.voucherCode,
      ref_suffix: refSuffix,
      ref_no: claim.refNo,
      authorized,
      minutes,
      ...(process.env.BASE_URL
        ? { status_link: String(process.env.BASE_URL).replace(/\/+$/, '') + '/status.html' }
        : {}),
    });

    // ── Bandwidth caps (best-effort) ─────────────────────────────────────
    // A premium purchase (amount ∈ PREMIUM_AMOUNTS_PESOS) gets the premium caps;
    // every other amount passes no explicit limits so the service applies
    // VOUCHER_DEFAULT_DOWN_MBPS / VOUCHER_DEFAULT_UP_KBPS. Mirrors the InstaPay
    // route, including the index wait — the tier rules themselves are shared
    // through utils/qos.js.
    if (authorized) {
      await delay(AUTHORIZE_INDEX_DELAY_MS);
      try {
        const customRateLimit = resolveCustomRateLimit(claim.amount);
        await omadaNorthbound.setClientRateLimit(
          customRateLimit ? { clientMac, customRateLimit } : { clientMac }
        );
        qosApplied = true;
        console.log(
          '[payment/claim] rate limit applied to ' + clientMac +
          (customRateLimit ? ' (premium tier)' : ' (default tier)')
        );
      } catch (err) {
        // The guest is already online, so a failed cap is NOT a failed claim.
        qosApplied = false;
        qosError = err && err.message ? err.message : String(err);
        console.error('[payment/claim] authorized but rate limit failed for ' + clientMac + ': ' + qosError);
      }
    }

    // Omada refused the authorization: the claim stands, the device is NOT
    // online. This is a genuine error, reported as one — while still handing
    // back the code so the customer is not stranded with nothing.
    if (authAttempted && !authorized) {
      return res.status(502).json({
        success: false,
        authorized: false,
        code: 'OMADA_AUTH_FAILED',
        error: 'Payment received but Wi-Fi authorization failed. Please contact support.',
        voucherCode: claim.voucherCode,
        ref_no: claim.refNo,
      });
    }

    console.log('[payment/claim] claimed voucher ' + claim.voucherCode + ' for ref ' + claim.refNo);

    return res.json({
      success: true,
      authorized,
      message: authorized ? 'Device authorized' : 'Voucher claimed. Enter the code to connect.',
      voucherCode: claim.voucherCode,
      ref_no: claim.refNo,
      minutes,
      ...(authorized ? { qosApplied } : {}),
      ...(qosError ? { qosError } : {}),
      ...(authError ? { authError } : {}),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
