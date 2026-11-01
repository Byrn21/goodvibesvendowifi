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
const {
  normalizeBandwidthKbps,
  normalizeVoucherType,
  resolveCustomRateLimit,
} = require('../utils/qos');
const omadaService = require('../services/omada');
const { recordSession } = require('../services/session');
const { loadPortalContext, resolveClientMacByIp } = require('../utils/portal-context');
const { setSessionCookie } = require('../utils/session-token');
const { macroDroidVerifyUrl, PENDING_CLAIM_TTL_MS } = require('../config');
const { listPaymentMethodStates } = require('../services/payment-methods');
const { v4: uuidv4 } = require('uuid');
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
  // Env-overridable like the other limits so a deployment (or the test suite,
  // which exercises dozens of claims) can tune it without editing code.
  max: parseInt(process.env.CLAIM_RATE_LIMIT_MAX || '30', 10),
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

// The controller does not always expose a just-authorized client to the
// client/QoS endpoints in the same tick, so a QoS PATCH sent immediately is
// silently dropped (the same constraint documented on the InstaPay route).
// Exactly 2000 ms.
const AUTHORIZE_INDEX_DELAY_MS = 2000;

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

// ── MacroDroid screen-scrape verification ───────────────────────────────
// How long the portal waits between GET /api/payment/claim/status polls while
// the Android handset reads the e-wallet screen. Returned to the caller as
// `retryAfterMs` so the browser and the backend cannot disagree.
const CLAIM_VERIFICATION_POLL_MS = 3000;

// A verification GET that has not been answered after this long is abandoned.
// It is fire-and-forget (the customer is already holding a 202), so a hanging
// socket must not keep the process alive.
const MACRODROID_VERIFY_TIMEOUT_MS = 10000;

/**
 * normalizeRequestedTier — the tier the customer asked for, if any.
 *
 * The claim modal sends only the 4 digits and the mobile number today, so this
 * is normally null and the tier is decided by the voucher MacroDroid finds.
 * When a portal build does send one it is stored on the pending claim so the
 * verification callback and any support lookup can see what was promised.
 *
 * @param {*} value
 * @returns {'standard'|'premium'|null}
 */
function normalizeRequestedTier(value) {
  if (typeof value !== 'string') return null;
  const tier = value.trim().toLowerCase();
  return tier === 'standard' || tier === 'premium' ? tier : null;
}

/**
 * fireVerificationRequest — ask the MacroDroid handset to read the receipt.
 *
 * Fire-and-forget on purpose: the claim is already parked as 'pending' and the
 * customer has already been answered with a 202, so an offline handset must not
 * turn that into an error. Its eventual answer arrives out of band at
 * POST /api/webhooks/macrodroid/verify-result.
 *
 * The reference suffix is the only thing logged — the mobile number is customer
 * PII and never belongs in application logs.
 *
 * @param {string} url verification URL from config.macroDroidVerifyUrl()
 * @param {string} refSuffix last 4 digits of the reference
 */
function fireVerificationRequest(url, refSuffix) {
  try {
    const options = { method: 'GET' };
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
      options.signal = AbortSignal.timeout(MACRODROID_VERIFY_TIMEOUT_MS);
    }
    fetch(url, options).then((res) => {
      if (res && res.ok) {
        console.log('[payment/claim] MacroDroid accepted the verification request for suffix ' + refSuffix);
      } else {
        console.error(
          '[payment/claim] MacroDroid verification returned HTTP ' +
          (res && res.status) + ' for suffix ' + refSuffix
        );
      }
    }).catch((err) => {
      console.error(
        '[payment/claim] MacroDroid verification failed for suffix ' + refSuffix + ': ' +
        ((err && err.message) || String(err))
      );
    });
  } catch (err) {
    // A synchronous throw (unreachable/malformed URL) must not escape into the
    // response path: the pending claim simply expires if nothing answers.
    console.error(
      '[payment/claim] MacroDroid verification could not be dispatched for suffix ' +
      refSuffix + ': ' + ((err && err.message) || String(err))
    );
  }
}

/**
 * beginPendingVerification — park an unmatched claim and ask MacroDroid to look.
 *
 * Returns null when MACRODROID_IP is not configured: the deployment has no way
 * to check the screen, so the claim keeps the original 404 behaviour instead of
 * hanging the customer on a spinner nobody will resolve.
 *
 * A retry (dropped response, double tap) reuses the newest still-open pending
 * claim for the same digits + mobile + MAC rather than starting a second
 * screen-scrape, and refreshes its TTL.
 *
 * @param {{db: Object, refSuffix: string, mobileNumber: string,
 *          clientMac: string|null, requestedTier: string|null}} ctx
 * @returns {Promise<{claimId: string, expiresAt: string}|null>}
 */
async function beginPendingVerification(ctx) {
  const { db, refSuffix, mobileNumber, clientMac, requestedTier } = ctx;
  const verifyUrl = macroDroidVerifyUrl(refSuffix, clientMac);
  if (!verifyUrl) return null;

  const now = new Date();
  const nowIso = now.toISOString();
  const expiresAt = new Date(now.getTime() + PENDING_CLAIM_TTL_MS).toISOString();

  // Two identifier variants rather than `client_mac IS ?`: PostgreSQL does not
  // accept a placeholder after IS, and a device with no MAC must still be able
  // to reopen its own claim.
  const macClause = clientMac ? 'client_mac = ?' : 'client_mac IS NULL';
  const params = clientMac ? [refSuffix, mobileNumber, clientMac, nowIso] : [refSuffix, mobileNumber, nowIso];
  const existing = await db.getOne(
    `SELECT claim_id FROM pending_claims
      WHERE state = 'pending' AND ref_suffix = ? AND mobile_number = ?
        AND ` + macClause + `
        AND (expires_at IS NULL OR expires_at > ?)
      ORDER BY id DESC LIMIT 1`,
    params
  );

  if (existing) {
    await db.run(
      `UPDATE pending_claims
          SET expires_at = ?, updated_at = ?
        WHERE claim_id = ?`,
      [expiresAt, nowIso, existing.claim_id]
    );
    fireVerificationRequest(verifyUrl, refSuffix);
    return { claimId: existing.claim_id, expiresAt };
  }

  const claimId = 'clm_' + uuidv4().replace(/-/g, '').slice(0, 16);
  await db.run(
    `INSERT INTO pending_claims
       (claim_id, ref_suffix, client_mac, mobile_number, requested_tier,
        state, created_at, updated_at, expires_at)
     VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)`,
    [claimId, refSuffix, clientMac, mobileNumber, requestedTier, nowIso, nowIso, expiresAt]
  );

  fireVerificationRequest(verifyUrl, refSuffix);
  return { claimId, expiresAt };
}

/**
 * applyRateLimitAfterResponse — apply the bandwidth cap AFTER the claim has
 * already been answered.
 *
 * The claim is committed before the customer is answered, so every millisecond
 * the handler spends after the commit is a chance for the connection to die
 * (captive-portal mini browser, a proxy in front of the backend, a host restart)
 * and leave the customer looking at a failed claim whose payment is already
 * consumed — the next tap then answers "Payment not found or already claimed".
 * The 2000 ms pre-QoS wait is the longest piece of that tail, so the response
 * is sent first and the cap is applied afterwards. The wait itself is still
 * required: Omada does not index the new auth record instantly, and a cap PATCH
 * sent in the same tick is silently dropped (see the InstaPay route).
 *
 * Deliberately NOT awaited and never throws: the response is already sent and
 * the guest is already authorized, so a failed or rejected cap is logged only.
 *
 * @param {{clientMac: string, amount: number, refNo: string}} ctx
 */
function applyRateLimitAfterResponse(ctx) {
  const { clientMac, amount, refNo } = ctx;

  const logFailure = (err) => {
    console.error(
      '[payment/claim] authorized but rate limit failed for ' + clientMac +
      ' (ref ' + refNo + '): ' + ((err && err.message) || String(err))
    );
  };

  const timer = setTimeout(() => {
    try {
      const customRateLimit = resolveCustomRateLimit(amount);
      omadaService
        .setClientRateLimit(customRateLimit ? { clientMac, customRateLimit } : { clientMac })
        .then(() => {
          console.log(
            '[payment/claim] rate limit applied to ' + clientMac +
            (customRateLimit ? ' (premium tier)' : ' (default tier)') +
            ' (ref ' + refNo + ')'
          );
        })
        .catch(logFailure);
    } catch (err) {
      // A synchronous throw (bad tier config, a mock returning no promise) must
      // not escape a timer callback: it would crash the process after the
      // customer already has their voucher.
      logFailure(err);
    }
  }, AUTHORIZE_INDEX_DELAY_MS);

  // Do not let this best-effort timer keep the process alive on its own (the
  // HTTP server already does); it also keeps test teardown clean.
  if (timer && typeof timer.unref === 'function') timer.unref();
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
 * `enabled` is the ADMIN-CONTROLLED availability flag (payment_methods table,
 * toggled from the admin panel's Payment Methods settings). It is separate
 * from the receiver details: a disabled method keeps its name/QR here so the
 * portal can render the tile greyed out with a "Temporarily Unavailable"
 * badge instead of silently dropping the option. A method with no row is
 * reported as enabled, so an unmigrated database keeps every option working.
 *
 * `logoBase64` is an optional admin-uploaded logo (a complete data URI) stored
 * in the same table. When it is null the portal keeps the bundled asset
 * (assets/images/<method>.png).
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

async function buildPaymentMethods() {
  const states = await listPaymentMethodStates();
  const byKey = {};
  states.forEach((state) => { byKey[state.key] = state; });
  const stateOf = (key) => byKey[key] || {};

  return {
    gcash: {
      name: 'GCash',
      enabled: stateOf('gcash').enabled !== false,
      // Admin-uploaded logo (data URI) or null when the bundled asset is used.
      // The portal swaps <img src> when this is present; the receiver details
      // below are unrelated and always come from the environment.
      logoBase64: stateOf('gcash').logoBase64 || null,
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
      enabled: stateOf('maya').enabled !== false,
      logoBase64: stateOf('maya').logoBase64 || null,
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
      enabled: stateOf('qrph').enabled !== false,
      logoBase64: stateOf('qrph').logoBase64 || null,
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
    // Cash has no QR code or receiver account: the guest selects it, reads the
    // counter instructions and claims a voucher. Only the admin-controlled
    // availability flag and the optional custom logo apply, so the cash tile
    // can be greyed out and branded like every other method.
    cash: {
      name: 'Cash',
      enabled: stateOf('cash').enabled !== false,
      logoBase64: stateOf('cash').logoBase64 || null,
    },
  };
}

router.get('/methods', async (req, res, next) => {
  try {
    // Payment details are configurable and mostly static, but never cache them
    // in shared/proxy storage: an operator can rotate the receiver details, and
    // an admin can disable a method, at any time.
    res.set('Cache-Control', 'no-store');
    return res.json(await buildPaymentMethods());
  } catch (err) {
    next(err);
  }
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
 *   ap_mac        — recorded for traceability only; the authorization uses the
 *                   AP/SSID/radio context captured by POST /api/payment/context
 *
 * Behaviour (in this order):
 *   1. Find the newest 'unclaimed' webhook_events row whose ref_no ends
 *      with ref_suffix → 404 'Payment not found or already claimed'.
 *   2. Convert the recorded amount from PESOS to CENTAVOS (webhook_events
 *      stores Pesos; vouchers.price stores centavos — never assume they match).
 *   3. Find one 'active', unassigned voucher whose price matches those
 *      centavos → 404 'No voucher available for this amount'.
 *   4. Authorize the paying device DIRECTLY through the controller web API
 *      (omadaService.authenticateClient, on the portal context captured at
 *      landing; a device with no fresh context is a 502 MISSING_PORTAL_CONTEXT
 *      and must reload the portal once). Steps 1–4 are READ-ONLY, so a refusal
 *      consumes nothing: the reference stays claimable and the same 4 digits
 *      can be retried instead of answering 'already claimed' on the second
 *      attempt.
 *   5. Only once the device is authorized (or no authorization was needed)
 *      atomically mark the voucher 'claimed' (recording the FULL ref_no in
 *      assigned_ref_no) AND the event 'claimed'. Any failure rolls BOTH
 *      back, so a voucher is never claimed without its event (or vice versa).
 *
 * If no UNCLAIMED payment matches, a payment that is already claimed by the
 * SAME mobile number is replayed (step 1b): its voucher code and minutes come
 * back with a 200 and `alreadyClaimed: true`, and nothing is authorized, written
 * or texted. That is what makes a dropped connection harmless — the result of a
 * first tap whose response never arrived can be fetched again with the same two
 * credentials instead of the customer being told their paid reference is gone.
 *
 * After the commit the customer is answered IMMEDIATELY (the SMS dispatch is
 * synchronous fire-and-forget). The 2000 ms index wait and setClientRateLimit
 * (best-effort QoS) then run AFTER the response has been sent, so no slow
 * post-commit work can delay — or, if the connection drops, swallow — the one
 * response that tells the customer their payment became a voucher.
 *
 * `minutes` is the claimed voucher's own `duration_minutes` (a plain integer,
 * already in minutes) — never a value derived from the payment amount, which
 * cannot know whether the voucher was a 1-minute or a 1-hour plan.
 *
 * Returns:
 *   200 { success: true, authorized: true, message: 'Device authorized',
 *         voucherCode, ref_no, minutes }  — the bandwidth cap is applied
 *                          afterwards; its outcome is logged, not returned.
 *   200 { success: true, authorized: false, voucherCode, ref_no, minutes,
 *         authError }  — no client_mac was supplied, or the claimed voucher
 *                          carries no usable duration. The code is still
 *                          returned so the customer can connect manually.
 *   200 { success: true, authorized: false, alreadyClaimed: true,
 *         voucherCode, ref_no, minutes }  — this payment was already claimed by
 *                          the SAME mobile number, so the voucher it produced
 *                          is replayed. Nothing is authorized, consumed, or
 *                          texted again.
 *   502 { success: false, authorized: false, code: 'OMADA_AUTH_FAILED',
 *         error }  — Omada refused. NOTHING was written (no voucher consumed,
 *                          no payment marked claimed, no SMS sent), so the same
 *                          reference can be claimed again.
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

/**
 * findClaimedEntitlement — the idempotent-retry lookup.
 *
 * A claim can be committed and then never reach the phone (the connection drops
 * while the handler finishes, a proxy or the host restarts, the captive-portal
 * mini browser is torn down). The payment is spent, so a retry used to answer
 * "Payment not found or already claimed" and the code was only recoverable
 * through support.
 *
 * This returns the newest CLAIMED payment ending in the same 4 digits whose
 * stored mobile number is the one the caller supplied, together with the voucher
 * that claim assigned to it. The caller replays that voucher; nothing is
 * authorized, written or texted.
 *
 * The mobile number is what makes this safe: it is exactly what the original
 * claim required, so a retry proves the same two things (the ref digits and the
 * number that paid). A claimed row with no stored number (older rows, or one
 * claimed before the field was saved) never matches — there is nothing to compare
 * against, so the caller keeps the generic 404 instead of handing a code to
 * whoever guessed the digits.
 *
 * @param {Object} db
 * @param {string} refSuffix last 4 digits of the payment reference
 * @param {string} mobileNumber the 11-digit number supplied with the retry
 * @returns {Promise<{refNo: string, voucherCode: string, minutes: number}|null>}
 */
async function findClaimedEntitlement(db, refSuffix, mobileNumber) {
  const event = await db.getOne(
    `SELECT ref_no, amount FROM webhook_events
      WHERE status = 'claimed' AND ref_no LIKE ? AND mobile_number = ?
      ORDER BY id DESC LIMIT 1`,
    ['%' + refSuffix, mobileNumber]
  );
  if (!event) return null;

  // The voucher this claim consumed carries the FULL reference in
  // assigned_ref_no — that is the link back, not the 4-digit suffix.
  const voucher = await db.getOne(
    `SELECT code, duration_minutes FROM vouchers
      WHERE assigned_ref_no = ?
      ORDER BY id DESC LIMIT 1`,
    [event.ref_no]
  );
  if (!voucher) return null;

  // Same rule as the first claim: the voucher's own duration wins, with the
  // amount rate only as a fallback for a row with no usable duration.
  const voucherMinutes = Math.floor(Number(voucher.duration_minutes));
  const minutes = Number.isFinite(voucherMinutes) && voucherMinutes > 0
    ? voucherMinutes
    : computeMinutesFromAmount(Number(event.amount));

  return { refNo: event.ref_no, voucherCode: voucher.code, minutes };
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

    // client_mac — the DIRECT AUTHORIZATION target. The portal page sends the
    // MAC it read from the controller's portal URL (or restored from
    // localStorage), and that EXPLICIT value wins: behind the cloud tunnel
    // req.ip is the tunnel's public address while the landing beacon recorded
    // the guest's LAN address, so the address reverse-lookup finds nothing.
    // Only a claim that carries no MAC at all is resolved from req.ip — the
    // LAN-direct case, where the address really is the client.
    //
    // Validation is strict: a malformed explicit value is a 400, and a valid
    // variant (dashes, no separators, lowercase) is sanitized to the canonical
    // AA:BB:CC:DD:EE:FF form before it is logged, stored or handed to
    // extPortal/auth. The claim itself does not depend on it: an older portal
    // build, or a device whose Omada context never reached the beacon, still
    // gets its voucher code — it simply is not auto-connected.
    let clientMac = parseMac(body.client_mac);
    const explicitMacSupplied =
      body.client_mac !== undefined && body.client_mac !== null && body.client_mac !== '';
    if (explicitMacSupplied && !clientMac) {
      return res.status(400).json({
        success: false,
        error: 'client_mac must be a valid MAC address.',
        code: 'INVALID_CLIENT_MAC',
      });
    }
    let macSource = clientMac ? 'body' : null;
    if (!clientMac) {
      try {
        const resolved = await resolveClientMacByIp(req.ip);
        clientMac = parseMac(resolved.clientMac);
        if (clientMac) macSource = 'ip';
      } catch (err) {
        // No portal context for this address (normal behind the tunnel until
        // the page supplies a MAC): the claim proceeds without a direct
        // authorization, exactly as it did before.
        console.log(
          '[payment/claim] no client_mac in body and none resolved from ip ' +
          String(req.ip || '(none)') + ': ' +
          (err && err.message ? err.message : String(err))
        );
      }
    }

    // ap_mac — recorded for traceability in the logs only. The Omada CLOUD
    // authorize call is keyed on the client MAC alone, unlike the local
    // extPortal/auth path which needs the AP/SSID/radio triple.
    const apMac = parseMac(body.ap_mac);

    // One line per attempt, written BEFORE anything is read or written. Without
    // it a failed tap leaves no server-side trace at all (the failure paths used
    // to log nothing), so "the portal said it could not verify the payment"
    // cannot be matched to a request in the logs. The mobile number is NOT
    // logged — it is customer PII.
    console.log(
      '[payment/claim] attempt suffix=' + refSuffix +
      ' client_mac=' + (clientMac || '(none)') +
      ' client_mac_source=' + (macSource || 'none') +
      ' ap_mac=' + (apMac || '(none)')
    );

    const db = getDb();

    // ── 1. Locate the payment and the voucher that pays for it ───────────
    // Both lookups are READ-ONLY: nothing is consumed until step 3, after the
    // authorization has been decided.
    const event = await db.getOne(
      `SELECT ref_no, amount FROM webhook_events
        WHERE status = 'unclaimed' AND ref_no LIKE ?
        ORDER BY id DESC LIMIT 1`,
      ['%' + refSuffix]
    );
    if (!event) {
      // ── 1b. Already claimed by THIS customer? Replay it ─────────────────
      // The first tap may have committed and then lost its response (dropped
      // connection, host restart, proxy timeout). Same 4 digits + same mobile
      // number is exactly the proof the first claim required, so the code that
      // payment already produced is handed back — without a second voucher, a
      // second authorization, or a second SMS.
      const replay = await findClaimedEntitlement(db, refSuffix, mobileNumber);
      if (replay) {
        console.log(
          '[payment/claim] idempotent retry: ref ' + replay.refNo +
          ' was already claimed by this mobile — replaying voucher ' +
          replay.voucherCode + ' (' + replay.minutes + 'min); nothing consumed'
        );
        return res.json({
          success: true,
          authorized: false,
          alreadyClaimed: true,
          message: 'This payment was already claimed. Here is the same voucher code.',
          voucherCode: replay.voucherCode,
          ref_no: replay.refNo,
          minutes: replay.minutes,
        });
      }

      // ── 1c. Ask MacroDroid to read the receipt ─────────────────────────
      // The webhook is best-effort: a notification the handset never forwarded,
      // or one that arrived without a reference, leaves a real, paid receipt
      // with no webhook_events row. When the screen-scrape channel is
      // configured, the claim is parked as 'pending' and the handset is asked
      // to check the last 4 digits on the e-wallet screen; the portal polls
      // GET /api/payment/claim/status and finishes the claim when it answers.
      //
      // Nothing is consumed here: no voucher is assigned and no payment row is
      // written until the verification callback confirms a real payment.
      const pending = await beginPendingVerification({
        db,
        refSuffix,
        mobileNumber,
        clientMac,
        requestedTier: normalizeRequestedTier(body.tier || body.requested_tier),
      });

      if (!pending) {
        // No verification channel: the original verdict stands. 404 = no
        // UNCLAIMED payment carries these digits, and no CLAIMED one carries
        // them for this mobile number — either the webhook never recorded the
        // payment, it was claimed by someone else, or it was claimed before the
        // mobile number was stored. Nothing was consumed, so this line is the
        // whole audit trail of the tap.
        console.warn(
          '[payment/claim] no claimable payment ends with ' + refSuffix +
          ' for this mobile — nothing consumed (webhook not received yet, already' +
          ' claimed by another number, or no number stored on the claim)'
        );
        return res.status(404).json({
          success: false,
          error: 'Payment not found or already claimed.',
          code: 'PAYMENT_NOT_FOUND',
        });
      }

      console.log(
        '[payment/claim] pending verification ' + pending.claimId +
        ' for suffix ' + refSuffix + ' (client_mac ' + (clientMac || '(none)') + ')'
      );
      return res.status(202).json({
        success: true,
        pending: true,
        state: 'pending',
        claimId: pending.claimId,
        ref_suffix: refSuffix,
        message: 'We are checking your payment on the receipt. This can take a few seconds.',
        retryAfterMs: CLAIM_VERIFICATION_POLL_MS,
        expiresAt: pending.expiresAt,
      });
    }

    // CRITICAL: webhook_events.amount is Pesos; vouchers.price is centavos.
    const amountCentavos = Math.round(Number(event.amount) * 100);

    // duration_minutes is the voucher's ENTITLEMENT: it is the number of
    // minutes the customer actually bought (e.g. 1 for a 1-minute voucher,
    // 60 for a 1-hour voucher), stored as a plain integer. It is NOT
    // milliseconds and must never be divided by 60000 — it is already the
    // exact total-minutes value the session, Omada and the SMS report.
    const voucher = await db.getOne(
      `SELECT id, code, type, duration_minutes, down_kbps, up_kbps FROM vouchers
        WHERE state = 'active' AND assigned_ref_no IS NULL AND price = ?
        ORDER BY id ASC LIMIT 1`,
      [amountCentavos]
    );
    if (!voucher) {
      console.warn(
        '[payment/claim] no active unassigned voucher priced ' + amountCentavos +
        ' centavos for ref ' + event.ref_no + ' (suffix ' + refSuffix + ') — nothing consumed'
      );
      return res.status(404).json({
        success: false,
        error: 'No voucher is available for this amount. Please contact support.',
        code: 'NO_VOUCHER_AVAILABLE',
      });
    }

    // The granted time comes from the VOUCHER's duration_minutes — the thing
    // that was actually sold — not from the amount. Deriving it from the amount
    // rounded a 1-minute voucher down to 0 when its price was below one whole
    // PESOS_PER_MINUTE unit, and reported 5 minutes for a 1-hour voucher.
    // duration_minutes is already an integer number of minutes, so it is used
    // as-is; the amount-derived rate is only a fallback for a voucher row with
    // no usable duration.
    const voucherMinutes = Math.floor(Number(voucher.duration_minutes));
    const minutes = Number.isFinite(voucherMinutes) && voucherMinutes > 0
      ? voucherMinutes
      : computeMinutesFromAmount(Number(event.amount));

    // ── 2. Authorize the device BEFORE anything is written ───────────────
    // The claim used to be committed first, so an Omada refusal burned the
    // customer's reference: the retry answered 'Payment not found or already
    // claimed' and only support could help. Authorizing first means a refusal
    // consumes nothing — the event stays 'unclaimed' and the voucher stays
    // 'active' and unassigned — so tapping Claim again is a REAL retry, which
    // normally succeeds once the device is associated on the controller.
    let authAttempted = false;
    let authorized = false;
    let authError = null;
    let authErrorCode = null;
    // Kept beyond the try below: the session recorded after the commit reuses
    // the exact controller context the authorization was built from.
    let portalContext = null;

    if (clientMac && minutes > 0) {
      authAttempted = true;
      try {
        const portal = await loadPortalContext(clientMac);
        portalContext = portal;
        const auth = await omadaService.authenticateClient({
          clientMac,
          clientIp: portal.clientIp,
          apMac: portal.apMac,
          ssidName: portal.ssidName,
          radioId: portal.radioId,
          durationMinutes: minutes,
        });
        // Fail closed: the controller is the only authority on whether the
        // guest is really authorized, so an unconfirmed answer is a failure.
        if (!auth || auth.success !== true) {
          const err = new Error('the controller did not confirm the authorization');
          err.code = 'OMADA_AUTH_NOT_CONFIRMED';
          throw err;
        }
        authorized = true;
        console.log(
          '[payment/claim] authorized ' + clientMac + ' for ' + minutes + 'min' +
          ' (ref ' + event.ref_no + ', ap ' + (apMac || portal.apMac) + ')'
        );
      } catch (err) {
        authError = (err && err.message) ? err.message : String(err);
        authErrorCode = (err && err.code) || null;
        console.error(
          '[payment/claim] authorization failed for ' + clientMac +
          ' (ref ' + event.ref_no + '): ' +
          ((err && err.code) ? err.code + ' — ' : '') + authError
        );
      }
    } else if (clientMac) {
      authError = 'the voucher carries no usable duration, so no session time could be granted';
    } else {
      authError = 'no client_mac was supplied with the claim';
    }

    // Omada refused: nothing has been written, so the same 4-digit reference
    // can be claimed again and no SMS is sent for a code that was never
    // consumed. This is the one failure that must not burn the payment.
    //
    // A missing/stale portal context is called out separately: the controller
    // was never asked, and the customer can fix it themselves by reloading the
    // captive portal page (which refreshes the context beacon) and claiming
    // again.
    if (authAttempted && !authorized) {
      const contextMissing = authErrorCode === 'MISSING_PORTAL_CONTEXT';
      return res.status(502).json({
        success: false,
        authorized: false,
        code: contextMissing ? 'MISSING_PORTAL_CONTEXT' : 'OMADA_AUTH_FAILED',
        error: contextMissing
          ? 'Open the Wi-Fi portal page once, then tap Claim again so this device can be connected.'
          : 'Payment received but the Wi-Fi authorization failed. Please tap Claim again.',
      });
    }

    // ── 3. Commit the claim — the only write in this handler ─────────────
    // Conditional updates keep the consume atomic against a concurrent claim
    // (or a double tap): rowCount 0 rolls the whole transaction back, so a
    // voucher is never claimed without its event (or vice versa).
    let claim;
    try {
      claim = await db.transaction(async (tx) => {
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

        // ── Record the granted session ──────────────────────────────────
        // /api/auth records a session when a voucher is redeemed. A claim never
        // goes through that route (it authorizes the MAC on the controller
        // itself), so without this insert the guest would hold a live Omada
        // authorization that no local row accounts for: /api/session/status
        // would answer SESSION_NOT_FOUND for the very device that paid, the
        // expiration worker would never sweep the session, and Pause/Resume
        // would have nothing to act on.
        //
        // Written INSIDE this transaction, immediately after the authorization
        // has been accepted, so a session row exists exactly when the claim
        // committed: if the conditional updates above roll back, this insert
        // rolls back with them and no orphan session is left for a payment that
        // was never claimed.
        let sessionId = null;
        if (authorized) {
          sessionId = 'sess_' + uuidv4().replace(/-/g, '').slice(0, 16);
          await recordSession({
            sessionId,
            clientMac,
            // The controller connection context the authorization used, so a
            // later re-authorization / pause rebuilds the same request.
            clientIp: portalContext ? portalContext.clientIp : '',
            apMac: (portalContext && portalContext.apMac) || apMac || '',
            ssidName: portalContext ? portalContext.ssidName : '',
            duration: minutes,                 // minutes, never seconds
            voucherUsed: voucher.code,
            voucherType: normalizeVoucherType(voucher.type),
            // NULL (tier/default caps) unless the voucher carries its own pair,
            // matching what a voucher login records.
            downKbps: normalizeBandwidthKbps(voucher.down_kbps),
            upKbps: normalizeBandwidthKbps(voucher.up_kbps),
            totalDurationSeconds: minutes * 60,
          }, tx);
        }

        return { voucherCode: voucher.code, refNo: event.ref_no, sessionId };
      });
    } catch (err) {
      if (err.code === 'PAYMENT_NOT_FOUND' || err.code === 'NO_VOUCHER_AVAILABLE') {
        console.warn(
          '[payment/claim] commit rolled back for ref ' + event.ref_no +
          ' (' + err.code + '): ' + err.message + ' — nothing consumed'
        );
        return res.status(err.status || 404).json({ success: false, error: err.message, code: err.code });
      }
      throw err;
    }

    // The claim is COMMITTED from here on: the customer's money is reconciled
    // to a voucher. Nothing below may turn this into an error response.
    //
    // The response goes out BEFORE the QoS step below (the 2000 ms index wait is
    // the longest thing in this handler). A committed claim whose response is
    // lost — the tab/proxy/host gives up while the handler is still sleeping —
    // is exactly how a reference gets "burned": the customer sees a failure, and
    // the retry answers "Payment not found or already claimed" even though the
    // first attempt succeeded. Answering first removes that window.
    //
    // The SMS is dispatched here too (synchronously fire-and-forget): it reports
    // whether the device was authorized, and the bandwidth cap applied after the
    // response is not part of the customer's message.
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

    console.log(
      '[payment/claim] claimed voucher ' + claim.voucherCode + ' for ref ' + claim.refNo +
      ' (session ' + (claim.sessionId || '(none)') + ')'
    );

    // Identify this browser for the session the claim just granted. The status
    // page then works from the cookie alone, even when the captive mini-browser
    // starts with empty storage and the request arrives from a public carrier
    // or tunnel address that matches no portal_client_context row.
    const statusToken = claim.sessionId
      ? setSessionCookie(req, res, claim.sessionId)
      : null;

    res.json({
      success: true,
      authorized,
      message: authorized ? 'Device authorized' : 'Voucher claimed. Enter the code to connect.',
      voucherCode: claim.voucherCode,
      ref_no: claim.refNo,
      minutes,
      sessionId: claim.sessionId || null,
      statusToken: statusToken || null,
      ...(authError ? { authError } : {}),
    });

    // ── Bandwidth caps (best-effort, AFTER the response) ─────────────────
    // A premium purchase (amount ∈ PREMIUM_AMOUNTS_PESOS) gets the premium caps;
    // every other amount passes no explicit limits so the service applies
    // VOUCHER_DEFAULT_DOWN_MBPS / VOUCHER_DEFAULT_UP_KBPS. Mirrors the InstaPay
    // route, including the index wait — the tier rules themselves are shared
    // through utils/qos.js. Its outcome is logged only: the response has already
    // been sent, the guest is already online, and a failed cap is NOT a failed
    // claim.
    if (authorized) {
      applyRateLimitAfterResponse({ clientMac, amount: Number(event.amount), refNo: claim.refNo });
    }
  } catch (err) {
    next(err);
  }
});

// ── Pending verification status ────────────────────────────────────────
/**
 * GET /api/payment/claim/status?claimId=…
 *
 * The polling endpoint behind the "verifying your payment" spinner. It reports
 * the pending claim's state and, once the payment has been verified and the
 * customer's retried claim produced a voucher, the voucher itself.
 *
 *   pending  — MacroDroid has not answered yet; poll again after retryAfterMs
 *   verified — the payment is now recorded as 'unclaimed'; the portal re-sends
 *              POST /api/payment/claim to convert it into the voucher
 *   claimed  — a voucher exists for that payment; voucherCode/minutes are set
 *   failed   — MacroDroid could not confirm the payment (see reason)
 *   expired  — no answer within PENDING_CLAIM_TTL_MS; let the customer retry
 *
 * UNAUTHENTICATED like the claim itself, but the claimId is a random opaque
 * token, so a poll cannot be used to enumerate other customers' claims. It is
 * read-only apart from expiring the row it was asked about.
 */
router.get('/claim/status', async (req, res, next) => {
  try {
    const claimId = typeof req.query.claimId === 'string' ? req.query.claimId.trim() : '';
    if (!/^clm_[A-Za-z0-9]{8,32}$/.test(claimId)) {
      return res.status(400).json({
        success: false,
        error: 'claimId is required.',
        code: 'INVALID_CLAIM_ID',
      });
    }

    const db = getDb();
    const claim = await db.getOne(
      `SELECT claim_id, ref_suffix, client_mac, mobile_number, requested_tier,
              state, ref_no, amount, failure_reason, expires_at
         FROM pending_claims
        WHERE claim_id = ?`,
      [claimId]
    );
    if (!claim) {
      return res.status(404).json({
        success: false,
        error: 'There is no verification in progress for this claim.',
        code: 'CLAIM_NOT_FOUND',
      });
    }

    const now = Date.now();
    let state = claim.state;

    // Expire lazily: there is no worker for pending claims, and the only thing
    // that ever reads them is this poll (or the callback, which checks the
    // deadline itself).
    if (state === 'pending' && claim.expires_at && Date.parse(claim.expires_at) <= now) {
      state = 'expired';
      await db.run(
        `UPDATE pending_claims SET state = 'expired', updated_at = ?
          WHERE claim_id = ? AND state = 'pending'`,
        [new Date(now).toISOString(), claimId]
      );
    }

    const payload = {
      success: true,
      claimId,
      state,
      ref_suffix: claim.ref_suffix,
      requested_tier: claim.requested_tier || null,
      expiresAt: claim.expires_at || null,
    };

    // A verified claim is only half the story: the portal completes it by
    // re-sending POST /api/payment/claim, and the voucher it produced carries
    // this payment's full reference in assigned_ref_no. Reporting 'claimed'
    // here means a reload (or a second tab) sees the finished result instead of
    // a spinner that will never move.
    if (state === 'verified' && claim.ref_no) {
      // The mobile number is part of the lookup for the same reason the
      // idempotent retry in POST /claim requires it: a voucher must never be
      // shown to someone who merely guessed the same 4 digits. A payment
      // claimed by a DIFFERENT number stays 'verified' here and the customer's
      // retried claim gets the generic failure instead.
      const voucher = await db.getOne(
        `SELECT v.code, v.duration_minutes
           FROM webhook_events e
           JOIN vouchers v ON v.assigned_ref_no = e.ref_no
          WHERE e.ref_no = ? AND e.status = 'claimed' AND e.mobile_number = ?
          ORDER BY v.id DESC LIMIT 1`,
        [claim.ref_no, claim.mobile_number]
      );
      if (voucher) {
        state = 'claimed';
        payload.state = 'claimed';
        payload.voucherCode = voucher.code;
        const minutes = Math.floor(Number(voucher.duration_minutes));
        payload.minutes = Number.isFinite(minutes) && minutes > 0 ? minutes : null;
        await db.run(
          `UPDATE pending_claims SET state = 'claimed', updated_at = ?
            WHERE claim_id = ? AND state = 'verified'`,
          [new Date(now).toISOString(), claimId]
        );
      }
    }

    if (state === 'failed' && claim.failure_reason) {
      payload.reason = claim.failure_reason;
    }
    if (state === 'verified' && claim.ref_no) {
      payload.ref_no = claim.ref_no;
      payload.amount = claim.amount;
    }

    // Poll answers must never be cached by a proxy or the captive WebView.
    res.set('Cache-Control', 'no-store');
    return res.json(payload);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
