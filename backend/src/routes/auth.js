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
const {
  validateVoucher,
  consumeVoucher,
  recordSession,
  getSession,
  resumeSession,
  reauthorizeSession,
  expireSession,
  getSessionByVoucher,
  isPausableVoucherType,
  applySessionRateLimit,
} = require('../services/session');
const { normalizeVoucherCode, validateVoucherCodeFormat } = require('../utils/voucher-code');
const { normalizeMac: normalizeDeviceMac, isSameMac } = require('../utils/device-id');
const { resolveClientMacByIp } = require('../utils/portal-context');
const { getDb } = require('../db/client');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

// POST /api/auth
router.post('/', async (req, res, next) => {
  // First statement in the handler: proves the browser actually reached the
  // backend when the guest taps Submit. If the portal fails before the
  // request is sent (blocked fetch, captive mini-browser navigation, a JS
  // error), this line never appears in the server logs — which is itself the
  // signal. The voucher itself is NEVER logged (still a live credential).
  //
  // PRIMITIVE-ONLY payload: a single plain string built from scalars. The
  // `req`/`res` objects (and their graphs — body, headers, socket,
  // connection) are NEVER handed to the logger: winston would retain the
  // reference, and a circular object graph held for the process lifetime is
  // a memory leak on a long-lived server. Each value is coerced with
  // String()/Boolean() so even a malformed client body (e.g. clientMac sent
  // as an object) cannot put a non-primitive into the message.
  logger.info(
    '[auth] POST /api/auth HIT — ip=' + String(req.ip || '(unknown)') +
    ' clientMac=' + String((req.body && req.body.clientMac) || '(none)') +
    ' voucherPresent=' + String(Boolean(req.body && req.body.voucher)) +
    ' contentType=' + String((req.headers && req.headers['content-type']) || '(none)') +
    ' origin=' + String((req.headers && req.headers.origin) || '(none)')
  );

  try {
    // `let` (not const) so the context-enrichment step below can fill in
    // ssidName / radioId when the body omitted them; the rest stays read-only.
    let {
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

    // ── Device identity: explicit MAC first, request address second ────────
    // The portal page sends the MAC it read from the controller's portal URL
    // (or restored from localStorage) as `clientMac`. That value is the only
    // reliable identity when the portal is reached through a cloud tunnel:
    // req.ip is then the tunnel's PUBLIC address while the landing beacon
    // recorded the guest's LAN address, so the reverse lookup finds nothing.
    //
    // Priority: body clientMac (client_mac accepted as an alias) → the device
    // that landed on the portal from req.ip. The explicit value is stripped to
    // hex and re-emitted in the canonical AA:BB:CC:DD:EE:FF form, or rejected
    // with 400 when it is present but malformed — nothing unvalidated ever
    // reaches extPortal/auth.
    const rawClientMac = firstProvidedMac(clientMac, req.body && req.body.client_mac);
    let normalizedMac = rawClientMac ? normalizeDeviceMac(rawClientMac) : null;
    if (rawClientMac && !normalizedMac) {
      return res.status(400).json({ success: false, error: 'Invalid client MAC address.', code: 'INVALID_MAC' });
    }
    if (!normalizedMac) {
      // No explicit MAC: identify the device by the address it reached the
      // portal from. This is the LAN-direct case, where req.ip IS the client.
      try {
        const resolved = await resolveClientMacByIp(req.ip);
        if (resolved.stale) {
          // The address once belonged to a device whose context is older than
          // the freshness window; DHCP may have handed it to someone else, so
          // binding this voucher to that MAC would authorize the wrong guest.
          // Proceed unidentified — the same outcome as having no fallback.
          logger.warn(
            '[auth] refusing stale portal context for ip ' + String(req.ip || '(none)') +
            ' (device ' + String(resolved.clientMac || '(none)') + ') — ' +
            'no clientMac in body; the voucher is not bound to that device'
          );
        } else {
          normalizedMac = normalizeDeviceMac(resolved.clientMac);
          logger.info(
            '[auth] no clientMac in body — resolved ' + String(normalizedMac || '(none)') +
            ' from ip ' + String(req.ip || '(none)')
          );
        }
      } catch (err) {
        logger.warn(
          '[auth] no clientMac in body and none resolved from ip ' +
          String(req.ip || '(none)') + ': ' + (err && err.message ? err.message : String(err))
        );
      }
    }

    // AP / gateway MACs are the identifiers Omada put in the portal URL and
    // expects back in the extPortal/auth body, so send them in the same
    // canonical form (uppercase, colon-separated). Invalid values are passed
    // through unchanged (Omada rejects them) rather than 400'ing here.
    let normalizedApMac = apMac ? (normalizeDeviceMac(apMac) || String(apMac).trim()) : '';
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

    // ── Re-login with an already-'used' voucher (Premium pause/resume) ──
    // Pause is tracked on the SESSION row, not the voucher, so a code whose
    // session is still 'paused' is a resume — not a fresh redemption. This
    // runs BEFORE validateVoucher, which would otherwise reject the 'used'
    // voucher as "already used" and never let the guest back online.
    const existingVoucher = await getDb().getOne(
      'SELECT state, used_by_mac FROM vouchers WHERE code = ? LIMIT 1',
      [normalizedVoucher]
    );
    if (existingVoucher && existingVoucher.state === 'used') {
      const outcome = await resumeUsedVoucher(
        normalizedVoucher, normalizedMac, existingVoucher.used_by_mac, redirectUrl
      );
      return res.status(outcome.status).json(outcome.body);
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

    // ── Context enrichment from the portal landing record ────────────────
    // extPortal/auth is connection-type specific: Omada will not accept the
    // authorization without apMac + ssidName + radioId for a wireless client.
    // The form normally submits them, but a body that omits them (or sends
    // null) would otherwise reach the controller incomplete and be rejected.
    // Fill ONLY the missing fields from the most recent context the landing
    // beacon stored for this MAC; anything the client did supply is never
    // overwritten. Best-effort: a missing/legacy table must not fail the login.
    const missingApMac = !normalizedApMac;
    const missingSsidName = !ssidName || String(ssidName).trim() === '';
    const missingRadioId = rawRadioId === undefined || rawRadioId === null || String(rawRadioId).trim() === '';
    if (normalizedMac && (missingApMac || missingSsidName || missingRadioId)) {
      try {
        const ctxRow = await getDb().getOne(
          `SELECT ap_mac, ssid_name, radio_id
             FROM portal_client_context
            WHERE client_mac = ?
            ORDER BY seen_at DESC LIMIT 1`,
          [normalizedMac]
        );
        if (ctxRow) {
          if (missingApMac && ctxRow.ap_mac) {
            normalizedApMac = normalizeDeviceMac(ctxRow.ap_mac) || String(ctxRow.ap_mac).trim();
          }
          if (missingSsidName && ctxRow.ssid_name) {
            ssidName = String(ctxRow.ssid_name).trim();
          }
          if (missingRadioId && ctxRow.radio_id !== null && ctxRow.radio_id !== undefined) {
            const ctxRadioId = parseInt(ctxRow.radio_id, 10);
            if (Number.isInteger(ctxRadioId) && ctxRadioId >= 0 && ctxRadioId <= 255) {
              rawRadioId = ctxRadioId;
            }
          }
        }
      } catch (ctxErr) {
        // Legacy DBs may predate the context table, and a lookup failure is not
        // a reason to refuse a voucher — proceed with what the client sent.
        logger.warn(
          '[auth] portal context lookup failed for ' + String(normalizedMac || '(none)') +
          ': ' + (ctxErr && ctxErr.message ? ctxErr.message : String(ctxErr))
        );
      }
    }

    // ── Call Omada extPortal/auth ──────────────────────────
    // The portal URL already carries the controller's connection context
    // (radioId, gatewayMac, vid, ...). Prefer the radioId submitted by the
    // form (or recovered above from the landing record); fall back to the
    // portal_client_context captured at landing, then 0.
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
          // Bandwidth snapshot, so every later re-auth/resume re-applies the
          // exact cap this code carries (NULL = tier/default caps).
          downKbps: voucherResult.downKbps,
          upKbps: voucherResult.upKbps,
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

    // ── Bandwidth (QoS) cap ─────────────────────────────────────────────
    // The extPortal/auth body carries NO bandwidth fields (TP-Link's External
    // Portal Server spec defines only clientMac/clientIp/apMac/ssidName/radioId
    // (or gatewayMac/vid)/site/time/authType, and an unknown field can make
    // firmware reject the authorization entirely). Omada applies a guest cap
    // through the separate documented call `updateClientRateLimitSetting`, so
    // that is what runs here — exactly like the payment webhook and claim
    // routes. The values come from this voucher's own caps, then the premium
    // tier, then the operator defaults (see utils/qos.js).
    //
    // Best-effort: the guest is ALREADY authorized by the controller and the
    // voucher is spent, so a failed cap must never turn a successful login into
    // an error. The response reports the outcome for the operator.
    const qos = await applySessionRateLimit({
      clientMac: normalizedMac,
      downKbps: voucherResult.downKbps,
      upKbps: voucherResult.upKbps,
      voucherType: voucherTypeResolved,
    });

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

    // ── Post-commit read-back: prove the active session is really stored ──
    // The transaction above either committed voucher+session together or threw
    // (in which case we answered 409/500 above), so the row must exist here.
    // Reading it back is the verification step AND the source of the timing
    // fields the success page renders: success.html shows the countdown from
    // the value the database holds, not from a number recomputed in this
    // handler. If the read-back somehow fails we still answer success — Omada
    // already authorized the client and the voucher is spent, so reporting an
    // error here would strand a guest who is actually online — but the failure
    // is logged loudly instead of being hidden.
    let storedSession = null;
    try {
      storedSession = await getSession(sessionId);
    } catch (readErr) {
      console.error(
        '[auth] post-commit read-back failed for session ' + sessionId + ': ' +
        (readErr && readErr.message ? readErr.message : String(readErr))
      );
    }
    if (!storedSession) {
      console.error(
        '[auth] post-commit verification FAILED — session ' + sessionId +
        ' (client ' + normalizedMac + ') is not readable after commit;' +
        ' the client is authorized on Omada but /api/session/status will 404.'
      );
    }

    const sessionStartedAt = (storedSession && storedSession.startedAt)
      || new Date().toISOString();
    const sessionExpiresAt = (storedSession && storedSession.expiresAt)
      || new Date(Date.now() + duration * 60 * 1000).toISOString();
    const sessionRemainingSeconds = storedSession && storedSession.expiresAt
      ? Math.max(0, Math.floor((new Date(storedSession.expiresAt).getTime() - Date.now()) / 1000))
      : duration * 60;
    const sessionTotalSeconds = (storedSession && storedSession.totalDurationSeconds)
      || duration * 60;

    if (storedSession && storedSession.state !== 'active') {
      console.warn(
        '[auth] session ' + sessionId + ' read back with state "' +
        storedSession.state + '" (expected "active")'
      );
    }

    return res.json({
      success: true,
      message: 'Authentication successful.',
      sessionId,
      // Echo the canonical device identity so the success/status pages can keep
      // querying the session by MAC even when the sessionId is lost.
      clientMac: (storedSession && storedSession.clientMac) || normalizedMac,
      redirectUrl: finalRedirectUrl,
      // Session timing, read back from the committed row. success.html renders
      // its "time remaining" from these values, so the countdown matches
      // Supabase the moment the page loads (instead of waiting for a poll and
      // showing “—”).
      startedAt: sessionStartedAt,
      expiresAt: sessionExpiresAt,
      durationMinutes: duration,
      totalSeconds: sessionTotalSeconds,
      // Whether the bandwidth cap was actually applied to this client. false =
      // the guest is online but UNCAPPED (check the server logs: OMADA_ADMIN_*
      // credentials / mock mode / controller rejection).
      qosApplied: qos.applied,
      qosMock: qos.mock === true,
      ...(qos.applied ? {} : { qosError: qos.error || 'rate limit not applied' }),
      session: {
        state: (storedSession && storedSession.state) || 'active',
        remainingSeconds: sessionRemainingSeconds,
        voucherType: (storedSession && storedSession.voucherType) || voucherTypeResolved,
        clientMac: (storedSession && storedSession.clientMac) || normalizedMac,
        startedAt: sessionStartedAt,
        expiresAt: sessionExpiresAt,
        totalSeconds: sessionTotalSeconds,
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

/**
 * resumeUsedVoucher — Handle POST /api/auth for a voucher that is already
 * 'used' (i.e. it was redeemed once and still has a session row).
 *
 * Pause/resume state lives on the SESSION row, not the voucher, so re-entering
 * a 'used' code is a re-login with two distinct cases:
 *
 *   1. ACTIVE (still counting down) on the SAME device — the device merely
 *      lost its firewall authorization (captive mini-browser reopened, Wi-Fi
 *      dropped, OS re-probe), NOT an error. We replay the Omada extPortal/auth
 *      call for the REMAINING time and return a NORMAL success so the portal
 *      lands on success.html and the guest regains access.
 *   2. PAUSED (Premium only) — resume from the frozen remaining time.
 *
 * Standard plans run continuously and never pause, but a still-ACTIVE session
 * on the SAME device is re-authorized for BOTH tiers (case 1) so a Standard
 * guest who drops off can reconnect; only the PAUSED resume (case 2) is
 * Premium-only. In every case the requesting device must match the MAC the
 * voucher was first bound to (vouchers.used_by_mac, falling back to the
 * session's client_mac) — this is the anti-sharing guard for BOTH paths.
 *
 * Always resolves to { status, body }: the caller sends it as the response.
 *
 * @param {string} voucher      Normalized voucher code
 * @param {string} clientMac    Normalized MAC of the requesting device
 * @param {string} [boundMac]   MAC the voucher was originally bound to
 *                              (vouchers.used_by_mac); falls back to the
 *                              session's client_mac when absent on legacy rows
 * @param {string} [redirectUrl] Validated post-login redirect URL from the form
 */
async function resumeUsedVoucher(voucher, clientMac, boundMac, redirectUrl) {
  const fail = (status, code, error) => ({ status, body: { success: false, code, error } });

  const session = await getSessionByVoucher(voucher);
  if (!session) {
    return fail(401, 'USED_VOUCHER', 'This voucher has already been used.');
  }

  // ── MAC binding: only the device the voucher was first used on may re-enter ──
  // Checked BEFORE the state branches so a shared code can neither reopen the
  // firewall (active) nor resume the timer (paused) on a second device.
  if (!isSameMac(boundMac || session.clientMac, clientMac)) {
    return fail(403, 'VOUCHER_DEVICE_MISMATCH',
      'This voucher is already in use on another device and cannot be resumed here.');
  }

  // getSession() already flips an active-but-timed-out session to 'expired',
  // so this covers "the time has fully elapsed".
  if (session.state === 'expired') {
    return fail(401, 'EXPIRED_VOUCHER', 'This voucher has expired.');
  }

  // ── Still-active session, same device: re-open the firewall ──────────────
  // The session is valid and belongs to this device, so this is NOT the
  // "already active" error case — replay extPortal/auth with the time left.
  // Runs for BOTH Standard and Premium: a Standard plan cannot pause, but its
  // live session is still re-authorized here (a dropped firewall / reopened
  // captive mini-browser is not an error).
  if (session.state === 'active') {
    let reauthed;
    try {
      reauthed = await reauthorizeSession(session.sessionId);
    } catch (err) {
      if (err && err.code === 'SESSION_EXPIRED') {
        await expireSession(session.sessionId, 'time_expired');
        return fail(401, 'EXPIRED_VOUCHER', 'This voucher has expired.');
      }
      console.error(
        '[auth] re-authorize failed for active voucher ' + maskVoucher(voucher) +
        ' (client ' + clientMac + '): ' + (err && err.message ? err.message : String(err))
      );
      return fail(502, 'OMADA_ERROR', 'Could not get you back online. Please try again.');
    }

    console.log(
      '[auth] ACTIVE RE-AUTH success (same device, firewall reopened) —' +
      ' client=' + clientMac +
      ' session=' + reauthed.session.sessionId +
      ' remainingSeconds=' + reauthed.remainingSeconds +
      ' voucher=' + maskVoucher(voucher)
    );

    // Standard success shape with NO `resumed` flag: the portal treats this as
    // a normal login and lands on success.html (exactly like a fresh voucher),
    // while the timer keeps running from the session's original expiry.
    return {
      status: 200,
      body: {
        success: true,
        message: 'Authentication successful.',
        sessionId: reauthed.session.sessionId,
        clientMac: reauthed.session.clientMac || clientMac,
        redirectUrl: redirectUrl || process.env.DEFAULT_REDIRECT_URL || 'https://www.google.com',
        startedAt: reauthed.session.startedAt,
        expiresAt: reauthed.session.expiresAt,
        totalSeconds: reauthed.session.totalDurationSeconds
          || session.totalDurationSeconds
          || reauthed.remainingSeconds,
        session: {
          state: 'active',
          remainingSeconds: reauthed.remainingSeconds,
          voucherType: reauthed.session.voucherType,
          clientMac: reauthed.session.clientMac || clientMac,
          startedAt: reauthed.session.startedAt,
          expiresAt: reauthed.session.expiresAt,
          totalSeconds: reauthed.session.totalDurationSeconds
            || session.totalDurationSeconds
            || reauthed.remainingSeconds,
        },
      },
    };
  }

  // ── Paused session: resume from the frozen remaining time ────────────────
  if (session.state !== 'paused') {
    // Any other state (e.g. a payment stage) is not resumable.
    return fail(409, 'ALREADY_ACTIVE', 'This session is already active on this device.');
  }

  // Pause/resume is a Premium-only feature: Standard plans run continuously
  // and never pause, so a non-pausable tier reaching this branch is an error.
  if (!isPausableVoucherType(session.voucherType)) {
    return fail(403, 'STANDARD_CONTINUOUS',
      'Standard vouchers run continuously and cannot be paused or resumed.');
  }

  const remaining = Math.max(0, Math.floor(session.remainingSeconds || 0));
  if (remaining <= 0) {
    await expireSession(session.sessionId, 'time_expired');
    return fail(401, 'EXPIRED_VOUCHER', 'This voucher has expired.');
  }

  // Re-authorize through Omada and flip the session back to active.
  // resumeSession() is fail-closed: if the controller rejects or throws, the
  // session stays paused and the guest can simply try again.
  let resumed;
  try {
    resumed = await resumeSession(session.sessionId);
  } catch (err) {
    console.error(
      '[auth] resume failed for voucher ' + maskVoucher(voucher) +
      ' (client ' + clientMac + '): ' + (err && err.message ? err.message : String(err))
    );
    return fail(502, 'OMADA_ERROR', 'Could not get you back online. Please try again.');
  }

  console.log(
    '[auth] RESUME SUCCESS (premium pause → active) —' +
    ' client=' + clientMac +
    ' session=' + resumed.sessionId +
    ' remainingSeconds=' + remaining +
    ' voucher=' + maskVoucher(voucher)
  );

  return {
    status: 200,
    body: {
      success: true,
      resumed: true,
      message: 'Session resumed.',
      sessionId: resumed.sessionId,
      clientMac: resumed.clientMac || clientMac,
      // The session page is the live view; its timer reads the remaining time
      // straight from the re-authorized session (expires_at = now + remaining).
      redirectUrl: 'status.html?sessionId=' + encodeURIComponent(resumed.sessionId) +
        (resumed.clientMac || clientMac
          ? '&clientMac=' + encodeURIComponent(resumed.clientMac || clientMac)
          : ''),
      startedAt: resumed.startedAt,
      expiresAt: resumed.expiresAt,
      session: {
        state: resumed.state,
        remainingSeconds: remaining,
        voucherType: resumed.voucherType,
        clientMac: resumed.clientMac || clientMac,
        startedAt: resumed.startedAt,
        expiresAt: resumed.expiresAt,
      },
    },
  };
}

/**
 * firstProvidedMac — the first MAC value the client actually supplied.
 *
 * An absent field (undefined/null) or an empty/whitespace-only string means
 * "not provided" and is skipped, so the caller can fall through to the
 * address-based lookup. Anything else is returned as-is for validation — a
 * non-string (an object, a number) is deliberately NOT skipped: it is a
 * malformed client payload and must reach the 400 INVALID_MAC branch rather
 * than silently degrade to an address lookup.
 *
 * @param {...*} values candidate values, highest priority first
 * @returns {*} the first provided value, or '' when none was supplied
 */
function firstProvidedMac() {
  for (let i = 0; i < arguments.length; i += 1) {
    const value = arguments[i];
    if (value === undefined || value === null) continue;
    if (typeof value === 'string' && value.trim() === '') continue;
    return value;
  }
  return '';
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
