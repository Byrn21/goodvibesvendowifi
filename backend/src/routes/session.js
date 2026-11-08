/**
 * routes/session.js
 *
 * GET  /api/session/status  — Poll session remaining time
 *                             (no identifier at all for the MAC-direct flow,
 *                              or ?sessionId=, ?mac=, or ?voucher= for the
 *                              offline "Check Voucher Status" modal)
 * POST /api/session/pause  — Pause active session
 * POST /api/session/resume — Resume paused session
 * POST /api/session/expire — Admin: immediately expire session
 */

const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const {
  getSession,
  pauseSession,
  resumeSession,
  reauthorizeSession,
  expireSession,
  isSessionActive,
  isPausableVoucherType,
  isHardExpired,
  getSessionByVoucher,
} = require('../services/session');
const omadaService = require('../services/omada');
const { ADMIN_API_KEY } = require('../config');
const { getDb } = require('../db/client');
const { normalizeMac } = require('../utils/device-id');
const { resolveClientMacByIp } = require('../utils/portal-context');
const { normalizeVoucherType } = require('../utils/qos');
const { normalizeVoucherCode, validateVoucherCodeFormat } = require('../utils/voucher-code');
const { safeEqual } = require('../utils/safe-compare');
const {
  tokenFromRequest,
  verifySessionToken,
  setSessionCookie,
} = require('../utils/session-token');

/**
 * submittedVoucherCode — the voucher code supplied with this request, if any.
 *
 * Accepted from the JSON body (`voucherCode`, `voucher_code` or `voucher`),
 * the query string (same names) and the `x-voucher-code` header. Values are
 * normalized with the shared rule and an invalid shape is ignored rather than
 * treated as a wrong credential, so a malformed field cannot turn into a 500.
 *
 * @param {Object} req Express request
 * @returns {string} a normalized 6-digit code, or '' when none was supplied
 */
function submittedVoucherCode(req) {
  const body = req && req.body ? req.body : {};
  const query = req && req.query ? req.query : {};
  const header = req && req.headers ? req.headers['x-voucher-code'] : '';

  const candidates = [
    body.voucherCode, body.voucher_code, body.voucher,
    query.voucherCode, query.voucher_code, query.voucher,
    header,
  ];

  for (const candidate of candidates) {
    if (candidate === null || candidate === undefined) continue;
    if (typeof candidate !== 'string' && typeof candidate !== 'number') continue;
    const code = normalizeVoucherCode(candidate);
    if (validateVoucherCodeFormat(code).ok) return code;
  }
  return '';
}

/**
 * assertSessionOwner — may this request act on this session?
 *
 * A bare sessionId in a POST body is not proof of anything: it can be copied
 * out of a URL, a screenshot or a log, and pause/resume change a paying guest's
 * network access. The identity this backend issues for a session comes in two
 * scopes (`utils/session-token.js`):
 *
 *   read    — minted by any lookup that resolves a session (GET /status by
 *             MAC, voucher or address). Good for displaying status only.
 *   control — minted ONLY by POST /api/auth, POST /api/payment/claim and
 *             POST /api/session/resume, i.e. routes that already performed an
 *             authenticated action. Required here.
 *
 * Both travel as the HttpOnly `portal_session` cookie and as `?token=` for
 * cookie-blocked browsers. A read token (including every token issued before
 * scopes existed) is deliberately NOT sufficient for a state change.
 *
 * VOUCHER-CODE FALLBACK: a guest who checks their time from the main browser
 * (Chrome/Safari after the captive popup closed) has no Omada `clientMac`
 * parameters and may not share the mini browser's cookie or storage, so the
 * vouched-for device identity is gone. The 6-digit code tied to the session is
 * the credential they still hold: when it matches `sessions.voucher_used`, the
 * request is authorized even without a control token. The comparison is
 * constant-time, and a blank/mismatched code changes nothing.
 *
 * @param {Object} req Express request
 * @param {Object} session session object from getSession()
 * @returns {boolean} true when the caller proved it owns the session
 */
function assertSessionOwner(req, session) {
  if (!session || !session.sessionId) return false;

  const verified = verifySessionToken(tokenFromRequest(req));
  if (
    verified &&
    verified.scope === 'control' &&
    verified.sessionId === session.sessionId
  ) {
    return true;
  }

  const suppliedCode = submittedVoucherCode(req);
  const sessionCode = normalizeVoucherCode(session.voucherUsed);
  return Boolean(suppliedCode && sessionCode && safeEqual(suppliedCode, sessionCode));
}

/**
 * identityScopeFor — what scope may this request's identity be refreshed at?
 *
 * Status lookups are allowed to mint a READ token for anyone who can resolve a
 * session, but they must never turn that lookup into control authority. When
 * the request already carries a valid CONTROL token for the same session, that
 * stronger identity is preserved (the caller already had it — refreshing it
 * grants nothing new). Otherwise the issued token is read-only.
 *
 * @param {Object} req Express request
 * @param {string} sessionId resolved session
 * @returns {'read'|'control'}
 */
function identityScopeFor(req, sessionId) {
  const verified = verifySessionToken(tokenFromRequest(req));
  return verified && verified.scope === 'control' && verified.sessionId === sessionId
    ? 'control'
    : 'read';
}

/**
 * rejectIfNotOwner — send the 403 SESSION_MISMATCH answer and report whether
 * the caller must stop. Kept next to assertSessionOwner so both pause and
 * resume share one response shape.
 */
function rejectIfNotOwner(req, res, session) {
  if (assertSessionOwner(req, session)) return false;
  res.status(403).json({
    success: false,
    code: 'SESSION_MISMATCH',
    error: 'This session does not belong to this device.',
  });
  return true;
}

/**
 * readAdminKey — the operator credential supplied with this request.
 *
 * The header is the documented transport; the body field exists for internal
 * callers that already POST JSON. It is deliberately never read from a query
 * string, which would leak it into access logs, browser history and Referer
 * headers.
 *
 * @param {Object} req Express request
 * @returns {string} the supplied key, '' when none
 */
function readAdminKey(req) {
  const header = req && req.headers ? req.headers['x-admin-key'] : '';
  if (typeof header === 'string' && header.trim()) return header.trim();
  const body = req && req.body ? req.body.adminKey : '';
  return typeof body === 'string' ? body.trim() : '';
}

/**
 * isAdminRequest — constant-time comparison against ADMIN_API_KEY.
 *
 * Fail-closed: no configured key or no supplied key is false, so the guarded
 * route refuses everyone rather than admitting everyone. The length check runs
 * first because timingSafeEqual throws on mismatched buffer sizes.
 *
 * @param {Object} req Express request
 * @returns {boolean}
 */
function isAdminRequest(req) {
  const configured = String(ADMIN_API_KEY || '');
  const provided = readAdminKey(req);
  if (!configured || !provided) return false;

  const given = Buffer.from(provided, 'utf8');
  const want = Buffer.from(configured, 'utf8');
  if (given.length !== want.length) return false;
  return crypto.timingSafeEqual(given, want);
}

// ── GET /api/session/status ──────────────────────────────────
router.get('/status', async (req, res, next) => {
  try {
    let { sessionId } = req.query;
    const { mac, voucher } = req.query;

    // The "Check Voucher Status / Reconnect" modal has no sessionId and the
    // client may not be online yet, so it polls with ?voucher=<code>. Answered
    // entirely from the voucher + its session row — nothing is mutated here
    // except marking an already-expired voucher 'expired' (see below).
    if (voucher !== undefined) {
      return await handleVoucherStatus(req, res, voucher);
    }

    // ── Which identifier wins ──────────────────────────────────────────
    // Freshest intent first:
    //   1. ?sessionId= in the URL — what success.html / portal.js hand over the
    //      moment a pass is bought, so it must beat anything cached.
    //   2. the signed cookie (or ?token=, its localStorage-carried twin) this
    //      backend issued when the device was authorized.
    //   3. ?mac=
    //   4. the request address (the historical, LAN-only behaviour).
    //
    // The cookie outranks the MAC because it names the exact session, and sits
    // ahead of the address lookup because that lookup is the one that fails
    // whenever the guest reaches us from a tunnel or a carrier NAT address
    // (Wi-Fi Assist, proxy browsers) instead of 192.168.0.x.
    let identity = typeof sessionId === 'string' && sessionId ? 'session_query' : '';

    if (!identity) {
      const token = tokenFromRequest(req);
      if (token) {
        const verified = verifySessionToken(token);
        // A valid signature only means WE issued the token; the row behind it
        // may have been deleted. Probe it here so an unknown session is not
        // reported as SESSION_NOT_FOUND — it must fall through to the other
        // identifiers exactly like an invalid token does.
        const known = verified
          ? await getDb().getOne('SELECT session_id FROM sessions WHERE session_id = ?', [verified.sessionId])
          : null;
        if (verified && known && known.session_id) {
          sessionId = verified.sessionId;
          identity = 'token';
        } else {
          // Never an error of its own: a stale/forged token just means this
          // request is identified some other way.
          console.warn('[session/status] ignoring an invalid or expired session token');
        }
      }
    }

    // ── MAC-direct identification (no identifier at all) ────────────────
    // Access is granted directly to the device's MAC, so the guest has no
    // voucher code (and often no session id) to hand to this page. With no
    // identifier, the device is resolved from the address it reached the
    // portal from — the landing beacon stored that address next to its MAC in
    // portal_client_context. A device that never loaded the portal page is the
    // explicit MISSING_PORTAL_CONTEXT failure (never "session not found":
    // reloading the portal is what fixes it).
    //
    // The NEWEST session is taken regardless of state, so a guest whose time
    // ran out is told the session expired instead of being told it does not
    // exist. getSession() below lazily expires it and the response reports the
    // terminal state (and remaining 0).
    if (!identity && !(mac && typeof mac === 'string')) {
      let resolved;
      try {
        resolved = await resolveClientMacByIp(req.ip);
      } catch (err) {
        if (err && err.code === 'MISSING_PORTAL_CONTEXT') {
          console.warn(
            '[session/status] MISSING_PORTAL_CONTEXT for ip ' + String(req.ip || '(none)') +
            ': ' + String(err.message || '(no message)')
          );
          return res.status(502).json({
            success: false,
            code: 'MISSING_PORTAL_CONTEXT',
            error: 'Open the Wi-Fi portal page once so this device can be identified, then tap Refresh.',
            // Operator-facing detail: this is missing CONTEXT, not a missing
            // session. A carrier/tunnel address (Wi-Fi Assist, proxy browser)
            // can never match the LAN address the landing beacon captured.
            hint: 'No portal context matches this request address (' +
              String(req.ip || 'unknown') + '). A public carrier or tunnel address cannot ' +
              'identify a device; the guest needs a saved cookie/MAC or must reopen the portal.',
          });
        }
        throw err;
      }

      identity = 'ip';

      if (resolved.stale) {
        console.warn(
          '[session/status] using stale portal context for ' + resolved.clientMac +
          ' (ip ' + String(req.ip || '(none)') + '): the device has not reloaded the portal recently'
        );
      }

      const latest = await getDb().getOne(
        `SELECT session_id FROM sessions
          WHERE LOWER(client_mac) = LOWER(?)
          ORDER BY id DESC LIMIT 1`,
        [resolved.clientMac]
      );
      if (!latest || !latest.session_id) {
        return res.status(404).json({
          success: false,
          error: 'No session exists for this device yet.',
          code: 'SESSION_NOT_FOUND',
          clientMac: resolved.clientMac,
        });
      }
      sessionId = latest.session_id;
    }

    // ?mac=<client_mac> — resolve the newest non-terminal session for that
    // device (case-insensitive MAC match); callers keep polling on 404.
    //
    // This is the fallback status.html uses behind the cloud tunnel: the
    // address-based lookup above answers MISSING_PORTAL_CONTEXT there, because
    // req.ip is the tunnel's public address rather than the guest's LAN
    // address, so the page retries with the MAC saved by assets/portal.js when
    // the claim succeeded. The value is validated (any accepted representation
    // is canonicalized, anything else is a 400) exactly like ?clientMac= on
    // the other routes, and only sessions belonging to that MAC are returned.
    if (!identity && mac && typeof mac === 'string') {
      const normalized = normalizeMac(mac);
      if (!normalized) {
        return res.status(400).json({
          success: false,
          error: 'Invalid client MAC address.',
          code: 'INVALID_MAC',
        });
      }
      const row = await getDb().getOne(
        `SELECT session_id FROM sessions
          WHERE LOWER(client_mac) = LOWER(?)
            AND state IN ('active', 'paused', 'pending_payment', 'pending_verification')
          ORDER BY id DESC LIMIT 1`,
        [normalized]
      );
      if (row && row.session_id) {
        sessionId = row.session_id;
        identity = 'mac';
      } else {
        // Nothing live under this MAC — fall back to the device's most recent
        // EXPIRED session instead of 404ing. A guest whose pass ran out (or hit
        // its Premium hard deadline) must be told it expired, with the reason
        // and deadline, rather than being dumped on "session not found". Only a
        // device that never had a session at all still gets 404.
        const expired = await getDb().getOne(
          `SELECT session_id FROM sessions
            WHERE LOWER(client_mac) = LOWER(?)
              AND state = 'expired'
            ORDER BY id DESC LIMIT 1`,
          [normalized]
        );
        if (expired && expired.session_id) {
          sessionId = expired.session_id;
          identity = 'mac';
        } else {
          return res.status(404).json({
            success: false,
            error: 'No session exists for this device.',
            code: 'SESSION_NOT_FOUND',
          });
        }
      }
    }

    if (!sessionId || typeof sessionId !== 'string') {
      return res.status(400).json({ success: false, error: 'sessionId is required.' });
    }

    const session = await getSession(sessionId);

    if (!session) {
      return res.status(404).json({
        success: false,
        error: 'No active session exists for this device.',
        code: 'SESSION_NOT_FOUND',
      });
    }

    // Re-issue this session's identity on every successful resolve. The cookie
    // is a sliding 7-day window, and it is kept even for an EXPIRED session on
    // purpose: the guest should still be told "expired" (with the reason and
    // the deadline) instead of "no session found". The same token is echoed in
    // the body for callers whose browser blocks cookies but keeps localStorage.
    //
    // Scope is the security boundary (H-01): a lookup by MAC / voucher / address
    // only refreshes a READ token. A CONTROL token is preserved only when this
    // request already presented one for the same session.
    const statusToken = setSessionCookie(
      req, res, sessionId, identityScopeFor(req, sessionId)
    );

    const serverTime = Math.floor(Date.now() / 1000);

    // Determine if session has expired server-side (defensive; backend should already expire)
    if (session.state === 'active' && session.expiresAt) {
      const expiresAt = Math.floor(new Date(session.expiresAt).getTime() / 1000);
      if (serverTime >= expiresAt) {
        // Server-side expired — call unauth and update state. A pass that is
        // also past its Premium hard deadline is recorded as such.
        const endedByHardExpiry = isHardExpired(session);
        await expireSession(sessionId, endedByHardExpiry ? 'hard_expired' : 'server_expired');
        try {
          await omadaService.unauthenticateClient({ clientMac: session.clientMac });
        } catch (_) { /* ignore */ }
                return res.json({
          sessionId,
          clientMac: session.clientMac || '',
          state: 'expired',
          remainingSeconds: 0,
          startedAt: session.startedAt,
          expiresAt: session.expiresAt,
          absoluteExpiresAt: session.absoluteExpiresAt || null,
          absolute_expires_at: session.absoluteExpiresAt || null,
          voucherType: session.voucherType || 'standard',
          voucherCode: maskVoucherCode(session.voucherUsed),
          // 'hard_expired' when the Premium hard deadline is what ended the
          // pass (computed above on the row we just read).
          expireReason: endedByHardExpiry ? 'hard_expired' : 'server_expired',
          expire_reason: endedByHardExpiry ? 'hard_expired' : 'server_expired',
          statusToken: statusToken || null,
          canPause: false,
          canResume: false,
        });
      }
    }

    const remainingSeconds = computeRemaining(session, serverTime);

        return res.json({
      sessionId: session.sessionId,
      // Echoed so the client can persist the device identity and keep polling
      // by MAC after the sessionId is lost, and so a stale stored sessionId
      // can be reconciled against the device's live session.
      clientMac: session.clientMac || '',
      state: session.state,
      remainingSeconds,
      startedAt: session.startedAt,
      expiresAt: session.expiresAt,
      // Premium hard deadline (null for Standard sessions). Reported in both
      // spellings: camelCase to sit alongside expiresAt, and the snake_case
      // name the status contract documents.
      absoluteExpiresAt: session.absoluteExpiresAt || null,
      absolute_expires_at: session.absoluteExpiresAt || null,
      voucherType: session.voucherType || 'standard',
      voucherCode: maskVoucherCode(session.voucherUsed),
      // Why an 'expired' session ended ('hard_expired' for a Premium pass that
      // hit PREMIUM_HARD_EXPIRY_HOURS, 'time_expired' when its minutes ran
      // out). Null while the session is still live. Reported in both spellings
      // like absolute_expires_at so the status page can render the right screen.
      expireReason: session.expireReason || null,
      expire_reason: session.expireReason || null,
      totalSeconds: (session.totalDurationSeconds || (session.duration || 60) * 60),
      // Signed identity for this session (also set as an HttpOnly cookie). The
      // status page stores it in localStorage and sends it as ?token= when the
      // cookie cannot be relied on.
      statusToken: statusToken || null,
      // Pause is a Premium CAPABILITY, not a once-per-session allowance: an
      // active Premium session may pause again after every resume, right up to
      // its absolute deadline. No pause counter or consumed flag is stored or
      // consulted (the schema has no can_pause / used_pause column), so the
      // only limits are the live state and the hard expiry, which getSession()
      // has already enforced above.
      canPause: session.state === 'active'
        && isPausableVoucherType(session.voucherType)
        && !isHardExpired(session),
      canResume: session.state === 'paused',
    });
  } catch (err) {
    // Log real database/processing errors server-side — never let them
    // masquerade as a "session not found" response on the client.
    console.error(
      '[session/status] Error while fetching session ' + sessionId + ': ' +
      String((err && err.message) || '(no message)') + ' ' +
      String((err && err.stack) || '(no stack)')
    );
    next(err);
  }
});

// ── POST /api/session/reauthorize ─────────────────────────────
// MAC-keyed silent reconnection: when a device whose voucher session is still
// live loses its firewall authorization (Wi-Fi dropped, captive mini-browser
// reopened, OS re-probe) it can be put back online WITHOUT re-entering a
// voucher. The most recent still-live active session for the MAC is looked up
// and reauthorizeSession() replays the Omada extPortal/auth call for the
// remaining time. Returns 404 { active: false } when there is nothing to
// resume, so the portal can fall through to normal voucher entry.
//
// UNAUTHENTICATED by design (the client is not online yet) — it grants nothing
// beyond re-opening the firewall for a session that already exists and is
// already bound to this MAC.
router.post('/reauthorize', async (req, res, next) => {
  try {
    const body = req.body || {};
    const rawMac = body.clientMac;

    if (!rawMac || typeof rawMac !== 'string') {
      return res.status(400).json({ success: false, error: 'clientMac is required.', code: 'INVALID_INPUT' });
    }
    const normalized = normalizeMac(rawMac);
    if (!normalized) {
      return res.status(400).json({ success: false, error: 'Invalid client MAC address.', code: 'INVALID_MAC' });
    }

    // Most recent STILL-LIVE active session for this device. `expires_at > now`
    // (not just state = 'active') so a session the expiration worker has not
    // swept yet is not mistaken for a resumable one.
    const row = await getDb().getOne(
      // The absolute Premium deadline is part of the filter too: a pass past it
      // is void no matter what expires_at says, so it must never be selected as
      // a re-authorization candidate in the first place.
      `SELECT session_id FROM sessions
        WHERE LOWER(client_mac) = LOWER(?)
          AND state = 'active'
          AND expires_at IS NOT NULL AND expires_at > ?
          AND (absolute_expires_at IS NULL OR absolute_expires_at > ?)
        ORDER BY id DESC LIMIT 1`,
      [normalized, new Date().toISOString(), new Date().toISOString()]
    );
    if (!row || !row.session_id) {
      return res.status(404).json({
        success: false,
        active: false,
        code: 'NO_ACTIVE_SESSION',
        error: 'No active session exists for this device.',
      });
    }

    // Re-open the firewall for the remaining time. reauthorizeSession() is
    // fail-closed: on controller rejection/throw the session's local state is
    // left untouched and the client may safely retry.
    let reauthed;
    try {
      reauthed = await reauthorizeSession(row.session_id);
    } catch (err) {
      if (err && err.code === 'SESSION_EXPIRED') {
        await expireSession(row.session_id, 'time_expired');
        return res.status(404).json({
          success: false,
          active: false,
          code: 'SESSION_EXPIRED',
          error: 'The session has expired.',
        });
      }
      console.error(
        '[session/reauthorize] Omada auth failed for ' + normalized +
        ' (session ' + row.session_id + '): ' + String((err && err.message) || '(no message)')
      );
      return res.status(502).json({
        success: false,
        error: 'Temporary connection error. Please wait a moment and try again.',
        code: 'OMADA_ERROR',
      });
    }

    console.log(
      '[session/reauthorize] re-authorized client ' + normalized +
      ' session=' + reauthed.session.sessionId +
      ' remainingSeconds=' + reauthed.remainingSeconds
    );

    return res.json({
      success: true,
      active: true,
      sessionId: reauthed.session.sessionId,
      state: reauthed.session.state,
      remainingSeconds: reauthed.remainingSeconds,
      expiresAt: reauthed.session.expiresAt,
      voucherType: reauthed.session.voucherType || 'standard',
    });
  } catch (err) {
    next(err);
  }
});

// ── POST /api/session/pause ───────────────────────────────────
router.post('/pause', async (req, res, next) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).json({ success: false, error: 'sessionId is required.' });
    }

    if (process.env.PAUSE_ENABLED !== 'true') {
      return res.status(403).json({ success: false, error: 'Pause is not enabled.', code: 'PAUSE_DISABLED' });
    }

    const session = await getSession(sessionId);
    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found.' });
    }
    // Hard expiry (Premium): past its absolute deadline the pass is void even
    // with frozen/remaining time left, so it must never be paused again.
    // getSession() has already terminalised the row.
    if (isHardExpired(session)) {
      return res.status(410).json({
        success: false,
        code: 'HARD_EXPIRED',
        error: 'This pass has reached its absolute expiry and can no longer be paused.',
        absolute_expires_at: session.absoluteExpiresAt || null,
      });
    }
        if (session.state !== 'active') {
      return res.status(409).json({ success: false, error: 'Session is not active.', code: 'INVALID_STATE' });
    }
    // Plan-tier gate: Standard (and any other non-pausable tier) is rejected
    // here even if the client bypasses the UI and POSTs directly.
    if (!isPausableVoucherType(session.voucherType)) {
      return res.status(403).json({ success: false, error: 'Pause is only available for Premium sessions.', code: 'PREMIUM_ONLY' });
    }
    // Ownership: only the device this session was issued to may stop its clock.
    if (rejectIfNotOwner(req, res, session)) return;

    const paused = await pauseSession(sessionId);
    return res.json({
      success: true,
      state: 'paused',
      voucherType: paused.voucherType || 'standard',
      remainingSeconds: computeRemaining(paused, Math.floor(Date.now() / 1000)),
      pausedAt: paused.pausedAt,
    });
  } catch (err) {
    // A pause that could not stop the client must NOT read as a pause: answer
    // 502 so the portal shows the retry message and the timer keeps running.
    if (err && err.code === 'OMADA_ERROR') {
      return res.status(502).json({
        success: false,
        code: 'OMADA_ERROR',
        error: err.message || 'Could not stop the network session. Please try again.',
      });
    }
    if (err && (err.code === 'SESSION_EXPIRED' || err.code === 'HARD_EXPIRED' || err.code === 'PAUSE_EXPIRED')) {
      return res.status(410).json({ success: false, code: err.code, error: err.message });
    }
    next(err);
  }
});

// ── POST /api/session/resume ──────────────────────────────────
router.post('/resume', async (req, res, next) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).json({ success: false, error: 'sessionId is required.' });
    }

    const session = await getSession(sessionId);
    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found.' });
    }
    // Hard expiry (Premium): frozen time does NOT extend the pass past its
    // absolute deadline, so a hard-expired pause can never be resumed.
    if (isHardExpired(session)) {
      return res.status(410).json({
        success: false,
        code: 'HARD_EXPIRED',
        error: 'This pass has reached its absolute expiry and can no longer be resumed.',
        absolute_expires_at: session.absoluteExpiresAt || null,
      });
    }
        if (session.state !== 'paused') {
      return res.status(409).json({ success: false, error: 'Session is not paused.', code: 'INVALID_STATE' });
    }
    if (!isPausableVoucherType(session.voucherType)) {
      return res.status(403).json({ success: false, error: 'Resume is only available for Premium sessions.', code: 'PREMIUM_ONLY' });
    }
    // Ownership: a copied sessionId must not restart someone else's pass.
    if (rejectIfNotOwner(req, res, session)) return;

    const resumed = await resumeSession(sessionId);
    // Same session, refreshed identity: keep the browser bound to it. This route
    // already required a control token, so it may mint a fresh one.
    const statusToken = setSessionCookie(req, res, sessionId, 'control');
    return res.json({
      success: true,
      state: 'active',
      voucherType: resumed.voucherType || 'standard',
      remainingSeconds: computeRemaining(resumed, Math.floor(Date.now() / 1000)),
      expiresAt: resumed.expiresAt,
      statusToken: statusToken || null,
    });
  } catch (err) {
    // A zero-time or past-deadline pass is GONE, not a server error: 410 with
    // the precise reason, so the status page can stop offering Resume.
    if (err && (err.code === 'SESSION_EXPIRED' || err.code === 'HARD_EXPIRED' || err.code === 'PAUSE_EXPIRED')) {
      return res.status(410).json({ success: false, code: err.code, error: err.message });
    }
    if (err && err.code === 'OMADA_ERROR') {
      return res.status(502).json({ success: false, code: 'OMADA_ERROR', error: err.message });
    }
    next(err);
  }
});

// ── POST /api/session/expire ──────────────────────────────────
// Admin/internal: this cuts a guest offline immediately, so it is the one
// session route that requires an OPERATOR credential instead of a device
// identity. `x-admin-key` (or adminKey in the body) must match ADMIN_API_KEY —
// anything else is a 401 and nothing is expired.
router.post('/expire', async (req, res, next) => {
  try {
    // Checked before the body is parsed for a sessionId: an unauthenticated
    // caller learns nothing about which ids exist, and cannot trigger a write.
    if (!isAdminRequest(req)) {
      return res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        error: 'Admin authorization required.',
      });
    }

    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).json({ success: false, error: 'sessionId is required.' });
    }

    const session = await getSession(sessionId);
    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found.' });
    }

    await expireSession(sessionId, 'admin_expired');

    // Call Omada to unauthenticate
    try {
      await omadaService.unauthenticateClient({ clientMac: session.clientMac });
    } catch (_) { /* ignore — client may already be disconnected */ }

    return res.json({ success: true, state: 'expired' });
  } catch (err) {
    next(err);
  }
});

// ── Helpers ──────────────────────────────────────────────────

/**
 * maskVoucherCode — partly mask a voucher code for display on the status
 * page, e.g. "123456" -> "••••56". Returns null when there is no code.
 */
function maskVoucherCode(code) {
  if (!code || typeof code !== 'string') return null;
  const cleaned = code.replace(/\s+/g, '');
  if (cleaned.length < 2) return '••••••';
  return '••••' + cleaned.slice(-2);
}

/**
 * handleVoucherStatus — answer GET /api/session/status?voucher=<code>.
 *
 * Backs the "Check Voucher Status / Reconnect" modal, which must work for a
 * guest who is OFFLINE (no sessionId, possibly no active session) and only
 * has the printed code in hand. Nothing here re-authorizes the client or
 * grants access — it only reports what the database already knows:
 *
 *   - active/paused session for the code   -> { active: true, remainingSeconds, expiresAt }
 *   - unused voucher with a known duration -> { active: true, remainingSeconds: duration*60 }
 *   - consumed / expired / unknown code    -> 200 { active: false, state: 'unknown' }
 *
 * The last group is deliberately ONE shape (H-03): telling an unauthenticated
 * caller apart "never existed" from "expired" from "already used" turns this
 * endpoint into a voucher-space enumeration oracle.
 *
 * The only write is marking an already time-expired voucher row 'expired',
 * matching validateVoucher()'s lazy sweep.
 */
async function handleVoucherStatus(req, res, voucher) {
  if (typeof voucher !== 'string' || !voucher) {
    return res.status(400).json({ success: false, error: 'voucher is required.', code: 'INVALID_INPUT' });
  }

  const code = normalizeVoucherCode(voucher);
  const format = validateVoucherCodeFormat(code);
  if (!format.ok) {
    return res.status(400).json({ success: false, error: format.message, code: 'INVALID_VOUCHER_FORMAT' });
  }

  const row = await getDb().getOne(
    `SELECT id, code, type, duration_minutes, state, expires_at
       FROM vouchers WHERE code = ? LIMIT 1`,
    [code]
  );

  // H-03: an unknown code, an expired code and a fully-used one all answer
  // with the SAME 200 body. Distinguishing them let an unauthenticated caller
  // enumerate the code space: 404 meant "not in the table", EXPIRED meant
  // "real but consumed", and an active body meant "redeemable now".
  if (!row) {
    return sendVoucherUnavailable(res);
  }

  const serverTime = Math.floor(Date.now() / 1000);
  const durationSeconds = (row.duration_minutes || 60) * 60;
  const voucherExpiresAt = row.expires_at || null;

  // An unused voucher that has passed its own expiry date is dead; sweep it
  // lazily like validateVoucher() does, then report EXPIRED.
  const voucherTimedOut = voucherExpiresAt
    ? serverTime >= Math.floor(new Date(voucherExpiresAt).getTime() / 1000)
    : false;

  if (row.state === 'expired' || voucherTimedOut) {
    if (row.state !== 'expired') {
      try {
        await getDb().run(`UPDATE vouchers SET state = 'expired' WHERE id = ?`, [row.id]);
      } catch (_) { /* best-effort sweep — the response is unchanged */ }
    }
    return sendVoucherUnavailable(res);
  }

  // The session this code already created, if any. Resolved BEFORE the
  // "unused voucher" answer below, because a CLAIMED voucher can own a LIVE
  // session: POST /api/payment/claim authorizes the paying device and marks
  // the voucher 'claimed' in the same transaction. Answering "unused, full
  // duration available" there would hide a session that is already counting
  // down — and deny the browser the identity that keeps status.html working
  // once it drops to mobile data (the mobile-data bug this lookup fixes).
  //
  // getSessionByVoucher -> getSession() applies server-side expiry, so an
  // active-but-timed-out session comes back as state 'expired'.
  const session = await getSessionByVoucher(code);

  // Unconsumed voucher with NO session behind it at all: its full duration is
  // still available. A claimed voucher whose claim never authorized a device
  // lands here too, which is correct — nothing is running yet. A voucher with
  // any session row (live OR elapsed) must fall through instead, so an elapsed
  // claim answers EXPIRED rather than pretending the code was never used.
  if (!session && (row.state === 'active' || row.state === 'claimed')) {
    return res.json({
      success: true,
      active: true,
      state: 'unused',
      remainingSeconds: durationSeconds,
      expiresAt: voucherExpiresAt,
      voucherType: normalizeVoucherType(row.type),
      durationMinutes: row.duration_minutes || 60,
    });
  }

  // ── Live session found: bind this browser to it ─────────────────────
  // The voucher code is the one credential a returning guest always has, so
  // this lookup is the portal's way of handing the browser its identity back
  // after the captive mini-browser dropped its storage. The signed cookie (and
  // the same token echoed in the body for cookie-blocked browsers) names the
  // EXACT session, which outranks both the MAC and the request address on
  // every later status request — so the page keeps working after the guest
  // switches to mobile data and req.ip stops matching portal_client_context.
  //
  // Nothing here re-authorizes the client: the session must already be live
  // (active / paused / pending payment). An unused voucher has no session to
  // name, and an expired one is reported inline instead — no cookie is set for
  // either, so a stale code can never bind the browser to a dead session.
  if (session && session.state === 'active') {
    const statusToken = setSessionCookie(
      req, res, session.sessionId, identityScopeFor(req, session.sessionId)
    );
    return res.json({
      success: true,
      active: true,
      state: 'active',
      sessionId: session.sessionId,
      statusToken: statusToken || null,
      remainingSeconds: computeRemaining(session, serverTime),
      expiresAt: session.expiresAt,
      voucherType: normalizeVoucherType(session.voucherType || row.type),
    });
  }

  if (session && session.state === 'paused') {
    // Premium pause freezes the remaining time on the session row.
    const statusToken = setSessionCookie(
      req, res, session.sessionId, identityScopeFor(req, session.sessionId)
    );
    return res.json({
      success: true,
      active: true,
      state: 'paused',
      sessionId: session.sessionId,
      statusToken: statusToken || null,
      remainingSeconds: computeRemaining(session, serverTime),
      expiresAt: session.expiresAt,
      voucherType: normalizeVoucherType(session.voucherType || row.type),
    });
  }

  if (session && (session.state === 'pending_payment' || session.state === 'pending_verification')) {
    // Payment recorded, duration not started yet — the full time is still due.
    const statusToken = setSessionCookie(
      req, res, session.sessionId, identityScopeFor(req, session.sessionId)
    );
    return res.json({
      success: true,
      active: true,
      state: session.state,
      sessionId: session.sessionId,
      statusToken: statusToken || null,
      remainingSeconds: computeRemaining(session, serverTime),
      expiresAt: session.expiresAt,
      voucherType: normalizeVoucherType(session.voucherType || row.type),
    });
  }

  // Used voucher with no live session left (or a session that has fully
  // elapsed). Same collapsed answer as an unknown code (H-03).
  return sendVoucherUnavailable(res);
}

/**
 * sendVoucherUnavailable — the ONE response for a code that is not currently
 * redeemable/queryable in a distinguishable way. Deliberately carries no
 * reason, duration, tier or expiry so "never existed" and "already used"
 * cannot be told apart by an unauthenticated caller.
 *
 * @param {Object} res
 */
function sendVoucherUnavailable(res) {
  return res.json({ success: true, active: false, state: 'unknown' });
}

function computeRemaining(session, serverTime) {
  if (!session) return 0;

  if (session.state === 'expired' || session.state === 'unknown') return 0;

  // Hard-expired Premium pass: report nothing left, whatever the frozen or
  // counted-down value still says (defensive — getSession() already expires it).
  if (isHardExpired(session)) return 0;

  if (session.state === 'paused') {
    // Use the server-side frozen remaining time
    return Math.max(0, session.remainingSeconds || 0);
  }

  // Active: calculate from expiresAt
  if (session.expiresAt) {
    const expiresAt = Math.floor(new Date(session.expiresAt).getTime() / 1000);
    return Math.max(0, expiresAt - serverTime);
  }

  // Fallback: use startedAt + duration
  const startedAt = Math.floor(new Date(session.startedAt).getTime() / 1000);
  const durationSecs = session.totalDurationSeconds || (session.duration || 60) * 60;
  return Math.max(0, (startedAt + durationSecs) - serverTime);
}

module.exports = router;
