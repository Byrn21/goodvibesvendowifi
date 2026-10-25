/**
 * routes/session.js
 *
 * GET  /api/session/status  — Poll session remaining time
 *                             (?sessionId=, ?mac=, or ?voucher= for the
 *                              offline "Check Voucher Status" modal)
 * POST /api/session/pause  — Pause active session
 * POST /api/session/resume — Resume paused session
 * POST /api/session/expire — Admin: immediately expire session
 */

const express = require('express');
const router = express.Router();
const {
  getSession,
  pauseSession,
  resumeSession,
  reauthorizeSession,
  expireSession,
  isSessionActive,
  getPauseRemaining,
  isPausableVoucherType,
  getSessionByVoucher,
} = require('../services/session');
const omadaService = require('../services/omada');
const { getDb } = require('../db/client');
const { normalizeMac } = require('../utils/device-id');
const { normalizeVoucherType } = require('../utils/qos');
const { normalizeVoucherCode, validateVoucherCodeFormat } = require('../utils/voucher-code');

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

    // The payment QR flow does not have a sessionId yet, so it polls with
    // ?mac=<client_mac>. Resolve the newest non-terminal session for that
    // device (case-insensitive MAC match); polling continues on 404.
    if (!sessionId && mac && typeof mac === 'string') {
      const normalized = normalizeMac(mac);
      const row = normalized
        ? await getDb().getOne(
            `SELECT session_id FROM sessions
              WHERE LOWER(client_mac) = LOWER(?)
                AND state IN ('active', 'paused', 'pending_payment', 'pending_verification')
              ORDER BY id DESC LIMIT 1`,
            [normalized]
          )
        : null;
      if (row && row.session_id) {
        sessionId = row.session_id;
      } else {
        return res.status(404).json({
          success: false,
          error: 'No active session exists for this device.',
          code: 'SESSION_NOT_FOUND',
        });
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

    const serverTime = Math.floor(Date.now() / 1000);

    // Determine if session has expired server-side (defensive; backend should already expire)
    if (session.state === 'active' && session.expiresAt) {
      const expiresAt = Math.floor(new Date(session.expiresAt).getTime() / 1000);
      if (serverTime >= expiresAt) {
        // Server-side expired — call unauth and update state
        await expireSession(sessionId, 'server_expired');
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
          voucherType: session.voucherType || 'standard',
          voucherCode: maskVoucherCode(session.voucherUsed),
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
      voucherType: session.voucherType || 'standard',
      voucherCode: maskVoucherCode(session.voucherUsed),
      totalSeconds: (session.totalDurationSeconds || (session.duration || 60) * 60),
      canPause:  session.state === 'active' && remainingSeconds > 60 && isPausableVoucherType(session.voucherType),
      canResume: session.state === 'paused',
      pauseValidRemainingSeconds: session.state === 'paused' && isPausableVoucherType(session.voucherType)
        ? await getPauseRemaining(sessionId)
        : null,
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
      `SELECT session_id FROM sessions
        WHERE LOWER(client_mac) = LOWER(?)
          AND state = 'active'
          AND expires_at IS NOT NULL AND expires_at > ?
        ORDER BY id DESC LIMIT 1`,
      [normalized, new Date().toISOString()]
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
        if (session.state !== 'active') {
      return res.status(409).json({ success: false, error: 'Session is not active.', code: 'INVALID_STATE' });
    }
    // Plan-tier gate: Standard (and any other non-pausable tier) is rejected
    // here even if the client bypasses the UI and POSTs directly.
    if (!isPausableVoucherType(session.voucherType)) {
      return res.status(403).json({ success: false, error: 'Pause is only available for Premium sessions.', code: 'PREMIUM_ONLY' });
    }

        const paused = await pauseSession(sessionId);
    return res.json({
      success: true,
      state: 'paused',
      voucherType: paused.voucherType || 'standard',
      remainingSeconds: computeRemaining(paused, Math.floor(Date.now() / 1000)),
      pausedAt: paused.pausedAt,
      pauseValidRemainingSeconds: await getPauseRemaining(sessionId),
    });
  } catch (err) {
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
        if (session.state !== 'paused') {
      return res.status(409).json({ success: false, error: 'Session is not paused.', code: 'INVALID_STATE' });
    }
    if (!isPausableVoucherType(session.voucherType)) {
      return res.status(403).json({ success: false, error: 'Resume is only available for Premium sessions.', code: 'PREMIUM_ONLY' });
    }

        const resumed = await resumeSession(sessionId);
    return res.json({
      success: true,
      state: 'active',
      voucherType: resumed.voucherType || 'standard',
      remainingSeconds: computeRemaining(resumed, Math.floor(Date.now() / 1000)),
      expiresAt: resumed.expiresAt,
    });
  } catch (err) {
    next(err);
  }
});

// ── POST /api/session/expire ──────────────────────────────────
// This is an admin/internal endpoint. In production, add admin auth.
router.post('/expire', async (req, res, next) => {
  try {
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
 *   - consumed voucher whose session ended -> { active: false, error: 'EXPIRED' }
 *   - code not in the vouchers table       -> 404 { active: false }
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

  // Unknown code — distinct from an expired one so the UI can say
  // "not found" rather than "expired".
  if (!row) {
    return res.status(404).json({
      success: false,
      active: false,
      code: 'VOUCHER_NOT_FOUND',
      error: 'Voucher code not found.',
    });
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
    return res.json({
      success: true,
      active: false,
      error: 'EXPIRED',
      state: 'expired',
      remainingSeconds: 0,
      expiresAt: voucherExpiresAt,
      voucherType: normalizeVoucherType(row.type),
    });
  }

  // Unconsumed voucher: its full duration is still available.
  if (row.state === 'active' || row.state === 'claimed') {
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

  // Consumed ('used'): the answer lives on the session the code created.
  // getSessionByVoucher -> getSession() applies server-side expiry, so an
  // active-but-timed-out session comes back as state 'expired'.
  const session = await getSessionByVoucher(code);

  if (session && session.state === 'active') {
    return res.json({
      success: true,
      active: true,
      state: 'active',
      sessionId: session.sessionId,
      remainingSeconds: computeRemaining(session, serverTime),
      expiresAt: session.expiresAt,
      voucherType: normalizeVoucherType(session.voucherType || row.type),
    });
  }

  if (session && session.state === 'paused') {
    // Premium pause freezes the remaining time on the session row.
    return res.json({
      success: true,
      active: true,
      state: 'paused',
      sessionId: session.sessionId,
      remainingSeconds: computeRemaining(session, serverTime),
      expiresAt: session.expiresAt,
      voucherType: normalizeVoucherType(session.voucherType || row.type),
    });
  }

  if (session && (session.state === 'pending_payment' || session.state === 'pending_verification')) {
    // Payment recorded, duration not started yet — the full time is still due.
    return res.json({
      success: true,
      active: true,
      state: session.state,
      sessionId: session.sessionId,
      remainingSeconds: computeRemaining(session, serverTime),
      expiresAt: session.expiresAt,
      voucherType: normalizeVoucherType(session.voucherType || row.type),
    });
  }

  // Used voucher with no live session left (or a session that has fully
  // elapsed): fully consumed / expired.
  return res.json({
    success: true,
    active: false,
    error: 'EXPIRED',
    state: (session && session.state) || 'expired',
    remainingSeconds: 0,
    expiresAt: (session && session.expiresAt) || voucherExpiresAt,
    voucherType: normalizeVoucherType((session && session.voucherType) || row.type),
  });
}

function computeRemaining(session, serverTime) {
  if (!session) return 0;

  if (session.state === 'expired' || session.state === 'unknown') return 0;

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
