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
const { getDb } = require('../db/client');
const { normalizeMac } = require('../utils/device-id');
const { resolveClientMacByIp } = require('../utils/portal-context');
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
    if (!sessionId && !(mac && typeof mac === 'string')) {
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
          });
        }
        throw err;
      }

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
    if (!sessionId && mac && typeof mac === 'string') {
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

        const paused = await pauseSession(sessionId);
    return res.json({
      success: true,
      state: 'paused',
      voucherType: paused.voucherType || 'standard',
      remainingSeconds: computeRemaining(paused, Math.floor(Date.now() / 1000)),
      pausedAt: paused.pausedAt,
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
