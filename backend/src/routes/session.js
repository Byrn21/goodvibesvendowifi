/**
 * routes/session.js
 *
 * GET  /api/session/status  — Poll session remaining time
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
  expireSession,
  isSessionActive,
  getPauseRemaining,
} = require('../services/session');
const omadaService = require('../services/omada');
const { getDb } = require('../db/client');
const { normalizeMac } = require('../utils/device-id');

// ── GET /api/session/status ──────────────────────────────────
router.get('/status', async (req, res, next) => {
  try {
    let { sessionId } = req.query;
    const { mac } = req.query;

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
      state: session.state,
      remainingSeconds,
      startedAt: session.startedAt,
      expiresAt: session.expiresAt,
      voucherType: session.voucherType || 'standard',
      voucherCode: maskVoucherCode(session.voucherUsed),
      totalSeconds: (session.totalDurationSeconds || (session.duration || 60) * 60),
      canPause:  session.state === 'active' && remainingSeconds > 60 && session.voucherType === 'premium',
      canResume: session.state === 'paused',
      pauseValidRemainingSeconds: session.state === 'paused' && session.voucherType === 'premium'
        ? await getPauseRemaining(sessionId)
        : null,
    });
  } catch (err) {
    // Log real database/processing errors server-side — never let them
    // masquerade as a "session not found" response on the client.
    console.error('[session/status] Error while fetching session ' + sessionId + ':', err.message, err.stack);
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
    if (session.voucherType !== 'premium') {
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
    if (session.voucherType !== 'premium') {
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
