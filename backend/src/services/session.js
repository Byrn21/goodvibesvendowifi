/**
 * services/session.js — Session state machine and database operations
 *
 * Server-side session management. The browser countdown is only a
 * display mechanism. THIS service is authoritative.
 *
 * States:
 *   active    — Session is running, timer counting down
 *   paused    — Session is frozen, timer stopped
 *   expired   — Session has ended (time up, or manually expired)
 */

const { v4: uuidv4 } = require('uuid');
const omadaService = require('./omada');
const { getDb } = require('../db/client');

const DEFAULT_DURATION = parseInt(process.env.DEFAULT_SESSION_DURATION || '60', 10);
const EXPIRE_CHECK_INTERVAL = parseInt(process.env.SESSION_ENFORCE_INTERVAL || '60000', 10);
const PREMIUM_PAUSE_VALIDITY_HOURS = parseInt(process.env.PREMIUM_PAUSE_VALIDITY_HOURS || '168', 10);
let expirationTimer = null;

/**
 * Normalize a MAC address to lowercase colon-separated format.
 */
function normalizeMac(mac) {
  if (!mac || typeof mac !== 'string') return null;
  const cleaned = mac.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (cleaned.length !== 12) return null;
  return cleaned.match(/.{2}/g).join(':');
}

/**
 * validateVoucher — Validate a voucher code against the database.
 * Returns { valid, code, duration, message }
 */
async function validateVoucher(voucher, clientMac) {
  const db = getDb();

    const row = await db.getOne(`
    SELECT id, code, duration_minutes, type, state, used_by_mac, expires_at
    FROM vouchers
    WHERE code = ? 
    LIMIT 1
  `, [voucher]);

  if (!row) {
    return { valid: false, code: 'INVALID_VOUCHER', message: 'Invalid voucher code.' };
  }

  if (row.state === 'expired') {
    return { valid: false, code: 'EXPIRED_VOUCHER', message: 'This voucher has expired.' };
  }

  if (row.state === 'used') {
    return { valid: false, code: 'USED_VOUCHER', message: 'This voucher has already been used.' };
  }

  if (row.state !== 'active') {
    return { valid: false, code: 'INVALID_VOUCHER', message: 'Voucher is not available.' };
  }

  // Check voucher expiration date
  if (row.expires_at) {
    const expiresAt = new Date(row.expires_at);
    if (Date.now() > expiresAt.getTime()) {
      await db.run(`UPDATE vouchers SET state = 'expired' WHERE id = ?`, [row.id]);
      return { valid: false, code: 'EXPIRED_VOUCHER', message: 'This voucher has expired.' };
    }
  }

  // Mark voucher as used
  await db.run(`
    UPDATE vouchers
    SET state = 'used', used_by_mac = ?, used_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `, [clientMac || '', row.id]);

    return { valid: true, duration: row.duration_minutes, type: row.type || 'standard', message: 'Voucher accepted.' };
}

/**
 * recordSession — Record a new active session in the database.
 */
async function recordSession({
  sessionId, clientMac, clientIp, apMac, ssidName,
  duration, voucherUsed, voucherType, totalDurationSeconds,
}) {
  const db = getDb();
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + duration * 60 * 1000).toISOString();

    await db.run(`
    INSERT INTO sessions (
      session_id, client_mac, client_ip, ap_mac, ssid_name,
      duration_minutes, voucher_type, total_duration_seconds, started_at, expires_at, state,
      voucher_used, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
  `, [
    sessionId,
    clientMac || '',
    clientIp || '',
    apMac || '',
    ssidName || '',
    duration,
    voucherType || 'standard',
    totalDurationSeconds || null,
    now,
    expiresAt,
    voucherUsed || null,
    now,
    now,
  ]);

  return await getSession(sessionId);
}

/**
 * getSession — Get a session by ID.
 */
async function getSession(sessionId) {
  const db = getDb();

  const row = await db.getOne(`
    SELECT * FROM sessions WHERE session_id = ? LIMIT 1
  `, [sessionId]);

  if (!row) return null;

  // Map database columns to camelCase
  const session = {
    sessionId: row.session_id,
    clientMac: row.client_mac,
    clientIp: row.client_ip,
    apMac: row.ap_mac,
    ssidName: row.ssid_name,
        duration: row.duration_minutes,
    voucherType: row.voucher_type || 'standard',
    totalDurationSeconds: row.total_duration_seconds,
    startedAt: row.started_at,
    expiresAt: row.expires_at,
    pausedAt: row.paused_at,
    remainingSeconds: row.remaining_seconds,
    state: row.state,
    voucherUsed: row.voucher_used,
    omadaAuthFailed: Boolean(row.omada_auth_failed),
    expireReason: row.expire_reason,
    expiredAt: row.expired_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };

  // radioId is not stored on sessions (controller context lives in
  // portal_client_context); enrich from there for resume/activate calls.
  // Best-effort: a missing row defaults to radioId 0 (single-radio APs).
  try {
    const ctxRow = await db.getOne(
      'SELECT radio_id FROM portal_client_context WHERE client_mac = ?',
      [row.client_mac]
    );
    session.radioId = ctxRow && ctxRow.radio_id !== null && ctxRow.radio_id !== undefined
      ? ctxRow.radio_id
      : 0;
  } catch (_) {
    session.radioId = 0; // context table may not exist yet in legacy DBs
  }

  // Check server-side expiration for active sessions
  if (session.state === 'active' && session.expiresAt) {
    const now = Date.now();
    const expiresAt = new Date(session.expiresAt).getTime();
    if (now >= expiresAt) {
      await expireSession(sessionId, 'time_expired');
      return { ...session, state: 'expired' };
    }
  }

  return session;
}

/**
 * expireSession — Deactivate via Omada and mark expired in DB.
 */
async function expireSession(sessionId, reason = 'time_expired') {
  const db = getDb();
  const session = await getSession(sessionId);

  if (!session) return false;
  if (session.state === 'expired') return false; // Idempotent

  const prevState = session.state;
  const now = new Date().toISOString();

  await db.run(`
    UPDATE sessions
    SET state = 'expired', expired_at = ?, expire_reason = ?, updated_at = ?
    WHERE session_id = ?
  `, [now, reason || 'unknown', now, sessionId]);

  // Call Omada unauth only if session was active or paused
  if (prevState === 'active' || prevState === 'paused') {
    try {
      await omadaService.unauthenticateClient({
        clientMac: session.clientMac,
        apMac: session.apMac,
        ssidName: session.ssidName,
      });
    } catch (err) {
      console.warn('[expireSession] Omada unauth failed:', err.message);
    }
  }

  return true;
}

/**
 * pauseSession — Freeze an active session's timer.
 * Omada unauthenticates the client; time is stored in remaining_seconds.
 */
async function pauseSession(sessionId) {
  const db = getDb();
  const session = await getSession(sessionId);

  if (!session) {
    throw new Error('Session not found');
  }

  if (session.state !== 'active') {
    throw new Error('Session not active');
  }

  // Premium-only: standard vouchers do not support pause
  if (session.voucherType !== 'premium') {
    const err = new Error('Pause is only available for Premium sessions');
    err.code = 'PREMIUM_ONLY';
    throw err;
  }

  // Enforce pause validity window for premium sessions
  if (session.pausedAt) {
    const pauseAgeHours = (Date.now() - new Date(session.pausedAt).getTime()) / (1000 * 60 * 60);
    if (pauseAgeHours >= PREMIUM_PAUSE_VALIDITY_HOURS) {
      await expireSession(sessionId, 'pause_expired');
      const expiredErr = new Error('Pause validity period has expired');
      expiredErr.code = 'PAUSE_EXPIRED';
      throw expiredErr;
    }
  }

  const now = new Date();
  const remainingSeconds = Math.max(
    0,
    Math.floor((new Date(session.expiresAt) - now) / 1000)
  );

  await db.run(`
    UPDATE sessions
    SET state = 'paused', paused_at = ?, remaining_seconds = ?, expires_at = NULL, updated_at = ?
    WHERE session_id = ?
  `, [now.toISOString(), remainingSeconds, now.toISOString(), sessionId]);

  // Tell Omada to de-authorize the client
  try {
    await omadaService.unauthenticateClient({
      clientMac: session.clientMac,
      apMac: session.apMac,
      ssidName: session.ssidName,
    });
  } catch (err) {
    console.warn('[pauseSession] Omada unauth failed:', err.message);
  }

  return await getSession(sessionId);
}

/**
 * resumeSession — Restart a paused session.
 * Restarts the timer from the remaining seconds.
 */
async function resumeSession(sessionId) {
  const db = getDb();
  const session = await getSession(sessionId);

  if (!session || session.state !== 'paused') {
    throw new Error('Session not paused');
  }

    const remaining = session.remainingSeconds || (session.duration || 60) * 60;
  const expiresAt = new Date(Date.now() + remaining * 1000).toISOString();

  const username = (session.voucherType === 'premium' ? 'prem_' : 'paid_') + sessionId;

  // Re-authenticate via Omada
  try {
    await omadaService.authenticateClient({
      clientMac: session.clientMac,
      clientIp: session.clientIp,
      apMac: session.apMac,
      ssidName: session.ssidName,
      radioId: session.radioId || 0,
      durationMinutes: Math.ceil(remaining / 60),
      sessionId,
    });
  } catch (err) {
    console.error('[resumeSession] Omada auth failed:', err.message);
    throw new Error('Could not reconnect to network. Please try again.');
  }

  await db.run(`
    UPDATE sessions
    SET state = 'active', paused_at = NULL, expires_at = ?, updated_at = ?
    WHERE session_id = ?
  `, [expiresAt, new Date().toISOString(), sessionId]);

    return await getSession(sessionId);
}

/**
 * Check if a session is currently active (server-side truth).
 */
async function isSessionActive(sessionId) {
  const session = await getSession(sessionId);
  if (!session) return false;
  if (session.state !== 'active') return false;
  if (session.expiresAt) {
    return Date.now() < new Date(session.expiresAt).getTime();
  }
    return true;
}

/**
 * startExpirationWorker — Background timer that expires sessions server-side.
 * Queries for active sessions whose expires_at has passed, then calls
 * Omada unauth and marks them expired. Runs every EXPIRE_CHECK_INTERVAL ms.
 */
function startExpirationWorker() {
  if (expirationTimer) return; // Already running

  expirationTimer = setInterval(async () => {
    const db = getDb();
    const now = new Date().toISOString();

        const expiredSessions = await db.query(`
      SELECT session_id FROM sessions
      WHERE state = 'active' AND expires_at IS NOT NULL AND expires_at <= ?
    `, [now]);

    for (const row of expiredSessions) {
      await expireSession(row.session_id, 'time_expired');
    }

        // Also expire premium sessions paused beyond the validity window
    const maxPausedAt = new Date(Date.now() - PREMIUM_PAUSE_VALIDITY_HOURS * 60 * 60 * 1000).toISOString();
    let stalePaused = [];
    try {
      stalePaused = await db.query(`
      SELECT session_id FROM sessions
      WHERE state = 'paused' AND voucher_type = 'premium' AND paused_at IS NOT NULL AND paused_at <= ?
    `, [maxPausedAt]);
    } catch (err) {
      // voucher_type column may not exist in older databases — fall back to query without it
      if (err.code === '42701' || err.message && err.message.includes('voucher_type')) {
        console.warn('[expiration-worker] voucher_type column not found, using fallback query');
        stalePaused = await db.query(`
        SELECT session_id FROM sessions
        WHERE state = 'paused' AND paused_at IS NOT NULL AND paused_at <= ?
      `, [maxPausedAt]);
      } else {
        throw err;
      }
    }

    for (const row of stalePaused) {
      await expireSession(row.session_id, 'pause_expired');
    }

    if (expiredSessions.length > 0) {
      console.log(`[expiration-worker] Expired ${expiredSessions.length} session(s)`);
    }
    if (stalePaused.length > 0) {
      console.log(`[expiration-worker] Expired ${stalePaused.length} paused premium session(s) past validity window`);
    }
  }, EXPIRE_CHECK_INTERVAL);

  // Don't let the timer keep the process alive in tests
  if (typeof expirationTimer.unref === 'function') {
    expirationTimer.unref();
  }
}

function stopExpirationWorker() {
    if (expirationTimer) {
    clearInterval(expirationTimer);
    expirationTimer = null;
  }
}

/**
 * markPaymentPending — Set session state to pending_payment with provider session ID.
 */
async function markPaymentPending(sessionId, providerSessionId) {
  const db = getDb();
  const now = new Date().toISOString();

  await db.run(`
    UPDATE sessions
    SET state = 'pending_payment',
        provider_session_id = ?,
        updated_at = ?
    WHERE session_id = ?
  `, [providerSessionId || null, now, sessionId]);

  return await getSession(sessionId);
}

/**
 * activatePaidSession — Activate a session after successful payment.
 * Sets state to 'active', records payment details, and authenticates via Omada.
 */
async function activatePaidSession(sessionId, eventId, amount, webhookVoucherType) {
  const db = getDb();
  const now = new Date().toISOString();

  // Compute expiry from existing duration
  const session = await getSession(sessionId);
  if (!session) {
    throw new Error('Session not found for payment activation');
  }

        const duration = session.duration;
  const voucherType = session.voucherType || webhookVoucherType || 'standard';

  // Compute expiry: for premium, use remainingSeconds if already set (from pause); otherwise full duration
  let expiresAt;
  if (voucherType === 'premium' && session.totalDurationSeconds) {
    const remaining = session.remainingSeconds || session.totalDurationSeconds;
    expiresAt = new Date(Date.now() + remaining * 1000).toISOString();
  } else {
    expiresAt = new Date(Date.now() + duration * 60 * 1000).toISOString();
  }
  const username = (voucherType === 'premium' ? 'prem_' : 'paid_') + sessionId;

  // Authenticate via Omada
  await omadaService.authenticateClient({
    clientMac: session.clientMac,
    clientIp:  session.clientIp,
    apMac:     session.apMac,
    ssidName:  session.ssidName,
    radioId:   session.radioId || 0,
    durationMinutes: duration,
    sessionId: sessionId,
  });

    await db.run(`
    UPDATE sessions
    SET state = 'active',
        payment_event_id = ?,
        payment_amount = ?,
        voucher_type = ?,
        started_at = ?,
        expires_at = ?,
        updated_at = ?
    WHERE session_id = ?
  `, [eventId || null, amount || null, voucherType, now, expiresAt, now, sessionId]);

  return await getSession(sessionId);
}

/**
 * markPaymentFailed — Mark a session's payment as failed.
 */
async function markPaymentFailed(sessionId, eventId) {
  const db = getDb();
  const now = new Date().toISOString();

  await db.run(`
    UPDATE sessions
    SET state = 'payment_failed',
        payment_event_id = ?,
        updated_at = ?
    WHERE session_id = ?
  `, [eventId || null, now, sessionId]);

  return await getSession(sessionId);
}

/**
 * isEventProcessed — Check if a webhook event has already been processed.
 */
async function isEventProcessed(eventId) {
  const db = getDb();
  const row = await db.getOne(`
    SELECT 1 FROM webhook_events WHERE event_id = ? LIMIT 1
  `, [eventId]);
  return !!row;
}

/**
 * markEventProcessed — Record a processed webhook event for idempotency.
 */
async function markEventProcessed(eventId, sessionId) {
  const db = getDb();
  const now = new Date().toISOString();

  try {
    await db.run(`
      INSERT INTO webhook_events (event_id, session_id, processed_at)
      VALUES (?, ?, ?)
    `, [eventId, sessionId || null, now]);
  } catch (err) {
    // Unique violation — event already recorded, skip (idempotent)
    if (err.code === '23505' || err.code === 'SQLITE_CONSTRAINT') {
      return;
    }
    throw err;
  }
}

/**
 * getPauseRemaining — Calculate seconds remaining in the pause validity window.
 * Only meaningful for premium sessions in 'paused' state.
 *
 * @param {string} sessionId
 * @returns {Promise<number|null>} seconds remaining, or null if not applicable
 */
async function getPauseRemaining(sessionId) {
  const session = await getSession(sessionId);
  if (!session || session.state !== 'paused' || session.voucherType !== 'premium') {
    return null;
  }
  if (!session.pausedAt) return null;

  const pauseValidUntil = new Date(session.pausedAt).getTime() + PREMIUM_PAUSE_VALIDITY_HOURS * 60 * 60 * 1000;
  const remaining = Math.max(0, Math.floor((pauseValidUntil - Date.now()) / 1000));
  return remaining;
}

module.exports = {
  validateVoucher,
  recordSession,
  getSession,
  pauseSession,
  resumeSession,
  expireSession,
  isSessionActive,
  startExpirationWorker,
  stopExpirationWorker,
  normalizeMac,
  markPaymentPending,
  activatePaidSession,
  markPaymentFailed,
    isEventProcessed,
  markEventProcessed,
  getPauseRemaining,
};
