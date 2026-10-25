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
const omadaNorthbound = require('./omada-northbound');
const { resolveVoucherRateLimit } = require('../utils/qos');
const { getDb } = require('../db/client');

const DEFAULT_DURATION = parseInt(process.env.DEFAULT_SESSION_DURATION || '60', 10);
const EXPIRE_CHECK_INTERVAL = parseInt(process.env.SESSION_ENFORCE_INTERVAL || '60000', 10);
const PREMIUM_PAUSE_VALIDITY_HOURS = parseInt(process.env.PREMIUM_PAUSE_VALIDITY_HOURS || '168', 10);
let expirationTimer = null;

/**
 * Plan tiers allowed to pause/resume a session.
 *
 * BUSINESS POLICY: only the premium tier is pausable today. Adding a tier id
 * here enables Pause/Resume for that tier everywhere, because the API gate
 * (routes/session.js) and every service guard below read this single list.
 * A Standard session therefore cannot pause even if the portal UI is
 * bypassed. The portal UI mirrors this list in status.html (PAUSABLE_PLANS).
 */
const PAUSABLE_VOUCHER_TYPES = ['premium'];

/**
 * isPausableVoucherType — true when a plan tier may pause/resume.
 * @param {string} voucherType  e.g. 'standard' | 'premium'
 */
function isPausableVoucherType(voucherType) {
  return PAUSABLE_VOUCHER_TYPES.indexOf(voucherType) !== -1;
}

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
 *
 * SIDE-EFFECT FREE: this performs the state/expiry checks only and NEVER
 * marks the voucher as used. Consumption is a separate step (consumeVoucher)
 * that callers must run ONLY after the Omada controller confirms the client
 * was authorized — otherwise a failed extPortal/auth call would burn the
 * guest's voucher while the network stays locked.
 *
 * Returns { valid, code, duration, type, message, id? }
 */
async function validateVoucher(voucher, clientMac) {
  const db = getDb();

    const row = await db.getOne(`
    SELECT id, code, duration_minutes, type, state, used_by_mac, expires_at,
           down_kbps, up_kbps
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

  // 'active' vouchers are freely redeemable. 'claimed' vouchers were matched
  // to a specific payment by POST /api/payment/claim (assigned_ref_no) and are
  // now being redeemed by that customer through the normal voucher flow — so
  // they are accepted here too. Any other state is unavailable.
  if (row.state !== 'active' && row.state !== 'claimed') {
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

  // Validation is intentionally read-only. The voucher is marked 'used' by
  // consumeVoucher() and only AFTER Omada confirms authorization.
  return {
    valid: true,
    id: row.id,
    duration: row.duration_minutes,
    type: row.type || 'standard',
    // Per-voucher QoS caps (Kbps). NULL/absent means the tier defaults apply —
    // see utils/qos.js → resolveVoucherRateLimit().
    downKbps: row.down_kbps,
    upKbps: row.up_kbps,
    message: 'Voucher accepted.',
  };
}

/**
 * consumeVoucher — Atomically mark a previously validated voucher as used.
 *
 * MUST be called only after Omada confirms the client is authorized. The
 * state guard (`state IN active/claimed`) makes the update race-safe and
 * idempotent: if another request consumed the voucher in between, rowCount
 * is 0 and this returns false — the caller must then NOT record a session.
 *
 * @param {string} voucher   Normalized voucher code
 * @param {string} clientMac Client MAC the voucher is being bound to
 * @param {Object} [tx]      Optional transaction handle from db.transaction(),
 *                           so the caller can commit this write together with
 *                           the session it records (see routes/auth.js)
 * @returns {Promise<boolean>} true only if THIS call consumed the voucher
 */
async function consumeVoucher(voucher, clientMac, tx) {
  // Running inside the caller's transaction when one is supplied keeps the
  // local voucher state and the session row in ONE atomic unit: the
  // controller does not track our vouchers, so this database is the only
  // authority and a torn write would either burn a valid code or leave a
  // session no voucher accounts for.
  const db = tx || getDb();
  const result = await db.run(`
    UPDATE vouchers
    SET state = 'used', used_by_mac = ?, used_at = CURRENT_TIMESTAMP
    WHERE code = ? AND state IN ('active', 'claimed')
  `, [clientMac || '', voucher]);
  return Boolean(result && result.rowCount > 0);
}

/**
 * recordSession — Record a new active session in the database.
 *
 * @param {Object} data           Session fields (see the destructuring below)
 * @param {Object} [tx]           Optional transaction handle from
 *                                db.transaction() so the insert commits with
 *                                the voucher consumption it belongs to.
 *                                In tx mode this returns null: the row is not
 *                                committed yet, and on PostgreSQL a pool-wide
 *                                read would not see it.
 * @returns {Promise<Object|null>} the stored session, or null in tx mode
 */
async function recordSession({
  sessionId, clientMac, clientIp, apMac, ssidName,
  duration, voucherUsed, voucherType, totalDurationSeconds,
  downKbps, upKbps,
}, tx) {
  const db = tx || getDb();
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + duration * 60 * 1000).toISOString();

    await db.run(`
    INSERT INTO sessions (
      session_id, client_mac, client_ip, ap_mac, ssid_name,
      duration_minutes, voucher_type, down_kbps, up_kbps, total_duration_seconds,
      started_at, expires_at, state,
      voucher_used, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
  `, [
    sessionId,
    clientMac || '',
    clientIp || '',
    apMac || '',
    ssidName || '',
    duration,
    voucherType || 'standard',
    // Bandwidth snapshot (Kbps). Stored with the session so a re-auth or a
    // premium resume re-applies the same cap without re-reading the voucher.
    downKbps || null,
    upKbps || null,
    totalDurationSeconds || null,
    now,
    expiresAt,
    voucherUsed || null,
    now,
    now,
  ]);

  // See the JSDoc: inside a transaction the caller must not depend on the
  // returned session (uncommitted here, invisible to a pool-wide read on
  // PostgreSQL).
  if (tx) return null;
  return await getSession(sessionId);
}

/**
 * loadSession — read a session row and map it to the session object.
 *
 * PURE READ: unlike getSession(), this NEVER applies the lazy active→expired
 * side effect. expireSession() uses it precisely so the chain
 * getSession() → expireSession() → loadSession() cannot re-enter getSession()
 * and recurse forever (see the note on getSession below).
 *
 * @param {string} sessionId
 * @returns {Promise<Object|null>}
 */
async function loadSession(sessionId) {
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
    downKbps: row.down_kbps,
    upKbps: row.up_kbps,
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

  return session;
}

/**
 * getSession — Get a session by ID, applying the lazy server-side expiry.
 *
 * CRITICAL: the expiry branch below passes the session it already read into
 * expireSession(). expireSession() must NEVER call getSession() back: the row
 * is still 'active' in the database (nothing has been written yet), so a
 * re-entrant getSession() would see the same active-but-timed-out row, call
 * expireSession() again, and so on — an unbounded async recursion that never
 * yields to the event loop and exhausts the heap on a long-lived server.
 *
 * @param {string} sessionId
 * @returns {Promise<Object|null>}
 */
async function getSession(sessionId) {
  const session = await loadSession(sessionId);
  if (!session) return null;

  // Check server-side expiration for active sessions
  if (session.state === 'active' && session.expiresAt) {
    const now = Date.now();
    const expiresAt = new Date(session.expiresAt).getTime();
    if (now >= expiresAt) {
      await expireSession(sessionId, 'time_expired', session);
      return { ...session, state: 'expired' };
    }
  }

  return session;
}

/**
 * expireSession — Deactivate via Omada and mark expired in DB.
 *
 * @param {string} sessionId
 * @param {string} [reason]
 * @param {Object} [loaded]  Session already read by the caller (getSession's
 *                           lazy-expiry path). Read here when absent. The row
 *                           is deliberately loaded with loadSession(), NOT
 *                           getSession(): the latter would re-enter its own
 *                           expiry branch on an active-but-timed-out row and
 *                           recurse forever.
 */
async function expireSession(sessionId, reason = 'time_expired', loaded) {
  const db = getDb();
  const session = loaded || await loadSession(sessionId);

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

  // Plan-tier gate: only pausable tiers (currently premium) may pause.
  if (!isPausableVoucherType(session.voucherType)) {
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

  // Plan-tier gate (defense in depth: the route rejects this first).
  if (!isPausableVoucherType(session.voucherType)) {
    const err = new Error('Resume is only available for Premium sessions');
    err.code = 'PREMIUM_ONLY';
    throw err;
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
      // Re-send the same voucher the session was opened with, so every
      // extPortal/auth call carries the `code` field identically.
      voucherCode: session.voucherUsed || '',
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

  // Re-apply the bandwidth cap: pause de-authorized the client, and the
  // controller is not guaranteed to keep a per-client rate limit across that.
  // Best-effort — the guest is online either way.
  await applySessionRateLimit(session);

    return await getSession(sessionId);
}

/**
 * applySessionRateLimit — apply a session's stored bandwidth caps to its client.
 *
 * NEVER throws: the guest is already authorized when this runs, so a failed QoS
 * call must not be turned into a failed login/resume. The caller logs what it
 * needs from the returned flag.
 *
 * The caps come from the session row (copied from the voucher at authorization
 * time), falling back to the tier rules in utils/qos.js.
 *
 * @param {Object} session session object from getSession()/loadSession()
 * @returns {Promise<{applied: boolean, mock?: boolean, error?: string, customRateLimit?: Object}>}
 */
async function applySessionRateLimit(session) {
  if (!session || !session.clientMac) return { applied: false, error: 'no session/clientMac' };

  const customRateLimit = resolveVoucherRateLimit({
    downKbps: session.downKbps,
    upKbps: session.upKbps,
    voucherType: session.voucherType,
  });

  try {
    const result = await omadaNorthbound.applyClientRateLimit(
      customRateLimit
        ? { clientMac: session.clientMac, customRateLimit }
        : { clientMac: session.clientMac }
    );

    if (result && result.mock) {
      console.warn(
        '[session/qos] rate limit NOT applied to ' + session.clientMac +
        ' — omada-northbound is in MOCK mode (configure OMADA_NORTHBOUND_BASE_URL' +
        ' / OMADA_NORTHBOUND_REGION + OMADA_CLIENT_ID + OMADA_CLIENT_SECRET)'
      );
    } else {
      console.log(
        '[session/qos] rate limit applied to ' + session.clientMac +
        ' (' + (customRateLimit ? 'voucher/premium caps' : 'default caps') + ')' +
        ' up=' + JSON.stringify(customRateLimit ? [customRateLimit.upUnit, customRateLimit.upLimit] : 'default') +
        ' down=' + JSON.stringify(customRateLimit ? [customRateLimit.downUnit, customRateLimit.downLimit] : 'default')
      );
    }

    return {
      applied: Boolean(result && result.success),
      mock: Boolean(result && result.mock),
      customRateLimit,
    };
  } catch (err) {
    console.error(
      '[session/qos] authorized but rate limit failed for ' + session.clientMac +
      ': ' + ((err && err.message) || String(err)) +
      ' — the guest is online but UNCAPPED; re-apply the cap manually or retry'
    );
    return { applied: false, error: (err && err.message) || String(err), customRateLimit };
  }
}

/**
 * reauthorizeSession — Re-open the firewall for an ALREADY-ACTIVE session.
 *
 * Used when a guest re-enters a still-valid, still-active voucher on the SAME
 * device (the captive mini-browser reopened, Wi-Fi dropped and reconnected,
 * or the OS lost its authorization). The local session already exists and is
 * still counting down, so we do NOT create a new one and do NOT touch its
 * state or expiry — we simply replay the controller's extPortal/auth call for
 * the REMAINING time so the device regains internet access.
 *
 * The remaining time is derived from the session's own expiry timestamp
 * (expires_at - now), which is the authoritative source while active.
 *
 * @param {string} sessionId
 * @returns {Promise<{session: Object, remainingSeconds: number}>}
 * @throws Error with code 'SESSION_NOT_FOUND' or 'SESSION_EXPIRED'
 */
async function reauthorizeSession(sessionId) {
  const session = await getSession(sessionId);
  if (!session) {
    const err = new Error('Session not found');
    err.code = 'SESSION_NOT_FOUND';
    throw err;
  }

  const remainingSeconds = session.expiresAt
    ? Math.max(0, Math.floor((new Date(session.expiresAt).getTime() - Date.now()) / 1000))
    : 0;
  if (remainingSeconds <= 0) {
    const err = new Error('Session has expired');
    err.code = 'SESSION_EXPIRED';
    throw err;
  }

  // Fail-closed: if the controller rejects/throws, the caller surfaces a
  // retryable error and the session's local state is left untouched.
  try {
    await omadaService.authenticateClient({
      clientMac: session.clientMac,
      clientIp: session.clientIp,
      apMac: session.apMac,
      ssidName: session.ssidName,
      radioId: session.radioId || 0,
      durationMinutes: Math.ceil(remainingSeconds / 60),
      sessionId,
      // Same voucher the session was opened with, so every extPortal/auth call
      // carries the `code` field identically (see resumeSession).
      voucherCode: session.voucherUsed || '',
    });
  } catch (err) {
    console.error('[reauthorizeSession] Omada auth failed:', err.message);
    throw err;
  }

  // A re-authorized client must come back at the speed it paid for. The caps
  // are the ones stored on the session when it was created, so a voucher whose
  // row was edited afterwards cannot silently change a live session.
  await applySessionRateLimit(session);

  return { session, remainingSeconds };
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
let isWorkerRunning = false; // Lock to prevent overlapping memory leaks

function startExpirationWorker() {
  if (expirationTimer) return; // Already running

  expirationTimer = setInterval(async () => {
    // 1. Check if the previous run is still working. If yes, skip this cycle.
    if (isWorkerRunning) return; 
    isWorkerRunning = true;

    try {
      const db = getDb();
      const now = new Date().toISOString();

      // 2. Add LIMIT 50 to prevent unbounded arrays from filling up the RAM
      const expiredSessions = await db.query(`
        SELECT session_id FROM sessions
        WHERE state = 'active' AND expires_at IS NOT NULL AND expires_at <= ?
        LIMIT 50
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
          LIMIT 50
        `, [maxPausedAt]);
      } catch (err) {
        // voucher_type column may not exist in older databases — fall back to query without it
        if (err.code === '42701' || (err.message && err.message.includes('voucher_type'))) {
          stalePaused = await db.query(`
            SELECT session_id FROM sessions
            WHERE state = 'paused' AND paused_at IS NOT NULL AND paused_at <= ?
            LIMIT 50
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
    } catch (err) {
      console.error('[expiration-worker] Critical error during run:', err);
    } finally {
      // 3. Release the lock so the next interval can run safely
      isWorkerRunning = false;
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
    // Payment-activated sessions may have no voucher (webhook flow); the
    // field is then omitted rather than sent empty.
    voucherCode: session.voucherUsed || '',
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
 * getSessionByVoucher — the newest session that consumed a given voucher code.
 *
 * Pause/resume state lives on the SESSION row (sessions.state = 'paused'), not
 * on the voucher, so this is how a re-login with an already-'used' voucher
 * finds the session it may resume. Returns null when no session references the
 * code (the voucher was never redeemed through this backend).
 *
 * NOTE: getSession() applies server-side expiry, so an active-but-timed-out
 * session comes back with state 'expired'.
 *
 * @param {string} voucher Normalized voucher code
 * @returns {Promise<Object|null>}
 */
async function getSessionByVoucher(voucher) {
  if (!voucher) return null;
  const row = await getDb().getOne(
    `SELECT session_id FROM sessions WHERE voucher_used = ? ORDER BY id DESC LIMIT 1`,
    [voucher]
  );
  if (!row) return null;
  return await getSession(row.session_id);
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
  if (!session || session.state !== 'paused' || !isPausableVoucherType(session.voucherType)) {
    return null;
  }
  if (!session.pausedAt) return null;

  const pauseValidUntil = new Date(session.pausedAt).getTime() + PREMIUM_PAUSE_VALIDITY_HOURS * 60 * 60 * 1000;
  const remaining = Math.max(0, Math.floor((pauseValidUntil - Date.now()) / 1000));
  return remaining;
}

module.exports = {
  validateVoucher,
  consumeVoucher,
  recordSession,
  getSession,
  pauseSession,
  resumeSession,
  reauthorizeSession,
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
  isPausableVoucherType,
  getSessionByVoucher,
  applySessionRateLimit,
};
