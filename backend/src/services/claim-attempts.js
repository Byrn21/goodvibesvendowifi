/**
 * services/claim-attempts.js — per-suffix claim budget.
 *
 * Why this exists
 * ---------------
 * POST /api/payment/claim is unauthenticated and takes the LAST 4 DIGITS of a
 * payment reference — a 10,000-value space. IP rate limiting is the wrong
 * control for that: the caller's address is spoofable (X-Forwarded-For) and,
 * even when it is not, an attacker can simply rotate it. A budget keyed on the
 * digits themselves cannot be rotated: every attempt against the same suffix
 * lands in the same bucket, whoever sends it and from wherever.
 *
 * It is defence in depth, not the primary fix — the claim route also requires
 * the payer's mobile number (recorded by the webhook when the payment arrived)
 * before it will release a voucher. This budget is what stops an attacker
 * enumerating suffixes to discover which ones are real, and what bounds the
 * MacroDroid screen-scrape path (each unmatched claim asks the handset to open
 * the e-wallet).
 *
 * Semantics
 * ---------
 *   - one row per ref_suffix, created on the first failed attempt;
 *   - failures inside WINDOW_MS accumulate; a success deletes the row;
 *   - once FAILURE_BUDGET is reached the suffix is LOCKED for the rest of the
 *     window (429 + Retry-After), then the count starts over;
 *   - only failed attempts count. Input-validation 400s never reach here, so a
 *     malformed request cannot lock a real customer out.
 *
 * Both values are env-tunable (CLAIM_FAILURE_BUDGET / CLAIM_FAILURE_WINDOW_MS)
 * so a deployment can loosen the budget without a code change, but the defaults
 * (5 failures / 15 minutes) are deliberately strict.
 */

const DEFAULT_FAILURE_BUDGET = 5;
const DEFAULT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Parse a positive integer env value, falling back to `fallback`.
 * @param {*} raw
 * @param {number} fallback
 * @returns {number}
 */
function positiveInt(raw, fallback) {
  const parsed = parseInt(raw, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

const FAILURE_BUDGET = positiveInt(process.env.CLAIM_FAILURE_BUDGET, DEFAULT_FAILURE_BUDGET);
const WINDOW_MS = positiveInt(process.env.CLAIM_FAILURE_WINDOW_MS, DEFAULT_WINDOW_MS);

/**
 * Read the current state of a suffix without modifying it.
 *
 * @param {{getOne: Function}} db database or transaction handle
 * @param {string} refSuffix exactly 4 digits
 * @returns {Promise<{failedCount: number, locked: boolean, retryAfterSeconds: number}>}
 */
async function getState(db, refSuffix) {
  const row = await db.getOne(
    `SELECT failed_count, window_started_at
       FROM claim_attempts WHERE ref_suffix = ?`,
    [refSuffix]
  );

  if (!row) {
    return { failedCount: 0, locked: false, retryAfterSeconds: 0 };
  }

  const failedCount = parseInt(row.failed_count, 10) || 0;
  const windowStart = row.window_started_at ? new Date(row.window_started_at).getTime() : NaN;

  // A row whose window has elapsed no longer locks anything: the next attempt
  // starts a fresh window (recordFailure resets the counter).
  const inWindow = Number.isFinite(windowStart) && (Date.now() - windowStart) < WINDOW_MS;
  if (!inWindow || failedCount < FAILURE_BUDGET) {
    return { failedCount, locked: false, retryAfterSeconds: 0 };
  }

  const retryAfterSeconds = Math.max(
    1,
    Math.ceil((windowStart + WINDOW_MS - Date.now()) / 1000)
  );
  return { failedCount, locked: true, retryAfterSeconds };
}

/**
 * Count one failed claim attempt and (re)start the window when it has elapsed.
 *
 * A single atomic upsert: concurrent attempts cannot read the same counter and
 * both write count+1, and no transaction is needed.
 *
 * @param {{run: Function}} db
 * @param {string} refSuffix
 * @param {string} [clientIp] recorded for diagnostics only — never used as a key
 * @returns {Promise<void>}
 */
async function recordFailure(db, refSuffix, clientIp) {
  const now = new Date().toISOString();
  const cutoff = new Date(Date.now() - WINDOW_MS).toISOString();
  const ip = clientIp ? String(clientIp).slice(0, 45) : null;

  await db.run(
    `INSERT INTO claim_attempts
       (ref_suffix, failed_count, window_started_at, last_attempt_at, last_client_ip)
     VALUES (?, 1, ?, ?, ?)
     ON CONFLICT (ref_suffix) DO UPDATE SET
       failed_count = CASE
         WHEN claim_attempts.window_started_at IS NULL
           OR claim_attempts.window_started_at < ?
         THEN 1
         ELSE claim_attempts.failed_count + 1
       END,
       window_started_at = CASE
         WHEN claim_attempts.window_started_at IS NULL
           OR claim_attempts.window_started_at < ?
         THEN ?
         ELSE claim_attempts.window_started_at
       END,
       last_attempt_at = ?,
       last_client_ip = ?`,
    [refSuffix, now, now, ip, cutoff, cutoff, now, now, ip]
  );
}

/**
 * Clear a suffix's budget after a successful claim.
 *
 * Best-effort at the call site: the claim is already committed, so a failed
 * cleanup must never turn a successful claim into an error. Worst case the
 * customer's next attempt starts with a stale counter.
 *
 * @param {{run: Function}} db
 * @param {string} refSuffix
 * @returns {Promise<void>}
 */
async function clearSuffix(db, refSuffix) {
  await db.run('DELETE FROM claim_attempts WHERE ref_suffix = ?', [refSuffix]);
}

module.exports = {
  FAILURE_BUDGET,
  WINDOW_MS,
  getState,
  recordFailure,
  clearSuffix,
};
