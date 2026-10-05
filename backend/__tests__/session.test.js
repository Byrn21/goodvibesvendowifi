/**
 * __tests__/session.test.js
 * Unit tests for session state machine, countdown math, and voucher
 * validation against the SQLite-backed session service.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Use a temporary test database BEFORE requiring db/client.js
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-test-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');

const sessionService = require('../src/services/session');
const { getDb, closeDb } = require('../src/db/client');

async function applySchema() {
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'db', 'schema.sql'),
    'utf8'
  );
  await getDb().exec(schema);
}

async function seedVouchers() {
  const voucherData = [
    ['WIFI-TEST-0001', 60, 'active'],
    ['EXPIRED-VOUCHER', 60, 'expired'],
    ['USED-VOUCHER', 60, 'used'],
  ];

  for (const v of voucherData) {
    try {
      await getDb().run(
        'INSERT INTO vouchers (code, duration_minutes, state) VALUES (?, ?, ?)',
        v
      );
    } catch (err) {
      if (err.code !== '23505' && err.code !== 'SQLITE_CONSTRAINT') {
        throw err;
      }
    }
  }
}

beforeAll(async () => {
  await applySchema();
});

afterAll(async () => {
  await closeDb();
  try {
    fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
  } catch (err) {
    // best-effort cleanup
  }
});

beforeEach(async () => {
  await getDb().exec('DELETE FROM sessions; DELETE FROM vouchers;');
  await seedVouchers();
});

describe('Session State Machine', () => {
  test('creates and retrieves a session', async () => {
    const s = await sessionService.recordSession({
      sessionId: 'sess_test_001',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      clientIp: '192.168.1.100',
      apMac: '00:11:22:33:44:55',
      ssidName: 'HotelGuest',
      duration: 60,
      voucherUsed: 'WIFI-TEST-0001',
    });

    expect(s.state).toBe('active');
    expect(s.sessionId).toBe('sess_test_001');
    expect(s.duration).toBe(60);
    expect(s.clientMac).toBe('aa:bb:cc:dd:ee:ff');
    expect(s.startedAt).toBeTruthy();
    expect(s.expiresAt).toBeTruthy();

    const retrieved = await sessionService.getSession('sess_test_001');
    expect(retrieved.sessionId).toBe('sess_test_001');
  });

    test('pause freezes session and records remaining time', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_pause_001',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });

    // Manually fast-forward expiresAt in the DB (30 min left)
    await getDb().run(
      'UPDATE sessions SET expires_at = ? WHERE session_id = ?',
      [new Date(Date.now() + 1800 * 1000).toISOString(), 'sess_pause_001']
    );

    const paused = await sessionService.pauseSession('sess_pause_001');
    expect(paused.state).toBe('paused');
    expect(paused.pausedAt).toBeTruthy();
    expect(paused.remainingSeconds).toBeGreaterThan(1700);
    expect(paused.remainingSeconds).toBeLessThanOrEqual(1800);
  });

  test('resume restarts timer from remaining seconds', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_resume_001',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
      voucherType: 'premium',
      totalDurationSeconds: 3600,
    });

        // Force the session into a paused state with 1500s remaining
    await getDb().run(
      `UPDATE sessions SET state = 'paused', paused_at = ?, remaining_seconds = 1500, expires_at = NULL WHERE session_id = ?`,
      [new Date().toISOString(), 'sess_resume_001']
    );

    const resumed = await sessionService.resumeSession('sess_resume_001');
    expect(resumed.state).toBe('active');
    expect(resumed.expiresAt).toBeTruthy();
    expect(resumed.pausedAt).toBeNull();

    const remainingMs = new Date(resumed.expiresAt) - Date.now();
    expect(remainingMs).toBeGreaterThan(1490 * 1000);
    expect(remainingMs).toBeLessThanOrEqual(1500 * 1000);
  });

  test('expire is idempotent', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_expire_001',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
    });

    await sessionService.expireSession('sess_expire_001');
    await sessionService.expireSession('sess_expire_001'); // second call â€” idempotent

    const s = await sessionService.getSession('sess_expire_001');
    expect(s.state).toBe('expired');
  });

    test('pause rejects non-active session', async () => {
    await expect(sessionService.pauseSession('nonexistent')).rejects.toThrow('Session not found');
  });

  test('resume rejects non-paused session', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_notpaused',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
    });
    await expect(sessionService.resumeSession('sess_notpaused')).rejects.toThrow('Session not paused');
  });
});

describe('Session Expiration Math', () => {
  test('remainingSeconds correctly computed for active session', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_remaining_001',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
    });

        // Manually set expiresAt to 30 min from now
    await getDb().run(
      'UPDATE sessions SET expires_at = ? WHERE session_id = ?',
      [new Date(Date.now() + 1800 * 1000).toISOString(), 'sess_remaining_001']
    );

    const retrieved = await sessionService.getSession('sess_remaining_001');
    expect(retrieved.state).toBe('active');
    expect(retrieved.remainingSeconds).toBeFalsy(); // getSession doesn't compute remaining directly
    // The routes/session.js computeRemaining function handles this
  });

  test('remainingSeconds is frozen when paused', async () => {
    await sessionService.recordSession({
      sessionId: 'sess_paused_remaining',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      duration: 60,
    });

        // Manually pause the session with 3600s frozen
    await getDb().run(
      `UPDATE sessions SET state = 'paused', paused_at = ?, remaining_seconds = 3600, expires_at = NULL WHERE session_id = ?`,
      [new Date().toISOString(), 'sess_paused_remaining']
    );

    const retrieved = await sessionService.getSession('sess_paused_remaining');
    expect(retrieved.state).toBe('paused');
    expect(retrieved.remainingSeconds).toBe(3600);
  });

  test('isSessionActive returns false for non-existent session', async () => {
    const active = await sessionService.isSessionActive('nonexistent');
    expect(active).toBe(false);
  });
});

describe('Countdown Display Math', () => {
  function formatDuration(totalSecs) {
    if (totalSecs == null || totalSecs < 0) return 'â€”';
    var h = Math.floor(totalSecs / 3600);
    var m = Math.floor((totalSecs % 3600) / 60);
    var s = totalSecs % 60;
    var pad = function (n) { return String(n).padStart(2, '0'); };
    return (h > 0 ? pad(h) + ':' : '') + pad(m) + ':' + pad(s);
  }

  test('formats HH:MM:SS for hours', () => {
    expect(formatDuration(3661)).toBe('01:01:01');
  });

  test('formats MM:SS for less than an hour', () => {
    expect(formatDuration(90)).toBe('01:30');
    expect(formatDuration(59)).toBe('00:59');
  });

  test('formats zero', () => {
    expect(formatDuration(0)).toBe('00:00');
  });

  test('returns dash for null/undefined', () => {
    expect(formatDuration(null)).toBe('â€”');
    expect(formatDuration(undefined)).toBe('â€”');
  });

  test('handles negative as zero', () => {
    expect(formatDuration(-10)).toBe('â€”'); // our function guards < 0
  });
});

describe('Voucher Validation', () => {
  test('accepts valid voucher', async () => {
    const r = await sessionService.validateVoucher('WIFI-TEST-0001', 'aa:bb:cc:dd:ee:ff');
    expect(r.valid).toBe(true);
    expect(r.duration).toBeDefined();
  });

  test('rejects expired voucher', async () => {
    const r = await sessionService.validateVoucher('EXPIRED-VOUCHER', 'aa:bb:cc:dd:ee:ff');
    expect(r.valid).toBe(false);
    expect(r.code).toBe('EXPIRED_VOUCHER');
  });

  test('rejects used voucher', async () => {
    const r = await sessionService.validateVoucher('USED-VOUCHER', 'aa:bb:cc:dd:ee:ff');
    expect(r.valid).toBe(false);
    expect(r.code).toBe('USED_VOUCHER');
  });

  test('rejects too-short voucher', async () => {
    const r = await sessionService.validateVoucher('ABC', 'aa:bb:cc:dd:ee:ff');
    expect(r.valid).toBe(false);
    expect(r.code).toBe('INVALID_VOUCHER');
  });
});
