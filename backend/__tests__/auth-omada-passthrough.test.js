/**
 * __tests__/auth-omada-passthrough.test.js
 *
 * Verifies that POST /api/auth forwards the Omada controller context it
 * receives from the portal (client/AP/gateway MAC, client IP, SSID, radioId,
 * vid) into services/omada.authenticateClient — the exact parameters the
 * controller needs to authorize the client via /hotspot/extPortal/auth.
 *
 * The Omada service is spied on so the assertions are about the ROUTE
 * contract (what the route hands to the service), independent of the
 * HTTP/mock behavior covered by omada.test.js.
 *
 * Patterns follow backend/__tests__/voucher-code.test.js:
 *   - Temp SQLite database created before requiring db/client.js
 *   - Schema applied via schema.sql
 *   - supertest with Express app exported from src/server.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Environment setup MUST happen before requiring any backend modules
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-authpassthru-test-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');
const omada = require('../src/services/omada');

async function applySchema() {
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'db', 'schema.sql'),
    'utf8'
  );
  await getDb().exec(schema);
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
  await getDb().exec('DELETE FROM sessions; DELETE FROM vouchers; DELETE FROM portal_client_context;');
  await getDb().run(
    'INSERT INTO vouchers (code, type, duration_minutes, price, state) VALUES (?, ?, ?, ?, ?)',
    ['123456', 'standard', 60, 0, 'active']
  );
});

afterEach(() => {
  jest.restoreAllMocks();
});

const BASE = { voucher: '123456', termsAccepted: true };

describe('POST /api/auth — Omada context passthrough', () => {
  test('forwards EAP context (clientIp, apMac, ssidName, radioId) with normalized MACs', async () => {
    const spy = jest
      .spyOn(omada, 'authenticateClient')
      .mockResolvedValue({ success: true, raw: {} });

    const res = await request(app).post('/api/auth').send({
      ...BASE,
      clientMac: 'aa:bb:cc:dd:ee:ff',
      clientIp: '192.168.1.50',
      apMac: 'aa:aa:aa:aa:aa:aa',
      ssidName: 'GuestWiFi',
      radioId: '1',
    });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(spy).toHaveBeenCalledTimes(1);

    const ctx = spy.mock.calls[0][0];
    expect(ctx.clientMac).toBe('AA:BB:CC:DD:EE:FF'); // normalized uppercase
    expect(ctx.apMac).toBe('AA:AA:AA:AA:AA:AA');     // normalized uppercase
    expect(ctx.clientIp).toBe('192.168.1.50');
    expect(ctx.ssidName).toBe('GuestWiFi');
    expect(ctx.radioId).toBe(1);                      // taken from the URL, not defaulted to 0
    // The submitted voucher reaches the service so it can travel with the
    // extPortal/auth body alongside authType=4.
    expect(ctx.voucherCode).toBe('123456');
  });

  test('logs the Omada response and the committed local lock on success', async () => {
    const spy = jest
      .spyOn(omada, 'authenticateClient')
      .mockResolvedValue({ success: true, raw: { errorCode: 0, msg: 'ok' } });
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});

    try {
      const res = await request(app).post('/api/auth').send({
        ...BASE,
        clientMac: 'aa:bb:cc:dd:ee:ff',
        apMac: 'aa:aa:aa:aa:aa:aa',
        ssidName: 'GuestWiFi',
        radioId: '0',
      });
      expect(res.status).toBe(200);
      expect(spy).toHaveBeenCalledTimes(1);

      const line = logSpy.mock.calls
        .map((c) => c.join(' '))
        .find((l) => l.includes('authorization SUCCESS'));
      expect(line).toBeDefined();
      expect(line).toContain('session=' + res.body.sessionId);
      expect(line).toContain('localState=voucher:used+session:recorded');
      // The controller's own body is logged verbatim ...
      expect(line).toContain('omadaResponse={"errorCode":0,"msg":"ok"}');
      // ... and it demonstrably carries no voucher (decoupled voucher list).
      expect(line).toContain('omadaEchoedVoucher=false');
      // The voucher itself is masked in the log, never raw.
      expect(line).toContain('••••56');
      expect(line).not.toContain('123456');
    } finally {
      logSpy.mockRestore();
    }
  });

  test('a local write failure does NOT burn the voucher (rolled back)', async () => {
    jest.spyOn(omada, 'authenticateClient').mockResolvedValue({ success: true, raw: { errorCode: 0 } });
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    // Force the session INSERT inside the transaction to fail.
    await getDb().exec('ALTER TABLE sessions RENAME TO sessions_backup');
    try {
      const res = await request(app).post('/api/auth').send({
        ...BASE,
        clientMac: 'aa:bb:cc:dd:ee:ff',
        apMac: 'aa:aa:aa:aa:aa:aa',
        ssidName: 'GuestWiFi',
        radioId: '0',
      });
      expect(res.status).toBe(500);
      expect(res.body.code).toBe('SESSION_WRITE_FAILED');

      // The client WAS authorized on Omada, but local state must be untouched.
      const voucher = await getDb().getOne('SELECT state FROM vouchers WHERE code = ?', ['123456']);
      expect(voucher.state).toBe('active');

      // ... and the rollback is reported explicitly, with the voucher masked.
      const errLines = errSpy.mock.calls.map((c) => c.join(' '));
      const rollbackLine = errLines.find((l) => l.includes('transaction rolled back; voucher left UNCONSUMED'));
      expect(rollbackLine).toBeDefined();
      expect(rollbackLine).toContain('••••56');
      expect(rollbackLine).not.toContain('123456');
    } finally {
      await getDb().exec('ALTER TABLE sessions_backup RENAME TO sessions');
      errSpy.mockRestore();
    }
  });

  test('forwards the normalized voucher even when the submitter pads it', async () => {
    const spy = jest
      .spyOn(omada, 'authenticateClient')
      .mockResolvedValue({ success: true, raw: {} });

    const res = await request(app).post('/api/auth').send({
      ...BASE,
      voucher: ' 123-456 ',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      apMac: 'aa:aa:aa:aa:aa:aa',
      ssidName: 'GuestWiFi',
      radioId: '0',
    });

    expect(res.status).toBe(200);
    expect(spy.mock.calls[0][0].voucherCode).toBe('123456');
  });

  test('forwards Gateway context (gatewayMac, vid) for wired clients', async () => {
    const spy = jest
      .spyOn(omada, 'authenticateClient')
      .mockResolvedValue({ success: true, raw: {} });

    const res = await request(app).post('/api/auth').send({
      ...BASE,
      clientMac: 'aa:bb:cc:dd:ee:ff',
      clientIp: '10.0.0.7',
      gatewayMac: 'aa:aa:aa:aa:aa:bb',
      vid: '20',
    });

    expect(res.status).toBe(200);
    const ctx = spy.mock.calls[0][0];
    expect(ctx.gatewayMac).toBe('AA:AA:AA:AA:AA:BB');
    expect(ctx.vid).toBe('20');
  });

  test('rejects an out-of-range radioId with 400 before calling Omada', async () => {
    const spy = jest
      .spyOn(omada, 'authenticateClient')
      .mockResolvedValue({ success: true, raw: {} });

    const res = await request(app).post('/api/auth').send({
      ...BASE,
      clientMac: 'aa:bb:cc:dd:ee:ff',
      radioId: '999',
    });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_INPUT');
    expect(spy).not.toHaveBeenCalled();
  });
});
