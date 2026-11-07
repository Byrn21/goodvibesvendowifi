/**
 * __tests__/rate-limit-endpoints.test.js
 *
 * H-02 regression for the two unauthenticated endpoints that bypassing the IP
 * key would make dangerous:
 *
 *   GET  /api/session/status?voucher=  — voucher enumeration oracle
 *   POST /api/session/reauthorize      — unauthenticated controller amplifier
 *
 * Both have dedicated strict limiters. Rotating X-Forwarded-For must not reset
 * either bucket when TRUST_PROXY_HOPS is unset.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-rate-endpoints-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';
// The global limiter stays generous; the endpoint-specific caps are the subject.
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';
process.env.VOUCHER_STATUS_RATE_LIMIT_MAX = '2';
process.env.REAUTHORIZE_RATE_LIMIT_MAX = '2';
delete process.env.TRUST_PROXY_HOPS;

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');

const MAC = 'AA:BB:CC:DD:EE:FF';

beforeAll(async () => {
  const schema = fs.readFileSync(path.join(__dirname, '..', 'src', 'db', 'schema.sql'), 'utf8');
  await getDb().exec(schema);
});

afterAll(async () => {
  await closeDb();
  try {
    fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
  } catch (err) { /* best-effort cleanup */ }
});

describe('strict limiters are not keyed on a spoofable header', () => {
  test('voucher status: the third rotated X-Forwarded-For request is throttled', async () => {
    for (let i = 1; i <= 2; i++) {
      const allowed = await request(app)
        .get('/api/session/status?voucher=123456')
        .set('X-Forwarded-For', '10.10.10.' + i);
      expect(allowed.status).not.toBe(429);
    }

    const throttled = await request(app)
      .get('/api/session/status?voucher=123456')
      .set('X-Forwarded-For', '10.10.10.3');

    expect(throttled.status).toBe(429);
    expect(throttled.body.code).toBe('RATE_LIMITED');
  });

  test('reauthorize: the third rotated X-Forwarded-For request is throttled', async () => {
    for (let i = 1; i <= 2; i++) {
      const allowed = await request(app)
        .post('/api/session/reauthorize')
        .set('X-Forwarded-For', '10.20.20.' + i)
        .send({ clientMac: MAC });
      expect(allowed.status).not.toBe(429);
    }

    const throttled = await request(app)
      .post('/api/session/reauthorize')
      .set('X-Forwarded-For', '10.20.20.3')
      .send({ clientMac: MAC });

    expect(throttled.status).toBe(429);
    expect(throttled.body.code).toBe('RATE_LIMITED');
  });
});
