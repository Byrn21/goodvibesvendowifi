/**
 * __tests__/rate-limit-proxy.test.js
 *
 * H-02 regression: with TRUST_PROXY_HOPS unset, req.ip must be the socket
 * address, so a caller cannot create a fresh rate-limit bucket by rotating
 * X-Forwarded-For. The global apiLimiter is set to max 1 here; the second
 * request — with a different spoofed address — must be throttled.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-rate-proxy-'));
process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';
// Keep the endpoint-specific and login limiters out of the way: this test is
// about the global per-IP limiter's key.
process.env.RATE_LIMIT_MAX_REQUESTS = '1';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';
process.env.VOUCHER_STATUS_RATE_LIMIT_MAX = '10000';
process.env.REAUTHORIZE_RATE_LIMIT_MAX = '10000';
// The deployment under test: no proxy in front, so XFF must be ignored.
delete process.env.TRUST_PROXY_HOPS;

const request = require('supertest');
const app = require('../src/server');
const { getDb, closeDb } = require('../src/db/client');

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

describe('rate limiting without trusted proxies', () => {
  test('rotating X-Forwarded-For does not create a new bucket', async () => {
    const first = await request(app)
      .get('/api/session/status?sessionId=sess_rate_proxy_missing')
      .set('X-Forwarded-For', '1.1.1.1');

    // The session does not exist; what matters is that the request was counted.
    expect(first.status).toBe(404);

    const second = await request(app)
      .get('/api/session/status?sessionId=sess_rate_proxy_missing')
      .set('X-Forwarded-For', '2.2.2.2');

    expect(second.status).toBe(429);
    expect(second.body.code).toBe('RATE_LIMITED');
  });
});
