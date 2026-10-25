/**
 * __tests__/cors.test.js
 * Integration tests for the CORS origin check in src/server.js
 *
 * Tests cover:
 *   - 200: a Termux LAN origin (http://192.168.0.4:3000) is accepted
 *   - 200: the same origin with a trailing slash / uppercase host is accepted
 *   - 200: same-origin requests (Host / X-Forwarded-Host match) are accepted
 *   - 200: CORS_ORIGINS entries are matched canonically (trailing slash tolerated)
 *   - 403: a public origin that is not allowlisted is rejected
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Environment setup MUST happen before requiring any backend modules
const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-cors-test-'));

process.env.DATABASE_URL = 'sqlite:' + path.join(TEST_DB_DIR, 'test.db');
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.OMADA_BASE_URL = '';
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.LOGIN_RATE_LIMIT_MAX = '10000';

// Require the Express app AFTER env is set
const request = require('supertest');
const app = require('../src/server');
const { closeDb } = require('../src/db/client');

afterAll(() => {
  try { closeDb(); } catch (err) { /* ignore */ }
  fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
});

describe('CORS origin check', () => {
  const ORIGINAL_CORS_ORIGINS = process.env.CORS_ORIGINS;

  afterEach(() => {
    if (ORIGINAL_CORS_ORIGINS === undefined) delete process.env.CORS_ORIGINS;
    else process.env.CORS_ORIGINS = ORIGINAL_CORS_ORIGINS;
  });

  test('accepts a Termux LAN origin with an explicit port', async () => {
    delete process.env.CORS_ORIGINS;
    const res = await request(app)
      .get('/health')
      .set('Origin', 'http://192.168.0.4:3000')
      .set('Host', '192.168.0.4:3000');

    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('http://192.168.0.4:3000');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });

  test('accepts the same LAN origin with a trailing slash and uppercase host', async () => {
    delete process.env.CORS_ORIGINS;
    const res = await request(app)
      .get('/health')
      .set('Origin', 'HTTP://192.168.0.4:3000/');

    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('HTTP://192.168.0.4:3000/');
  });

  test('accepts the other private ranges on any port', async () => {
    delete process.env.CORS_ORIGINS;
    for (const origin of ['http://10.1.2.3:8080', 'http://172.20.0.7:3000', 'http://192.168.1.20:5555', 'http://localhost:8080']) {
      const res = await request(app).get('/health').set('Origin', origin);
      expect(res.status).toBe(200);
      expect(res.headers['access-control-allow-origin']).toBe(origin);
    }
  });

  test('accepts a preflight from the LAN origin for the reauthorize endpoint', async () => {
    delete process.env.CORS_ORIGINS;
    const res = await request(app)
      .options('/api/session/reauthorize')
      .set('Origin', 'http://192.168.0.4:3000')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type');

    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('http://192.168.0.4:3000');
  });

  test('accepts same-origin requests via the Host header', async () => {
    delete process.env.CORS_ORIGINS;
    const res = await request(app)
      .get('/health')
      .set('Origin', 'https://portal.example.test')
      .set('Host', 'portal.example.test');

    expect(res.status).toBe(200);
  });

  test('accepts same-origin requests via X-Forwarded-Host', async () => {
    delete process.env.CORS_ORIGINS;
    const res = await request(app)
      .get('/health')
      .set('Origin', 'https://calm-river.trycloudflare.com')
      .set('Host', '127.0.0.1:3000')
      .set('X-Forwarded-Host', 'calm-river.trycloudflare.com');

    expect(res.status).toBe(200);
  });

  test('matches CORS_ORIGINS entries canonically (trailing slash tolerated)', async () => {
    process.env.CORS_ORIGINS = 'https://portal.example.test/, http://localhost:8080';
    const res = await request(app)
      .get('/health')
      .set('Origin', 'https://portal.example.test');

    expect(res.status).toBe(200);
  });

  test('rejects a public origin that is not allowlisted', async () => {
    delete process.env.CORS_ORIGINS;
    const res = await request(app)
      .get('/health')
      .set('Origin', 'https://evil.example.com');

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CORS_FORBIDDEN');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('rejects a malformed Origin header', async () => {
    delete process.env.CORS_ORIGINS;
    const res = await request(app)
      .get('/health')
      .set('Origin', 'http://:3000');

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CORS_FORBIDDEN');
  });
});
