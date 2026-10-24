/**
 * server.js — Express backend entry point
 *
 * Routes:
 *   POST /api/auth              — Voucher authentication
 *   GET  /api/session/status    — Poll session remaining time
 *   POST /api/session/pause     — Pause active session
 *   POST /api/session/resume    — Resume paused session
 *   POST /api/session/expire    — Admin: immediately expire session
 *   GET  /health               — Health check
 */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');

const { rateLimit } = require('express-rate-limit');
const path = require('path');
const authRoutes = require('./routes/auth');
const sessionRoutes = require('./routes/session');
const adminRoutes = require('./routes/admin');
const webhookRoutes = require('./routes/webhook');
const paymentRoutes = require('./routes/payment');
const omadaService = require('./services/omada');
const { startExpirationWorker } = require('./services/session');
const { fixMissingColumns } = require('./db/migrate_fix');
const { run: runVoucherRefMigration } = require('./db/migrate_add_voucher_ref');

const app = express();

// Trust the first proxy hop (Render, Nginx, etc.) so req.ip resolves to the
// client's real IP from X-Forwarded-For — required for correct per-IP limits.
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:8080';

// ── Security middleware ──────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
             scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https://images.unsplash.com", "https:"],
      styleSrc: ["'self'", "https:", "'unsafe-inline'"],
      fontSrc: ["'self'", "https:", "data:"],
      formAction: ["'self'"],
      baseUri: ["'self'"],
      frameAncestors: ["'self'"],
      objectSrc: ["'none'"],
    },
  },
}));

// CORS: allow same-origin, the configured allowlist, and localhost / private-LAN
// origins. "Same-origin" is decided by comparing the request's Origin host:port
// with the Host it actually arrived on (directly or through the tunnel's
// X-Forwarded-Host). That is what makes a new Termux LAN IP or a rotating
// Cloudflare quick-tunnel hostname work with no allowlist edit.
const PRIVATE_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\]|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(:\d+)?$/i;

function originHost(origin) {
  try { return new URL(origin).host.toLowerCase(); } catch (err) { return ''; }
}

function isAllowedOrigin(origin, req) {
  // Allow requests with no origin (mobile captive portals)
  if (!origin) return true;
  // Allow null origin (file:// protocol for admin.html)
  if (origin === 'null') return true;
  // Allow localhost / private LAN (admin panel access from a phone on the same Wi-Fi)
  if (PRIVATE_ORIGIN_RE.test(origin)) return true;
  // Allow same-origin requests (this backend also serves the portal pages)
  const host = String(req.headers.host || '').toLowerCase();
  if (host && originHost(origin) === host) return true;
  const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim().toLowerCase();
  if (forwardedHost && originHost(origin) === forwardedHost) return true;
  const allowed = (process.env.CORS_ORIGINS || FRONTEND_ORIGIN)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  return allowed.includes(origin);
}

const corsOptions = {
  // Reflect the caller's Origin: it was already validated by isAllowedOrigin()
  // below, and reflection is required for credentialed requests.
  origin: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Admin-Password'],
  credentials: true,
};

app.use(cors((req, cb) => {
  if (isAllowedOrigin(req.headers.origin, req)) return cb(null, corsOptions);
  const err = new Error('CORS: origin not allowed');
  err.status = 403;
  err.code = 'CORS_FORBIDDEN';
  cb(err);
}));

app.use(compression());
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));

// ── Rate limiting ────────────────────────────────────────────
// Strict limiter for login endpoints only (admin login + voucher auth).
// Successful logins do NOT count toward the limit (skipSuccessfulRequests),
// so logging out and back in — even from another device — never locks out a
// legitimate user. Only repeated FAILED attempts are throttled.
const loginLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 min
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX || '25', 10),
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { success: false, error: 'Too many login attempts. Please try again later.', code: 'RATE_LIMITED' },
  handler: (req, res) => {
    const resetMs = req.rateLimit && req.rateLimit.resetTime
      ? Math.max(0, req.rateLimit.resetTime.getTime() - Date.now())
      : parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10);
    const retryAfterSecs = Math.max(1, Math.ceil(resetMs / 1000));
    const mins = Math.max(1, Math.ceil(retryAfterSecs / 60));
    res.status(429)
      .set('Retry-After', String(retryAfterSecs))
      .json({
        success: false,
        error: 'Too many login attempts. Please try again in ' + mins + ' minute' + (mins === 1 ? '' : 's') + '.',
        code: 'RATE_LIMITED',
        retryAfterSeconds: retryAfterSecs,
      });
  },
  // Disable X-Forwarded-For validation — Render's proxy header format triggers ERR_ERL_UNEXPECTED_X_FORWARDED_FOR
  validate: {
    xForwardedForHeader: false,
  },
});

// Generous limiter for the rest of the API (dashboard stats, voucher list,
// session list, logout, etc.). High enough that normal admin usage and client
// polling never reach it — it exists only as an abuse safety net.
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 min
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '600', 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests. Please wait.', code: 'RATE_LIMITED' },
  validate: {
    xForwardedForHeader: false,
  },
});

// Login endpoints get the strict limiter; everything else the generous one
app.use('/api/admin/login', loginLimiter);
app.use('/api/auth', loginLimiter);
app.use('/api/', apiLimiter);

// ── Routes ───────────────────────────────────────────────────
app.use('/api/auth',     authRoutes);
app.use('/api/session',  sessionRoutes);
app.use('/api/admin',    adminRoutes);
app.use('/api/webhooks', webhookRoutes);
app.use('/api/payment',  paymentRoutes);

// Health check (unauthenticated)
app.get('/health', (req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString(), env: NODE_ENV });
});

// ── Static file serving for captive portal pages ──────────────────
// Docker: static files copied to /app/public/ by Dockerfile
// Local dev: HTML files live in the project root (parent of backend/)
const fs = require('fs');

const candidates = [
  path.join(__dirname, '..', 'public'),              // Docker: /app/public/
  path.join(__dirname, '..', '..'),                 // Local dev: project-root/
];

let PORTAL_HTML_DIR = null;
for (const candidate of candidates) {
  if (fs.existsSync(path.join(candidate, 'index.html'))) {
    PORTAL_HTML_DIR = candidate;
    break;
  }
}

if (PORTAL_HTML_DIR) {
  app.use(express.static(PORTAL_HTML_DIR, {
    setHeaders: (res, filePath) => {
      // config/config.js carries the public backend URL. Serving it no-store
      // stops the browser (and the captive mini-browser) from running a stale
      // copy after the backend address changes.
      if (/[\\/]config[\\/]config\.js$/i.test(filePath)) {
        res.setHeader('Cache-Control', 'no-store, must-revalidate');
      }
    },
  }));
  app.get('/', (req, res) => res.sendFile(path.join(PORTAL_HTML_DIR, 'index.html')));
  app.get('/success', (req, res) => res.sendFile(path.join(PORTAL_HTML_DIR, 'success.html')));
      app.get('/status', (req, res) => res.sendFile(path.join(PORTAL_HTML_DIR, 'status.html')));
  app.get('/admin', (req, res) => res.sendFile(path.join(PORTAL_HTML_DIR, 'admin.html')));
  app.get('/login', (req, res) => res.sendFile(path.join(PORTAL_HTML_DIR, 'login.html')));
  app.get('/error', (req, res) => res.sendFile(path.join(PORTAL_HTML_DIR, 'error.html')));
} else {
  console.warn('[WARN] Portal HTML directory not found — static file serving disabled.');
}

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Not found' });
});

// Global error handler (never leaks internals)
app.use((err, req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  const code = err.code || 'SERVER_ERROR';
  // Log full error server-side; return generic message to client.
  // Primitive-only: coerce to strings so a non-Error throw (or an object with
  // a circular `stack`/`message`) can never reach V8's serializer.
  console.error(
    '[' + req.method + ' ' + req.path + '] ' +
    String((err && err.message) || '(no message)') + ' ' +
    String((err && err.stack) || '(no stack)')
  );
            res.status(status).json({
    success: false,
    error: NODE_ENV === 'production' ? 'An internal error occurred.' : err.message,
    code: code,
  });
});

// ── Start ────────────────────────────────────────────────────
const startup = async () => {
  // Ensure all schema columns exist on existing production tables
  try {
    await fixMissingColumns();
    // Add vouchers.assigned_ref_no (pre-generated voucher claim architecture).
    // Idempotent — a no-op once the column exists.
    await runVoucherRefMigration();
  } catch (err) {
    console.error('[startup] Column migration failed:', err.message);
  }

  // Echo the resolved Omada target configuration (base, OMADAC id, SITE, TLS)
  // so the Render logs show exactly which controller + site this backend will
  // call. A captive loop is usually a mismatch between this line and the
  // controller's own Site / API settings.
  try {
    omadaService.logResolvedConfig();
  } catch (err) {
    console.error('[startup] Omada config logging failed:', err.message);
  }

  app.listen(PORT, () => {
    console.log(`Omada portal backend running on port ${PORT} [${NODE_ENV}]`);

    // Start session expiration worker (calls Omada unauth when sessions expire)
    if (process.env.OMADA_BASE_URL) {
      startExpirationWorker();
    } else if (NODE_ENV !== 'test') {
      console.warn('[WARN] OMADA_BASE_URL not set — session expiration worker is disabled.');
      console.warn('[WARN] In production, set OMADA_BASE_URL to enable automatic session expiry.');
    }
  });
};

startup();

module.exports = app;








