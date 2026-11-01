/**
 * utils/session-token.js
 *
 * The device identity that survives a lost URL, a shared carrier address and a
 * cloud tunnel: a signed, opaque token naming ONE session.
 *
 * Why this exists
 * ---------------
 * The status page identified a device by its request address, which only works
 * when the guest reaches the backend from the LAN address the portal landing
 * beacon captured. Behind a tunnel, or with Wi-Fi Assist / a proxy browser
 * routing HTTP over LTE, req.ip is a public carrier address (124.217.x.x) that
 * matches no row → `502 MISSING_PORTAL_CONTEXT`, even for a guest physically
 * connected to the SSID. The MAC query parameter (`?mac=`) already covers most
 * returning guests, but it lives only in localStorage on ONE origin: a captive
 * mini-browser that opens with fresh, partitioned or per-app storage has no MAC
 * and no session id, so it falls straight through to the doomed address lookup.
 *
 * A cookie travels independently of page JavaScript, so the backend can answer
 * "which session is this?" for that guest on the first request.
 *
 * Token shape
 * -----------
 *   base64url("<sessionId>.<expiresAtMs>") + "." + base64url(HMAC-SHA256(...))
 *
 * It is deliberately NOT the bare session id: a value in a URL or a cookie can
 * be copied, and a guessable one would expose another guest's session. The
 * signature is verified in constant time, and the token expires on its own, so
 * a captured value cannot be replayed indefinitely.
 *
 * Secret
 * ------
 * PORTAL_SESSION_SECRET. When unset (a fresh checkout, development, tests) a
 * per-process random secret is generated and a warning is logged ONCE: tokens
 * then stop validating across a restart, which degrades to the previous
 * behaviour (MAC / IP lookup) instead of erroring, and never to a predictable
 * key. Set it in backend/.env for a stable deployment.
 *
 * Both transports use the same token:
 *   - cookie  `portal_session`  (HttpOnly; primary — survives JS-less reloads)
 *   - query   `?token=`         (for a cross-origin API or a cookie-blocked
 *                                browser that still has localStorage)
 */

const crypto = require('crypto');

/** Cookie name. Also the lookup key in `Cookie:` request headers. */
const COOKIE_NAME = 'portal_session';

/** Query parameter carrying the same token for localStorage-based callers. */
const TOKEN_PARAM = 'token';

/** How long a token (and the cookie carrying it) stays valid. */
const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

let cachedSecret = null;
let warnedAboutSecret = false;

/**
 * The signing key, resolved once per process.
 *
 * @returns {Buffer}
 */
function getSecret() {
  if (cachedSecret) return cachedSecret;

  const fromEnv = String(process.env.PORTAL_SESSION_SECRET || '').trim();
  if (fromEnv) {
    cachedSecret = Buffer.from(fromEnv, 'utf8');
    return cachedSecret;
  }

  cachedSecret = crypto.randomBytes(32);
  if (!warnedAboutSecret) {
    warnedAboutSecret = true;
    console.warn(
      '[session-token] PORTAL_SESSION_SECRET is not set — using a random per-process key. ' +
      'Session cookies stop validating after a restart (guests fall back to the MAC / IP lookup). ' +
      'Set it in backend/.env for a stable deployment.'
    );
  }
  return cachedSecret;
}

/**
 * base64url without padding.
 *
 * @param {Buffer|string} value
 * @returns {string}
 */
function base64url(value) {
  return Buffer.from(value).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode a base64url string back to UTF-8 text.
 *
 * @param {string} value
 * @returns {string|null}
 */
function fromBase64url(value) {
  try {
    const padded = String(value).replace(/-/g, '+').replace(/_/g, '/');
    const text = Buffer.from(padded, 'base64').toString('utf8');
    return text || null;
  } catch (_) {
    return null;
  }
}

/**
 * HMAC-SHA256 of a payload under the server secret.
 *
 * @param {string} payload
 * @returns {string} base64url signature
 */
function sign(payload) {
  return base64url(crypto.createHmac('sha256', getSecret()).update(payload).digest());
}

/**
 * Issue a token naming one session.
 *
 * @param {string} sessionId
 * @param {number} [ttlMs]
 * @returns {string|null} the token, or null when sessionId is unusable
 */
function issueSessionToken(sessionId, ttlMs) {
  const id = String(sessionId == null ? '' : sessionId).trim();
  if (!id) return null;

  const ttl = Number.isFinite(ttlMs) && ttlMs > 0 ? ttlMs : TOKEN_TTL_MS;
  const payload = base64url(id + '.' + (Date.now() + ttl));
  return payload + '.' + sign(payload);
}

/**
 * Verify a token and extract the session it names.
 *
 * Never throws: anything malformed, tampered with or expired is simply not a
 * token this server issued, and the caller falls through to its other
 * identifiers.
 *
 * @param {string} token
 * @returns {{sessionId: string, expiresAt: number}|null}
 */
function verifySessionToken(token) {
  const text = String(token == null ? '' : token).trim();
  if (!text) return null;

  const parts = text.split('.');
  if (parts.length !== 2) return null;

  const [payload, signature] = parts;
  const expected = sign(payload);

  // Constant-time comparison; length differences are rejected first because
  // timingSafeEqual throws on mismatched buffer sizes.
  const given = Buffer.from(signature, 'utf8');
  const want = Buffer.from(expected, 'utf8');
  if (given.length !== want.length) return null;
  if (!crypto.timingSafeEqual(given, want)) return null;

  const decoded = fromBase64url(payload);
  if (!decoded) return null;

  const dot = decoded.lastIndexOf('.');
  if (dot <= 0) return null;

  const sessionId = decoded.slice(0, dot);
  const expiresAt = Number.parseInt(decoded.slice(dot + 1), 10);

  if (!sessionId || !Number.isFinite(expiresAt)) return null;
  if (Date.now() >= expiresAt) return null;

  return { sessionId, expiresAt };
}

/**
 * Read one cookie from the request.
 *
 * Parsed by hand: the app has no cookie middleware, and a single name=value
 * pair does not justify adding a dependency (the `cookie` package in
 * node_modules is only Express's transitive dep).
 *
 * @param {Object} req Express request
 * @param {string} name
 * @returns {string} the value, or '' when absent
 */
function readCookie(req, name) {
  const header = req && req.headers ? req.headers.cookie : '';
  if (!header) return '';

  const pairs = String(header).split(';');
  for (const pair of pairs) {
    const eq = pair.indexOf('=');
    if (eq === -1) continue;
    if (pair.slice(0, eq).trim() !== name) continue;
    try {
      return decodeURIComponent(pair.slice(eq + 1).trim());
    } catch (_) {
      return pair.slice(eq + 1).trim();
    }
  }
  return '';
}

/**
 * Is this request served over HTTPS (directly or through the tunnel)?
 *
 * `app.set('trust proxy', 1)` makes req.secure read X-Forwarded-Proto for the
 * hop in front of us. The LAN direct flow is plain HTTP on 192.168.0.x, where a
 * `Secure` cookie would be silently DROPPED by the browser — so the flag has to
 * follow the actual scheme instead of being hard-coded.
 *
 * @param {Object} req
 * @returns {boolean}
 */
function isSecureRequest(req) {
  if (req && req.secure) return true;
  const proto = req && req.headers ? req.headers['x-forwarded-proto'] : '';
  return String(proto || '').split(',')[0].trim().toLowerCase() === 'https';
}

/**
 * Set (or refresh) the session cookie for a session.
 *
 * Max-Age longer than a session's own lifetime is intentional: an expired pass
 * must still resolve to its session row so the status page can say "expired"
 * (with the reason and the deadline) instead of "no session found".
 *
 * @param {Object} req
 * @param {Object} res
 * @param {string} sessionId
 * @returns {string|null} the token that was set, or null for an unusable id
 */
function setSessionCookie(req, res, sessionId) {
  const token = issueSessionToken(sessionId);
  if (!token || !res || typeof res.cookie !== 'function') return token;

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isSecureRequest(req),
    path: '/',
    maxAge: TOKEN_TTL_MS,
  });
  return token;
}

/**
 * Remove the session cookie (used when a guest explicitly starts over).
 *
 * @param {Object} req
 * @param {Object} res
 */
function clearSessionCookie(req, res) {
  if (!res || typeof res.clearCookie !== 'function') return;
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isSecureRequest(req),
    path: '/',
  });
}

/**
 * The token supplied with this request: `?token=` first (an explicit,
 * freshly-saved value from status.html), then the cookie.
 *
 * @param {Object} req
 * @returns {string} '' when neither is present
 */
function tokenFromRequest(req) {
  const query = req && req.query ? req.query[TOKEN_PARAM] : '';
  if (typeof query === 'string' && query.trim()) return query.trim();
  return readCookie(req, COOKIE_NAME);
}

module.exports = {
  COOKIE_NAME,
  TOKEN_PARAM,
  TOKEN_TTL_MS,
  issueSessionToken,
  verifySessionToken,
  readCookie,
  tokenFromRequest,
  setSessionCookie,
  clearSessionCookie,
  isSecureRequest,
};
