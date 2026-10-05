# Omada Captive Portal

A production-ready, mobile-first HTML captive login portal for TP-Link Omada EAP225 + OC200 controller deployments.

## Table of Contents

1. [Architecture](#architecture)
2. [Project Structure](#project-structure)
3. [Quick Start](#quick-start)
4. [Configuration Reference](#configuration-reference)
5. [Omada Controller Setup](#omada-controller-setup)
6. [Walled Garden Configuration](#walled-garden-configuration)
7. [Backend API Reference](#backend-api-reference)
8. [Testing](#testing)
9. [Troubleshooting](#troubleshooting)
10. [Security Checklist](#security-checklist)
11. [Controller-Specific Values to Verify](#controller-specific-values-to-verify)

---

## Architecture

```
[Client Device]  -->  [Omada EAP225 AP]  -->  [Omada OC200 Controller]
                         (captive portal redirect)

[Portal Server]
  /index.html?clientMac=...&ssidName=...&redirectUrl=...
        |
        +--> [Option A: Direct] POST /extPortal/auth (Omada built-in auth)
        |         (free voucher mode, no backend required)
        |
        +--> [Option B: Backend Proxy] POST /api/auth
                  |          (voucher mode)
                  +--> Omada extPortal/auth
                  +--> SQLite session DB
                  +--> /status.html (countdown + pause/resume)
```

**Two operating modes:**

| Mode | Backend | Session Timer |
|---|---|---|
| Free Voucher | Not required | Omada enforces |
| Managed (voucher) | Required (Node.js) | Backend enforces |

---

## Project Structure

```
omada-captive-portal/
├── index.html              # Main entry / login form
├── status.html             # Authenticated session status
├── success.html            # Post-auth success page
├── error.html              # Error page
├── assets/
│   ├── style.css           # All styles (mobile-first)
│   ├── portal.js           # Core logic (query params, form submit, countdown)
│   └── images/
│       └── logo.svg         # Placeholder logo (replace with yours)
├── config/
│   └── config.example.js   # Frontend configuration template
├── backend/
│   ├── README.md            # Backend-specific documentation
│   ├── .env.example         # Environment variables template
│   ├── package.json
│   └── src/
│       ├── server.js        # Express server entry
│       ├── routes/
│       │   ├── auth.js      # POST /api/auth
│       │   └── session.js   # GET /api/session/status, POST pause/resume/expire
│       ├── services/
│       │   ├── omada.js     # Omada controller adapter
│       │   └── session.js   # Session state machine
│       └── db/
│           └── schema.sql   # Database schema
├── portal-upload.zip        # Upload this ZIP to Omada
└── README.md                # This file
```

---

## Quick Start

### Option A — Free Voucher (No Backend)

1. Edit `config/config.example.js`, rename to `config.js`, set:
   ```js
   const CONFIG = {
     mode: 'direct',
     authEndpoint: 'https://<controller-ip>:8043/extPortal/auth',
     // ...
   };
   ```
2. Serve `index.html`, `success.html`, `error.html`, and `assets/` via HTTPS.
3. Configure Omada to use "External Portal" pointing to your HTTPS URL.
4. Add the domain to the Omada walled garden.

### Option B — Paid / Managed (With Backend)

1. Edit `.env` from `.env.example`.
2. Edit `config/config.example.js` → `config.js`.
3. Run:
   ```bash
   cd backend
   npm install
   npm run db:migrate
   npm run dev
   ```
4. Point Omada to `https://your-domain/index.html`
5. Point portal config endpoint to `https://your-domain/api/auth`

---

## Configuration Reference

### Frontend (`config/config.js`)

```js
const CONFIG = {
  // === Branding ===
  brandName: 'Hotel WiFi Portal',
  logoUrl: 'assets/images/logo.svg',     // Local asset
  primaryColor: '#1a73e8',              // Button, heading accent
  accentColor: '#e8f0fe',               // Backgrounds, cards
  textColor: '#202124',
  errorColor: '#d93025',
  successColor: '#188038',
  supportEmail: 'support@example.com',
  supportPhone: '+1-555-0100',

  // === Authentication Mode ===
  // 'direct' = POST to Omada extPortal endpoint (free voucher only)
  // 'backend' = POST to your backend /api/auth
  mode: 'direct',

  // === Direct Mode (free voucher, no backend) ===
  // VERIFY: path and hostname depend on your controller version
  authEndpoint: 'https://192.168.1.252:8043/extPortal/auth',
  // HTTP method: 'POST' (form-encoded) or 'POST_JSON' (application/json)
  authMethod: 'POST',
  // Required hidden fields Omada expects
  authParams: {
    username: 'voucher',
    password: 'voucher',
    // 'username' and 'password' are EXAMPLES — verify with your controller
  },

  // === Backend Mode ===
  apiBaseUrl: 'https://api.your-domain.com',

  // === Voucher Validation (frontend hints only; backend enforces) ===
  voucher: {
    required: true,
    // RULE: exactly 6 numeric digits (matches backend/src/utils/voucher-code.js).
    minLength: 6,
    maxLength: 6,
    pattern: /^\d{6}$/,
    patternHint: 'Voucher code must be exactly 6 digits.',
  },

  // === Redirect ===
  // URLs allowed as post-auth redirect destinations
  // List exact domains/IPs your users will access
  allowedRedirectDomains: ['example.com', 'google.com'],
  // Default redirect if original URL is unavailable
  defaultRedirectUrl: 'https://www.example.com/welcome',

  // === Terms ===
  termsRequired: true,
  termsUrl: '#terms',

  // === Status Page ===
  statusPollingInterval: 30000,  // ms (server-enforced; this is display only)
  showPauseResume: true,

  // === Controller Query Parameter Mapping ===
  // ADJUST THESE based on your controller version's actual parameter names.
  // Capture a redirect request to confirm the exact names.
  paramMap: {
    clientMac:    'clientMac',   // Device MAC address
    clientIp:     'clientIp',    // Device IP address
    apMac:        'apMac',       // Access Point MAC
    ssidName:     'ssidName',    // SSID name
    redirectUrl:  'redirectUrl', // Where to send user after auth
    originalUrl:  'originalUrl',  // Originally requested URL
    authUrl:      'authUrl',      // Controller auth URL
    targetUrl:    'targetUrl',    // Alternative redirect param
    // 'token': 'token',         // Controller-specific token, if present
    // 'wlanacname': 'wlanacname', // Some controllers send these
    // 'wlanacip': 'wlanacip',
  },

  // === Mock Mode (development only) ===
  mockMode: false,
};
```

### Backend Environment (`.env`)

```env
NODE_ENV=development
PORT=3000
BASE_URL=https://api.your-domain.com
FRONTEND_ORIGIN=https://portal.your-domain.com

# === Omada Controller ===
OMADA_BASE_URL=https://192.168.1.252:8043
OMADA_API_TOKEN=your-controller-api-token
OMADA_SITE=Default
OMADA_AUTH_OPERATION=authenticateClient   # Your identified auth operation
OMADA_UNAUTH_OPERATION=unauthenticateClient
OMADA_AUTH_TIMEOUT=10000

# === Database ===
DATABASE_URL=sqlite:./data/portal.db
# For PostgreSQL:
# DATABASE_URL=postgresql://user:pass@localhost:5432/portal

# === Session Defaults ===
SESSION_DURATION_OPTIONS=[60,120,180,360,720,1440]  # minutes
DEFAULT_SESSION_DURATION=60
PAUSE_ENABLED=true

# === Security ===
JWT_SECRET=change-me-in-production
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=600
LOGIN_RATE_LIMIT_MAX=25
CORS_ORIGINS=https://portal.your-domain.com

# === Logging ===
LOG_LEVEL=info
```

---

## Omada Controller Setup

### 1. Enable Captive Portal

1. Log into the Omada Controller (OC200 web UI or software controller).
2. Go to **Settings → Authentication → Portal**.
3. Create a new Portal Profile:
   - **Type**: External Portal
   - **Server URL**: `https://your-portal-domain.com` (no trailing slash)
   - **Authentication Path**: `/index.html`
   - **Success URL**: `/success.html`
   - **Failure URL**: `/error.html`
4. Bind the portal profile to your SSID under **SSID Configuration**.

### 2. Configure Walled Garden

Allow access **before authentication** to:

| Purpose | Domain / IP |
|---|---|
| Portal frontend | `portal.your-domain.com` |
| Backend API | `api.your-domain.com` |

### 3. Capture Query Parameters

Before finalizing `config.js`, capture the actual redirect:

```bash
# On a test client before authentication, run:
adb shell "logcat | grep -i redirect"   # Android
# Or on macOS:
sudo tcpdump -i en0 -A 'tcp port 80' | grep -i redirect
```

Common parameter variations by Omada version:

| Parameter | Common aliases |
|---|---|
| `clientMac` | `mac`, `clientmac`, `usermac` |
| `clientIp` | `ip`, `clientip`, `userip` |
| `apMac` | `apmac`, `acmac` |
| `ssidName` | `ssid`, `wlan`, `ssidname` |
| `redirectUrl` | `redirect`, `url`, `target`, `dst` |
| Controller token | `token`, `ap_session`, `sessid` |

### 4. External Portal URL to Configure

For Omada, set the **Server URL + Authentication Path** to:
```
https://portal.your-domain.com/index.html
```

The controller appends its query parameters automatically.

---

## Walled Garden Configuration

In the Omada Controller, go to **Settings → WLAN → Walled Garden** and add:

```
portal.your-domain.com
api.your-domain.com
```

---

## Backend API Reference

### `POST /api/auth`

Authenticate a client via Omada.

**Request:**
```json
{
  "voucher": "123456",
  "clientMac": "aa:bb:cc:dd:ee:ff",
  "clientIp": "192.168.1.105",
  "apMac": "00:11:22:33:44:55",
  "ssidName": "HotelGuest",
  "redirectUrl": "https://www.google.com",
  "termsAccepted": true
}
```

**Response (success, 200):**
```json
{
  "success": true,
  "message": "Authentication successful",
  "sessionId": "sess_abc123",
  "redirectUrl": "https://www.google.com"
}
```

**Response (failure, 401):**
```json
{
  "success": false,
  "error": "Invalid voucher code",
  "code": "INVALID_VOUCHER"
}
```

---

### `GET /api/session/status`

Poll session remaining time.

**Query params:** `?sessionId=sess_abc123`

**Response:**
```json
{
  "sessionId": "sess_abc123",
  "state": "active",
  "remainingSeconds": 4523,
  "startedAt": "2026-09-24T10:00:00Z",
  "expiresAt": "2026-09-24T12:00:00Z",
  "totalSeconds": 7200,
  "canPause": true,
  "canResume": false
}
```

---

### `POST /api/session/pause`

**Request:** `{ "sessionId": "sess_abc123" }`

**Response:** `{ "success": true, "state": "paused", "remainingSeconds": 3500 }`

---

### `POST /api/session/resume`

**Request:** `{ "sessionId": "sess_abc123" }`

**Response:** `{ "success": true, "state": "active", "remainingSeconds": 3480 }`

---

### `POST /api/session/expire`

Administrative: immediately end a session.

**Request:** `{ "sessionId": "sess_abc123" }`

---

### `GET /health`

Health check.

**Response:** `{ "ok": true, "timestamp": "2026-09-24T10:00:00Z" }`

---

## Testing

### Manual Testing (No Controller)

Enable mock mode in `config.js`:
```js
mockMode: true,
```

This bypasses real authentication and shows the full UI flow.

### Unit Tests

```bash
cd backend
npm install
npm test
```

Tests cover:
- `portal.js`: query param parsing, voucher validation, redirect allowlist, duplicate submission prevention
- `session.js`: pause/resume state machine, expiration math, countdown
- `omada.js`: error handling, timeout behavior

### End-to-End (with live controller)

1. Deploy portal to a publicly accessible HTTPS URL.
2. Configure Omada external portal pointing to that URL.
3. Add the domain to walled garden.
4. Connect a test device to the SSID.
5. Observe redirect, capture parameters, update `config.js`.
6. Submit a real voucher.

---

## Troubleshooting

### Redirect Not Working

- **Cause**: Portal URL in controller config does not match the actual server URL (HTTP vs HTTPS, trailing slash).
- **Fix**: Ensure the controller's **Server URL** matches exactly (no `/` at end, correct protocol).

### Parameters Missing or Named Differently

- **Cause**: Different Omada Controller firmware version uses different parameter names.
- **Fix**: Use browser dev tools or `tcpdump` to capture the actual redirect URL from the AP. Update `config.paramMap` with the exact names.

### "Authentication failed" from Controller

- **Cause**: Wrong `authEndpoint`, wrong request body schema, or missing required fields.
- **Fix**: Verify the exact `extPortal/auth` request format for your controller version. Common issues:
  - Sending JSON when the endpoint expects `application/x-www-form-urlencoded`
  - Missing `username`/`password` fields
  - Wrong token format in Authorization header
  - Self-signed cert on controller not trusted

### Session Not Expiring

- **Cause**: Browser countdown is display-only; backend must enforce expiration.
- **Fix**: Ensure the session expiration job is running. Check `SESSION_ENFORCE_INTERVAL` in `server.js`. The backend should call `extPortal/unauth` when time expires.

### Captive Portal Detection Loop

- **Cause**: Some captive portals (Android, iOS) check `connectivitycheck.gstatic.com` or `captive.apple.com`. If these are blocked or return non-200, the OS keeps showing the captive banner.
- **Fix**: Allow these URLs in the walled garden, or accept that the captive detection banner may persist even after successful auth (the user can open a browser and navigate manually).

---

## Security Checklist

Before deploying to production:

- [ ] HTTPS is enabled on both portal and backend (no HTTP in production)
- [ ] Self-signed certificates are NOT used for production (use Let's Encrypt or cloud-managed certs)
- [ ] `OMADA_API_TOKEN` is stored in `.env`, not in frontend files
- [ ] Database uses parameterized queries (no raw string interpolation)
- [ ] CORS is restricted to the known portal origin
- [ ] Rate limiting is enabled on public endpoints
- [ ] Admin routes require authentication
- [ ] No secrets in `config.js` (it ships in the ZIP)
- [ ] `portal-upload.zip` does not contain `.env`, `.git`, `node_modules`, or log files
- [ ] MAC addresses are normalized (lowercase, colon-separated) before storage
- [ ] Redirect URLs are validated against an allowlist (no open redirects)
- [ ] Generic error messages shown to users (no stack traces, no internal paths)
- [ ] Server-side session expiration is implemented (not browser-only)

---

## Controller-Specific Values to Verify

These values **must be confirmed** before deployment on your specific hardware/firmware combination:

### Critical (may break auth if wrong)

1. **`extPortal/auth` endpoint base URL**
   - Format: `https://<controller-ip>:<port>/extPortal/auth`
   - Port may be `8043` (HTTPS) or `8080` (HTTP) — verify in controller UI
   - Some controllers use `/api/v2/extPortal/auth` or similar paths

2. **Request body format**
   - Content-Type: `application/x-www-form-urlencoded` or `application/json`?
   - Required fields: typically `username` + `password` OR `token` + `mac`

3. **Authentication mechanism**
   - API token in `Authorization: Bearer <token>` header?
   - Token in request body?
   - Basic auth?

4. **Controller session enforcement mode**
   - Some controllers enforce session length server-side (you only call `auth`, not `unauth`)
   - Others require you to call `unauth` when the session ends

5. **Query parameter names**
   - The names listed in `paramMap` above are common but NOT guaranteed
   - Always capture a real redirect and inspect the URL

### Important (may affect UX)

6. **`extPortal/unauth` endpoint path** (if session control is needed)
7. **Session idle timeout vs. hard timeout** — how long does auth persist?
8. **Concurrent session limits** — can one MAC be authenticated from multiple devices?
9. **Redirect URL format** — some controllers URL-encode the original URL as a parameter value
10. **HTTPS certificate requirement** — does the controller verify TLS certs on the portal server?

---

## License

MIT. Modify and use freely for commercial or personal deployments.
