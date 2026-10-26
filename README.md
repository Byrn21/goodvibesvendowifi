# GoodVibesVendoWifi — Cloud Captive Portal

A cloud-hosted guest Wi-Fi captive portal for TP-Link Omada deployments. A TP-Link
Omada **OC200** hardware controller is configured with the **External Portal
Server** authentication method and redirects guest Wi-Fi traffic to a
Node.js/Express portal and backend hosted on **Render**. Paid access is verified
without any payment-gateway fees using **MacroDroid** to intercept GCash, Maya,
and QR Ph payment confirmations on an Android phone.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Network & Captive Portal Layer](#2-network--captive-portal-layer)
3. [Automated Payment Verification (MacroDroid)](#3-automated-payment-verification-macrodroid)
4. [Project Structure](#4-project-structure)
5. [Backend Setup & Running](#5-backend-setup--running)
6. [Environment Variables](#6-environment-variables)
7. [Secure Frontend Build (`inject-secrets.js`)](#7-secure-frontend-build-inject-secretsjs)
8. [Backend API Reference](#8-backend-api-reference)
9. [Testing](#9-testing)
10. [Security Notes](#10-security-notes)

---

## 1. Architecture Overview

```
[Guest device]
      │  joins SSID, hits any HTTP site
      ▼
[Omada OC200 controller]  ── External Portal Server auth method ──┐
      │  redirects the guest (with controller query params)        │
      ▼                                                            │
[Captive portal + backend on Render]                               │
  https://goodvibesvendowifi.onrender.com                          │
      │                                                            │
      ├── Serves index.html / success.html / error.html / status.html
      │                                                            │
      ├── POST /api/auth ─────────────► Omada controller API ──────┘
      │                                  (authorizes the client)
      │    ▲
      │    │  POST /api/webhooks/macrodroid
      │    │  (verified payment)
      │    │
      │ [Android phone running MacroDroid]
      │    ├── GCash / Maya  → intercepts app push notification
      │    └── QR Ph         → intercepts SMS containing "QRPH"
      │
      └── PostgreSQL (Render) — vouchers, sessions, webhook events
```

The portal itself is **hosted in the cloud**, so there is no on-site web server
to expose and **no tunnel is required**. See
[§2](#2-network--captive-portal-layer) for why.

---

## 2. Network & Captive Portal Layer

The Wi-Fi edge is a **TP-Link Omada OC200** hardware controller. On the OC200:

- The guest portal profile is set to the **External Portal Server**
  authentication method.
- Before a guest is authorized, the controller redirects their HTTP traffic to
  the cloud portal URL — in this deployment
  `https://goodvibesvendowifi.onrender.com` — and appends controller context as
  query parameters (`clientMac`, `clientIp`, `apMac`, `ssidName`, `redirectUrl`,
  …).
- The portal page captures that controller context (AP MAC, SSID, radio ID) and
  sends it to the backend, where it is stored against the client MAC so it is
  ready when a payment arrives.

### Why there is no tunnel

Older deployments exposed a portal running on local hardware by tunnelling it to
the public internet. That is **no longer part of this architecture**:

- The captive portal HTML, the Express backend, and the database all run on
  Render, which is already publicly reachable over HTTPS.
- The OC200 points straight at that public HTTPS URL. There is no local portal
  server and therefore nothing to tunnel.
- **No Cloudflare Tunnel, ngrok, Raspberry Pi, or any other local tunnel/host is
  used or required.** Do not add tunnel setup steps.

> The backend still talks to the Omada controller through `OMADA_BASE_URL`
> (§6) to authorize clients — but that is an outbound API call from the backend,
> not a locally hosted tunnel serving the portal.

---

## 3. Automated Payment Verification (MacroDroid)

Paid access is verified with a **zero-fee mobile interception** design built on
[MacroDroid](https://macrodroid.com/) running on an Android phone:

| Provider | MacroDroid trigger | Source event |
|---|---|---|
| **GCash** | `Notification Received` | GCash app push notification |
| **Maya** | `Notification Received` | Maya app push notification |
| **QR Ph** | `SMS Received` | Text message containing the keyword `QRPH` |

For all three providers, the macro applies **Regex** to the intercepted
notification/SMS content to extract:

- the **payment amount**, and
- the **reference number**.

It then sends an HTTP **POST** to the backend's payment webhook,
[`POST /api/webhooks/macrodroid`](#post-apiwebhooks-macrodroid), hosted on
Render:

```
POST https://goodvibesvendowifi.onrender.com/api/webhooks/macrodroid
Content-Type: application/json
```

### Webhook payload

The webhook route reads these fields from the request body:

```json
{
  "secret_token": "<MACRODROID_WEBHOOK_SECRET>",
  "amount": "50",
  "ref_no": "1234567890123",
  "mac_address": "AA:BB:CC:DD:EE:FF"
}
```

- `secret_token` — must match `MACRODROID_WEBHOOK_SECRET`; compared in constant
  time and rejected with `401` on mismatch.
- `amount` — the payment amount; must be a positive number.
- `ref_no` — the payment reference number; must be a non-empty string of at most
  64 characters and is deduplicated at the database level.
- `mac_address` — the paying device's MAC; normalized to
  `AA:BB:CC:DD:EE:FF` format.

<!-- TODO: confirm — the example payload below was supplied in the task brief as
     "what MacroDroid sends", but it does NOT match the fields the webhook route
     actually reads. The route consumes secret_token / amount / ref_no /
     mac_address; it has no reference_number or provider fields, and the provider
     is hard-coded as "macrodroid" in the webhook_events row. The payload below
     would be rejected (missing secret_token → 401). Confirm the real macro
     output before publishing/using this example. -->
```json
{ "amount": "1.00", "reference_number": "123456", "provider": "GCash|Maya|QRPH" }
```

### What the webhook does

`POST /api/webhooks/macrodroid` (see `backend/src/routes/webhook.js`) processes a
notification in this order:

1. Validates `secret_token`, `amount`, `ref_no`, and `mac_address`.
2. Compares `secret_token` against `MACRODROID_WEBHOOK_SECRET` in constant time.
3. Rejects a duplicate `ref_no` with `409` (DB-level unique constraint).
4. Computes the granted minutes:
   `floor(amount / MACRODROID_PESOS_PER_MINUTE)`.
5. Writes a `webhook_events` row and a `pending_payment` session row first, so
   the payment is **durable** even if later steps fail.
6. Resolves the client's stored portal context (AP/SSID/radio). If it is missing,
   partial, or older than one hour, responds `422 MISSING_PORTAL_CONTEXT` — the
   customer must re-open the portal page and pay again.
7. Authorizes the device on the Omada controller
   (`POST /{OMADAC_ID}/api/v2/hotspot/extPortal/auth`). On controller failure it
   responds `502` but keeps the payment recorded and flags the session
   `omada_auth_failed`.
8. On success, marks the session `active` and returns the session id and granted
   minutes.

### Manual fallback

If an SMS confirmation is slow, the portal's QR modal offers a manual reference
number entry that calls
[`POST /api/payment/claim`](#post-apipaymentclaim). Known references are
authorized immediately; unknown references are rejected.

---

## 4. Project Structure

```
goodvibesvendowifi/
├── index.html                 # Captive portal entry / login + payment QR modal
├── success.html               # Post-auth success page
├── error.html                 # Error page
├── status.html                # Session status page (countdown, pause/resume)
├── login.html                 # Admin login page
├── admin.html                 # Admin dashboard (vouchers, sessions, stats)
├── assets/
│   ├── style.css              # All styles (mobile-first)
│   ├── portal.js              # Portal logic + payment/context calls
│   ├── carousel.js            # Landing carousel
│   └── images/                # Logos and static images
├── config/
│   ├── config.js              # Active frontend config
│   └── config.example.js      # Frontend config template
├── scripts/
│   └── generate-qr-placeholders.js
├── inject-secrets.js          # Build-time secret injection into the HTML pages
├── backend/
│   ├── package.json           # All npm scripts live here (see §5)
│   ├── .env.example           # Environment variable template
│   ├── Dockerfile             # Production image (build + runtime)
│   └── src/
│       ├── server.js          # Express entry point (mounts all routes)
│       ├── config/index.js    # Centralized business constants
│       ├── routes/            # auth, session, admin, webhook, payment
│       ├── services/          # omada (controller adapter), session state machine
│       ├── utils/             # voucher-code, device-id, duration, price
│       └── db/                # client, schema.sql, migrations, seed
└── README.md                  # This file
```

> There is **no `package.json` in the repository root**. All npm scripts,
> dependencies, and the Node entry point live under `backend/`. Run every `npm`
> command from the `backend/` directory.

---

## 5. Backend Setup & Running

All commands below are the exact scripts defined in `backend/package.json`.

### Prerequisites

- **Node.js `>=22.0.0`** (enforced by the `engines` field).
- npm.
- Optional: **PostgreSQL** for production. Local development defaults to SQLite
  (`better-sqlite3` is a dependency).
- An Android phone running MacroDroid (§3) for live payment verification.
- A TP-Link Omada controller (OC200) configured with the External Portal Server
  method (§2).

### 1. Install dependencies

```bash
cd backend
npm install
```

### 2. Configure the environment

```bash
cp .env.example .env
# then edit .env with your values (see §6)
```

### 3. Initialize the database

Local development (SQLite) defaults to `sqlite:./data/portal.db`:

```bash
npm run db:migrate
```

To seed sample data:

```bash
npm run db:seed
```

For PostgreSQL, set `DATABASE_URL` to a `postgresql://…` connection string and run
`npm run db:migrate` again.

### 4. Start the server

```bash
# Development (nodemon auto-reload)
npm run dev

# Production
npm start
```

The server listens on `process.env.PORT` (default **3000**) and exposes an
unauthenticated health check at `GET /health`.

### Available scripts

| Script | Command | Purpose |
|---|---|---|
| `npm run start` | `node src/server.js` | Production server |
| `npm run dev` | `nodemon src/server.js` | Development server with auto-reload |
| `npm test` | `jest` | Run the test suite |
| `npm run test:watch` | `jest --watch` | Run tests in watch mode |
| `npm run db:migrate` | `node src/db/migrate.js` | Apply the database schema |
| `npm run db:seed` | `node src/db/seed.js` | Seed sample data (refuses to run when `NODE_ENV=production`) |

> In the Docker image the container starts with
> `node src/db/migrate.js && node src/server.js`, so migrations run automatically
> on every Render deploy. `npm run db:migrate` is only needed for local setup.

---

## 6. Environment Variables

Only variables that are **actually referenced by the backend code** are listed
here. Set them in `backend/.env` on the host that runs the backend (the file is
loaded relative to `src/server.js`, so the working directory does not matter).

### Core / server

| Variable | Referenced in | Default | Description |
|---|---|---|---|
| `NODE_ENV` | `server.js`, `db/client.js`, `db/seed.js` | `development` | Environment mode; production hides internal error details and enables Postgres TLS. |
| `PORT` | `server.js` | `3000` | HTTP port. Render sets this automatically. |
| `DATABASE_URL` | `db/client.js`, `db/migrate.js` | `sqlite:./data/portal.db` | `sqlite:…` or `postgresql://…` connection string. |
| `PG_SSL_REJECT_UNAUTHORIZED` | `db/client.js` | `true` | Set to `false` for Render PostgreSQL (self-signed certs). |
| `FRONTEND_ORIGIN` | `server.js` | `http://localhost:8080` | Fallback allowed CORS origin. |
| `CORS_ORIGINS` | `server.js` | `FRONTEND_ORIGIN` | Comma-separated allowed CORS origins. |
| `RATE_LIMIT_WINDOW_MS` | `server.js` | `900000` | Rate-limit window (ms) for both limiters. |
| `RATE_LIMIT_MAX_REQUESTS` | `server.js` | `600` | Max requests per window for the general API limiter. |
| `LOGIN_RATE_LIMIT_MAX` | `server.js` | `25` | Max **failed** login/auth attempts per window. |

### Omada controller

| Variable | Referenced in | Default | Description |
|---|---|---|---|
| `OMADA_BASE_URL` | `server.js`, `services/omada.js` | *(empty)* | Base URL the backend uses to reach the Omada controller API. When unset, Omada runs in mock mode and the session-expiration worker is disabled. |
| `OMADA_OMADAC_ID` | `services/omada.js` | *(empty)* | Omada controller ID (OMADAC ID) used in API paths. |
| `OMADA_SITE` | `services/omada.js`, `routes/payment.js` | `Default` | Omada site name. Sent in the body of every hotspot call and resolved to the site key its web-API paths embed (`GET …/api/v2/users/current`, falling back to `GET …/api/v2/sites`). |
| `OMADA_PORTAL_OPERATOR_NAME` | `services/omada.js` | *(empty)* | Hotspot portal operator username (for `POST /{OMADAC_ID}/api/v2/hotspot/login`). Used **only** for captive-portal authorization (`/hotspot/extPortal/*`, including the undocumented `unauth`/`session` endpoints tried as a fallback); this account has no site privileges. |
| `OMADA_PORTAL_OPERATOR_PASSWORD` | `services/omada.js` | *(empty)* | Hotspot portal operator password. |
| `OMADA_ADMIN_NAME` | `services/omada.js` | *(empty)* | Controller **administrator** username (for `POST /{OMADAC_ID}/api/v2/login`). Used **only** for privileged calls: site-list lookup, the per-client rate-limit `PATCH`, and kicking an expired client off the site (`…/hotspot/clients/{MAC}/unauth`). Required for bandwidth caps **and** for expirations to actually disconnect a guest; Omada refuses admin accounts on the hotspot portal endpoints, hence the separate credentials. |
| `OMADA_ADMIN_PASSWORD` | `services/omada.js` | *(empty)* | Controller administrator password. |
| `OMADA_AUTH_TIMEOUT` | `services/omada.js` | `10000` | Controller request timeout (ms). |
| `OMADA_TLS_REJECT` | `services/omada.js` | `false` | Default accepts the controller's self-signed cert (OC200/ER605). Set to `true` only when the controller has a publicly-trusted certificate. |
| `OMADA_MOCK` | `services/omada.js` | `false` | `true` bypasses the controller entirely (mock mode). |
| `OMADA_TIME_UNIT` | `config/index.js` | `ms` | Unit (`ms`, `us`, or `s`) for the Omada `time` field; depends on controller firmware. |

### Omada web UI authorization (payment flows)

Every guest authorization goes through the controller's **web UI API**
(`services/omada.js`). There is no cloud/Open API path: the backend signs in to
the controller itself and calls `/api/v2/hotspot/extPortal/auth`. This applies to
the voucher login (`POST /api/auth`) and to both payment flows
(`POST /api/payment/claim`, `POST /api/webhooks/instapay`).

**Payment authorization therefore requires `OMADA_BASE_URL`,
`OMADA_PORTAL_OPERATOR_NAME` / `OMADA_PORTAL_OPERATOR_PASSWORD` (the session that
calls `extPortal/auth`) and `OMADA_ADMIN_NAME` / `OMADA_ADMIN_PASSWORD` (the
administrator session that applies the bandwidth cap and disconnects expired
clients).** With `OMADA_BASE_URL` unset the deployment is in mock mode and no
device is really authorized.

| Variable | Why it is required |
|---|---|
| `OMADA_BASE_URL` | The controller the backend calls. When unset, Omada runs in mock mode and nothing is really authorized. |
| `OMADA_OMADAC_ID` | Controller ID used in every API path. |
| `OMADA_PORTAL_OPERATOR_NAME` / `OMADA_PORTAL_OPERATOR_PASSWORD` | Hotspot portal operator session (`POST …/api/v2/hotspot/login`). Authorizing guests (`/hotspot/extPortal/*`) is the only thing this account may do. |
| `OMADA_ADMIN_NAME` / `OMADA_ADMIN_PASSWORD` | Controller administrator session (`POST …/api/v2/login`). Required for the bandwidth-cap `PATCH …/clients/{MAC}/ratelimit` and for kicking an expired client off the site; the portal operator account holds no site/QoS rights. |

**Operational requirement — the device must have loaded the portal at least
once.** `extPortal/auth` is connection-type specific: it needs the client's AP
MAC, SSID and radio ID (or `gatewayMac` + `vid`), which the backend only knows
from the `portal_client_context` row written by the landing beacon
(`POST /api/payment/context`). The portal page sends that beacon automatically
when a device opens the captive portal.

A paying device with **no** context row — it paid from a bookmark or history
entry, never loaded the portal, or reconnected to a different AP — cannot be
authorized. Both payment routes then fail loud with **HTTP 502 and
`code: "MISSING_PORTAL_CONTEXT"`**, telling the caller to open the portal page
once and retry. Nothing is consumed in that case: the payment stays claimable and
the voucher stays active, so the retry after the portal page loads is a real
retry. Context rows older than `PORTAL_CONTEXT_MAX_AGE_MS` (1 hour,
`config/index.js`) are treated as missing, so a long-idle device has to reload the
portal to refresh its AP/SSID association.

### Sessions

| Variable | Referenced in | Default | Description |
|---|---|---|---|
| `DEFAULT_SESSION_DURATION` | `services/session.js` | `60` | Default session duration (minutes). |
| `SESSION_ENFORCE_INTERVAL` | `services/session.js` | `60000` | How often the expiration worker checks sessions (ms). |
| `PREMIUM_PAUSE_VALIDITY_HOURS` | `services/session.js` | `168` | How long a premium session may stay paused (hours). |
| `PAUSE_ENABLED` | `routes/session.js` | *(unset → disabled)* | Must be exactly `true` to allow session pause/resume. |

### MacroDroid payment webhook

| Variable | Referenced in | Default | Description |
|---|---|---|---|
| `MACRODROID_WEBHOOK_SECRET` | `routes/webhook.js` | *(empty)* | Shared secret MacroDroid sends as `secret_token`; compared in constant time. |
| `MACRODROID_PESOS_PER_MINUTE` | `config/index.js` | `10` | Whole units of currency granted per minute of Wi-Fi time. |
| `MACRODROID_SMS_WEBHOOK_URL` | `routes/payment.js` | *(empty → no SMS)* | MacroDroid SMS macro endpoint. `POST /api/payment/claim` POSTs the claimed voucher here so the code can be texted to the customer. |

`MACRODROID_SMS_WEBHOOK_URL` is optional and the call is **fire-and-forget**:
it is dispatched without blocking the response and any failure is logged only,
so an unreachable SMS endpoint can never turn a successful claim into an error.
The request is a `POST` with **no body**: every value is appended to
`MACRODROID_SMS_WEBHOOK_URL` as a URL query parameter, so a MacroDroid
variable whitelist can extract it straight from the request URL —
`?target_number=…&voucher_code=…&ref_suffix=…&ref_no=…&authorized=…&minutes=…`.
`target_number` is the customer's 11-digit mobile, `voucher_code` is the
6-digit code they need (with `ref_suffix` kept for correlation), and
`status_link` (`BASE_URL` + `/status.html`) is included only when `BASE_URL`
is set. A query string already present on the configured URL is preserved.

### InstaPay / PESONet webhook + tiered QoS

`POST /api/webhooks/instapay` authorizes the paying device directly through the
controller's web UI API. The device must have loaded the captive portal at least
once so its AP MAC / SSID / radio ID are on record — see
[Omada web UI authorization](#omada-web-ui-authorization-payment-flows); without
that context the callback answers `502 MISSING_PORTAL_CONTEXT` and changes
nothing, so it can be retried once the device has opened the portal. A payment
whose `amount` is one of `PREMIUM_AMOUNTS_PESOS` receives the premium bandwidth
caps; every other amount receives the default caps. Values are parsed with
`parseInt(..., 10)` and range-checked (1–1024) before reaching the controller.

| Variable | Referenced in | Default | Description |
|---|---|---|---|
| `INSTAPAY_WEBHOOK_SECRET` | `routes/webhook.js` | `MACRODROID_WEBHOOK_SECRET` | Shared secret for the InstaPay/PESONet webhook. |
| `PREMIUM_AMOUNTS_PESOS` | `routes/webhook.js` | `25,45,80` | Comma-separated payment amounts (Pesos) treated as the premium tier. |
| `PREMIUM_DOWN_MBPS` | `utils/qos.js` | *(empty → `PREMIUM_DOWN_KBPS`, else default caps)* | Premium download cap (Mbps). Unset/out-of-range falls back to the default caps. |
| `PREMIUM_DOWN_KBPS` | `utils/qos.js` | *(empty → default caps)* | Alias for the premium download cap expressed in Kbps (≤1024 stays Kbps, above converts to Mbps). Used only when `PREMIUM_DOWN_MBPS` is unset/invalid. |
| `PREMIUM_UP_KBPS` | `utils/qos.js` | *(empty → default caps)* | Premium upload cap (Kbps). Unset/out-of-range falls back to the default caps. |
| `VOUCHER_DEFAULT_DOWN_MBPS` | `services/omada.js` | *(empty → error)* | Default download cap (Mbps) for non-premium amounts. |
| `VOUCHER_DEFAULT_UP_KBPS` | `services/omada.js` | *(empty → error)* | Default upload cap (Kbps) for non-premium amounts. |

### Per-voucher bandwidth caps (voucher login)

A guest who redeems a voucher is capped through the same controller call the
payment flows use (`services/omada.js` → `setClientRateLimit`). The
`extPortal/auth` body itself carries **no**
QoS fields: TP-Link's External Portal Server spec defines only
`clientMac`/`clientIp`/`apMac`/`ssidName`/`radioId` (or `gatewayMac`/`vid`),
`site`, `time` and `authType`, and an unknown field can make firmware reject the
whole authorization.

Resolution order for a redeemed voucher (`utils/qos.js` →
`resolveVoucherRateLimit`):

1. `vouchers.down_kbps` / `vouchers.up_kbps` — per-voucher caps, stored in Kbps
   (5 Mbps = 5000). Values above 1024 Kbps are converted to Mbps for the
   controller, which accepts 1–1024 per unit (unit 1 = Kbps, unit 2 = Mbps).
2. Premium vouchers (`type = 'premium'`) → `PREMIUM_DOWN_MBPS` (or
   `PREMIUM_DOWN_KBPS`) / `PREMIUM_UP_KBPS`.
3. Everything else → `VOUCHER_DEFAULT_DOWN_MBPS` / `VOUCHER_DEFAULT_UP_KBPS`.

The tier is read from `vouchers.type` (the row is selected with that column in
`services/session.js` → `validateVoucher`) and normalized through
`utils/qos.js` → `normalizeVoucherType` (trim + lowercase), so a row stored as
`Premium`/`PREMIUM`/` premium ` still resolves to the premium tier. A premium
session whose `PREMIUM_*` caps cannot be resolved logs
`[session/qos] PREMIUM session … has NO premium caps` and is capped with the
`VOUCHER_DEFAULT_*` values — that log line is the signal that the premium
variables are missing or misnamed, not that the voucher was misread.

Both per-voucher caps must be set together; a half-configured row is treated as
unset so one direction can never be left on the default by accident. The caps
are copied onto the session (`sessions.down_kbps`, `sessions.up_kbps`) so a
re-authorization or a premium resume re-applies exactly the cap the guest paid
for, even if the voucher row is edited afterwards.

**Transport.** The cap is applied through the controller's web API —
`PATCH /{omadacId}/api/v2/sites/{siteKey}/clients/{MAC}/ratelimit` on a **fresh
administrator session** obtained at the start of every call from
`OMADA_ADMIN_NAME` / `OMADA_ADMIN_PASSWORD` (`OMADA_BASE_URL`). The hotspot
**portal operator** account cannot be used here: it holds no site privileges, so
the site query returns 0 sites and the cap is rejected. This is the same call the
controller UI makes, so it needs no OAuth credentials; a fallback under
`/openapi/v1/…` with the same admin session is tried if the firmware does not
expose the `/api/v2` route. Captive-portal authorization keeps using the separate
portal operator session (`OMADA_PORTAL_OPERATOR_*`), which Omada requires for
`/hotspot/extPortal/*`.

Applying the cap is **best-effort**: the guest is already authorized and the
voucher already spent, so a rejected/failed rate-limit call never fails the
login. `POST /api/auth` reports the outcome as `qosApplied`, with `qosError` when
it failed and `qosMock: true` when no controller is configured (mock mode: no
`OMADA_BASE_URL`).

Per-voucher caps are set through `POST /api/admin/vouchers`
(`downKbps`/`upKbps`, both or neither, in Kbps), `PUT /api/admin/vouchers/:id`
(send `null` for both to clear), or the optional `Download (Kbps)` /
`Upload (Kbps)` columns of a voucher import. Both columns are optional; leave
them blank to use the tier/default caps. The admin voucher table shows the
resulting speed (`default`, `↓ 20 Mbps / ↑ 5 Mbps`, …).

### Captive-portal QR payment methods

Served to the frontend by `GET /api/payment/methods`; each defaults to `''`
when unset. The `*_QR_B64` values are complete data-URI strings
(e.g. `data:image/png;base64,iVBORw0KGgo…`).

| Variable | Description |
|---|---|
| `GCASH_NAME`, `GCASH_NUMBER`, `GCASH_QR_B64` | GCash receiver name, number, and QR image. |
| `MAYA_NAME`, `MAYA_NUMBER`, `MAYA_QR_B64` | Maya receiver name, number, and QR image. |
| `QRPH_NAME`, `QRPH_NUMBER`, `QRPH_QR_B64` | QR Ph receiver name, number, and QR image. |

### Admin

| Variable | Referenced in | Default | Description |
|---|---|---|---|
| `ADMIN_API_KEY` | `routes/admin.js` | *(unset)* | API key accepted via `X-API-Key` / bearer token for `/api/admin/*`. |
| `ADMIN_USERNAME` | `routes/admin.js` | `admin` | Username for `POST /api/admin/login`. |
| `ADMIN_PASSWORD` | `routes/admin.js` | `ADMIN_API_KEY` | Admin login password for `POST /api/admin/login`. |

### Redirects

| Variable | Referenced in | Default | Description |
|---|---|---|---|
| `ALLOWED_REDIRECT_DOMAINS` | `routes/auth.js` | *(empty → allow any)* | Comma-separated allowlist of post-auth redirect domains. |
| `DEFAULT_REDIRECT_URL` | `routes/auth.js` | `https://www.google.com` | Fallback destination when no redirect is supplied. |

### Variables no longer used

The following appear in `.env.example` or older docs but are **not referenced
anywhere in the backend code** and should not be carried over from legacy setups:

- `OMADA_API_TOKEN` — superseded by the hotspot portal operator credentials
  (`OMADA_PORTAL_OPERATOR_NAME` / `OMADA_PORTAL_OPERATOR_PASSWORD`).
- `JWT_SECRET` — no JWT signing is performed by the backend.
- `PRICE_PER_HOUR`, `PREMIUM_PRICE_MODIFIER` — dynamic pricing is not read from
  the environment by the current code.
- `SESSION_DURATION_OPTIONS`, `BASE_URL`, `LOG_LEVEL`,
  `OMADA_AUTH_OPERATION`, `OMADA_UNAUTH_OPERATION` — not read by the code.

> `backend/.env.example` still lists a few of these legacy names. Treat the code
> (and the tables above) as the source of truth.

---

## 7. Secure Frontend Build (`inject-secrets.js`)

The public HTML pages in this repository ship with **placeholder tokens** so that
real contact details never live in the public repo. The root-level
`inject-secrets.js` (dependency-free; uses only Node's `fs` and `path`) replaces
those tokens in place at build time.

### What it injects

| Placeholder token | Environment variable | Files |
|---|---|---|
| `__STORE_LOCATION__` | `STORE_LOCATION` | `index.html` (HTML text) |
| `__FACEBOOK_PAGE_NAME__` | `FACEBOOK_PAGE_NAME` | `index.html`, `error.html`, `status.html` (JS) |
| `__FACEBOOK_URL__` | `FACEBOOK_URL` | `index.html`, `error.html`, `status.html` (JS) |
| `__CONTACT_NUMBER__` | `CONTACT_NUMBER` | `index.html`, `error.html`, `status.html` (JS) |
| `__SUPPORT_EMAIL__` | `SUPPORT_EMAIL` | `index.html`, `success.html`, `error.html`, `status.html` |

Values are HTML-escaped or JavaScript-escaped depending on where each token
lives. **Unset values degrade safely**: the Contact Support modal hides the
affected row, and footer links fall back to `#`. The script never logs the
values, only replacement counts.

> This step injects **contact/store details only**. It does **not** inject API
> keys or the MacroDroid secret — those stay server-side as backend environment
> variables (§6).

### Where it runs in the pipeline

- **Primary (production):** during the Docker image build. `backend/Dockerfile`
  copies `inject-secrets.js` to `/app` and the HTML to `/app/public`, declares
  the five variables as build `ARG`s, and runs `node inject-secrets.js`. Render
  passes dashboard environment variables to the Docker build, so setting them in
  the Render dashboard is enough.
- **Manual (for testing):** run it directly from the repository root:

  ```bash
  STORE_LOCATION="123 Example St" SUPPORT_EMAIL="help@example.com" node inject-secrets.js
  ```

  ⚠️ The script rewrites the target HTML files **in place**. If you run it
  locally, restore the placeholders before committing:

  ```bash
  git checkout index.html success.html error.html status.html
  ```

- There is **no npm script** for this step; it is a Docker build step. When
  running the backend locally (outside Docker), the root HTML files do not have
  the tokens replaced — set the values in the Render dashboard for production.

---

## 8. Backend API Reference

All routes are mounted in `backend/src/server.js`. JSON request bodies are
limited to 16 kB.

### Public portal routes

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth` | Voucher authentication (6-digit code) + Omada authorization. |
| `GET` | `/api/session/status` | Session remaining time. Accepts `?sessionId=…` or `?mac=…`. |
| `POST` | `/api/session/pause` | Pause a premium session. |
| `POST` | `/api/session/resume` | Resume a paused premium session. |
| `POST` | `/api/session/expire` | Expire a session (admin/internal). |
| `GET` | `/health` | Unauthenticated health check → `{ ok, timestamp, env }`. |

#### `POST /api/webhooks/macrodroid`

Receives a verified payment from MacroDroid. See §3 for the body and flow.

#### `POST /api/payment/context`

Fire-and-forget beacon called when a client lands on the portal. Stores the
client MAC, optional client IP, AP MAC, SSID, and radio ID in
`portal_client_context` for later payment authorization. Unauthenticated by
design, protected by strict validation and a dedicated per-IP limiter.

#### `GET /api/payment/methods`

Returns GCash/Maya/QR Ph receiver names, numbers, and QR images from the
environment. Cache-Control is `no-store`.

#### `POST /api/payment/claim`

Manual fallback: submit a reference number when the automatic interception has
not arrived.

Body: `{ ref_suffix, mobile_number, client_mac?, ap_mac? }`

| Field | Required | Notes |
|---|---|---|
| `ref_suffix` | yes | Last 4 digits of the payment reference. |
| `mobile_number` | yes | 11-digit PH mobile (`09XXXXXXXXX`). Saved on the reconciled `webhook_events` row and used as the SMS destination. |
| `client_mac` | no | The device to authorize. Without it the claim still succeeds, it is just not auto-connected. |
| `ap_mac` | no | Recorded in logs for traceability; the authorization itself uses the AP MAC / SSID / radio ID captured by `POST /api/payment/context`. |

The paying device is authorized **directly** through the controller's web UI API
(`omadaService.authenticateClient` → `POST …/api/v2/hotspot/extPortal/auth`)
**before** the claim is written — so the customer does not have to type a code at
all — and only once the controller has accepted is the payment marked claimed.
Because that call needs the device's AP MAC / SSID / radio ID, a device that has
never loaded the portal cannot be auto-connected; the request answers
`502 MISSING_PORTAL_CONTEXT` and consumes nothing (see
[Omada web UI authorization](#omada-web-ui-authorization-payment-flows)). The
response is then sent **immediately**, before the 2000 ms wait and the
`setClientRateLimit` cap: those run after the caller already has its answer, and
their outcome is logged rather than returned. The bandwidth cap comes from the
same amount-based tier rules as the InstaPay webhook (`utils/qos.js`); a premium
amount gets the `PREMIUM_*` caps and every other amount gets the
`VOUCHER_DEFAULT_*` caps.

| Result | Response |
|---|---|
| Device authorized | `200 { success: true, authorized: true, message: 'Device authorized', voucherCode, ref_no, minutes }` |
| Not auto-connected (no `client_mac`, or the claimed voucher has no usable duration) | `200 { success: true, authorized: false, voucherCode, ref_no, minutes, authError }` |
| Already claimed by the SAME mobile number | `200 { success: true, authorized: false, alreadyClaimed: true, voucherCode, ref_no, minutes }` |
| Omada refused | `502 { success: false, authorized: false, code: 'OMADA_AUTH_FAILED', error }` |
| Device has no fresh portal context (never loaded the portal, or the row is older than 1 hour) | `502 { success: false, authorized: false, code: 'MISSING_PORTAL_CONTEXT', error }` — nothing consumed; load the portal page and tap Claim again |
| Payment not found / claimed by another number | `404 { success: false, error: 'Payment not found or already claimed.', code: 'PAYMENT_NOT_FOUND' }` |
| No voucher left for the amount | `404 { success: false, error: 'No voucher is available for this amount…', code: 'NO_VOUCHER_AVAILABLE' }` |

Four deliberate behaviours worth noting:

- **A refused authorization consumes nothing.** Nothing is written before Omada
  answers, so a refusal leaves the payment `unclaimed` and the voucher `active`
  and unassigned: the customer can claim the SAME 4 digits again — a second tap
  is a real retry instead of "Payment not found or already claimed" — and no SMS
  is sent for a code that was never consumed.
- **A claim that already succeeded can be replayed.** If the first response never
  reached the phone, retrying the same 4 digits with the same `mobile_number`
  returns the voucher that payment already produced (`alreadyClaimed: true`),
  with no second voucher, no second SMS and no second authorization (which would
  extend the session for free). A different number keeps the generic 404, and so
  does a claimed row with no stored number, so the code never leaks to someone
  who only guessed the digits.
- **The success response is sent before the bandwidth cap.** The claim is already
  committed, so no slow post-commit step may delay that answer: a connection that
  dies during the 2000 ms wait before the cap would make a successful claim
  *look* failed, and the retry would answer "already claimed". A failed cap is
  logged only — the guest is already online.
- **Every attempt is logged.** Each request writes one `[payment/claim] attempt`
  line (suffix + MACs, never the mobile number), and the 404 / rollback /
  authorization paths log their outcome, so a support report can be matched to a
  request instead of leaving no trace.
- **`voucherCode` is still returned even when the device is authorized.** It
  keeps the payment↔voucher ledger intact and provides the manual fallback, so
  the portal can stop *showing* it without the backend losing the audit trail.

### Admin routes

`/api/admin/*` require a bearer token from `POST /api/admin/login` or the
`ADMIN_API_KEY` via `X-API-Key`.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/admin/login` | Exchange username/password for a session token. |
| `GET` | `/api/admin/me` | Current admin username. |
| `GET` | `/api/admin/vouchers` | List vouchers. |
| `POST` | `/api/admin/vouchers` | Create voucher(s). |
| `PUT` | `/api/admin/vouchers/:id` | Update a voucher. |
| `DELETE` | `/api/admin/vouchers/:id` | Delete a voucher. |
| `POST` | `/api/admin/vouchers/import` | Import vouchers from CSV/XLSX. |
| `POST` | `/api/admin/vouchers/delete-all` | Delete all vouchers and reset the ID sequence. |
| `GET` | `/api/admin/sessions` | List active/pending sessions. |
| `POST` | `/api/admin/sessions/:id/expire` | Force-expire a session. |
| `GET` | `/api/admin/stats` | Dashboard statistics. |

### Static pages

When the portal HTML directory is found, `express.static` serves it and these
routes are added:

| Method | Path | File |
|---|---|---|
| `GET` | `/` | `index.html` |
| `GET` | `/success` | `success.html` |
| `GET` | `/status` | `status.html` |
| `GET` | `/admin` | `admin.html` |
| `GET` | `/login` | `login.html` |
| `GET` | `/error` | `error.html` |

---

## 9. Testing

```bash
cd backend
npm test
```

Tests use Jest + supertest and cover (among others):

- `POST /api/webhooks/macrodroid` — secret validation, field validation,
  duplicate reference rejection, success, Omada failure (`502`), and the
  `422 MISSING_PORTAL_CONTEXT` fail-loud paths.
- `POST /api/payment/claim` and `GET /api/payment/methods`.
- Session state transitions, pause/resume, and expiration math.

Run in watch mode with `npm run test:watch`.

---

## 10. Security Notes

- Public HTML is committed with placeholders only; real contact details are
  injected at build time (§7). Never commit injected values.
- The MacroDroid `secret_token` is compared in constant time and grants no access
  unless it matches `MACRODROID_WEBHOOK_SECRET`.
- Payment reference numbers are deduplicated at the database level to prevent
  replaying a single payment.
- Redirect targets are validated against `ALLOWED_REDIRECT_DOMAINS`
  (empty allowlist permits any http/https URL — set it in production).
- Rate limiting is applied to all API routes, with a stricter limiter on
  login/auth endpoints.
- MAC addresses are normalized to uppercase colon-separated format before storage
  and lookup.
- The server trusts one proxy hop (`trust proxy = 1`) so per-IP rate limits use
  the real client IP behind Render's proxy.
- Never place secrets in `config/config.js` — it ships with the portal frontend.

---

## License

MIT. Modify and use freely for commercial or personal deployments.
