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
9. [Deployment on Render](#9-deployment-on-render)
10. [Testing](#10-testing)
11. [Security Notes](#11-security-notes)

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
authorized immediately; unknown references are stored as `pending` for human
review in the claims dashboard (admin-claims.html). Operators review and approve
or reject them via the `/api/admin/claims/*` routes.

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
├── admin-claims.html          # Pending manual-payment-claims dashboard
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
├── render.yaml                # Render blueprint (web service + PostgreSQL)
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
here. Set them in `backend/.env` for local development, and in the **Render
dashboard → Environment** (or `render.yaml`) for production.

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
| `OMADA_SITE` | `services/omada.js`, `routes/payment.js` | `Default` | Omada site name. |
| `OMADA_PORTAL_OPERATOR_NAME` | `services/omada.js` | *(empty)* | Hotspot portal operator username (for `POST /{OMADAC_ID}/api/v2/hotspot/login`). |
| `OMADA_PORTAL_OPERATOR_PASSWORD` | `services/omada.js` | *(empty)* | Hotspot portal operator password. |
| `OMADA_AUTH_TIMEOUT` | `services/omada.js` | `10000` | Controller request timeout (ms). |
| `OMADA_TLS_REJECT` | `services/omada.js` | `true` | Set to `false` only for dev with self-signed controller certs. |
| `OMADA_MOCK` | `services/omada.js` | `false` | `true` bypasses the controller entirely (mock mode). |
| `OMADA_TIME_UNIT` | `config/index.js` | `ms` | Unit (`ms`, `us`, or `s`) for the Omada `time` field; depends on controller firmware. |

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
| `ADMIN_PASSWORD` | `routes/admin.js` | `ADMIN_API_KEY` | Admin login password **and** the `x-admin-password` header for the claims dashboard. The claims routes **fail closed** (401) when unset. |

### Redirects

| Variable | Referenced in | Default | Description |
|---|---|---|---|
| `ALLOWED_REDIRECT_DOMAINS` | `routes/auth.js` | *(empty → allow any)* | Comma-separated allowlist of post-auth redirect domains. |
| `DEFAULT_REDIRECT_URL` | `routes/auth.js` | `https://www.google.com` | Fallback destination when no redirect is supplied. |

### Variables no longer used

The following appear in `.env.example`, `render.yaml`, or older docs but are
**not referenced anywhere in the backend code** and should not be carried over
from legacy setups:

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

### Admin routes

`/api/admin/*` (except the password-protected claims routes) require a bearer
token from `POST /api/admin/login` or the `ADMIN_API_KEY` via `X-API-Key`.

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

Claims routes require the `x-admin-password` header (matched against
`ADMIN_PASSWORD`; **fail closed** when unset):

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/claims/pending` | List pending manual payment claims. |
| `POST` | `/api/admin/claims/approve` | Authorize the device and process the claim. |
| `POST` | `/api/admin/claims/reject` | Reject a claim. |

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

## 9. Deployment on Render

The repository includes a Render blueprint (`render.yaml`):

- A **web service** named `goodvibesvendowifi`, built from
  `backend/Dockerfile` with `dockerContext: .`, health check on `/health`, and
  auto-deploy enabled.
- A **PostgreSQL** database; its connection string is injected as
  `DATABASE_URL`.

The Docker build:

1. Installs production dependencies (`npm ci --omit=dev`).
2. Copies the backend code and the portal HTML into `/app/public`.
3. Runs `inject-secrets.js` to bake in the store/contact details (§7).
4. On start, runs `node src/db/migrate.js` and then `node src/server.js`.

Set all secrets from §6 — plus the build-time variables `STORE_LOCATION`,
`FACEBOOK_PAGE_NAME`, `FACEBOOK_URL`, `CONTACT_NUMBER`, and `SUPPORT_EMAIL` — in
the Render dashboard, not in this repository.

---

## 10. Testing

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

## 11. Security Notes

- Public HTML is committed with placeholders only; real contact details are
  injected at build time (§7). Never commit injected values.
- The MacroDroid `secret_token` is compared in constant time and grants no access
  unless it matches `MACRODROID_WEBHOOK_SECRET`.
- Payment reference numbers are deduplicated at the database level to prevent
  replaying a single payment.
- The claims dashboard requires `ADMIN_PASSWORD` and fails closed when unset.
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
