# Omada Captive Portal — Backend

A Node.js / Express backend for the Omada captive portal. Handles voucher validation, session management, and Omada controller integration.

## Architecture

```
Browser (captive portal)  →  index.html
                                  │
                                  ├── [free voucher, direct mode]
                                  │         ↓
                                  │   Omada extPortal/auth (direct POST)
                                  │
                                  └── [managed mode]
                                            ↓
                                      Backend server
                                      ├── /api/auth         → validate voucher + call Omada
                                      ├── /api/session/status  → return remaining time
                                      ├── /api/session/pause   → freeze timer
                                      ├── /api/session/resume  → restart timer
                                      └── /api/session/expire  → admin: end session
```

## Prerequisites

- Node.js 18+
- npm or yarn
- Omada Controller (OC200 or software) with external portal configured
- Optional: PostgreSQL for production (SQLite for development)

## Setup

### 1. Install dependencies

```bash
cd backend
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your values
```

### 3. Initialize the database

```bash
# SQLite (default for development)
npm run db:migrate

# PostgreSQL (production)
# 1. Create the database:
#    createdb portal
# 2. Set DATABASE_URL in .env:
#    DATABASE_URL=postgresql://user:pass@localhost:5432/portal
# 3. Run migrations:
npm run db:migrate
```

### 4. Start the server

```bash
# Development (with auto-reload)
npm run dev

# Production
npm start
```

The server starts on port 3000 by default. Set `PORT` in `.env` to change.

## Environment Variables

See `.env.example` for the full list. Critical variables:

| Variable | Description |
|---|---|
| `OMADA_BASE_URL` | Omada controller base URL |
| `OMADA_API_TOKEN` | Controller API token |
| `DATABASE_URL` | Database connection string |
| `JWT_SECRET` | Secret for JWT signing (change in prod!) |

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth` | None | Authenticate with voucher |
| `GET` | `/api/session/status` | None | Get session info |
| `POST` | `/api/session/pause` | None | Pause active session |
| `POST` | `/api/session/resume` | None | Resume paused session |
| `POST` | `/api/session/expire` | None | Expire a session |
| `GET` | `/health` | None | Health check |

See the main `README.md` for full request/response formats.

## Testing

```bash
npm test
```

Tests cover:
- `portal.js` (frontend): query param parsing, voucher validation, redirect allowlist, mock auth
- `session.js`: state transitions, pause/resume, expiration math
- `omada.js`: error handling, mock responses

### End-to-end (with live controller)

1. Set `OMADA_MOCK=false` and provide `OMADA_BASE_URL` + `OMADA_API_TOKEN`
2. Deploy portal to HTTPS URL
3. Configure Omada external portal pointing to your server
4. Add domain to walled garden
5. Connect test device and complete real auth flow

## Production Checklist

- [ ] HTTPS enabled (Let's Encrypt or cloud-managed certificate)
- [ ] `NODE_ENV=production`
- [ ] Strong `JWT_SECRET`
- [ ] `OMADA_TLS_REJECT=true` (verify controller cert or use trusted CA)
- [ ] PostgreSQL instead of SQLite (or persistent volume for SQLite)
- [ ] Rate limiting configured
- [ ] Session expiration worker running (check logs on startup)
- [ ] Logs monitored (no secrets logged)
- [ ] Database backed up

## Known Controller Variations

The actual API behavior depends on your firmware. See the main `README.md` §Controller-Specific Values for the values that must be verified.
