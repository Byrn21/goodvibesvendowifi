# Phase 3 Security & Stability Audit
## Good Vibes Vendo Wi-Fi Captive Portal

**Date:** 2026-11-06
**Scope:** `backend/src/routes/`, `backend/src/services/`, `backend/src/utils/`, `backend/src/server.js`, `index.html`, `assets/portal.js`
**Posture:** Read-only audit. **No patches were written or committed.**
**Method:** Manual source review with control-flow tracing, plus two executed reproductions (marked ✅ *Reproduced*).

---

## 1. Executive Summary

The session lifecycle hardening from Phase 2 holds up well: voucher consumption is transactional and race-safe, session tokens are HMAC-signed with constant-time verification, webhook secrets are compared in constant time and fail closed, and the Omada deauth path verifies actual revocation instead of trusting HTTP 200. The frontend is clean of DOM XSS — every dynamic value goes through `textContent`.

However, the **authentication and authorization perimeter** has two exploitable holes that undermine the hardening work, and the rate limiting that is supposed to protect the unauthenticated payment/session routes can be bypassed with a single request header.

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| C-01 | **Critical** | Admin login accepts an empty password when no admin secret is configured (production included) — full admin takeover | `routes/admin.js:47-48,119-124` |
| C-02 | **Critical** | Unauthenticated payment takeover: a 4-digit guess claims another customer's paid voucher and gets the code back | `routes/payment.js:779-786,1002` |
| H-01 | High | `GET /api/session/status` mints a valid session-ownership token to anyone who knows a MAC or voucher code → kick a paying guest offline | `routes/session.js:306,780,795,810` |
| H-02 | High | All rate limits bypassable by rotating `X-Forwarded-For` (verified) | `server.js:39,226-246` |
| H-03 | High | Voucher enumeration oracle over a 1,000,000-code space, unauthenticated | `routes/session.js:128,682-830` |
| M-01 | Medium | Admin bearer tokens never expire and cannot be revoked | `routes/admin.js:105-117` |
| M-02 | Medium | CORS accepts `Origin: null` with credentials and trusts every private-LAN origin | `server.js:126,134,159` |
| M-03 | Medium | Device is authorized on Omada *before* the claim commits — rollback leaves an online, unconsumed client; voucher pick is unlocked | `routes/payment.js:929-1050` |
| M-04 | Medium | Failed deauth is terminal (no retry), and the expiry worker can stall for tens of minutes on a dead controller | `services/session.js:383-425,790-855` |
| M-05 | Medium | `xlsx@0.18.5` — known prototype-pollution and ReDoS CVEs reachable via admin import | `routes/admin.js` (import), `package.json` |
| M-06 | Medium | Credential comparisons in `admin.js` are not constant-time (inconsistent with the rest of the codebase) | `routes/admin.js:112,122` |
| L-01…L-10 | Low | Logging, voucher-generation format, CSP, config fragility, unauthenticated reauthorize amplification | see §5 |

**Highest business risk:** C-02 lets an attacker on the same SSID (or via the public tunnel) obtain a paid voucher code without paying, while simultaneously denying that voucher to the customer who did pay. It requires no account, no token and no device context.

---

## 2. Critical Findings

### C-01 — Admin authentication bypass when no admin secret is configured

**Location:** `backend/src/routes/admin.js:47-48` and `:119-124`

```js
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || ADMIN_API_KEY;
...
if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
  const token = require('crypto').randomBytes(32).toString('hex');
```

`config/index.js` intentionally resolves `ADMIN_API_KEY` to the empty string in production when the env var is missing, with a comment claiming the guard then "*fails closed (401 for everyone)*":

```js
const ADMIN_API_KEY = process.env.ADMIN_API_KEY
  || (process.env.NODE_ENV === 'production' ? '' : 'dev_admin_key');
```

That fail-closed guarantee is defeated by the login fallback. With both `ADMIN_API_KEY` and `ADMIN_PASSWORD` unset, `ADMIN_PASSWORD` becomes `''`, and `body.password === ''` compares equal. `POST /api/admin/login` with `{"username":"admin","password":""}` returns a valid 32-byte bearer token that `requireAuth` accepts on **every** admin endpoint.

**✅ Reproduced** (fresh process, `NODE_ENV=production`, both secrets unset):

```
empty-password login -> 200 {"success":true,"token":"687a724a…","expiresIn":28800}
wrong-password login -> 401 {"success":false,"error":"Invalid credentials."}
token used on /me    -> 200 {"success":true,"username":"admin"}
```

**Impact:** Complete administrative compromise — voucher CRUD and bulk delete, session termination, transaction export (customer mobile numbers), payment-method toggling, logo upload, CSV/XLSX import (see M-05). This is the single highest-impact finding in the codebase.

**Preconditions:** The deployment never set `ADMIN_API_KEY` / `ADMIN_PASSWORD`. This is *not* hypothetical: `.env.example` marks both as "change-this-…" template values, and `.env` is git-ignored, so a fresh Termux install that skipped that step is in this state. Note `ADMIN_PASSWORD` is **not** in `config/index.js` at all, contradicting the stated single-source-of-truth design — the file only exports `ADMIN_API_KEY`.

**Secondary defect:** The login handler is also the only place that reads `ADMIN_PASSWORD` from raw `process.env`, so the two consumers of the operator credential (`routes/admin.js`, `routes/session.js`) can disagree about what the credential is.

---

### C-02 — Unauthenticated payment takeover via 4-digit reference suffix

**Location:** `backend/src/routes/payment.js:779-786`

```js
const event = await db.getOne(
  `SELECT event_id, ref_no, amount FROM webhook_events
    WHERE status = 'unclaimed' AND ref_no LIKE ?
    ORDER BY id DESC LIMIT 1`,
  ['%' + refSuffix]
);
```

**Nothing binds the claimant to the payment.** The only credentials the route requires are:

* `ref_suffix` — the last **4 digits** of the reference (10,000 possibilities), and
* `mobile_number` — any syntactically valid PH mobile number in `09XXXXXXXXX` form.

`mobile_number` is *written* to `webhook_events` at claim time (`payment.js:1013`); it is never *checked* against the payment, because the webhook never recorded one (`webhook.js:122-127` inserts `event_id, ref_no, amount, status` only). The comment at `schema.sql:80` confirms the column is "*captured at claim time*".

So the entitlement proof is: *guess 4 digits before the real customer does.*

The handler then:

1. picks the first active voucher whose price matches the payment amount,
2. authorizes **the caller's** `client_mac` on the controller for the voucher's full duration (`payment.js:939-975`),
3. marks the voucher `claimed` and returns `voucherCode` in the response body (`payment.js:1148`).

`client_mac` is optional: without it the claim still succeeds and the code is still returned (`authError: 'no client_mac was supplied…'`). So an attacker needs **no device context at all** — just an HTTP client and a 4-digit guess.

**Impact:**
* Theft of paid service — attacker's MAC is authorized, or they receive the voucher code to sell/reuse.
* Denial of service against the paying customer — their payment is now `claimed`; their retry hits the replay path and 404s unless they know their number was already used, and support must intervene.
* At scale, `ref_suffix` collisions across concurrent payments make this a repeatable harvesting primitive.

**Aggravating factors:** `claimLimiter` is 30 attempts / 15 min / IP, but H-02 makes the IP key attacker-controlled, so effective attempts are unbounded. Even at 30/15min, 10,000 guesses is ~83 hours from one IP — but a 1,000-request burst against a busy evening's payment queue finds matches routinely.

**Why the existing mitigations don't cover it:**
* `ref_no` `UNIQUE` + the existence check make *double* claims impossible — they do not make *unauthenticated* claims safe.
* The `pending_claims` / MacroDroid screen-scrape path (step 1c) only runs when **no** unclaimed event matches. It is a fallback, not a gate, and the primary path bypasses it entirely.
* `findClaimedEntitlement()` *does* check the mobile number (`payment.js:660-668`) — which shows the intended model. The primary path is simply missing that same check.

---

## 3. High Findings

### H-01 — Session-ownership token handed out on MAC / voucher knowledge

**Location:** `backend/src/routes/session.js:306` (MAC/IP flow), `:780`, `:795`, `:810` (voucher flow)

`assertSessionOwner()` exists precisely because "*a bare sessionId in a POST body is not proof of anything*" — but the status route then mints that proof to the caller:

```js
// after resolving a session by ?mac= or by ?voucher= or by req.ip
const statusToken = setSessionCookie(req, res, sessionId);   // HttpOnly cookie …
...
statusToken,                                                  // … and the body
```

`?mac=AA:BB:CC:DD:EE:FF` resolves the newest session for that device and returns a signed 7-day token naming it. That token satisfies `assertSessionOwner`, so:

* `POST /api/session/pause { sessionId }` + the token → **`pauseSession()` calls `unauthenticateClient()` and kicks the guest off the controller** (`services/session.js:478-495`) while freezing their timer.
* `POST /api/session/resume { sessionId }` + the token → re-authorizes the device.

MAC addresses are not secrets — they are broadcast on the air, visible in the controller UI, and shipped in Omada's portal URL. A voucher code (6 digits) is also guessable and is itself an oracle via H-03.

**Impact:** Targeted, repeatable denial of service against Premium guests (kick + frozen clock), and a bypass of the ownership model that Phase 2 introduced. It does not grant the attacker paid time (resume only restores the victim's own session), which is why this is High rather than Critical.

**Preconditions:** `PAUSE_ENABLED=true`, target session is Premium and `active`. The pause → Omada unauth → offline effect is immediate.

### H-02 — Rate limiting is bypassable via `X-Forwarded-For`

**Location:** `backend/src/server.js:39` and `:226-246`

```js
app.set('trust proxy', 1);
...
const apiLimiter = rateLimit({ ..., validate: { xForwardedForHeader: false } });
```

With `trust proxy = 1`, `req.ip` is taken from the request's `X-Forwarded-For` chain, and `express-rate-limit` keys its buckets on `req.ip`. Disabling `xForwardedForHeader` validation removes the only warning that would have flagged this.

**✅ Reproduced** (express 4 + `express-rate-limit@7.5.1`, `trust proxy 1`, `max: 1`):

```
XFF 1.1.1.1        -> 200 {"ip":"1.1.1.1"}
XFF 2.2.2.2        -> 200 {"ip":"2.2.2.2"}      <-- new bucket, no 429
XFF 1.1.1.1 again  -> 429 {"blocked":true}
```

One header per request yields an unlimited supply of limiter identities.

**Impact:** Neutralises `loginLimiter` (admin login + `/api/auth`), `apiLimiter`, `claimLimiter` and `contextLimiter`. Directly enables:
* unlimited admin password brute force (C-01 makes this moot *today*, but it is the recovery blocker after C-01 is fixed),
* unlimited C-02 claim guesses,
* unlimited H-03 voucher enumeration,
* unlimited Omada amplification via `POST /api/session/reauthorize` (L-07).

**Exploitability depends on topology:** this works when the backend is reachable without a proxy that appends the true peer address — i.e. the documented Termux LAN deployment (`http://192.168.0.4:3000`) or a directly exposed port. Behind Cloudflare Tunnel, Cloudflare appends the real client IP as the right-most entry, so `req.ip` resolves correctly. The LAN case is the one guests are on.

### H-03 — Voucher enumeration oracle

**Location:** `backend/src/routes/session.js:128` → `handleVoucherStatus()` `:682-830`

`GET /api/session/status?voucher=NNNNNN` is unauthenticated, requires no session, and returns a **distinguishable** answer per state:

| Input | Response |
|-------|----------|
| code not in table | `404 { code: 'VOUCHER_NOT_FOUND' }` |
| unused voucher | `200 { active: true, state: 'unused', remainingSeconds, durationMinutes, voucherType }` |
| live session | `200 { active: true, state: 'active', sessionId, statusToken, remainingSeconds }` |
| consumed | `200 { active: false, error: 'EXPIRED' }` |

The code space is exactly `^\d{6}$` → 1,000,000. A hit on an unused code yields its tier, duration and validity, and — via H-01 — a working ownership token for any *live* code. Protection is `apiLimiter` only, which H-02 removes.

**Impact:** Inventory disclosure (how many valid codes exist, their denominations) and free access by redeeming discovered unused codes through `/api/auth`. This is a rational precursor to C-02/H-01 rather than an end in itself.

---

## 4. Medium Findings

### M-01 — Admin tokens never expire and cannot be revoked
`routes/admin.js:105-117`. `rememberToken()` stores a bare 64-char string; there is no expiry, no logout, and no per-user revocation. The login response advertises `expiresIn: 8 * 3600`, but nothing enforces it. `MAX_VALID_TOKENS = 100` only evicts the oldest by insertion order, and tokens only die on process restart (which is the sole revocation mechanism today). A token read from a shoulder-surfed admin session, a backup, or a leaked log is valid indefinitely.

### M-02 — Permissive CORS with credentials
`server.js:126` returns `true` for any `Origin: null`, and `:134` allows every private-LAN hostname on any port. With `origin: true` reflection and `credentials: true` (`:159`), any page that can produce a `null` origin (sandboxed iframe, `file://`) is admitted with credentials. Current admin auth is header-based, so this is not directly exploitable for admin takeover, and `SameSite=Lax` blocks the `portal_session` cookie on cross-site POSTs — but it is a latent hole that becomes exploitable the moment any cookie-based auth is added, and it lets arbitrary web content read unauthenticated API responses.

### M-03 — Claim authorizes the device before the commit; voucher pick is unlocked
`routes/payment.js:939-975` authorizes on Omada, then `:1000` opens the transaction that consumes the voucher and event. If the transaction rolls back (`NO_VOUCHER_AVAILABLE` on a concurrent claim, `PAYMENT_NOT_FOUND` on a double tap, or a DB error), the client **remains authorized on the controller with the full granted duration** while no voucher was consumed and no session row exists. The guest is online with nothing accounting for them; the dashboard, expiry worker and pause/resume all miss them.

Additionally, the voucher is chosen with a plain `SELECT ... WHERE state='active' AND assigned_ref_no IS NULL ORDER BY id ASC LIMIT 1` (`:870-875`) and only *later* conditionally updated by `id`. Two concurrent claims for the same amount select the **same** row; one wins and the other answers `NO_VOUCHER_AVAILABLE` even though other vouchers exist — and, per the paragraph above, the loser is already online. There is no `FOR UPDATE` / `SKIP LOCKED` and no reservation step.

### M-04 — Deauth failure is terminal; the expiry worker can stall
`services/session.js:383-425`: `expireSession()` writes `state='expired'` **then** calls `unauthenticateClient()` once. If that fails, it logs and returns `true`; nothing ever retries, because the row is no longer `active`. The guest keeps access until the controller's own `time` expires them (extPortal/auth does set a controller-side limit, which bounds the damage) — but the local record now claims they are offline.

`startExpirationWorker()` (`:790-855`) processes up to 50 sessions **sequentially** with `await`. Each `unauthenticateClient()` can attempt 3 deauth routes, each preceded by a session login, plus up to 2 authed-record list calls, each with `OMADA_AUTH_TIMEOUT` (default 10 s) — worst case on the order of a minute per session. With 50 expired sessions and an unreachable controller, one cycle can exceed `SESSION_ENFORCE_INTERVAL` (60 s) by an order of magnitude; the `isWorkerRunning` guard then silently skips every intervening cycle, so sessions that expired during the stall are not swept until it finishes. `pauseSession` has the same single-shot dependency, but there the ordering is correct (deauth **before** the state write, refusing the pause on failure).

### M-05 — Known vulnerabilities in `xlsx@0.18.5`
Installed version verified as `0.18.5`. Affected by CVE-2023-30533 (prototype pollution, fixed in 0.19.3) and CVE-2024-22363 (ReDoS, fixed in 0.20.2). Reachable through `POST /api/admin/vouchers/import`, which parses an attacker-supplied workbook with `XLSX.read(buffer)` before any validation. Requires admin auth (C-01 makes that trivial today), so this compounds rather than stands alone.

### M-06 — Non-constant-time credential comparison in `admin.js`
`:112` `provided === ADMIN_API_KEY` and `:122` `password === ADMIN_PASSWORD` are byte-wise early-exit comparisons. `routes/session.js` and `utils/session-token.js` both correctly use `crypto.timingSafeEqual`; the admin router is the outlier. The oracle is noisy over HTTP, so this is a defense-in-depth inconsistency rather than a practical break — but it is the same credential C-01 exposes.

---

## 5. Low Findings

| ID | Finding | Location | Note |
|----|---------|----------|------|
| L-01 | Live voucher code written to logs unmasked on Omada failure paths | `routes/auth.js:336,360` | Other paths correctly use `maskVoucher()`; on a *failed* auth the code is still redeemable, so this leaks a live credential into `server-run.log`/journal |
| L-02 | Admin-created vouchers can never be redeemed | `routes/admin.js:199` | Generates `` `${prefix}-${uuid12hex}` `` but `utils/voucher-code.js` requires `^\d{6}$`; `normalizeVoucherCode()` strips letters, so the result is not 6 digits. `prefix` is also unvalidated (any length up to the 16 kB body cap) |
| L-03 | Bulk voucher creation is not transactional | `routes/admin.js:198-206` | Loop of individual `INSERT`s; a mid-loop failure leaves a partial batch |
| L-04 | CSP allows inline script | `server.js:50` (`scriptSrc: 'unsafe-inline'`) | No XSS found to exploit it, but it removes the main mitigation if one is ever introduced |
| L-05 | `/health` discloses `NODE_ENV` | `server.js:262-263` | Minor fingerprinting |
| L-06 | `.env.example` rate-limit value conflicts with portal polling | `.env.example:221` (`RATE_LIMIT_MAX_REQUESTS=20`) vs `server.js` default 600 | A copy of the example value 429s the status page within minutes of normal polling; also makes `/api/session/status` unusable behind a shared NAT |
| L-07 | `POST /api/session/reauthorize` is an unauthenticated controller amplifier | `routes/session.js:410-500` | MAC-keyed, no ownership proof, each call performs extPortal/auth + admin login + QoS PATCH; bounded only by `apiLimiter` (see H-02). Grant time is correctly capped at `expires_at`, so it cannot extend a session |
| L-08 | InstaPay accepts arbitrary `duration_minutes` | `routes/webhook.js:451-453` | Secret-gated, so this is a blast-radius issue if the shared secret leaks; there is no upper bound |
| L-09 | Voucher update accepts arbitrary `state` and unvalidated numerics | `routes/admin.js:214-250` | Admin-only; `state` is unconstrained and `durationMinutes`/`price` are not range-checked (create is) |
| L-10 | CSV formula injection | `routes/admin.js` `csvField()` | **Not reachable**: `mobile_number` is digits-only by `MOBILE_RE`, `voucher_code` is generated, `ref_no` is secret-gated. Recorded for completeness only |

---

## 6. Verified Sound (No Findings)

These were specifically examined because they are the usual failure points, and they hold:

1. **Voucher consumption is atomic.** `routes/auth.js:400-450` wraps `consumeVoucher()` + `recordSession()` in one transaction, and `consumeVoucher()` guards on `state IN ('active','claimed')`, returning `false` on a lost race with nothing written. The Omada call happens *before* the transaction and the voucher is deliberately left unconsumed when the controller refuses (`auth.js:330-370`) — correct fail-closed ordering.
2. **Session tokens are cryptographically sound.** `utils/session-token.js`: HMAC-SHA256 over `sessionId.expiresAt`, constant-time verify, 7-day TTL, `HttpOnly` + `SameSite=Lax` + conditional `Secure`. No default/static secret (a random per-process key is generated and warned about). *The problem is who receives the token (H-01), not the token itself.*
3. **Webhook authentication is constant-time and fails closed.** `webhook.js:60-77,100` — missing or unset `MACRODROID_WEBHOOK_SECRET` yields 401, and the comparison is `timingSafeEqual` with a flat-timing dummy for length mismatch.
4. **Duplicate payments are blocked at the DB level.** `schema.sql:37,75,132,133` define `UNIQUE` on `sessions.ref_no` and `webhook_events.ref_no` (plus partial unique indexes), and the routes map `23505`/`SQLITE_CONSTRAINT` to 409. The `SELECT`-then-`INSERT` race is correctly backstopped.
5. **Omada deauth verifies revocation.** `services/omada.js:640-700` accepts a route only when the controller answers `errorCode 0` **and** the MAC is absent from `authed-records`, otherwise it falls through to the next route and finally the `time=1` fallback. `authenticateClient` treats anything other than `success === true` as failure. Timeouts destroy the socket (`OMADA_TIMEOUT`), and 500s/non-zero `errorCode` throw `OMADA_AUTH_REJECTED` — both propagate to a 502 without consuming vouchers. **A failed auth/deauth does not corrupt the local DB** (the one exception is M-03's claim ordering).
6. **No DOM-based XSS in `index.html` / `assets/portal.js`.** There is exactly one `innerHTML` in `portal.js:1679`, and it assigns `''`. Every URL parameter (`?mac=`, `?error=`, `?ssidName=`, `?originUrl=`), every `localStorage` value, and every API-supplied string is rendered through `textContent` / `setAttribute`. `success.html` additionally restricts its exit redirect to `http:`/`https:` (`success.html:562`) and `inject-secrets.js:164` HTML-escapes its replacements. The `?mac=` / `?error=` sinks named in the brief are safe. **The frontend's weakness is not injection; it is that it trusts identity (H-01).**
7. **The expiration worker writes local state before the network call.** `expireSession()` persists `expired` first, so a controller outage leaves the DB conservative and consistent (see M-04 for the remaining consequence).

---

## 7. Patch Execution Plan (highest priority first)

Do **not** apply these yet — this is the plan for approval. Each step lists the change, the file, and how to verify it. Steps 1–2 are independent and can land together.

### Step 1 — Close C-01 (admin auth bypass) — *blocking*

1. Move `ADMIN_PASSWORD` into `backend/src/config/index.js` next to `ADMIN_API_KEY`, resolved once at process start, with the same production fail-closed rule (`''` when unset). Export it. `routes/admin.js` must import it and never read `process.env.ADMIN_PASSWORD` again.
2. Reject the login outright when the configured secret is empty:
   ```js
   if (!ADMIN_PASSWORD) return res.status(401).json({ success:false, error:'Admin login is not configured.' });
   ```
   Place it before the credential comparison so an unconfigured deployment answers 401 instead of issuing a token.
3. Add a startup assertion in `server.js` after config load: in production, refuse to start (or log a loud `[FATAL]`) when both `ADMIN_API_KEY` and `ADMIN_PASSWORD` are empty. A portal that boots with no admin credential is a misconfiguration, not a valid mode.
4. Replace both `===` comparisons in `routes/admin.js` (`:112`, `:122`) with a shared `safeEqual()` helper (move the one in `routes/webhook.js` into `src/utils/` and reuse it) — closes M-06 in the same edit.
5. Add `ADMIN_USERNAME` to the same config module for consistency.

**Verify:** with `NODE_ENV=production` and both secrets unset → `POST /api/admin/login {username:"admin",password:""}` must be **401**; with a configured `ADMIN_PASSWORD`, correct password → 200 only when the password matches exactly; wrong password → 401. Reuse the reproduction harness from §2 (supertest against the router).

### Step 2 — Close C-02 (payment takeover) — *blocking*

Order matters; (a) is the real fix, (b) is the safety net that survives a webhook that cannot carry a number.

1. **(a) Bind the payment to the payer.** Extend the MacroDroid webhook contract to accept the payer's mobile number and store it in `webhook_events.mobile_number` at record time (the schema column already exists but is only written at claim time). In `POST /api/payment/claim`, require the supplied `mobile_number` to equal the stored one; treat a mismatch as the same generic `404 PAYMENT_NOT_FOUND` (never a distinct "wrong number" response — that would be a new oracle). Mirror the check in `findClaimedEntitlement()` (already correct) and in `/claim/status`.
2. **(b) Server-side per-suffix attempt budget.** Add a `claim_attempts` table (or a `pending_claims`-style row keyed by `ref_suffix`) incremented on every *failed* claim, independent of IP. Lock the suffix for a cooldown after N failures (e.g. 5) and alert to logs. This is the only control that survives H-02, because it is not keyed on anything the request supplies.
3. **(c) Raise the entropy floor.** If the MacroDroid flow can supply the full reference or a longer suffix, accept 6+ digits and keep 4-digit acceptance only for legacy pending claims. Document the customer-facing change ("last 6 digits") if adopted.
4. **(d) Stop returning `voucherCode` when the claimant's device was not authorized** — currently an unauthenticated caller with no `client_mac` still receives the code. Require a `client_mac` whose portal context exists, or return the code only via the SMS channel.

**Verify:** a claim with a mismatched mobile number must not reveal a voucher; the 6th failed guess on one suffix must be throttled regardless of source IP; a legitimate first-tap→retry sequence must still replay the original voucher (`alreadyClaimed: true`). Add a regression test alongside `backend/__tests__/voucher-qos.test.js`.

### Step 3 — Close H-01 (ownership token minted from MAC/voucher) — *high*

1. Split identity into two tokens: keep the read-only `portal_session` token (safe to issue from a MAC/voucher lookup — it only powers status polling), and add a **control token** carrying a per-session nonce stored on the `sessions` row. Issue the control token **only** in the responses of `POST /api/auth`, `POST /api/payment/claim`, and `POST /api/session/resume` — never from `GET /api/session/status`.
2. Require the control token in `assertSessionOwner()` for `POST /api/session/pause` and `POST /api/session/resume` (`routes/session.js:57-70`). Keep the read token as a fallback only for reading.
3. While there: make `pause` re-check `isPausableVoucherType` **and** re-read state inside the same operation that writes it (currently `pauseSession` re-reads, so this is already close; the token is the actual gap).

**Verify:** `GET /api/session/status?mac=<victim>` must no longer yield a token usable on `/api/session/pause` (expect 403 `SESSION_MISMATCH`); a guest who just authenticated must still be able to pause/resume from the status page and after a WebView storage wipe (regression risk — test the "cookie only, no localStorage" path).

### Step 4 — Fix rate limiting (H-02 → protects H-03, C-02, Omada) — *high*

1. Make proxy trust explicit and deployment-driven:
   ```js
   const TRUST_PROXY = process.env.TRUST_PROXY_HOPS;   // undefined → do NOT trust
   app.set('trust proxy', TRUST_PROXY === undefined ? false : parseInt(TRUST_PROXY, 10));
   ```
   Default `false` for the LAN/Termux deployment; document `TRUST_PROXY_HOPS=1` for Cloudflare Tunnel. Never ship `trust proxy 1` as the default.
2. Remove `validate: { xForwardedForHeader: false }` from both limiters and let the library warn on misconfiguration.
3. Add a dedicated strict limiter on `GET /api/session/status?voucher=` (e.g. 10/15 min/IP) and on `POST /api/session/reauthorize` (L-07), separate from `apiLimiter`.
4. Reconcile `.env.example:221` (`RATE_LIMIT_MAX_REQUESTS=20`) with the 600 default, and note the polling requirement in the comment (L-06).

**Verify:** repeat the §3 experiment — `X-Forwarded-For: 1.1.1.1` then `2.2.2.2` against a `max: 1` limiter must return 429 for the second request when `trust proxy` is `false`.

### Step 5 — Reduce the H-03 oracle

1. Collapse the response: an unknown code, a code belonging to another device, and an expired code should share one shape and status (e.g. `200 { active:false, state:'unknown' }`), with the precise reason reserved for a caller that presents a valid session token.
2. Drop `durationMinutes`/`voucherType` from unauthenticated responses.
3. Rate-limit per the step above.

**Verify:** scripted enumeration of 100 sequential codes must produce one indistinguishable response shape and must trip the limiter well before 100.

### Step 6 — Fix the claim commit ordering (M-03) and deauth resilience (M-04)

1. **Reserve, then authorize, then finalize.** Inside one transaction: conditional `UPDATE vouchers SET state='reserved' WHERE id = (SELECT id … FOR UPDATE SKIP LOCKED)`, commit the reservation; authorize on Omada; then finalize (`claimed` + event `claimed` + session row) or release the reservation on failure. On PostgreSQL use `SKIP LOCKED` to stop concurrent claims colliding on the same row; on SQLite rely on the conditional update plus the reservation state.
2. If finalization fails after a successful authorization, **compensate**: call `unauthenticateClient()` for that MAC so the guest is not left online against an unconsumed voucher.
3. Bounded deauth: give `expireSession()` a shorter controller budget than the general timeout, cap the worker's concurrency (e.g. 3 at a time), and add a lightweight retry queue (`deauth_pending` flag + backoff) so a controller outage is reconciled later instead of being lost when the row leaves `active`.
4. Consider moving the worker's Omada calls behind `setImmediate`/a queue so a stalled controller cannot hold the cycle open.

**Verify:** kill network access to the controller and confirm the worker completes a cycle within the interval (log timestamps), that rows stay consistent, and that recovery re-attempts the kick once the controller returns. Concurrency test: two simultaneous claims for the same amount must consume **two distinct** vouchers, not one voucher plus one failure.

### Step 7 — Dependency and hygiene pass (M-05, L-01…L-05)

1. Upgrade `xlsx` to ≥ 0.20.2 (or the current SheetJS distribution) and confirm the import path still parses the sample workbooks; keep the 5 MB cap and memory-only storage.
2. Mask voucher codes in `routes/auth.js:336,360` (`maskVoucher()` is already imported in that file).
3. Fix `routes/admin.js:199` so generated codes are 6 digits (`String(n).padStart(6,'0')` from a sequence, or a digits-only random), and validate `prefix` length/charset.
4. Wrap bulk create in `db.transaction()` (L-03).
5. Remove `'unsafe-inline'` from `scriptSrc` after moving the remaining inline scripts in `index.html`/`status.html`/`success.html` to files (L-04) — schedule separately; it is a refactor with breakage risk in captive WebViews.
6. Trim `/health` to `{ ok, timestamp }` (L-05).

---

## 8. Residual Risk & Notes

* **Shared-secret single factor.** `MACRODROID_WEBHOOK_SECRET` / `INSTAPAY_WEBHOOK_SECRET` authenticate payment events with a bearer-style secret over plain HTTP on the LAN. There is no HMAC signature, timestamp or replay window. Anyone who can read that secret (or the traffic) can mint payments. Out of scope to redesign here, but worth scheduling: HMAC + timestamp + nonce.
* **`MOCK_MODE`.** `services/omada.js` honours a mock mode; confirm it cannot be enabled in production (an auth bypass by configuration).
* **Test coverage.** `backend/__tests__/` has strong coverage of voucher claim, webhook, session and status flows. The findings above are largely *authorization* gaps, which is why they passed: the suites assert behaviour, not who is allowed to trigger it. Each patch step above should add an adversarial case (wrong identity, spoofed header, repeated guess).
* **Scope limit.** `admin.html`, `login.html`, `status.html` and `success.html` were reviewed only where the requested frontend scope (`index.html`, `assets/portal.js`) flows into them. A full pass over the admin panel's client-side rendering is recommended before the next release, since C-01 makes that panel the highest-value target.

---

**Status: report only. No source files were modified and nothing was committed. Awaiting approval to begin with Step 1 (C-01) and Step 2 (C-02).**
