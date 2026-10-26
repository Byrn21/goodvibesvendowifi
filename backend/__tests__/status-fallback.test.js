/**
 * __tests__/status-fallback.test.js
 * Drives the REAL status.html inline script in a minimal DOM stub (no jsdom
 * dependency) to verify the cloud-tunnel fallback:
 *
 *   - the page asks GET /api/session/status with NO query first (address-based
 *     device lookup)
 *   - when the backend answers 502 MISSING_PORTAL_CONTEXT — the expected answer
 *     behind a tunnel, where req.ip is the tunnel's public address and never the
 *     guest's LAN address — it immediately retries with the MAC that
 *     assets/portal.js saved as `device_mac`, or with a stored session id
 *   - with nothing saved either, it shows the "open the portal page" guidance
 *     instead of claiming the session ended
 *
 * The stub only implements what the page touches; anything missing surfaces as
 * a thrown error rather than being silently skipped.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..', '..');
const CONFIG_JS = fs.readFileSync(path.join(ROOT, 'config', 'config.js'), 'utf8');
const STATUS_HTML = fs.readFileSync(path.join(ROOT, 'status.html'), 'utf8');

/** The inline <script> that polls the status API (not the support-link one). */
const STATUS_JS = (() => {
  const scripts = [];
  const re = /<script>([\s\S]*?)<\/script>/g;
  let match;
  while ((match = re.exec(STATUS_HTML)) !== null) scripts.push(match[1]);
  const found = scripts.find((s) => s.indexOf('Session status polling') !== -1);
  if (!found) throw new Error('status.html: status polling script not found');
  return found;
})();

const MAC = 'AA:BB:CC:DD:EE:FF';
const SESSION_ID = 'sess_tunnel_1';

const MISSING_CONTEXT_MESSAGE =
  'We could not identify this device yet. Open the Wi-Fi portal page once, then tap Refresh.';

// ── Minimal DOM stub ────────────────────────────────────────────
function makeClassList() {
  const set = new Set();
  return {
    add(...names) { names.forEach((n) => set.add(n)); },
    remove(...names) { names.forEach((n) => set.delete(n)); },
    contains(name) { return set.has(name); },
    toggle(name) {
      if (set.has(name)) { set.delete(name); } else { set.add(name); }
      return set.has(name);
    },
    values() { return Array.from(set); },
  };
}

function createElement(id) {
  return {
    id,
    textContent: '',
    innerHTML: '',
    href: '',
    value: '',
    disabled: false,
    style: {},
    classList: makeClassList(),
    setAttribute() {},
    getAttribute() { return null; },
    addEventListener() {},
    removeEventListener() {},
    appendChild() {},
    removeChild() {},
    closest() { return null; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    focus() {},
    blur() {},
  };
}

/**
 * Load config/config.js + the status.html script into a fresh context.
 *
 * @param {Object} opts
 * @param {string} opts.search   window.location.search for this load
 * @param {Map}    opts.storage  localStorage contents
 * @param {Array}  opts.responses [{test: RegExp, status, body}] — the first
 *   entry whose `test` matches the request URL wins
 * @param {Function} [opts.respond] (url, callIndex) => {status, body}; overrides
 *   `responses` for tests that need a different answer per call
 * @returns {Object} { els, fetchCalls, storage, flush, runPoll }
 */
function loadStatus(opts) {
  const storage = opts.storage || new Map();
  const fetchCalls = [];
  const timeouts = [];
  const els = new Map();
  const getEl = (id) => {
    if (!els.has(id)) els.set(id, createElement(id));
    return els.get(id);
  };

  const localStorageStub = {
    getItem: (k) => (storage.has(k) ? storage.get(k) : null),
    setItem: (k, v) => storage.set(k, String(v)),
    removeItem: (k) => storage.delete(k),
  };
  const sessionStorageStub = {
    getItem: () => null,
    setItem() {},
    removeItem() {},
  };

  const fetchStub = (url) => {
    const callIndex = fetchCalls.length;
    fetchCalls.push(url);
    const rule = opts.respond
      ? opts.respond(url, callIndex)
      : (opts.responses || []).find((r) => r.test.test(url));
    if (!rule) throw new Error('unexpected status request: ' + url);
    return Promise.resolve({
      ok: rule.status >= 200 && rule.status < 300,
      status: rule.status,
      json: () => Promise.resolve(rule.body),
    });
  };

  const documentStub = {
    getElementById: (id) => getEl(id),
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener() {},
    hidden: false,
  };

  const windowStub = {
    location: { search: opts.search || '', href: '' },
    localStorage: localStorageStub,
    sessionStorage: sessionStorageStub,
    document: documentStub,
    addEventListener() {},
    removeEventListener() {},
  };

  const sandbox = {
    window: windowStub,
    document: documentStub,
    localStorage: localStorageStub,
    sessionStorage: sessionStorageStub,
    URLSearchParams,
    URL,
    fetch: fetchStub,
    console: { log() {}, warn() {}, error() {} },
    // Polling / countdown timers are recorded, never scheduled: the tests
    // assert on the request order and drive a poll by hand.
    setTimeout: (fn, ms) => { timeouts.push({ fn, ms }); return timeouts.length; },
    clearTimeout() {},
    setInterval: () => 0,
    clearInterval() {},
  };
  vm.createContext(sandbox);

  vm.runInContext(CONFIG_JS, sandbox, { filename: 'config/config.js' });
  vm.runInContext(STATUS_JS, sandbox, { filename: 'status.html (inline)' });

  return {
    els,
    getEl,
    fetchCalls,
    storage,
    window: windowStub,
    /** Let the pending promise chains settle. */
    flush: () => new Promise((resolve) => setTimeout(resolve, 0)),
    /** Run the most recently scheduled poll, as the 30 s interval would. */
    runPoll: () => {
      const timer = timeouts.pop();
      if (!timer || typeof timer.fn !== 'function') throw new Error('no poll was scheduled');
      timer.fn();
    },
  };
}

const MISSING_CONTEXT = {
  test: /\/api\/session\/status$/,
  status: 502,
  body: {
    success: false,
    code: 'MISSING_PORTAL_CONTEXT',
    error: 'Open the Wi-Fi portal page once so this device can be identified, then tap Refresh.',
  },
};

const ACTIVE_SESSION = {
  test: /[?&]mac=/,
  status: 200,
  body: {
    success: true,
    sessionId: SESSION_ID,
    clientMac: MAC,
    state: 'active',
    remainingSeconds: 125,
    startedAt: '2026-10-26T10:00:00.000Z',
    expiresAt: '2026-10-26T10:30:00.000Z',
    voucherType: 'standard',
  },
};

// ── Tests ───────────────────────────────────────────────────────

describe('status.html — cloud-tunnel fallback to the saved device MAC', () => {
  test('MISSING_PORTAL_CONTEXT immediately retries with ?mac=<device_mac>', async () => {
    const status = loadStatus({
      search: '',
      storage: new Map([['device_mac', MAC]]),
      responses: [MISSING_CONTEXT, ACTIVE_SESSION],
    });

    await status.flush();
    await status.flush();

    // 1) address-based lookup, 2) saved-MAC fallback.
    expect(status.fetchCalls).toHaveLength(2);
    expect(status.fetchCalls[0]).toMatch(/\/api\/session\/status$/);
    expect(status.fetchCalls[1]).toBe('/api/session/status?mac=' + encodeURIComponent(MAC));

    // The active session is rendered, not the "could not identify" screen.
    expect(status.getEl('session-active').classList.contains('hidden')).toBe(false);
    expect(status.getEl('countdown-time-display').textContent).toBe('02:05');
    expect(status.getEl('unknown-message').textContent).toBe('');
  });

  test('the dash-separated value saved by another page is canonicalized before use', async () => {
    const status = loadStatus({
      search: '',
      storage: new Map([['device_mac', 'aa-bb-cc-dd-ee-ff']]),
      responses: [MISSING_CONTEXT, ACTIVE_SESSION],
    });

    await status.flush();
    await status.flush();

    expect(status.fetchCalls[1]).toBe('/api/session/status?mac=' + encodeURIComponent(MAC));
  });

  test('the older portalClientMac key is still honoured', async () => {
    const status = loadStatus({
      search: '',
      storage: new Map([['portalClientMac', MAC]]),
      responses: [MISSING_CONTEXT, ACTIVE_SESSION],
    });

    await status.flush();
    await status.flush();

    expect(status.fetchCalls[1]).toBe('/api/session/status?mac=' + encodeURIComponent(MAC));
    expect(status.getEl('session-active').classList.contains('hidden')).toBe(false);
  });

  test('falls back to a stored session id when no MAC is saved', async () => {
    const status = loadStatus({
      search: '',
      storage: new Map([['portalSessionId', SESSION_ID]]),
      responses: [
        MISSING_CONTEXT,
        {
          test: /[?&]sessionId=/,
          status: 200,
          body: {
            success: true,
            sessionId: SESSION_ID,
            clientMac: MAC,
            state: 'expired',
            remainingSeconds: 0,
            expiresAt: '2026-10-26T10:00:00.000Z',
            voucherType: 'standard',
          },
        },
      ],
    });

    await status.flush();
    await status.flush();

    expect(status.fetchCalls).toHaveLength(2);
    expect(status.fetchCalls[1]).toBe(
      '/api/session/status?sessionId=' + encodeURIComponent(SESSION_ID)
    );
    expect(status.getEl('session-expired').classList.contains('hidden')).toBe(false);
  });

  test('with nothing saved it asks the guest to open the portal page once', async () => {
    const status = loadStatus({ search: '', responses: [MISSING_CONTEXT] });

    await status.flush();
    await status.flush();

    expect(status.fetchCalls).toHaveLength(1);
    expect(status.getEl('session-unknown').classList.contains('hidden')).toBe(false);
    expect(status.getEl('unknown-message').textContent).toBe(MISSING_CONTEXT_MESSAGE);
  });

  test('a successful fallback is pinned: later polls skip the IP request entirely', async () => {
    const status = loadStatus({
      search: '',
      storage: new Map([['device_mac', MAC]]),
      responses: [MISSING_CONTEXT, ACTIVE_SESSION],
    });

    await status.flush();
    await status.flush();
    expect(status.fetchCalls).toHaveLength(2);

    // The next 30 s poll goes straight to the query that works.
    status.runPoll();
    await status.flush();
    await status.flush();

    expect(status.fetchCalls).toHaveLength(3);
    expect(status.fetchCalls[2]).toBe('/api/session/status?mac=' + encodeURIComponent(MAC));

    // And keeps doing so.
    status.runPoll();
    await status.flush();
    await status.flush();

    expect(status.fetchCalls).toHaveLength(4);
    expect(status.fetchCalls[3]).toBe('/api/session/status?mac=' + encodeURIComponent(MAC));
  });

  test('a pinned query that stops matching falls back to the next identifier, then re-pins', async () => {
    let macHits = 0;
    const status = loadStatus({
      search: '',
      storage: new Map([['device_mac', MAC], ['portalSessionId', SESSION_ID]]),
      respond: (url) => {
        if (/[?&]mac=/.test(url)) {
          macHits += 1;
          // First poll: the MAC answers. Afterwards the plan ended, so it no
          // longer resolves and the stored session id has to report "expired".
          return macHits === 1
            ? { status: 200, body: ACTIVE_SESSION.body }
            : {
                status: 404,
                body: { success: false, code: 'SESSION_NOT_FOUND', error: 'No active session exists for this device.' },
              };
        }
        if (/[?&]sessionId=/.test(url)) {
          return {
            status: 200,
            body: { ...ACTIVE_SESSION.body, state: 'expired', remainingSeconds: 0 },
          };
        }
        return MISSING_CONTEXT;
      },
    });

    await status.flush();
    await status.flush();
    expect(status.fetchCalls[0]).toMatch(/\/api\/session\/status$/);
    expect(status.fetchCalls[1]).toBe('/api/session/status?mac=' + encodeURIComponent(MAC));

    // Pinned ?mac= now 404s: the page advances to the stored session id and
    // renders the expired state.
    status.runPoll();
    await status.flush();
    await status.flush();

    expect(status.fetchCalls[2]).toBe('/api/session/status?mac=' + encodeURIComponent(MAC));
    expect(status.fetchCalls[3]).toBe(
      '/api/session/status?sessionId=' + encodeURIComponent(SESSION_ID)
    );
    expect(status.getEl('session-expired').classList.contains('hidden')).toBe(false);

    // The session-id query is now the pinned one.
    status.runPoll();
    await status.flush();
    await status.flush();

    expect(status.fetchCalls[4]).toBe(
      '/api/session/status?sessionId=' + encodeURIComponent(SESSION_ID)
    );
  });

  test('a poll resolved by address stores the MAC as device_mac for the next visit', async () => {
    const status = loadStatus({
      search: '',
      responses: [{ test: /\/api\/session\/status$/, status: 200, body: ACTIVE_SESSION.body }],
    });

    await status.flush();
    await status.flush();

    // Nothing in the URL or storage identified the device, so these values can
    // only come from the response rendered above — and they are what the tunnel
    // fallback will use on the next visit.
    expect(status.storage.get('device_mac')).toBe(MAC);
    expect(status.storage.get('portalSessionId')).toBe(SESSION_ID);
  });
});

// ── Hard expiry rendering ───────────────────────────────────────

const HARD_DEADLINE = '2026-10-29T15:45:00.000Z';

const PAUSED_PREMIUM = {
  test: /[?&]mac=/,
  status: 200,
  body: {
    success: true,
    sessionId: SESSION_ID,
    clientMac: MAC,
    state: 'paused',
    remainingSeconds: 5400,
    startedAt: '2026-10-26T10:00:00.000Z',
    expiresAt: null,
    absoluteExpiresAt: HARD_DEADLINE,
    absolute_expires_at: HARD_DEADLINE,
    voucherType: 'premium',
  },
};

const HARD_EXPIRED = {
  test: /[?&]mac=/,
  status: 200,
  body: {
    success: true,
    sessionId: SESSION_ID,
    clientMac: MAC,
    state: 'expired',
    remainingSeconds: 0,
    startedAt: '2026-10-26T10:00:00.000Z',
    expiresAt: null,
    absoluteExpiresAt: HARD_DEADLINE,
    absolute_expires_at: HARD_DEADLINE,
    voucherType: 'premium',
    expireReason: 'hard_expired',
    expire_reason: 'hard_expired',
  },
};

describe('status.html — Premium hard expiry notice and expired screen', () => {
  test('the paused view shows the absolute deadline too', async () => {
    const status = loadStatus({
      search: '',
      storage: new Map([['device_mac', MAC]]),
      responses: [MISSING_CONTEXT, PAUSED_PREMIUM],
    });

    await status.flush();
    await status.flush();

    expect(status.getEl('session-paused').classList.contains('hidden')).toBe(false);
    const notice = status.getEl('paused-hard-expiry-notice');
    expect(notice.classList.contains('hidden')).toBe(false);
    expect(notice.textContent).toContain('Pass expires completely on');
  });

  test('a Standard session hides both notices', async () => {
    // Standard sessions carry no hard deadline at all, so neither notice shows.
    const status = loadStatus({
      search: '',
      responses: [{ test: /\/api\/session\/status$/, status: 200, body: ACTIVE_SESSION.body }],
    });

    await status.flush();
    await status.flush();

    expect(status.getEl('hard-expiry-notice').classList.contains('hidden')).toBe(true);
    expect(status.getEl('paused-hard-expiry-notice').classList.contains('hidden')).toBe(true);
  });

  test('a hard-expired pass renders its own screen with the deadline', async () => {
    const status = loadStatus({
      search: '',
      storage: new Map([['device_mac', MAC]]),
      responses: [MISSING_CONTEXT, HARD_EXPIRED],
    });

    await status.flush();
    await status.flush();

    expect(status.getEl('session-expired').classList.contains('hidden')).toBe(false);
    expect(status.getEl('session-unknown').classList.contains('hidden')).toBe(true);
    expect(status.getEl('expired-heading').textContent).toBe('Your Pass Has Expired');
    expect(status.getEl('expired-message').textContent).toContain('absolute expiry');
    const stamp = status.getEl('expired-timestamp');
    expect(stamp.classList.contains('hidden')).toBe(false);
    expect(stamp.textContent).toContain('Pass expired on');
  });

  test('a normally expired session keeps the generic copy and shows its expires_at', async () => {
    const status = loadStatus({
      search: '',
      storage: new Map([['device_mac', MAC]]),
      responses: [MISSING_CONTEXT, {
        test: /[?&]mac=/,
        status: 200,
        body: {
          ...ACTIVE_SESSION.body,
          state: 'expired',
          remainingSeconds: 0,
          expireReason: 'time_expired',
          expire_reason: 'time_expired',
        },
      }],
    });

    await status.flush();
    await status.flush();

    expect(status.getEl('session-expired').classList.contains('hidden')).toBe(false);
    expect(status.getEl('expired-heading').textContent).toBe('Session Expired');
    expect(status.getEl('expired-message').textContent).toContain('Your WiFi session has ended');
    expect(status.getEl('expired-timestamp').textContent).toContain('Session expired on');
  });
});
