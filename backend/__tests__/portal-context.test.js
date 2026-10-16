/**
 * __tests__/portal-context.test.js
 * Drives the REAL frontend files — config/config.js and assets/portal.js — in a
 * minimal DOM stub (no jsdom dependency) to verify the captive-portal context
 * flow end to end:
 *
 *   - clientMac / apMac / ssidName are captured from the Omada redirect URL on
 *     page load and written to localStorage immediately
 *   - a refresh / re-opened tab (bare URL, no query string) restores them from
 *     localStorage, so the context beacon and the payment claim still carry the
 *     device identity
 *   - the reference-number form (Claim Voucher) POSTs client_mac + ap_mac to
 *     /api/payment/claim, read from localStorage
 *   - a fresh controller redirect wins over stale stored values
 *   - blocked storage (strict captive mini-browser / private mode) degrades to
 *     URL-only instead of breaking the page
 *
 * The stub only implements what portal.js touches; anything not provided here
 * surfaces as a thrown error rather than being silently skipped.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..', '..');
const CONFIG_JS = fs.readFileSync(path.join(ROOT, 'config', 'config.js'), 'utf8');
const PORTAL_JS = fs.readFileSync(path.join(ROOT, 'assets', 'portal.js'), 'utf8');

const CONTEXT = {
  clientMac: 'aa:bb:cc:dd:ee:ff',
  apMac: '11:22:33:44:55:66',
  ssidName: 'GoodVibesVendoWifi',
};
const REDIRECT_SEARCH =
  '?clientMac=aa%3Abb%3Acc%3Add%3Aee%3Aff' +
  '&apMac=11%3A22%3A33%3A44%3A55%3A66' +
  '&ssidName=GoodVibesVendoWifi&radioId=1&clientIp=10.0.0.5';

// ── Minimal DOM stub ────────────────────────────────────────────
function createElement(id) {
  const listeners = {};
  return {
    id,
    value: '',
    textContent: '',
    innerHTML: '',
    href: '',
    disabled: false,
    onclick: null,
    style: { setProperty() {}, removeProperty() {}, getPropertyValue() { return ''; } },
    dataset: {},
    classList: { add() {}, remove() {}, contains() { return false; }, toggle() {} },
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    removeEventListener() {},
    setAttribute() {},
    getAttribute() { return null; },
    removeAttribute() {},
    appendChild() {},
    removeChild() {},
    insertAdjacentHTML() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
    closest() { return null; },
    focus() {},
    blur() {},
    click() {},
  };
}

/**
 * Load config/config.js + assets/portal.js into a fresh context.
 *
 * @param {Object} opts
 * @param {string} opts.search  window.location.search for this load
 * @param {Function} [opts.getStored]  localStorage.getItem (defaults to the map)
 * @param {Function} [opts.setStored]  localStorage.setItem
 * @returns {Object} { els, fetchCalls, storage, flush }
 */
function loadPortal(opts) {
  const storage = opts.storage || new Map();
  const fetchCalls = [];
  const els = new Map();
  const getEl = (id) => {
    if (!els.has(id)) els.set(id, createElement(id));
    return els.get(id);
  };

  const documentStub = {
    getElementById: (id) => getEl(id),
    querySelector: (sel) => getEl('sel:' + sel),
    querySelectorAll: () => [],
    addEventListener() {},
    createElement: (tag) => createElement(tag),
    body: createElement('body'),
    documentElement: createElement('html'),
  };

  const localStorageStub = opts.blockStorage
    ? {
        getItem() { throw new Error('storage blocked'); },
        setItem() { throw new Error('storage blocked'); },
        removeItem() { throw new Error('storage blocked'); },
      }
    : {
        getItem: (k) => (storage.has(k) ? storage.get(k) : null),
        setItem: (k, v) => storage.set(k, String(v)),
        removeItem: (k) => storage.delete(k),
      };

  const fetchStub = (url, init) => {
    fetchCalls.push({ url, init, body: init && init.body ? JSON.parse(init.body) : null });
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ success: true }),
    });
  };

  // portal.js also reads sessionStorage (connection-instruction handoff).
  const sessionStorageStub = {
    getItem: () => null,
    setItem() {},
    removeItem() {},
  };

  const windowStub = {
    location: { search: opts.search, href: '' },
    localStorage: localStorageStub,
    sessionStorage: sessionStorageStub,
    document: documentStub,
    navigator: { userAgent: 'jest' },
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (t) => clearTimeout(t),
    addEventListener() {},
    removeEventListener() {},
  };

  const sandbox = {
    window: windowStub,
    document: documentStub,
    navigator: windowStub.navigator,
    fetch: fetchStub,
    localStorage: localStorageStub,
    sessionStorage: sessionStorageStub,
    URLSearchParams,
    URL,
    console: { log() {}, warn() {}, error() {} },
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (t) => clearTimeout(t),
    setInterval: (fn, ms) => setInterval(fn, ms),
    clearInterval: (t) => clearInterval(t),
  };
  vm.createContext(sandbox);

  // config/config.js assigns window.CONFIG; portal.js reads it at load.
  vm.runInContext(CONFIG_JS, sandbox, { filename: 'config/config.js' });
  vm.runInContext(PORTAL_JS, sandbox, { filename: 'assets/portal.js' });

  return {
    els,
    getEl,
    fetchCalls,
    storage,
    /** Let the pending promise chains settle. */
    flush: () => new Promise((resolve) => setTimeout(resolve, 0)),
    window: windowStub,
  };
}

/** The beacon body POSTed to /api/payment/context, if any. */
function beaconBody(portal) {
  const call = portal.fetchCalls.find((c) => c.url.indexOf('/api/payment/context') !== -1);
  return call ? call.body : null;
}

/** The body POSTed to /api/payment/claim, if any. */
function claimBody(portal) {
  const call = portal.fetchCalls.find((c) => c.url.indexOf('/api/payment/claim') !== -1);
  return call ? call.body : null;
}

// ── Tests ───────────────────────────────────────────────────────

describe('Omada redirect context — capture and persistence', () => {
  test('page load writes clientMac / apMac / ssidName to localStorage immediately', () => {
    const portal = loadPortal({ search: REDIRECT_SEARCH });

    expect(portal.storage.get('portalClientMac')).toBe(CONTEXT.clientMac);
    expect(portal.storage.get('portalApMac')).toBe(CONTEXT.apMac);
    expect(portal.storage.get('portalSsidName')).toBe(CONTEXT.ssidName);
  });

  test('the captured context reaches the backend (context beacon)', () => {
    const portal = loadPortal({ search: REDIRECT_SEARCH });
    const body = beaconBody(portal);

    expect(body).toBeTruthy();
    expect(body.client_mac).toBe(CONTEXT.clientMac);
    expect(body.ap_mac).toBe(CONTEXT.apMac);
    expect(body.ssid_name).toBe(CONTEXT.ssidName);
  });

  test('a refresh / re-opened tab (no query string) restores the context from localStorage', () => {
    // 1) First landing from the controller — writes storage.
    const first = loadPortal({ search: REDIRECT_SEARCH });
    expect(first.storage.get('portalClientMac')).toBe(CONTEXT.clientMac);

    // 2) Refresh: same localStorage, bare URL.
    const second = loadPortal({ search: '', storage: first.storage });
    const body = beaconBody(second);

    expect(body).toBeTruthy();
    expect(body.client_mac).toBe(CONTEXT.clientMac);
    expect(body.ap_mac).toBe(CONTEXT.apMac);
    expect(body.ssid_name).toBe(CONTEXT.ssidName);
  });

  test('a fresh controller redirect overrides stale stored values', () => {
    const storage = new Map([
      ['portalClientMac', 'aa:aa:aa:aa:aa:aa'],
      ['portalApMac', 'bb:bb:bb:bb:bb:bb'],
      ['portalSsidName', 'OldSSID'],
    ]);

    const portal = loadPortal({ search: REDIRECT_SEARCH, storage });

    expect(portal.storage.get('portalClientMac')).toBe(CONTEXT.clientMac);
    expect(portal.storage.get('portalApMac')).toBe(CONTEXT.apMac);
    expect(portal.storage.get('portalSsidName')).toBe(CONTEXT.ssidName);
  });

  test('blocked storage degrades to URL-only without breaking the page', () => {
    const portal = loadPortal({ search: REDIRECT_SEARCH, blockStorage: true });
    const body = beaconBody(portal);

    expect(body).toBeTruthy();
    expect(body.client_mac).toBe(CONTEXT.clientMac);
    expect(body.ap_mac).toBe(CONTEXT.apMac);
  });
});

describe('Claim Voucher (reference number) submission', () => {
  test('POSTs ref_suffix + client_mac + ap_mac read from localStorage', async () => {
    const storage = new Map([
      ['portalClientMac', CONTEXT.clientMac],
      ['portalApMac', CONTEXT.apMac],
      ['portalSsidName', CONTEXT.ssidName],
    ]);

    // Bare URL: exactly the refresh / re-opened-tab case, where the device
    // identity can only come from storage.
    const portal = loadPortal({ search: '', storage });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    const body = claimBody(portal);
    expect(body).toBeTruthy();
    expect(body).toEqual({
      ref_suffix: '1234',
      client_mac: CONTEXT.clientMac,
      ap_mac: CONTEXT.apMac,
    });
  });

  test('omits the device fields when no context is known (never sends junk)', async () => {
    const portal = loadPortal({ search: '' });

    portal.getEl('claim-ref-input').value = '9999';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    expect(claimBody(portal)).toEqual({ ref_suffix: '9999' });
  });

  test('a non-4-digit entry is rejected client-side (no request at all)', async () => {
    const portal = loadPortal({ search: REDIRECT_SEARCH });

    portal.getEl('claim-ref-input').value = '12';
    portal.getEl('claim-verify').onclick();
    await portal.flush();

    expect(claimBody(portal)).toBeNull();
    expect(portal.getEl('claim-input-error').textContent)
      .toBe('Enter the last 4 digits of your reference number.');
  });
});
