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
 *   - the reference-number + mobile-number form (Claim Voucher) POSTs
 *     ref_suffix + mobile_number, plus client_mac + ap_mac (read from
 *     localStorage), to /api/payment/claim
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
    /** Test helper: invoke every handler registered for `type`. */
    fire(type, event) { (listeners[type] || []).forEach((fn) => fn(event || {})); },
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
 * @param {boolean} [opts.captureTimers] record window.setTimeout calls instead
 *   of scheduling them, so a test can drive a delayed hand-off (the 3 s
 *   success-page redirect) without waiting for it
 * @returns {Object} { els, fetchCalls, storage, flush, timers }
 */
function loadPortal(opts) {
  const storage = opts.storage || new Map();
  const fetchCalls = [];
  const timers = [];
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
    // opts.fetchJson lets a test drive a specific backend response shape
    // (authorized:true vs voucherCode-only vs failure).
    const payload = (opts.fetchJson && opts.fetchJson(url)) || { success: true };
    return Promise.resolve({
      ok: opts.fetchOk === undefined ? true : opts.fetchOk,
      status: opts.fetchStatus || 200,
      json: () => Promise.resolve(payload),
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
    setTimeout: (fn, ms) => {
      if (opts.captureTimers) { timers.push({ fn, ms }); return 0; }
      return setTimeout(fn, ms);
    },
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
    timers,
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
  test('POSTs ref_suffix + mobile_number + client_mac + ap_mac read from localStorage', async () => {
    const storage = new Map([
      ['portalClientMac', CONTEXT.clientMac],
      ['portalApMac', CONTEXT.apMac],
      ['portalSsidName', CONTEXT.ssidName],
    ]);

    // Bare URL: exactly the refresh / re-opened-tab case, where the device
    // identity can only come from storage.
    const portal = loadPortal({ search: '', storage });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    const body = claimBody(portal);
    expect(body).toBeTruthy();
    expect(body).toEqual({
      ref_suffix: '1234',
      mobile_number: '09171234567',
      client_mac: CONTEXT.clientMac,
      ap_mac: CONTEXT.apMac,
    });
  });

  test('sends the MAC saved by a previous claim (device_mac) on a bare URL', async () => {
    // Only device_mac exists — the key a successful MAC-direct claim writes.
    // The voucher form must still identify the device explicitly, otherwise the
    // backend (seeing only the tunnel's public address) cannot authorize it.
    const storage = new Map([['device_mac', 'aa-bb-cc-dd-ee-ff']]);
    const portal = loadPortal({ search: '', storage });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    expect(claimBody(portal).client_mac).toBe(CONTEXT.clientMac);
  });

  test('omits the device fields when no context is known (never sends junk)', async () => {
    const portal = loadPortal({ search: '' });

    portal.getEl('claim-ref-input').value = '9999';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    expect(claimBody(portal)).toEqual({ ref_suffix: '9999', mobile_number: '09171234567' });
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

  test('a missing or malformed mobile number is rejected client-side (no request at all)', async () => {
    const portal = loadPortal({ search: REDIRECT_SEARCH });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-verify').onclick();
    await portal.flush();

    // Empty field: nothing is sent, and the mobile field reports the error.
    expect(claimBody(portal)).toBeNull();
    expect(portal.getEl('claim-mobile-error').textContent)
      .toBe('Enter your 11-digit mobile number (e.g. 09171234567).');

    // 10 digits: too short.
    portal.getEl('claim-mobile-input').value = '0917123456';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    expect(claimBody(portal)).toBeNull();

    // 11 digits, but not a 09 number.
    portal.getEl('claim-mobile-input').value = '99171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    expect(claimBody(portal)).toBeNull();
  });

  test('normalizes a spaced / dashed mobile number before sending', async () => {
    const portal = loadPortal({ search: '' });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '0917-123 4567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    expect(claimBody(portal).mobile_number).toBe('09171234567');
  });

  test('the voucher form POSTs clientMac explicitly, even from a bare URL + saved device_mac', async () => {
    // The cloud tunnel makes the backend's req.ip the tunnel address, so the
    // explicit clientMac in the body is what identifies the device. Here the
    // only identity is the MAC a previous claim saved.
    const storage = new Map([['device_mac', 'aa:bb:cc:dd:ee:ff']]);
    const portal = loadPortal({ search: '', storage });

    portal.getEl('voucher-input').value = '123456';
    portal.getEl('terms-checkbox').checked = true;
    portal.getEl('sel:form.auth-form').fire('submit', { preventDefault() {} });
    await portal.flush();
    await portal.flush();

    const call = portal.fetchCalls.find((c) => c.url.indexOf('/api/auth') !== -1);
    expect(call).toBeTruthy();
    expect(call.body.clientMac).toBe(CONTEXT.clientMac);
    expect(call.body.voucher).toBe('123456');
    // ... and the successful login persists it for status.html as well.
    expect(portal.storage.get('device_mac')).toBe(CONTEXT.clientMac);
  });

  test('a fresh controller redirect still wins over a stale device_mac', async () => {
    const storage = new Map([['device_mac', '11:22:33:44:55:66']]);
    const portal = loadPortal({ search: REDIRECT_SEARCH, storage });

    portal.getEl('voucher-input').value = '123456';
    portal.getEl('terms-checkbox').checked = true;
    portal.getEl('sel:form.auth-form').fire('submit', { preventDefault() {} });
    await portal.flush();
    await portal.flush();

    const call = portal.fetchCalls.find((c) => c.url.indexOf('/api/auth') !== -1);
    expect(call.body.clientMac).toBe(CONTEXT.clientMac);
  });

  test('pasting a full reference number keeps only its last 4 digits', () => {
    const portal = loadPortal({ search: '' });
    const input = portal.getEl('claim-ref-input');
    let prevented = false;

    input.fire('paste', {
      target: input,
      clipboardData: { getData: () => 'GCash Ref 2026-0917-1234' },
      preventDefault: () => { prevented = true; },
    });

    expect(prevented).toBe(true);
    expect(input.value).toBe('1234');
  });

  test('pasting fewer than 4 digits keeps the stripped value as-is', () => {
    const portal = loadPortal({ search: '' });
    const input = portal.getEl('claim-ref-input');

    input.fire('paste', {
      target: input,
      clipboardData: { getData: () => '1a2' },
      preventDefault: () => {},
    });

    expect(input.value).toBe('12');
  });

  test('pasting clears a lingering reference error', () => {
    const portal = loadPortal({ search: '' });
    const input = portal.getEl('claim-ref-input');
    const errEl = portal.getEl('claim-input-error');

    // Trigger the validation error first: fewer than 4 digits, no mobile.
    input.value = '12';
    portal.getEl('claim-verify').onclick();
    expect(errEl.textContent).toBe('Enter the last 4 digits of your reference number.');

    input.fire('paste', {
      target: input,
      clipboardData: { getData: () => '99887766' },
      preventDefault: () => {},
    });

    expect(input.value).toBe('7766');
    expect(errEl.textContent).toBe('');
  });

  test('an authorized response shows the auto-authorized state, not a voucher code', async () => {
    const portal = loadPortal({
      search: '',
      fetchJson: () => ({ success: true, authorized: true, message: 'Device authorized' }),
    });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    // The only action left is dismissal ("Done"), and NO code is rendered.
    expect(portal.getEl('claim-cancel').textContent).toBe('Done');
    expect(portal.getEl('claim-voucher-code').textContent).toBe('');
  });

  test('the auto-authorized state waits 4 s before handing the guest to status.html', async () => {
    const portal = loadPortal({
      search: '',
      captureTimers: true,
      fetchJson: () => ({ success: true, authorized: true }),
    });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    // 3–4 s of headroom for the controller to finish programming the MAC, so
    // status.html's first request does not fail with no connection yet.
    const redirect = portal.timers.find((t) => t.ms === 4000);
    expect(redirect).toBeTruthy();

    redirect.fn();
    // success.html is skipped: a cached copy of it in the captive WebView is
    // what used to lose the MAC before it reached the status page.
    expect(portal.window.location.href).toBe('status.html');
  });

  test('clicking Done in the auto-authorized state goes to status.html immediately', async () => {
    const portal = loadPortal({
      search: '',
      fetchJson: () => ({ success: true, authorized: true }),
    });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    portal.getEl('claim-cancel').onclick();
    expect(portal.window.location.href).toBe('status.html');
  });

  test('the auto-authorized hand-off carries the claimed MAC to status.html', async () => {
    // The MAC must ride in the URL: the captive WebView can drop localStorage
    // between navigations, and status.html reads ?mac= before storage / IP lookup.
    const portal = loadPortal({
      search: REDIRECT_SEARCH,
      captureTimers: true,
      fetchJson: () => ({ success: true, authorized: true }),
    });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    portal.timers.find((t) => t.ms === 4000).fn();
    expect(portal.window.location.href).toBe(
      'status.html?mac=aa%3Abb%3Acc%3Add%3Aee%3Aff'
    );
  });

  test('Cancel outside the authorized state still just dismisses the modal', async () => {
    const portal = loadPortal({
      search: '',
      fetchJson: () => ({ success: true, voucherCode: '777777' }),
    });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    expect(portal.getEl('claim-cancel').textContent).toBe('Cancel');
    portal.getEl('claim-cancel').onclick();
    expect(portal.window.location.href).toBe('');
  });

  test('a successful claim saves the device MAC for status.html (device_mac)', async () => {
    // The portal is reached through a cloud tunnel, so status.html cannot be
    // identified by its request address; the claimed MAC saved here is what its
    // MISSING_PORTAL_CONTEXT fallback queries with.
    const storage = new Map([['portalClientMac', 'aa-bb-cc-dd-ee-ff']]);
    const portal = loadPortal({
      search: '',
      storage,
      fetchJson: () => ({ success: true, authorized: true, message: 'Device authorized' }),
    });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    // Canonical form, not the dashed value that was stored before the claim.
    expect(portal.storage.get('device_mac')).toBe(CONTEXT.clientMac);
    expect(portal.storage.get('portalClientMac')).toBe(CONTEXT.clientMac);
  });

  test('a voucherCode-only claim saves the device MAC as well', async () => {
    const portal = loadPortal({
      search: REDIRECT_SEARCH,
      fetchJson: () => ({ success: true, authorized: false, voucherCode: '777777' }),
    });

    expect(portal.storage.has('device_mac')).toBe(false);

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    expect(portal.storage.get('device_mac')).toBe(CONTEXT.clientMac);
  });

  test('a failed claim saves nothing (no stale device MAC is left behind)', async () => {
    const portal = loadPortal({
      search: REDIRECT_SEARCH,
      fetchOk: false,
      fetchStatus: 404,
      fetchJson: () => ({ success: false, code: 'PAYMENT_NOT_FOUND', error: 'Payment not found or already claimed.' }),
    });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    expect(portal.storage.has('device_mac')).toBe(false);
  });

  test('a voucherCode-only response still falls back to the manual code flow', async () => {
    // The backend replies this way when it could not auto-authorize the device
    // (no MAC context, or Omada refused), so the guest must still get the code.
    const portal = loadPortal({
      search: '',
      fetchJson: () => ({ success: true, voucherCode: '777777' }),
    });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-verify').onclick();
    await portal.flush();
    await portal.flush();

    expect(portal.getEl('claim-voucher-code').textContent).toBe('777777');
    expect(portal.getEl('claim-cancel').textContent).toBe('Cancel');
  });

  test('opening the modal clears the previous mobile number and its error', async () => {
    const portal = loadPortal({ search: REDIRECT_SEARCH });

    portal.getEl('claim-ref-input').value = '1234';
    portal.getEl('claim-mobile-input').value = '09171234567';
    portal.getEl('claim-mobile-input').disabled = true;
    portal.getEl('claim-mobile-error').textContent = 'stale error';

    // Portal-screen CTA -> openClaimModal() -> resetClaimModal().
    portal.getEl('claim-voucher-btn').fire('click');

    expect(portal.getEl('claim-mobile-input').value).toBe('');
    expect(portal.getEl('claim-mobile-input').disabled).toBe(false);
    expect(portal.getEl('claim-mobile-error').textContent).toBe('');
    // The reference field keeps its existing reset behaviour.
    expect(portal.getEl('claim-ref-input').value).toBe('');

    // Let resetClaimModal's focus timeout settle so no timer leaks.
    await new Promise((resolve) => setTimeout(resolve, 80));
  });
});
