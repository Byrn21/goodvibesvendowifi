/**
 * __tests__/status-polling.test.js — regression test for status.html polling.
 *
 * status.html keeps its whole controller in one inline <script>, so it is not
 * reachable through require() and no existing test covers it. This harness
 * extracts that script and runs it inside a vm context with a stub DOM, stub
 * storage and a fake clock, so the polling behaviour itself can be asserted.
 *
 * The bug being locked down: a guest on mobile data with no token gets
 * 502 MISSING_PORTAL_CONTEXT from GET /api/session/status. The page painted the
 * mobile-data warning but left a timer armed, so it kept re-running the whole
 * identifier chain and spamming the backend. A CONFIRMED missing context must
 * leave the page completely idle — no poll timer, no network retry, no fetch on
 * returning to the tab — until Refresh is tapped. A generic 5xx must still
 * self-recover, because a tunnel restart is transient.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const STATUS_HTML = path.resolve(__dirname, '..', '..', 'status.html');

/**
 * extractPollingScript — the inline script that owns fetchStatus().
 *
 * External scripts (<script src=…>) are skipped; there is a second, unrelated
 * inline script (the support-email row), which is ignored because it does not
 * contain fetchStatus.
 *
 * @param {string} html
 * @returns {string} the polling IIFE source
 */
function extractPollingScript(html) {
  const blocks = [];
  const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let match;
  while ((match = re.exec(html)) !== null) blocks.push(match[1]);

  const script = blocks.find((block) => block.includes('function fetchStatus'));
  if (!script) throw new Error('status.html: the polling script was not found');
  return script;
}

/** Minimal element stand-in: classList, textContent, listeners, disabled. */
function createElement(id) {
  const classes = new Set();
  const listeners = {};
  return {
    id,
    textContent: '',
    disabled: false,
    style: {},
    classList: {
      add() {
        for (let i = 0; i < arguments.length; i += 1) classes.add(arguments[i]);
      },
      remove() {
        for (let i = 0; i < arguments.length; i += 1) classes.delete(arguments[i]);
      },
      contains: (name) => classes.has(name),
      toggle(name) {
        if (classes.has(name)) classes.delete(name);
        else classes.add(name);
      },
    },
    getAttribute: () => '',
    setAttribute: () => {},
    addEventListener(type, fn) {
      if (!listeners[type]) listeners[type] = [];
      listeners[type].push(fn);
    },
    click() {
      const handlers = listeners.click || [];
      handlers.forEach((fn) => fn({ preventDefault() {} }));
    },
  };
}

/** localStorage / sessionStorage stand-in, seeded with a plain object. */
function createStorage(seed) {
  const map = new Map(Object.entries(seed || {}).map(([k, v]) => [k, String(v)]));
  return {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => { map.set(key, String(value)); },
    removeItem: (key) => { map.delete(key); },
  };
}

/** Fake clock: records what the page scheduled so tests can inspect it. */
function createClock() {
  let nextId = 1;
  const timeouts = new Map();
  const intervals = new Map();
  return {
    setTimeout(fn, ms) {
      const id = nextId++;
      timeouts.set(id, { fn, ms: Number(ms) || 0 });
      return id;
    },
    clearTimeout(id) { timeouts.delete(id); },
    setInterval(fn, ms) {
      const id = nextId++;
      intervals.set(id, { fn, ms: Number(ms) || 0 });
      return id;
    },
    clearInterval(id) { intervals.delete(id); },
    pendingTimeouts: () => Array.from(timeouts.values()),
    pendingIntervals: () => Array.from(intervals.values()),
  };
}

/** Timers of this length or longer can only be a poll (POLL_INTERVAL 30 s). */
const POLL_TIMER_FLOOR_MS = 10000;

/**
 * loadStatusPage — run status.html's polling script against stubs.
 *
 * @param {Object} [options]
 * @param {Object} [options.storage]  seed for localStorage
 * @param {string} [options.search]   window.location.search
 * @param {Function} [options.respond] (url, callNumber) → { status, body }
 * @returns {Promise<Object>} page harness (flush, fireVisibility, click, …)
 */
async function loadStatusPage(options) {
  const opts = options || {};
  const clock = createClock();
  const elements = new Map();
  const documentListeners = {};
  const fetchCalls = [];

  const doc = {
    hidden: false,
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, createElement(id));
      return elements.get(id);
    },
    addEventListener(type, fn) {
      if (!documentListeners[type]) documentListeners[type] = [];
      documentListeners[type].push(fn);
    },
    querySelector: () => null,
  };

  const windowObject = {
    CONFIG: { statusPollingInterval: 30000 },
    location: { search: opts.search || '', href: '' },
    localStorage: createStorage(opts.storage),
    sessionStorage: createStorage({}),
  };

  const respond = opts.respond
    || (() => ({ status: 502, body: { success: false, code: 'MISSING_PORTAL_CONTEXT' } }));

  const fetchStub = (url) => {
    fetchCalls.push(String(url));
    const spec = respond(String(url), fetchCalls.length) || {};
    const status = Number(spec.status) || 200;
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(spec.body === undefined ? {} : spec.body),
    });
  };

  const context = {
    window: windowObject,
    document: doc,
    fetch: fetchStub,
    console: { warn() {}, log() {}, error() {} },
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
    setInterval: clock.setInterval,
    clearInterval: clock.clearInterval,
    URLSearchParams,
  };
  vm.createContext(context);
  vm.runInContext(extractPollingScript(fs.readFileSync(STATUS_HTML, 'utf8')), context, {
    filename: 'status.html',
  });

  const page = {
    clock,
    fetchCalls,
    elements,
    doc,
    /** Let the promise chain behind fetch() settle. */
    async flush() {
      for (let i = 0; i < 6; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    },
    fireVisibility(hidden) {
      doc.hidden = hidden;
      (documentListeners.visibilitychange || []).forEach((fn) => fn({}));
    },
    click(id) {
      const el = elements.get(id);
      if (!el) throw new Error('no such element in the page: ' + id);
      el.click();
    },
    /** Timeouts that can only be the status poll, not the button re-enable. */
    pollTimeouts: () => clock.pendingTimeouts().filter((t) => t.ms >= POLL_TIMER_FLOOR_MS),
  };

  await page.flush();
  return page;
}

describe('status.html polling halt (502 MISSING_PORTAL_CONTEXT)', () => {
  test('a confirmed missing context leaves no poll timer behind', async () => {
    const page = await loadStatusPage();

    expect(page.fetchCalls).toHaveLength(1);
    expect(page.pollTimeouts()).toHaveLength(0);
    expect(page.clock.pendingTimeouts()).toHaveLength(0);
    expect(page.clock.pendingIntervals()).toHaveLength(0);

    // The mobile-data warning is on screen, not the generic not-found copy.
    expect(page.elements.get('session-unknown').classList.contains('hidden')).toBe(false);
    expect(page.elements.get('unknown-message').textContent).toMatch(/mobile data/i);
  });

  test('returning to the tab does not restart the polling', async () => {
    const page = await loadStatusPage();
    const before = page.fetchCalls.length;

    page.fireVisibility(false);
    await page.flush();

    expect(page.fetchCalls).toHaveLength(before);
    expect(page.pollTimeouts()).toHaveLength(0);
  });

  test('the Refresh button makes exactly one manual request, then halts again', async () => {
    const page = await loadStatusPage();
    expect(page.fetchCalls).toHaveLength(1);

    page.click('btn-refresh-unknown');
    await page.flush();

    expect(page.fetchCalls).toHaveLength(2);
    // Only the 2 s button re-enable may remain — never a poll or retry timer.
    expect(page.pollTimeouts()).toHaveLength(0);

    page.fireVisibility(false);
    await page.flush();
    expect(page.fetchCalls).toHaveLength(2);
  });

  test('a stored token is tried once per chain, then the page halts', async () => {
    const page = await loadStatusPage({ storage: { portalStatusToken: 'stale-token' } });

    // ?token=… (rejected) then the identifier-less device lookup, and no more.
    expect(page.fetchCalls).toHaveLength(2);
    expect(page.fetchCalls[0]).toContain('?token=stale-token');
    expect(page.fetchCalls[1]).toMatch(/\/api\/session\/status$/);
    expect(page.pollTimeouts()).toHaveLength(0);
  });

  test('a generic 5xx still self-recovers (the retry path is unchanged)', async () => {
    const page = await loadStatusPage({
      respond: () => ({ status: 503, body: { error: 'tunnel restarting' } }),
    });

    expect(page.fetchCalls).toHaveLength(1);
    const pending = page.pollTimeouts();
    expect(pending).toHaveLength(1);

    pending[0].fn();
    await page.flush();
    expect(page.fetchCalls).toHaveLength(2);
  });

  test('a 502 without the MISSING_PORTAL_CONTEXT code is not halted', async () => {
    const page = await loadStatusPage({
      respond: () => ({ status: 502, body: { error: 'bad gateway' } }),
    });

    expect(page.pollTimeouts()).toHaveLength(1);
  });
});
