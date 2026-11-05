/**
 * __tests__/guide-modal.test.js
 *
 * Locks in the visibility contract of index.html's "How to Connect" guide:
 *
 *   - it AUTO-OPENS on the first visit from a browser;
 *   - it records the dismissal in localStorage under `gv_guide_seen`, so a
 *     RETURNING guest is not shown the guide again — not on a reload, not in a
 *     new tab, not after closing the browser;
 *   - if localStorage is unavailable (captive-portal WebViews, private mode)
 *     the guide still opens instead of breaking the portal;
 *   - and the close paths (X, dark overlay, Escape) still work.
 *
 * There is no explicit "Need help connecting?" trigger any more: the guide is
 * the onboarding step, not an optional help link, so this suite asserts the
 * button is gone from the markup.
 *
 * Harness: same shape as status-fallback.test.js / status-polling.test.js — the
 * REAL inline script is read out of index.html and executed in a vm context
 * with a minimal DOM stub, so the assertions run against shipped code and none
 * of it is re-implemented here. jsdom is deliberately not used: it is not a
 * dependency of this package (it resolves only from a parent node_modules on a
 * developer machine), so a jsdom-based test would fail on a bare `npm ci`.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..', '..');
const INDEX_HTML = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');

/** Every inline <script> body in index.html (external scripts are skipped). */
function inlineScripts(html) {
  const blocks = [];
  const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let match;
  while ((match = re.exec(html)) !== null) blocks.push(match[1]);
  return blocks;
}

/** The guide's own IIFE — found by its header, so a rename fails loudly here. */
const GUIDE_JS = (() => {
  const found = inlineScripts(INDEX_HTML)
    .find((script) => script.indexOf('HOW TO CONNECT GUIDE MODAL') !== -1);
  if (!found) throw new Error('index.html: the How to Connect guide script was not found');
  return found;
})();

const GUIDE_SEEN_KEY = 'gv_guide_seen';

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
  };
}

function createElement(id) {
  const listeners = {};
  const attributes = {};
  return {
    id,
    listeners,
    attributes,
    classList: makeClassList(),
    focused: false,
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(attributes, name) ? attributes[name] : null;
    },
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    removeEventListener(type, fn) {
      if (!listeners[type]) return;
      listeners[type] = listeners[type].filter((handler) => handler !== fn);
    },
    /** Test helper: invoke every handler registered for `type`. */
    fire(type, event) {
      (listeners[type] || []).slice().forEach((fn) => fn(event || { preventDefault() {} }));
    },
    focus() { this.focused = true; },
    blur() { this.focused = false; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
  };
}

/**
 * Map-backed localStorage. It outlives any single page load, which is exactly
 * the property under test: a "returning guest" is a second load sharing it.
 */
function makeLocalStorage(seed) {
  const data = new Map(Object.entries(seed || {}));
  return {
    data,
    getItem(key) { return data.has(key) ? data.get(key) : null; },
    setItem(key, value) { data.set(key, String(value)); },
    removeItem(key) { data.delete(key); },
  };
}

/** Stand-in for private mode / storage disabled in a captive-portal WebView. */
function throwingLocalStorage() {
  const boom = () => { throw new Error('SecurityError: localStorage disabled'); };
  return { getItem: boom, setItem: boom, removeItem: boom };
}

/**
 * Load the real guide script into a fresh context.
 *
 * @param {Object}  [opts]
 * @param {Object}  [opts.localStorage] storage to reuse (default: empty)
 * @param {string}  [opts.readyState] document.readyState seen by the script
 * @returns {Object} element handles, storage, and document-event drivers
 */
function loadPage(opts = {}) {
  const elements = new Map();
  const documentListeners = {};
  const getEl = (id) => {
    if (!elements.has(id)) elements.set(id, createElement(id));
    return elements.get(id);
  };

  const doc = {
    readyState: opts.readyState || 'complete',
    activeElement: createElement('active-element'),
    body: createElement('body'),
    documentElement: createElement('html'),
    getElementById: getEl,
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener(type, fn) {
      (documentListeners[type] = documentListeners[type] || []).push(fn);
    },
    removeEventListener() {},
  };

  const localStorage = opts.localStorage || makeLocalStorage();

  // Deliberately no sessionStorage in the context: the dismissal has to
  // survive a new tab, so the script must not be able to fall back to it.
  const context = {
    window: { document: doc, localStorage },
    document: doc,
    console: { warn() {}, log() {}, error() {} },
    setTimeout,
    clearTimeout,
  };
  vm.createContext(context);
  vm.runInContext(GUIDE_JS, context, { filename: 'index.html' });

  return {
    overlay: getEl('guide-modal'),
    closeBtn: getEl('guide-modal-close'),
    body: doc.body,
    localStorage,
    seenFlag: localStorage.data ? localStorage.data.get(GUIDE_SEEN_KEY) : undefined,
    /** Fire any DOMContentLoaded listeners the script registered. */
    fireDomContentLoaded() {
      (documentListeners.DOMContentLoaded || []).forEach((fn) => fn({}));
    },
    /** Fire a document-level keydown. */
    pressKey(key) {
      (documentListeners.keydown || []).forEach((fn) => fn({ key, preventDefault() {} }));
    },
    documentListeners,
  };
}

describe('How to Connect guide — auto-opens once per browser', () => {
  test('opens by itself on the first visit', () => {
    const page = loadPage();

    expect(page.overlay.classList.contains('is-open')).toBe(true);
    expect(page.overlay.getAttribute('aria-hidden')).toBe('false');
    expect(page.body.classList.contains('modal-open')).toBe(true);
    // Focus moves into the dialog (its close button) for keyboard users.
    expect(page.closeBtn.focused).toBe(true);
  });

  test('records the dismissal in localStorage under gv_guide_seen', () => {
    const page = loadPage();

    expect(page.localStorage.getItem(GUIDE_SEEN_KEY)).toBe('1');
    expect(GUIDE_JS).toContain('gv_guide_seen');
    expect(GUIDE_JS).toContain('localStorage');
  });

  test('does not fall back to sessionStorage', () => {
    // sessionStorage would reset in a new tab, which is the friction this
    // change removes — so the shipped script must not reference it at all.
    expect(GUIDE_JS).not.toMatch(/sessionStorage/);
  });

  test('does not open again for a returning guest (new browser session)', () => {
    // One store across both loads = the guest closes the browser and comes back.
    const localStorage = makeLocalStorage();

    const firstVisit = loadPage({ localStorage });
    expect(firstVisit.overlay.classList.contains('is-open')).toBe(true);
    firstVisit.closeBtn.fire('click');
    expect(firstVisit.overlay.classList.contains('is-open')).toBe(false);

    const returnVisit = loadPage({ localStorage });
    expect(returnVisit.overlay.classList.contains('is-open')).toBe(false);
    expect(returnVisit.body.classList.contains('modal-open')).toBe(false);
    expect(returnVisit.closeBtn.focused).toBe(false);
    // Still recorded, so every later visit stays quiet too.
    expect(localStorage.getItem(GUIDE_SEEN_KEY)).toBe('1');
  });

  test('stays dismissed even if the guest never closed it manually', () => {
    // The flag is written when the guide opens, not when it is dismissed, so a
    // guest who paid and navigated away is not shown it again.
    const localStorage = makeLocalStorage();

    const firstVisit = loadPage({ localStorage });
    expect(firstVisit.seenFlag).toBe('1');

    const returnVisit = loadPage({ localStorage });
    expect(returnVisit.overlay.classList.contains('is-open')).toBe(false);
  });

  test('waits for DOMContentLoaded when the parser is still running', () => {
    const page = loadPage({ readyState: 'loading' });

    // Not open yet: the dialog markup may not be parsed at this point.
    expect(page.overlay.classList.contains('is-open')).toBe(false);
    expect(page.documentListeners.DOMContentLoaded).toHaveLength(1);

    page.fireDomContentLoaded();

    expect(page.overlay.classList.contains('is-open')).toBe(true);
    expect(page.localStorage.getItem(GUIDE_SEEN_KEY)).toBe('1');
  });

  test('still opens when localStorage throws (private mode / WebView)', () => {
    const page = loadPage({ localStorage: throwingLocalStorage() });

    // Storage failure must not swallow the onboarding, and must not throw.
    expect(page.overlay.classList.contains('is-open')).toBe(true);
  });

  test('the close button dismisses it', () => {
    const page = loadPage();

    page.closeBtn.fire('click');

    expect(page.overlay.classList.contains('is-open')).toBe(false);
    expect(page.overlay.getAttribute('aria-hidden')).toBe('true');
    expect(page.body.classList.contains('modal-open')).toBe(false);
  });

  test('clicking the dark overlay closes it', () => {
    const page = loadPage();

    page.overlay.fire('click', { target: page.overlay });

    expect(page.overlay.classList.contains('is-open')).toBe(false);
  });

  test('Escape closes it, and is harmless once it is closed', () => {
    const page = loadPage();
    expect(page.overlay.classList.contains('is-open')).toBe(true);

    page.pressKey('Escape');
    expect(page.overlay.classList.contains('is-open')).toBe(false);

    // Closed: the handler must not reopen anything or throw.
    page.pressKey('Escape');
    expect(page.overlay.classList.contains('is-open')).toBe(false);
  });

  test('the markup has no manual "Need help connecting?" trigger', () => {
    expect(INDEX_HTML).toContain('id="guide-modal"');
    expect(INDEX_HTML).not.toContain('id="guide-open-btn"');
    expect(INDEX_HTML).not.toContain('Need help connecting?');
  });
});
