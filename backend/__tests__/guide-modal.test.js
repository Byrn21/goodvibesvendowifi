/**
 * __tests__/guide-modal.test.js
 *
 * Locks in the visibility contract of index.html's "How to Connect" guide:
 *
 *   - it does NOT open on page load, before or after DOMContentLoaded;
 *   - it opens ONLY from #guide-open-btn ("Need help connecting?");
 *   - and it still closes the way it always did (X, dark overlay, Escape).
 *
 * The behaviour lives in an inline <script> in index.html, which the portal.js
 * harness in portal-context.test.js cannot reach, so this is its own suite.
 *
 * Harness: same shape as status-fallback.test.js / status-polling.test.js — the
 * REAL inline script is read out of index.html and executed in a vm context
 * with a minimal DOM stub, so the assertions run against shipped code and none
 * of it is re-implemented here.
 *
 * jsdom is deliberately not used. It is not a dependency of this package (it
 * resolves only from a parent node_modules on a developer machine), so a
 * jsdom-based test would fail on a bare `npm ci`; the other UI suites are
 * written against these stubs for the same reason.
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
 * Load the real guide script into a fresh context.
 *
 * @param {Object} [opts]
 * @param {Object} [opts.sessionStorage] override (defaults to a stub that
 *   throws on ANY access: the guide must no longer consult a "seen" flag)
 * @returns {Object} element handles + document-event drivers
 */
function loadPage(opts = {}) {
  const elements = new Map();
  const documentListeners = {};
  const getEl = (id) => {
    if (!elements.has(id)) elements.set(id, createElement(id));
    return elements.get(id);
  };

  const doc = {
    readyState: 'complete',
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

  const sessionStorageStub = opts.sessionStorage || {
    getItem() { throw new Error('the guide must not read sessionStorage'); },
    setItem() { throw new Error('the guide must not write sessionStorage'); },
    removeItem() { throw new Error('the guide must not clear sessionStorage'); },
  };

  const context = {
    window: { document: doc, sessionStorage: sessionStorageStub },
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
    openBtn: getEl('guide-open-btn'),
    body: doc.body,
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

describe('How to Connect guide — manual trigger only', () => {
  test('is closed on page load, before and after DOMContentLoaded', () => {
    const page = loadPage();

    expect(page.overlay.classList.contains('is-open')).toBe(false);
    expect(page.body.classList.contains('modal-open')).toBe(false);

    // A re-introduced auto-open that hooks DOMContentLoaded would be caught here.
    page.fireDomContentLoaded();
    expect(page.overlay.classList.contains('is-open')).toBe(false);

    // Proof the IIFE ran to completion rather than bailing out early: the
    // trigger is wired, so the "closed" state above is real, not a no-op.
    expect(page.openBtn.listeners.click).toHaveLength(1);
    expect(page.closeBtn.listeners.click).toHaveLength(1);
  });

  test('reads no sessionStorage flag (no once-per-session behaviour remains)', () => {
    // The default stub throws on any access; reaching the assertions means the
    // script never touched storage, so it cannot gate on a "seen" flag.
    const page = loadPage();
    expect(page.overlay.classList.contains('is-open')).toBe(false);
    expect(GUIDE_JS).not.toMatch(/autoOpenGuide|gv_guide_seen|sessionStorage\.(get|set|remove)Item/);
  });

  test('opens when #guide-open-btn is clicked', () => {
    const page = loadPage();

    page.openBtn.fire('click');

    expect(page.overlay.classList.contains('is-open')).toBe(true);
    expect(page.overlay.getAttribute('aria-hidden')).toBe('false');
    expect(page.body.classList.contains('modal-open')).toBe(true);
    // Focus moves into the dialog (its close button) for keyboard users.
    expect(page.closeBtn.focused).toBe(true);
  });

  test('the close button dismisses it again', () => {
    const page = loadPage();
    page.openBtn.fire('click');

    page.closeBtn.fire('click');

    expect(page.overlay.classList.contains('is-open')).toBe(false);
    expect(page.overlay.getAttribute('aria-hidden')).toBe('true');
    expect(page.body.classList.contains('modal-open')).toBe(false);
  });

  test('clicking the dark overlay closes it', () => {
    const page = loadPage();
    page.openBtn.fire('click');

    page.overlay.fire('click', { target: page.overlay });

    expect(page.overlay.classList.contains('is-open')).toBe(false);
  });

  test('Escape closes it, and is harmless while it is already closed', () => {
    const page = loadPage();

    // Closed: the handler must not open anything or throw.
    page.pressKey('Escape');
    expect(page.overlay.classList.contains('is-open')).toBe(false);

    page.openBtn.fire('click');
    expect(page.overlay.classList.contains('is-open')).toBe(true);

    page.pressKey('Escape');
    expect(page.overlay.classList.contains('is-open')).toBe(false);
  });

  test('the markup ships the trigger that this script wires up', () => {
    expect(INDEX_HTML).toContain('id="guide-open-btn"');
    expect(INDEX_HTML).toContain('Need help connecting?');
    // The dialog itself is still present, so the link has something to open.
    expect(INDEX_HTML).toContain('id="guide-modal"');
    expect(INDEX_HTML).not.toContain('gv_guide_seen');
  });
});
