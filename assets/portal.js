/* =============================================================
   portal.js — Omada captive portal core logic
   =============================================================
   - Reads Omada-provided query parameters
   - Validates voucher/credential input
   - Submits auth to backend or direct controller endpoint
   - Handles success / error / network failure states
   - Applies theming from CONFIG
   ============================================================= */

(function () {
  'use strict';

  // ===============================================================
  // CONFIG — loaded from config/config.js on the window
  // ===============================================================
  var C = window.CONFIG || {};

  // Defaults for missing config properties
  var DEFAULTS = {
    mode: 'direct',               // 'direct' or 'backend'
    authEndpoint: '',
    authMethod: 'POST',           // 'POST' or 'POST_JSON'
    apiBaseUrl: '',
    voucher: {
      required: true,
      // RULE: exactly 6 numeric digits (matches backend/src/utils/voucher-code.js).
      minLength: 6,
      maxLength: 6,
      pattern: /^\d{6}$/,
      patternHint: 'Voucher code must be exactly 6 digits.',
    },
    allowedRedirectDomains: [],
    defaultRedirectUrl: '',
    termsRequired: false,
    termsUrl: '#terms',
    privacyUrl: '#privacy',
    statusPollingInterval: 30000,
    showPauseResume: true,
    brandName: 'WiFi Portal',
    brandTagline: 'Connect to the guest network',
    primaryColor: '#1a73e8',
    successPage: 'success.html',
    errorPage: 'error.html',
    statusPage: 'status.html',
    // Post-auth settling delay (ms) before the portal hands the browser over
    // to success.html. Omada applies the client's authorization rules
    // asynchronously AFTER it accepts the voucher; redirecting the phone
    // immediately makes its OS re-check internet access too early, conclude
    // the network is still captive, and close the captive mini-browser asking
    // the user to sign in again. Default 3.5s.
    connectDelayMs: 3500,
    // Omada controller context appended to the portal URL. Both the wireless
    // (EAP: clientMac/clientIp/apMac/ssidName/radioId) and wired (Gateway:
    // clientMac/clientIp/gatewayMac/vid) shapes are captured so the backend
    // can forward the exact set the controller expects for extPortal/auth.
    paramMap: {
      clientMac:   'clientMac',
      clientIp:    'clientIp',
      apMac:       'apMac',
      gatewayMac:  'gatewayMac',
      vid:         'vid',
      ssidName:    'ssidName',
      radioId:     'radioId',
      site:        'site',
      redirectUrl: 'redirectUrl',
      originalUrl: 'originalUrl',
      authUrl:     'authUrl',
      targetUrl:   'targetUrl',
    },
    // Left empty on purpose: the real address is injected into the page at
    // build time (see inject-secrets.js), so it is never committed here.
    supportEmail: '',
    supportPhone: '',
    mockMode: false,
    mockSuccessDelay: 800,
    pricingPlans: {
      standard: [],
      premium: [],
    },
  };

  // Merge config with defaults
  var CONFIG = {};
  for (var k in DEFAULTS) {
    if (DEFAULTS.hasOwnProperty(k)) {
      if (k === 'paramMap' || k === 'voucher') {
        CONFIG[k] = Object.assign({}, DEFAULTS[k], C[k] || {});
      } else {
        CONFIG[k] = (C[k] !== undefined) ? C[k] : DEFAULTS[k];
      }
    }
  }

  // ===============================================================
  // UTILITY
  // ===============================================================
  function $(id) { return document.getElementById(id); }

  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function show(el) { if (el) el.classList.remove('hidden'); }
  function hide(el) { if (el) el.classList.add('hidden'); }

  function setBanner(message, type) {
    var banner = $('status-banner');
    if (!banner) return;
    banner.textContent = message;
    banner.className = 'status-banner status-banner--' + (type || 'info');
    if (message) show(banner); else hide(banner);
  }

  function setError(inputId, msg) {
    var input = $(inputId);
    var errEl = $(inputId + '-error');
    if (input) {
      if (msg) { input.classList.add('is-error'); input.removeAttribute('aria-invalid'); input.setAttribute('aria-invalid', 'true'); }
      else     { input.classList.remove('is-error'); input.removeAttribute('aria-invalid'); }
    }
    if (errEl) {
      if (msg) { errEl.textContent = msg; show(errEl); }
      else     { errEl.textContent = '';  hide(errEl); }
    }
  }

  function setFormError(msg) {
    var box = $('form-error');
    if (!box) return;
    if (msg) { box.textContent = msg; show(box); }
    else     { box.textContent = '';  hide(box); }
  }

  // ===============================================================
  // MAC ADDRESS NORMALIZATION
  // ===============================================================
  function normalizeMac(mac) {
    if (!mac) return null;
    var cleaned = String(mac).replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    if (cleaned.length !== 12) return null;
    // Re-add colons
    return cleaned.match(/.{2}/g).join(':');
  }

  // ===============================================================
  // QUERY PARAMETER PARSING
  // ===============================================================
  var queryParams = {};
  function parseQueryParams() {
    var params = new URLSearchParams(window.location.search);
    var raw = {};
    params.forEach(function (val, key) {
      raw[key] = decodeURIComponent(val);
    });

    // Map Omada param names → our standard names
    var result = { raw: raw };
    var map = CONFIG.paramMap;
    for (var ourName in map) {
      if (map.hasOwnProperty(ourName)) {
        var theirName = map[ourName];
        if (raw[theirName] !== undefined) {
          result[ourName] = raw[theirName];
        }
      }
    }
    // Save raw for passthrough (e.g., controller tokens)
    queryParams = result;
    return result;
  }

  // ===============================================================
  // OMADA CONTEXT PERSISTENCE (localStorage)
  // ===============================================================
  // The controller appends its context (clientMac, apMac, ssidName, …) to the
  // portal URL on the FIRST redirect only. A page refresh, an accidentally
  // closed-and-reopened tab, or a return visit therefore lands on the bare
  // portal URL — and without clientMac + apMac + ssidName the backend cannot
  // rebuild the controller's extPortal/auth request for this device.
  //
  // RULE: the URL always wins (it is the freshest controller context); the
  // persisted copy fills whichever fields this page load is missing. Whatever
  // is resolved is written straight back, so the values survive refreshes and
  // are available to every later step — context beacon, voucher submission and
  // the payment claim.
  //
  // Keys match the names already used by success.html (`portalClientMac`) so a
  // hand-off between pages keeps reading the same values.
  var CONTEXT_STORAGE_KEYS = {
    clientMac: 'portalClientMac',
    apMac:     'portalApMac',
    ssidName:  'portalSsidName',
  };

  /**
   * getStoredContext — read the persisted Omada context.
   * Never throws: private mode / disabled storage degrades to URL-only.
   * @returns {Object} { clientMac?, apMac?, ssidName? }
   */
  function getStoredContext() {
    var stored = {};
    try {
      for (var name in CONTEXT_STORAGE_KEYS) {
        if (!CONTEXT_STORAGE_KEYS.hasOwnProperty(name)) continue;
        var value = window.localStorage.getItem(CONTEXT_STORAGE_KEYS[name]);
        if (value) stored[name] = value;
      }
    } catch (e) { /* storage unavailable — this page load falls back to the URL */ }
    return stored;
  }

  /**
   * saveContext — persist the Omada context. Never throws (same reason as
   * getStoredContext): a storage failure must not break the portal.
   * @param {Object} values { clientMac?, apMac?, ssidName? }
   */
  function saveContext(values) {
    try {
      for (var name in CONTEXT_STORAGE_KEYS) {
        if (!CONTEXT_STORAGE_KEYS.hasOwnProperty(name)) continue;
        var value = values ? values[name] : null;
        if (value) window.localStorage.setItem(CONTEXT_STORAGE_KEYS[name], value);
      }
    } catch (e) { /* storage unavailable — the URL values still work this load */ }
  }

  /**
   * captureOmadaContext — resolve clientMac / apMac / ssidName on page load and
   * persist them to localStorage.
   *
   * Resolution order per field: URL query param → localStorage. The resolved
   * values are copied back into `queryParams` so the context beacon, the
   * voucher submission and the payment claim see them even when this page load
   * had an empty query string (refresh / re-opened tab).
   *
   * @returns {Object} the resolved { clientMac?, apMac?, ssidName? }
   */
  function captureOmadaContext() {
    var stored = getStoredContext();
    var resolved = {};
    var fromStorage = 0;

    for (var name in CONTEXT_STORAGE_KEYS) {
      if (!CONTEXT_STORAGE_KEYS.hasOwnProperty(name)) continue;

      var urlValue = queryParams[name];
      var hasUrlValue = urlValue !== undefined && urlValue !== null && String(urlValue).trim() !== '';
      var value = hasUrlValue ? String(urlValue).trim() : stored[name];

      if (!value) continue;

      resolved[name] = value;
      queryParams[name] = value; // visible to every later step in this page load
      if (!hasUrlValue) fromStorage += 1;
    }

    // Write back unconditionally: on a fresh redirect this stores the new
    // context (also replacing a previous device's values), and on a bare URL it
    // simply re-writes what was already there.
    saveContext(resolved);

    if (fromStorage) {
      console.log(
        '[portal] Omada context restored from localStorage (' + fromStorage +
        ' field(s); this page load had no query string)'
      );
    }

    return resolved;
  }

  function getRedirectDestination() {
    var candidate = queryParams.redirectUrl
      || queryParams.originalUrl
      || queryParams.targetUrl
      || '';
    candidate = decodeURIComponent(candidate);
    if (isAllowedRedirect(candidate)) return candidate;
    return CONFIG.defaultRedirectUrl;
  }

  function isAllowedRedirect(url) {
    if (!url) return false;
    try {
      var u = new URL(url);
      // http/https only
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
      // Allow localhost for dev
      if (u.hostname === 'localhost' || u.hostname === '127.0.0.1') return true;
      // Check allowlist
      var domains = CONFIG.allowedRedirectDomains || [];
      if (domains.length === 0) return true; // open if no allowlist configured
      for (var i = 0; i < domains.length; i++) {
        var d = domains[i].toLowerCase();
        var host = u.hostname.toLowerCase();
        if (host === d || host.endsWith('.' + d)) return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  // ===============================================================
  // VALIDATION
  // ===============================================================
  // Shared rule: exactly 6 numeric digits (mirrors backend/src/utils/voucher-code.js).
  // Codes are sanitized (non-digits stripped) as the user types AND here,
  // so a pasted "123 456" or "123-456" becomes "123456" before validation.
  var VOUCHER_CODE_MESSAGE = 'Voucher code must be exactly 6 digits.';

  function sanitizeVoucherCode(raw) {
    return String(raw == null ? '' : raw).trim().replace(/\D/g, '');
  }

  function validateVoucher(code) {
    var v = CONFIG.voucher || {};
    if (!code || !code.trim()) return { ok: false, message: 'Enter your voucher code.' };
    var digits = sanitizeVoucherCode(code);
    if (!digits) return { ok: false, message: 'Enter your voucher code.' };
    // Single shared rule: exactly 6 numeric digits. minLength/maxLength are
    // kept as a legacy fallback so older config files still behave.
    var pattern = v.pattern || /^\d{6}$/;
    if (!new RegExp(pattern).test(digits)) {
      return { ok: false, message: v.patternHint || VOUCHER_CODE_MESSAGE };
    }
    if (v.minLength && digits.length < v.minLength) {
      return { ok: false, message: v.patternHint || VOUCHER_CODE_MESSAGE };
    }
    if (v.maxLength && digits.length > v.maxLength) {
      return { ok: false, message: v.patternHint || VOUCHER_CODE_MESSAGE };
    }
    return { ok: true, value: digits };
  }

  function validateTerms(checked) {
    if (CONFIG.termsRequired && !checked) {
      return { ok: false, message: 'You must accept the terms before connecting.' };
    }
    return { ok: true };
  }

  // ===============================================================
  // THEMING
  // ===============================================================
  function applyTheming() {
    var root = document.documentElement;
    if (CONFIG.primaryColor) root.style.setProperty('--primary', CONFIG.primaryColor);
    if (CONFIG.accentColor)  root.style.setProperty('--accent',  CONFIG.accentColor);

    var brandEl = $('brand-name');
    if (brandEl && CONFIG.brandName) brandEl.textContent = CONFIG.brandName;

    var tagline = $('brand-tagline');
    if (tagline && CONFIG.brandTagline) tagline.textContent = CONFIG.brandTagline;

    // Support link — the address is injected into the page at build time by
    // inject-secrets.js. Prefer that injected href and only fall back to
    // CONFIG.supportEmail; when neither is available the whole line is hidden
    // so an empty or malformed mailto: link is never shown.
    var supportEmail = String(CONFIG.supportEmail || '').trim();
    var supportLinks = document.querySelectorAll('[id*="support-email"]');
    for (var i = 0; i < supportLinks.length; i++) {
      var supportLink = supportLinks[i];
      var injectedHref = supportLink.getAttribute('href') || '';

      if (/^mailto:[^@\s]+@[^@\s]+$/.test(injectedHref)) {
        continue; // build-time value wins; the markup is already correct
      }

      if (supportEmail) {
        supportLink.href = 'mailto:' + encodeURIComponent(supportEmail);
        supportLink.textContent = supportEmail;
      } else {
        var supportRow = supportLink.closest ? supportLink.closest('.support-info') : null;
        if (supportRow) supportRow.style.display = 'none';
      }
    }

    // Terms link
    var termsLink = $('terms-link');
    if (termsLink && CONFIG.termsUrl) termsLink.href = CONFIG.termsUrl;

    var privacyLink = $('privacy-link');
    if (privacyLink && CONFIG.privacyUrl) privacyLink.href = CONFIG.privacyUrl;
  }

  // ===============================================================
  // FORM SUBMISSION
  // ===============================================================
  var submitting = false;
  // Set once a successful auth is being handed off to the success page (we
  // deliberately wait before navigating), so the submit cleanup below does not
  // tear down the "Connecting…" state during that wait.
  var navigating = false;

  function handleSubmit(e) {
    e.preventDefault();
    if (submitting) return;

    // Clear previous errors
    setError('voucher-input', '');
    setError('terms-checkbox', '');
    setFormError('');
    setBanner('');

    var voucherInput = $('voucher-input');
    var termsCheckbox = $('terms-checkbox');
    var submitBtn = $('submit-btn');
    var submitLabel = $('submit-label');
    var loadingOverlay = $('loading-overlay');
    var loadingText = $('loading-text');

        var voucherVal = voucherInput ? voucherInput.value : '';
    var termsChecked = termsCheckbox ? termsCheckbox.checked : true;

    // ---- Voucher validation ----
    // The main login area is ALWAYS the voucher input + Connect Now layout,
    // for every payment method. Paying (cash / GCash / Maya / QR Ph) yields a
    // voucher code via the Claim Voucher flow, which is then entered here.
    // (The old "Pay & Connect" checkout redirect targeted a non-existent
    // /api/payment/initiate route and has been removed.)
    var vResult = validateVoucher(voucherVal);
    if (!vResult.ok) {
      setError('voucher-input', vResult.message);
      voucherInput.focus();
      return;
    }

    // ---- Terms validation ----
    var tResult = validateTerms(termsChecked);
    if (!tResult.ok) {
      setError('terms-checkbox', tResult.message);
      if (termsCheckbox) termsCheckbox.focus();
      return;
    }

    // ---- Begin submission ----
    submitting = true;
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.setAttribute('aria-busy', 'true');
    }
    if (submitLabel) submitLabel.textContent = 'Connecting…';
    if (loadingOverlay) {
      loadingOverlay.setAttribute('aria-hidden', 'false');
      show(loadingOverlay);
    }
    if (loadingText) loadingText.textContent = 'Connecting…';

    var clientContext = buildClientContext();
    clientContext.voucher = vResult.value;
    clientContext.termsAccepted = termsChecked;

    var promise;
    if (CONFIG.mockMode) {
      promise = mockAuthenticate(clientContext);
    } else if (CONFIG.mode === 'backend') {
      promise = backendAuthenticate(clientContext);
    } else {
      promise = directAuthenticate(clientContext);
    }

    promise.then(handleSuccess).catch(handleFailure).then(function () {
      if (navigating) return; // success hand-off deliberately owns the UI now
      submitting = false;
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.removeAttribute('aria-busy');
      }
      if (submitLabel) submitLabel.textContent = 'Connect Now';
      if (loadingOverlay) {
        loadingOverlay.setAttribute('aria-hidden', 'true');
        hide(loadingOverlay);
      }
    });
  }

  function buildClientContext() {
    return {
      clientMac:  normalizeMac(queryParams.clientMac) || queryParams.clientMac || '',
      clientIp:   queryParams.clientIp  || '',
      apMac:      normalizeMac(queryParams.apMac) || queryParams.apMac || '',
      gatewayMac: normalizeMac(queryParams.gatewayMac) || queryParams.gatewayMac || '',
      vid:        queryParams.vid        || '',
      ssidName:   queryParams.ssidName   || '',
      radioId:    queryParams.radioId,
      site:       queryParams.site       || '',
      redirectUrl: getRedirectDestination(),
      authUrl:    queryParams.authUrl   || '',
      raw:        queryParams.raw       || {},
    };
  }

  // ---- Direct mode: POST to Omada extPortal auth endpoint ----
  // NOTE: This is a best-effort adapter. Exact request format varies
  // by Omada controller version. Verify against your firmware's actual API.
  function directAuthenticate(ctx) {
    return new Promise(function (resolve, reject) {
      var endpoint = CONFIG.authEndpoint;
      if (!endpoint) {
        reject({ code: 'CONFIG_ERROR', message: 'Authentication endpoint not configured.' });
        return;
      }

      var formData = new FormData();
      formData.append('username', ctx.voucher);
      formData.append('password', ctx.voucher);
      if (ctx.clientMac)  formData.append('clientMac',  ctx.clientMac);
      if (ctx.clientIp)   formData.append('clientIp',   ctx.clientIp);
      if (ctx.apMac)      formData.append('apMac',      ctx.apMac);
      if (ctx.ssidName)   formData.append('ssidName',   ctx.ssidName);

      // Passthrough any controller-specific token params
      if (ctx.raw) {
        for (var key in ctx.raw) {
          if (ctx.raw.hasOwnProperty(key) && key.indexOf('token') !== -1) {
            formData.append(key, ctx.raw[key]);
          }
        }
      }

      // CORS note: Omada controllers often don't set CORS headers on extPortal endpoints.
      // In direct mode, the form POST is same-origin relative to the portal page that
      // the controller redirected to — but the controller is a different host.
      // For best results, use backend mode which proxies the auth call.

      fetch(endpoint, {
        method: 'POST',
        mode: 'no-cors',
        credentials: 'include',
        body: formData,
      }).then(function () {
        // With no-cors, we can't read the response.
        // We have to trust that the controller handled it.
        // Redirect to success page after a short delay.
        setTimeout(function () {
          resolve({ redirectUrl: ctx.redirectUrl });
        }, 1000);
      }).catch(function () {
        reject({ code: 'NETWORK_ERROR', message: 'Could not reach the authentication server.' });
      });
    });
  }

  // ---- Backend mode: POST to our backend proxy ----
  function backendAuthenticate(ctx) {
    return new Promise(function (resolve, reject) {
      var url = CONFIG.apiBaseUrl + '/api/auth';

      fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        // Forward the full Omada connection context (extracted from the portal
        // URL with URLSearchParams) together with the voucher so the backend can
        // rebuild the controller's extPortal/auth request without losing any of
        // the parameters Omada itself generated.
        body: JSON.stringify({
          voucher:    ctx.voucher,
          clientMac:  ctx.clientMac,
          clientIp:   ctx.clientIp,
          apMac:      ctx.apMac,
          gatewayMac: ctx.gatewayMac,
          vid:        ctx.vid,
          ssidName:   ctx.ssidName,
          radioId:    ctx.radioId,
          site:       ctx.site,
          redirectUrl: ctx.redirectUrl,
          termsAccepted: ctx.termsAccepted,
        }),
      }).then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (data) {
          return { status: r.status, data: data };
        });
      }).then(function (result) {
        var data = result.data || {};
        if (result.status >= 200 && result.status < 300 && data.success) {
          resolve({
            redirectUrl: data.redirectUrl || ctx.redirectUrl,
            sessionId: data.sessionId,
            // Session timing echoed by POST /api/auth from the committed row.
            // Carried to success.html so the "time remaining" box renders the
            // real value immediately instead of waiting on a status poll.
            clientMac:       data.clientMac || '',
            startedAt:       data.startedAt || '',
            expiresAt:       data.expiresAt || '',
            durationMinutes: data.durationMinutes || 0,
            totalSeconds:    data.totalSeconds || 0,
            remainingSeconds: (data.session && data.session.remainingSeconds) || 0,
            voucherType:     (data.session && data.session.voucherType) || '',
            // Set when the backend resumed a paused Premium session instead of
            // redeeming a fresh voucher (login-with-existing-voucher flow).
            resumed: data.resumed === true,
          });
        } else {
          reject({
            code: data.code || 'AUTH_FAILED',
            message: data.error || data.message || 'Authentication failed.',
          });
        }
      }).catch(function (err) {
        if (err.name === 'TypeError') {
          reject({ code: 'NETWORK_ERROR', message: 'The network could not be reached. Please try again.' });
        } else {
          reject({ code: 'SERVER_ERROR', message: 'A server error occurred. Please try again.' });
        }
      });
    });
  }

  // ---- Mock mode: simulate auth for testing without controller ----
  function mockAuthenticate(ctx) {
    return new Promise(function (resolve, reject) {
      var delay = CONFIG.mockSuccessDelay || 800;
      setTimeout(function () {
        var v = ctx.voucher.toUpperCase();
        if (v === 'EXPIRED' || v === 'EXPIRED-VOUCHER') {
          reject({ code: 'EXPIRED_VOUCHER', message: 'This voucher has expired.' });
        } else if (v === 'USED' || v === 'USED-VOUCHER') {
          reject({ code: 'USED_VOUCHER', message: 'This voucher has already been used.' });
        } else if (v === 'FAIL' || v === 'INVALID') {
          reject({ code: 'INVALID_VOUCHER', message: 'Invalid voucher code.' });
        } else if (v === 'RATE' || v === 'RATE-LIMIT') {
          reject({ code: 'RATE_LIMITED', message: 'Too many attempts. Please wait.' });
        } else if (v === 'NETWORK' || v === 'NETERROR') {
          reject({ code: 'NETWORK_ERROR', message: 'Network error (mock).' });
        } else {
          resolve({
            redirectUrl: ctx.redirectUrl,
            sessionId: 'sess_mock_' + Math.random().toString(36).slice(2, 10),
          });
        }
      }, delay);
    });
  }

  // ---- Handle successful auth ----
  function handleSuccess(result) {
    // Persist the session identifier so the session status page can find
    // this device even after the post-login redirect (the sessionId would
    // otherwise be lost once the user leaves success.html).
    try {
      if (result.sessionId) {
        window.localStorage.setItem('portalSessionId', result.sessionId);
        window.sessionStorage.setItem('portalSessionId', result.sessionId);
      }
      // Persist the client MAC so a later silent re-authorization can still
      // identify this device even if the Omada query params are gone.
      if (queryParams.clientMac) {
        window.localStorage.setItem(
          'portalClientMac',
          normalizeMac(queryParams.clientMac) || queryParams.clientMac
        );
      }
    } catch (e) { /* storage unavailable — URL param still works */ }

    // Build the post-login destination.
    var target;
    if (result.resumed && result.sessionId) {
      // Re-login that resumed a paused Premium session: go straight to the
      // live session page. Its countdown reads the remaining time the backend
      // just re-authorized, so the timer continues from where it left off.
      var statusPage = CONFIG.statusPage || 'status.html';
      target = statusPage + '?sessionId=' + encodeURIComponent(result.sessionId) +
        (queryParams.clientMac
          ? '&clientMac=' + encodeURIComponent(normalizeMac(queryParams.clientMac) || queryParams.clientMac)
          : '');
    } else {
      // Build success URL with redirect and session info
      var params = new URLSearchParams();
      if (result.redirectUrl) params.set('redirectUrl', encodeURIComponent(result.redirectUrl));
      if (result.sessionId)   params.set('sessionId', result.sessionId);
      var mac = queryParams.clientMac
        ? (normalizeMac(queryParams.clientMac) || queryParams.clientMac)
        : (result.clientMac || '');
      if (mac) params.set('clientMac', mac);

      // Session timing: success.html renders its countdown from these, so the
      // page agrees with the row POST /api/auth just committed. `duration` is
      // minutes (used only when no absolute expiry is available); `expiresAt`
      // is the authoritative ISO timestamp.
      if (result.expiresAt) params.set('expiresAt', result.expiresAt);
      if (result.startedAt) params.set('startedAt', result.startedAt);
      if (result.durationMinutes) params.set('duration', String(result.durationMinutes));
      if (result.totalSeconds) params.set('totalSeconds', String(result.totalSeconds));
      if (result.remainingSeconds) params.set('remaining', String(result.remainingSeconds));
      if (result.voucherType) params.set('voucherType', result.voucherType);
      params.set('countdown', '3');

      // Carry Omada's originUrl (the URL the guest first tried to open) through
      // to success.html so it can nudge the OS with a real internet request.
      var originUrl = queryParams.raw && (queryParams.raw.originUrl || queryParams.raw.originalUrl);
      if (originUrl) params.set('originUrl', encodeURIComponent(originUrl));

      target = CONFIG.successPage + '?' + params.toString();
    }

    // ---- Settle before navigating (race-condition fix) ----
    // The backend has confirmed the voucher, but the Omada controller still has
    // to program the firewall / authorization rules for THIS client's MAC. If
    // we navigate right away, the phone's OS probes for internet before that
    // access exists, marks the network as still-captive, and tears the captive
    // mini-browser down asking the user to sign in again. Hold on the
    // "Connecting…" screen for a few seconds so the controller catches up.
    var delayMs = (typeof CONFIG.connectDelayMs === 'number') ? CONFIG.connectDelayMs : 3500;

    // Keep the loading overlay visible (and labelled) throughout the wait.
    var settleOverlay = $('loading-overlay');
    var settleText = $('loading-text');
    var settleLabel = $('submit-label');
    if (settleOverlay) { settleOverlay.setAttribute('aria-hidden', 'false'); show(settleOverlay); }
    if (settleText) settleText.textContent = result.resumed ? 'Resuming your session…' : 'Connecting…';
    if (settleLabel) settleLabel.textContent = result.resumed ? 'Resuming…' : 'Connecting…';

    // Return a promise so the caller's cleanup waits for the hand-off instead
    // of resolving (and resetting the UI) during the delay.
    navigating = true;
    return new Promise(function (resolve) {
      window.setTimeout(function () {
        window.location.href = target;
        resolve();
      }, delayMs);
    });
  }

  // ---- Handle auth failure ----
  function handleFailure(err) {
    var code = err.code || 'AUTH_FAILED';
    var message = err.message || 'Authentication failed.';

    // Public-safe messages only
    var SAFE_MESSAGES = {
      INVALID_VOUCHER: 'Your voucher code was not recognized. Please check and try again.',
      EXPIRED_VOUCHER: 'This voucher has expired. Please obtain a new code.',
      USED_VOUCHER:    'This voucher has already been used.',
      SESSION_LIMIT:   'The maximum number of connected devices has been reached.',
      NETWORK_ERROR:   'The network could not be reached. Please check your connection and try again.',
      SERVER_ERROR:    'The authentication server is temporarily unavailable. Please try again shortly.',
      RATE_LIMITED:    'Too many attempts. Please wait a moment before trying again.',
      TERMS_REQUIRED:  'You must accept the terms before connecting.',
      // Pause/resume (login with an existing Premium voucher)
      STANDARD_CONTINUOUS:     'Standard vouchers run continuously and cannot be paused or resumed.',
      VOUCHER_DEVICE_MISMATCH: 'This voucher is already in use on another device and cannot be resumed here.',
      ALREADY_ACTIVE:          'This session is already active on this device.',
      CONFIG_ERROR:    'Portal configuration error. Please contact support.',
      OMADA_ERROR:     'Temporary connection error. Please wait a moment and try again.',
      AUTH_FAILED:     'Authentication failed. Please check your voucher and try again.',
    };

    var publicMsg = SAFE_MESSAGES[code] || SAFE_MESSAGES.AUTH_FAILED;

    setFormError(publicMsg);

    // If it's a voucher-specific error, highlight the field
    if (code === 'INVALID_VOUCHER' || code === 'EXPIRED_VOUCHER' || code === 'USED_VOUCHER' ||
        code === 'STANDARD_CONTINUOUS' || code === 'VOUCHER_DEVICE_MISMATCH') {
      setError('voucher-input', publicMsg);
    }
  }

  // ===============================================================
  // INPUT ENHANCEMENTS
  // ===============================================================
  function initInputEnhancements() {
    var input = $('voucher-input');
    if (!input) return;

    // Clear error as user types, and strip non-digits live so pasting
    // "123 456" or "123-456" becomes "123456" immediately.
    input.addEventListener('input', function () {
      var cleaned = sanitizeVoucherCode(input.value);
      if (cleaned !== input.value) {
        input.value = cleaned;
      }
      setError('voucher-input', '');
      setFormError('');
    });

    // Also sanitize pasted content (paste fires before input in some browsers)
    input.addEventListener('paste', function () {
      setTimeout(function () {
        var cleaned = sanitizeVoucherCode(input.value);
        if (cleaned !== input.value) {
          input.value = cleaned;
        }
        setError('voucher-input', '');
        setFormError('');
      }, 0);
    });

    // Trim and strip non-digits on blur
    input.addEventListener('blur', function () {
      if (input.value) {
        input.value = sanitizeVoucherCode(input.value);
      }
    });

    // Terms checkbox: clear error on change
    var termsCheckbox = $('terms-checkbox');
    if (termsCheckbox) {
      termsCheckbox.addEventListener('change', function () {
        setError('terms-checkbox', '');
      });
    }

    // Enter key on terms checkbox submits form
    if (termsCheckbox) {
      termsCheckbox.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          var form = termsCheckbox.closest('form');
          if (form) form.dispatchEvent(new Event('submit', { cancelable: true }));
        }
      });
    }
  }

  // ===============================================================
  // TERMS SECTION INIT
  // ===============================================================
  function initTermsSection() {
    var termsSection = $('terms-section');
    if (!termsSection) return;
    if (CONFIG.termsRequired) {
      show(termsSection);
    }
    }

  // ---------------------------------------------------------------
  function formatPrice(amount) {
    // Amount in smallest currency unit (e.g., centavos for PHP)
    var pesos = (amount / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    return '₱' + pesos;
  }

  // ===============================================================
  // PAYMENT TILES (backend/paid mode)
  // ===============================================================
    function initPaymentTiles() {
    var tiles = document.querySelectorAll('.payment-tile');
    if (!tiles.length) return;

    tiles.forEach(function (tile) {

      tile.addEventListener('click', function () {
        // Deselect all
        tiles.forEach(function (t) { t.classList.remove('is-selected'); });
        // Select this one
        tile.classList.add('is-selected');

        var method = tile.getAttribute('data-payment');

        // Cash: show timer modal with countdown, then redirect to voucher input
        if (method === 'cash') {
          showCashTimerModal();
          return;
        }

        // GCash / Maya / QR Ph: open the in-page QR payment modal. The
        // selected plan's price is passed in as the exact amount to pay.
        if (QR_METHOD_IDS.indexOf(method) !== -1) {
          var amountCents = getSelectedPlanAmountCents();
          if (amountCents === null) {
            tile.classList.remove('is-selected');
            setBanner('Please choose a plan above first, then select a payment method.', 'info');
            var pricingSection = document.querySelector('.pricing-section');
            if (pricingSection) pricingSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
            return;
          }
          openPaymentQrModal(method, amountCents);
        }
      });
    });
  }

    // ===============================================================
  // PRICING TABLE SELECT HANDLER
  // ===============================================================

  // ===============================================================
  // PLAN SELECTION MODAL POPUP
  // ===============================================================
  function showPlanModal(tier, durText) {
    var modal = $('plan-modal');
    var planEl = $('plan-modal-plan');
    var closeBtn = $('plan-modal-close');
    var okBtn = $('plan-modal-ok');
    
    if (!modal || !planEl) return;
    
    // Set the message content
    var tierName = tier.charAt(0).toUpperCase() + tier.slice(1);
    planEl.textContent = tierName + ' - ' + durText + ' plan';
    
    // Show modal
    show(modal);
    modal.focus();
    
    // Hide the status banner when modal is shown
    setBanner('');
    
    // Auto-focus OK button for keyboard users
    if (okBtn) setTimeout(function() { okBtn.focus(); }, 100);
    
    // Close handler
    function closeModal() {
      hide(modal);
      
      // Scroll payment section into view
      var paymentSection = document.querySelector('.payment-method-section');
      if (paymentSection) {
        paymentSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
    
    // Remove existing listeners to avoid duplicates
    if (closeBtn) {
      closeBtn.onclick = closeModal;
    }
    if (okBtn) {
      okBtn.onclick = closeModal;
    }
    
    // Close on overlay click
    modal.onclick = function(e) {
      if (e.target === modal) closeModal();
    };
    
    // Close on Escape key
    function onEsc(e) {
      if (e.key === 'Escape') {
        closeModal();
        document.removeEventListener('keydown', onEsc);
      }
    }
    document.addEventListener('keydown', onEsc);
  }


   // ==============================================================================
   // CASH PAYMENT TIMER MODAL
   /**
  
   * showConnectionInstructions — Show a popup with WiFi connection instructions.
  
   * Triggered when the user is redirected to the voucher page after
  
   * selecting "I already have a voucher" from the cash payment timer.
  
   */
  
  function showConnectionInstructions() {
  
    var modal = $('connection-instructions-modal');
  
    var closeBtn = $('connection-instructions-close');
  
    var gotItBtn = $('connection-instructions-got-it');
  
  
  
    if (!modal) return;
  
  
  
    // Check if the flag is set
  
    var shouldShow = sessionStorage.getItem('showConnectionInstructions');
  
    if (shouldShow !== 'true') return;
  
  
  
    // Remove flag
  
    sessionStorage.removeItem('showConnectionInstructions');
  
  
  
    // Show modal
  
    show(modal);
  
    modal.focus();
  
  
  
    // Focus the Got It button
  
    if (gotItBtn) setTimeout(function () { gotItBtn.focus(); }, 100);
  
  
  
    // Close handlers
  
    function closeConnectionModal() {
  
      hide(modal);
  
    }
  
  
  
    if (closeBtn) closeBtn.onclick = closeConnectionModal;
  
    if (gotItBtn) gotItBtn.onclick = closeConnectionModal;
  
  
  
    // Close on overlay click
  
    modal.onclick = function (e) {
  
      if (e.target === modal) closeConnectionModal();
  
    };
  
  
  
    // Close on Escape key
  
    function onEsc(e) {
  
      if (e.key === 'Escape') {
  
        closeConnectionModal();
  
        document.removeEventListener('keydown', onEsc);
  
      }
  
    }
  
    document.addEventListener('keydown', onEsc);
  
  }
  
  
  
  
  // ==============================================================================
   function showCashTimerModal() {
     var modal = $('cash-modal');
     var closeBtn = $('cash-modal-close');
     var cancelBtn = $('cash-timer-cancel');
     var haveVoucherBtn = $('cash-timer-have-voucher');
     var timerDisplay = $('cash-timer-seconds');

     if (!modal) return;

     // Timer: 2 minutes 50 seconds = 170 seconds (configurable via CONFIG.cashPayment.timerSeconds)
     var TOTAL_SECONDS = (window.CONFIG && window.CONFIG.cashPayment && window.CONFIG.cashPayment.timerSeconds) || 170;
     var remaining = TOTAL_SECONDS;
     var countdownInterval = null;

     // Format seconds as M:SS
     function formatTime(seconds) {
       var m = Math.floor(seconds / 60);
       var s = seconds % 60;
       return m + ':' + (s < 10 ? '0' : '') + s;
     }

     // Update the timer display
     function updateTimerDisplay() {
       if (timerDisplay) {
         timerDisplay.textContent = formatTime(remaining);
       }
     }

     // Start the countdown
     function startCountdown() {
       remaining = TOTAL_SECONDS;
       updateTimerDisplay();

       countdownInterval = setInterval(function () {
         remaining--;
         updateTimerDisplay();

         if (remaining <= 0) {
           clearInterval(countdownInterval);
           // Timer expired - redirect to voucher input page
           sessionStorage.setItem('showConnectionInstructions', 'true');
           var redirectUrl = (window.CONFIG && window.CONFIG.cashPayment && window.CONFIG.cashPayment.redirectUrl) || 'index.html';
           window.location.href = redirectUrl;
         }
       }, 1000);
     }

     // Stop the countdown
     function stopCountdown() {
       if (countdownInterval) {
         clearInterval(countdownInterval);
         countdownInterval = null;
       }
     }

     // Close handler - also deselects the Cash tile
     function closeModal() {
       stopCountdown();
       hide(modal);

       // Deselect the Cash payment tile
       var tiles = document.querySelectorAll('.payment-tile');
       tiles.forEach(function (t) { t.classList.remove('is-selected'); });

       // Scroll payment section into view
       var paymentSection = document.querySelector('.payment-method-section');
       if (paymentSection) {
         paymentSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
       }
     }

     // "I already have a voucher" handler
     function redirectToVoucher() {
       stopCountdown();
       // Set flag to show connection instructions on next page load
       sessionStorage.setItem('showConnectionInstructions', 'true');
       var redirectUrl = (window.CONFIG && window.CONFIG.cashPayment && window.CONFIG.cashPayment.redirectUrl) || 'index.html';
       window.location.href = redirectUrl;
     }

     // Show modal
     show(modal);
     modal.focus();

     // Hide the status banner when modal is shown
     setBanner('');

     // Start the countdown
     startCountdown();

     // Auto-focus Cancel button for keyboard users
     if (cancelBtn) setTimeout(function () { cancelBtn.focus(); }, 100);

     // Remove existing listeners to avoid duplicates
     if (closeBtn) {
       closeBtn.onclick = closeModal;
     }
     if (cancelBtn) {
       cancelBtn.onclick = closeModal;
     }
     if (haveVoucherBtn) {
       haveVoucherBtn.onclick = redirectToVoucher;
     }

     // Close on overlay click
     modal.onclick = function (e) {
       if (e.target === modal) closeModal();
     };

     // Close on Escape key
     function onEsc(e) {
       if (e.key === 'Escape') {
         closeModal();
         document.removeEventListener('keydown', onEsc);
       }
     }
     document.addEventListener('keydown', onEsc);
   }

   function initPricingTable() {
    var selectButtons = document.querySelectorAll('.btn--select');
    if (!selectButtons.length) return;

        selectButtons.forEach(function (btn) {
      btn.addEventListener('click', function () {
        var row = btn.closest('tr');
        if (!row) return;

        var tier = row.getAttribute('data-tier');
        var duration = parseInt(row.getAttribute('data-duration'), 10);
        var price = parseInt(row.getAttribute('data-price'), 10);
        var planId = row.getAttribute('data-id');

        // Keep the voucher input visible — the main login area uses the
        // single voucher layout for every payment method — and reveal the
        // payment tiles below it.
        var paymentSection = document.querySelector('.payment-section');

        // Store selected plan in hidden field on the form
        var form = document.querySelector('form.auth-form');
        if (form) {
          // Remove any existing selectedPlan hidden input to avoid duplicates
          var existingInput = form.querySelector('input[name="selectedPlan"]');
          if (existingInput) {
            form.removeChild(existingInput);
          }
          // Store selected plan details
          var hiddenInput = document.createElement('input');
          hiddenInput.type = 'hidden';
          hiddenInput.name = 'selectedPlan';
          hiddenInput.value = JSON.stringify({
            tier: tier,
            duration: duration,
            price: price,
            planId: planId
          });
          form.appendChild(hiddenInput);
        }

        // Clear any form errors
        setFormError('');
        setBanner('');

                // Show payment tiles section
        if (paymentSection) {
          paymentSection.classList.add('payment-section--visible');
        }

        // Highlight the selected row (deselect across ALL pricing tables, not just same table)
        var allTables = document.querySelectorAll('.pricing-table');
        var allRows = [];
        allTables.forEach(function (table) {
          var rows = table.querySelectorAll('tbody tr');
          rows.forEach(function (r) { allRows.push(r); });
        });
        allRows.forEach(function (r) {
          r.classList.remove('is-selected');
        });
        row.classList.add('is-selected');

        // Show plan selection modal
        var durMin = duration;
        var durText = '';
        if (duration >= 1440) {
          durText = (duration / 1440) + ' day' + (duration / 1440 >= 2 ? 's' : '');
        } else if (duration >= 60) {
          durText = (duration / 60) + ' hour' + (duration / 60 >= 2 ? 's' : '');
        } else {
          durText = duration + ' minute' + (duration >= 2 ? 's' : '');
        }

        showPlanModal(tier, durText);
      });
    });

    // Add handlers for clear/reset buttons
    var clearButtons = document.querySelectorAll('.btn--clear');
    clearButtons.forEach(function (btn) {
      btn.addEventListener('click', function () {
        // Find the parent row and remove highlight
        var row = btn.closest('tr');
        if (row) {
          row.classList.remove('is-selected');
        }

        // Remove all row highlights across the table
        var allTables = document.querySelectorAll('.pricing-table');
        allTables.forEach(function (table) {
          var rows = table.querySelectorAll('tbody tr');
          rows.forEach(function (r) {
            r.classList.remove('is-selected');
          });
        });

        // Remove the selectedPlan hidden input
        var form = document.querySelector('form.auth-form');
        if (form) {
          var hiddenInput = form.querySelector('input[name="selectedPlan"]');
          if (hiddenInput) {
            form.removeChild(hiddenInput);
          }
        }

        // Hide payment section
        var paymentSection = document.querySelector('.payment-section');
        if (paymentSection) {
          paymentSection.classList.remove('payment-section--visible');
        }

        var modalEl = document.getElementById("plan-modal");
        if (modalEl) hide(modalEl);
        setBanner('');
        setFormError('');
      });
    });
  }

  // ===============================================================
  // CONTEXT CAPTURE BEACON (fire-and-forget)
  // ===============================================================
  /**
   * sendContextBeacon — POST the controller context to
   * /api/payment/context on portal landing so the payment webhook can
   * authorize this device later. Fire-and-forget: a .catch() swallows
   * network errors so the beacon NEVER blocks or breaks the portal UI.
   * If capture fails, the webhook's MISSING_PORTAL_CONTEXT fail-loud
   * path handles it (durable payment + 422 + re-open-portal resolution).
   */
  function sendContextBeacon() {
    if (!queryParams.clientMac || !queryParams.apMac || !queryParams.ssidName) {
      // Incomplete context — still beacon what we have? No: the backend
      // rejects incomplete payloads, so skip the request entirely.
      return;
    }
    var beaconUrl = (CONFIG.apiBaseUrl || '') + '/api/payment/context';
    try {
      fetch(beaconUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          client_mac: normalizeMac(queryParams.clientMac) || queryParams.clientMac,
          client_ip:  queryParams.clientIp || '',
          ap_mac:     normalizeMac(queryParams.apMac) || queryParams.apMac,
          ssid_name:  queryParams.ssidName,
          radio_id:   parseInt(queryParams.radioId, 10) || 0,
        }),
        // keepalive helps the beacon survive an immediate redirect
        keepalive: true,
      }).catch(function () { /* fire-and-forget — never surface beacon errors */ });
    } catch (e) { /* ignore — beacon must never break page load */ }
  }

  // ===============================================================
  // DYNAMIC PAYMENT QR MODAL (GCash / Maya / QR Ph)
  // ===============================================================
  // Receiver details, account numbers and QR images are NOT hard-coded here.
  // They are fetched from GET /api/payment/methods (backed by environment
  // variables on the server) and cached for the lifetime of the page so the
  // modal opens instantly after the first fetch. The amount is never
  // hard-coded either: it is passed in from the plan the customer selected.
  var qrMethodsCache = null;

  // Methods that open the in-page QR modal (cash uses its own timer modal).
  var QR_METHOD_IDS = ['gcash', 'maya', 'qrph'];

  function loadPaymentMethods() {
    if (qrMethodsCache) return Promise.resolve(qrMethodsCache);
    return fetch((CONFIG.apiBaseUrl || '') + '/api/payment/methods', {
      credentials: 'same-origin'
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (data) {
      if (!data || typeof data !== 'object') throw new Error('Malformed payment config');
      qrMethodsCache = data;
      return data;
    });
  }

  var qrState = {
    method: null,
    amountCents: 0,
    open: false,
    lastFocus: null
  };

  function qrEl(id) { return document.getElementById(id); }

  // Resolve the exact amount (in centavos) for the current plan selection.
  // The pricing table stores a JSON snapshot in the selectedPlan hidden
  // input; returns null when no plan has been chosen yet.
  function getSelectedPlanAmountCents() {
    var pricingInput = document.querySelector('input[name="selectedPlan"]');
    if (pricingInput && pricingInput.value) {
      try {
        var parsed = JSON.parse(pricingInput.value);
        if (parsed && parsed.price !== undefined && parsed.price !== null) {
          return Number(parsed.price);
        }
      } catch (e) { /* ignore malformed snapshot */ }
    }
    return null;
  }

  async function openPaymentQrModal(method, amountCents) {
    var overlay = qrEl('payment-qr-modal');
    if (!overlay) return;

    // Fetch (and cache) the receiver details + QR images from the backend.
    // Show a loading state while waiting; on failure surface a graceful
    // message and never open the modal.
    var tile = document.querySelector('.payment-tile[data-payment="' + method + '"]');
    var needsFetch = !qrMethodsCache;
    if (needsFetch) {
      if (tile) { tile.classList.add('is-loading'); tile.setAttribute('aria-busy', 'true'); }
      setBanner('Loading payment details\u2026', 'info');
    }

    var methods;
    try {
      methods = await loadPaymentMethods();
    } catch (err) {
      if (tile) {
        tile.classList.remove('is-loading');
        tile.classList.remove('is-selected');
        tile.removeAttribute('aria-busy');
      }
      setBanner('Payment methods are currently unavailable. Please try again later.', 'error');
      return;
    }

    if (tile) { tile.classList.remove('is-loading'); tile.removeAttribute('aria-busy'); }
    if (needsFetch) setBanner('');

    var def = methods && methods[method];
    if (!def) {
      if (tile) tile.classList.remove('is-selected');
      setBanner('This payment method is currently unavailable.', 'error');
      return;
    }

    qrState.method = method;
    qrState.amountCents = amountCents;
    qrState.lastFocus = document.activeElement;

    // Header
    var titleEl = qrEl('qr-modal-title');
    if (titleEl) titleEl.textContent = 'Pay with ' + def.name;
    var subtitleEl = qrEl('qr-modal-desc');
    if (subtitleEl) subtitleEl.textContent = 'Scan the QR code below using the ' + def.name + ' app';

    // Static QR image + receiver details
    var img = qrEl('qr-image');
    if (img) { img.src = def.qrImage; img.alt = def.name + ' payment QR code'; }
    var nameRow = qrEl('qr-account-name-row');
    if (nameRow) show(nameRow);
    var nameEl = qrEl('qr-account-name');
    if (nameEl) nameEl.textContent = def.accountName;
    // QR Ph is identified by the scanned code itself, so its Account Number
    // row is hidden. GCash and Maya keep both Account Name and Account Number.
    var numRow = qrEl('qr-account-number-row');
    var numEl = qrEl('qr-account-number');
    if (def.accountNumber && method !== 'qrph') {
      if (numEl) numEl.textContent = def.accountNumber;
      if (numRow) show(numRow);
    } else {
      if (numRow) hide(numRow);
    }
    var amountEl = qrEl('qr-amount-value');
    if (amountEl) amountEl.textContent = formatPrice(amountCents);

    // Dynamic, numbered instructions for the selected method
    var list = qrEl('qr-instructions');
    if (list) {
      list.innerHTML = '';
      def.instructions.forEach(function (step) {
        var li = document.createElement('li');
        li.textContent = step;
        list.appendChild(li);
      });
      show(list);
    }

    // Open with fade + scale, lock background scroll
    overlay.classList.add('is-open');
    document.body.classList.add('qr-modal-open');
    qrState.open = true;

    setTimeout(function () {
      var closeBtn = qrEl('qr-modal-close');
      if (closeBtn) closeBtn.focus();
    }, 60);
  }

  // Close the QR modal. Returns focus to the tile that opened it.
  function qrClose() {
    if (!qrState.open) return;
    var overlay = qrEl('payment-qr-modal');
    if (overlay) overlay.classList.remove('is-open');
    document.body.classList.remove('qr-modal-open');
    qrState.open = false;
    var focusTarget = qrState.lastFocus;
    qrState.lastFocus = null;
    if (focusTarget && typeof focusTarget.focus === 'function') {
      setTimeout(function () { focusTarget.focus(); }, 60);
    }
  }

  // ===============================================================
  // CLAIM VOUCHER MODAL (centralized post-payment claim)
  // ===============================================================
  // The customer pays via GCash / Maya / QR Ph, MacroDroid POSTs the
  // confirmation to /api/webhooks/macrodroid (creating an 'unclaimed' event),
  // and the customer claims the matching pre-imported voucher here by typing
  // the last 4 digits of their reference number.
  //
  // The permanent flow authorizes the guest's MAC directly, so the modal ends
  // in the "authorized" state with no code to show or retype; its Done button
  // (and a short automatic wait) hands the guest to success.html.
  var claimState = {
    open: false,
    submitting: false,
    voucherCode: null,
    step: null,
    redirectTimer: null,
    lastFocus: null
  };

  // How long the auto-authorized confirmation stays on screen before the
  // guest is taken to success.html. "Done" skips the wait.
  var CLAIM_SUCCESS_REDIRECT_MS = 3000;

  function claimEl(id) { return document.getElementById(id); }

  // Show exactly one of the modal's states (input / loading / success / error)
  // and align the footer buttons with it.
  function showClaimStep(step) {
    claimState.step = step;
    var steps = {
      input: claimEl('claim-step-input'),
      loading: claimEl('claim-step-loading'),
      success: claimEl('claim-step-success'),
      authorized: claimEl('claim-step-authorized'),
      error: claimEl('claim-step-error')
    };
    for (var name in steps) {
      if (!steps.hasOwnProperty(name)) continue;
      var el = steps[name];
      if (!el) continue;
      if (name === step) show(el); else hide(el);
    }

    var verifyBtn = claimEl('claim-verify');
    var retryBtn = claimEl('claim-retry');
    var connectBtn = claimEl('claim-connect');
    // In the auto-authorized state the guest is already online, so a "Connect
    // Now" button would be misleading — but "Cancel" would read as a failure
    // for what is in fact success, hence the relabel.
    var cancelBtn = claimEl('claim-cancel');
    if (cancelBtn) cancelBtn.textContent = (step === 'authorized') ? 'Done' : 'Cancel';
    if (step === 'success') {
      if (verifyBtn) hide(verifyBtn);
      if (retryBtn) hide(retryBtn);
      if (connectBtn) show(connectBtn);
    } else if (step === 'authorized') {
      if (verifyBtn) hide(verifyBtn);
      if (retryBtn) hide(retryBtn);
      if (connectBtn) hide(connectBtn);
    } else if (step === 'error') {
      if (verifyBtn) hide(verifyBtn);
      if (retryBtn) show(retryBtn);
      if (connectBtn) hide(connectBtn);
    } else {
      if (verifyBtn) show(verifyBtn);
      if (retryBtn) hide(retryBtn);
      if (connectBtn) hide(connectBtn);
    }

    setTimeout(function () {
      if (step === 'input') {
        var input = claimEl('claim-ref-input');
        if (input) input.focus();
      } else if (step === 'success' && connectBtn) {
        connectBtn.focus();
      } else if (step === 'authorized' && cancelBtn) {
        cancelBtn.focus();
      }
    }, 60);
  }

  function setClaimError(message) {
    var errEl = claimEl('claim-input-error');
    if (errEl) {
      if (message) { errEl.textContent = message; show(errEl); }
      else { errEl.textContent = ''; hide(errEl); }
    }
    var input = claimEl('claim-ref-input');
    if (input) {
      if (message) input.classList.add('is-error');
      else input.classList.remove('is-error');
    }
  }

  function setMobileError(message) {
    var errEl = claimEl('claim-mobile-error');
    if (errEl) {
      if (message) { errEl.textContent = message; show(errEl); }
      else { errEl.textContent = ''; hide(errEl); }
    }
    var input = claimEl('claim-mobile-input');
    if (input) {
      if (message) input.classList.add('is-error');
      else input.classList.remove('is-error');
    }
  }

  // Reset the modal to its initial input state (called every time it opens).
  function resetClaimModal() {
    // A pending hand-off from an earlier claim must never navigate this new
    // attempt away from the portal page.
    if (claimState.redirectTimer) {
      window.clearTimeout(claimState.redirectTimer);
      claimState.redirectTimer = null;
    }
    claimState.submitting = false;
    claimState.voucherCode = null;

    var input = claimEl('claim-ref-input');
    if (input) { input.value = ''; input.disabled = false; input.classList.remove('is-error'); }
    var mobileInput = claimEl('claim-mobile-input');
    if (mobileInput) { mobileInput.value = ''; mobileInput.disabled = false; mobileInput.classList.remove('is-error'); }
    setClaimError('');
    setMobileError('');

    var errText = claimEl('claim-error-text');
    if (errText) errText.textContent = '';
    var codeEl = claimEl('claim-voucher-code');
    if (codeEl) codeEl.textContent = '';

    var verifyBtn = claimEl('claim-verify');
    var verifyLabel = claimEl('claim-verify-label');
    var verifySpinner = claimEl('claim-verify-spinner');
    if (verifyBtn) { verifyBtn.disabled = false; verifyBtn.removeAttribute('aria-busy'); }
    if (verifyLabel) verifyLabel.textContent = 'Connect & Send Status Link';
    if (verifySpinner) hide(verifySpinner);

    var connectBtn = claimEl('claim-connect');
    if (connectBtn) connectBtn.disabled = false;

    // Collapse the reference cheat sheet again so the modal reopens in its
    // compact state on every visit.
    var guideContainer = claimEl('ref-guide-container');
    var guideBtn = claimEl('show-ref-guide-btn');
    if (guideContainer) hide(guideContainer);
    if (guideBtn) guideBtn.textContent = 'Saan makikita ang Reference No.?';

    showClaimStep('input');
  }

  function openClaimModal() {
    var modal = claimEl('claim-modal');
    if (!modal) return;
    claimState.lastFocus = document.activeElement;
    resetClaimModal();
    show(modal);
    claimState.open = true;
    setBanner('');
  }

  function closeClaimModal() {
    if (!claimState.open) return;
    var modal = claimEl('claim-modal');
    if (modal) hide(modal);
    claimState.open = false;
    var focusTarget = claimState.lastFocus;
    claimState.lastFocus = null;
    if (focusTarget && typeof focusTarget.focus === 'function') {
      setTimeout(function () { focusTarget.focus(); }, 60);
    }
  }

  /**
   * getDeviceContext — the client/AP MAC for a payment request.
   *
   * captureOmadaContext() ran at page load and merged the URL params with the
   * persisted copy, so reading localStorage here is what keeps the device
   * identifiable when the request is made from the parameterless URL of a
   * refresh or a re-opened tab. MACs are normalized to the canonical
   * aa:bb:cc:dd:ee:ff form the backend expects; a value we cannot parse is
   * forwarded unchanged so the controller can still try it.
   *
   * @returns {{clientMac: string, apMac: string}}
   */
  function getDeviceContext() {
    var stored = getStoredContext();
    var clientMac = queryParams.clientMac || stored.clientMac || '';
    var apMac = queryParams.apMac || stored.apMac || '';
    return {
      clientMac: normalizeMac(clientMac) || clientMac,
      apMac: normalizeMac(apMac) || apMac,
    };
  }

  // Where status.html looks for the device a claim belongs to. The portal is
  // served through a cloud tunnel, so when status.html asks the backend for
  // "this device" the address the backend sees is the tunnel's public address,
  // never the guest's LAN address recorded by the landing beacon — the
  // address-based lookup therefore answers MISSING_PORTAL_CONTEXT. Saving the
  // claimed MAC here (same origin as status.html) is what lets that page fall
  // back to /api/session/status?mac=<mac> instead of giving up.
  var DEVICE_MAC_STORAGE_KEY = 'device_mac';

  /**
   * rememberDeviceIdentity — persist the device a successful claim belongs to.
   *
   * The claim response carries no device id (it reports the voucher and the
   * granted minutes), so the MAC comes from this page's own context — the very
   * value the claim POSTed as client_mac and the backend authorized.
   * `portalClientMac` is written alongside it because success.html and
   * status.html already read that key.
   *
   * Called only AFTER the claim succeeded, so a failed attempt never leaves a
   * stale MAC behind. Never throws: with storage blocked the page keeps
   * working and status.html simply stays on the address lookup.
   */
  function rememberDeviceIdentity() {
    var mac = normalizeMac(getDeviceContext().clientMac) || '';
    if (!mac) return;
    try {
      window.localStorage.setItem(DEVICE_MAC_STORAGE_KEY, mac);
      window.localStorage.setItem(CONTEXT_STORAGE_KEYS.clientMac, mac);
    } catch (e) { /* storage unavailable — status.html falls back to the address lookup */ }
  }

  // POST /api/payment/claim { ref_suffix, mobile_number, client_mac, ap_mac }
  // and drive the modal states. The device context is sent with the claim so the
  // backend can authorize THIS device directly (no code to type).
  //
  // Response handling is deliberately tolerant, because the backend can answer
  // in four ways:
  //   authorized:true  — the MAC is online, so there is no code to show
  //   voucherCode only — claimed, but not auto-authorized (no MAC context);
  //                      fall back to the manual code flow
  //   error            — a real failure, shown on the error step. A refused
  //                      Omada authorization is reported here and consumes
  //                      nothing, so the same digits can simply be retried.
  //   not JSON at all  — the host or a proxy answered with something other than
  //                      the claim API's JSON (a suspended service, a gateway
  //                      error page, a captive-portal interception). That is NOT
  //                      "payment not found": the claim may never have reached
  //                      the backend, so it is reported as a payment server that
  //                      did not answer, not as an unverifiable payment.
  function submitClaim() {
    if (claimState.submitting) return;

    var input = claimEl('claim-ref-input');
    var suffix = input ? String(input.value || '').replace(/\D/g, '') : '';

    // Client-side rule: exactly 4 digits (mirrors the backend validation).
    if (suffix.length !== 4) {
      setClaimError('Enter the last 4 digits of your reference number.');
      if (input) input.focus();
      return;
    }

    // Client-side rule: 11 digits, PH format (mirrors the backend validation).
    var mobileInput = claimEl('claim-mobile-input');
    var mobile = mobileInput ? String(mobileInput.value || '').replace(/\D/g, '') : '';
    if (!/^09\d{9}$/.test(mobile)) {
      setMobileError('Enter your 11-digit mobile number (e.g. 09171234567).');
      if (mobileInput) mobileInput.focus();
      return;
    }
    setMobileError('');

    claimState.submitting = true;
    setClaimError('');
    showClaimStep('loading');

    var verifyBtn = claimEl('claim-verify');
    var verifyLabel = claimEl('claim-verify-label');
    var verifySpinner = claimEl('claim-verify-spinner');
    if (verifyBtn) { verifyBtn.disabled = true; verifyBtn.setAttribute('aria-busy', 'true'); }
    if (verifyLabel) verifyLabel.textContent = 'Verifying\u2026';
    if (verifySpinner) show(verifySpinner);

    // Device context from localStorage (see getDeviceContext). Fields are only
    // sent when known, so an unknown context never overwrites a better one the
    // backend already captured from /api/payment/context.
    var device = getDeviceContext();
    var claimBody = { ref_suffix: suffix, mobile_number: mobile };
    if (device.clientMac) claimBody.client_mac = device.clientMac;
    if (device.apMac) claimBody.ap_mac = device.apMac;

    fetch((CONFIG.apiBaseUrl || '') + '/api/payment/claim', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(claimBody)
    }).then(function (r) {
      // A body that is not JSON is a server/host problem, not a verdict on the
      // payment — keep that distinction instead of collapsing it into {}.
      return r.json().then(
        function (data) { return { ok: r.ok, status: r.status, data: data, json: true }; },
        function () { return { ok: r.ok, status: r.status, data: {}, json: false }; }
      );
    }).then(function (res) {
      var data = res.data || {};
      if (!res.json) {
        showClaimFailure(
          'The payment server did not answer properly (HTTP ' + res.status + '). ' +
          'Your payment may still be fine \u2014 please tap Try Again in a moment.'
        );
      } else if (res.ok && data.success && data.authorized) {
        // Remember the device before the hand-off to success.html / status.html.
        rememberDeviceIdentity();
        showClaimAuthorized();
      } else if (data.voucherCode) {
        // Claimed but not auto-authorized (the guest still connects manually).
        // The device is still known here, so the status page gets the same help.
        rememberDeviceIdentity();
        showClaimSuccess(data.voucherCode);
      } else {
        showClaimFailure(data.error || 'We could not verify that payment. Please check the digits and try again.');
      }
    }).catch(function () {
      showClaimFailure('The network could not be reached. Please check your connection and try again.');
    });
  }

  function claimClearBusy() {
    var verifyBtn = claimEl('claim-verify');
    var verifyLabel = claimEl('claim-verify-label');
    var verifySpinner = claimEl('claim-verify-spinner');
    if (verifyBtn) { verifyBtn.disabled = false; verifyBtn.removeAttribute('aria-busy'); }
    if (verifyLabel) verifyLabel.textContent = 'Connect & Send Status Link';
    if (verifySpinner) hide(verifySpinner);
  }

  function showClaimSuccess(voucherCode) {
    claimState.submitting = false;
    claimState.voucherCode = voucherCode;
    var codeEl = claimEl('claim-voucher-code');
    if (codeEl) codeEl.textContent = voucherCode;
    claimClearBusy();
    showClaimStep('success');
  }

  // Hand the guest to the success page. No query string is needed: the device
  // is identified server-side by its address, so there is no voucher code or
  // session id to carry through the MAC-direct flow.
  function goToSuccessPage() {
    if (claimState.redirectTimer) {
      window.clearTimeout(claimState.redirectTimer);
      claimState.redirectTimer = null;
    }
    window.location.href = 'success.html';
  }

  // Auto-authorized: the backend authorized this device's MAC, so there is no
  // code to display, copy, or re-enter — the guest is already online.
  function showClaimAuthorized() {
    claimState.submitting = false;
    claimState.voucherCode = null;
    claimClearBusy();
    showClaimStep('authorized');
    // Leave the confirmation up long enough to read, then continue to the
    // success page. The Done button (the relabelled Cancel) does it at once.
    claimState.redirectTimer = window.setTimeout(goToSuccessPage, CLAIM_SUCCESS_REDIRECT_MS);
  }

  function showClaimFailure(message) {
    claimState.submitting = false;
    var errText = claimEl('claim-error-text');
    if (errText) errText.textContent = message || 'Something went wrong. Please try again.';
    claimClearBusy();
    showClaimStep('error');
  }

  // "Connect Now" — reuse the EXISTING voucher authentication pipeline by
  // dropping the claimed code into the main form and submitting it. This runs
  // the same validation / terms check / Omada authorization as manual entry,
  // so the connection logic is never duplicated here.
  function connectClaimVoucher() {
    if (!claimState.voucherCode) return;

    var form = document.querySelector('form.auth-form');
    var voucherInput = $('voucher-input');
    if (!form || !voucherInput) {
      closeClaimModal();
      setBanner('Could not start the connection. Please enter your voucher code manually.', 'error');
      return;
    }

    // Clear any lingering plan selection so the form authenticates the voucher
    // instead of redirecting to a payment plan.
    var planInput = form.querySelector('input[name="selectedPlan"]');
    if (planInput) form.removeChild(planInput);
    var voucherGroup = voucherInput.closest ? voucherInput.closest('.form-group') : null;
    if (voucherGroup) voucherGroup.classList.remove('hidden');

    voucherInput.value = sanitizeVoucherCode(claimState.voucherCode);
    setError('voucher-input', '');
    setFormError('');

    closeClaimModal();

    // requestSubmit() fires the submit event so the existing handleSubmit
    // pipeline runs (it calls preventDefault, so no navigation happens here).
    if (typeof form.requestSubmit === 'function') {
      form.requestSubmit();
    } else {
      form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
    }
  }

  function initClaimModal() {
    var modal = claimEl('claim-modal');
    if (!modal) return;

    var openBtn = $('claim-voucher-btn');
    var closeBtn = claimEl('claim-modal-close');
    var cancelBtn = claimEl('claim-cancel');
    var verifyBtn = claimEl('claim-verify');
    var retryBtn = claimEl('claim-retry');
    var connectBtn = claimEl('claim-connect');
    var input = claimEl('claim-ref-input');

    if (openBtn) openBtn.addEventListener('click', openClaimModal);
    if (closeBtn) closeBtn.onclick = closeClaimModal;
    if (cancelBtn) cancelBtn.onclick = function () {
      // In the auto-authorized state this footer button is labelled "Done":
      // the device is already online, so it continues to the success page
      // instead of dismissing the modal back to the voucher form.
      if (claimState.step === 'authorized') { goToSuccessPage(); return; }
      closeClaimModal();
    };
    if (verifyBtn) verifyBtn.onclick = submitClaim;
    if (connectBtn) connectBtn.onclick = connectClaimVoucher;

    // Error state "Try Again": return to the input step with the digits
    // preserved so the customer can correct them and resubmit.
    if (retryBtn) retryBtn.onclick = function () {
      var errText = claimEl('claim-error-text');
      if (errText) errText.textContent = '';
      setClaimError('');
      showClaimStep('input');
    };

    // "Saan makikita ang Reference No.?" — toggle the screenshot cheat sheet
    // that shows where the reference number sits in a GCash / Maya receipt.
    var guideBtn = claimEl('show-ref-guide-btn');
    var guideContainer = claimEl('ref-guide-container');
    if (guideBtn && guideContainer) {
      guideBtn.addEventListener('click', function () {
        if (guideContainer.classList.contains('hidden')) {
          show(guideContainer);
          guideBtn.textContent = 'Itago ang guide';
        } else {
          hide(guideContainer);
          guideBtn.textContent = 'Saan makikita ang Reference No.?';
        }
      });
    }

    // Click on the dimmed overlay (outside the dialog) closes the modal
    modal.addEventListener('click', function (e) {
      if (e.target === modal) closeClaimModal();
    });

    if (input) {
      // Numeric only, exactly 4 digits.
      input.addEventListener('input', function () {
        input.value = input.value.replace(/\D/g, '').slice(0, 4);
        setClaimError('');
      });
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          submitClaim();
        }
      });
      // Accepting a full reference number pasted from an SMS / receipt: keep
      // only the last 4 digits so the customer does not have to trim it.
      input.addEventListener('paste', function (e) {
        e.preventDefault();
        var pasted = (e.clipboardData || window.clipboardData).getData('text') || '';
        var digits = String(pasted).replace(/\D/g, '');
        if (digits.length >= 4) digits = digits.slice(-4);
        e.target.value = digits;
        setClaimError('');
      });
    }

    var mobileInput = claimEl('claim-mobile-input');
    if (mobileInput) {
      // Numeric only, exactly 11 digits.
      mobileInput.addEventListener('input', function () {
        mobileInput.value = mobileInput.value.replace(/\D/g, '').slice(0, 11);
        setMobileError('');
      });
      mobileInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          submitClaim();
        }
      });
    }

    document.addEventListener('keydown', function (e) {
      if (!claimState.open) return;
      if (e.key === 'Escape') { e.preventDefault(); closeClaimModal(); }
    });
  }

  // ===============================================================
  // CHECK VOUCHER STATUS / RECONNECT MODAL
  // ===============================================================
  // Works for a guest who is OFFLINE (or whose Wi-Fi just dropped) and only
  // has the printed code in hand: GET /api/session/status?voucher=<code>
  // reports the time left on that code, and the dialog also carries the
  // reconnect steps. Nothing here grants access — the checker is read-only,
  // and re-opening the firewall is what attemptAutoReconnect()/the voucher
  // form already do.
  var statusState = {
    open: false,
    checking: false,
    lastFocus: null
  };

  // "1h 30m" / "45m" / "30s" — the modal reports time in hours/minutes, not
  // the m:ss the cash-payment countdown uses.
  function formatRemainingLong(seconds) {
    var total = Math.max(0, Math.floor(Number(seconds) || 0));
    var hours = Math.floor(total / 3600);
    var mins = Math.floor((total % 3600) / 60);
    if (hours > 0 && mins > 0) return hours + 'h ' + mins + 'm';
    if (hours > 0) return hours + 'h';
    if (mins > 0) return mins + 'm';
    return total + 's';
  }

  // Show a line in #status-result-box. `tone` picks the theme colour:
  // 'success' (green), 'error' (red), 'warning' (amber), 'info' (brown).
  function setStatusResult(message, tone) {
    var box = $('status-result-box');
    if (!box) return;
    if (!message) {
      box.textContent = '';
      box.style.color = '';
      hide(box);
      return;
    }
    var colors = {
      success: 'var(--green)',
      error: 'var(--error-text)',
      warning: 'var(--warning-text)',
      info: 'var(--text-2)'
    };
    box.textContent = message;
    box.style.color = colors[tone] || colors.info;
    show(box);
  }

  function setStatusInputError(message) {
    var errEl = $('status-input-error');
    if (errEl) {
      if (message) { errEl.textContent = message; show(errEl); }
      else { errEl.textContent = ''; hide(errEl); }
    }
    var input = $('status-voucher-input');
    if (input) {
      if (message) input.classList.add('is-error');
      else input.classList.remove('is-error');
    }
  }

  function openStatusModal() {
    var modal = $('status-modal');
    if (!modal) return;
    statusState.lastFocus = document.activeElement;
    statusState.checking = false;

    var input = $('status-voucher-input');
    if (input) { input.value = ''; input.classList.remove('is-error'); }
    setStatusInputError('');
    setStatusResult('');

    show(modal);
    statusState.open = true;
    modal.focus();

    // Hide the page-level banner so the modal is the only message on screen.
    setBanner('');

    var submitBtn = $('check-status-submit');
    if (submitBtn) { submitBtn.disabled = false; submitBtn.removeAttribute('aria-busy'); }

    if (input) setTimeout(function () { input.focus(); }, 60);
  }

  function closeStatusModal() {
    if (!statusState.open) return;
    var modal = $('status-modal');
    if (modal) hide(modal);
    statusState.open = false;
    var focusTarget = statusState.lastFocus;
    statusState.lastFocus = null;
    if (focusTarget && typeof focusTarget.focus === 'function') {
      setTimeout(function () { focusTarget.focus(); }, 60);
    }
  }

  // Map a successful payload onto the result line. The backend distinguishes
  // an unused voucher (full duration still due), a live/paused session, and a
  // fully consumed one ({ active: false, error: 'EXPIRED' }).
  function renderVoucherStatus(data) {
    var remaining = formatRemainingLong(data.remainingSeconds);

    if (data.active) {
      if (data.state === 'active') {
        return setStatusResult(
          'Active session: ' + remaining + ' left. Nawala ang Wi-Fi? I-OFF at I-ON lang ang Wi-Fi para bumalik.',
          'success'
        );
      }
      if (data.state === 'paused') {
        return setStatusResult(
          'Session is paused \u2014 ' + remaining + ' left when you resume.',
          'success'
        );
      }
      if (data.state === 'pending_payment' || data.state === 'pending_verification') {
        return setStatusResult(
          'Payment confirmed \u2014 your ' + remaining + ' of internet starts when you connect.',
          'success'
        );
      }
      return setStatusResult(
        'Voucher is still valid \u2014 ' + remaining + ' of internet available.',
        'success'
      );
    }

    return setStatusResult(
      'This voucher has been fully used or has expired.',
      'error'
    );
  }

  // GET /api/session/status?voucher=<code> — native fetch, same shape as the
  // other portal calls (see attemptAutoReconnect / submitClaim).
  function checkVoucherStatus() {
    if (statusState.checking) return;

    var input = $('status-voucher-input');
    var raw = input ? input.value : '';

    // Reuse the shared 6-digit rule (validateVoucher) rather than a new one.
    var check = validateVoucher(raw);
    if (!check.ok) {
      setStatusInputError(check.message);
      setStatusResult('');
      if (input) input.focus();
      return;
    }

    statusState.checking = true;
    setStatusInputError('');
    setStatusResult('Checking\u2026', 'info');

    var submitBtn = $('check-status-submit');
    if (submitBtn) { submitBtn.disabled = true; submitBtn.setAttribute('aria-busy', 'true'); }

    fetch((CONFIG.apiBaseUrl || '') + '/api/session/status?voucher=' + encodeURIComponent(check.value), {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      credentials: 'same-origin'
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        return { ok: r.ok, status: r.status, data: data };
      });
    }).then(function (res) {
      var data = res.data || {};

      if (res.status === 404) {
        setStatusResult('Voucher code not found. Please check the 6 digits and try again.', 'error');
        return;
      }
      if (res.status === 400) {
        setStatusResult(data.error || 'Please enter a valid 6-digit voucher code.', 'error');
        return;
      }
      if (!res.ok || !data.success) {
        setStatusResult('Temporary connection error. Please wait a moment and try again.', 'warning');
        return;
      }
      renderVoucherStatus(data);
    }).catch(function () {
      setStatusResult('Temporary connection error. Please wait a moment and try again.', 'warning');
    }).then(function () {
      statusState.checking = false;
      var btn = $('check-status-submit');
      if (btn) { btn.disabled = false; btn.removeAttribute('aria-busy'); }
    });
  }

  function initVoucherStatusModal() {
    var modal = $('status-modal');
    if (!modal) return;

    var openBtn = $('open-status-modal-btn');
    var closeBtn = $('status-modal-close');
    var submitBtn = $('check-status-submit');
    var input = $('status-voucher-input');

    if (openBtn) openBtn.addEventListener('click', openStatusModal);
    if (closeBtn) closeBtn.onclick = closeStatusModal;
    if (submitBtn) submitBtn.addEventListener('click', checkVoucherStatus);

    // Click on the dimmed overlay (outside the dialog) closes the modal.
    modal.addEventListener('click', function (e) {
      if (e.target === modal) closeStatusModal();
    });

    if (input) {
      // Numeric only, at most 6 digits — mirrors the voucher input on the form.
      input.addEventListener('input', function () {
        input.value = input.value.replace(/\D/g, '').slice(0, 6);
        setStatusInputError('');
      });
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          checkVoucherStatus();
        }
      });
    }

    document.addEventListener('keydown', function (e) {
      if (!statusState.open) return;
      if (e.key === 'Escape') { e.preventDefault(); closeStatusModal(); }
    });
  }

  // Keep keyboard focus inside the dialog while it is open.
  function qrFocusable() {
    var overlay = qrEl('payment-qr-modal');
    if (!overlay) return [];
    var nodes = overlay.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])');
    var visible = [];
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].offsetParent !== null) visible.push(nodes[i]);
    }
    return visible;
  }

  function qrOnKeydown(e) {
    if (!qrState.open) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      qrClose();
      return;
    }
    if (e.key === 'Tab') {
      var focusables = qrFocusable();
      if (!focusables.length) return;
      var first = focusables[0];
      var last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  function initPaymentQrModal() {
    var overlay = qrEl('payment-qr-modal');
    if (!overlay) return;

    var closeBtn = qrEl('qr-modal-close');
    var cancelBtn = qrEl('qr-cancel');

    if (closeBtn) closeBtn.onclick = function () { qrClose(); };
    if (cancelBtn) cancelBtn.onclick = function () { qrClose(); };

    // Click on the dimmed overlay (outside the dialog) closes the modal
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) qrClose();
    });

    document.addEventListener('keydown', qrOnKeydown);
  }

  // ===============================================================
  // INIT
  // ===============================================================
  // PRICING SECTION CLOSE BUTTON
  // ===============================================================
  function initPricingClose() {
    var closeBtn = $('pricing-close');
    var pricingSection = document.querySelector('.pricing-section');
    var loginCard = document.querySelector('.login-card');
    if (!closeBtn || !pricingSection) return;

    closeBtn.addEventListener('click', function () {
      // Hide the whole plan selection view (pricing + payment tiles)
      hide(pricingSection);
      var paymentSection = document.querySelector('.payment-method-section');
      if (paymentSection) hide(paymentSection);
      // Clear any in-progress plan selection
      var selected = document.querySelector('.pricing-tier.is-selected');
      if (selected) selected.classList.remove('is-selected');
      var planModal = $('plan-modal');
      if (planModal && !planModal.classList.contains('hidden')) hide(planModal);
      // Show a way back in
      var viewPlans = document.querySelector('.view-plans-wrap');
      if (viewPlans) show(viewPlans);
      // Scroll back to the voucher login form
      if (loginCard) loginCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  function initViewPlansButton() {
    var viewPlansWrap = document.querySelector('.view-plans-wrap');
    var viewPlans = $('view-plans-btn');
    var pricingSection = document.querySelector('.pricing-section');
    if (!viewPlansWrap || !viewPlans || !pricingSection) return;

    viewPlans.addEventListener('click', function () {
      show(pricingSection);
      var paymentSection = document.querySelector('.payment-method-section');
      if (paymentSection) show(paymentSection);
      hide(viewPlansWrap);
      pricingSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  // ===============================================================
  // AUTO-RECONNECT ON LOAD (MAC-based, no voucher re-entry)
  // ===============================================================
  // A device whose session is still live but whose firewall authorization was
  // lost (Wi-Fi dropped, captive mini-browser reopened, OS re-probe) is
  // silently re-authorized by MAC so the guest reconnects WITHOUT re-entering a
  // voucher. The controller call is proxied by the backend (backend mode only);
  // a 404 (no active session) falls through to the normal voucher form.
  function attemptAutoReconnect() {
    if (CONFIG.mockMode || CONFIG.mode !== 'backend') return;

    var clientMac = queryParams.clientMac;
    if (!clientMac) return;

    fetch((CONFIG.apiBaseUrl || '') + '/api/session/reauthorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({
        clientMac: normalizeMac(clientMac) || clientMac,
        apMac:     normalizeMac(queryParams.apMac) || queryParams.apMac || '',
        ssidName:  queryParams.ssidName || '',
        radioId:   queryParams.radioId,
      }),
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        return { ok: r.ok, data: data };
      });
    }).then(function (res) {
      var data = res.data || {};
      if (!res.ok || !data.success || !data.sessionId) {
        // 404 / not active / anything else → fall through to voucher entry.
        return;
      }

      // Persist the identifiers so status.html can recover the session after
      // the redirect, even if it is opened later without query params.
      try {
        window.localStorage.setItem('portalSessionId', data.sessionId);
        window.sessionStorage.setItem('portalSessionId', data.sessionId);
        window.localStorage.setItem(
          'portalClientMac',
          normalizeMac(clientMac) || clientMac
        );
      } catch (e) { /* storage unavailable — URL param still works */ }

      setBanner('Active session detected, reconnecting\u2026', 'info');

      var params = new URLSearchParams();
      params.set('sessionId', data.sessionId);
      params.set('clientMac', normalizeMac(clientMac) || clientMac);
      // Remaining/expiry come straight from the re-authorized session so the
      // success page's countdown matches the database instead of showing “—”.
      if (data.expiresAt) params.set('expiresAt', data.expiresAt);
      if (typeof data.remainingSeconds === 'number') {
        params.set('remaining', String(data.remainingSeconds));
      }
      if (data.voucherType) params.set('voucherType', data.voucherType);
      params.set('countdown', '3');
      var target = (CONFIG.successPage || 'success.html') + '?' + params.toString();

      // Reuse the post-auth settling delay so Omada's asynchronous firewall
      // programming finishes before the OS re-probes the network.
      var delayMs = (typeof CONFIG.connectDelayMs === 'number') ? CONFIG.connectDelayMs : 3500;
      window.setTimeout(function () { window.location.href = target; }, delayMs);
    }).catch(function () { /* silent — the voucher form still works */ });
  }

  function init() {
    // Parse Omada query params first (affects everything)
    parseQueryParams();

    // Capture + persist the Omada context (clientMac / apMac / ssidName)
    // immediately, before anything below reads it: a refresh or a re-opened
    // tab arrives without query params, and localStorage is what keeps the
    // device identifiable for the backend's later authorization call.
    captureOmadaContext();

    // Silent reconnection: if the controller gave us a clientMac and an active
    // session still exists for it, re-open the firewall and hand off to
    // success.html without asking for a voucher again.
    attemptAutoReconnect();

    // Fire-and-forget context capture: on portal LANDING, beacon the
    // controller context (client/AP MAC, SSID, radioId) to the backend so
    // the later payment webhook can authorize this device via
    // /hotspot/extPortal/auth even if the client is offline at payment
    // time. Never blocks or breaks the portal UI — failures are silent
    // here; the webhook fails loud (MISSING_PORTAL_CONTEXT) instead.
    sendContextBeacon();

    // Apply brand theming
    applyTheming();

    // Set up terms visibility
    initTermsSection();

    // Set up pricing table select buttons
    initPricingTable();

    // Set up pricing section close button + view-plans toggle
    initPricingClose();
    initViewPlansButton();

    // Set up payment tile interactions
    initPaymentTiles();

    // Set up the GCash / Maya / QR Ph payment modal
    initPaymentQrModal();

    // Set up the centralized Claim Voucher modal
    initClaimModal();

    // Set up the Check Voucher Status / Reconnect modal
    initVoucherStatusModal();

    // Input UX
    initInputEnhancements();

    // Form submission
    var form = document.querySelector('form.auth-form');
    if (form) {
      form.addEventListener('submit', handleSubmit);
    }

    // Prefill hint: if SSID is known, show it
    if (queryParams.ssidName && $('card-subtitle')) {
      $('card-subtitle').textContent = 'Connect to ' + queryParams.ssidName;
    }

    // Mock mode banner
    if (CONFIG.mockMode) {
      setBanner('Mock mode enabled — authentication is simulated.', 'info');
    }

        // Show connection instructions if redirected from cash payment flow
    showConnectionInstructions();
  }

  // ── Start ───────────────────────────────────────────────────
  init();

})();


  
