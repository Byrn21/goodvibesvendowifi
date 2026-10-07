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
    paramMap: {
      clientMac:   'clientMac',
      clientIp:    'clientIp',
      apMac:       'apMac',
      ssidName:    'ssidName',
      radioId:     'radioId',
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

        // Check if we're in paid/backend mode with plan selection
    var selectedType = getSelectedVoucherType();

    // Check for pricing table selection
    var pricingPlan = null;
    var pricingInput = document.querySelector('input[name="selectedPlan"]');
    if (pricingInput && pricingInput.value) {
      try {
        pricingPlan = JSON.parse(pricingInput.value);
      } catch (e) {
        pricingPlan = null;
      }
    }

    // ---- Paid mode: redirect to payment checkout ----
    if (CONFIG.mode === 'backend' && selectedType && selectedType.tier) {
      var checkoutUrl = (CONFIG.apiBaseUrl || '') + '/api/payment/initiate?' + [
        'voucherType=' + encodeURIComponent(selectedType.tier),
        'planId=' + encodeURIComponent(selectedType.planId),
        'plan=' + encodeURIComponent($('plan-select').value),
        'clientMac=' + encodeURIComponent(queryParams.clientMac || ''),
        'clientIp=' + encodeURIComponent(queryParams.clientIp || ''),
        'apMac=' + encodeURIComponent(queryParams.apMac || ''),
        'ssidName=' + encodeURIComponent(queryParams.ssidName || ''),
        'radioId=' + encodeURIComponent(queryParams.radioId || '0'),
        'redirectUrl=' + encodeURIComponent(getRedirectDestination()),
      ].join('&');

            window.location.href = checkoutUrl;
      return;
    }

    // ---- Pricing table selection: redirect to payment checkout ----
    if (pricingPlan && pricingPlan.tier) {
      var pricingCheckoutUrl = (CONFIG.apiBaseUrl || '') + '/api/payment/initiate?' + [
        'voucherType=' + encodeURIComponent(pricingPlan.tier),
        'planId=' + encodeURIComponent(pricingPlan.planId),
        'duration=' + encodeURIComponent(pricingPlan.duration),
        'price=' + encodeURIComponent(pricingPlan.price),
        'clientMac=' + encodeURIComponent(queryParams.clientMac || ''),
        'clientIp=' + encodeURIComponent(queryParams.clientIp || ''),
        'apMac=' + encodeURIComponent(queryParams.apMac || ''),
        'ssidName=' + encodeURIComponent(queryParams.ssidName || ''),
        'radioId=' + encodeURIComponent(queryParams.radioId || '0'),
        'redirectUrl=' + encodeURIComponent(getRedirectDestination()),
      ].join('&');

      window.location.href = pricingCheckoutUrl;
      return;
    }

    // ---- Voucher validation ----
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
      clientMac: normalizeMac(queryParams.clientMac) || queryParams.clientMac || '',
      clientIp:  queryParams.clientIp  || '',
      apMac:     normalizeMac(queryParams.apMac) || queryParams.apMac || '',
      ssidName:  queryParams.ssidName  || '',
      redirectUrl: getRedirectDestination(),
      authUrl:   queryParams.authUrl   || '',
      raw:       queryParams.raw       || {},
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
        body: JSON.stringify({
          voucher: ctx.voucher,
          clientMac: ctx.clientMac,
          clientIp:  ctx.clientIp,
          apMac:     ctx.apMac,
          ssidName:  ctx.ssidName,
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
    } catch (e) { /* storage unavailable — URL param still works */ }

    // Build success URL with redirect and session info
    var params = new URLSearchParams();
    if (result.redirectUrl) params.set('redirectUrl', encodeURIComponent(result.redirectUrl));
    if (result.sessionId)   params.set('sessionId', result.sessionId);
    params.set('countdown', '3');

    window.location.href = CONFIG.successPage + '?' + params.toString();
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
      CONFIG_ERROR:    'Portal configuration error. Please contact support.',
      AUTH_FAILED:     'Authentication failed. Please check your voucher and try again.',
    };

    var publicMsg = SAFE_MESSAGES[code] || SAFE_MESSAGES.AUTH_FAILED;

    setFormError(publicMsg);

    // If it's a voucher-specific error, highlight the field
    if (code === 'INVALID_VOUCHER' || code === 'EXPIRED_VOUCHER' || code === 'USED_VOUCHER') {
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
  // PLAN SELECTOR (paid mode)
  // ===============================================================
     function initPlanSelector() {
    var typeSection = $('voucher-type-section');
    var typeSelect = $('voucher-type-select');
    var planSection = $('plan-section');
    var planSelect = $('plan-select');
    if (!typeSection || !typeSelect || !planSection || !planSelect) return;

    // Paid plans only visible in backend mode with plans configured
    if (CONFIG.mode !== 'backend' || !CONFIG.plans || (!CONFIG.plans.standard && !CONFIG.plans.premium)) {
      return;
    }

    show(typeSection);
    show(planSection);

    // Populate the type selector with standard plans
    populateTypeSelect('standard');

    // When type changes, repopulate plan options
    typeSelect.addEventListener('change', function () {
      var selectedType = typeSelect.value.startsWith('premium') ? 'premium' : 'standard';
      populateTypeSelect(selectedType);
      var submitLabel = $('submit-label');
      if (submitLabel) {
        submitLabel.textContent = (planSelect.value && typeSelect.value) ? 'Pay & Connect' : 'Connect Now';
      }
    });

    // When plan changes, update submit button label
    planSelect.addEventListener('change', function () {
      var submitLabel = $('submit-label');
      if (submitLabel) {
        submitLabel.textContent = (planSelect.value && typeSelect.value) ? 'Pay & Connect' : 'Connect Now';
      }
    });
  }

  function populateTypeSelect(type) {
    var planSelect = $('plan-select');
    if (!planSelect) return;

    // Clear existing options
    planSelect.innerHTML = '<option value="">— Choose a plan —</option>';

    var plans = (CONFIG.plans[type] || []).slice();
    plans.forEach(function (plan) {
      var opt = document.createElement('option');
      opt.value = plan.duration; // minutes
      opt.textContent = plan.label + ' — ' + formatPrice(plan.price);
      planSelect.appendChild(opt);
    });
  }

  // Return the selected voucherType prefix (standard or premium)
  function getSelectedVoucherType() {
    var typeSelect = $('voucher-type-select');
    var planSelect = $('plan-select');
    if (!typeSelect || !planSelect) return null;
    if (!typeSelect.value || !planSelect.value) return null;

    // The typeSelect value is like "standard-1h" or "premium-5h"
    var parts = typeSelect.value.split('-');
    var tier = parts[0]; // "standard" or "premium"
    var planId = typeSelect.value; // full ID like "premium-5h"
    return { tier: tier, planId: planId };
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

        // Hide the voucher form, show payment section
        var voucherSection = $('voucher-input') ? $('voucher-input').closest('.form-group') : null;
        var paymentSection = document.querySelector('.payment-section');
        var formError = $('form-error');

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

        // Hide voucher input if present
        if (voucherSection) {
          voucherSection.classList.add('hidden');
        }

        // Clear any form errors
        setFormError('');
        setBanner('');

                // Show payment tiles section
        if (paymentSection) {
          paymentSection.classList.add('payment-section--visible');
        }

        // Update submit button label
        var submitLabel = $('submit-label');
        if (submitLabel) {
          submitLabel.textContent = 'Pay & Connect';
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

        // Re-enable the voucher section
        var voucherSection = $('voucher-input') ? $('voucher-input').closest('.form-group') : null;
        if (voucherSection) {
          voucherSection.classList.remove('hidden');
        }

                // Hide payment section
        var paymentSection = document.querySelector('.payment-section');
        if (paymentSection) {
          paymentSection.classList.remove('payment-section--visible');
        }

        // Reset submit button label
        var submitLabel = $('submit-label');
        if (submitLabel) {
          submitLabel.textContent = 'Connect Now';
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
  // The pricing table stores a JSON snapshot; the plan <select> maps back
  // to CONFIG.plans. Returns null when no plan has been chosen.
  function getSelectedPlanAmountCents() {
    var pricingInput = document.querySelector('input[name="selectedPlan"]');
    if (pricingInput && pricingInput.value) {
      try {
        var parsed = JSON.parse(pricingInput.value);
        if (parsed && parsed.price !== undefined && parsed.price !== null) {
          return Number(parsed.price);
        }
      } catch (e) { /* fall through to plan select */ }
    }
    var selectedType = getSelectedVoucherType();
    if (selectedType && selectedType.tier && CONFIG.plans) {
      var plans = CONFIG.plans[selectedType.tier] || [];
      for (var i = 0; i < plans.length; i++) {
        if (plans[i].id === selectedType.planId) return Number(plans[i].price);
      }
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
  // the last 4 digits of their reference number. No MAC/device binding is
  // involved — the returned voucher code is fed into the existing voucher
  // authentication form (see connectClaimVoucher).
  var claimState = {
    open: false,
    submitting: false,
    voucherCode: null,
    lastFocus: null
  };

  function claimEl(id) { return document.getElementById(id); }

  // Show exactly one of the modal's states (input / loading / success / error)
  // and align the footer buttons with it.
  function showClaimStep(step) {
    var steps = {
      input: claimEl('claim-step-input'),
      loading: claimEl('claim-step-loading'),
      success: claimEl('claim-step-success'),
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
    if (step === 'success') {
      if (verifyBtn) hide(verifyBtn);
      if (retryBtn) hide(retryBtn);
      if (connectBtn) show(connectBtn);
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

  // Reset the modal to its initial input state (called every time it opens).
  function resetClaimModal() {
    claimState.submitting = false;
    claimState.voucherCode = null;

    var input = claimEl('claim-ref-input');
    if (input) { input.value = ''; input.disabled = false; input.classList.remove('is-error'); }
    setClaimError('');

    var errText = claimEl('claim-error-text');
    if (errText) errText.textContent = '';
    var codeEl = claimEl('claim-voucher-code');
    if (codeEl) codeEl.textContent = '';

    var verifyBtn = claimEl('claim-verify');
    var verifyLabel = claimEl('claim-verify-label');
    var verifySpinner = claimEl('claim-verify-spinner');
    if (verifyBtn) { verifyBtn.disabled = false; verifyBtn.removeAttribute('aria-busy'); }
    if (verifyLabel) verifyLabel.textContent = 'Verify Payment';
    if (verifySpinner) hide(verifySpinner);

    var connectBtn = claimEl('claim-connect');
    if (connectBtn) connectBtn.disabled = false;

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

  // POST /api/payment/claim { ref_suffix } and drive the modal states.
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

    claimState.submitting = true;
    setClaimError('');
    showClaimStep('loading');

    var verifyBtn = claimEl('claim-verify');
    var verifyLabel = claimEl('claim-verify-label');
    var verifySpinner = claimEl('claim-verify-spinner');
    if (verifyBtn) { verifyBtn.disabled = true; verifyBtn.setAttribute('aria-busy', 'true'); }
    if (verifyLabel) verifyLabel.textContent = 'Verifying\u2026';
    if (verifySpinner) show(verifySpinner);

    fetch((CONFIG.apiBaseUrl || '') + '/api/payment/claim', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ ref_suffix: suffix })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        return { ok: r.ok, data: data };
      });
    }).then(function (res) {
      var data = res.data || {};
      if (res.ok && data.success && data.voucherCode) {
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
    if (verifyLabel) verifyLabel.textContent = 'Verify Payment';
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
    if (cancelBtn) cancelBtn.onclick = closeClaimModal;
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
    }

    document.addEventListener('keydown', function (e) {
      if (!claimState.open) return;
      if (e.key === 'Escape') { e.preventDefault(); closeClaimModal(); }
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

  function init() {
    // Parse Omada query params first (affects everything)
    parseQueryParams();

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

    // Set up plan selector (paid mode)
    initPlanSelector();

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


  
