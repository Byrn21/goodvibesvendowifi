/**
 * config.js â€” GoodVibesVendoWifi Captive Portal Frontend Configuration
 *
 * Copy this file to config/config.js (keep config.example.js as a template).
 *
 * SECRETS AND CREDENTIALS MUST NEVER BE PLACED IN THIS FILE.
 * This file ships inside portal-upload.zip.
 */

(function () {
  'use strict';

  window.CONFIG = {

    // ==============================================================
    // BRANDING â€” GoodVibesVendoWifi
    // ==============================================================
    brandName: 'GoodVibesVendoWifi',
    brandTagline: 'Connect to our Guest Network',
    logoUrl: 'assets/images/logo.svg',
    primaryColor: '#2d6a4f',
    accentColor: '#e9f5db',
    textColor: '#2c1810',
    // Left empty on purpose: the real address is injected at build time by
    // inject-secrets.js (SUPPORT_EMAIL), so it is never committed here.
    supportEmail: '',
    supportPhone: '',

    // ==============================================================
    // AUTHENTICATION MODE â€” backend mode (voucher-based)
    // ==============================================================
    mode: 'backend',

    // ==============================================================
    // BACKEND MODE
    // ==============================================================
    // Base URL of your backend server (no trailing slash)
    // Update this when you deploy to Render:
    // e.g. https://goodvibesvendowifi.onrender.com
    apiBaseUrl: 'https://goodvibesvendowifi.onrender.com',

    // ==============================================================
    // VOUCHER VALIDATION
    // ==============================================================
    // RULE: exactly 6 numeric digits (matches backend/src/utils/voucher-code.js).
    // Keep all three in sync if this ever changes.
    voucher: {
      required: true,
      minLength: 6,
      maxLength: 6,
      pattern: /^\d{6}$/,
      patternHint: 'Voucher code must be exactly 6 digits.',
    },

    // ==============================================================
    // REDIRECT ALLOWLIST
    // ==============================================================
    allowedRedirectDomains: [
      'goodvibesvendowifi.com',
      'captive.apple.com',
      'connectivitycheck.gstatic.com',
    ],

    defaultRedirectUrl: 'https://www.google.com',

    // ==============================================================
    // TERMS AND CONDITIONS
    // ==============================================================
    termsRequired: true,
    termsUrl: '#terms',
    privacyUrl: '#privacy',

    // ==============================================================
    // STATUS PAGE
    // ==============================================================
    statusPollingInterval: 30000,
        showPauseResume: true,

    // =============================================================
    // CASH PAYMENT TIMER
    // =============================================================
    cashPayment: {
      // Timer duration in seconds (2 minutes 50 seconds)
      timerSeconds: 170,
      // Page to redirect to when timer expires or voucher claimed
      redirectUrl: 'index.html',
    },
    // ==============================================================
    // PRICING TABLE (pricing plans displayed on portal)
    // =============================================================
    pricingPlans: {
      standard: [
        { id: 'standard-1h',   label: '1 Hour',      duration: 60,    price: 500 },
        { id: 'standard-3h',   label: '3 Hours',     duration: 180,   price: 1000 },
        { id: 'standard-12h',  label: '12 Hours',    duration: 720,   price: 2000 },
        { id: 'standard-1d',   label: '24 Hours',    duration: 1440,  price: 3000 },
        { id: 'standard-7d',   label: '7 Days',      duration: 10080, price: 12000 },
        { id: 'standard-30d',  label: '30 Days',     duration: 43200, price: 35000 },
      ],
      premium: [
        { id: 'premium-5h',   label: '5 Hours (Pausable)',  duration: 300,  price: 2500 },
        { id: 'premium-12h',  label: '12 Hours (Pausable)', duration: 720,  price: 4500 },
        { id: 'premium-24h',  label: '24 Hours (Pausable)', duration: 1440, price: 8000 },
      ],
    },

    // =============================================================
    // DUAL-TIER VOUCHER PRICING
    // ==============================================================
        plans: {
      standard: [
        { id: 'standard-1h',   label: '1 Hour',   duration: 60,   price: 5000 },
        { id: 'standard-2h',   label: '2 Hours',  duration: 120,  price: 10000 },
        { id: 'standard-4h',   label: '4 Hours',  duration: 240,  price: 20000 },
        { id: 'standard-8h',   label: '8 Hours',  duration: 480,  price: 40000 },
        { id: 'standard-12h',  label: '12 Hours', duration: 720,  price: 60000 },
        { id: 'standard-24h',  label: '24 Hours', duration: 1440, price: 120000 },
      ],
      premium: [
        { id: 'premium-5h',  label: '5 Hours',  duration: 300,  price: 37500 },
        { id: 'premium-8h',  label: '8 Hours',  duration: 480,  price: 60000 },
        { id: 'premium-24h', label: '24 Hours', duration: 1440, price: 180000 },
      ],
    },
    premiumModifier: 1.5,
    premiumPauseValidityHours: 168,
    adminPage: 'admin.html',

    // ==============================================================
    // CONTROLLER QUERY PARAMETER MAPPING
    // ==============================================================
    paramMap: {
      clientMac:   'clientMac',
      clientIp:    'clientIp',
      apMac:       'apMac',
      ssidName:    'ssidName',
      redirectUrl: 'redirectUrl',
      originalUrl: 'originalUrl',
      authUrl:     'authUrl',
      targetUrl:   'targetUrl',
    },

    // ==============================================================
    // DEVELOPMENT / TESTING
    // ==============================================================
    mockMode: false,
    mockSuccessDelay: 800,

    // ==============================================================
    // PAGE ROUTES
    // ==============================================================
    successPage: 'success.html',
    errorPage:   'error.html',
    statusPage:  'status.html',

  };

})();


