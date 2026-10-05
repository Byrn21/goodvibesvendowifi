/**
 * config.js â€” Omada Captive Portal Frontend Configuration
 *
 * Copy this file to config/config.js (keep config.example.js as a template).
 *
 * SECRETS AND CREDENTIALS MUST NEVER BE PLACED IN THIS FILE.
 * This file ships inside portal-upload.zip.
 *
 * Values marked âš ï¸ MUST be verified against your specific controller firmware
 * version before deployment. See README.md Â§Controller-Specific Values.
 */

(function () {
  'use strict';

  window.CONFIG = {

    // ==============================================================
    // BRANDING â€” Replace these with your organization's details
    // ==============================================================
    brandName: 'Hotel WiFi Portal',
    brandTagline: 'Connect to our Guest Network',
    // Path relative to index.html. Keep local â€” no external URLs.
    logoUrl: 'assets/images/logo.svg',
    // CSS color value (hex, rgb, hsl)
    primaryColor: '#1a73e8',
    accentColor: '#e8f0fe',
    textColor: '#202124',
    supportEmail: 'support@example.com',
    supportPhone: '+1-555-0100',

    // ==============================================================
    // AUTHENTICATION MODE
    // ==============================================================
    // 'direct'  â€” Form POST directly to the Omada controller extPortal endpoint.
    //              Works for free voucher mode without a backend.
    //              âš ï¸ CORS: Some Omada controllers block cross-origin POSTs.
    //              Prefer 'backend' mode for reliable operation.
    //
    // 'backend' â€” JavaScript fetch() POST to your backend /api/auth.
    //              Backend proxies to Omada. Supports voucher-based sessions.
    mode: 'direct',

    // ==============================================================
    // DIRECT MODE (mode: 'direct')
    // âš ï¸ Verify every value in this section with your controller.
    // ==============================================================

    // The Omada controller's external portal authentication endpoint.
    // Format: https://<controller-ip>:<port>/extPortal/auth
    // Common ports: 8043 (HTTPS), 8080 (HTTP), 8043 (Omada app-based)
    // âš ï¸ Some controllers use /api/v2/extPortal/auth or /extPortal/auth.htm
    authEndpoint: 'https://192.168.1.252:8043/extPortal/auth',

    // HTTP method for the direct POST.
    // 'POST' = application/x-www-form-urlencoded (most common)
    // 'POST_JSON' = application/json (verify your controller supports this)
    authMethod: 'POST',

    // Fixed fields to include in the direct-mode POST body.
    // âš ï¸ These field NAMES vary by Omada version. Common alternatives:
    //   username/password vs. token/mac vs. key/value vs. voucher/token
    //   Always capture a real redirect request to confirm the exact field names.
    authParams: {
      username: 'voucher',   // maps voucher input â†’ body[username]
      password: 'voucher',  // maps voucher input â†’ body[password]
      // clientMac and clientIp are auto-included from query params
      // Add any additional fixed fields your controller requires here
    },

    // ==============================================================
    // BACKEND MODE (mode: 'backend')
    // ==============================================================

    // Base URL of your backend server (no trailing slash)
    apiBaseUrl: 'https://goodvibesvendowifi.onrender.com',

    // ==============================================================
    // VOUCHER VALIDATION (frontend hints only â€” backend enforces)
    // ==============================================================
    voucher: {
      required: true,
      // RULE: exactly 6 numeric digits (matches backend/src/utils/voucher-code.js).
      minLength: 6,
      maxLength: 6,
      pattern: /^\d{6}$/,
      patternHint: 'Voucher code must be exactly 6 digits.',
    },

    // ==============================================================
    // REDIRECT ALLOWLIST
    // After successful auth, users are redirected here.
    // âš ï¸ Must include any domains you want users to reach post-auth.
    //    Empty array = allow any http/https URL (not recommended).
    // ==============================================================
    allowedRedirectDomains: [
      'example.com',
      'google.com',
      'captive.apple.com',
      'connectivitycheck.gstatic.com',
      // Add your actual guest-facing domains here
    ],

    // Fallback destination if no original URL is captured.
    // âš ï¸ Must be a valid https:// URL or localhost for dev.
    defaultRedirectUrl: 'https://www.example.com/welcome',

    // ==============================================================
    // TERMS AND CONDITIONS
    // ==============================================================
    termsRequired: false,
    termsUrl: '#terms',
    privacyUrl: '#privacy',

    // ==============================================================
    // STATUS PAGE
    // ==============================================================
    // How often status.html polls the backend for updates (milliseconds).
    // This is display-only; the backend enforces session expiration.
    statusPollingInterval: 30000,
    // Show pause/resume controls (requires backend session management)
        showPauseResume: true,

    // ===============================================================
    // DUAL-TIER VOUCHER PRICING
    // ===============================================================
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
    // âš ï¸  These are the most common names. Your controller version may differ.
    //      Inspect the actual redirect URL from your AP to confirm.
    //
    // Common variations:
    //   clientMac  â†’ mac, clientmac, usermac, client_mac
    //   clientIp   â†’ ip, clientip, userip, client_ip
    //   apMac      â†’ apmac, acmac, ap_mac
    //   ssidName   â†’ ssid, wlan, ssidname, wlan_name, WLANName
    //   redirectUrlâ†’ redirect, url, target, dst, go, targetUrl, u
    //   Controller-specific tokens may appear as: token, ap_session, sessid, sid
    // ==============================================================
    paramMap: {
      // Our canonical name â†’ Omada parameter name
      clientMac:   'clientMac',
      clientIp:    'clientIp',
      apMac:       'apMac',
      ssidName:    'ssidName',
      redirectUrl: 'redirectUrl',
      originalUrl: 'originalUrl',
      authUrl:     'authUrl',
      targetUrl:   'targetUrl',
      // Uncomment and adjust if your controller uses different names:
      // clientMac:   'mac',
      // redirectUrl: 'url',
      // ssidName:    'ssid',
    },

    // ==============================================================
    // DEVELOPMENT / TESTING
    // ==============================================================
    // Set to true to simulate authentication without a live controller.
    // NEVER enable mockMode in production.
    mockMode: false,
    // Delay (ms) before mock auth resolves
    mockSuccessDelay: 800,

    // ==============================================================
    // PAGE ROUTES â€” change if you rename the HTML files
    // ==============================================================
    successPage: 'success.html',
    errorPage:   'error.html',
    statusPage:  'status.html',

  };

})();

