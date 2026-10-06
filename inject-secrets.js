/**
 * inject-secrets.js
 *
 * Build-time injection of production contact details (and the store location)
 * into the public captive-portal HTML, so the real values never have to live in
 * the public GitHub repository while still rendering on the live site.
 *
 * Placeholders replaced (see the PLACEHOLDERS table below):
 *   __STORE_LOCATION__      <- STORE_LOCATION      (index.html — HTML text)
 *   __FACEBOOK_PAGE_NAME__  <- FACEBOOK_PAGE_NAME  (index.html, error.html, status.html)
 *   __FACEBOOK_URL__        <- FACEBOOK_URL        (index.html, error.html, status.html)
 *   __CONTACT_NUMBER__      <- CONTACT_NUMBER      (index.html, error.html, status.html)
 *   __SUPPORT_EMAIL__       <- SUPPORT_EMAIL       (all four pages)
 *
 * One page may hold both kinds of token: index.html renders the store location
 * as HTML but builds its Contact Support config out of JS string literals. The
 * HTML-vs-JS context is therefore resolved per placeholder, not per file (see
 * TARGETS and contextFor() below), so a single pass replaces every token.
 *
 * Set the real values in the Render dashboard (Environment Variables) — never in
 * this repository. Missing values never render a broken `tel:`/`mailto:` link:
 * the Contact Support modal hides the affected row, and footer links fall back to
 * a harmless `#`.
 *
 * Usage:
 *   STORE_LOCATION="123 Example St" SUPPORT_EMAIL="help@example.com" node inject-secrets.js
 *
 * -----------------------------------------------------------------------------
 * WARNING — this script rewrites the target HTML files IN PLACE.
 * Running it locally replaces the placeholders in your working copy with the
 * real values. Restore them BEFORE committing so nothing leaks by accident:
 *
 *     git checkout index.html success.html error.html status.html
 * -----------------------------------------------------------------------------
 *
 * Dependency-free: uses only Node's built-in `fs` and `path` modules.
 */

'use strict';

const fs = require('fs');
const path = require('path');

/* -------------------------------------------------------------------------- *
 * Placeholders
 *
 * `html` renders the value for HTML context and is `null` when the token is
 * never used there. `js` renders it inside a JavaScript string literal in the
 * page's inline <script> and is likewise `null` when unused.
 *
 * Both receive the raw, trimmed environment value ('' when unset) and return
 * the exact text to substitute.
 * -------------------------------------------------------------------------- */
const PLACEHOLDERS = [
  {
    token: '__STORE_LOCATION__',
    env: 'STORE_LOCATION',
    html: function (value) {
      return value ? escapeHtml(value) : 'Store location coming soon';
    },
    js: null,
  },
  {
    token: '__FACEBOOK_PAGE_NAME__',
    env: 'FACEBOOK_PAGE_NAME',
    // Empty when unset: the modal hides a row that has no value.
    html: null,
    js: function (value) {
      return escapeJs(value);
    },
  },
  {
    token: '__FACEBOOK_URL__',
    env: 'FACEBOOK_URL',
    // Never leave an empty link target behind.
    html: null,
    js: function (value) {
      return escapeJs(value || '#');
    },
  },
  {
    token: '__CONTACT_NUMBER__',
    env: 'CONTACT_NUMBER',
    html: null,
    js: function (value) {
      return escapeJs(value);
    },
  },
  {
    token: '__SUPPORT_EMAIL__',
    env: 'SUPPORT_EMAIL',
    // In HTML the token *is* the full href, so an unset value becomes a safe
    // '#' rather than a malformed `mailto:` link.
    html: function (value) {
      return value ? 'mailto:' + escapeHtml(value) : '#';
    },
    js: function (value) {
      return escapeJs(value);
    },
  },
];

/**
 * Target pages. `context` selects which renderer above applies:
 *   html — tokens live in HTML attributes/text (safe to HTML-escape)
 *   js   — tokens live inside a JavaScript string literal (needs JS escaping)
 *
 * A page is not limited to one context. `context` is therefore either a plain
 * string (the same context for every token in that file) or an object keyed by
 * placeholder token, with an optional `default` for the tokens not listed:
 *
 *   { default: 'js', '__STORE_LOCATION__': 'html' }
 */
const TARGETS = [
  // Store hours are HTML text; the Contact Support modal config is JS.
  { name: 'index.html', context: { default: 'js', '__STORE_LOCATION__': 'html' } },
  { name: 'success.html', context: 'html' },
  { name: 'error.html', context: 'js' },
  { name: 'status.html', context: 'js' },
];

/**
 * Pick the context ('html' or 'js') that applies to one placeholder in one
 * target file.
 *
 * `target.context` is either a string (applies to every token in the file) or
 * a token -> context map with an optional `default` entry. Anything else falls
 * back to HTML, the safe default for a token sitting in markup.
 */
function contextFor(target, placeholder) {
  const context = target.context;
  if (typeof context === 'string') return context;
  if (context && typeof context === 'object') {
    return context[placeholder.token] || context.default || 'html';
  }
  return 'html';
}

/**
 * Locate the directory holding the portal HTML.
 *
 * It is this script's own directory in the repository root, but inside the
 * Docker image (see backend/Dockerfile) the HTML is copied to /app/public while
 * this script sits at /app. Try both layouts and use the first that exists, so
 * the same script works locally (Windows or Linux) and on Render.
 */
function resolvePortalDir() {
  const candidates = [
    __dirname, // repo root: script + HTML are siblings
    path.join(__dirname, 'public'), // Docker image: /app + /app/public
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, 'index.html'))) return candidate;
  }
  return null;
}

/** Escape a value so it is safe inside HTML text/attribute context. */
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Escape a value so it is safe inside a single- or double-quoted JavaScript
 * string literal that is itself embedded in a <script> block. `<` is escaped as
 * `\x3C` so a value can never terminate the script element.
 */
function escapeJs(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029')
    .replace(/</g, '\\x3C');
}

function main() {
  const portalDir = resolvePortalDir();
  if (!portalDir) {
    console.error(
      '[inject-secrets] ERROR: could not find index.html next to ' +
        __dirname +
        ' (looked in ./ and ./public/).'
    );
    process.exit(1);
  }

  // env name -> total number of replacements, for the end-of-run summary.
  const counts = {};
  let filesChanged = 0;

  for (const target of TARGETS) {
    const filePath = path.join(portalDir, target.name);

    if (!fs.existsSync(filePath)) {
      console.warn('[inject-secrets] WARNING: ' + target.name + ' not found in ' + portalDir + ' — skipped.');
      continue;
    }

    let html;
    try {
      html = fs.readFileSync(filePath, 'utf8');
    } catch (err) {
      console.error('[inject-secrets] ERROR: failed to read ' + filePath + ': ' + err.message);
      process.exit(1);
    }

    let output = html;
    const notes = [];

    for (const placeholder of PLACEHOLDERS) {
      const context = contextFor(target, placeholder);
      const render = placeholder[context];
      if (!render) continue; // token is not used in this context

      const pattern = new RegExp(placeholder.token, 'g');
      const matches = output.match(pattern);
      if (!matches) continue;

      const raw = (process.env[placeholder.env] || '').trim();
      const rendered = render(raw);

      // Function replacer, so `$&`, `$1`, … inside a value stay literal text
      // instead of being treated as replacement patterns.
      output = output.replace(pattern, function () {
        return rendered;
      });

      counts[placeholder.env] = (counts[placeholder.env] || 0) + matches.length;
      notes.push(placeholder.env + ' (' + matches.length + 'x ' + context + (raw ? '' : ', unset') + ')');
    }

    if (output === html) continue; // page had no placeholders — leave it alone

    try {
      fs.writeFileSync(filePath, output, 'utf8');
    } catch (err) {
      console.error('[inject-secrets] ERROR: failed to write ' + filePath + ': ' + err.message);
      process.exit(1);
    }

    filesChanged += 1;
    // Never print the actual values.
    console.log('[inject-secrets] ' + target.name + ' <- ' + notes.join(', '));
  }

  if (filesChanged === 0) {
    console.warn(
      '[inject-secrets] WARNING: no placeholders were found in any target file — nothing was replaced ' +
        '(already injected, or the pages were edited). Files left unchanged.'
    );
    return;
  }

  const summary = Object.keys(counts)
    .map(function (env) {
      return env + '=' + counts[env];
    })
    .join(' ');
  console.log('[inject-secrets] Done. ' + filesChanged + ' file(s) updated. Replacements: ' + summary + '. Values not logged.');
}

main();
