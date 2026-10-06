/**
 * inject-secrets.js
 *
 * Build-time injection of the store location into the public captive-portal HTML.
 *
 * Replaces every `__STORE_LOCATION__` placeholder in index.html with the value
 * of the STORE_LOCATION environment variable, so the real address never has to
 * live in the public GitHub repository while still rendering on the live site.
 * The value is set in the Render dashboard (see .env.example / RENDER_DEPLOYMENT.md).
 *
 * Usage:
 *   STORE_LOCATION="123 Example St, Brgy. Sample, City" node inject-secrets.js
 *
 * -----------------------------------------------------------------------------
 * WARNING — this script rewrites index.html IN PLACE.
 * Running it locally replaces the placeholder in your working copy with the real
 * value. Restore the placeholder BEFORE committing so the address is not
 * committed by accident:
 *
 *     git checkout index.html
 * -----------------------------------------------------------------------------
 *
 * Dependency-free: uses only Node's built-in `fs` and `path` modules.
 */

'use strict';

const fs = require('fs');
const path = require('path');

// The literal token written into index.html (see Task 1).
const PLACEHOLDER = '__STORE_LOCATION__';

// Rendered when STORE_LOCATION is missing or empty, so the layout still shows.
const FALLBACK = 'Store location coming soon';

/**
 * Locate index.html.
 *
 * It sits next to this script in the repository root, but inside the Docker
 * image (see backend/Dockerfile) index.html is copied to /app/public while this
 * script sits at /app. Try both layouts and use the first that exists, so the
 * same script works locally (Windows or Linux) and on Render.
 */
function resolveIndexPath() {
  const candidates = [
    path.join(__dirname, 'index.html'), // repo root: script + index.html are siblings
    path.join(__dirname, 'public', 'index.html'), // Docker image: /app + /app/public
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
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

function main() {
  const indexPath = resolveIndexPath();
  if (!indexPath) {
    console.error(
      '[inject-secrets] ERROR: could not find index.html next to ' +
        __dirname +
        ' (looked in ./ and ./public/).'
    );
    process.exit(1);
  }

  let html;
  try {
    html = fs.readFileSync(indexPath, 'utf8');
  } catch (err) {
    console.error('[inject-secrets] ERROR: failed to read ' + indexPath + ': ' + err.message);
    process.exit(1);
  }

  // Trim first, then decide whether we have a real value or the fallback.
  const raw = (process.env.STORE_LOCATION || '').trim();
  const usingFallback = raw.length === 0;
  const value = escapeHtml(usingFallback ? FALLBACK : raw);

  // Replace ALL occurrences using a function replacer, so `$&`, `$1`, etc. that
  // might appear in an address are treated as literal text instead of special
  // replacement patterns. The placeholder is a plain literal (no regex
  // metacharacters), so it can be used directly in the pattern.
  const placeholderPattern = new RegExp(PLACEHOLDER, 'g');
  let replaced = 0;
  const output = html.replace(placeholderPattern, () => {
    replaced += 1;
    return value;
  });

  if (replaced === 0) {
    console.warn(
      '[inject-secrets] WARNING: placeholder ' +
        PLACEHOLDER +
        ' not found in ' +
        indexPath +
        ' — nothing was replaced (already injected, or index.html was edited). File left unchanged.'
    );
    return;
  }

  try {
    fs.writeFileSync(indexPath, output, 'utf8');
  } catch (err) {
    console.error('[inject-secrets] ERROR: failed to write ' + indexPath + ': ' + err.message);
    process.exit(1);
  }

  const occurrences = replaced + ' occurrence' + (replaced === 1 ? '' : 's');
  if (usingFallback) {
    console.log(
      '[inject-secrets] STORE_LOCATION was unset or empty — injected fallback text into ' +
        indexPath +
        ' (' +
        occurrences +
        ').'
    );
  } else {
    // Never print the actual address.
    console.log(
      '[inject-secrets] STORE_LOCATION injected into ' + indexPath + ' (' + occurrences + '). Value not logged.'
    );
  }
}

main();
