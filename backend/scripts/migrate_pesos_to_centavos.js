#!/usr/bin/env node
/**
 * scripts/migrate_pesos_to_centavos.js — convert LEGACY peso rows in
 * sessions.payment_amount to integer centavos.
 *
 * sessions.payment_amount is defined as integer CENTAVOS everywhere else
 * (utils/price.js, routes/payment.js, admin.html divides by 100). The old
 * activatePaidSession() flow wrote the raw peso amount instead, so those rows
 * read 100x too small on the dashboard. The writer is fixed; this script
 * repairs the rows it already produced.
 *
 * WHY NOT JUST "WHERE payment_amount < 2000":
 *   That predicate cannot tell a peso row from a legitimate centavo row under
 *   P20.00 — and, worse, running it twice multiplies the same row twice
 *   (5 -> 500 -> 50000), silently inflating Total Revenue. So each candidate is
 *   checked against the payment event that produced it:
 *     sessions.payment_event_id -> webhook_events.event_id
 *   and only converted when the stored value equals that event's peso amount.
 *   A row that already equals amount * 100 is centavos and is skipped, which
 *   makes re-running safe: after the first pass nothing matches the peso value
 *   any more.
 *
 * UNLINKED / AMBIGUOUS ROWS: rows under the threshold with no matching payment
 * event (or whose amount matches neither unit) cannot be classified from the
 * data. They are listed and left ALONE by default. `--include-unlinked`
 * converts them with the plain threshold rule — a deliberate one-shot decision,
 * because that rule is not idempotent.
 *
 * Usage (run inside backend/):
 *   node scripts/migrate_pesos_to_centavos.js                       # apply
 *   node scripts/migrate_pesos_to_centavos.js --dry-run             # preview
 *   node scripts/migrate_pesos_to_centavos.js --include-unlinked    # also x100 unverifiable rows
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const { getDb, closeDb } = require('../src/db/client');
const { centavosToPesoString } = require('../src/utils/price');

// A peso payment is a small integer (P5 -> 5). Any stored value at or above
// this is assumed to already be centavos (P20.00 and up). Mirrors the rule in
// the original migration plan.
const LEGACY_PESO_CEILING = 2000;

(async () => {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  const includeUnlinked = args.includes('--include-unlinked');

  const db = getDb();

  const rows = await db.query(`
    SELECT s.id, s.session_id, s.payment_amount, s.payment_event_id,
           w.event_id AS webhook_event_id, w.ref_no, w.amount AS webhook_amount
      FROM sessions s
      LEFT JOIN webhook_events w ON w.event_id = s.payment_event_id
     WHERE s.payment_amount IS NOT NULL
       AND s.payment_amount > 0
       AND s.payment_amount < ?
     ORDER BY s.id
  `, [LEGACY_PESO_CEILING]);

  console.log(
    (dryRun ? 'DRY RUN' : 'APPLY') + ' - ' + rows.length +
    ' session(s) under ' + LEGACY_PESO_CEILING + ' need a unit check.'
  );

  const toConvert = [];   // verified peso rows
  const unlinked = [];    // no usable payment event
  const ambiguous = [];   // event exists, but neither unit matches
  let alreadyCentavos = 0;

  for (const row of rows) {
    const stored = Number(row.payment_amount);

    if (row.webhook_event_id == null || row.webhook_amount == null) {
      unlinked.push(row);
      continue;
    }

    const pesos = Number(row.webhook_amount);
    const centavos = Math.round(pesos * 100);

    if (stored === centavos) {
      // Already normalized (e.g. written by the fixed claim route) — leave it.
      alreadyCentavos++;
    } else if (stored === pesos) {
      toConvert.push(row);
    } else {
      ambiguous.push(row);
    }
  }

  for (const row of toConvert) {
    const from = Number(row.payment_amount);
    const to = Math.round(from * 100);
    console.log(
      '  ' + row.session_id +
      '  ref=' + (row.ref_no || '(none)') +
      '  ' + from + ' (' + centavosToPesoString(from) + ')' +
      '  ->  ' + to + ' (' + centavosToPesoString(to) + ')'
    );
  }

  if (unlinked.length > 0 || ambiguous.length > 0) {
    console.log(
      '\n  ' + unlinked.length + ' row(s) have no matching payment event and ' +
      ambiguous.length + ' did not match either unit:'
    );
    for (const row of unlinked.concat(ambiguous)) {
      console.log(
        '  ?  ' + row.session_id +
        '  payment_amount=' + row.payment_amount +
        '  event=' + (row.payment_event_id || '(none)') +
        '  webhook_amount=' + (row.webhook_amount == null ? '(none)' : row.webhook_amount)
      );
    }
    console.log(
      includeUnlinked
        ? '  Converting them with the threshold rule (--include-unlinked).'
        : '  Left untouched. Re-run with --include-unlinked to convert these too.'
    );
  }

  if (alreadyCentavos > 0) {
    console.log('\n  ' + alreadyCentavos + ' row(s) already hold centavos — skipped.');
  }

  const targets = includeUnlinked ? toConvert.concat(unlinked, ambiguous) : toConvert;

  if (dryRun) {
    console.log(
      '\nDRY RUN only - nothing was changed. ' + targets.length +
      ' row(s) would be converted.'
    );
    console.log('Re-run without --dry-run to commit.');
    await closeDb();
    return;
  }

  let updated = 0;
  for (const row of targets) {
    // payment_amount = ? in the WHERE clause: a concurrent writer that already
    // changed the row wins over this migration, and a stale value is never
    // multiplied.
    const result = await db.run(
      `UPDATE sessions
          SET payment_amount = ?
        WHERE session_id = ? AND payment_amount = ?`,
      [Math.round(Number(row.payment_amount) * 100), row.session_id, row.payment_amount]
    );
    if (result && result.rowCount > 0) updated++;
  }

  console.log('\nUpdated ' + updated + ' session(s) to centavos.');

  const sum = await db.getOne(
    'SELECT SUM(payment_amount) AS total FROM sessions WHERE payment_amount IS NOT NULL'
  );
  console.log('Total Revenue now reads ' + centavosToPesoString(sum && sum.total ? sum.total : 0) + '.');

  await closeDb();
})().catch(async (err) => {
  // Primitive-only: never hand a raw Error object to console.
  console.error(
    '[migrate_pesos_to_centavos] FAILED: ' + (err && err.stack ? err.stack : String(err))
  );
  try {
    await closeDb();
  } catch (closeErr) {
    // The process is exiting anyway; the original error is the useful one.
  }
  process.exitCode = 1;
});
