#!/usr/bin/env node
/**
 * scripts/backfill_revenue.js — fill in payment details on sessions created by
 * the OLD voucher-claim flow.
 *
 * POST /api/payment/claim used to record the voucher, the webhook event and the
 * session, but never copied the amount onto the session. The admin dashboard's
 * Total Revenue sums sessions.payment_amount, so every one of those claimed
 * payments was invisible. The claim route now writes the column itself; this
 * script repairs the rows created before that fix.
 *
 * The link back to the money is:
 *   sessions.voucher_used  ->  vouchers.code
 *   vouchers.assigned_ref_no ->  webhook_events.ref_no
 * (assigned_ref_no is only set on claim, and ref_no is UNIQUE, so each session
 * resolves to at most one payment event.)
 *
 * Only rows with payment_amount IS NULL are touched, so the script is safe to
 * re-run: a session that already carries an amount is never overwritten.
 *
 * UNITS: webhook_events.amount is stored in PESOS; sessions.payment_amount is
 * in CENTAVOS (admin.html divides it by 100 for display). The conversion is
 * Math.round(amount * 100), matching the claim route exactly.
 *
 * Usage (run inside backend/):
 *   node scripts/backfill_revenue.js              # apply the backfill
 *   node scripts/backfill_revenue.js --dry-run    # preview, change nothing
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const { getDb, closeDb } = require('../src/db/client');

(async () => {
  const dryRun = process.argv.slice(2).includes('--dry-run');
  const db = getDb();

  // One row per missing session. The amount is converted in JS rather than in
  // SQL because Math.round over pesos is the same expression the claim route
  // uses — keeping the two paths byte-for-byte consistent on cents.
  const rows = await db.query(`
    SELECT s.session_id, s.voucher_used, s.payment_amount,
           w.event_id, w.ref_no, w.amount
      FROM sessions s
      JOIN vouchers v       ON v.code = s.voucher_used
      JOIN webhook_events w ON w.ref_no = v.assigned_ref_no
     WHERE s.payment_amount IS NULL
       AND w.amount IS NOT NULL
     ORDER BY s.id
  `);

  console.log(
    (dryRun ? 'DRY RUN' : 'APPLY') + ' - ' + rows.length +
    ' session(s) need a payment backfill.'
  );

  if (rows.length === 0) {
    console.log('Nothing to do.');
    await closeDb();
    return;
  }

  let updated = 0;
  let skipped = 0;

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const cents = Math.round(Number(row.amount) * 100);

    // A NaN/negative total would corrupt the metric — leave the row for a human.
    if (!Number.isFinite(cents) || cents < 0) {
      skipped++;
      console.warn(
        '  [' + (i + 1) + '/' + rows.length + '] SKIP ' + row.session_id +
        ' — webhook_events.amount is not a usable number (' + row.amount + ')'
      );
      continue;
    }

    console.log(
      '  [' + (i + 1) + '/' + rows.length + '] ' + row.session_id +
      '  voucher=' + (row.voucher_used || '(none)') +
      '  ref=' + row.ref_no +
      '  ' + row.amount + ' pesos -> ' + cents + ' centavos'
    );

    if (dryRun) continue;

    // payment_amount IS NULL in the WHERE clause as well: a concurrent claim
    // (or a previous run) that filled the row wins over this backfill.
    const result = await db.run(
      `UPDATE sessions
          SET payment_amount = ?, payment_event_id = ?
        WHERE session_id = ? AND payment_amount IS NULL`,
      [cents, row.event_id, row.session_id]
    );

    if (result && result.rowCount > 0) updated++;
    else skipped++;
  }

  if (dryRun) {
    console.log('\nDRY RUN only - nothing was changed.');
    console.log('Re-run without --dry-run to commit.');
  } else {
    console.log('\nUpdated ' + updated + ' session(s); skipped ' + skipped + '.');
  }

  await closeDb();
})().catch(async (err) => {
  // Primitive-only: never hand a raw Error object to console.
  console.error(
    '[backfill_revenue] FAILED: ' + (err && err.stack ? err.stack : String(err))
  );
  try {
    await closeDb();
  } catch (closeErr) {
    // The process is exiting anyway; the original error is the useful one.
  }
  process.exit(1);
});
