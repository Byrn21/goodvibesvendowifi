#!/usr/bin/env node
/**
 * scripts/fix-voucher-prices.js - one-time correction for vouchers whose
 * price was stored in pesos instead of centavos by the OLD import code
 * (the old parser stored the raw peso number, e.g. 50 for a 50-peso voucher,
 * while the rest of the system expects centavos, so imported vouchers
 * displayed 100x too small).
 *
 * Usage (run inside backend/):
 *   node scripts/fix-voucher-prices.js                                  # DRY RUN (default) - changes nothing
 *   node scripts/fix-voucher-prices.js --apply --all                    # apply x100 to ALL vouchers with a price
 *   node scripts/fix-voucher-prices.js --apply --codes 123456,654321    # only specific codes
 *
 * Recommended alternative: POST /api/admin/vouchers/delete-all then
 * re-import the corrected file - that also resets voucher IDs back to 1.
 */

require('dotenv').config();
const { getDb, closeDb } = require('../src/db/client');
const { centavosToPesoString } = require('../src/utils/price');

(async () => {
  const args = process.argv.slice(2);
  const apply = args.includes('--apply');
  const all = args.includes('--all');
  const codesIdx = args.indexOf('--codes');
  const codes = codesIdx >= 0
    ? String(args[codesIdx + 1] || '').split(',').map(s => s.trim()).filter(Boolean)
    : null;

  if (apply && !all && !codes) {
    console.error('Refusing to apply without an explicit target. Use --all or --codes <comma,separated,codes>.');
    process.exit(1);
  }

  const db = getDb();
  const rows = await db.query(
    'SELECT id, code, price, state FROM vouchers WHERE price IS NOT NULL ORDER BY id'
  );
  const targets = rows.filter(r => !codes || codes.includes(r.code));

  if (targets.length === 0) {
    console.log('No vouchers matched. Nothing to do.');
    await closeDb();
    return;
  }

  console.log((apply ? 'APPLY' : 'DRY RUN') + ' - ' + targets.length + ' voucher(s) selected:\n');
  for (const r of targets) {
    const fixed = r.price * 100;
    console.log(
      '  id=' + r.id + '  code=' + r.code + '  state=' + r.state +
      '   ' + r.price + ' centavos (' + centavosToPesoString(r.price) + ')' +
      '  ->  ' + fixed + ' centavos (' + centavosToPesoString(fixed) + ')'
    );
  }

  if (!apply) {
    console.log('\nDRY RUN only - nothing was changed.');
    console.log('Re-run with --apply --all (or --apply --codes ...) to commit.');
  } else {
    for (const r of targets) {
      await db.run('UPDATE vouchers SET price = ? WHERE id = ?', [r.price * 100, r.id]);
    }
    console.log('\nUpdated ' + targets.length + ' voucher price(s).');
  }
  await closeDb();
})().catch(e => { console.error(e); process.exit(1); });
