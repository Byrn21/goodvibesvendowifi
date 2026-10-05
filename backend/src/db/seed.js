/**
 * db/seed.js — Development seed data
 *
 * Creates sample vouchers for local testing.
 * Do NOT run in production.
 */

require('dotenv').config();
const { getDb, closeDb } = require('./client');

async function seed() {
  if (process.env.NODE_ENV === 'production') {
    console.error('[seed] Refusing to run in production. Set NODE_ENV=development.');
    process.exit(1);
  }

  console.log('[seed] Creating development voucher codes...');

    const vouchers = [
    { code: 'WIFI-TEST-0001', type: 'standard', duration: 60,  state: 'active', price: 333 },
    { code: 'WIFI-TEST-0002', type: 'standard', duration: 120, state: 'active', price: 667 },
    { code: 'WIFI-TEST-0003', type: 'standard', duration: 180, state: 'active', price: 1000 },
    { code: 'EXPIRED-VOUCHER', type: 'standard', duration: 60,  state: 'expired', price: 333 },
    { code: 'USED-VOUCHER',    type: 'standard', duration: 60,  state: 'used', price: 333 },
    // Premium vouchers — consumable with pause/resume (7-day pause validity)
    { code: 'PREMIUM-TEST-001', type: 'premium', duration: 300,  state: 'active', price: 667 },
    { code: 'PREMIUM-TEST-002', type: 'premium', duration: 480,  state: 'active', price: 1167 },
    { code: 'PREMIUM-TEST-003', type: 'premium', duration: 1440, state: 'active', price: 3000 },
  ];

  const db = getDb();

  for (const v of vouchers) {
    try {
      await db.run(
        'INSERT INTO vouchers (code, type, duration_minutes, price, state) VALUES (?, ?, ?, ?, ?) ON CONFLICT (code) DO NOTHING',
        [v.code, v.type, v.duration, v.price, v.state]
      );
    } catch (err) {
      // Unique violation — voucher already exists, skip
      if (err.code === '23505' || err.code === 'SQLITE_CONSTRAINT') {
        // Skip duplicate — expected for re-runs
      } else {
        throw err;
      }
    }
  }

  console.log('[seed] Inserted', vouchers.length, 'vouchers (including premium).');
  await closeDb();
}

seed().catch(err => {
  console.error('[seed] Seed failed:', err.message);
  process.exit(1);
});
