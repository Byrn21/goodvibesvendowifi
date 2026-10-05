/**
 * db/migrate.js — Database migration runner
 *
 * Reads DATABASE_URL from .env and applies the database schema.
 * Supports both SQLite (development) and PostgreSQL (Render.com production).
 *
 * Execution order matters:
 *   Phase 1: fixMissingColumns() — reconciles missing columns on tables
 *            that already exist. CREATE TABLE IF NOT EXISTS cannot add
 *            columns to pre-existing tables, and the partial unique
 *            ref_no indexes in schema.sql fail with PostgreSQL 42703
 *            ("column \"ref_no\" does not exist") when ref_no has not
 *            been added yet — so reconciliation must run first.
 *   Phase 2: schema.sql — creates any missing tables plus all indexes
 *            (safe now, because every referenced column exists).
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { getDb, closeDb } = require('./client');
const { fixMissingColumns } = require('./migrate_fix');

const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

async function migrate() {
  console.log('[migrate] Starting database migration...');
  console.log('[migrate] Database URL:', process.env.DATABASE_URL || 'sqlite:./data/portal.db');

  const db = getDb();

  console.log('[migrate] Phase 1/2: reconciling columns on existing tables...');
  await fixMissingColumns();

  console.log('[migrate] Phase 2/2: applying schema.sql (missing tables + indexes)...');
  const schema = fs.readFileSync(SCHEMA_PATH, 'utf8');
  await db.exec(schema);

  console.log('[migrate] Schema applied successfully.');
  console.log('[migrate] Done.');

  await closeDb();
}

migrate().catch(err => {
  console.error('[migrate] Migration failed:', err.message);
  process.exit(1);
});
