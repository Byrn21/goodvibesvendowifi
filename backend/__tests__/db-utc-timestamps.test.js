/**
 * __tests__/db-utc-timestamps.test.js — TIMESTAMP columns are UTC
 *
 * services/session.js writes `started_at` / `expires_at` as UTC ISO-8601
 * ("…Z"). PostgreSQL stores that wall clock verbatim in a plain TIMESTAMP
 * column, but node-postgres would otherwise parse the value it reads back in
 * the PROCESS's local timezone — so on a host east of UTC a session created
 * seconds ago read as already expired and the lazy expiry in services/session.js
 * killed it (and called Omada extPortal/unauth) immediately.
 *
 * These tests pin the parser that db/client.js installs for OID 1114.
 */

'use strict';

const { types } = require('pg');
const { parseUtcTimestamp } = require('../src/db/client');

// The exact text PostgreSQL returns for a `timestamp without time zone`.
const STORED = '2026-10-25 12:00:00.123';

describe('PostgreSQL TIMESTAMP (OID 1114) parsing', () => {
  test('is registered on the pg type parser', () => {
    expect(types.getTypeParser(1114)).toBe(parseUtcTimestamp);
  });

  test('interprets a bare timestamp as UTC, not as local time', () => {
    expect(parseUtcTimestamp(STORED).getTime()).toBe(Date.UTC(2026, 9, 25, 12, 0, 0, 123));
    expect(parseUtcTimestamp(STORED).toISOString()).toBe('2026-10-25T12:00:00.123Z');
    expect(parseUtcTimestamp('2026-10-25 12:00:00').toISOString()).toBe('2026-10-25T12:00:00.000Z');
  });

  test('truncates PostgreSQL microseconds to milliseconds', () => {
    expect(parseUtcTimestamp('2026-10-25 12:00:00.123456').toISOString())
      .toBe('2026-10-25T12:00:00.123Z');
  });

  test('passes an explicit offset / Z through unchanged', () => {
    expect(parseUtcTimestamp('2026-10-25T12:00:00.000Z').toISOString()).toBe('2026-10-25T12:00:00.000Z');
    expect(parseUtcTimestamp('2026-10-25 17:30:00+05:30').toISOString()).toBe('2026-10-25T12:00:00.000Z');
  });

  test('round-trips a freshly written expiry without shifting the instant', () => {
    const startedMs = Date.now();
    // What the column holds after recordSession() writes the ISO string.
    const storedText = new Date(startedMs).toISOString().slice(0, 23).replace('T', ' ');

    const readBackMs = parseUtcTimestamp(storedText).getTime();
    expect(Math.abs(readBackMs - startedMs)).toBeLessThan(1000);

    // A 60-minute session read back a moment after creation is still live —
    // this is exactly the check that used to fail ("read back with state
    // \"expired\"").
    expect(Date.now() < readBackMs + 60 * 60 * 1000).toBe(true);
  });

  test('handles NULL and infinity like the default parser', () => {
    expect(parseUtcTimestamp(null)).toBeNull();
    expect(parseUtcTimestamp('')).toBeNull();
    expect(parseUtcTimestamp('infinity')).toBe(Infinity);
    expect(parseUtcTimestamp('-infinity')).toBe(-Infinity);
  });
});
