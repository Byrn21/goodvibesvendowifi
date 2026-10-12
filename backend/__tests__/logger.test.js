'use strict';

/**
 * __tests__/logger.test.js — memory-safety regression tests.
 *
 * A logger must never crash the process by trying to serialize a large,
 * circular object (a raw Axios Error, an Express req/res, etc.). These tests
 * pin the guarantee that:
 *   - toSafeString() converts anything to a string, following no cycles
 *   - every level method hands winston a formatted STRING, never an object
 */

const logger = require('../src/utils/logger');

const MESSAGE = Symbol.for('message');

describe('logger memory-safety', () => {
  describe('toSafeString', () => {
    test('passes strings through untouched', () => {
      expect(logger.toSafeString('hello')).toBe('hello');
    });

    test('stringifies primitives', () => {
      expect(logger.toSafeString(42)).toBe('42');
      expect(logger.toSafeString(true)).toBe('true');
      expect(logger.toSafeString(null)).toBe('null');
      expect(logger.toSafeString(undefined)).toBe('undefined');
    });

    test('uses an Error stack (or name: message) rather than "{}"', () => {
      const err = new Error('boom');
      const out = logger.toSafeString(err);
      expect(typeof out).toBe('string');
      expect(out).toContain('boom');
      expect(out).not.toBe('{}');
    });

    test('breaks circular references instead of throwing/blowing the heap', () => {
      const a = { name: 'a' };
      const b = { name: 'b', a };
      a.b = b; // a.b.a.b... cycle
      const out = logger.toSafeString(a);
      expect(typeof out).toBe('string');
      expect(out).toContain('[Circular]');
    });

    test('survives an Express-req-shaped circular graph', () => {
      const req = { method: 'POST', path: '/api/auth' };
      req.socket = { parser: { incoming: req } };
      req.raw = req;
      expect(() => logger.toSafeString(req)).not.toThrow();
      expect(logger.toSafeString(req)).toContain('[Circular]');
    });
  });

  describe('level methods', () => {
    const transport = logger.transports[0];
    const originalLog = transport.log;
    let captured;

    beforeEach(() => {
      captured = [];
      transport.log = (info, callback) => {
        captured.push(info);
        if (typeof callback === 'function') callback();
      };
    });

    afterEach(() => {
      transport.log = originalLog;
    });

    function lastFormatted() {
      const info = captured[captured.length - 1];
      return info && (info[MESSAGE] || info.message);
    }

    test('a circular object is formatted to a string containing [Circular]', () => {
      const circular = { self: null };
      circular.self = circular;

      expect(() => logger.info(circular)).not.toThrow();

      const line = lastFormatted();
      expect(typeof line).toBe('string');
      expect(line).toContain('[Circular]');
    });

    test('a raw Error + circular req never throws and stays a string', () => {
      const req = { headers: {} };
      req.res = { req };
      const err = new Error('kaboom');

      expect(() => logger.error(err, req)).not.toThrow();

      const line = lastFormatted();
      expect(typeof line).toBe('string');
      expect(line).toContain('kaboom');
    });

    test('normal primitive logging is unchanged in shape', () => {
      logger.info('[auth] HIT — ip=1.2.3.4 voucherPresent=true');
      expect(lastFormatted()).toContain('[auth] HIT — ip=1.2.3.4 voucherPresent=true');
    });
  });
});
