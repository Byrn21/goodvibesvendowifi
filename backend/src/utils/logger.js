/**
 * utils/logger.js — shared application logger.
 *
 * winston is already a project dependency (backend/package.json) and LOG_LEVEL
 * comes from the environment (default: info). This wraps
 * it so routes/services use a single `logger.info/warn/error` instead of each
 * file rolling its own console output, and so severity filtering is possible.
 *
 * Output is one timestamped line, e.g.:
 *   2026-10-12T09:00:00.000Z [info] [auth] POST /api/auth HIT — ip=...
 *
 * Levels (winston/npm): error > warn > info > http > verbose > debug > silly.
 *
 * ── HARDENING (memory-safety) ──────────────────────────────────────────
 * A logger must NEVER crash the process. Historically the worst way it can is
 * to be handed a raw `Error` (e.g. an Axios error, which carries `config`,
 * `request`, `response`, and socket handles) or an Express `req`/`res` object
 * whose graph is huge and *circular*. Winston (and V8's util.inspect behind
 * the Console transport) then tries to serialize that graph and can blow the
 * heap ("JavaScript heap out of memory") on a long-lived server.
 *
 * Every level method below therefore runs its arguments through toSafeString()
 * first, so only a plain primitive string ever reaches winston. Callers should
 * still pass primitives (e.g. `err.message`, `err.response?.data`) — this is
 * the last line of defense, not a license to hand over live objects.
 */

const winston = require('winston');

const LEVEL = process.env.LOG_LEVEL || 'info';

/**
 * toSafeString — coerce ANY value to a plain string, without ever throwing and
 * without following circular references.
 *
 * - strings pass through untouched
 * - null/undefined/numbers/booleans/bigints/symbols → String(value)
 * - functions → a short label
 * - Errors → the stack (or `name: message` when no stack is available), which
 *   is what we actually want in a log line
 * - objects/arrays → JSON with a WeakSet cycle guard (`[Circular]`) and a
 *   try/catch so a throwing getter or a BigInt value cannot escape
 *
 * @param {*} value
 * @returns {string}
 */
function toSafeString(value) {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return String(value);

  const type = typeof value;
  if (type === 'number' || type === 'boolean' || type === 'bigint' || type === 'symbol') {
    return String(value);
  }
  if (type === 'function') {
    return '[Function ' + (value.name || 'anonymous') + ']';
  }

  // Errors first: JSON.stringify(new Error('x')) yields "{}" and would hide
  // the reason. Prefer the stack, which already contains the message.
  if (value instanceof Error) {
    return value.stack ? String(value.stack) : (value.name + ': ' + value.message);
  }

  // Plain objects, arrays, and class instances: bounded, cycle-safe JSON.
  try {
    const seen = new WeakSet();
    const json = JSON.stringify(value, function (_key, val) {
      if (typeof val === 'object' && val !== null) {
        if (seen.has(val)) return '[Circular]';
        seen.add(val);
      }
      return val;
    });
    return json === undefined ? String(value) : json;
  } catch (_) {
    // Throwing getters, BigInt values, oversized depth — never crash on log.
    try {
      return Object.prototype.toString.call(value);
    } catch (_) {
      return '[Unserializable]';
    }
  }
}

const logger = winston.createLogger({
  level: LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) =>
      timestamp + ' [' + level + '] ' + message)
  ),
  transports: [new winston.transports.Console()],
});

// Wrap every level method so winston only ever receives a primitive string.
// The original bound method is captured per level so overriding one does not
// recurse into another.
const LEVELS = ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'];
for (const level of LEVELS) {
  if (typeof logger[level] !== 'function') continue;
  const original = logger[level].bind(logger);
  logger[level] = function (...args) {
    return original(args.map(toSafeString).join(' '));
  };
}

// Exposed for tests and for any code that wants the same safe coercion.
logger.toSafeString = toSafeString;

module.exports = logger;
