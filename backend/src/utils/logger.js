/**
 * utils/logger.js — shared application logger.
 *
 * winston is already a project dependency (backend/package.json) and LOG_LEVEL
 * is provisioned by the deployment (render.yaml: LOG_LEVEL=info). This wraps
 * it so routes/services use a single `logger.info/warn/error` instead of each
 * file rolling its own console output, and so severity filtering is possible.
 *
 * Output is one timestamped line, e.g.:
 *   2026-10-12T09:00:00.000Z [info] [auth] POST /api/auth HIT — ip=...
 *
 * Levels (winston/npm): error > warn > info > http > verbose > debug > silly.
 */

const winston = require('winston');

const LEVEL = process.env.LOG_LEVEL || 'info';

const logger = winston.createLogger({
  level: LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) =>
      timestamp + ' [' + level + '] ' + message)
  ),
  transports: [new winston.transports.Console()],
});

module.exports = logger;
