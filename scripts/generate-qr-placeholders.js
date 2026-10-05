/**
 * scripts/generate-qr-placeholders.js
 *
 * Generates the STATIC placeholder QR images used by the payment modal:
 *   assets/gcash-qr-placeholder.png
 *   assets/maya-qr-placeholder.png
 *   assets/qrph-qr-placeholder.png
 *
 * These are deliberately fake, QR-looking graphics — swap them for the real
 * receiver QR codes. Re-run with:  node scripts/generate-qr-placeholders.js
 *
 * Dependency-free PNG writer (zlib only) so it works in any Node env.
 */

'use strict';

const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

// ── Minimal PNG encoder (8-bit RGBA, no filters) ──────────────────────
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function encodePng(width, height, rgba) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type: RGBA
  const stride = width * 4 + 1;
  const raw = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    raw[y * stride] = 0; // filter: none
    rgba.copy(raw, y * stride + 1, y * width * 4, (y + 1) * width * 4);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([
    signature,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', idat),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

// ── Drawing helpers ───────────────────────────────────────────────────
const SIZE = 240;
const MODULES = 21;          // QR "version 1" module count
const QUIET = 4;             // quiet-zone modules
const TOTAL = MODULES + QUIET * 2;
const MODULE_PX = Math.floor(SIZE / TOTAL);
const OFFSET = Math.floor((SIZE - MODULE_PX * TOTAL) / 2);

function makeCanvas(bg, border) {
  const rgba = Buffer.alloc(SIZE * SIZE * 4);
  for (let i = 0; i < SIZE * SIZE; i++) {
    rgba[i * 4] = bg[0];
    rgba[i * 4 + 1] = bg[1];
    rgba[i * 4 + 2] = bg[2];
    rgba[i * 4 + 3] = 255;
  }
  // Accent border to make the placeholder obviously branded.
  for (let x = 0; x < SIZE; x++) {
    for (let y = 0; y < SIZE; y++) {
      if (x < 6 || y < 6 || x >= SIZE - 6 || y >= SIZE - 6) {
        const i = (y * SIZE + x) * 4;
        rgba[i] = border[0];
        rgba[i + 1] = border[1];
        rgba[i + 2] = border[2];
      }
    }
  }
  return rgba;
}

function fillModule(rgba, col, row, color) {
  const x0 = OFFSET + col * MODULE_PX;
  const y0 = OFFSET + row * MODULE_PX;
  for (let y = y0; y < y0 + MODULE_PX; y++) {
    for (let x = x0; x < x0 + MODULE_PX; x++) {
      if (x < 0 || y < 0 || x >= SIZE || y >= SIZE) continue;
      const i = (y * SIZE + x) * 4;
      rgba[i] = color[0];
      rgba[i + 1] = color[1];
      rgba[i + 2] = color[2];
    }
  }
}

// Cheap deterministic PRNG so the pattern is stable across runs.
function makeRng(seed) {
  let s = seed >>> 0;
  return function () {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

function drawQrLike(rgba, accent, seed) {
  const dark = [34, 30, 26];
  const rng = makeRng(seed);
  const grid = [];
  for (let r = 0; r < MODULES; r++) {
    grid[r] = [];
    for (let c = 0; c < MODULES; c++) grid[r][c] = rng() > 0.5;
  }

  const finder = [
    [0, 0], [MODULES - 7, 0], [0, MODULES - 7],
  ];
  for (const [fr, fc] of finder) {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        const edge = r === 0 || r === 6 || c === 0 || c === 6;
        const core = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        grid[fr + r][fc + c] = edge || core;
      }
    }
  }

  for (let r = 0; r < MODULES; r++) {
    for (let c = 0; c < MODULES; c++) {
      if (grid[r][c]) fillModule(rgba, c + QUIET, r + QUIET, dark);
    }
  }
  // Tint the center with the provider accent (visual only).
  fillModule(rgba, QUIET + 10, QUIET + 10, accent);
}

function generate(fileName, accent, seed) {
  const rgba = makeCanvas([255, 255, 255], accent);
  drawQrLike(rgba, accent, seed);
  const png = encodePng(SIZE, SIZE, rgba);
  const outPath = path.join(__dirname, '..', 'assets', fileName);
  fs.writeFileSync(outPath, png);
  console.log('wrote', path.relative(path.join(__dirname, '..'), outPath), '(' + png.length + ' bytes)');
}

generate('gcash-qr-placeholder.png', [0, 112, 224], 1337);
generate('maya-qr-placeholder.png', [0, 195, 137], 4242);
generate('qrph-qr-placeholder.png', [109, 76, 189], 2024);
