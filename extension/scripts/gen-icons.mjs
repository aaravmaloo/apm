// Generates extension icons (dark rounded square + blue passkey ring) with
// zero dependencies — hand-rolled PNG encoder using node's built-in zlib.
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// ── Minimal PNG encoder ───────────────────────────────────────────────────────
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function encodePng(width, height, rgba) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const idat = deflateSync(raw, { level: 9 });
  return Buffer.concat([
    sig,
    chunk('IHDR', ihdr),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ── Icon drawing ──────────────────────────────────────────────────────────────
const BG = [17, 19, 24]; // near-black, APM dark surface
const ACCENT = [10, 132, 255]; // APM blue

function inRoundedRect(x, y, S, r) {
  if (x < 0 || y < 0 || x >= S || y >= S) return false;
  const cx = Math.min(Math.max(x, r), S - 1 - r);
  const cy = Math.min(Math.max(y, r), S - 1 - r);
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}

function makeIcon(S) {
  const px = Buffer.alloc(S * S * 4);
  const ringCx = S * 0.5;
  const ringCy = S * 0.42;
  const ringR = S * 0.21;
  const ringW = Math.max(2, S * 0.07);
  const shaftX0 = S * 0.43;
  const shaftX1 = S * 0.57;
  const shaftY0 = ringCy + ringR;
  const shaftY1 = S * 0.8;
  const toothY = S * 0.66;

  for (let y = 0; y < S; y++) {
    for (let x = 0; x < S; x++) {
      let col = null;
      // rounded background
      if (inRoundedRect(x, y, S, S * 0.22)) col = BG;
      // ring (annulus distance check)
      const d = Math.hypot(x - ringCx, y - ringCy);
      if (Math.abs(d - ringR) <= ringW / 2) col = ACCENT;
      // shaft + teeth
      if (x >= shaftX0 && x <= shaftX1 && y >= shaftY0 && y <= shaftY1) col = ACCENT;
      if (x >= shaftX1 && x <= S * 0.68 && y >= toothY && y <= toothY + ringW) col = ACCENT;
      if (x >= shaftX1 && x <= S * 0.63 && y >= S * 0.76 && y <= S * 0.76 + ringW) col = ACCENT;

      if (col) {
        const i = (y * S + x) * 4;
        px[i] = col[0];
        px[i + 1] = col[1];
        px[i + 2] = col[2];
        px[i + 3] = 255;
      }
    }
  }
  return encodePng(S, S, px);
}

mkdirSync(join(root, 'icons'), { recursive: true });
writeFileSync(join(root, 'icons', 'icon-128.png'), makeIcon(128));
writeFileSync(join(root, 'icons', 'icon-32.png'), makeIcon(32));
console.log('icons written to extension/icons/');
