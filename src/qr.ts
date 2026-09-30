/**
 * A QR code encoder, just enough for a pairing code (relay.ts): byte mode,
 * error correction L or M, every version 1–40, the mask chosen by the
 * standard's penalty rules. No dependencies, like the rest of hush.
 *
 * It follows ISO/IEC 18004 as laid out in Project Nayuki's reference
 * implementation (MIT), whose tables are reproduced below. test/qr.test.ts
 * checks the output against an independent encoder, module for module.
 */

export type Ecc = "L" | "M";

// Indexed by version (0 unused). From the standard's table 9.
const ECC_PER_BLOCK: Record<Ecc, number[]> = {
  L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
};
const NUM_BLOCKS: Record<Ecc, number[]> = {
  L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
};
const FORMAT_ECC_BITS: Record<Ecc, number> = { L: 1, M: 0 };

function rawDataModules(ver: number): number {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}

const dataCodewords = (ver: number, ecc: Ecc): number =>
  Math.floor(rawDataModules(ver) / 8) - ECC_PER_BLOCK[ecc][ver] * NUM_BLOCKS[ecc][ver];

// ------------------------------------------------------------ Reed–Solomon

function gfMul(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function rsDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = gfMul(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return result;
}

function rsRemainder(data: number[], divisor: number[]): number[] {
  const result = divisor.map(() => 0);
  for (const b of data) {
    const factor = b ^ (result.shift() as number);
    result.push(0);
    divisor.forEach((coef, i) => (result[i] ^= gfMul(coef, factor)));
  }
  return result;
}

// ------------------------------------------------------------------ encoding

function codewords(bytes: Uint8Array, ecc: Ecc): { ver: number; data: number[] } {
  let ver = 1;
  for (; ; ver++) {
    if (ver > 40) throw new Error("too much data for a QR code");
    const countBits = ver <= 9 ? 8 : 16;
    if (4 + countBits + bytes.length * 8 <= dataCodewords(ver, ecc) * 8 && bytes.length < 1 << countBits) break;
  }
  const bits: number[] = [];
  const put = (value: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  put(0b0100, 4); // byte mode
  put(bytes.length, ver <= 9 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  const capacity = dataCodewords(ver, ecc) * 8;
  put(0, Math.min(4, capacity - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) put(pad, 8);
  const data: number[] = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  return { ver, data };
}

function withEcc(data: number[], ver: number, ecc: Ecc): number[] {
  const numBlocks = NUM_BLOCKS[ecc][ver];
  const eccLen = ECC_PER_BLOCK[ecc][ver];
  const raw = Math.floor(rawDataModules(ver) / 8);
  const numShort = numBlocks - (raw % numBlocks);
  const shortLen = Math.floor(raw / numBlocks);
  const divisor = rsDivisor(eccLen);
  const blocks: number[][] = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1));
    k += dat.length;
    const block = [...dat];
    if (i < numShort) block.push(0);
    blocks.push([...block, ...rsRemainder(dat, divisor)]);
  }
  const result: number[] = [];
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((block, j) => {
      if (i !== shortLen - eccLen || j >= numShort) result.push(block[i]);
    });
  }
  return result;
}

// ------------------------------------------------------------------ the matrix

class Matrix {
  readonly ver: number;
  readonly size: number;
  readonly dark: boolean[][];
  readonly fixed: boolean[][];
  constructor(ver: number) {
    this.ver = ver;
    this.size = ver * 4 + 17;
    this.dark = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
    this.fixed = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
  }
  set(x: number, y: number, dark: boolean): void {
    this.dark[y][x] = dark;
    this.fixed[y][x] = true;
  }
}

function alignmentPositions(ver: number): number[] {
  if (ver === 1) return [];
  const numAlign = Math.floor(ver / 7) + 2;
  const step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let pos = ver * 4 + 17 - 7; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
  return result;
}

function drawFunctionPatterns(m: Matrix): void {
  const n = m.size;
  for (let i = 0; i < n; i++) {
    m.set(6, i, i % 2 === 0);
    m.set(i, 6, i % 2 === 0);
  }
  for (const [cx, cy] of [[3, 3], [n - 4, 3], [3, n - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        const x = cx + dx, y = cy + dy;
        if (x >= 0 && x < n && y >= 0 && y < n) m.set(x, y, d !== 2 && d !== 4);
      }
    }
  }
  const pos = alignmentPositions(m.ver);
  const last = pos.length - 1;
  pos.forEach((px, i) =>
    pos.forEach((py, j) => {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) m.set(px + dx, py + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }),
  );
  drawFormat(m, "L", 0); // reserves the format areas; redrawn per mask
  if (m.ver >= 7) {
    let rem = m.ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (m.ver << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = ((bits >>> i) & 1) !== 0;
      const a = n - 11 + (i % 3), b = Math.floor(i / 3);
      m.set(a, b, bit);
      m.set(b, a, bit);
    }
  }
}

function drawFormat(m: Matrix, ecc: Ecc, mask: number): void {
  const data = (FORMAT_ECC_BITS[ecc] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i: number) => ((bits >>> i) & 1) !== 0;
  const n = m.size;
  for (let i = 0; i <= 5; i++) m.set(8, i, bit(i));
  m.set(8, 7, bit(6));
  m.set(8, 8, bit(7));
  m.set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) m.set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) m.set(n - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) m.set(8, n - 15 + i, bit(i));
  m.set(8, n - 8, true);
}

function drawCodewords(m: Matrix, data: number[]): void {
  const n = m.size;
  let i = 0;
  for (let right = n - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < n; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? n - 1 - vert : vert;
        if (!m.fixed[y][x] && i < data.length * 8) {
          m.dark[y][x] = ((data[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0;
          i++;
        }
      }
    }
  }
}

const MASKS: ((x: number, y: number) => boolean)[] = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

function applyMask(m: Matrix, mask: number): void {
  for (let y = 0; y < m.size; y++) for (let x = 0; x < m.size; x++) if (!m.fixed[y][x] && MASKS[mask](x, y)) m.dark[y][x] = !m.dark[y][x];
}

/** The standard's four penalty rules; the lowest total picks the mask. */
function penalty(m: Matrix): number {
  const n = m.size;
  let score = 0;
  const lines: boolean[][] = [];
  for (let i = 0; i < n; i++) {
    lines.push(m.dark[i]);
    lines.push(m.dark.map((row) => row[i]));
  }
  const finderA = [true, false, true, true, true, false, true, false, false, false, false];
  const finderB = [...finderA].reverse();
  for (const line of lines) {
    let run = 1;
    for (let i = 1; i <= n; i++) {
      if (i < n && line[i] === line[i - 1]) run++;
      else {
        if (run >= 5) score += 3 + (run - 5);
        run = 1;
      }
    }
    // Light modules outside the symbol count as light.
    const padded = [false, false, false, false, ...line, false, false, false, false];
    for (let i = 0; i + 11 <= padded.length; i++) {
      const hit = (p: boolean[]) => p.every((v, k) => padded[i + k] === v);
      if (hit(finderA) || hit(finderB)) score += 40;
    }
  }
  for (let y = 0; y < n - 1; y++) {
    for (let x = 0; x < n - 1; x++) {
      const c = m.dark[y][x];
      if (c === m.dark[y][x + 1] && c === m.dark[y + 1][x] && c === m.dark[y + 1][x + 1]) score += 3;
    }
  }
  const dark = m.dark.reduce((s, row) => s + row.filter(Boolean).length, 0);
  const total = n * n;
  score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
  return score;
}

/** The QR code for `text` (UTF-8), as rows of dark (true) and light modules, without the quiet zone. */
export function qrMatrix(text: string, ecc: Ecc = "M", forceMask?: number): boolean[][] {
  const { ver, data } = codewords(new TextEncoder().encode(text), ecc);
  const m = new Matrix(ver);
  drawFunctionPatterns(m);
  drawCodewords(m, withEcc(data, ver, ecc));
  let mask = forceMask ?? -1;
  if (mask < 0) {
    let best = Infinity;
    for (let k = 0; k < 8; k++) {
      applyMask(m, k);
      drawFormat(m, ecc, k);
      const p = penalty(m);
      if (p < best) {
        best = p;
        mask = k;
      }
      applyMask(m, k);
    }
  }
  applyMask(m, mask);
  drawFormat(m, ecc, mask);
  return m.dark;
}

/**
 * For a terminal: two modules per character with half blocks, and a quiet zone.
 * Light modules are drawn in the text colour and dark ones left as background,
 * which is the right way round on the dark terminals most people use.
 */
export function qrToTerminal(text: string, ecc: Ecc = "M", quiet = 2): string {
  const core = qrMatrix(text, ecc);
  const n = core.length + quiet * 2;
  const light = (x: number, y: number) => {
    const cx = x - quiet, cy = y - quiet;
    return cx < 0 || cy < 0 || cx >= core.length || cy >= core.length || !core[cy][cx];
  };
  const lines: string[] = [];
  for (let y = 0; y < n; y += 2) {
    let line = "";
    for (let x = 0; x < n; x++) {
      const top = light(x, y), bottom = y + 1 < n ? light(x, y + 1) : false;
      line += top && bottom ? "█" : top ? "▀" : bottom ? "▄" : " ";
    }
    lines.push(line);
  }
  return lines.join("\n");
}
