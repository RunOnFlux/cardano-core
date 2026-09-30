import { invalidInput } from './errors.js';

/** BIP-173 bech32 (not bech32m), with a configurable length limit: Cardano strings exceed 90 chars. */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: readonly number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i] as number;
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function convertBits(
  data: ArrayLike<number>,
  from: number,
  to: number,
  pad: boolean,
): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (let i = 0; i < data.length; i++) {
    const v = data[i] as number;
    if (v < 0 || v >> from !== 0)
      throw invalidInput('invalid data for bit conversion');
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    throw invalidInput('invalid bech32 padding');
  }
  return out;
}

export function bech32Encode(
  hrp: string,
  data: Uint8Array,
  limit = 1023,
): string {
  if (hrp.length < 1 || hrp !== hrp.toLowerCase())
    throw invalidInput('invalid bech32 prefix');
  const words = convertBits(data, 8, 5, true);
  const values = [...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0];
  const mod = polymod(values) ^ 1;
  let s = `${hrp}1`;
  for (const w of words) s += CHARSET.charAt(w);
  for (let i = 0; i < 6; i++) s += CHARSET.charAt((mod >> (5 * (5 - i))) & 31);
  if (s.length > limit) throw invalidInput('bech32 string too long');
  return s;
}

export function bech32Decode(
  str: string,
  limit = 1023,
): { prefix: string; data: Uint8Array } {
  if (str.length > limit) throw invalidInput('bech32 string too long');
  const lower = str.toLowerCase();
  if (str !== lower && str !== str.toUpperCase())
    throw invalidInput('mixed-case bech32');
  const sep = lower.lastIndexOf('1');
  if (sep < 1 || sep + 7 > lower.length)
    throw invalidInput('invalid bech32 separator');
  const hrp = lower.slice(0, sep);
  for (let i = 0; i < hrp.length; i++) {
    const c = hrp.charCodeAt(i);
    if (c < 33 || c > 126)
      throw invalidInput('invalid bech32 prefix character');
  }
  const words: number[] = [];
  for (const ch of lower.slice(sep + 1)) {
    const v = CHARSET.indexOf(ch);
    if (v === -1) throw invalidInput('invalid bech32 character');
    words.push(v);
  }
  if (polymod([...hrpExpand(hrp), ...words]) !== 1)
    throw invalidInput('invalid bech32 checksum');
  const data = Uint8Array.from(convertBits(words.slice(0, -6), 5, 8, false));
  return { prefix: hrp, data };
}

// ---- base58 (Bitcoin alphabet), used by Byron addresses ----

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(data: Uint8Array): string {
  let n = 0n;
  for (const b of data) n = (n << 8n) | BigInt(b);
  let s = '';
  while (n > 0n) {
    s = (B58[Number(n % 58n)] as string) + s;
    n /= 58n;
  }
  for (const b of data) {
    if (b !== 0) break;
    s = `1${s}`;
  }
  return s;
}

export function base58Decode(str: string): Uint8Array {
  if (str.length === 0) throw invalidInput('empty base58 string');
  let n = 0n;
  for (const ch of str) {
    const v = B58.indexOf(ch);
    if (v === -1) throw invalidInput('invalid base58 character');
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const ch of str) {
    if (ch !== '1') break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}
