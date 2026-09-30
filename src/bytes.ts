import { invalidInput } from './errors.js';

export const U64_MAX = (1n << 64n) - 1n;

const HEX_RE = /^(?:[0-9a-f]{2})*$/;

/** Strict lowercase-or-uppercase hex to bytes. Rejects odd length and non-hex. */
export function hexToBytes(hex: string): Uint8Array {
  const h = hex.toLowerCase();
  if (!HEX_RE.test(h)) throw invalidInput('invalid hex string');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Constant-time for equal lengths. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Lexicographic byte comparison; shorter prefix sorts first. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/** Overwrites a buffer with zeros. JavaScript cannot guarantee other copies are gone. */
export function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
}

/**
 * UTF-8 encode without relying on `TextEncoder` (absent on older Hermes).
 * Lone surrogates encode as U+FFFD, matching `TextEncoder`.
 */
export function utf8(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      } else c = 0xfffd;
    } else if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c < 0x10000)
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    else
      out.push(
        0xf0 | (c >> 18),
        0x80 | ((c >> 12) & 0x3f),
        0x80 | ((c >> 6) & 0x3f),
        0x80 | (c & 0x3f),
      );
  }
  return Uint8Array.from(out);
}

/**
 * Strict UTF-8 decode. Throws on malformed sequences, overlongs, surrogates and
 * code points above U+10FFFF (RFC 3629), which CBOR text strings must not contain.
 */
export function utf8Decode(bytes: Uint8Array): string {
  let s = '';
  let i = 0;
  const bad = (): never => {
    throw invalidInput('invalid UTF-8');
  };
  const cont = (k: number): number => {
    const b = bytes[k];
    if (b === undefined || (b & 0xc0) !== 0x80) bad();
    return (b as number) & 0x3f;
  };
  while (i < bytes.length) {
    const b0 = bytes[i] as number;
    let cp: number;
    if (b0 < 0x80) {
      cp = b0;
      i += 1;
    } else if (b0 >= 0xc2 && b0 <= 0xdf) {
      cp = ((b0 & 0x1f) << 6) | cont(i + 1);
      i += 2;
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      cp = ((b0 & 0x0f) << 12) | (cont(i + 1) << 6) | cont(i + 2);
      if (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff)) bad();
      i += 3;
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      cp =
        ((b0 & 0x07) << 18) |
        (cont(i + 1) << 12) |
        (cont(i + 2) << 6) |
        cont(i + 3);
      if (cp < 0x10000 || cp > 0x10ffff) bad();
      i += 4;
    } else {
      return bad();
    }
    s += String.fromCodePoint(cp);
  }
  return s;
}

/** Little-endian unsigned integer of arbitrary length. */
export function bytesToBigIntLE(b: Uint8Array): bigint {
  let r = 0n;
  for (let i = b.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(b[i] ?? 0);
  return r;
}

/** Little-endian encoding of `n` into exactly `len` bytes (n must fit). */
export function bigIntToBytesLE(n: bigint, len: number): Uint8Array {
  if (n < 0n || n >> BigInt(len * 8) !== 0n) {
    throw invalidInput('integer does not fit');
  }
  const out = new Uint8Array(len);
  let t = n;
  for (let i = 0; i < len; i++) {
    out[i] = Number(t & 0xffn);
    t >>= 8n;
  }
  return out;
}

export function u32le(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw invalidInput('u32 out of range');
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

/** Accepts a hex string or bytes and returns a copy as bytes. */
export function toBytes(v: string | Uint8Array): Uint8Array {
  return typeof v === 'string' ? hexToBytes(v) : Uint8Array.from(v);
}
