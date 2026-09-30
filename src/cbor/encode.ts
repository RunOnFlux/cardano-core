import { compareBytes, concatBytes, utf8 } from '../bytes.js';
import { invalidInput } from '../errors.js';
import type { CborEncodable } from './types.js';

export interface CborEncodeOptions {
  /**
   * RFC 8949 §4.2.1 core deterministic encoding: definite lengths only and map
   * keys sorted by their encoded bytes (which sorts byte-string keys length
   * first). Integer heads are always minimal. Default false: entry order and
   * indefinite-length flags are kept as given.
   */
  readonly canonical?: boolean;
}

const MAX_U64 = (1n << 64n) - 1n;

/** Minimal-length head for major type `major` with argument `arg`. */
export function encodeHead(major: number, arg: bigint | number): Uint8Array {
  const v = typeof arg === 'number' ? BigInt(arg) : arg;
  if (v < 0n || v > MAX_U64) throw invalidInput('CBOR argument out of range');
  const m = major << 5;
  if (v < 24n) return Uint8Array.of(m | Number(v));
  if (v < 0x100n) return Uint8Array.of(m | 24, Number(v));
  if (v < 0x10000n)
    return Uint8Array.of(m | 25, Number(v >> 8n), Number(v & 0xffn));
  if (v < 0x100000000n) {
    const out = new Uint8Array(5);
    out[0] = m | 26;
    new DataView(out.buffer).setUint32(1, Number(v));
    return out;
  }
  const out = new Uint8Array(9);
  out[0] = m | 27;
  new DataView(out.buffer).setBigUint64(1, v);
  return out;
}

function numberToHalf(v: number): number | null {
  // Returns the IEEE half bits if `v` is exactly representable, else null.
  if (Number.isNaN(v)) return 0x7e00;
  if (v === Infinity) return 0x7c00;
  if (v === -Infinity) return 0xfc00;
  if (Object.is(v, -0)) return 0x8000;
  if (v === 0) return 0;
  const sign = v < 0 ? 0x8000 : 0;
  const a = Math.abs(v);
  const exp = Math.floor(Math.log2(a));
  if (exp >= -14 && exp <= 15) {
    const mant = (a / 2 ** exp - 1) * 1024;
    if (Number.isInteger(mant) && mant >= 0 && mant < 1024) {
      return sign | ((exp + 15) << 10) | mant;
    }
  }
  // Subnormal half
  const sub = a / 2 ** -24;
  if (Number.isInteger(sub) && sub > 0 && sub < 1024) return sign | sub;
  return null;
}

function encodeFloat(v: number, width?: 16 | 32 | 64): Uint8Array {
  let w = width;
  if (w === undefined) {
    if (numberToHalf(v) !== null) w = 16;
    else if (Number.isNaN(v) || Math.fround(v) === v) w = 32;
    else w = 64;
  }
  if (w === 16) {
    const h = numberToHalf(v);
    if (h === null) throw invalidInput('float not representable as half');
    return Uint8Array.of(0xf9, h >> 8, h & 0xff);
  }
  if (w === 32) {
    const out = new Uint8Array(5);
    out[0] = 0xfa;
    new DataView(out.buffer).setFloat32(1, v);
    return out;
  }
  const out = new Uint8Array(9);
  out[0] = 0xfb;
  new DataView(out.buffer).setFloat64(1, v);
  return out;
}

function enc(
  node: CborEncodable,
  canonical: boolean,
  parts: Uint8Array[],
): void {
  switch (node.type) {
    case 'raw':
      parts.push(node.bytes);
      return;
    case 'uint':
      parts.push(encodeHead(0, node.value));
      return;
    case 'nint':
      if (node.value >= 0n) throw invalidInput('nint must be negative');
      parts.push(encodeHead(1, -1n - node.value));
      return;
    case 'bytes':
      if (!canonical && node.chunks) {
        parts.push(Uint8Array.of(0x5f));
        for (const c of node.chunks) parts.push(encodeHead(2, c.length), c);
        parts.push(Uint8Array.of(0xff));
      } else {
        parts.push(encodeHead(2, node.value.length), node.value);
      }
      return;
    case 'text':
      if (!canonical && node.chunks) {
        parts.push(Uint8Array.of(0x7f));
        for (const c of node.chunks) {
          const b = utf8(c);
          parts.push(encodeHead(3, b.length), b);
        }
        parts.push(Uint8Array.of(0xff));
      } else {
        const b = utf8(node.value);
        parts.push(encodeHead(3, b.length), b);
      }
      return;
    case 'array':
      if (!canonical && node.indefinite) {
        parts.push(Uint8Array.of(0x9f));
        for (const it of node.items) enc(it, canonical, parts);
        parts.push(Uint8Array.of(0xff));
      } else {
        parts.push(encodeHead(4, node.items.length));
        for (const it of node.items) enc(it, canonical, parts);
      }
      return;
    case 'map': {
      let entries: (readonly [Uint8Array, Uint8Array])[] = node.entries.map(
        ([k, v]) => [
          encodeCbor(k, { canonical }),
          encodeCbor(v, { canonical }),
        ],
      );
      if (canonical) {
        entries = [...entries].sort((a, b) => compareBytes(a[0], b[0]));
        for (let i = 1; i < entries.length; i++) {
          const prev = entries[i - 1];
          const cur = entries[i];
          if (prev && cur && compareBytes(prev[0], cur[0]) === 0) {
            throw invalidInput('duplicate map key');
          }
        }
      }
      if (!canonical && node.indefinite) parts.push(Uint8Array.of(0xbf));
      else parts.push(encodeHead(5, entries.length));
      for (const [k, v] of entries) parts.push(k, v);
      if (!canonical && node.indefinite) parts.push(Uint8Array.of(0xff));
      return;
    }
    case 'tag':
      parts.push(encodeHead(6, node.tag));
      enc(node.value, canonical, parts);
      return;
    case 'simple':
      if (
        node.value < 0 ||
        node.value > 255 ||
        (node.value >= 24 && node.value < 32)
      ) {
        throw invalidInput('invalid simple value');
      }
      parts.push(
        node.value < 24
          ? Uint8Array.of(0xe0 | node.value)
          : Uint8Array.of(0xf8, node.value),
      );
      return;
    case 'float':
      parts.push(encodeFloat(node.value, canonical ? undefined : node.width));
      return;
  }
}

export function encodeCbor(
  node: CborEncodable,
  options: CborEncodeOptions = {},
): Uint8Array {
  const parts: Uint8Array[] = [];
  enc(node, options.canonical ?? false, parts);
  return concatBytes(...parts);
}

// ---- small constructors, so builders read tersely ----

export const cUint = (v: bigint | number): CborEncodable => ({
  type: 'uint',
  value: BigInt(v),
});

/** Signed integer: picks major type 0 or 1. */
export const cInt = (v: bigint | number): CborEncodable => {
  const b = BigInt(v);
  return b >= 0n ? { type: 'uint', value: b } : { type: 'nint', value: b };
};

export const cBytes = (v: Uint8Array): CborEncodable => ({
  type: 'bytes',
  value: v,
});

export const cText = (v: string): CborEncodable => ({ type: 'text', value: v });

export const cArray = (items: readonly CborEncodable[]): CborEncodable => ({
  type: 'array',
  items,
});

export const cMap = (
  entries: readonly (readonly [CborEncodable, CborEncodable])[],
): CborEncodable => ({ type: 'map', entries });

export const cTag = (
  tag: bigint | number,
  value: CborEncodable,
): CborEncodable => ({
  type: 'tag',
  tag: BigInt(tag),
  value,
});

export const cRaw = (bytes: Uint8Array): CborEncodable => ({
  type: 'raw',
  bytes,
});

export const cBool = (v: boolean): CborEncodable => ({
  type: 'simple',
  value: v ? 21 : 20,
});

export const cNull: CborEncodable = { type: 'simple', value: 22 };
