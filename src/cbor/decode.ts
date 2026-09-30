import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, utf8Decode } from '../bytes.js';
import { CardanoError, invalidCbor } from '../errors.js';
import type { CborNode, Span } from './types.js';

export interface CborDecodeOptions {
  /** Maximum nesting depth (default 128). */
  readonly maxDepth?: number;
  /**
   * Accept maps with repeated keys (default false). Duplicate keys make a value
   * ambiguous (which one does the ledger read?), so a wallet should refuse them.
   */
  readonly allowDuplicateKeys?: boolean;
  /** Refuse inputs longer than this many bytes before decoding anything (default: no limit). */
  readonly maxBytes?: number;
}

const BREAK = 0xff;

/**
 * Tracks the keys of one map in time linear in their size. Scalar keys compare
 * by value, so a non-minimal re-encoding of a key is still a duplicate.
 * Composite keys (arrays, maps, tags, …) compare by their exact encoding: a
 * cheap fingerprint (length, first and last 16 bytes) first; only keys whose
 * fingerprints collide are hashed (once each), so neither deeply nested
 * composite keys nor many look-alike keys make decoding quadratic.
 */
export class MapKeyTracker {
  private readonly scalar = new Set<string>();
  /** fingerprint → first span seen, plus (after a collision) hash → span for every key with it. */
  private readonly composite = new Map<
    string,
    { first: Span; byHash: Map<string, Span> | null }
  >();
  constructor(private readonly buf: Uint8Array) {}

  /** Records `key`; returns false if an equal key was already recorded. */
  add(key: CborNode): boolean {
    switch (key.type) {
      case 'uint':
      case 'nint':
        return this.addScalar(`i:${key.value}`);
      case 'bytes':
        return this.addScalar(`b:${bytesToHex(key.value)}`);
      case 'text':
        return this.addScalar(`t:${key.value}`);
      default: {
        const sp = key.span;
        if (!sp) return true;
        const len = sp.end - sp.start;
        const head = bytesToHex(
          this.buf.subarray(sp.start, Math.min(sp.end, sp.start + 16)),
        );
        const tail = bytesToHex(
          this.buf.subarray(Math.max(sp.start, sp.end - 16), sp.end),
        );
        const fp = `${len}:${head}:${tail}`;
        const entry = this.composite.get(fp);
        if (!entry) {
          this.composite.set(fp, { first: sp, byHash: null });
          return true;
        }
        // Fingerprints collide: hash each colliding key once (never per nesting level).
        if (!entry.byHash)
          entry.byHash = new Map([[this.hash(entry.first), entry.first]]);
        const h = this.hash(sp);
        const seen = entry.byHash.get(h);
        if (seen && this.sameBytes(seen, sp)) return false;
        entry.byHash.set(h, sp);
        return true;
      }
    }
  }

  private hash(sp: Span): string {
    return bytesToHex(
      blake2b(this.buf.subarray(sp.start, sp.end), { dkLen: 16 }),
    );
  }

  private addScalar(k: string): boolean {
    if (this.scalar.has(k)) return false;
    this.scalar.add(k);
    return true;
  }

  private sameBytes(a: Span, b: Span): boolean {
    const n = a.end - a.start;
    if (n !== b.end - b.start) return false;
    for (let i = 0; i < n; i++) {
      if (this.buf[a.start + i] !== this.buf[b.start + i]) return false;
    }
    return true;
  }
}

interface State {
  readonly buf: Uint8Array;
  pos: number;
  readonly maxDepth: number;
  readonly allowDuplicateKeys: boolean;
}

function need(s: State, n: number): void {
  if (n < 0 || s.pos + n > s.buf.length)
    throw invalidCbor('unexpected end of input');
}

function readByte(s: State): number {
  need(s, 1);
  const b = s.buf[s.pos] as number;
  s.pos += 1;
  return b;
}

/** Reads the argument of a head; returns null for indefinite length (ai = 31). */
function readArgument(s: State, ai: number): bigint | null {
  if (ai < 24) return BigInt(ai);
  if (ai === 24) return BigInt(readByte(s));
  if (ai === 25 || ai === 26 || ai === 27) {
    const n = ai === 25 ? 2 : ai === 26 ? 4 : 8;
    need(s, n);
    let v = 0n;
    for (let i = 0; i < n; i++)
      v = (v << 8n) | BigInt(s.buf[s.pos + i] as number);
    s.pos += n;
    return v;
  }
  if (ai === 31) return null;
  throw invalidCbor(`reserved additional information ${ai}`);
}

function toLength(s: State, v: bigint): number {
  if (v > BigInt(s.buf.length - s.pos))
    throw invalidCbor('length exceeds input');
  return Number(v);
}

function halfToNumber(h: number): number {
  const sign = h & 0x8000 ? -1 : 1;
  const exp = (h >> 10) & 0x1f;
  const mant = h & 0x3ff;
  if (exp === 0) return sign * 2 ** -14 * (mant / 1024);
  if (exp === 31) return mant ? NaN : sign * Infinity;
  return sign * 2 ** (exp - 15) * (1 + mant / 1024);
}

function readItem(s: State, depth: number): CborNode {
  if (depth > s.maxDepth) throw invalidCbor('nesting too deep');
  const start = s.pos;
  const ib = readByte(s);
  const major = ib >> 5;
  const ai = ib & 0x1f;
  const span = (): Span => ({ start, end: s.pos });

  switch (major) {
    case 0: {
      const v = readArgument(s, ai);
      if (v === null) throw invalidCbor('indefinite integer');
      return { type: 'uint', value: v, span: span() };
    }
    case 1: {
      const v = readArgument(s, ai);
      if (v === null) throw invalidCbor('indefinite integer');
      return { type: 'nint', value: -1n - v, span: span() };
    }
    case 2:
    case 3: {
      const len = readArgument(s, ai);
      if (len === null) {
        const chunks: Uint8Array[] = [];
        for (;;) {
          need(s, 1);
          if (s.buf[s.pos] === BREAK) {
            s.pos += 1;
            break;
          }
          const cb = readByte(s);
          if (cb >> 5 !== major || (cb & 0x1f) === 31) {
            throw invalidCbor('invalid chunk in indefinite string');
          }
          const cl = readArgument(s, cb & 0x1f);
          const n = toLength(s, cl ?? 0n);
          chunks.push(s.buf.slice(s.pos, s.pos + n));
          s.pos += n;
        }
        if (major === 2) {
          let total = 0;
          for (const c of chunks) total += c.length;
          const value = new Uint8Array(total);
          let o = 0;
          for (const c of chunks) {
            value.set(c, o);
            o += c.length;
          }
          return { type: 'bytes', value, chunks, span: span() };
        }
        let text: string[];
        try {
          text = chunks.map((c) => utf8Decode(c));
        } catch {
          throw invalidCbor('invalid UTF-8 in text string');
        }
        return {
          type: 'text',
          value: text.join(''),
          chunks: text,
          span: span(),
        };
      }
      const n = toLength(s, len);
      const raw = s.buf.slice(s.pos, s.pos + n);
      s.pos += n;
      if (major === 2) return { type: 'bytes', value: raw, span: span() };
      let value: string;
      try {
        value = utf8Decode(raw);
      } catch {
        throw invalidCbor('invalid UTF-8 in text string');
      }
      return { type: 'text', value, span: span() };
    }
    case 4: {
      const len = readArgument(s, ai);
      const items: CborNode[] = [];
      if (len === null) {
        for (;;) {
          need(s, 1);
          if (s.buf[s.pos] === BREAK) {
            s.pos += 1;
            break;
          }
          items.push(readItem(s, depth + 1));
        }
        return { type: 'array', items, indefinite: true, span: span() };
      }
      // Every item takes at least one byte.
      const n = toLength(s, len);
      for (let i = 0; i < n; i++) items.push(readItem(s, depth + 1));
      return { type: 'array', items, span: span() };
    }
    case 5: {
      const len = readArgument(s, ai);
      const entries: [CborNode, CborNode][] = [];
      const seen = s.allowDuplicateKeys ? null : new MapKeyTracker(s.buf);
      const add = (): void => {
        const k = readItem(s, depth + 1);
        if (seen && !seen.add(k)) throw invalidCbor('duplicate map key');
        const v = readItem(s, depth + 1);
        entries.push([k, v]);
      };
      if (len === null) {
        for (;;) {
          need(s, 1);
          if (s.buf[s.pos] === BREAK) {
            s.pos += 1;
            break;
          }
          add();
        }
        return { type: 'map', entries, indefinite: true, span: span() };
      }
      const n = toLength(s, len * 2n) / 2;
      for (let i = 0; i < n; i++) add();
      return { type: 'map', entries, span: span() };
    }
    case 6: {
      const tag = readArgument(s, ai);
      if (tag === null) throw invalidCbor('indefinite tag');
      const value = readItem(s, depth + 1);
      return { type: 'tag', tag, value, span: span() };
    }
    default: {
      // major 7
      if (ai < 20) return { type: 'simple', value: ai, span: span() };
      if (ai <= 23) return { type: 'simple', value: ai, span: span() };
      if (ai === 24) {
        const v = readByte(s);
        if (v < 32) throw invalidCbor('invalid two-byte simple value');
        return { type: 'simple', value: v, span: span() };
      }
      if (ai === 25) {
        need(s, 2);
        const h =
          ((s.buf[s.pos] as number) << 8) | (s.buf[s.pos + 1] as number);
        s.pos += 2;
        return {
          type: 'float',
          value: halfToNumber(h),
          width: 16,
          span: span(),
        };
      }
      if (ai === 26 || ai === 27) {
        const n = ai === 26 ? 4 : 8;
        need(s, n);
        const dv = new DataView(s.buf.buffer, s.buf.byteOffset + s.pos, n);
        const value = n === 4 ? dv.getFloat32(0) : dv.getFloat64(0);
        s.pos += n;
        return { type: 'float', value, width: n === 4 ? 32 : 64, span: span() };
      }
      if (ai === 31) throw invalidCbor('unexpected break');
      throw invalidCbor(`reserved simple encoding ${ai}`);
    }
  }
}

/** Decodes one CBOR item starting at `offset`; returns it and the offset just past it. */
export function decodeCborPrefix(
  bytes: Uint8Array,
  offset = 0,
  options: CborDecodeOptions = {},
): { node: CborNode; end: number } {
  if (
    options.maxBytes !== undefined &&
    bytes.length - offset > options.maxBytes
  ) {
    throw invalidCbor(`input larger than ${options.maxBytes} bytes`);
  }
  const s: State = {
    buf: bytes,
    pos: offset,
    maxDepth: options.maxDepth ?? 128,
    allowDuplicateKeys: options.allowDuplicateKeys ?? false,
  };
  try {
    const node = readItem(s, 0);
    return { node, end: s.pos };
  } catch (e) {
    if (e instanceof CardanoError) throw e;
    // RangeError from DataView etc.
    throw invalidCbor('malformed CBOR');
  }
}

/** Decodes exactly one CBOR item spanning the whole buffer. Spans index into `bytes`. */
export function decodeCbor(
  bytes: Uint8Array,
  options: CborDecodeOptions = {},
): CborNode {
  const { node, end } = decodeCborPrefix(bytes, 0, options);
  if (end !== bytes.length) throw invalidCbor('trailing bytes after CBOR item');
  return node;
}
