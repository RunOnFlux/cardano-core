import { invalidCbor } from '../errors.js';
import { MapKeyTracker } from './decode.js';
import type { CborNode, CborMap } from './types.js';

/** Typed accessors over decoded nodes. Each throws INVALID_CBOR naming `what`. */

export function expectUint(node: CborNode | undefined, what: string): bigint {
  if (node?.type !== 'uint')
    throw invalidCbor(`${what}: expected unsigned integer`);
  return node.value;
}

/** Unsigned integer that must fit a JS number safely (indexes, sizes). */
export function expectSmallUint(
  node: CborNode | undefined,
  what: string,
): number {
  const v = expectUint(node, what);
  if (v > BigInt(Number.MAX_SAFE_INTEGER))
    throw invalidCbor(`${what}: too large`);
  return Number(v);
}

export function expectInt(node: CborNode | undefined, what: string): bigint {
  if (node?.type === 'uint' || node?.type === 'nint') return node.value;
  throw invalidCbor(`${what}: expected integer`);
}

export function expectBytes(
  node: CborNode | undefined,
  what: string,
  length?: number,
): Uint8Array {
  if (node?.type !== 'bytes')
    throw invalidCbor(`${what}: expected byte string`);
  if (length !== undefined && node.value.length !== length) {
    throw invalidCbor(`${what}: expected ${length} bytes`);
  }
  return node.value;
}

export function expectText(node: CborNode | undefined, what: string): string {
  if (node?.type !== 'text') throw invalidCbor(`${what}: expected text string`);
  return node.value;
}

export function expectArray(
  node: CborNode | undefined,
  what: string,
): readonly CborNode[] {
  if (node?.type !== 'array') throw invalidCbor(`${what}: expected array`);
  return node.items;
}

export function expectMap(node: CborNode | undefined, what: string): CborMap {
  if (node?.type !== 'map') throw invalidCbor(`${what}: expected map`);
  return node;
}

/** Items of a CDDL `set<a>`: either `#6.258([* a])` or a plain array. */
export function setItems(
  node: CborNode | undefined,
  what: string,
): readonly CborNode[] {
  if (node?.type === 'tag' && node.tag === 258n)
    return expectArray(node.value, what);
  return expectArray(node, what);
}

/** Whether a set was encoded with tag 258. */
export function isTaggedSet(node: CborNode | undefined): boolean {
  return node?.type === 'tag' && node.tag === 258n;
}

/** Value for an unsigned-integer key, or undefined. */
export function mapGet(
  map: CborMap,
  key: number | bigint,
): CborNode | undefined {
  const k = BigInt(key);
  for (const [mk, mv] of map.entries) {
    if (mk.type === 'uint' && mk.value === k) return mv;
  }
  return undefined;
}

/** Value for a text key, or undefined. */
export function mapGetText(map: CborMap, key: string): CborNode | undefined {
  for (const [mk, mv] of map.entries) {
    if (mk.type === 'text' && mk.value === key) return mv;
  }
  return undefined;
}

/** The exact source bytes of a decoded node (a view, not a copy). */
export function rawBytes(source: Uint8Array, node: CborNode): Uint8Array {
  if (!node.span) throw invalidCbor('node has no source span');
  return source.subarray(node.span.start, node.span.end);
}

/**
 * Throws INVALID_CBOR if a map repeats a key. Use on the maps a wallet
 * interprets (body, witness set, outputs, values, mint, withdrawals, votes)
 * when the document was decoded with `allowDuplicateKeys: true` so that opaque
 * parts (Plutus data, metadata) keep their ledger-legal duplicates.
 */
export function assertUniqueKeys(
  map: CborMap,
  what: string,
  source: Uint8Array,
): CborMap {
  const t = new MapKeyTracker(source);
  for (const [k] of map.entries) {
    if (!t.add(k)) throw invalidCbor(`${what}: duplicate map key`);
  }
  return map;
}
