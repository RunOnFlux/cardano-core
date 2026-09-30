import { bytesToHex, hexToBytes, U64_MAX } from './bytes.js';
import { cArray, cBytes, cMap, cUint } from './cbor/encode.js';
import {
  assertUniqueKeys,
  expectArray,
  expectBytes,
  expectMap,
  expectUint,
} from './cbor/read.js';
import type { CborEncodable, CborNode } from './cbor/types.js';
import { invalidCbor, invalidInput } from './errors.js';

/**
 * Native assets as `policyId (56 hex) → assetName (0–64 hex) → quantity`.
 * Keys are lowercase hex. Quantities in a `Value` are positive.
 */
export type MultiAsset = ReadonlyMap<string, ReadonlyMap<string, bigint>>;

export interface Value {
  readonly coin: bigint;
  readonly assets: MultiAsset;
}

export interface AssetAmount {
  /** 56 hex characters. */
  readonly policyId: string;
  /** 0–64 hex characters. */
  readonly assetName: string;
  readonly quantity: bigint;
}

const POLICY_RE = /^[0-9a-f]{56}$/;
const NAME_RE = /^(?:[0-9a-f]{2}){0,32}$/;

export const EMPTY_ASSETS: MultiAsset = new Map();

export function checkAssetId(policyId: string, assetName: string): void {
  if (!POLICY_RE.test(policyId))
    throw invalidInput('policy id must be 56 lowercase hex characters');
  if (!NAME_RE.test(assetName))
    throw invalidInput('asset name must be 0–32 bytes of lowercase hex');
}

/** `policyId ‖ assetName` hex, the Blockfrost/Koios "unit". */
export function assetUnit(policyId: string, assetName: string): string {
  return `${policyId}${assetName}`;
}

/** Splits a Blockfrost/Koios unit (`policyId ‖ assetNameHex`). */
export function parseAssetUnit(unit: string): {
  policyId: string;
  assetName: string;
} {
  const u = unit.toLowerCase();
  const policyId = u.slice(0, 56);
  const assetName = u.slice(56);
  checkAssetId(policyId, assetName);
  return { policyId, assetName };
}

function mutableAssets(a: MultiAsset): Map<string, Map<string, bigint>> {
  const out = new Map<string, Map<string, bigint>>();
  for (const [p, names] of a) out.set(p, new Map(names));
  return out;
}

function freezeAssets(m: Map<string, Map<string, bigint>>): MultiAsset {
  const out = new Map<string, Map<string, bigint>>();
  for (const [p, names] of m) {
    const kept = new Map<string, bigint>();
    for (const [n, q] of names) if (q !== 0n) kept.set(n, q);
    if (kept.size > 0) out.set(p, kept);
  }
  return out;
}

export function makeValue(
  coin: bigint,
  assets: readonly AssetAmount[] = [],
): Value {
  if (typeof coin !== 'bigint' || coin < 0n || coin > U64_MAX) {
    throw invalidInput('coin must be a bigint in range');
  }
  const m = new Map<string, Map<string, bigint>>();
  for (const a of assets) {
    checkAssetId(a.policyId, a.assetName);
    if (
      typeof a.quantity !== 'bigint' ||
      a.quantity <= 0n ||
      a.quantity > U64_MAX
    ) {
      throw invalidInput('asset quantity must be a positive bigint in range');
    }
    let names = m.get(a.policyId);
    if (!names) {
      names = new Map();
      m.set(a.policyId, names);
    }
    const q = (names.get(a.assetName) ?? 0n) + a.quantity;
    if (q > U64_MAX) throw invalidInput('asset quantity out of range');
    names.set(a.assetName, q);
  }
  return { coin, assets: freezeAssets(m) };
}

export function coinValue(coin: bigint): Value {
  return makeValue(coin);
}

export function assetList(v: Value | MultiAsset): AssetAmount[] {
  const assets: MultiAsset = 'coin' in v ? v.assets : v;
  const out: AssetAmount[] = [];
  for (const [policyId, names] of assets) {
    for (const [assetName, quantity] of names)
      out.push({ policyId, assetName, quantity });
  }
  return out;
}

export function assetQuantity(
  v: Value,
  policyId: string,
  assetName: string,
): bigint {
  return v.assets.get(policyId)?.get(assetName) ?? 0n;
}

export function hasAssets(v: Value): boolean {
  return v.assets.size > 0;
}

export function addValues(a: Value, b: Value): Value {
  const m = mutableAssets(a.assets);
  for (const [p, names] of b.assets) {
    let t = m.get(p);
    if (!t) {
      t = new Map();
      m.set(p, t);
    }
    for (const [n, q] of names) t.set(n, (t.get(n) ?? 0n) + q);
  }
  return { coin: a.coin + b.coin, assets: freezeAssets(m) };
}

export function sumValues(values: readonly Value[]): Value {
  return values.reduce<Value>((acc, v) => addValues(acc, v), coinValue(0n));
}

/**
 * `a - b`. Returns null if any quantity (or the coin) would go negative, so
 * callers can tell "not enough" from a valid remainder.
 */
export function subtractValues(a: Value, b: Value): Value | null {
  const coin = a.coin - b.coin;
  if (coin < 0n) return null;
  const m = mutableAssets(a.assets);
  for (const [p, names] of b.assets) {
    const t = m.get(p);
    for (const [n, q] of names) {
      const have = t?.get(n) ?? 0n;
      if (have < q) return null;
      t?.set(n, have - q);
    }
  }
  return { coin, assets: freezeAssets(m) };
}

export function equalValues(a: Value, b: Value): boolean {
  if (a.coin !== b.coin) return false;
  const la = assetList(a);
  const lb = assetList(b);
  if (la.length !== lb.length) return false;
  for (const x of la) {
    if (assetQuantity(b, x.policyId, x.assetName) !== x.quantity) return false;
  }
  return true;
}

/** Whether `a` holds at least everything in `b`. */
export function valueCovers(a: Value, b: Value): boolean {
  return subtractValues(a, b) !== null;
}

/** Asset names sort by their CBOR encoding: shorter first, then bytewise (RFC 8949 §4.2.1, as CSL does). */
function compareHexAsBytes(a: string, b: string): number {
  if (a.length !== b.length) return a.length - b.length;
  // Keys are validated lowercase hex: for equal lengths, string order is byte order.
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Multi-asset map in canonical order (policies bytewise, names length-first). */
export function encodeMultiAsset(assets: MultiAsset): CborEncodable {
  const policies = [...assets.keys()].sort(compareHexAsBytes);
  return cMap(
    policies.map((p) => {
      const names = assets.get(p) ?? new Map<string, bigint>();
      const sorted = [...names.keys()].sort(compareHexAsBytes);
      return [
        cBytes(hexToBytes(p)),
        cMap(
          sorted.map(
            (n) => [cBytes(hexToBytes(n)), cUint(names.get(n) ?? 0n)] as const,
          ),
        ),
      ] as const;
    }),
  );
}

/** `coin` alone, or `[coin, multiasset]` — byte-identical to CSL. */
export function encodeValue(v: Value): CborEncodable {
  if (!hasAssets(v)) return cUint(v.coin);
  return cArray([cUint(v.coin), encodeMultiAsset(v.assets)]);
}

/** Decodes a multi-asset map; `signed` allows negative quantities (mint field). */
export function decodeAssetMap(
  node: CborNode | undefined,
  what: string,
  signed = false,
  source: Uint8Array = new Uint8Array(0),
): { policyId: string; assetName: string; quantity: bigint }[] {
  const out: { policyId: string; assetName: string; quantity: bigint }[] = [];
  for (const [pk, pv] of assertUniqueKeys(expectMap(node, what), what, source)
    .entries) {
    const policyId = bytesToHex(expectBytes(pk, `${what} policy`, 28));
    for (const [nk, nv] of assertUniqueKeys(
      expectMap(pv, `${what} assets`),
      `${what} assets`,
      source,
    ).entries) {
      const name = expectBytes(nk, `${what} asset name`);
      if (name.length > 32)
        throw invalidCbor(`${what}: asset name longer than 32 bytes`);
      let quantity: bigint;
      if (nv.type === 'uint') quantity = nv.value;
      else if (signed && nv.type === 'nint') quantity = nv.value;
      else throw invalidCbor(`${what}: bad quantity`);
      out.push({ policyId, assetName: bytesToHex(name), quantity });
    }
  }
  return out;
}

/** Decodes an output value. Zero quantities are kept out of the result. */
export function decodeValue(
  node: CborNode | undefined,
  what = 'value',
  source: Uint8Array = new Uint8Array(0),
): Value {
  if (node?.type === 'uint') return { coin: node.value, assets: EMPTY_ASSETS };
  const items = expectArray(node, what);
  if (items.length !== 2)
    throw invalidCbor(`${what}: expected [coin, multiasset]`);
  const coin = expectUint(items[0], `${what} coin`);
  const m = new Map<string, Map<string, bigint>>();
  for (const a of decodeAssetMap(
    items[1],
    `${what} multiasset`,
    false,
    source,
  )) {
    let names = m.get(a.policyId);
    if (!names) {
      names = new Map();
      m.set(a.policyId, names);
    }
    names.set(a.assetName, (names.get(a.assetName) ?? 0n) + a.quantity);
  }
  return { coin, assets: freezeAssets(m) };
}
