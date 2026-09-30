import { compareBytes } from '../bytes.js';
import {
  cArray,
  cBool,
  cBytes,
  cMap,
  cNull,
  cRaw,
  cTag,
  cUint,
  encodeCbor,
} from '../cbor/encode.js';
import type { CborEncodable } from '../cbor/types.js';
import { invalidInput } from '../errors.js';
import { encodeValue } from '../value.js';
import type { TxBody, TxInput, TxOutput, VkeyWitness } from './model.js';

/**
 * Encoders produce the same bytes as cardano-serialization-lib 14:
 * sets (inputs, vkey witnesses) carry tag 258, inputs are sorted by
 * (tx id, index), multi-assets are in canonical order, outputs keep the form
 * they were given in, and body keys appear in ascending order.
 */

const SET_TAG = 258;

function checkInput(i: TxInput): void {
  if (i.txHash.length !== 32)
    throw invalidInput('input tx id must be 32 bytes');
  if (!Number.isInteger(i.index) || i.index < 0 || i.index > 0xffff) {
    throw invalidInput('input index out of range');
  }
}

export function compareInputs(a: TxInput, b: TxInput): number {
  const c = compareBytes(a.txHash, b.txHash);
  return c !== 0 ? c : a.index - b.index;
}

/** Sorted, de-duplicated `#6.258([* [txid, index]])`. */
export function encodeInputSet(inputs: readonly TxInput[]): CborEncodable {
  inputs.forEach(checkInput);
  const sorted = [...inputs].sort(compareInputs);
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    const cur = sorted[i];
    if (prev && cur && compareInputs(prev, cur) === 0)
      throw invalidInput('duplicate input');
  }
  return cTag(
    SET_TAG,
    cArray(sorted.map((i) => cArray([cBytes(i.txHash), cUint(i.index)]))),
  );
}

export function encodeOutputNode(o: TxOutput): CborEncodable {
  if (o.format === 'array') {
    if (o.inlineDatum || o.scriptRef)
      throw invalidInput(
        'array-form outputs cannot carry inline datums or scripts',
      );
    const items: CborEncodable[] = [cBytes(o.address), encodeValue(o.value)];
    if (o.datumHash) items.push(cBytes(o.datumHash));
    return cArray(items);
  }
  const entries: (readonly [CborEncodable, CborEncodable])[] = [
    [cUint(0), cBytes(o.address)],
    [cUint(1), encodeValue(o.value)],
  ];
  if (o.datumHash && o.inlineDatum)
    throw invalidInput('output has both a datum hash and an inline datum');
  if (o.datumHash)
    entries.push([cUint(2), cArray([cUint(0), cBytes(o.datumHash)])]);
  if (o.inlineDatum)
    entries.push([
      cUint(2),
      cArray([cUint(1), cTag(24, cBytes(o.inlineDatum))]),
    ]);
  if (o.scriptRef) entries.push([cUint(3), cTag(24, cBytes(o.scriptRef))]);
  return cMap(entries);
}

export function encodeOutput(o: TxOutput): Uint8Array {
  return encodeCbor(encodeOutputNode(o));
}

export function encodeBodyNode(body: TxBody): CborEncodable {
  if (body.fee < 0n) throw invalidInput('fee must be non-negative');
  const entries: (readonly [CborEncodable, CborEncodable])[] = [
    [cUint(0), encodeInputSet(body.inputs)],
    [cUint(1), cArray(body.outputs.map(encodeOutputNode))],
    [cUint(2), cUint(body.fee)],
  ];
  if (body.ttl !== undefined) entries.push([cUint(3), cUint(body.ttl)]);
  if (body.auxiliaryDataHash !== undefined) {
    if (body.auxiliaryDataHash.length !== 32)
      throw invalidInput('auxiliary data hash must be 32 bytes');
    entries.push([cUint(7), cBytes(body.auxiliaryDataHash)]);
  }
  if (body.validityStart !== undefined)
    entries.push([cUint(8), cUint(body.validityStart)]);
  if (body.networkId !== undefined)
    entries.push([cUint(15), cUint(body.networkId)]);
  return cMap(entries);
}

export function encodeBody(body: TxBody): Uint8Array {
  return encodeCbor(encodeBodyNode(body));
}

/** `{0: #6.258([* [vkey, signature]])}` — or `{}` without witnesses. */
export function encodeWitnessSet(vkeys: readonly VkeyWitness[]): Uint8Array {
  if (vkeys.length === 0) return encodeCbor(cMap([]));
  for (const w of vkeys) {
    if (w.vkey.length !== 32 || w.signature.length !== 64)
      throw invalidInput('malformed vkey witness');
  }
  return encodeCbor(
    cMap([
      [
        cUint(0),
        cTag(
          SET_TAG,
          cArray(
            vkeys.map((w) => cArray([cBytes(w.vkey), cBytes(w.signature)])),
          ),
        ),
      ],
    ]),
  );
}

export interface AssembleOptions {
  readonly isValid?: boolean;
  /** Encoded auxiliary data, or null (default). */
  readonly auxiliaryData?: Uint8Array | null;
}

/** `[body, witness_set, is_valid, auxiliary_data / null]`, splicing the given bytes verbatim. */
export function assembleTransaction(
  bodyBytes: Uint8Array,
  witnessSetBytes: Uint8Array,
  options: AssembleOptions = {},
): Uint8Array {
  const aux = options.auxiliaryData ?? null;
  return encodeCbor(
    cArray([
      cRaw(bodyBytes),
      cRaw(witnessSetBytes),
      cBool(options.isValid ?? true),
      aux ? cRaw(aux) : cNull,
    ]),
  );
}

/**
 * Exact size of the transaction once signed by `witnessCount` vkey witnesses
 * (each witness entry is always 101 bytes, so zero-filled placeholders measure
 * the same as real signatures).
 */
export function signedSize(
  bodyBytes: Uint8Array,
  witnessCount: number,
): number {
  const dummy: VkeyWitness[] = [];
  for (let i = 0; i < witnessCount; i++) {
    dummy.push({ vkey: new Uint8Array(32), signature: new Uint8Array(64) });
  }
  return assembleTransaction(bodyBytes, encodeWitnessSet(dummy)).length;
}
