import { invalidInput } from './errors.js';
import { assetList, makeValue, parseAssetUnit } from './value.js';
import type { AssetAmount, Value } from './value.js';

/** An unspent output the planner can spend. */
export interface Utxo {
  /** 64 lowercase hex characters. */
  readonly txHash: string;
  readonly index: number;
  readonly value: Value;
  /** The output's address as the backend reported it, when known. */
  readonly address?: string;
  /** Hex hash of a reference script sitting in this output, if any. */
  readonly referenceScriptHash?: string;
  /** Size in bytes of that reference script, when known (priced by the Conway ref-script fee). */
  readonly referenceScriptSize?: number;
  readonly datumHash?: string;
  readonly inlineDatum?: string;
}

/** Blockfrost/Koios-style UTXO (ZelCore's backend shape). */
export interface BackendUtxo {
  readonly tx_hash: string;
  readonly output_index: number;
  readonly amount: readonly {
    readonly unit: string;
    readonly quantity: string | number;
  }[];
  readonly address?: string;
  readonly reference_script_hash?: string | null;
  readonly inline_datum?: string | null;
  readonly data_hash?: string | null;
}

const TXID_RE = /^[0-9a-f]{64}$/;
const QTY_RE = /^\d{1,20}$/;

function qty(q: string | number): bigint {
  const s =
    typeof q === 'number'
      ? Number.isSafeInteger(q) && q >= 0
        ? String(q)
        : ''
      : q;
  if (!QTY_RE.test(s))
    throw invalidInput('quantity must be a non-negative integer');
  return BigInt(s);
}

/** Converts `[{ unit, quantity }]` (unit `lovelace` or `policyId ‖ assetNameHex`) to a Value. */
export function valueFromAmounts(amount: BackendUtxo['amount']): Value {
  let coin = 0n;
  let sawLovelace = false;
  const assets: AssetAmount[] = [];
  for (const a of amount) {
    if (a.unit === 'lovelace') {
      if (sawLovelace) throw invalidInput('duplicate lovelace entry');
      sawLovelace = true;
      coin = qty(a.quantity);
    } else {
      const { policyId, assetName } = parseAssetUnit(a.unit);
      const q = qty(a.quantity);
      if (q > 0n) assets.push({ policyId, assetName, quantity: q });
    }
  }
  return makeValue(coin, assets);
}

/** The inverse of `valueFromAmounts`. */
export function amountsFromValue(
  value: Value,
): { unit: string; quantity: string }[] {
  return [
    { unit: 'lovelace', quantity: value.coin.toString() },
    ...assetList(value).map((a) => ({
      unit: `${a.policyId}${a.assetName}`,
      quantity: a.quantity.toString(),
    })),
  ];
}

/** Validates and converts one backend UTXO. */
export function utxoFromBackend(u: BackendUtxo): Utxo {
  const txHash = u.tx_hash.toLowerCase();
  if (!TXID_RE.test(txHash))
    throw invalidInput('utxo tx_hash must be 64 hex characters');
  if (
    !Number.isInteger(u.output_index) ||
    u.output_index < 0 ||
    u.output_index > 0xffff
  ) {
    throw invalidInput('utxo output_index out of range');
  }
  return {
    txHash,
    index: u.output_index,
    value: valueFromAmounts(u.amount),
    ...(u.address ? { address: u.address } : {}),
    ...(u.reference_script_hash
      ? { referenceScriptHash: u.reference_script_hash }
      : {}),
    ...(u.inline_datum ? { inlineDatum: u.inline_datum } : {}),
    ...(u.data_hash ? { datumHash: u.data_hash } : {}),
  };
}

export function utxosFromBackend(list: readonly BackendUtxo[]): Utxo[] {
  return list.map(utxoFromBackend);
}

/** `txHash#index` with the hash lower-cased, so the same outpoint always gives the same key. */
export function outpointKey(u: Pick<Utxo, 'txHash' | 'index'>): string {
  return `${u.txHash.toLowerCase()}#${u.index}`;
}
