import { encodeCbor } from './cbor/encode.js';
import { invalidInput } from './errors.js';
import { MAINNET_EXECUTION } from './params.js';
import type { ProtocolParams, Rational } from './params.js';
import { encodeOutput } from './tx/encode.js';
import type { TxOutput } from './tx/model.js';
import { encodeValue } from './value.js';
import type { Value } from './value.js';

/** `minFeeA × size + minFeeB` for a signed transaction of `size` bytes. */
export function linearFee(
  size: number,
  params: Pick<ProtocolParams, 'minFeeA' | 'minFeeB'>,
): bigint {
  if (!Number.isInteger(size) || size < 0)
    throw invalidInput('size must be a non-negative integer');
  return params.minFeeA * BigInt(size) + params.minFeeB;
}

/**
 * Conway reference-script fee: the price per byte starts at `costPerByte` and
 * is multiplied by 1.2 for every full 25,600-byte tier; the total is floored
 * once at the end (`tierRefScriptFee` in cardano-ledger).
 */
export function referenceScriptFee(
  totalBytes: number,
  costPerByte: Rational,
): bigint {
  if (!Number.isInteger(totalBytes) || totalBytes < 0)
    throw invalidInput('size must be a non-negative integer');
  if (totalBytes === 0) return 0n;
  const STRIDE = 25_600n;
  // Exact rational arithmetic: price = costPerByte × (6/5)^tier.
  let accNum = 0n;
  let accDen = 1n;
  let priceNum = costPerByte.num;
  let priceDen = costPerByte.den;
  let remaining = BigInt(totalBytes);
  for (;;) {
    const chunk = remaining < STRIDE ? remaining : STRIDE;
    // acc += chunk × price
    accNum = accNum * priceDen + chunk * priceNum * accDen;
    accDen = accDen * priceDen;
    remaining -= chunk;
    if (remaining === 0n) break;
    priceNum *= 6n;
    priceDen *= 5n;
  }
  return accNum / accDen;
}

export function outputSize(output: TxOutput): number {
  return encodeOutput(output).length;
}

/** Serialized size of a value (checked against `maxValueSize`). */
export function valueSize(value: Value): number {
  return encodeCbor(encodeValue(value)).length;
}

/**
 * The ledger's minimum for an output as it is encoded now:
 * `coinsPerUtxoByte × (160 + size(output))`. An output is valid when its coin
 * is at least this.
 */
export function requiredAda(
  output: TxOutput,
  coinsPerUtxoByte: bigint,
): bigint {
  return coinsPerUtxoByte * BigInt(160 + outputSize(output));
}

/**
 * The smallest coin that makes `output` valid, accounting for the coin's own
 * encoded width. Same algorithm (and result) as CSL `min_ada_for_output`.
 */
export function minAdaForOutput(
  output: TxOutput,
  coinsPerUtxoByte: bigint,
): bigint {
  let o = output;
  for (let i = 0; i < 3; i++) {
    const required = requiredAda(o, coinsPerUtxoByte);
    if (o.value.coin < required)
      o = { ...o, value: { ...o.value, coin: required } };
    else return required;
  }
  return requiredAda(
    { ...o, value: { ...o.value, coin: (1n << 64n) - 1n } },
    coinsPerUtxoByte,
  );
}

export function isOutputAboveMinimum(
  output: TxOutput,
  coinsPerUtxoByte: bigint,
): boolean {
  return output.value.coin >= requiredAda(output, coinsPerUtxoByte);
}

/** Conway ledger constant: most reference-script bytes one transaction may use (`maxRefScriptSizePerTx`). */
export const MAX_REF_SCRIPT_SIZE_PER_TX = 204_800;

/**
 * The largest fee a valid transaction can need under `params`: the linear fee
 * at `maxTxSize`, plus the full execution budget at the execution prices
 * (rounded up, as the ledger does), plus the reference-script fee at the
 * per-transaction limit. About 8.9 ADA on mainnet (epoch 658).
 */
export function maxTransactionFee(params: ProtocolParams): bigint {
  const priceMem = params.priceMem ?? MAINNET_EXECUTION.priceMem;
  const priceStep = params.priceStep ?? MAINNET_EXECUTION.priceStep;
  const mem = params.maxTxExMem ?? MAINNET_EXECUTION.maxTxExMem;
  const steps = params.maxTxExSteps ?? MAINNET_EXECUTION.maxTxExSteps;
  // ceil(mem × priceMem + steps × priceStep), over a common denominator.
  const num =
    mem * priceMem.num * priceStep.den + steps * priceStep.num * priceMem.den;
  const den = priceMem.den * priceStep.den;
  const execution = (num + den - 1n) / den;
  return (
    linearFee(params.maxTxSize, params) +
    execution +
    referenceScriptFee(
      MAX_REF_SCRIPT_SIZE_PER_TX,
      params.minFeeRefScriptCostPerByte,
    )
  );
}
