import { CardanoError } from './errors.js';

/** A non-negative rational, as the ledger uses for some fee parameters. */
export interface Rational {
  readonly num: bigint;
  readonly den: bigint;
}

/** The protocol parameters transaction building needs. */
export interface ProtocolParams {
  /** Lovelace per byte of the signed transaction (`min_fee_a`). */
  readonly minFeeA: bigint;
  /** Constant lovelace per transaction (`min_fee_b`). */
  readonly minFeeB: bigint;
  /** Lovelace per byte of a serialized output, plus 160 bytes overhead (Babbage onwards). */
  readonly coinsPerUtxoByte: bigint;
  readonly maxTxSize: number;
  /** Maximum serialized size of an output's value. */
  readonly maxValueSize: number;
  /** Base price per byte of reference scripts (Conway), tiered ×1.2 every 25 KiB. */
  readonly minFeeRefScriptCostPerByte: Rational;
  readonly keyDeposit: bigint;
  readonly poolDeposit: bigint;
  /**
   * Plutus execution prices (lovelace per memory unit / per CPU step) and the
   * per-transaction execution limits. Optional (mainnet defaults apply); used
   * to bound the largest fee a valid transaction can need.
   */
  readonly priceMem?: Rational;
  readonly priceStep?: Rational;
  readonly maxTxExMem?: bigint;
  readonly maxTxExSteps?: bigint;
}

/** Mainnet Plutus execution prices and per-transaction limits (epoch 658). */
export const MAINNET_EXECUTION: {
  readonly priceMem: Rational;
  readonly priceStep: Rational;
  readonly maxTxExMem: bigint;
  readonly maxTxExSteps: bigint;
} = Object.freeze({
  priceMem: Object.freeze({ num: 577n, den: 10_000n }),
  priceStep: Object.freeze({ num: 721n, den: 10_000_000n }),
  maxTxExMem: 16_500_000n,
  maxTxExSteps: 10_000_000_000n,
});

/** Mainnet values (protocol version 11, epoch 658, 2026-09-29). */
export const MAINNET_DEFAULTS: ProtocolParams = Object.freeze({
  minFeeA: 44n,
  minFeeB: 155381n,
  coinsPerUtxoByte: 4310n,
  maxTxSize: 16384,
  maxValueSize: 5000,
  minFeeRefScriptCostPerByte: Object.freeze({ num: 15n, den: 1n }),
  keyDeposit: 2000000n,
  poolDeposit: 500000000n,
  ...MAINNET_EXECUTION,
});

/** Sanity bounds for parameters fetched from a backend, so a lying server cannot make fees or min-ADA absurd. */
export interface ParamBounds {
  readonly maxMinFeeA: bigint;
  readonly maxMinFeeB: bigint;
  readonly maxCoinsPerUtxoByte: bigint;
  readonly maxTxSizeLimit: number;
  readonly maxValueSizeLimit: number;
  readonly maxRefScriptCostPerByte: bigint;
  readonly maxKeyDeposit: bigint;
  /** Execution-unit bounds (optional; the defaults below apply). */
  readonly maxPriceMem?: bigint;
  readonly maxPriceStep?: bigint;
  readonly maxTxExMemLimit?: bigint;
  readonly maxTxExStepsLimit?: bigint;
}

export const DEFAULT_PARAM_BOUNDS: ParamBounds = Object.freeze({
  maxMinFeeA: 1000n,
  maxMinFeeB: 10_000_000n,
  maxCoinsPerUtxoByte: 100_000n,
  maxTxSizeLimit: 1 << 20,
  maxValueSizeLimit: 1 << 20,
  maxRefScriptCostPerByte: 10_000n,
  maxKeyDeposit: 100_000_000n,
  maxPriceMem: 10n,
  maxPriceStep: 1n,
  maxTxExMemLimit: 10_000_000_000n,
  maxTxExStepsLimit: 10_000_000_000_000n,
});

const bad = (message: string): CardanoError =>
  new CardanoError('INVALID_PARAMS', message);

export function validateParams(
  p: ProtocolParams,
  bounds: ParamBounds = DEFAULT_PARAM_BOUNDS,
): ProtocolParams {
  const inRange = (v: bigint, max: bigint, name: string): void => {
    if (v < 0n || v > max) throw bad(`${name} out of range`);
  };
  inRange(p.minFeeA, bounds.maxMinFeeA, 'minFeeA');
  inRange(p.minFeeB, bounds.maxMinFeeB, 'minFeeB');
  if (p.coinsPerUtxoByte < 1n) throw bad('coinsPerUtxoByte out of range');
  inRange(p.coinsPerUtxoByte, bounds.maxCoinsPerUtxoByte, 'coinsPerUtxoByte');
  if (
    !Number.isInteger(p.maxTxSize) ||
    p.maxTxSize < 1024 ||
    p.maxTxSize > bounds.maxTxSizeLimit
  ) {
    throw bad('maxTxSize out of range');
  }
  if (
    !Number.isInteger(p.maxValueSize) ||
    p.maxValueSize < 100 ||
    p.maxValueSize > bounds.maxValueSizeLimit
  ) {
    throw bad('maxValueSize out of range');
  }
  const r = p.minFeeRefScriptCostPerByte;
  if (
    r.den <= 0n ||
    r.num < 0n ||
    r.num > bounds.maxRefScriptCostPerByte * r.den
  ) {
    throw bad('minFeeRefScriptCostPerByte out of range');
  }
  inRange(p.keyDeposit, bounds.maxKeyDeposit, 'keyDeposit');
  if (p.poolDeposit < 0n) throw bad('poolDeposit out of range');
  const ratio = (x: Rational | undefined, max: bigint, name: string): void => {
    if (x === undefined) return;
    if (x.den <= 0n || x.num < 0n || x.num > max * x.den)
      throw bad(`${name} out of range`);
  };
  ratio(p.priceMem, bounds.maxPriceMem ?? 10n, 'priceMem');
  ratio(p.priceStep, bounds.maxPriceStep ?? 1n, 'priceStep');
  if (p.maxTxExMem !== undefined)
    inRange(
      p.maxTxExMem,
      bounds.maxTxExMemLimit ?? 10_000_000_000n,
      'maxTxExMem',
    );
  if (p.maxTxExSteps !== undefined) {
    inRange(
      p.maxTxExSteps,
      bounds.maxTxExStepsLimit ?? 10_000_000_000_000n,
      'maxTxExSteps',
    );
  }
  return p;
}

const INT_RE = /^\d{1,30}$/;
const DEC_RE = /^(\d{1,20})(?:\.(\d{1,18}))?(?:[eE]([+-]?\d{1,3}))?$/;

function toBigInt(v: unknown, name: string): bigint {
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0)
    return BigInt(v);
  if (typeof v === 'string' && INT_RE.test(v)) return BigInt(v);
  if (typeof v === 'bigint' && v >= 0n) return v;
  throw bad(`${name} missing or not a non-negative integer`);
}

function toSmall(v: unknown, name: string): number {
  const b = toBigInt(v, name);
  if (b > BigInt(Number.MAX_SAFE_INTEGER)) throw bad(`${name} too large`);
  return Number(b);
}

/** Parses `15`, `"15"`, `15.5`, `"44.5"` or `7.21e-05` into an exact rational. */
export function parseRational(v: unknown, name: string): Rational {
  const s =
    typeof v === 'number'
      ? Number.isFinite(v) && v >= 0
        ? String(v)
        : ''
      : typeof v === 'string'
        ? v
        : '';
  const m = DEC_RE.exec(s);
  if (!m) throw bad(`${name} missing or not a non-negative decimal`);
  const frac = m[2] ?? '';
  const exp = Number(m[3] ?? '0');
  if (Math.abs(exp) > 30) throw bad(`${name} exponent out of range`);
  let num = BigInt(`${m[1] ?? '0'}${frac}`);
  let den = 10n ** BigInt(frac.length);
  if (exp > 0) num *= 10n ** BigInt(exp);
  else if (exp < 0) den *= 10n ** BigInt(-exp);
  return { num, den };
}

/** Execution prices and limits, when the backend reports them. */
function optionalExUnits(o: Record<string, unknown>): Partial<ProtocolParams> {
  const present = (k: string): boolean => o[k] !== undefined && o[k] !== null;
  return {
    ...(present('price_mem')
      ? { priceMem: parseRational(o['price_mem'], 'price_mem') }
      : {}),
    ...(present('price_step')
      ? { priceStep: parseRational(o['price_step'], 'price_step') }
      : {}),
    ...(present('max_tx_ex_mem')
      ? { maxTxExMem: toBigInt(o['max_tx_ex_mem'], 'max_tx_ex_mem') }
      : {}),
    ...(present('max_tx_ex_steps')
      ? { maxTxExSteps: toBigInt(o['max_tx_ex_steps'], 'max_tx_ex_steps') }
      : {}),
  };
}

function obj(json: unknown): Record<string, unknown> {
  const o = Array.isArray(json) ? (json[0] as unknown) : json;
  if (typeof o !== 'object' || o === null)
    throw bad('parameters must be an object');
  return o as Record<string, unknown>;
}

/**
 * Blockfrost `GET /epochs/latest/parameters`. Older backends expose
 * `coins_per_utxo_word`; only `coins_per_utxo_size` is accepted here.
 */
export function parseBlockfrostParams(
  json: unknown,
  bounds: ParamBounds = DEFAULT_PARAM_BOUNDS,
): ProtocolParams {
  const o = obj(json);
  const ref = o['min_fee_ref_script_cost_per_byte'];
  return validateParams(
    {
      minFeeA: toBigInt(o['min_fee_a'], 'min_fee_a'),
      minFeeB: toBigInt(o['min_fee_b'], 'min_fee_b'),
      coinsPerUtxoByte: toBigInt(
        o['coins_per_utxo_size'],
        'coins_per_utxo_size',
      ),
      maxTxSize: toSmall(o['max_tx_size'], 'max_tx_size'),
      maxValueSize: toSmall(o['max_val_size'], 'max_val_size'),
      minFeeRefScriptCostPerByte:
        ref === null || ref === undefined
          ? MAINNET_DEFAULTS.minFeeRefScriptCostPerByte
          : parseRational(ref, 'min_fee_ref_script_cost_per_byte'),
      keyDeposit: toBigInt(o['key_deposit'], 'key_deposit'),
      poolDeposit: toBigInt(o['pool_deposit'], 'pool_deposit'),
      ...optionalExUnits(o),
    },
    bounds,
  );
}

/** Koios `GET /epoch_params` (an array; the first row is used) or a single row. */
export function parseKoiosParams(
  json: unknown,
  bounds: ParamBounds = DEFAULT_PARAM_BOUNDS,
): ProtocolParams {
  // Koios uses the same snake_case names as Blockfrost for everything we read.
  return parseBlockfrostParams(obj(json), bounds);
}
