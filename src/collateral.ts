import { parseAddressInput } from './address.js';
import { bytesToHex, equalBytes } from './bytes.js';
import { invalidInput } from './errors.js';
import { maxTransactionFee } from './fee.js';
import { MAINNET_DEFAULTS, validateParams } from './params.js';
import type { ProtocolParams } from './params.js';
import type { DecodedOutput, DecodedTransaction } from './tx/decode.js';
import { outpointKey } from './utxo.js';
import type { Utxo } from './utxo.js';

/**
 * Collateral is forfeited when a transaction's scripts fail — and `is_valid`
 * is not covered by the signature, so the submitter (the dapp) can declare
 * them failed after the user signs. What the wallet then loses:
 *
 * - `total_collateral` (body key 17) when it is stated: the ledger enforces it;
 * - otherwise the collateral inputs minus the collateral return (all of them
 *   with no return), which can only be valued for inputs the wallet knows
 *   (`ownUtxos`).
 *
 * A return that pays anyone but the wallet hands them the whole collateral.
 *
 * The default cap comes from the protocol parameters, never from the
 * transaction: the dapp chooses the fee and pays it from its own inputs, which
 * are never spent when it flips `is_valid`.
 */

/** Floor of the default cap on collateral at risk. */
export const MIN_COLLATERAL_CAP = 5_000_000n;

/**
 * Ceiling of the default cap on collateral at risk (25 ADA), whatever the
 * parameters say: parameters within `DEFAULT_PARAM_BOUNDS` could otherwise lift
 * it to millions of ADA. An explicit `maxCollateralAtRisk` is not clamped.
 */
export const MAX_DEFAULT_COLLATERAL_CAP = 25_000_000n;

/**
 * Default cap on collateral at risk: 1.5 × the largest fee a valid transaction
 * can need under `params`, clamped to [5 ADA, 25 ADA] — about 13.3 ADA on
 * mainnet. The ledger requires collateral of at least `collateralPercentage`
 * (150 %) of the fee. Throws `INVALID_PARAMS` for parameters outside
 * `DEFAULT_PARAM_BOUNDS`.
 */
export function defaultCollateralCap(
  params: ProtocolParams = MAINNET_DEFAULTS,
): bigint {
  const bound = (maxTransactionFee(validateParams(params)) * 3n + 1n) / 2n;
  if (bound < MIN_COLLATERAL_CAP) return MIN_COLLATERAL_CAP;
  return bound > MAX_DEFAULT_COLLATERAL_CAP
    ? MAX_DEFAULT_COLLATERAL_CAP
    : bound;
}

export interface CollateralCheckOptions {
  /** The wallet's own addresses; the collateral return must pay one of them exactly. */
  readonly ownAddresses: readonly (string | Uint8Array)[];
  /** The wallet's UTXOs with their values, used to value collateral inputs when no total is stated. */
  readonly ownUtxos?: readonly Utxo[];
  /** Most lovelace the wallet may lose if the scripts fail (default `defaultCollateralCap(params)`). */
  readonly maxCollateralAtRisk?: bigint;
  /** Protocol parameters for the default cap (default: mainnet). */
  readonly params?: ProtocolParams;
  /**
   * Accept a collateral return to someone else — only when `ownUtxos` is
   * non-empty and none of the collateral inputs are among them (dapp-provided
   * collateral). This trusts `ownUtxos` to list every UTXO at every address
   * form the wallet can sign for (base, enterprise, pointer, any account).
   * Every other check, including the cap, stays in force.
   */
  readonly allowForeignReturn?: boolean;
  /**
   * Accept collateral that cannot be valued: an input not among `ownUtxos` with no
   * `total_collateral` stated, when the return pays the wallet or there is none. Honoured only
   * when `ownUtxos` is given (the caller looked and the input is not listed). The foreign-return
   * check and the cap on valued collateral stay in force. Set it only after the user was told
   * that the amount at risk is unknown.
   */
  readonly allowUnvalued?: boolean;
}

export interface CollateralAssessment {
  readonly inputCount: number;
  /** `total_collateral` (body key 17), when stated. */
  readonly total?: bigint;
  readonly returnOutput?: DecodedOutput;
  /** The return pays one of the wallet's addresses exactly (false when there is none). */
  readonly returnIsOwn: boolean;
  /**
   * Lovelace lost if the scripts fail: every collateral input when the return
   * is foreign; `total_collateral` when stated; else the valued inputs minus an
   * own return (or all of them with no return). 0 without collateral; null when
   * it cannot be computed (treat as every collateral input).
   */
  readonly atRiskLovelace: bigint | null;
  /** The cap in force: `maxCollateralAtRisk`, or `defaultCollateralCap(params)`. */
  readonly cap: bigint;
  /** Why the wallet should refuse to sign, or null. */
  readonly refusal: string | null;
}

/** Judges a transaction's collateral against the wallet's addresses, known UTXOs and cap. */
export function assessCollateral(
  d: DecodedTransaction,
  options: CollateralCheckOptions,
): CollateralAssessment {
  // A plain boolean check: Array.isArray would narrow the list to any[].
  const isList = (x: unknown): boolean => Array.isArray(x);
  if (!isList(options.ownAddresses))
    throw invalidInput('ownAddresses is required');
  const inputs = d.body.collateral;
  const total = d.body.totalCollateral;
  const ret = d.body.collateralReturn;
  const cap =
    options.maxCollateralAtRisk ?? defaultCollateralCap(options.params);
  const own = options.ownAddresses.map((a) => parseAddressInput(a).bytes);
  const returnIsOwn =
    ret !== undefined && own.some((b) => equalBytes(b, ret.address));
  const base = {
    inputCount: inputs.length,
    ...(total !== undefined ? { total } : {}),
    ...(ret ? { returnOutput: ret } : {}),
    returnIsOwn,
    cap,
  };
  if (inputs.length === 0)
    return { ...base, atRiskLovelace: 0n, refusal: null };

  // Sum of the collateral inputs the wallet can value (null if any cannot be),
  // and whether any collateral input is one of the wallet's known UTXOs.
  const known = new Map(
    (options.ownUtxos ?? []).map((u) => [outpointKey(u), u]),
  );
  let inputsValue: bigint | null = 0n;
  let anyOwnInput = false;
  for (const i of inputs) {
    const u = known.get(`${bytesToHex(i.txHash)}#${i.index}`);
    if (u) anyOwnInput = true;
    // Outpoint-only entries (no value) cannot value an input.
    const coin = (u as { value?: { coin?: unknown } } | undefined)?.value?.coin;
    if (typeof coin !== 'bigint') inputsValue = null;
    else if (inputsValue !== null) inputsValue += coin;
  }

  const foreign = ret !== undefined && !returnIsOwn;
  let atRisk: bigint | null;
  let refusal: string | null = null;
  if (foreign) {
    const listed = options.ownUtxos?.length ?? 0;
    if (options.allowForeignReturn && listed > 0 && !anyOwnInput) {
      // Dapp-provided collateral: none of the wallet's known UTXOs is at stake.
      atRisk = 0n;
    } else {
      // The return goes to someone else: every collateral input is lost to the wallet.
      atRisk = inputsValue;
      const why = !options.allowForeignReturn
        ? ''
        : anyOwnInput
          ? " (a collateral input is the wallet's own)"
          : options.ownUtxos === undefined
            ? ' (without ownUtxos the wallet cannot tell the collateral is not its own)'
            : ' (ownUtxos is empty, so the wallet cannot tell the collateral is not its own)';
      refusal = `the collateral return pays an address outside this wallet: if the scripts fail, the collateral goes there${why}`;
    }
  } else if (total !== undefined) {
    // Own or no return: the ledger takes exactly total_collateral.
    atRisk = total;
  } else if (ret) {
    atRisk =
      inputsValue === null
        ? null
        : inputsValue > ret.value.coin
          ? inputsValue - ret.value.coin
          : 0n;
  } else {
    // No return and no stated total: every collateral input, valued from ownUtxos.
    atRisk = inputsValue;
  }
  if (!refusal) {
    if (atRisk === null) {
      if (!(options.allowUnvalued && options.ownUtxos !== undefined))
        refusal =
          "cannot tell how much collateral is at risk: a collateral input is not among the wallet's known UTXOs";
    } else if (atRisk > cap) {
      refusal = `${atRisk} lovelace of collateral would be lost if the scripts fail (limit ${cap})`;
    }
  }
  return { ...base, atRiskLovelace: atRisk, refusal };
}

/** The refusal reason of `assessCollateral`, or null. */
export function collateralRisk(
  d: DecodedTransaction,
  options: CollateralCheckOptions,
): string | null {
  return assessCollateral(d, options).refusal;
}
