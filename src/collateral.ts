import { parseAddressInput } from './address.js';
import type { ParsedAddress } from './address.js';
import { bytesToHex, equalBytes, hexToBytes } from './bytes.js';
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
   * Accept collateral inputs missing from `ownUtxos` once each one is
   * accounted for by `resolvedCollateral`. Honoured only when `ownUtxos` is
   * given; otherwise (and when false) the 0.1.0 rules apply unchanged. With it,
   * every collateral input must be either listed in `ownUtxos` with a value,
   * or resolved: an input locked by one of the wallet's keys (see
   * `ownKeyHashes`) or paid to one of `ownAddresses` is valued at the resolved
   * lovelace and counts against the cap; an input locked by any other key or by
   * a script adds nothing to what the wallet can lose. A listed input without a
   * value, a Byron or unreadable resolved address, or no wallet key to compare
   * with is refused; an input missing from `resolvedCollateral` is refused with
   * `retryable: true`. The foreign-return refusal and the cap stay in force.
   * Set it only after the user was told what this covers.
   */
  readonly allowUnvalued?: boolean;
  /**
   * The collateral inputs looked up again by outpoint, each with its `address`
   * and value, from the caller's own chain backend (never from the dapp or the
   * transaction). Read only with `allowUnvalued`; entries without an address or
   * a lovelace value count as missing.
   */
  readonly resolvedCollateral?: readonly Utxo[];
  /**
   * Key hashes the wallet signs with (28 bytes, or 56 hex characters), besides
   * the payment and stake keys of `ownAddresses`. `signTxWitnessSet` adds its
   * signers' keys. Read only with `allowUnvalued`.
   */
  readonly ownKeyHashes?: readonly (string | Uint8Array)[];
}

/**
 * The collateral options `signTxWitnessSet` and `describeTransaction` take, in
 * their names; `collateralCheckOptions` maps them for `assessCollateral`.
 */
export interface WalletCollateralOptions {
  readonly ownUtxos?: readonly Utxo[];
  readonly maxCollateralAtRisk?: bigint;
  readonly allowForeignCollateralReturn?: boolean;
  readonly allowUnvaluedCollateral?: boolean;
  readonly resolvedCollateral?: readonly Utxo[];
  readonly ownKeyHashes?: readonly (string | Uint8Array)[];
}

/**
 * The one mapping from wallet-level options to `CollateralCheckOptions`, shared
 * by every entry point that decides on collateral. `signerKeyHashes` (the keys
 * that will sign) join `ownKeyHashes` when `allowUnvaluedCollateral` is set.
 */
export function collateralCheckOptions(
  ownAddresses: readonly (string | Uint8Array)[],
  params: ProtocolParams | undefined,
  o: WalletCollateralOptions,
  signerKeyHashes: readonly Uint8Array[] = [],
): CollateralCheckOptions {
  const keys = [...(o.ownKeyHashes ?? []), ...signerKeyHashes];
  return {
    ownAddresses,
    ...(o.ownUtxos ? { ownUtxos: o.ownUtxos } : {}),
    ...(o.maxCollateralAtRisk !== undefined
      ? { maxCollateralAtRisk: o.maxCollateralAtRisk }
      : {}),
    ...(params ? { params } : {}),
    ...(o.allowForeignCollateralReturn ? { allowForeignReturn: true } : {}),
    ...(o.allowUnvaluedCollateral
      ? {
          allowUnvalued: true,
          ...(o.resolvedCollateral
            ? { resolvedCollateral: o.resolvedCollateral }
            : {}),
          ...(keys.length > 0 ? { ownKeyHashes: keys } : {}),
        }
      : {}),
  };
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
  /**
   * Set (true) only when the refusal may clear on a retry with a fresh
   * `resolvedCollateral`: a collateral input could not be looked up.
   * `signTxWitnessSet` throws `COLLATERAL_UNRESOLVED` for it.
   */
  readonly retryable?: true;
}

interface InputProblem {
  readonly reason: string;
  readonly retryable: boolean;
}

interface InputValuation {
  /** Lovelace of the wallet's collateral inputs; null when an input is a problem. */
  readonly value: bigint | null;
  /** Lovelace of the wallet's inputs that could be valued (a floor when `value` is null). */
  readonly known: bigint;
  readonly anyOwnInput: boolean;
  /** The first refusal a retry cannot clear, else the first retryable one. */
  readonly problem: InputProblem | null;
}

/** 0.1.0: inputs valued from `ownUtxos` only (null if any cannot be). */
function valueFromOwnUtxos(
  inputs: DecodedTransaction['body']['collateral'],
  known: ReadonlyMap<string, Utxo>,
): InputValuation {
  let value: bigint | null = 0n;
  let anyOwnInput = false;
  for (const i of inputs) {
    const u = known.get(`${bytesToHex(i.txHash)}#${i.index}`);
    if (u) anyOwnInput = true;
    // Outpoint-only entries (no value) cannot value an input.
    const coin = (u as { value?: { coin?: unknown } } | undefined)?.value?.coin;
    if (typeof coin !== 'bigint') value = null;
    else if (value !== null) value += coin;
  }
  return { value, known: value ?? 0n, anyOwnInput, problem: null };
}

const coinOf = (u: Utxo | undefined): bigint | undefined => {
  const coin = (u as { value?: { coin?: unknown } } | undefined)?.value?.coin;
  return typeof coin === 'bigint' ? coin : undefined;
};

/** `allowUnvalued`: every input listed with a value, or resolved and judged by who can spend it. */
function valueWithResolution(
  inputs: DecodedTransaction['body']['collateral'],
  known: ReadonlyMap<string, Utxo>,
  own: readonly ParsedAddress[],
  options: CollateralCheckOptions,
): InputValuation {
  const keyHashes: Uint8Array[] = [];
  for (const a of own) {
    for (const c of [a.payment, a.stake])
      if (c?.type === 'key') keyHashes.push(c.hash);
  }
  for (const h of options.ownKeyHashes ?? []) {
    const b = typeof h === 'string' ? hexToBytes(h) : h;
    if (!(b instanceof Uint8Array) || b.length !== 28)
      throw invalidInput('ownKeyHashes entries must be 28-byte key hashes');
    keyHashes.push(b);
  }
  const resolved = new Map<string, Utxo>();
  const conflicting = new Set<string>();
  for (const u of options.resolvedCollateral ?? []) {
    const k = outpointKey(u);
    const prev = resolved.get(k);
    if (prev && (prev.address !== u.address || coinOf(prev) !== coinOf(u)))
      conflicting.add(k);
    resolved.set(k, u);
  }
  let value = 0n;
  let anyOwnInput = false;
  let fatal: InputProblem | null = null;
  let retry: InputProblem | null = null;
  const refuse = (reason: string) => {
    fatal ??= { reason, retryable: false };
  };
  const ours = (coin: bigint) => {
    anyOwnInput = true;
    value += coin;
  };
  for (const i of inputs) {
    const key = `${bytesToHex(i.txHash)}#${i.index}`;
    const listed = known.get(key);
    if (listed) {
      anyOwnInput = true;
      const coin = coinOf(listed);
      if (coin === undefined)
        refuse(
          `collateral input ${key} is listed among the wallet's UTXOs without a value`,
        );
      else value += coin;
      continue;
    }
    const r = resolved.get(key);
    const coin = coinOf(r);
    if (!r || typeof r.address !== 'string' || coin === undefined) {
      retry ??= {
        reason: `collateral input ${key} could not be looked up: retry with a fresh resolvedCollateral`,
        retryable: true,
      };
      continue;
    }
    if (conflicting.has(key)) {
      refuse(
        `collateral input ${key} is resolved twice with different contents`,
      );
      continue;
    }
    let addr: ParsedAddress;
    try {
      addr = parseAddressInput(r.address);
    } catch {
      refuse(`cannot read the address of collateral input ${key}`);
      continue;
    }
    if (own.some((a) => equalBytes(a.bytes, addr.bytes))) {
      ours(coin);
      continue;
    }
    if (addr.kind === 'byron' || addr.kind === 'reward') {
      refuse(
        `cannot tell whether the wallet can spend collateral input ${key} (a ${addr.kind} address)`,
      );
      continue;
    }
    if (addr.payment?.type === 'key') {
      if (keyHashes.length === 0) {
        refuse(
          `cannot tell whether the wallet can spend collateral input ${key}: no wallet key hashes`,
        );
        continue;
      }
      const hash = addr.payment.hash;
      if (keyHashes.some((h) => equalBytes(h, hash))) {
        ours(coin);
        continue;
      }
    }
    // Locked by a key the wallet does not sign with, or by a script (the
    // ledger accepts only key-locked collateral): not the wallet's to lose.
  }
  const problem = fatal ?? retry;
  return { value: problem ? null : value, known: value, anyOwnInput, problem };
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
  const ownParsed = options.ownAddresses.map((a) => parseAddressInput(a));
  const own = ownParsed.map((a) => a.bytes);
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

  // What the wallet's collateral inputs are worth (null if any cannot be
  // valued), and whether any collateral input is the wallet's.
  const known = new Map(
    (options.ownUtxos ?? []).map((u) => [outpointKey(u), u]),
  );
  const v =
    options.allowUnvalued && options.ownUtxos !== undefined
      ? valueWithResolution(inputs, known, ownParsed, options)
      : valueFromOwnUtxos(inputs, known);
  const inputsValue = v.value;
  const anyOwnInput = v.anyOwnInput;
  const problem = v.problem;

  const foreign = ret !== undefined && !returnIsOwn;
  let atRisk: bigint | null;
  let refusal: string | null = null;
  if (foreign) {
    const listed = options.ownUtxos?.length ?? 0;
    if (options.allowForeignReturn && listed > 0 && !anyOwnInput) {
      // Dapp-provided collateral: none of the wallet's known UTXOs is at stake
      // (with `allowUnvalued`, only once every input is resolved).
      atRisk = problem ? null : 0n;
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
  let retryable = false;
  if (!refusal) {
    // With an input problem (`allowUnvalued` only): at least this much is
    // lost even before the inputs a retry could resolve. Otherwise atRisk.
    const floor =
      atRisk ??
      (!problem
        ? null
        : foreign || total !== undefined
          ? 0n
          : ret
            ? v.known > ret.value.coin
              ? v.known - ret.value.coin
              : 0n
            : v.known);
    if (problem && !problem.retryable) {
      refusal = problem.reason;
    } else if (floor !== null && floor > cap) {
      refusal = `${atRisk === null ? 'at least ' : ''}${floor} lovelace of collateral would be lost if the scripts fail (limit ${cap})`;
    } else if (problem) {
      refusal = problem.reason;
      retryable = true;
    } else if (atRisk === null) {
      refusal =
        "cannot tell how much collateral is at risk: a collateral input is not among the wallet's known UTXOs";
    }
  }
  return {
    ...base,
    atRiskLovelace: atRisk,
    refusal,
    ...(retryable ? { retryable: true as const } : {}),
  };
}

/** The refusal reason of `assessCollateral`, or null. */
export function collateralRisk(
  d: DecodedTransaction,
  options: CollateralCheckOptions,
): string | null {
  return assessCollateral(d, options).refusal;
}
