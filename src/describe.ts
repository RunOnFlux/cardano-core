import { addressToString, parseAddress, parseAddressInput } from './address.js';
import type { ParsedAddress } from './address.js';
import { bytesToHex, equalBytes, hexToBytes } from './bytes.js';
import { bech32Encode } from './encoding.js';
import { assessCollateral } from './collateral.js';
import { MAINNET_DEFAULTS } from './params.js';
import type { ProtocolParams } from './params.js';
import { decodeTransaction } from './tx/decode.js';
import type { DecodedTransaction, DRep } from './tx/decode.js';
import { addValues, coinValue, sumValues } from './value.js';
import type { Utxo } from './utxo.js';
import type { Value } from './value.js';

export interface DescribedOutput {
  /** bech32/base58, or hex when the bytes are not a valid address. */
  readonly address: string;
  readonly value: Value;
  /** The address is byte-for-byte one of the wallet's own addresses. */
  readonly own: boolean;
  /**
   * Not one of our addresses, but its payment credential is one of our keys:
   * spendable by us, yet invisible to the wallet and staked by someone else
   * (a "franken" address). Counted as leaving the wallet.
   */
  readonly ourPaymentKeyForeignAddress: boolean;
}

export interface CertificateSummary {
  readonly kind: string;
  /** The certificate's credential is a stake key of this wallet. */
  readonly ownCredential: boolean;
  /** Deposit taken (positive) or refunded (negative), in lovelace. */
  readonly depositDelta: bigint;
  readonly pool?: string;
  readonly drep?: string;
}

/**
 * Collateral and what the wallet loses if the transaction's scripts fail.
 * `is_valid` is not covered by the signature, so the submitter (the dapp)
 * decides that after signing: treat collateral at risk as real.
 */
export interface CollateralDescription {
  readonly inputCount: number;
  /** `total_collateral` (body key 17), when stated. */
  readonly total?: bigint;
  /** The collateral return output (body key 16), described like any output. */
  readonly return?: DescribedOutput;
  /** The return pays one of the wallet's addresses exactly. */
  readonly returnIsOwn: boolean;
  /**
   * Lovelace lost if the scripts fail (`total_collateral`, or valued inputs
   * minus an own return); null when it cannot be computed — then every
   * collateral input is at risk.
   */
  readonly atRiskLovelace: bigint | null;
  /** Cap `signTxWitnessSet` applies (default `defaultCollateralCap(params)`, about 13.3 ADA on mainnet). */
  readonly cap: bigint;
  /** Why `signTxWitnessSet` refuses this transaction, or null. */
  readonly refusal: string | null;
}

export interface TransactionDescription {
  readonly txIdHex: string;
  readonly fee: bigint;
  readonly outputs: readonly DescribedOutput[];
  /** Sum of outputs not paid to one of the wallet's own addresses. */
  readonly toOthers: Value;
  /** Deposits certificates take (stake, pool, DRep registrations). */
  readonly deposits: bigint;
  /** Deposits certificates release back into this transaction. */
  readonly refunds: bigint;
  /** Governance proposal deposits (returned later to each proposal's reward account). */
  readonly proposalDeposits: bigint;
  /** Treasury donation (body key 22). */
  readonly donation: bigint;
  readonly withdrawals: { readonly own: bigint; readonly foreign: bigint };
  readonly mint: readonly {
    readonly policyId: string;
    readonly assetName: string;
    readonly quantity: bigint;
  }[];
  readonly certificates: readonly string[];
  readonly certificateDetails: readonly CertificateSummary[];
  /** Pools named by delegations, registrations and retirements (bech32 `pool1…`). */
  readonly pools: readonly string[];
  /** DReps votes are delegated to or registered. */
  readonly dreps: readonly string[];
  /** Reward accounts outside the wallet that receive refunds, pool rewards or withdrawals. */
  readonly foreignRewardAccounts: readonly string[];
  readonly validity: { readonly from?: bigint; readonly until?: bigint };
  readonly hasScripts: boolean;
  readonly hasGovernance: boolean;
  readonly hasCollateral: boolean;
  /** Collateral and what is lost if the scripts fail — separate from `totalOutflow`. */
  readonly collateral: CollateralDescription;
  /**
   * Headline next to `totalOutflow`: lovelace lost if the scripts fail (0 without
   * collateral); null when it cannot be computed (every collateral input).
   */
  readonly collateralAtRisk: bigint | null;
  readonly unknownBodyKeys: readonly string[];
  /** Certificates of kinds this library does not know (their deposits are not counted). */
  readonly unknownCertificates: number;
  /** Human-readable flags for a signing prompt. */
  readonly warnings: readonly string[];
}

export interface DescribeOptions {
  /** Every address of the wallet (base and reward), in any form `parseAddressInput` accepts. */
  readonly addresses?: readonly (string | Uint8Array)[];
  /**
   * Deposits for certificates that do not state them (tags 0, 1, 3) and the
   * parameters behind the default collateral cap. Missing fields: mainnet.
   */
  readonly params?: Partial<ProtocolParams>;
  /** The wallet's UTXOs with values, to value collateral inputs when no total is stated. */
  readonly ownUtxos?: readonly Utxo[];
  /** Cap on collateral at risk (default `defaultCollateralCap(params)`), as `signTxWitnessSet` applies it. */
  readonly maxCollateralAtRisk?: bigint;
}

function drepLabel(d: DRep): string {
  return d.kind === 'abstain' || d.kind === 'no_confidence'
    ? d.kind
    : `${d.kind}:${bytesToHex(d.hash)}`;
}

function rewardLabel(bytes: Uint8Array): string {
  try {
    return addressToString(parseAddress(bytes));
  } catch {
    return bytesToHex(bytes);
  }
}

/**
 * A summary of what a (dapp-supplied) transaction does, for a signing prompt.
 * Ownership is decided only by exact address bytes: pass every address of the
 * wallet. The input values cannot be known without a UTXO lookup, so a prompt
 * should headline `totalOutflow` (everything that leaves or is locked) and show
 * `totalInflow` (withdrawals and refunds) separately.
 */
export function describeTransaction(
  tx: DecodedTransaction | string | Uint8Array,
  options: DescribeOptions = {},
): TransactionDescription {
  const d =
    typeof tx === 'string' || tx instanceof Uint8Array
      ? decodeTransaction(typeof tx === 'string' ? hexToBytes(tx) : tx)
      : tx;
  const params: ProtocolParams = { ...MAINNET_DEFAULTS, ...options.params };
  const own = (options.addresses ?? []).map((a) => parseAddressInput(a));
  const ownBytes = own.map((p) => p.bytes);
  const ownPaymentKeys = own.flatMap((p) =>
    p.payment?.type === 'key' ? [p.payment.hash] : [],
  );
  const ownStakeKeys = own.flatMap((p) =>
    p.stake?.type === 'key' ? [p.stake.hash] : [],
  );
  const isOwnStake = (hash: Uint8Array): boolean =>
    ownStakeKeys.some((h) => equalBytes(h, hash));
  const isOwnAddress = (bytes: Uint8Array): boolean =>
    ownBytes.some((o) => equalBytes(o, bytes));
  const isOwnReward = (bytes: Uint8Array): boolean => {
    let parsed: ParsedAddress;
    try {
      parsed = parseAddress(bytes);
    } catch {
      return false;
    }
    return (
      parsed.kind === 'reward' &&
      parsed.stake?.type === 'key' &&
      isOwnStake(parsed.stake.hash) &&
      own.some((o) => o.network === parsed.network)
    );
  };

  const warnings: string[] = [];
  const foreignRewardAccounts = new Set<string>();

  const describeOutput = (o: {
    readonly address: Uint8Array;
    readonly value: Value;
  }): DescribedOutput => {
    let parsed: ParsedAddress | undefined;
    try {
      parsed = parseAddress(o.address);
    } catch {
      parsed = undefined;
    }
    const ownOut = isOwnAddress(o.address);
    const payment = parsed?.payment;
    const franken =
      !ownOut &&
      payment?.type === 'key' &&
      ownPaymentKeys.some((h) => equalBytes(h, payment.hash));
    return {
      address: parsed ? addressToString(parsed) : bytesToHex(o.address),
      value: o.value,
      own: ownOut,
      ourPaymentKeyForeignAddress: franken,
    };
  };
  const outputs: DescribedOutput[] = d.body.outputs.map(describeOutput);
  if (outputs.some((o) => o.ourPaymentKeyForeignAddress)) {
    warnings.push(
      "pays an address with this wallet's payment key but another stake part (not shown as your balance)",
    );
  }

  // Certificates: deposits, refunds, pools, DReps.
  let deposits = 0n;
  let refunds = 0n;
  const pools = new Set<string>();
  const dreps = new Set<string>();
  let foreignDeposit = false;
  const certificateDetails: CertificateSummary[] = d.body.certificates.map(
    (c) => {
      let delta = 0n;
      if (c.deposit !== undefined) delta = c.deposit;
      else if (c.refund !== undefined) delta = -c.refund;
      else if (c.kind === 'stake_registration') delta = params.keyDeposit;
      else if (c.kind === 'stake_deregistration') delta = -params.keyDeposit;
      else if (c.kind === 'pool_registration') delta = params.poolDeposit;
      if (delta > 0n) deposits += delta;
      else refunds += -delta;
      const ownCredential =
        c.credential?.type === 'key' && isOwnStake(c.credential.hash);
      if (delta > 0n && !ownCredential) foreignDeposit = true;
      const pool = c.poolKeyHash
        ? bech32Encode('pool', c.poolKeyHash)
        : undefined;
      if (pool) pools.add(pool);
      let drep: string | undefined;
      if (c.drep) drep = drepLabel(c.drep);
      else if (c.kind.endsWith('drep_cert') && c.credential) {
        drep = `${c.credential.type}:${bytesToHex(c.credential.hash)}`;
      }
      if (drep) dreps.add(drep);
      if (c.poolRewardAccount && !isOwnReward(c.poolRewardAccount)) {
        foreignRewardAccounts.add(rewardLabel(c.poolRewardAccount));
      }
      return {
        kind: c.kind,
        ownCredential,
        depositDelta: delta,
        ...(pool ? { pool } : {}),
        ...(drep ? { drep } : {}),
      };
    },
  );
  if (d.body.certificates.length > 0) {
    warnings.push('includes certificates (staking or governance)');
  }
  if (deposits > 0n) {
    warnings.push(`locks ${deposits} lovelace in certificate deposits`);
  }
  if (foreignDeposit) {
    warnings.push(
      'pays deposits for credentials that are not this wallet’s (the refund goes to them)',
    );
  }
  if (d.body.certificates.some((c) => c.kind === 'pool_registration')) {
    warnings.push('registers or updates a stake pool');
  }
  if (d.body.certificates.some((c) => c.kind === 'pool_retirement')) {
    warnings.push('retires a stake pool');
  }
  if (pools.size > 0)
    warnings.push(`names stake pools: ${[...pools].join(', ')}`);
  if (dreps.size > 0) {
    warnings.push(
      `delegates votes to or registers DReps: ${[...dreps].join(', ')}`,
    );
  }

  // Governance proposals: each deposit goes back to the proposal's reward account.
  let proposalDeposits = 0n;
  for (const p of d.body.proposals) {
    proposalDeposits += p.deposit;
    if (!isOwnReward(p.rewardAccount)) {
      foreignRewardAccounts.add(rewardLabel(p.rewardAccount));
    }
  }
  if (proposalDeposits > 0n) {
    warnings.push(
      `locks ${proposalDeposits} lovelace in governance proposal deposits`,
    );
  }

  // Withdrawals.
  let ownW = 0n;
  let foreignW = 0n;
  for (const w of d.body.withdrawals) {
    if (isOwnReward(w.rewardAddress)) ownW += w.amount;
    else {
      foreignW += w.amount;
      foreignRewardAccounts.add(rewardLabel(w.rewardAddress));
    }
  }
  if (d.body.withdrawals.length > 0) warnings.push('withdraws rewards');
  if (foreignW > 0n) {
    warnings.push('withdraws rewards from accounts that are not this wallet’s');
  }

  const witnessKeys = new Set(d.witnessSet.keys);
  const hasScripts =
    d.body.scriptDataHash !== undefined ||
    [3, 5, 6, 7].some((k) => witnessKeys.has(k)) ||
    d.body.referenceInputs.length > 0;
  const hasGovernance =
    d.body.votingProcedures !== undefined ||
    d.body.proposalProcedures !== undefined;
  if (d.body.mint.length > 0) warnings.push('mints or burns tokens');
  if (hasGovernance)
    warnings.push('casts votes or submits governance proposals');
  if (d.body.unknownFields.length > 0) {
    warnings.push('contains fields this wallet does not understand');
  }
  const donation = d.body.donation ?? 0n;
  if (donation > 0n)
    warnings.push(`donates ${donation} lovelace to the treasury`);
  if (!d.isValid) warnings.push('marked invalid: collateral will be taken');

  // Collateral: at risk whatever `is_valid` says, because it is not signed.
  const assessment = assessCollateral(d, {
    ownAddresses: options.addresses ?? [],
    params,
    ...(options.ownUtxos ? { ownUtxos: options.ownUtxos } : {}),
    ...(options.maxCollateralAtRisk !== undefined
      ? { maxCollateralAtRisk: options.maxCollateralAtRisk }
      : {}),
  });
  const collateralReturn = d.body.collateralReturn
    ? describeOutput(d.body.collateralReturn)
    : undefined;
  const n = d.body.collateral.length;
  const atRisk = assessment.atRiskLovelace;
  if (n > 0) {
    if (collateralReturn && !assessment.returnIsOwn) {
      warnings.push(
        `COLLATERAL RETURN PAYS SOMEONE ELSE (${collateralReturn.address}): if the scripts fail — which the dapp can arrange after signing — all ${n} collateral input(s) go to them`,
      );
    } else if (!collateralReturn && d.body.totalCollateral === undefined) {
      warnings.push(
        `no collateral return: if the scripts fail, all ${n} collateral input(s) are lost`,
      );
    } else if (atRisk === null) {
      warnings.push(
        `${n} collateral input(s) at risk if the scripts fail, of unknown value (the dapp decides that after signing)`,
      );
    } else {
      warnings.push(
        `${atRisk} lovelace of collateral at risk if the scripts fail (the dapp decides that after signing)`,
      );
    }
  }
  const unknownCertificates = d.body.certificates.filter(
    (c) =>
      c.kind === 'unknown' ||
      c.kind === 'genesis_key_delegation' ||
      c.kind === 'move_instantaneous_rewards',
  ).length;
  if (unknownCertificates > 0) {
    warnings.push(
      'contains certificates this wallet does not understand or Conway does not accept (their deposits are not counted)',
    );
  }
  if (foreignRewardAccounts.size > 0) {
    warnings.push(
      `sends deposits, rewards or refunds to reward accounts outside this wallet: ${[...foreignRewardAccounts].join(', ')}`,
    );
  }

  return {
    txIdHex: bytesToHex(d.txId),
    fee: d.body.fee,
    outputs,
    toOthers: sumValues(outputs.filter((o) => !o.own).map((o) => o.value)),
    deposits,
    refunds,
    proposalDeposits,
    donation,
    withdrawals: { own: ownW, foreign: foreignW },
    mint: d.body.mint,
    certificates: d.body.certificates.map((c) => c.kind),
    certificateDetails,
    pools: [...pools],
    dreps: [...dreps],
    foreignRewardAccounts: [...foreignRewardAccounts],
    validity: {
      ...(d.body.validityStart !== undefined
        ? { from: d.body.validityStart }
        : {}),
      ...(d.body.ttl !== undefined ? { until: d.body.ttl } : {}),
    },
    hasScripts,
    hasGovernance,
    hasCollateral: d.body.collateral.length > 0,
    collateral: {
      inputCount: d.body.collateral.length,
      ...(d.body.totalCollateral !== undefined
        ? { total: d.body.totalCollateral }
        : {}),
      ...(collateralReturn ? { return: collateralReturn } : {}),
      returnIsOwn: assessment.returnIsOwn,
      atRiskLovelace: atRisk,
      cap: assessment.cap,
      refusal: assessment.refusal,
    },
    collateralAtRisk: atRisk,
    unknownBodyKeys: d.body.unknownFields.map((f) => f.key.toString()),
    unknownCertificates,
    warnings,
  };
}

/**
 * Everything that leaves the wallet's control, assuming the inputs are ours:
 * outputs to others, fee, certificate and proposal deposits, and donation.
 * Gross: withdrawals and refunds are not subtracted (see `totalInflow`).
 */
export function totalOutflow(desc: TransactionDescription): Value {
  return addValues(
    desc.toOthers,
    coinValue(desc.fee + desc.deposits + desc.proposalDeposits + desc.donation),
  );
}

/** Value entering the transaction from outside its inputs: withdrawals and deposit refunds. */
export function totalInflow(desc: TransactionDescription): bigint {
  return desc.withdrawals.own + desc.withdrawals.foreign + desc.refunds;
}
