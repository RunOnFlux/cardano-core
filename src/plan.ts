import { U64_MAX, bytesToHex, equalBytes, hexToBytes } from './bytes.js';
import {
  parseAddress,
  parseAddressInput,
  parsePaymentAddress,
} from './address.js';
import type { ParsedAddress } from './address.js';
import {
  CardanoError,
  InsufficientFundsError,
  invalidInput,
} from './errors.js';
import {
  linearFee,
  minAdaForOutput,
  referenceScriptFee,
  requiredAda,
  valueSize,
} from './fee.js';
import type { ProtocolParams } from './params.js';
import { encodeBody, encodeOutput, signedSize } from './tx/encode.js';
import { txIdOfBody } from './tx/decode.js';
import type { TxBody, TxInput, TxOutput } from './tx/model.js';
import { outpointKey } from './utxo.js';
import type { Utxo } from './utxo.js';
import {
  addValues,
  assetList,
  assetQuantity,
  coinValue,
  equalValues,
  hasAssets,
  makeValue,
  subtractValues,
  sumValues,
} from './value.js';
import type { AssetAmount, Value } from './value.js';

/**
 * - `amount`: send `coin` and/or `assets`; everything else comes back as change.
 * - `maxAda`: send `assets` (if any) plus all the ADA the wallet can spare;
 *   other native assets stay in change with their minimum ADA.
 * - `all`: sweep every eligible UTXO — all ADA and all assets — to `to`.
 *
 * `maxAda` and `all` spend as many UTXOs as fit in one transaction (richest
 * first); `plan.leftoverUtxos` says how many were left for a further one.
 */
export type SendMode = 'amount' | 'maxAda' | 'all';

export interface PlanSendRequest {
  readonly utxos: readonly Utxo[];
  readonly to: string | Uint8Array;
  readonly mode?: SendMode;
  /** Lovelace for the recipient. With `assets`, an optional amount above the token-output floor. */
  readonly coin?: bigint;
  readonly assets?: readonly AssetAmount[];
  readonly changeAddress: string | Uint8Array;
  /**
   * The wallet's own addresses (required). `changeAddress` must be one of them
   * byte for byte — so change can never go to an address that merely reuses
   * our payment key with someone else's stake part.
   */
  readonly ownAddresses: readonly (string | Uint8Array)[];
  readonly params: ProtocolParams;
  /** Absolute slot after which the transaction is invalid; `null` for no expiry. Required. */
  readonly ttl: bigint | null;
  /** Expected network id (default: the change address's). */
  readonly network?: number;
  /** Lowest ADA a token-carrying recipient output gets (default 1.5 ADA); raised to the ledger minimum when that is higher. */
  readonly tokenOutputMinCoin?: bigint;
  /** Refuse plans whose fee exceeds this (default 5 ADA). */
  readonly maxFee?: bigint;
  /** Spend UTXOs that carry a reference script. Requires `referenceScriptSize` on them (default false: skipped). */
  readonly allowReferenceScriptInputs?: boolean;
  /** Take inputs in the given order instead of the default preference (default false). */
  readonly preserveOrder?: boolean;
}

export interface PlannedOutput {
  readonly role: 'recipient' | 'change';
  readonly address: Uint8Array;
  readonly output: TxOutput;
  readonly value: Value;
  /** Ledger minimum for this output as encoded. */
  readonly minAda: bigint;
}

export interface Plan {
  readonly mode: SendMode;
  readonly body: TxBody;
  readonly bodyBytes: Uint8Array;
  readonly txId: Uint8Array;
  readonly txIdHex: string;
  /** Fee the transaction pays, including any folded dust. */
  readonly fee: bigint;
  /** Fee the ledger requires for the signed size (linear + reference scripts). */
  readonly minFee: bigint;
  /** Fee paid above the ledger minimum because ADA-only change below the output minimum was folded into it. */
  readonly dustToFee: bigint;
  readonly referenceScriptFee: bigint;
  readonly inputs: readonly Utxo[];
  readonly outputs: readonly PlannedOutput[];
  /** The first recipient output. */
  readonly recipient: PlannedOutput;
  /** Every recipient output (more than one when the assets exceed `maxValueSize`). */
  readonly recipients: readonly PlannedOutput[];
  /** Sum of the recipient outputs. */
  readonly totalToRecipient: Value;
  /** Change outputs (more than one when the assets exceed `maxValueSize`). */
  readonly change: readonly PlannedOutput[];
  readonly totalIn: Value;
  /** Total sent back as change. */
  readonly totalChange: Value;
  /** Exact size of the signed transaction. */
  readonly signedSize: number;
  /** Payment key hashes that must sign (one vkey witness each). */
  readonly requiredKeyHashes: readonly Uint8Array[];
  readonly recipientAddress: Uint8Array;
  readonly changeAddress: Uint8Array;
  /** `maxAda` / `all`: eligible UTXOs left out because the transaction was full. */
  readonly leftoverUtxos: number;
  /** Things a UI should tell the user (for example, a script recipient without a datum). */
  readonly warnings: readonly string[];
  /** Parameters and fee ceiling the plan was made with (re-checked by `signPlan`). */
  readonly params: ProtocolParams;
  readonly maxFee: bigint;
  readonly ttl?: bigint;
}

const DEFAULT_TOKEN_OUTPUT_MIN = 1_500_000n;
const DEFAULT_MAX_FEE = 5_000_000n;
const MAX_FEE_ITERATIONS = 24;
/** Rough signed-size cost of one more input: [txid, index] plus set overhead. */
const INPUT_BYTES = 40n;
/** Largest unsigned values of each CBOR head width: crossing one changes an integer's encoded size. */
const WIDTH_LIMITS = [23n, 255n, 65535n, 4294967295n] as const;
const TXID_RE = /^[0-9a-f]{64}$/;
/** A plain boolean check: Array.isArray would narrow a typed list to any[]. */
const isList = (x: unknown): boolean => Array.isArray(x);

interface Ctx {
  readonly req: PlanSendRequest;
  readonly params: ProtocolParams;
  readonly mode: SendMode;
  readonly to: ParsedAddress;
  readonly change: ParsedAddress;
  readonly tokenMin: bigint;
  readonly maxFee: bigint;
  readonly warnings: readonly string[];
  /** Payment key hash per outpoint, computed once. */
  readonly keyHashOf: Map<string, Uint8Array>;
}

interface Attempt {
  readonly ok: true;
  readonly plan: Plan;
}

interface Shortfall {
  readonly ok: false;
  readonly code:
    'INSUFFICIENT_FUNDS' | 'INSUFFICIENT_ADA_FOR_CHANGE' | 'TX_TOO_LARGE';
  readonly shortfall: bigint;
  /** A dust-only shortfall: an extra ADA-only input would avoid folding change into the fee. */
  readonly dust?: boolean;
}

type Built =
  | { readonly kind: 'plan'; readonly attempt: Attempt; readonly dust: bigint }
  | {
      readonly kind: 'under';
      readonly minFee: bigint;
      readonly bodyFee: bigint;
      readonly dust: bigint;
    }
  | { readonly kind: 'fail'; readonly shortfall: Shortfall };

const inputOf = (u: Utxo): TxInput => ({
  txHash: hexToBytes(u.txHash),
  index: u.index,
});

function out(address: Uint8Array, value: Value): TxOutput {
  return { address, value, format: 'array' };
}

/** Payment key hash that must witness spending `u` (from its address, else the change address). */
function keyHashFor(u: Utxo, change: ParsedAddress): Uint8Array {
  const parsed = u.address ? parseAddress(u.address) : change;
  if (parsed.kind === 'byron' || !parsed.payment) {
    throw new CardanoError(
      'UNSUPPORTED',
      'cannot spend from Byron or reward addresses',
    );
  }
  if (parsed.payment.type !== 'key')
    throw new CardanoError('UNSUPPORTED', 'cannot spend script-locked outputs');
  return parsed.payment.hash;
}

/** Lower-cases the tx hash and checks the outpoint, so hand-built UTXOs behave like backend ones. */
function normalizeUtxo(u: Utxo): Utxo {
  const txHash = typeof u.txHash === 'string' ? u.txHash.toLowerCase() : '';
  if (!TXID_RE.test(txHash))
    throw invalidInput('utxo txHash must be 64 hex characters');
  if (!Number.isInteger(u.index) || u.index < 0 || u.index > 0xffff)
    throw invalidInput('utxo index out of range');
  return txHash === u.txHash ? u : { ...u, txHash };
}

function eligibleUtxos(ctx: Ctx): Utxo[] {
  const seen = new Set<string>();
  const outList: Utxo[] = [];
  for (const raw of ctx.req.utxos) {
    const u = normalizeUtxo(raw);
    const k = outpointKey(u);
    if (seen.has(k)) continue;
    seen.add(k);
    if (
      u.referenceScriptHash &&
      !(
        ctx.req.allowReferenceScriptInputs &&
        u.referenceScriptSize !== undefined
      )
    )
      continue;
    if (u.address) {
      const p = parseAddress(u.address);
      if (p.kind === 'byron' || p.payment?.type !== 'key') continue;
    }
    ctx.keyHashOf.set(k, keyHashFor(u, ctx.change));
    outList.push(u);
  }
  return outList;
}

function checkQuantities(assets: readonly AssetAmount[]): void {
  for (const a of assets) {
    if (a.quantity > U64_MAX) {
      throw new CardanoError(
        'VALUE_TOO_LARGE',
        'a token amount exceeds 2^64 − 1 in one output',
      );
    }
  }
}

/** Encoded size of a CBOR head for `n`. */
function headSize(n: bigint | number): number {
  const v = BigInt(n);
  return v < 24n ? 1 : v < 256n ? 2 : v < 65536n ? 3 : v < 4294967296n ? 5 : 9;
}

/**
 * Splits assets into chunks whose encoded value stays within `maxValueSize`.
 * The value's size is tracked incrementally (array head, a maximal 9-byte coin,
 * the policy map, each policy's asset map), so splitting is linear in the
 * number of assets; each chunk is then checked once against the real encoding.
 */
function splitAssets(
  assets: readonly AssetAmount[],
  maxValueSize: number,
): AssetAmount[][] {
  checkQuantities(assets);
  // Group by policy so a policy's assets stay together where possible.
  const byPolicy = new Map<string, AssetAmount[]>();
  for (const a of assets) {
    const list = byPolicy.get(a.policyId);
    if (list) list.push(a);
    else byPolicy.set(a.policyId, [a]);
  }
  const chunks: AssetAmount[][] = [];
  let current: AssetAmount[] = [];
  let policies = new Map<string, number>(); // policy → asset count in the current chunk
  let body = 0; // bytes of the policy entries (without the policy map head)
  const sizeWith = (policyCount: number, bodyBytes: number): number =>
    1 + 9 + headSize(policyCount) + bodyBytes;
  const assetBytes = (a: AssetAmount): number => {
    const nameLen = a.assetName.length / 2;
    return headSize(nameLen) + nameLen + headSize(a.quantity);
  };
  for (const list of byPolicy.values()) {
    for (const a of list) {
      const count = policies.get(a.policyId) ?? 0;
      // Adding the asset: its own bytes, a new policy entry (key + map head) or a wider map head.
      const delta =
        count === 0
          ? 30 + headSize(1) + assetBytes(a)
          : headSize(count + 1) - headSize(count) + assetBytes(a);
      const nextPolicies = count === 0 ? policies.size + 1 : policies.size;
      if (sizeWith(nextPolicies, body + delta) <= maxValueSize) {
        policies.set(a.policyId, count + 1);
        body += delta;
        current.push(a);
        continue;
      }
      if (current.length === 0)
        throw new CardanoError(
          'VALUE_TOO_LARGE',
          'a single asset exceeds the maximum value size',
        );
      chunks.push(current);
      current = [a];
      policies = new Map([[a.policyId, 1]]);
      body = 30 + headSize(1) + assetBytes(a);
      if (sizeWith(1, body) > maxValueSize)
        throw new CardanoError(
          'VALUE_TOO_LARGE',
          'a single asset exceeds the maximum value size',
        );
    }
  }
  if (current.length > 0) chunks.push(current);
  for (const c of chunks) {
    if (valueSize(makeValue(U64_MAX, c)) > maxValueSize) {
      throw new CardanoError(
        'INVARIANT_VIOLATION',
        'asset chunk size estimate was wrong',
      );
    }
  }
  return chunks;
}

/**
 * Outputs to one address holding `value`, split so each stays within
 * `maxValueSize`: every chunk but the last carries its own minimum ADA, the
 * last carries the rest. Returns the shortfall when the ADA does not cover
 * every chunk's minimum.
 */
function outputsFor(
  role: 'recipient' | 'change',
  address: Uint8Array,
  value: Value,
  params: ProtocolParams,
): PlannedOutput[] | { shortfall: bigint } {
  const assets = assetList(value);
  if (assets.length === 0) {
    const o = out(address, value);
    return [
      {
        role,
        address,
        output: o,
        value,
        minAda: requiredAda(o, params.coinsPerUtxoByte),
      },
    ];
  }
  const chunks = splitAssets(assets, params.maxValueSize);
  const mins = chunks.map((c) =>
    minAdaForOutput(out(address, makeValue(0n, c)), params.coinsPerUtxoByte),
  );
  const totalMin = mins.reduce((a, b) => a + b, 0n);
  if (value.coin < totalMin) return { shortfall: totalMin - value.coin };
  const result: PlannedOutput[] = [];
  let coinLeft = value.coin;
  for (let i = 0; i < chunks.length; i++) {
    const last = i === chunks.length - 1;
    const coin = last ? coinLeft : (mins[i] as bigint);
    coinLeft -= coin;
    const v = makeValue(coin, chunks[i]);
    const o = out(address, v);
    const req = requiredAda(o, params.coinsPerUtxoByte);
    if (coin < req)
      return { shortfall: minAdaForOutput(o, params.coinsPerUtxoByte) - coin };
    result.push({ role, address, output: o, value: v, minAda: req });
  }
  return result;
}

/** Minimum ADA needed to carry `assets` at `address` (sum over the split chunks). */
function reserveFor(
  address: Uint8Array,
  assets: readonly AssetAmount[],
  params: ProtocolParams,
): bigint {
  if (assets.length === 0) return 0n;
  let total = 0n;
  for (const chunk of splitAssets(assets, params.maxValueSize)) {
    total += minAdaForOutput(
      out(address, makeValue(0n, chunk)),
      params.coinsPerUtxoByte,
    );
  }
  return total;
}

/** A growing input set with its running totals. */
class Selection {
  readonly utxos: Utxo[] = [];
  readonly inputs: TxInput[] = [];
  readonly keys = new Set<string>();
  readonly keyHashes: Uint8Array[] = [];
  total: Value = coinValue(0n);
  refBytes = 0;
  constructor(private readonly ctx: Ctx) {}
  has(u: Utxo): boolean {
    return this.keys.has(outpointKey(u));
  }
  add(u: Utxo): void {
    const k = outpointKey(u);
    if (this.keys.has(k)) return;
    this.keys.add(k);
    this.utxos.push(u);
    this.inputs.push(inputOf(u));
    this.total = addValues(this.total, u.value);
    this.refBytes += u.referenceScriptSize ?? 0;
    const h = this.ctx.keyHashOf.get(k) ?? keyHashFor(u, this.ctx.change);
    if (!this.keyHashes.some((x) => equalBytes(x, h))) this.keyHashes.push(h);
  }
}

/**
 * One attempt with a fixed input set. `recipientFor(fee)` returns the
 * recipient value (it depends on the fee in `all`/`maxAda` modes).
 */
function attempt(
  ctx: Ctx,
  sel: Selection,
  recipientFor: (fee: bigint) => Value | null,
  canTopUpDust: boolean,
  leftoverUtxos: number,
): Attempt | Shortfall {
  const { params } = ctx;
  const totalIn = sel.total;
  const refFee = referenceScriptFee(
    sel.refBytes,
    params.minFeeRefScriptCostPerByte,
  );
  const witnessCount = sel.keyHashes.length;
  const txInputs = sel.inputs;
  const fail = (s: Shortfall): Built => ({ kind: 'fail', shortfall: s });

  /** Builds the transaction paying `fee` (plus any folded dust). */
  const buildAt = (fee: bigint): Built => {
    const recipientValue = recipientFor(fee);
    if (!recipientValue)
      return fail({
        ok: false,
        code: 'INSUFFICIENT_FUNDS',
        shortfall: fee + 1n,
      });
    const recipients = outputsFor(
      'recipient',
      ctx.to.bytes,
      recipientValue,
      params,
    );
    if (!Array.isArray(recipients)) {
      if (ctx.mode === 'amount') {
        throw new CardanoError(
          'OUTPUT_BELOW_MIN_ADA',
          'the recipient output is below the ledger minimum',
        );
      }
      return fail({
        ok: false,
        code: 'INSUFFICIENT_FUNDS',
        shortfall: recipients.shortfall,
      });
    }
    for (const r of recipients) {
      if (r.value.coin < r.minAda) {
        if (ctx.mode === 'amount') {
          throw new CardanoError(
            'OUTPUT_BELOW_MIN_ADA',
            `the recipient output needs at least ${r.minAda} lovelace`,
          );
        }
        return fail({
          ok: false,
          code: 'INSUFFICIENT_FUNDS',
          shortfall: r.minAda - r.value.coin,
        });
      }
    }
    const changeValue = subtractValues(
      totalIn,
      addValues(recipientValue, coinValue(fee)),
    );
    if (!changeValue) {
      // Price the fee these inputs would need (no change output) so the shortfall is what the user must add.
      const probe = encodeBody({
        inputs: txInputs,
        outputs: recipients.map((r) => r.output),
        fee: 0xffffffffn,
      });
      const needFee =
        linearFee(signedSize(probe, witnessCount), params) + refFee;
      const short =
        recipientValue.coin + (needFee > fee ? needFee : fee) - totalIn.coin;
      return fail({
        ok: false,
        code: 'INSUFFICIENT_FUNDS',
        shortfall: short > 0n ? short : 1n,
      });
    }

    const planned: PlannedOutput[] = [...recipients];
    let dust = 0n;
    if (hasAssets(changeValue)) {
      const change = outputsFor(
        'change',
        ctx.change.bytes,
        changeValue,
        params,
      );
      if (!Array.isArray(change)) {
        return fail({
          ok: false,
          code: 'INSUFFICIENT_ADA_FOR_CHANGE',
          shortfall: change.shortfall,
        });
      }
      planned.push(...change);
    } else if (changeValue.coin > 0n) {
      const o = out(ctx.change.bytes, changeValue);
      const min = requiredAda(o, params.coinsPerUtxoByte);
      if (changeValue.coin >= min) {
        planned.push({
          role: 'change',
          address: ctx.change.bytes,
          output: o,
          value: changeValue,
          minAda: min,
        });
      } else if (canTopUpDust) {
        return fail({
          ok: false,
          code: 'INSUFFICIENT_FUNDS',
          shortfall: min - changeValue.coin,
          dust: true,
        });
      } else {
        dust = changeValue.coin;
      }
    }

    const bodyFee = fee + dust;
    const body: TxBody = {
      inputs: txInputs,
      outputs: planned.map((p) => p.output),
      fee: bodyFee,
      ...(ctx.req.ttl !== null ? { ttl: ctx.req.ttl } : {}),
    };
    const bodyBytes = encodeBody(body);
    const size = signedSize(bodyBytes, witnessCount);
    if (size > params.maxTxSize) {
      return fail({
        ok: false,
        code: 'TX_TOO_LARGE',
        shortfall: BigInt(size - params.maxTxSize),
      });
    }
    const minFee = linearFee(size, params) + refFee;
    if (minFee > bodyFee) return { kind: 'under', minFee, bodyFee, dust };
    const recipientOutputs = planned.filter((p) => p.role === 'recipient');
    const change = planned.filter((p) => p.role === 'change');
    const txId = txIdOfBody(bodyBytes);
    return {
      kind: 'plan',
      dust,
      attempt: {
        ok: true,
        plan: {
          mode: ctx.mode,
          body,
          bodyBytes,
          txId,
          txIdHex: bytesToHex(txId),
          fee: bodyFee,
          minFee,
          // Everything above the ledger minimum that folding the dust added to the fee.
          dustToFee: dust > 0n ? bodyFee - minFee : 0n,
          referenceScriptFee: refFee,
          inputs: [...sel.utxos],
          outputs: planned,
          recipient: recipientOutputs[0] as PlannedOutput,
          recipients: recipientOutputs,
          totalToRecipient: sumValues(recipientOutputs.map((p) => p.value)),
          change,
          totalIn,
          totalChange: sumValues(change.map((c) => c.value)),
          signedSize: size,
          requiredKeyHashes: [...sel.keyHashes],
          recipientAddress: ctx.to.bytes,
          changeAddress: ctx.change.bytes,
          leftoverUtxos,
          warnings: ctx.warnings,
          params,
          maxFee: ctx.maxFee,
          ...(ctx.req.ttl !== null ? { ttl: ctx.req.ttl } : {}),
        },
      },
    };
  };

  // Fixed point: price the fee for the size, rebuild, repeat. `best` is the lowest valid plan.
  let best: Attempt | null = null;
  let fee = 0n;
  for (let iter = 0; iter < MAX_FEE_ITERATIONS; iter++) {
    const r = buildAt(fee);
    if (r.kind === 'fail') return best ?? r.shortfall;
    if (r.kind === 'plan') {
      if (!best || r.attempt.plan.fee < best.plan.fee) best = r.attempt;
      const p = r.attempt.plan;
      if (r.dust > 0n || p.minFee === p.fee || p.minFee >= fee) break;
      fee = p.minFee;
      continue;
    }
    // Under-priced.
    if (best) {
      if (r.dust === 0n && r.minFee < best.plan.fee && r.minFee > fee) {
        fee = r.minFee;
        continue;
      }
      break;
    }
    if (r.dust > 0n) {
      // Everything left over already went to the fee and still does not cover it.
      return {
        ok: false,
        code: 'INSUFFICIENT_FUNDS',
        shortfall: r.minFee - r.bodyFee,
      };
    }
    fee = r.minFee;
  }
  if (!best)
    throw new CardanoError('INVARIANT_VIOLATION', 'fee did not converge');

  // The fixed point can settle above the true minimum when a lower fee pushes the change (or, in
  // maxAda/all, the recipient) across a CBOR width boundary. Try the few fees that could be lower:
  // the price of each smaller size, and the fees that put the residual output exactly at a width limit.
  const p = best.plan;
  if (p.dustToFee === 0n && p.fee > p.minFee) {
    const residual =
      ctx.mode === 'amount'
        ? p.change[p.change.length - 1]
        : p.recipients[p.recipients.length - 1];
    const candidates = new Set<bigint>();
    for (let k = 1; k <= 16 && p.signedSize - k > 0; k++)
      candidates.add(linearFee(p.signedSize - k, params) + refFee);
    for (const limit of WIDTH_LIMITS) {
      candidates.add(limit);
      if (residual && limit >= residual.value.coin)
        candidates.add(p.fee - (limit - residual.value.coin));
    }
    const lower = [...candidates]
      .filter((f) => f >= 0n && f < p.fee)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    for (const f of lower) {
      const r = buildAt(f);
      if (r.kind === 'plan' && r.attempt.plan.fee < best.plan.fee) {
        best = r.attempt;
        break;
      }
    }
  }
  return best;
}

interface Ranked {
  readonly u: Utxo;
  readonly assetCount: number;
}

function adaPreference(a: Ranked, b: Ranked): number {
  if ((a.assetCount === 0) !== (b.assetCount === 0))
    return a.assetCount === 0 ? -1 : 1;
  if (a.assetCount !== b.assetCount) return a.assetCount - b.assetCount;
  return coinDescending(a, b);
}

function coinDescending(a: Ranked, b: Ranked): number {
  return a.u.value.coin === b.u.value.coin
    ? 0
    : a.u.value.coin > b.u.value.coin
      ? -1
      : 1;
}

function rank(list: readonly Utxo[]): Ranked[] {
  return list.map((u) => ({ u, assetCount: assetList(u.value).length }));
}

function fail(r: Shortfall): never {
  if (r.code === 'TX_TOO_LARGE') {
    throw new CardanoError(
      'TX_TOO_LARGE',
      'the transaction would exceed maxTxSize: too many inputs or outputs',
    );
  }
  throw new InsufficientFundsError(
    r.code,
    r.code === 'INSUFFICIENT_ADA_FOR_CHANGE'
      ? 'not enough ADA to return the remaining tokens as change'
      : 'insufficient funds',
    r.shortfall > 0n ? r.shortfall : 0n,
  );
}

/**
 * Plans a payment: selects inputs, prices the fee exactly for the signed size,
 * returns change (never folding native assets into the fee) and checks every
 * invariant before returning. The plan is a pure function of its inputs — the
 * fee a UI shows is the fee that will be signed.
 */
export function planSend(req: PlanSendRequest): Plan {
  const params = req.params;
  const mode = req.mode ?? 'amount';
  if (req.ttl === undefined)
    throw invalidInput(
      'ttl is required: pass the expiry slot, or null for none',
    );
  for (const [name, v] of [
    ['coin', req.coin],
    ['ttl', req.ttl ?? undefined],
    ['maxFee', req.maxFee],
    ['tokenOutputMinCoin', req.tokenOutputMinCoin],
  ] as const) {
    if (v !== undefined && typeof v !== 'bigint')
      throw invalidInput(`${name} must be a bigint`);
  }
  const change = parsePaymentAddress(req.changeAddress);
  const network = req.network ?? change.network;
  if (change.network !== network)
    throw new CardanoError(
      'WRONG_NETWORK',
      'change address is for another network',
    );
  if (change.kind === 'byron' || change.payment?.type !== 'key') {
    throw invalidInput('change address must have a key payment credential');
  }
  const ownList: readonly (string | Uint8Array)[] = req.ownAddresses;
  if (!isList(ownList))
    throw invalidInput("ownAddresses is required: the wallet's own addresses");
  const own = ownList.map((a) => parseAddressInput(a).bytes);
  if (!own.some((b) => equalBytes(b, change.bytes))) {
    throw new CardanoError(
      'CHANGE_ADDRESS_NOT_OWN',
      "the change address is not one of the wallet's addresses",
    );
  }
  const to = parsePaymentAddress(req.to, network);
  const warnings: string[] = [];
  if (to.payment?.type === 'script') {
    warnings.push(
      'the recipient is a script address and no datum is attached: the funds may be unspendable',
    );
  }
  const ctx: Ctx = {
    req,
    params,
    mode,
    to,
    change,
    tokenMin: req.tokenOutputMinCoin ?? DEFAULT_TOKEN_OUTPUT_MIN,
    maxFee: req.maxFee ?? DEFAULT_MAX_FEE,
    warnings,
    keyHashOf: new Map(),
  };
  const sendAssets = makeValue(0n, req.assets ?? []);
  const eligible = eligibleUtxos(ctx);

  let result: Attempt | Shortfall;
  if (mode === 'amount') {
    result = planAmount(ctx, eligible, sendAssets, 'preferred');
    // Many small ADA-only UTXOs can fill the transaction although a few large (token-bearing)
    // ones would do: retry richest-first. Native assets still never go to the fee.
    if (!result.ok && result.code === 'TX_TOO_LARGE' && !req.preserveOrder) {
      result = planAmount(ctx, eligible, sendAssets, 'coinDescending');
    }
  } else {
    result = planMax(ctx, eligible, sendAssets);
  }
  if (!result.ok) fail(result);
  checkPlanInvariants(result.plan, params, ctx.maxFee);
  return result.plan;
}

/** `maxAda` and `all`: spend the largest prefix of the preferred order that fits in one transaction. */
function planMax(
  ctx: Ctx,
  eligible: readonly Utxo[],
  sendAssets: Value,
): Attempt | Shortfall {
  const { params } = ctx;
  if (eligible.length === 0)
    throw new InsufficientFundsError(
      'INSUFFICIENT_FUNDS',
      'no spendable UTXOs',
    );
  const wanted = assetList(sendAssets);
  const holdsWanted = (u: Utxo): boolean =>
    wanted.some((a) => assetQuantity(u.value, a.policyId, a.assetName) > 0n);
  // Requested tokens first, then ADA-only by coin, then the rest; `all` keeps the same order.
  const ordered = ctx.req.preserveOrder
    ? [...eligible]
    : rank(eligible)
        .sort((a, b) => {
          const wa = holdsWanted(a.u);
          const wb = holdsWanted(b.u);
          if (wa !== wb) return wa ? -1 : 1;
          return adaPreference(a, b);
        })
        .map((r) => r.u);

  const tryPrefix = (n: number): Attempt | Shortfall => {
    const sel = new Selection(ctx);
    for (let i = 0; i < n; i++) sel.add(ordered[i] as Utxo);
    const totalIn = sel.total;
    if (ctx.mode === 'all') {
      return attempt(
        ctx,
        sel,
        (fee) => subtractValues(totalIn, coinValue(fee)),
        false,
        eligible.length - n,
      );
    }
    const leftover = subtractValues(
      { coin: 0n, assets: totalIn.assets },
      sendAssets,
    );
    if (!leftover)
      throw new InsufficientFundsError(
        'INSUFFICIENT_TOKENS',
        'not enough of the requested tokens',
      );
    const reserve = reserveFor(ctx.change.bytes, assetList(leftover), params);
    return attempt(
      ctx,
      sel,
      (fee) => {
        const coin = totalIn.coin - fee - reserve;
        return coin < 0n ? null : { coin, assets: sendAssets.assets };
      },
      false,
      eligible.length - n,
    );
  };

  const full = tryPrefix(ordered.length);
  if (full.ok || full.code !== 'TX_TOO_LARGE') return full;
  // Too many inputs: binary-search the largest prefix that fits.
  let lo = 1;
  let hi = ordered.length - 1;
  let best: Attempt | Shortfall = full;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    let r: Attempt | Shortfall;
    try {
      r = tryPrefix(mid);
    } catch (e) {
      if (
        e instanceof InsufficientFundsError &&
        e.code === 'INSUFFICIENT_TOKENS'
      ) {
        lo = mid + 1;
        continue;
      }
      throw e;
    }
    if (r.ok) {
      best = r;
      lo = mid + 1;
    } else if (r.code === 'TX_TOO_LARGE') {
      hi = mid - 1;
    } else {
      if (!best.ok) best = r;
      lo = mid + 1;
    }
  }
  return best;
}

function planAmount(
  ctx: Ctx,
  eligible: readonly Utxo[],
  sendAssets: Value,
  order: 'preferred' | 'coinDescending',
): Attempt | Shortfall {
  const { req, params } = ctx;
  const assets = assetList(sendAssets);
  if ((req.coin ?? 0n) <= 0n && assets.length === 0)
    throw invalidInput('nothing to send');
  if ((req.coin ?? 0n) < 0n) throw invalidInput('coin must be non-negative');

  // Recipient value is fixed in amount mode.
  let recipientValue: Value;
  if (assets.length > 0) {
    const floor =
      (req.coin ?? 0n) > ctx.tokenMin ? (req.coin as bigint) : ctx.tokenMin;
    const min = reserveFor(ctx.to.bytes, assets, params);
    recipientValue = makeValue(floor > min ? floor : min, assets);
  } else {
    recipientValue = coinValue(req.coin as bigint);
  }

  const sel = new Selection(ctx);

  // 1. Tokens first.
  for (const a of assets) {
    let have = 0n;
    for (const u of sel.utxos)
      have += assetQuantity(u.value, a.policyId, a.assetName);
    let candidates = eligible.filter(
      (u) =>
        !sel.has(u) && assetQuantity(u.value, a.policyId, a.assetName) > 0n,
    );
    if (!req.preserveOrder) {
      candidates = rank(candidates)
        .sort((x, y) => {
          const qx = assetQuantity(x.u.value, a.policyId, a.assetName);
          const qy = assetQuantity(y.u.value, a.policyId, a.assetName);
          return qx === qy ? adaPreference(x, y) : qx > qy ? -1 : 1;
        })
        .map((r) => r.u);
    }
    for (const c of candidates) {
      if (have >= a.quantity) break;
      sel.add(c);
      have += assetQuantity(c.value, a.policyId, a.assetName);
    }
    if (have < a.quantity)
      throw new InsufficientFundsError(
        'INSUFFICIENT_TOKENS',
        'not enough of the requested tokens',
      );
  }

  // 2. ADA. Preferred: ADA-only UTXOs first (they add nothing to the change), richest first.
  //    Fallback: richest first regardless of tokens (fewest inputs).
  const adaOrder = req.preserveOrder
    ? [...eligible]
    : rank(eligible)
        .sort(order === 'preferred' ? adaPreference : coinDescending)
        .map((r) => r.u);
  let cursor = 0;
  let adaOnlyCursor = 0;
  const nextCandidate = (): Utxo | undefined => {
    while (cursor < adaOrder.length && sel.has(adaOrder[cursor] as Utxo))
      cursor++;
    return adaOrder[cursor];
  };
  const nextAdaOnly = (): Utxo | undefined => {
    while (
      adaOnlyCursor < adaOrder.length &&
      (sel.has(adaOrder[adaOnlyCursor] as Utxo) ||
        hasAssets((adaOrder[adaOnlyCursor] as Utxo).value))
    ) {
      adaOnlyCursor++;
    }
    return adaOrder[adaOnlyCursor];
  };
  const perInput = params.minFeeA * INPUT_BYTES;
  /** Adds inputs until they bring at least `need` more lovelace (always at least one). */
  const addFor = (need: bigint): boolean => {
    let added = 0n;
    let any = false;
    while (!any || added < need) {
      const u = nextCandidate();
      if (!u) return any;
      sel.add(u);
      added += u.value.coin - perInput;
      any = true;
    }
    return true;
  };

  // Seed with enough for the recipient plus a fee estimate, then correct from each shortfall.
  const seed =
    recipientValue.coin + params.minFeeB + perInput * 4n - sel.total.coin;
  if (seed > 0n || sel.utxos.length === 0) addFor(seed > 0n ? seed : 1n);

  for (;;) {
    if (sel.utxos.length === 0)
      return {
        ok: false,
        code: 'INSUFFICIENT_FUNDS',
        shortfall: recipientValue.coin,
      };
    const r = attempt(
      ctx,
      sel,
      () => recipientValue,
      nextAdaOnly() !== undefined,
      0,
    );
    if (r.ok || r.code === 'TX_TOO_LARGE') return r;
    if (r.dust) {
      const u = nextAdaOnly();
      if (u) {
        sel.add(u);
        continue;
      }
      // No ADA-only input left to absorb the dust: fold it into the fee.
      return attempt(ctx, sel, () => recipientValue, false, 0);
    }
    if (!addFor(r.shortfall + perInput)) return r;
  }
}

/** Re-checks a plan from scratch; throws INVARIANT_VIOLATION (or the specific limit code) on any breach. */
export function checkPlanInvariants(
  plan: Plan,
  params: ProtocolParams,
  maxFee = DEFAULT_MAX_FEE,
): void {
  const bad = (m: string): never => {
    throw new CardanoError('INVARIANT_VIOLATION', m);
  };
  if (
    !equalBytes(txIdOfBody(plan.bodyBytes), plan.txId) ||
    bytesToHex(plan.txId) !== plan.txIdHex
  ) {
    bad('transaction id does not match the body');
  }
  if (!equalBytes(encodeBody(plan.body), plan.bodyBytes))
    bad('body bytes do not match the body');
  const totalIn = sumValues(plan.inputs.map((u) => u.value));
  if (!equalValues(totalIn, plan.totalIn))
    bad('totalIn does not match the inputs');
  if (plan.inputs.length !== plan.body.inputs.length)
    bad('inputs do not match the body');
  const bodyInputs = new Set(
    plan.body.inputs.map((i) => `${bytesToHex(i.txHash)}#${i.index}`),
  );
  if (bodyInputs.size !== plan.body.inputs.length) bad('duplicate input');
  for (const u of plan.inputs)
    if (!bodyInputs.has(outpointKey(u))) bad('inputs do not match the body');
  const totalOut = sumValues(plan.body.outputs.map((o) => o.value));
  if (!equalValues(totalIn, addValues(totalOut, coinValue(plan.body.fee))))
    bad('inputs do not equal outputs plus fee');
  if (plan.fee !== plan.body.fee) bad('fee mismatch');
  if (plan.outputs.length !== plan.body.outputs.length)
    bad('outputs do not match the body');
  plan.outputs.forEach((p, i) => {
    const o = plan.body.outputs[i] as TxOutput;
    if (!equalBytes(encodeOutput(p.output), encodeOutput(o)))
      bad('outputs do not match the body');
    const want =
      p.role === 'recipient' ? plan.recipientAddress : plan.changeAddress;
    if (!equalBytes(o.address, want) || !equalBytes(p.address, want))
      bad(`${p.role} output pays the wrong address`);
  });
  for (const o of plan.body.outputs) {
    if (o.value.coin < requiredAda(o, params.coinsPerUtxoByte))
      bad('an output is below the minimum ADA');
    if (valueSize(o.value) > params.maxValueSize) {
      throw new CardanoError(
        'VALUE_TOO_LARGE',
        'an output value exceeds maxValueSize',
      );
    }
    for (const a of assetList(o.value))
      if (a.quantity <= 0n || a.quantity > U64_MAX)
        bad('asset quantity out of range');
  }
  const size = signedSize(plan.bodyBytes, plan.requiredKeyHashes.length);
  if (size !== plan.signedSize) bad('signed size mismatch');
  if (size > params.maxTxSize)
    throw new CardanoError('TX_TOO_LARGE', 'transaction exceeds maxTxSize');
  const refBytes = plan.inputs.reduce(
    (n, u) => n + (u.referenceScriptSize ?? 0),
    0,
  );
  const minFee =
    linearFee(size, params) +
    referenceScriptFee(refBytes, params.minFeeRefScriptCostPerByte);
  if (plan.body.fee < minFee) bad('fee below the ledger minimum');
  if (plan.body.fee > maxFee)
    throw new CardanoError(
      'FEE_TOO_HIGH',
      `fee ${plan.body.fee} exceeds the ceiling ${maxFee}`,
    );
}
