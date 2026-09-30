import {
  accountKeysFromEntropy,
  addValues,
  addressToString,
  assetList,
  assetQuantity,
  bytesToHex,
  enterpriseAddress,
  equalValues,
  keyBaseAddress,
  keyHash,
  localSigner,
  MAINNET_DEFAULTS,
  makeValue,
  outpointKey,
  parseAddressInput,
  planSend,
  publicKeyOf,
  signPlan,
  signTxWitnessSet,
  subtractValues,
  sumValues,
} from '../../src/index.js';
import type {
  AssetAmount,
  LocalSigner,
  Plan,
  PlanSendRequest,
  ProtocolParams,
  SignPlanOptions,
  Utxo,
  WitnessSetOptions,
} from '../../src/index.js';
import { big, CSL, hex } from './csl.js';
import type { Rng } from './random.js';

export interface TestWallet {
  readonly address: string;
  /** Enterprise address with the same payment key. */
  readonly enterprise: string;
  readonly payment: LocalSigner;
  readonly stake: LocalSigner;
  readonly paymentKeyHash: Uint8Array;
  readonly stakeKeyHash: Uint8Array;
}

/** A throwaway wallet from seeded entropy. */
export function testWallet(rng: Rng, network = 1): TestWallet {
  const { payment, stake } = accountKeysFromEntropy(rng.bytes(32));
  const pk = keyHash(publicKeyOf(payment));
  const sk = keyHash(publicKeyOf(stake));
  return {
    address: addressToString(keyBaseAddress(network, pk, sk)),
    enterprise: addressToString(
      enterpriseAddress(network, { type: 'key', hash: pk }),
    ),
    payment: localSigner(payment),
    stake: localSigner(stake),
    paymentKeyHash: pk,
    stakeKeyHash: sk,
  };
}

export const SNEK = {
  policyId: '279c909f348e533da5808898f87f9a14bb2c3dfbbacccd631d927a3f',
  assetName: '534e454b',
};

export function utxo(
  rng: Rng,
  coin: bigint,
  assets: readonly AssetAmount[] = [],
): Utxo {
  return {
    txHash: bytesToHex(rng.bytes(32)),
    index: rng.int(8),
    value: makeValue(coin, assets),
  };
}

export function randomPolicyAssets(rng: Rng, n: number): AssetAmount[] {
  return Array.from({ length: n }, () => ({
    policyId: bytesToHex(rng.bytes(28)),
    assetName: bytesToHex(rng.bytes(rng.int(20))),
    quantity: rng.quantity(),
  }));
}

function cslValueOf(u: Utxo): InstanceType<typeof CSL.Value> {
  const v = CSL.Value.new(big(u.value.coin));
  if (u.value.assets.size === 0) return v;
  const ma = CSL.MultiAsset.new();
  for (const [p, names] of u.value.assets) {
    const a = CSL.Assets.new();
    for (const [n, q] of names)
      a.insert(CSL.AssetName.new(Buffer.from(n, 'hex')), big(q));
    ma.insert(CSL.ScriptHash.from_hex(p), a);
  }
  v.set_multiasset(ma);
  return v;
}

/** What the caller asked for, so the check can confirm the recipient got it. */
export interface Expected {
  readonly request: PlanSendRequest;
  readonly params?: ProtocolParams;
}

/**
 * Checks a plan with cardano-serialization-lib as the independent judge:
 * the body round-trips; value is conserved (ADA and every asset); every output
 * meets CSL's min-ADA and `maxValueSize`; the fee covers CSL's `min_fee` of the
 * signed tx and the size fits `maxTxSize`; the tx id and every witness verify;
 * inputs are unique and come from the request; recipient outputs come first and
 * pay the recipient exactly what was asked (amount mode), all ADA but the change
 * reserve (`maxAda`) or everything minus the fee (`all`); every other output pays
 * the change address.
 */
export function cslCheckPlan(
  plan: Plan,
  signedTx: Uint8Array,
  expected?: Expected,
): void {
  const params =
    expected?.params ?? expected?.request.params ?? MAINNET_DEFAULTS;
  const body = CSL.TransactionBody.from_bytes(plan.bodyBytes);
  if (hex(body.to_bytes()) !== hex(plan.bodyBytes))
    throw new Error('CSL re-encodes the body differently');
  // Inputs: unique, and every one comes from the request.
  const offered = new Map(
    (expected?.request.utxos ?? plan.inputs).map((u) => [outpointKey(u), u]),
  );
  const ins = body.inputs();
  const seen = new Set<string>();
  let inV = CSL.Value.new(big(0n));
  for (let i = 0; i < ins.len(); i++) {
    const input = ins.get(i);
    const key = `${input.transaction_id().to_hex()}#${input.index()}`;
    if (seen.has(key)) throw new Error('duplicate input');
    seen.add(key);
    const u = offered.get(key);
    if (!u) throw new Error('input not offered by the wallet');
    inV = inV.checked_add(cslValueOf(u));
  }
  let outV = CSL.Value.new(body.fee());
  const outs = body.outputs();
  const dc = CSL.DataCost.new_coins_per_byte(big(params.coinsPerUtxoByte));
  for (let i = 0; i < outs.len(); i++) {
    const o = outs.get(i);
    outV = outV.checked_add(o.amount());
    if (CSL.min_ada_for_output(o, dc).compare(o.amount().coin()) > 0)
      throw new Error(`output ${i} below CSL min-ADA`);
    if (o.amount().to_bytes().length > params.maxValueSize)
      throw new Error(`output ${i} value exceeds maxValueSize`);
  }
  if (inV.compare(outV) !== 0) throw new Error('value not conserved');
  const tx = CSL.Transaction.from_bytes(signedTx);
  const minFee = CSL.min_fee(
    tx,
    CSL.LinearFee.new(big(params.minFeeA), big(params.minFeeB)),
  );
  if (minFee.compare(body.fee()) > 0)
    throw new Error(
      `fee ${body.fee().to_str()} below CSL min_fee ${minFee.to_str()}`,
    );
  if (signedTx.length !== plan.signedSize)
    throw new Error('signed size differs from the plan');
  if (signedTx.length > params.maxTxSize)
    throw new Error('tx exceeds maxTxSize');
  const fixed = CSL.FixedTransaction.from_bytes(signedTx);
  if (hex(fixed.transaction_hash().to_bytes()) !== plan.txIdHex)
    throw new Error('tx id differs');
  const vk = tx.witness_set().vkeys();
  if (!vk) throw new Error('no vkey witnesses');
  for (let i = 0; i < vk.len(); i++) {
    const w = vk.get(i);
    if (
      !w
        .vkey()
        .public_key()
        .verify(fixed.transaction_hash().to_bytes(), w.signature())
    )
      throw new Error('witness does not verify');
  }
  if (!expected) return;

  // Output roles: recipients first, then change only.
  const req = expected.request;
  const toBytes = hex(parseAddressInput(req.to).bytes);
  const changeBytes = hex(parseAddressInput(req.changeAddress).bytes);
  const nRecipients = plan.recipients.length;
  let toRecipient = makeValue(0n);
  for (let i = 0; i < outs.len(); i++) {
    const addr = hex(outs.get(i).address().to_bytes());
    const value = plan.body.outputs[i]!.value;
    if (i < nRecipients) {
      if (addr !== toBytes)
        throw new Error(`recipient output ${i} pays the wrong address`);
      toRecipient = addValues(toRecipient, value);
    } else if (addr !== changeBytes) {
      throw new Error(`change output ${i} pays the wrong address`);
    }
  }
  const mode = req.mode ?? 'amount';
  const asked = makeValue(0n, req.assets ?? []);
  if (mode !== 'all') {
    for (const a of assetList(asked)) {
      if (assetQuantity(toRecipient, a.policyId, a.assetName) !== a.quantity)
        throw new Error('recipient token amount differs from the request');
    }
    if (assetList(toRecipient).length !== assetList(asked).length)
      throw new Error('recipient received tokens that were not asked for');
  }
  if (mode === 'amount') {
    if (assetList(asked).length === 0 && toRecipient.coin !== req.coin)
      throw new Error('recipient ADA differs from the request');
    if (req.coin !== undefined && toRecipient.coin < req.coin)
      throw new Error('recipient got less ADA than asked');
  }
  const fee = BigInt(body.fee().to_str());
  const spent = sumValues(plan.inputs.map((u) => u.value));
  if (mode === 'all') {
    const want = subtractValues(spent, makeValue(fee));
    if (!want || !equalValues(want, toRecipient))
      throw new Error('all: recipient does not get everything minus the fee');
  }
  if (mode === 'maxAda') {
    let reserve = 0n;
    let changeCoin = 0n;
    for (let i = nRecipients; i < outs.len(); i++) {
      changeCoin += plan.body.outputs[i]!.value.coin;
      reserve += BigInt(CSL.min_ada_for_output(outs.get(i), dc).to_str());
    }
    if (changeCoin - reserve > 20n * params.coinsPerUtxoByte)
      throw new Error('maxAda: change keeps more ADA than its minimum');
  }
}

/**
 * `planSend` with the change address as the wallet's own address unless the
 * test passes its own list (ownership tests do).
 */
export function planOwn(
  req: Omit<PlanSendRequest, 'ownAddresses'> & {
    readonly ownAddresses?: PlanSendRequest['ownAddresses'];
  },
): Plan {
  return planSend({
    ...req,
    ownAddresses: req.ownAddresses ?? [req.changeAddress],
  });
}

/**
 * `signPlan` with the wallet's values taken from the plan unless the test
 * passes its own (tamper and ownership tests do).
 */
export function signOwn(
  plan: Plan,
  signers: Parameters<typeof signPlan>[1],
  extra: Partial<SignPlanOptions> = {},
): ReturnType<typeof signPlan> {
  return signPlan(plan, signers, {
    ownAddresses: [plan.changeAddress],
    maxFee: plan.maxFee,
    params: plan.params,
    ...extra,
  });
}

/** `signTxWitnessSet` with no own addresses unless the test passes them. */
export function signTxOwn(
  tx: Parameters<typeof signTxWitnessSet>[0],
  signers: Parameters<typeof signTxWitnessSet>[1],
  extra: Partial<WitnessSetOptions> = {},
): Promise<string> {
  return signTxWitnessSet(tx, signers, { ownAddresses: [], ...extra });
}
