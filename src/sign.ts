import { parseAddress, parseAddressInput } from './address.js';
import { bytesToHex, equalBytes } from './bytes.js';
import { CardanoError } from './errors.js';
import { keyHash, signChecked, verifyEd25519 } from './keys.js';
import type { Signer } from './keys.js';
import { checkPlanInvariants } from './plan.js';
import type { Plan } from './plan.js';
import type { ProtocolParams } from './params.js';
import { assembleTransaction, encodeWitnessSet } from './tx/encode.js';
import type { AssembleOptions } from './tx/encode.js';
import type { VkeyWitness } from './tx/model.js';

/** A vkey witness: the signer's signature over the transaction id. */
export async function witnessFor(
  txId: Uint8Array,
  signer: Signer,
): Promise<VkeyWitness> {
  if (txId.length !== 32)
    throw new CardanoError('INVALID_INPUT', 'transaction id must be 32 bytes');
  const signature = await signChecked(signer, txId);
  return { vkey: Uint8Array.from(signer.publicKey), signature };
}

export function verifyWitness(txId: Uint8Array, w: VkeyWitness): boolean {
  return verifyEd25519(w.vkey, txId, w.signature);
}

export interface SignedTransaction {
  readonly bytes: Uint8Array;
  readonly hex: string;
  readonly txId: Uint8Array;
  readonly txIdHex: string;
}

/** Which change address the wallet accepts: the exact expected one, or any of its own addresses (or both). */
export type ChangeAddressCheck =
  | {
      /** The change address the wallet expects; the plan's change must pay exactly these bytes. */
      readonly expectedChangeAddress: string | Uint8Array;
      readonly ownAddresses?: readonly (string | Uint8Array)[];
    }
  | {
      readonly expectedChangeAddress?: string | Uint8Array;
      /** The wallet's own addresses; the plan's change address must be one of them. */
      readonly ownAddresses: readonly (string | Uint8Array)[];
    };

/**
 * Required: the wallet's view of change, fee ceiling and parameters. The plan
 * object carries its own copies, which on their own only prove it is
 * self-consistent.
 */
export type SignPlanOptions = AssembleOptions &
  ChangeAddressCheck & {
    /** The wallet's fee ceiling. */
    readonly maxFee: bigint;
    /** The wallet's protocol parameters, used for the re-check. */
    readonly params: ProtocolParams;
  };

/**
 * Signs a plan with exactly the keys it requires. Before any signature it
 * re-checks the plan from scratch (tx id recomputed from the body bytes, value
 * conservation, min-ADA, fee, sizes, output addresses by role) and requires the
 * change address to belong to one of the signers, so a plan object that was
 * altered after `planSend` is refused. Refuses when a required key has no
 * signer. Extra signers are ignored: the fee was priced for
 * `requiredKeyHashes.length` witnesses.
 *
 * The wallet's `expectedChangeAddress` (or `ownAddresses`), `maxFee` and
 * `params` are required, so the plan is held to the wallet's values, not its
 * own: a change address that reuses our payment key with someone else's stake
 * part, or an enterprise form of our key, is refused (`CHANGE_ADDRESS_NOT_OWN`);
 * missing options are `INVALID_INPUT`.
 */
export async function signPlan(
  plan: Plan,
  signers: readonly Signer[],
  options: SignPlanOptions,
): Promise<SignedTransaction> {
  const opts = options as Partial<SignPlanOptions> | undefined;
  if (
    !opts ||
    (opts.expectedChangeAddress === undefined &&
      !Array.isArray(opts.ownAddresses))
  ) {
    throw new CardanoError(
      'INVALID_INPUT',
      'signPlan needs expectedChangeAddress or ownAddresses',
    );
  }
  if (
    typeof opts.maxFee !== 'bigint' ||
    typeof opts.params !== 'object' ||
    opts.params === null
  ) {
    throw new CardanoError(
      'INVALID_INPUT',
      "signPlan needs the wallet's maxFee and params",
    );
  }
  if (options.auxiliaryData && !plan.body.auxiliaryDataHash) {
    throw new CardanoError(
      'INVALID_INPUT',
      'auxiliary data given but the body commits to none',
    );
  }
  checkPlanInvariants(plan, options.params, options.maxFee);
  if (options.expectedChangeAddress !== undefined) {
    if (
      !equalBytes(
        parseAddressInput(options.expectedChangeAddress).bytes,
        plan.changeAddress,
      )
    ) {
      throw new CardanoError(
        'CHANGE_ADDRESS_NOT_OWN',
        'the plan pays change to another address',
      );
    }
  }
  if (options.ownAddresses !== undefined) {
    const own = options.ownAddresses.map((a) => parseAddressInput(a).bytes);
    if (!own.some((b) => equalBytes(b, plan.changeAddress))) {
      throw new CardanoError(
        'CHANGE_ADDRESS_NOT_OWN',
        "the plan's change address is not one of the wallet's addresses",
      );
    }
  }
  const signerHashes = signers.map((s) => keyHash(s.publicKey));
  const change = parseAddress(plan.changeAddress);
  const changeKey = change.payment?.type === 'key' ? change.payment.hash : null;
  if (!changeKey || !signerHashes.some((h) => equalBytes(h, changeKey))) {
    throw new CardanoError(
      'KEY_MISMATCH',
      'the change address is not controlled by any of the signers',
    );
  }
  const witnesses: VkeyWitness[] = [];
  for (const required of plan.requiredKeyHashes) {
    const signer = signers.find((s) =>
      equalBytes(keyHash(s.publicKey), required),
    );
    if (!signer) {
      throw new CardanoError(
        'KEY_MISMATCH',
        `no signer for payment key hash ${bytesToHex(required)}`,
      );
    }
    witnesses.push(await witnessFor(plan.txId, signer));
  }
  const bytes = assembleTransaction(
    plan.bodyBytes,
    encodeWitnessSet(witnesses),
    options,
  );
  return {
    bytes,
    hex: bytesToHex(bytes),
    txId: plan.txId,
    txIdHex: plan.txIdHex,
  };
}
