import { parseAddress, parseAddressInput, rewardAddress } from './address.js';
import type { ParsedAddress } from './address.js';
import { bytesToHex, equalBytes, hexToBytes } from './bytes.js';
import { cArray, cBytes, cUint, encodeCbor } from './cbor/encode.js';
import { CardanoError } from './errors.js';
import { keyHash } from './keys.js';
import type { Signer } from './keys.js';
import { assessCollateral, collateralCheckOptions } from './collateral.js';
import type { ProtocolParams } from './params.js';
import { verifyWitness, witnessFor } from './sign.js';
import { decodeTransaction } from './tx/decode.js';
import type { DecodedTransaction } from './tx/decode.js';
import { encodeWitnessSet } from './tx/encode.js';
import type { VkeyWitness } from './tx/model.js';
import type { Utxo } from './utxo.js';
import { encodeValue, hasAssets } from './value.js';
import type { Value } from './value.js';

/** Helpers for the CIP-30 wallet API (all return hex CBOR, as the API does). */

function addrBytes(address: string | Uint8Array): Uint8Array {
  return parseAddressInput(address).bytes;
}

/** `getBalance` / value encoding. */
export function encodeValueHex(value: Value): string {
  return bytesToHex(encodeCbor(encodeValue(value)));
}

/** `getUtxos` entry: `[[txid, index], [address, value]]` (legacy-array output, as CSL emits). */
export function encodeUtxoHex(
  utxo: Utxo,
  address: string | Uint8Array,
): string {
  return bytesToHex(
    encodeCbor(
      cArray([
        cArray([cBytes(hexToBytes(utxo.txHash)), cUint(utxo.index)]),
        cArray([cBytes(addrBytes(address)), encodeValue(utxo.value)]),
      ]),
    ),
  );
}

/** Raw address bytes as hex (`getUsedAddresses`, `getChangeAddress`). */
export function addressHex(address: string | Uint8Array): string {
  return bytesToHex(addrBytes(address));
}

/** Reward address hex for a stake key hash (`getRewardAddresses`). */
export function rewardAddressHex(
  network: number,
  stakeKeyHash: Uint8Array,
): string {
  return bytesToHex(
    rewardAddress(network, { type: 'key', hash: stakeKeyHash }),
  );
}

/**
 * `getCollateral`: the first ADA-only UTXO holding at least `minCoin`
 * (default 5 ADA), or null.
 */
export function pickCollateral(
  utxos: readonly Utxo[],
  minCoin = 5_000_000n,
): Utxo | null {
  return (
    utxos.find((u) => !hasAssets(u.value) && u.value.coin >= minCoin) ?? null
  );
}

export interface WitnessSetOptions {
  /**
   * Also return the vkey witnesses already in the transaction (after ours),
   * de-duplicated by key. Only witnesses that verify against the transaction
   * id are kept. ZelCore's WalletConnect handler does this when `partialSign`
   * is false.
   */
  readonly mergeExisting?: boolean;
  /**
   * Sign even when the body has fields this library does not understand
   * (future eras). Default false: such a transaction is refused, because the
   * wallet cannot show the user what those fields do.
   */
  readonly allowUnknownFields?: boolean;
  /**
   * The wallet's own addresses (required). A collateral return must pay one
   * of them exactly.
   */
  readonly ownAddresses: readonly (string | Uint8Array)[];
  /**
   * The wallet's UTXOs with their values. Used to value collateral inputs when
   * the transaction states no `total_collateral`; an input that cannot be
   * valued makes the transaction refused.
   */
  readonly ownUtxos?: readonly Utxo[];
  /**
   * Most lovelace the wallet may lose if the scripts fail. Default:
   * `defaultCollateralCap(params)` — 1.5 × the largest fee a valid transaction
   * can need, clamped to [5 ADA, 25 ADA]; about 13.3 ADA on mainnet — never
   * derived from the transaction's own fee. An explicit value is not clamped.
   */
  readonly maxCollateralAtRisk?: bigint;
  /** Protocol parameters for the default collateral cap (default: mainnet). */
  readonly params?: ProtocolParams;
  /**
   * Accept a collateral return that pays someone else — only when `ownUtxos`
   * is non-empty and none of the collateral inputs are among them
   * (dapp-provided collateral). This trusts `ownUtxos` to list every UTXO at
   * every address form the wallet can sign for (base, enterprise, pointer, any
   * account). Every other collateral check, including the cap, stays in force.
   * Default false:
   * `is_valid` is not covered by the signature, so the dapp can make the
   * scripts "fail" after signing and the ledger then keeps the collateral and
   * pays the collateral return.
   */
  readonly allowForeignCollateralReturn?: boolean;
  /**
   * Sign collateral inputs missing from `ownUtxos` once each is accounted for
   * by `resolvedCollateral` (see `CollateralCheckOptions.allowUnvalued`): the
   * wallet's own are valued and capped, others add nothing. The signers' keys
   * count as the wallet's. An input missing from the lookup throws
   * `COLLATERAL_UNRESOLVED` (retryable). Honoured only with `ownUtxos`.
   */
  readonly allowUnvaluedCollateral?: boolean;
  /** Fresh lookup of the collateral inputs by outpoint, with address and value (read only with `allowUnvaluedCollateral`). */
  readonly resolvedCollateral?: readonly Utxo[];
  /** More key hashes the wallet signs with, besides `ownAddresses` and the signers (read only with `allowUnvaluedCollateral`). */
  readonly ownKeyHashes?: readonly (string | Uint8Array)[];
}

/** Certificate kinds a Conway node cannot decode (pre-Conway genesis delegation and MIR). */
const OBSOLETE_CERTS = new Set([
  'genesis_key_delegation',
  'move_instantaneous_rewards',
]);

/**
 * CIP-30 `signTx`: signs the transaction id — blake2b-256 of the body's
 * original bytes, never a re-encoding — and returns a witness set.
 *
 * Refuses (unless the matching opt-in is set): body fields or certificate
 * kinds this library does not understand, and obsolete pre-Conway
 * certificates (`UNSUPPORTED`); collateral that pays a foreign or missing
 * return, cannot be valued (unless `allowUnvaluedCollateral` and every input
 * is resolved), or exceeds the cap (`COLLATERAL_AT_RISK`, see
 * `assessCollateral`); a collateral input missing from `resolvedCollateral`
 * (`COLLATERAL_UNRESOLVED`, retryable). `options.ownAddresses` is required.
 */
export async function signTxWitnessSet(
  tx: string | Uint8Array,
  signers: readonly Signer[],
  options: WitnessSetOptions,
): Promise<string> {
  if (!Array.isArray(options?.ownAddresses)) {
    throw new CardanoError(
      'INVALID_INPUT',
      "signTxWitnessSet needs the wallet's ownAddresses",
    );
  }
  const decoded = decodeTransaction(
    typeof tx === 'string' ? hexToBytes(tx) : tx,
  );
  if (signers.length === 0)
    throw new CardanoError('INVALID_INPUT', 'no signers');
  if (!options.allowUnknownFields) {
    if (decoded.body.unknownFields.length > 0) {
      throw new CardanoError(
        'UNSUPPORTED',
        `transaction body has fields this wallet does not understand (keys ${decoded.body.unknownFields.map((f) => f.key.toString()).join(', ')})`,
      );
    }
    const unknownCerts = decoded.body.certificates.filter(
      (c) => c.kind === 'unknown' || OBSOLETE_CERTS.has(c.kind),
    );
    if (unknownCerts.length > 0) {
      throw new CardanoError(
        'UNSUPPORTED',
        `transaction has certificates this wallet does not understand or Conway does not accept (tags ${unknownCerts.map((c) => c.tag).join(', ')})`,
      );
    }
  }
  const collateral = assessCollateral(
    decoded,
    collateralCheckOptions(
      options.ownAddresses,
      options.params,
      options,
      // The keys about to sign authorise spending any input they lock.
      options.allowUnvaluedCollateral
        ? signers.map((s) => keyHash(s.publicKey))
        : [],
    ),
  );
  if (collateral.refusal) {
    throw new CardanoError(
      collateral.retryable ? 'COLLATERAL_UNRESOLVED' : 'COLLATERAL_AT_RISK',
      collateral.refusal,
    );
  }
  const witnesses: VkeyWitness[] = [];
  for (const s of signers) {
    if (witnesses.some((w) => equalBytes(w.vkey, s.publicKey))) continue;
    witnesses.push(await witnessFor(decoded.txId, s));
  }
  if (options.mergeExisting) {
    for (const w of decoded.witnessSet.vkeys) {
      if (witnesses.some((x) => equalBytes(x.vkey, w.vkey))) continue;
      if (verifyWitness(decoded.txId, w)) witnesses.push(w);
    }
  }
  return bytesToHex(encodeWitnessSet(witnesses));
}

export interface OwnKeys {
  readonly paymentKeyHash: Uint8Array;
  readonly stakeKeyHash?: Uint8Array;
  /** CIP-105 DRep key hash, if the wallet has one. */
  readonly drepKeyHash?: Uint8Array;
}

export interface RequiredSigners {
  /** Our stake key must sign (certificates, pool ownership, withdrawals, votes or required signers name it). */
  readonly stake: boolean;
  /** Our DRep key must sign (DRep certificates or votes). */
  readonly drep: boolean;
  /** Our payment key is named in `required_signers` or as a voter. Inputs cannot be attributed without a UTXO lookup. */
  readonly paymentInRequiredSigners: boolean;
  readonly reasons: readonly string[];
}

/** Certificates that require a witness from their (stake, DRep or committee) credential. */
const WITNESSED_CERTS = new Set([
  'stake_deregistration',
  'stake_delegation',
  'reg_cert',
  'unreg_cert',
  'vote_deleg_cert',
  'stake_vote_deleg_cert',
  'stake_reg_deleg_cert',
  'vote_reg_deleg_cert',
  'stake_vote_reg_deleg_cert',
  'auth_committee_hot_cert',
  'resign_committee_cold_cert',
  'reg_drep_cert',
  'unreg_drep_cert',
  'update_drep_cert',
]);

/**
 * Which of our keys a dapp transaction needs, beyond the payment key for our
 * inputs: certificates naming our credentials, pool registrations listing our
 * stake key as an owner, withdrawals from our reward account, voters that are
 * our keys, and `required_signers`.
 */
export function requiredSigners(
  tx: DecodedTransaction | string | Uint8Array,
  own: OwnKeys,
): RequiredSigners {
  const d =
    typeof tx === 'string' || tx instanceof Uint8Array
      ? decodeTransaction(typeof tx === 'string' ? hexToBytes(tx) : tx)
      : tx;
  const reasons: string[] = [];
  let stake = false;
  let drep = false;
  let payment = false;
  const role = (hash: Uint8Array): 'stake' | 'drep' | 'payment' | null => {
    if (own.stakeKeyHash && equalBytes(hash, own.stakeKeyHash)) return 'stake';
    if (own.drepKeyHash && equalBytes(hash, own.drepKeyHash)) return 'drep';
    if (equalBytes(hash, own.paymentKeyHash)) return 'payment';
    return null;
  };
  const mark = (r: 'stake' | 'drep' | 'payment' | null, why: string): void => {
    if (r === 'stake') stake = true;
    else if (r === 'drep') drep = true;
    else if (r === 'payment') payment = true;
    else return;
    reasons.push(`${why} (${r})`);
  };
  for (const c of d.body.certificates) {
    if (WITNESSED_CERTS.has(c.kind) && c.credential?.type === 'key') {
      mark(role(c.credential.hash), `certificate ${c.kind}`);
    }
    for (const owner of c.poolOwners ?? []) mark(role(owner), 'pool owner');
  }
  for (const w of d.body.withdrawals) {
    let parsed: ParsedAddress | undefined;
    try {
      parsed = parseAddress(w.rewardAddress);
    } catch {
      parsed = undefined;
    }
    if (parsed?.kind === 'reward' && parsed.stake?.type === 'key') {
      mark(role(parsed.stake.hash), 'withdrawal');
    }
  }
  for (const v of d.body.voters) {
    if (v.credential.type === 'key')
      mark(role(v.credential.hash), `vote as ${v.role}`);
  }
  for (const h of d.body.requiredSigners) mark(role(h), 'required signer');
  return { stake, drep, paymentInRequiredSigners: payment, reasons };
}

export interface DataSigningWallet {
  readonly payment: Signer;
  readonly stake?: Signer;
  /** Every address the wallet exposes (base, reward), in any form `parseAddressInput` accepts. */
  readonly addresses: readonly (string | Uint8Array)[];
  /** Network the wallet is on; addresses for any other network are refused. */
  readonly network?: number;
}

/**
 * CIP-30 `signData` key choice. The address (bech32, base58, hex or bytes)
 * must be byte-for-byte one of the wallet's own addresses on the wallet's
 * network; a reward address is then signed by the stake key and a payment
 * address by the payment key, and only when the address's credential is that
 * key. Anything else — an address that merely reuses our payment key with
 * another stake part, an enterprise or pointer form of our key, another
 * network — is `ADDRESS_NOT_PK` (CIP-30 DataSignError AddressNotPK).
 */
export function resolveDataSigner(
  address: string | Uint8Array,
  wallet: DataSigningWallet,
): Signer {
  const notOurs = (): never => {
    throw new CardanoError(
      'ADDRESS_NOT_PK',
      'the address is not controlled by this wallet',
    );
  };
  let parsed: ParsedAddress;
  try {
    parsed = parseAddressInput(address);
  } catch {
    return notOurs();
  }
  if (wallet.network !== undefined && parsed.network !== wallet.network)
    return notOurs();
  // Tolerate callers of the 0.1.0 signature (no address list): nothing is ours then.
  const ownBytes = (wallet.addresses ?? []).map(
    (a) => parseAddressInput(a).bytes,
  );
  if (!ownBytes.some((b) => equalBytes(b, parsed.bytes))) return notOurs();
  if (parsed.kind === 'reward') {
    if (
      wallet.stake &&
      parsed.stake?.type === 'key' &&
      equalBytes(parsed.stake.hash, keyHash(wallet.stake.publicKey))
    ) {
      return wallet.stake;
    }
  } else if (
    parsed.payment?.type === 'key' &&
    equalBytes(parsed.payment.hash, keyHash(wallet.payment.publicKey))
  ) {
    return wallet.payment;
  }
  return notOurs();
}
