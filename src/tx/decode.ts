import { decodeCbor } from '../cbor/decode.js';
import {
  assertUniqueKeys,
  expectArray,
  expectBytes,
  expectMap,
  expectSmallUint,
  expectUint,
  isTaggedSet,
  rawBytes,
  setItems,
} from '../cbor/read.js';
import type { CborMap, CborNode } from '../cbor/types.js';
import { invalidCbor } from '../errors.js';
import { blake2b256 } from '../hash.js';
import { decodeAssetMap, decodeValue } from '../value.js';
import type { TxInput, TxOutput, VkeyWitness } from './model.js';

/**
 * Decoding never normalises: every part keeps its source byte range, and the
 * transaction id is blake2b-256 of the body's **original** bytes. Re-encoding a
 * body a dapp sent could change its hash; this module never does that.
 *
 * Duplicate map keys are refused in every map the wallet interprets (body,
 * witness set, outputs, values, mint, withdrawals, voting procedures). Plutus
 * data, redeemers, scripts and auxiliary data are opaque: their ledger-legal
 * duplicate keys are kept as they are.
 */

/** Default and hard ceiling for `decodeTransaction` input (Conway's max tx size is 16 KiB). */
export const DEFAULT_MAX_TX_BYTES = 64 * 1024;

export interface DecodeTransactionOptions {
  /** Refuse larger inputs before decoding (default 64 KiB). */
  readonly maxBytes?: number;
  /** Maximum CBOR nesting depth (default 128). */
  readonly maxDepth?: number;
}

export interface DecodedOutput extends TxOutput {
  /** The output's original bytes. */
  readonly raw: Uint8Array;
}

export interface Withdrawal {
  /** Raw reward-address bytes. */
  readonly rewardAddress: Uint8Array;
  readonly amount: bigint;
}

export interface MintEntry {
  readonly policyId: string;
  readonly assetName: string;
  /** Positive to mint, negative to burn. */
  readonly quantity: bigint;
}

export type CertificateKind =
  | 'stake_registration'
  | 'stake_deregistration'
  | 'stake_delegation'
  | 'pool_registration'
  | 'pool_retirement'
  | 'genesis_key_delegation'
  | 'move_instantaneous_rewards'
  | 'reg_cert'
  | 'unreg_cert'
  | 'vote_deleg_cert'
  | 'stake_vote_deleg_cert'
  | 'stake_reg_deleg_cert'
  | 'vote_reg_deleg_cert'
  | 'stake_vote_reg_deleg_cert'
  | 'auth_committee_hot_cert'
  | 'resign_committee_cold_cert'
  | 'reg_drep_cert'
  | 'unreg_drep_cert'
  | 'update_drep_cert'
  | 'unknown';

const CERT_KINDS: readonly CertificateKind[] = [
  'stake_registration',
  'stake_deregistration',
  'stake_delegation',
  'pool_registration',
  'pool_retirement',
  'genesis_key_delegation',
  'move_instantaneous_rewards',
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
];

export interface CredentialRef {
  readonly type: 'key' | 'script';
  readonly hash: Uint8Array;
}

/** A DRep a stake credential delegates its vote to. */
export type DRep =
  | { readonly kind: 'key'; readonly hash: Uint8Array }
  | { readonly kind: 'script'; readonly hash: Uint8Array }
  | { readonly kind: 'abstain' }
  | { readonly kind: 'no_confidence' };

export interface DecodedCertificate {
  readonly kind: CertificateKind;
  readonly tag: number;
  /** The stake, DRep or committee (cold) credential the certificate is about. */
  readonly credential?: CredentialRef;
  /** Explicit deposit this certificate takes (Conway tags 7, 11, 12, 13, 16). */
  readonly deposit?: bigint;
  /** Explicit deposit refund this certificate releases (Conway tags 8, 17). */
  readonly refund?: bigint;
  /** Pool delegated to (2, 10, 11, 13), registered (3, operator) or retired (4). */
  readonly poolKeyHash?: Uint8Array;
  /** Vote delegation target (9, 10, 12, 13). */
  readonly drep?: DRep;
  /** Pool registration: the pool's reward account (raw bytes). */
  readonly poolRewardAccount?: Uint8Array;
  /** Pool registration: owner stake key hashes (each must sign). */
  readonly poolOwners?: readonly Uint8Array[];
  /** Committee hot credential (14). */
  readonly hotCredential?: CredentialRef;
  readonly raw: Uint8Array;
}

export interface Proposal {
  readonly deposit: bigint;
  /** Where the deposit is returned (raw reward-address bytes). */
  readonly rewardAccount: Uint8Array;
  readonly raw: Uint8Array;
}

export type VoterRole = 'committee_hot' | 'drep' | 'stake_pool';

export interface Voter {
  readonly role: VoterRole;
  readonly credential: CredentialRef;
}

export interface DecodedBody {
  readonly inputs: readonly TxInput[];
  readonly outputs: readonly DecodedOutput[];
  readonly fee: bigint;
  readonly ttl?: bigint;
  readonly certificates: readonly DecodedCertificate[];
  readonly withdrawals: readonly Withdrawal[];
  readonly auxiliaryDataHash?: Uint8Array;
  readonly validityStart?: bigint;
  readonly mint: readonly MintEntry[];
  readonly scriptDataHash?: Uint8Array;
  readonly collateral: readonly TxInput[];
  readonly requiredSigners: readonly Uint8Array[];
  readonly networkId?: number;
  readonly collateralReturn?: DecodedOutput;
  readonly totalCollateral?: bigint;
  readonly referenceInputs: readonly TxInput[];
  /** Raw CBOR of the voting procedures (key 19), and the voters it names. */
  readonly votingProcedures?: Uint8Array;
  readonly voters: readonly Voter[];
  /** Raw CBOR of the proposal procedures (key 20), and their deposits and return accounts. */
  readonly proposalProcedures?: Uint8Array;
  readonly proposals: readonly Proposal[];
  readonly currentTreasuryValue?: bigint;
  readonly donation?: bigint;
  /** Body keys this library does not know (future eras), with their raw value bytes. */
  readonly unknownFields: readonly {
    readonly key: bigint;
    readonly raw: Uint8Array;
  }[];
  /** Whether the input set used tag 258. */
  readonly taggedSets: boolean;
}

export interface DecodedWitnessSet {
  readonly vkeys: readonly VkeyWitness[];
  /** Keys present in the witness-set map (0 vkeys, 1 native scripts, 2 bootstrap, 3/6/7 Plutus, 4 data, 5 redeemers). */
  readonly keys: readonly number[];
  readonly bootstrapCount: number;
}

export interface DecodedTransaction {
  /** The full transaction bytes as given. */
  readonly bytes: Uint8Array;
  readonly bodyBytes: Uint8Array;
  readonly witnessSetBytes: Uint8Array;
  readonly auxiliaryDataBytes: Uint8Array | null;
  readonly isValid: boolean;
  /** blake2b-256 of the original body bytes. */
  readonly txId: Uint8Array;
  readonly body: DecodedBody;
  readonly witnessSet: DecodedWitnessSet;
  /** Pre-Alonzo transactions are 3-element arrays (no `is_valid`). */
  readonly format: 'three-element' | 'four-element';
}

function decodeInput(node: CborNode, what: string): TxInput {
  const items = expectArray(node, what);
  if (items.length !== 2) throw invalidCbor(`${what}: expected [txid, index]`);
  return {
    txHash: expectBytes(items[0], `${what} txid`, 32),
    index: expectSmallUint(items[1], `${what} index`),
  };
}

function decodeInputs(node: CborNode | undefined, what: string): TxInput[] {
  return setItems(node, what).map((n, i) => decodeInput(n, `${what}[${i}]`));
}

function decodeOutput(
  source: Uint8Array,
  node: CborNode,
  what: string,
): DecodedOutput {
  const raw = rawBytes(source, node);
  if (node.type === 'array') {
    const items = node.items;
    if (items.length < 2 || items.length > 3)
      throw invalidCbor(`${what}: bad legacy output`);
    const base = {
      raw,
      format: 'array' as const,
      address: expectBytes(items[0], `${what} address`),
      value: decodeValue(items[1], `${what} value`, source),
    };
    return items.length === 3
      ? { ...base, datumHash: expectBytes(items[2], `${what} datum hash`, 32) }
      : base;
  }
  const map = assertUniqueKeys(expectMap(node, what), what, source);
  let address: Uint8Array | undefined;
  let value: DecodedOutput['value'] | undefined;
  let datumHash: Uint8Array | undefined;
  let inlineDatum: Uint8Array | undefined;
  let scriptRef: Uint8Array | undefined;
  for (const [k, v] of map.entries) {
    const key = expectUint(k, `${what} key`);
    if (key === 0n) address = expectBytes(v, `${what} address`);
    else if (key === 1n) value = decodeValue(v, `${what} value`, source);
    else if (key === 2n) {
      const d = expectArray(v, `${what} datum`);
      const kind = expectUint(d[0], `${what} datum kind`);
      if (d.length !== 2) throw invalidCbor(`${what}: bad datum option`);
      if (kind === 0n) datumHash = expectBytes(d[1], `${what} datum hash`, 32);
      else if (kind === 1n) {
        const t = d[1];
        if (t?.type !== 'tag' || t.tag !== 24n)
          throw invalidCbor(`${what}: inline datum must be tag 24`);
        inlineDatum = expectBytes(t.value, `${what} inline datum`);
      } else throw invalidCbor(`${what}: unknown datum option`);
    } else if (key === 3n) {
      if (v.type !== 'tag' || v.tag !== 24n)
        throw invalidCbor(`${what}: script ref must be tag 24`);
      scriptRef = expectBytes(v.value, `${what} script ref`);
    } else throw invalidCbor(`${what}: unknown output key ${key}`);
  }
  if (!address || !value)
    throw invalidCbor(`${what}: output without address or value`);
  return {
    raw,
    format: 'map',
    address,
    value,
    ...(datumHash ? { datumHash } : {}),
    ...(inlineDatum ? { inlineDatum } : {}),
    ...(scriptRef ? { scriptRef } : {}),
  };
}

function decodeCredential(
  node: CborNode | undefined,
  what: string,
): CredentialRef {
  const items = expectArray(node, what);
  if (items.length !== 2) throw invalidCbor(`${what}: expected [kind, hash]`);
  const kind = expectUint(items[0], `${what} kind`);
  if (kind > 1n) throw invalidCbor(`${what}: unknown credential kind`);
  return {
    type: kind === 0n ? 'key' : 'script',
    hash: expectBytes(items[1], `${what} hash`, 28),
  };
}

function decodeDRep(node: CborNode | undefined, what: string): DRep {
  const items = expectArray(node, what);
  const kind = expectUint(items[0], `${what} kind`);
  if (kind === 0n || kind === 1n) {
    if (items.length !== 2) throw invalidCbor(`${what}: expected [kind, hash]`);
    return {
      kind: kind === 0n ? 'key' : 'script',
      hash: expectBytes(items[1], `${what} hash`, 28),
    };
  }
  if (items.length !== 1) throw invalidCbor(`${what}: unexpected fields`);
  if (kind === 2n) return { kind: 'abstain' };
  if (kind === 3n) return { kind: 'no_confidence' };
  throw invalidCbor(`${what}: unknown DRep kind`);
}

function decodeCertificate(
  source: Uint8Array,
  node: CborNode,
  what: string,
): DecodedCertificate {
  const items = expectArray(node, what);
  const tag = expectSmallUint(items[0], `${what} tag`);
  const kind = CERT_KINDS[tag] ?? 'unknown';
  const raw = rawBytes(source, node);
  const cred = (i: number): CredentialRef =>
    decodeCredential(items[i], `${what} credential`);
  const pool = (i: number): Uint8Array =>
    expectBytes(items[i], `${what} pool`, 28);
  const coin = (i: number): bigint => expectUint(items[i], `${what} coin`);
  const drep = (i: number): DRep => decodeDRep(items[i], `${what} drep`);
  const need = (n: number): void => {
    if (items.length !== n) throw invalidCbor(`${what}: expected ${n} fields`);
  };
  switch (kind) {
    case 'stake_registration':
    case 'stake_deregistration':
      need(2);
      return { kind, tag, raw, credential: cred(1) };
    case 'stake_delegation':
      need(3);
      return { kind, tag, raw, credential: cred(1), poolKeyHash: pool(2) };
    case 'pool_registration': {
      need(10);
      const owners = setItems(items[7], `${what} owners`).map((o) =>
        expectBytes(o, `${what} owner`, 28),
      );
      return {
        kind,
        tag,
        raw,
        poolKeyHash: pool(1),
        poolRewardAccount: expectBytes(items[6], `${what} reward account`),
        poolOwners: owners,
      };
    }
    case 'pool_retirement':
      need(3);
      return { kind, tag, raw, poolKeyHash: pool(1) };
    case 'reg_cert':
      need(3);
      return { kind, tag, raw, credential: cred(1), deposit: coin(2) };
    case 'unreg_cert':
      need(3);
      return { kind, tag, raw, credential: cred(1), refund: coin(2) };
    case 'vote_deleg_cert':
      need(3);
      return { kind, tag, raw, credential: cred(1), drep: drep(2) };
    case 'stake_vote_deleg_cert':
      need(4);
      return {
        kind,
        tag,
        raw,
        credential: cred(1),
        poolKeyHash: pool(2),
        drep: drep(3),
      };
    case 'stake_reg_deleg_cert':
      need(4);
      return {
        kind,
        tag,
        raw,
        credential: cred(1),
        poolKeyHash: pool(2),
        deposit: coin(3),
      };
    case 'vote_reg_deleg_cert':
      need(4);
      return {
        kind,
        tag,
        raw,
        credential: cred(1),
        drep: drep(2),
        deposit: coin(3),
      };
    case 'stake_vote_reg_deleg_cert':
      need(5);
      return {
        kind,
        tag,
        raw,
        credential: cred(1),
        poolKeyHash: pool(2),
        drep: drep(3),
        deposit: coin(4),
      };
    case 'auth_committee_hot_cert':
      need(3);
      return { kind, tag, raw, credential: cred(1), hotCredential: cred(2) };
    case 'resign_committee_cold_cert':
      need(3);
      return { kind, tag, raw, credential: cred(1) };
    case 'reg_drep_cert':
      need(4);
      return { kind, tag, raw, credential: cred(1), deposit: coin(2) };
    case 'unreg_drep_cert':
      need(3);
      return { kind, tag, raw, credential: cred(1), refund: coin(2) };
    case 'update_drep_cert':
      need(3);
      return { kind, tag, raw, credential: cred(1) };
    default:
      return { kind, tag, raw };
  }
}

const VOTER_ROLES: readonly [VoterRole, 'key' | 'script'][] = [
  ['committee_hot', 'key'],
  ['committee_hot', 'script'],
  ['drep', 'key'],
  ['drep', 'script'],
  ['stake_pool', 'key'],
];

function decodeVoters(source: Uint8Array, node: CborNode | undefined): Voter[] {
  const voters: Voter[] = [];
  for (const [k, v] of assertUniqueKeys(
    expectMap(node, 'voting procedures'),
    'voting procedures',
    source,
  ).entries) {
    const items = expectArray(k, 'voter');
    if (items.length !== 2) throw invalidCbor('voter: expected [kind, hash]');
    const role = VOTER_ROLES[expectSmallUint(items[0], 'voter kind')];
    if (!role) throw invalidCbor('voter: unknown kind');
    voters.push({
      role: role[0],
      credential: {
        type: role[1],
        hash: expectBytes(items[1], 'voter hash', 28),
      },
    });
    assertUniqueKeys(expectMap(v, 'votes'), 'votes', source);
  }
  return voters;
}

function decodeProposals(
  source: Uint8Array,
  node: CborNode | undefined,
): Proposal[] {
  return setItems(node, 'proposal procedures').map((p, i) => {
    const items = expectArray(p, `proposal[${i}]`);
    if (items.length !== 4)
      throw invalidCbor(`proposal[${i}]: expected 4 fields`);
    return {
      deposit: expectUint(items[0], `proposal[${i}] deposit`),
      rewardAccount: expectBytes(items[1], `proposal[${i}] reward account`),
      raw: rawBytes(source, p),
    };
  });
}

function decodeBody(source: Uint8Array, map: CborMap): DecodedBody {
  assertUniqueKeys(map, 'transaction body', source);
  let inputs: TxInput[] | undefined;
  let outputs: DecodedOutput[] | undefined;
  let fee: bigint | undefined;
  let taggedSets = false;
  const out: {
    ttl?: bigint;
    certificates: DecodedCertificate[];
    withdrawals: Withdrawal[];
    auxiliaryDataHash?: Uint8Array;
    validityStart?: bigint;
    mint: MintEntry[];
    scriptDataHash?: Uint8Array;
    collateral: TxInput[];
    requiredSigners: Uint8Array[];
    networkId?: number;
    collateralReturn?: DecodedOutput;
    totalCollateral?: bigint;
    referenceInputs: TxInput[];
    votingProcedures?: Uint8Array;
    voters: Voter[];
    proposalProcedures?: Uint8Array;
    proposals: Proposal[];
    currentTreasuryValue?: bigint;
    donation?: bigint;
    unknownFields: { key: bigint; raw: Uint8Array }[];
  } = {
    certificates: [],
    withdrawals: [],
    mint: [],
    collateral: [],
    requiredSigners: [],
    referenceInputs: [],
    voters: [],
    proposals: [],
    unknownFields: [],
  };
  for (const [k, v] of map.entries) {
    const key = expectUint(k, 'body key');
    switch (key) {
      case 0n:
        inputs = decodeInputs(v, 'inputs');
        taggedSets = isTaggedSet(v);
        break;
      case 1n:
        outputs = expectArray(v, 'outputs').map((o, i) =>
          decodeOutput(source, o, `outputs[${i}]`),
        );
        break;
      case 2n:
        fee = expectUint(v, 'fee');
        break;
      case 3n:
        out.ttl = expectUint(v, 'ttl');
        break;
      case 4n:
        out.certificates = setItems(v, 'certificates').map((c, i) =>
          decodeCertificate(source, c, `certificates[${i}]`),
        );
        break;
      case 5n:
        for (const [ra, amt] of assertUniqueKeys(
          expectMap(v, 'withdrawals'),
          'withdrawals',
          source,
        ).entries) {
          out.withdrawals.push({
            rewardAddress: expectBytes(ra, 'withdrawal address'),
            amount: expectUint(amt, 'withdrawal amount'),
          });
        }
        break;
      case 7n:
        out.auxiliaryDataHash = expectBytes(v, 'auxiliary data hash', 32);
        break;
      case 8n:
        out.validityStart = expectUint(v, 'validity start');
        break;
      case 9n:
        out.mint = decodeAssetMap(v, 'mint', true, source);
        break;
      case 11n:
        out.scriptDataHash = expectBytes(v, 'script data hash', 32);
        break;
      case 13n:
        out.collateral = decodeInputs(v, 'collateral');
        break;
      case 14n:
        out.requiredSigners = setItems(v, 'required signers').map((s) =>
          expectBytes(s, 'required signer', 28),
        );
        break;
      case 15n:
        out.networkId = expectSmallUint(v, 'network id');
        break;
      case 16n:
        out.collateralReturn = decodeOutput(source, v, 'collateral return');
        break;
      case 17n:
        out.totalCollateral = expectUint(v, 'total collateral');
        break;
      case 18n:
        out.referenceInputs = decodeInputs(v, 'reference inputs');
        break;
      case 19n:
        out.votingProcedures = rawBytes(source, v);
        out.voters = decodeVoters(source, v);
        break;
      case 20n:
        out.proposalProcedures = rawBytes(source, v);
        out.proposals = decodeProposals(source, v);
        break;
      case 21n:
        out.currentTreasuryValue = expectUint(v, 'treasury value');
        break;
      case 22n:
        out.donation = expectUint(v, 'donation');
        break;
      default:
        // Opaque: kept as raw bytes, never interpreted.
        out.unknownFields.push({ key, raw: rawBytes(source, v) });
    }
  }
  if (!inputs || !outputs || fee === undefined)
    throw invalidCbor('body is missing inputs, outputs or fee');
  return { inputs, outputs, fee, taggedSets, ...out };
}

function decodeWitnessSet(
  source: Uint8Array,
  node: CborNode | undefined,
): DecodedWitnessSet {
  const map = assertUniqueKeys(
    expectMap(node, 'witness set'),
    'witness set',
    source,
  );
  const keys: number[] = [];
  const vkeys: VkeyWitness[] = [];
  let bootstrapCount = 0;
  for (const [k, v] of map.entries) {
    const key = expectSmallUint(k, 'witness set key');
    keys.push(key);
    if (key === 0) {
      for (const w of setItems(v, 'vkey witnesses')) {
        const pair = expectArray(w, 'vkey witness');
        if (pair.length !== 2)
          throw invalidCbor('vkey witness: expected [vkey, signature]');
        vkeys.push({
          vkey: expectBytes(pair[0], 'vkey', 32),
          signature: expectBytes(pair[1], 'signature', 64),
        });
      }
    } else if (key === 2) {
      bootstrapCount = setItems(v, 'bootstrap witnesses').length;
    }
    // Scripts, Plutus data and redeemers stay opaque.
  }
  return { vkeys, keys, bootstrapCount };
}

function decodeRoot(
  bytes: Uint8Array,
  options: DecodeTransactionOptions,
): { source: Uint8Array; items: readonly CborNode[] } {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_TX_BYTES;
  const source = Uint8Array.from(bytes);
  // Duplicate keys are checked per structural map below, not in opaque Plutus data or metadata.
  const root = decodeCbor(source, {
    maxBytes,
    allowDuplicateKeys: true,
    ...(options.maxDepth !== undefined ? { maxDepth: options.maxDepth } : {}),
  });
  const items = expectArray(root, 'transaction');
  if (items.length !== 3 && items.length !== 4)
    throw invalidCbor('transaction: expected 3 or 4 elements');
  return { source, items };
}

/**
 * Decodes a signed or unsigned transaction (Shelley through Conway), keeping
 * the original bytes of the body, witness set and auxiliary data. Inputs above
 * `maxBytes` (default 64 KiB) are refused before any decoding.
 */
export function decodeTransaction(
  bytes: Uint8Array,
  options: DecodeTransactionOptions = {},
): DecodedTransaction {
  const { source, items } = decodeRoot(bytes, options);
  const bodyNode = items[0];
  const witnessNode = items[1];
  if (!bodyNode || !witnessNode)
    throw invalidCbor('transaction: missing body or witnesses');
  const four = items.length === 4;
  let isValid = true;
  if (four) {
    const v = items[2];
    if (v?.type !== 'simple' || (v.value !== 20 && v.value !== 21)) {
      throw invalidCbor('transaction: is_valid must be a boolean');
    }
    isValid = v.value === 21;
  }
  const auxNode = items[four ? 3 : 2];
  const auxiliaryDataBytes =
    auxNode === undefined || (auxNode.type === 'simple' && auxNode.value === 22)
      ? null
      : rawBytes(source, auxNode);
  const bodyBytes = rawBytes(source, bodyNode);
  return {
    bytes: source,
    bodyBytes,
    witnessSetBytes: rawBytes(source, witnessNode),
    auxiliaryDataBytes,
    isValid,
    txId: blake2b256(bodyBytes),
    body: decodeBody(source, expectMap(bodyNode, 'transaction body')),
    witnessSet: decodeWitnessSet(source, witnessNode),
    format: four ? 'four-element' : 'three-element',
  };
}

/** Transaction id of a body given as its original bytes. */
export function txIdOfBody(bodyBytes: Uint8Array): Uint8Array {
  return blake2b256(bodyBytes);
}

/** Transaction id of a full transaction: hashes the original body bytes, never a re-encoding. */
export function txIdOfTransaction(
  txBytes: Uint8Array,
  options: DecodeTransactionOptions = {},
): Uint8Array {
  const { source, items } = decodeRoot(txBytes, options);
  const body = items[0];
  if (!body) throw invalidCbor('transaction: missing body');
  assertUniqueKeys(
    expectMap(body, 'transaction body'),
    'transaction body',
    source,
  );
  return blake2b256(rawBytes(source, body));
}
