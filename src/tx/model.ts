import type { Value } from '../value.js';

export interface TxInput {
  /** 32-byte transaction id. */
  readonly txHash: Uint8Array;
  readonly index: number;
}

/**
 * A transaction output. `format` preserves which CDDL form it uses: the legacy
 * array `[address, value, ?datum_hash]` (what CSL's builder emits) or the
 * Babbage map `{0: address, 1: value, ?2: datum_option, ?3: script_ref}`.
 */
export interface TxOutput {
  readonly address: Uint8Array;
  readonly value: Value;
  readonly format: 'array' | 'map';
  /** 32-byte datum hash (array form, or map form datum option 0). */
  readonly datumHash?: Uint8Array;
  /** Encoded Plutus data of an inline datum (map form datum option 1), without tag 24. */
  readonly inlineDatum?: Uint8Array;
  /** Encoded script of a reference script, without tag 24. */
  readonly scriptRef?: Uint8Array;
}

/** The transaction body fields this library produces. Decoding reads every Conway field (see `DecodedBody`). */
export interface TxBody {
  readonly inputs: readonly TxInput[];
  readonly outputs: readonly TxOutput[];
  readonly fee: bigint;
  /** Absolute slot after which the transaction is invalid (`ttl`, key 3). */
  readonly ttl?: bigint;
  /** Absolute slot before which the transaction is invalid (key 8). */
  readonly validityStart?: bigint;
  /** 32-byte hash of the auxiliary data (key 7). */
  readonly auxiliaryDataHash?: Uint8Array;
  /** Network id (key 15). */
  readonly networkId?: number;
}

export interface VkeyWitness {
  /** 32-byte Ed25519 public key. */
  readonly vkey: Uint8Array;
  /** 64-byte Ed25519 signature over the transaction id. */
  readonly signature: Uint8Array;
}
