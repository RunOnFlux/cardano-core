import { addressFromBytes, parseAddressInput } from './address.js';
import { bytesToHex, equalBytes, hexToBytes } from './bytes.js';
import { decodeCbor } from './cbor/decode.js';
import {
  cArray,
  cBool,
  cBytes,
  cInt,
  cMap,
  cText,
  encodeCbor,
} from './cbor/encode.js';
import {
  expectArray,
  expectBytes,
  expectMap,
  mapGet,
  mapGetText,
} from './cbor/read.js';
import { CardanoError } from './errors.js';
import { keyHash, signChecked, verifyEd25519 } from './keys.js';
import type { Signer } from './keys.js';

/**
 * CIP-8 / CIP-30 `signData`: an untagged COSE_Sign1 over
 * `Sig_structure = ["Signature1", protected, h'', payload]` with the protected
 * header `{1: -8 (EdDSA), "address": address_bytes}` and the unprotected header
 * `{"hashed": false}` — byte-identical to cardano-message-signing 1.1.
 */

export interface DataSignature {
  /** Hex COSE_Sign1. */
  readonly signature: string;
  /** Hex COSE_Key. */
  readonly key: string;
}

const ALG_EDDSA = -8;

function toBytes(v: string | Uint8Array): Uint8Array {
  return typeof v === 'string' ? hexToBytes(v) : v;
}

/** The protected header map, encoded. */
export function protectedHeader(addressBytes: Uint8Array): Uint8Array {
  return encodeCbor(
    cMap([
      [cInt(1), cInt(ALG_EDDSA)],
      [cText('address'), cBytes(addressBytes)],
    ]),
  );
}

/** `["Signature1", protected, h'', payload]` — the bytes that get signed. */
export function sigStructure(
  protectedBytes: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  return encodeCbor(
    cArray([
      cText('Signature1'),
      cBytes(protectedBytes),
      cBytes(new Uint8Array(0)),
      cBytes(payload),
    ]),
  );
}

/** COSE_Key `{1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: publicKey}`. */
export function coseKey(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 32)
    throw new CardanoError('INVALID_INPUT', 'public key must be 32 bytes');
  return encodeCbor(
    cMap([
      [cInt(1), cInt(1)],
      [cInt(3), cInt(ALG_EDDSA)],
      [cInt(-1), cInt(6)],
      [cInt(-2), cBytes(publicKey)],
    ]),
  );
}

/**
 * Signs `payload` for `address` (raw bytes, hex, or bech32/base58).
 * Choosing the right key for the address is the caller's job — see
 * `resolveDataSigner` in `cip30`.
 */
export async function signData(
  address: string | Uint8Array,
  payload: string | Uint8Array,
  signer: Signer,
): Promise<DataSignature> {
  const addressBytes = parseAddressInput(address).bytes;
  const payloadBytes = toBytes(payload);
  const prot = protectedHeader(addressBytes);
  const sig = await signChecked(signer, sigStructure(prot, payloadBytes));
  const sign1 = encodeCbor(
    cArray([
      cBytes(prot),
      cMap([[cText('hashed'), cBool(false)]]),
      cBytes(payloadBytes),
      cBytes(sig),
    ]),
  );
  return {
    signature: bytesToHex(sign1),
    key: bytesToHex(coseKey(signer.publicKey)),
  };
}

export interface VerifiedData {
  /**
   * The signature verifies for the COSE_Key over the protected header and
   * payload — and, when `expected.address` is given, the address is that one
   * and its credential is the signing key.
   */
  readonly valid: boolean;
  readonly address: Uint8Array;
  readonly payload: Uint8Array;
  readonly publicKey: Uint8Array;
  /** The address's payment credential (or, for a reward address, its stake credential) is this key. */
  readonly addressMatchesKey: boolean;
}

/**
 * Verifies a CIP-8 signature and reports which address it claims. Pass
 * `expected` to also require a given address and/or payload; `valid` is false
 * when they differ, or when the expected address's credential is not the
 * signing key. Without `expected.address`, check `addressMatchesKey` yourself.
 */
export function verifyData(
  sig: DataSignature,
  expected: {
    readonly address?: string | Uint8Array;
    readonly payload?: string | Uint8Array;
  } = {},
): VerifiedData {
  const sign1 = expectArray(
    decodeCbor(hexToBytes(sig.signature)),
    'COSE_Sign1',
  );
  if (sign1.length !== 4)
    throw new CardanoError('INVALID_INPUT', 'COSE_Sign1 must have 4 elements');
  const protBytes = expectBytes(sign1[0], 'protected header');
  const prot = expectMap(decodeCbor(protBytes), 'protected header');
  const alg = mapGet(prot, 1);
  if (alg?.type !== 'nint' || alg.value !== BigInt(ALG_EDDSA))
    throw new CardanoError('UNSUPPORTED', 'algorithm is not EdDSA');
  const address = expectBytes(mapGetText(prot, 'address'), 'address header');
  const unprot = expectMap(sign1[1], 'unprotected header');
  const hashed = mapGetText(unprot, 'hashed');
  if (hashed?.type === 'simple' && hashed.value === 21)
    throw new CardanoError('UNSUPPORTED', 'hashed payloads are not supported');
  const payload = expectBytes(sign1[2], 'payload');
  const signature = expectBytes(sign1[3], 'signature', 64);

  const key = expectMap(decodeCbor(hexToBytes(sig.key)), 'COSE_Key');
  const kty = mapGet(key, 1);
  const crv = key.entries.find(
    ([k]) => k.type === 'nint' && k.value === -1n,
  )?.[1];
  const x = key.entries.find(
    ([k]) => k.type === 'nint' && k.value === -2n,
  )?.[1];
  if (
    kty?.type !== 'uint' ||
    kty.value !== 1n ||
    crv?.type !== 'uint' ||
    crv.value !== 6n
  ) {
    throw new CardanoError('UNSUPPORTED', 'COSE_Key is not an Ed25519 OKP key');
  }
  const keyAlg = mapGet(key, 3);
  if (
    keyAlg &&
    !(keyAlg.type === 'nint' && keyAlg.value === BigInt(ALG_EDDSA))
  ) {
    throw new CardanoError('UNSUPPORTED', 'COSE_Key algorithm is not EdDSA');
  }
  const publicKey = expectBytes(x, 'COSE_Key x', 32);

  let valid = verifyEd25519(
    publicKey,
    sigStructure(protBytes, payload),
    signature,
  );
  const parsed = addressFromBytes(address);
  const cred = parsed.kind === 'reward' ? parsed.stake : parsed.payment;
  const addressMatchesKey =
    cred?.type === 'key' && equalBytes(cred.hash, keyHash(publicKey));
  if (expected.address !== undefined) {
    const want = parseAddressInput(expected.address).bytes;
    // A foreign key signing "for" our address proves nothing about our address.
    if (!equalBytes(want, address) || !addressMatchesKey) valid = false;
  }
  if (
    expected.payload !== undefined &&
    !equalBytes(toBytes(expected.payload), payload)
  )
    valid = false;
  return { valid, address, payload, publicKey, addressMatchesKey };
}
