import { bytesToHex, concatBytes, equalBytes, hexToBytes } from './bytes.js';
import { decodeCbor } from './cbor/decode.js';
import {
  expectArray,
  expectBytes,
  expectMap,
  expectUint,
} from './cbor/read.js';
import {
  base58Decode,
  base58Encode,
  bech32Decode,
  bech32Encode,
} from './encoding.js';
import { CardanoError, invalidAddress } from './errors.js';
import { crc32 } from './hash.js';

/**
 * Shelley addresses (CIP-19) and Byron addresses.
 *
 * Header nibble (high 4 bits of byte 0):
 * 0–3 base, 4–5 pointer, 6–7 enterprise, 8 Byron, 14–15 reward (stake).
 * The low nibble is the network id (1 mainnet, 0 testnets).
 */

export type CredentialType = 'key' | 'script';

export interface Credential {
  readonly type: CredentialType;
  /** 28-byte blake2b-224 key or script hash. */
  readonly hash: Uint8Array;
}

export type AddressKind =
  'base' | 'pointer' | 'enterprise' | 'reward' | 'byron';

export interface Pointer {
  readonly slot: bigint;
  readonly txIndex: bigint;
  readonly certIndex: bigint;
}

export interface ParsedAddress {
  readonly kind: AddressKind;
  /** Raw address bytes (what goes into transaction outputs). */
  readonly bytes: Uint8Array;
  /** Shelley network id. Byron: 1 when the address carries no protocol magic (mainnet), else 0. */
  readonly network: number;
  /** Payment credential (base, pointer, enterprise). */
  readonly payment?: Credential;
  /** Stake credential (base, reward). */
  readonly stake?: Credential;
  readonly pointer?: Pointer;
  /** Byron only: the protocol magic in the address attributes, if any. */
  readonly byronProtocolMagic?: number;
  /** Byron only: 0 public key, 1 script, 2 redeem. */
  readonly byronType?: number;
  /** Byron only: the ledger's attribute size (HD payload plus unknown attributes; outputs above 64 bytes are refused). */
  readonly byronAttributesSize?: number;
}

/** Byron mainnet protocol magic. An address that spells it out is still a testnet address to the ledger. */
export const BYRON_MAINNET_MAGIC = 764824073;

/** The ledger's limit on Byron address attributes in outputs (Allegra onwards). */
export const MAX_BYRON_ATTRIBUTES_SIZE = 64;

export const NetworkId = { Testnet: 0, Mainnet: 1 } as const;

const HASH_LEN = 28;

const cred = (type: CredentialType, hash: Uint8Array): Credential => ({
  type,
  hash,
});

function checkNetwork(network: number): void {
  if (!Number.isInteger(network) || network < 0 || network > 15) {
    throw invalidAddress('network id must be 0–15');
  }
}

function checkCred(c: Credential): void {
  if (c.hash.length !== HASH_LEN)
    throw invalidAddress('credential hash must be 28 bytes');
}

// ---- pointer naturals: base-128 big-endian with continuation bit ----

function encodeNat(n: bigint): Uint8Array {
  if (n < 0n) throw invalidAddress('pointer value must be non-negative');
  const out = [Number(n & 0x7fn)];
  let v = n >> 7n;
  while (v > 0n) {
    out.unshift(Number(v & 0x7fn) | 0x80);
    v >>= 7n;
  }
  return Uint8Array.from(out);
}

function decodeNat(
  bytes: Uint8Array,
  offset: number,
): { value: bigint; next: number } {
  let v = 0n;
  let i = offset;
  for (;;) {
    const b = bytes[i];
    if (b === undefined) throw invalidAddress('truncated pointer');
    v = (v << 7n) | BigInt(b & 0x7f);
    i += 1;
    if (v > (1n << 64n) - 1n) throw invalidAddress('pointer value too large');
    if ((b & 0x80) === 0) return { value: v, next: i };
  }
}

// ---- constructors ----

export function baseAddress(
  network: number,
  payment: Credential,
  stake: Credential,
): Uint8Array {
  checkNetwork(network);
  checkCred(payment);
  checkCred(stake);
  const t =
    (payment.type === 'script' ? 1 : 0) | (stake.type === 'script' ? 2 : 0);
  return concatBytes(
    Uint8Array.of((t << 4) | network),
    payment.hash,
    stake.hash,
  );
}

export function enterpriseAddress(
  network: number,
  payment: Credential,
): Uint8Array {
  checkNetwork(network);
  checkCred(payment);
  const t = payment.type === 'script' ? 7 : 6;
  return concatBytes(Uint8Array.of((t << 4) | network), payment.hash);
}

export function pointerAddress(
  network: number,
  payment: Credential,
  pointer: Pointer,
): Uint8Array {
  checkNetwork(network);
  checkCred(payment);
  const t = payment.type === 'script' ? 5 : 4;
  return concatBytes(
    Uint8Array.of((t << 4) | network),
    payment.hash,
    encodeNat(pointer.slot),
    encodeNat(pointer.txIndex),
    encodeNat(pointer.certIndex),
  );
}

export function rewardAddress(network: number, stake: Credential): Uint8Array {
  checkNetwork(network);
  checkCred(stake);
  const t = stake.type === 'script' ? 15 : 14;
  return concatBytes(Uint8Array.of((t << 4) | network), stake.hash);
}

/** Base address for a pair of verification-key hashes (the usual wallet address). */
export function keyBaseAddress(
  network: number,
  paymentKeyHash: Uint8Array,
  stakeKeyHash: Uint8Array,
): Uint8Array {
  return baseAddress(
    network,
    cred('key', paymentKeyHash),
    cred('key', stakeKeyHash),
  );
}

// ---- parsing ----

function parseByron(bytes: Uint8Array): ParsedAddress {
  const outer = expectArray(decodeCbor(bytes), 'byron address');
  if (outer.length !== 2)
    throw invalidAddress('byron address: expected [payload, crc]');
  const tagged = outer[0];
  if (tagged?.type !== 'tag' || tagged.tag !== 24n)
    throw invalidAddress('byron address: expected tag 24');
  const payload = expectBytes(tagged.value, 'byron payload');
  const crc = expectUint(outer[1], 'byron crc');
  if (BigInt(crc32(payload)) !== crc)
    throw invalidAddress('byron address: bad checksum');
  const inner = expectArray(decodeCbor(payload), 'byron payload');
  if (inner.length !== 3)
    throw invalidAddress('byron payload: expected 3 fields');
  expectBytes(inner[0], 'byron root', HASH_LEN);
  const attrs = expectMap(inner[1], 'byron attributes');
  const byronTypeValue = expectUint(inner[2], 'byron type');
  if (byronTypeValue > 255n) throw invalidAddress('byron type out of range');
  const byronType = Number(byronTypeValue);
  // The ledger's measure (bootstrapAddressAttrsSize): length of the HD derivation payload
  // (attribute 1, a CBOR byte string inside the attribute's bytes) plus the byte length of every
  // unknown attribute. The network magic (attribute 2) does not count.
  let byronAttributesSize = 0;
  for (const [k, v] of attrs.entries) {
    const key = expectUint(k, 'byron attribute key');
    const raw = expectBytes(v, 'byron attribute');
    if (key === 1n) {
      byronAttributesSize += expectBytes(
        decodeCbor(raw),
        'byron derivation path',
      ).length;
    } else if (key !== 2n) {
      byronAttributesSize += raw.length;
    }
  }
  let magic: number | undefined;
  for (const [k, v] of attrs.entries) {
    if (k.type === 'uint' && k.value === 2n) {
      const m = expectUint(
        decodeCbor(expectBytes(v, 'byron magic')),
        'byron magic',
      );
      if (m > 0xffffffffn)
        throw invalidAddress('byron protocol magic out of range');
      magic = Number(m);
    }
  }
  // Like the ledger (getNetwork): no magic attribute means mainnet, and ANY explicit magic —
  // even the mainnet value — means testnet. CSL's network_id() reports such an address as
  // mainnet; the node would reject an output to it on mainnet with WrongNetwork.
  const network = magic === undefined ? NetworkId.Mainnet : NetworkId.Testnet;
  return {
    kind: 'byron',
    bytes,
    network,
    byronType,
    byronAttributesSize,
    ...(magic === undefined ? {} : { byronProtocolMagic: magic }),
  };
}

/** Byron parsing with every malformed-CBOR failure reported as an invalid address. */
function parseByronChecked(bytes: Uint8Array): ParsedAddress {
  try {
    return parseByron(bytes);
  } catch (e) {
    if (e instanceof CardanoError && e.code === 'INVALID_CBOR') {
      throw invalidAddress(`malformed Byron address: ${e.message}`);
    }
    throw e;
  }
}

/** Parses raw address bytes, validating their structure. */
export function addressFromBytes(input: Uint8Array): ParsedAddress {
  const bytes = Uint8Array.from(input);
  const h = bytes[0];
  if (h === undefined) throw invalidAddress('empty address');
  const type = h >> 4;
  const network = h & 0x0f;
  const body = bytes.subarray(1);
  const hashAt = (o: number): Uint8Array =>
    bytes.slice(1 + o, 1 + o + HASH_LEN);
  switch (type) {
    case 0:
    case 1:
    case 2:
    case 3:
      if (body.length !== 2 * HASH_LEN)
        throw invalidAddress('base address must be 57 bytes');
      return {
        kind: 'base',
        bytes,
        network,
        payment: cred(type & 1 ? 'script' : 'key', hashAt(0)),
        stake: cred(type & 2 ? 'script' : 'key', hashAt(HASH_LEN)),
      };
    case 4:
    case 5: {
      if (body.length < HASH_LEN + 3)
        throw invalidAddress('pointer address too short');
      let o = 1 + HASH_LEN;
      const slot = decodeNat(bytes, o);
      o = slot.next;
      const txIndex = decodeNat(bytes, o);
      o = txIndex.next;
      const certIndex = decodeNat(bytes, o);
      if (certIndex.next !== bytes.length)
        throw invalidAddress('trailing bytes in pointer address');
      return {
        kind: 'pointer',
        bytes,
        network,
        payment: cred(type === 5 ? 'script' : 'key', hashAt(0)),
        pointer: {
          slot: slot.value,
          txIndex: txIndex.value,
          certIndex: certIndex.value,
        },
      };
    }
    case 6:
    case 7:
      if (body.length !== HASH_LEN)
        throw invalidAddress('enterprise address must be 29 bytes');
      return {
        kind: 'enterprise',
        bytes,
        network,
        payment: cred(type === 7 ? 'script' : 'key', hashAt(0)),
      };
    case 8:
      return parseByronChecked(bytes);
    case 14:
    case 15:
      if (body.length !== HASH_LEN)
        throw invalidAddress('reward address must be 29 bytes');
      return {
        kind: 'reward',
        bytes,
        network,
        stake: cred(type === 15 ? 'script' : 'key', hashAt(0)),
      };
    default:
      throw invalidAddress(`unknown address type ${type}`);
  }
}

/** Expected bech32 prefix for an address's kind and network (CIP-5). */
export function bech32Prefix(
  kind: Exclude<AddressKind, 'byron'>,
  network: number,
): string {
  const test = network !== NetworkId.Mainnet;
  if (kind === 'reward') return test ? 'stake_test' : 'stake';
  return test ? 'addr_test' : 'addr';
}

const BECH32_LIKE = /^(addr|addr_test|stake|stake_test)1[02-9ac-hj-np-z]+$/i;

/**
 * Parses a bech32 (Shelley) or base58 (Byron) address string, or raw bytes.
 * Bech32 prefixes must match the address kind and network.
 */
export function parseAddress(input: string | Uint8Array): ParsedAddress {
  if (input instanceof Uint8Array) return addressFromBytes(input);
  if (typeof input !== 'string')
    throw invalidAddress('address must be a string or bytes');
  const s = input.trim();
  if (BECH32_LIKE.test(s)) {
    let decoded: { prefix: string; data: Uint8Array };
    try {
      decoded = bech32Decode(s);
    } catch {
      throw invalidAddress('invalid bech32 address');
    }
    const parsed = addressFromBytes(decoded.data);
    if (parsed.kind === 'byron')
      throw invalidAddress('byron address in bech32');
    if (decoded.prefix !== bech32Prefix(parsed.kind, parsed.network)) {
      throw invalidAddress(
        'bech32 prefix does not match address type or network',
      );
    }
    return parsed;
  }
  // Byron addresses are well under 256 characters; bound the quadratic base58 decode.
  if (s.length > 256) throw invalidAddress('address too long');
  let raw: Uint8Array;
  try {
    raw = base58Decode(s);
  } catch {
    throw invalidAddress('not a bech32 or base58 address');
  }
  if (raw[0] === undefined || raw[0] >> 4 !== 8)
    throw invalidAddress('not a Byron address');
  return parseByronChecked(raw);
}

/** Parses hex-encoded raw address bytes (the CIP-30 wire form). */
export function parseAddressHex(hex: string): ParsedAddress {
  return addressFromBytes(hexToBytes(hex));
}

const HEX_RE = /^(?:[0-9a-fA-F]{2})+$/;

/**
 * Every form an address arrives in from a dapp or the CIP-30 API: raw bytes,
 * hex of the raw bytes (CIP-30 wire format), bech32 or Byron base58. One
 * parser for all of them, so every entry point accepts the same inputs.
 */
export function parseAddressInput(input: string | Uint8Array): ParsedAddress {
  if (input instanceof Uint8Array) return addressFromBytes(input);
  if (typeof input !== 'string')
    throw invalidAddress('address must be a string or bytes');
  const s = input.trim();
  // Base58 has no '0', and bech32 addresses contain letters beyond a–f, so hex is unambiguous
  // in practice; still, fall back to the other forms if the hex does not decode.
  if (HEX_RE.test(s)) {
    try {
      return addressFromBytes(hexToBytes(s));
    } catch {
      /* not address bytes: try bech32 / base58 */
    }
  }
  return parseAddress(s);
}

/** bech32 (Shelley) or base58 (Byron) string for raw address bytes. */
export function addressToString(input: Uint8Array | ParsedAddress): string {
  const parsed = input instanceof Uint8Array ? addressFromBytes(input) : input;
  if (parsed.kind === 'byron') return base58Encode(parsed.bytes);
  return bech32Encode(bech32Prefix(parsed.kind, parsed.network), parsed.bytes);
}

export function isValidAddress(input: string | Uint8Array): boolean {
  try {
    parseAddress(input);
    return true;
  } catch {
    return false;
  }
}

/** Any address that can hold funds in a transaction output (everything except reward addresses). */
export function isPaymentAddress(
  input: string | Uint8Array | ParsedAddress,
): boolean {
  const parsed =
    typeof input === 'string' || input instanceof Uint8Array
      ? parseAddress(input)
      : input;
  return parsed.kind !== 'reward';
}

/**
 * Parses an address that will receive funds. Rejects reward (`stake1…`)
 * addresses, which the ledger refuses as outputs, and a network mismatch.
 */
export function parsePaymentAddress(
  input: string | Uint8Array,
  expectedNetwork?: number,
): ParsedAddress {
  const parsed = parseAddress(input);
  if (parsed.kind === 'reward') {
    throw new CardanoError(
      'NOT_A_PAYMENT_ADDRESS',
      'a stake address cannot receive funds',
    );
  }
  if (expectedNetwork !== undefined && parsed.network !== expectedNetwork) {
    throw new CardanoError('WRONG_NETWORK', 'address is for another network');
  }
  if (parsed.kind === 'byron') {
    if (parsed.byronType !== 0) {
      throw invalidAddress('only public-key Byron addresses can receive funds');
    }
    if ((parsed.byronAttributesSize ?? 0) > MAX_BYRON_ATTRIBUTES_SIZE) {
      throw invalidAddress('Byron address attributes exceed the ledger limit');
    }
  }
  return parsed;
}

/** Whether two credentials are identical. */
export function sameCredential(
  a: Credential | undefined,
  b: Credential | undefined,
): boolean {
  if (!a || !b) return false;
  return a.type === b.type && equalBytes(a.hash, b.hash);
}

export function credentialToHex(c: Credential): string {
  return bytesToHex(c.hash);
}
