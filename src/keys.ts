import { ed25519 } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha512 } from '@noble/hashes/sha2.js';
import {
  bigIntToBytesLE,
  bytesToBigIntLE,
  concatBytes,
  equalBytes,
  u32le,
  zeroize,
} from './bytes.js';
import { CardanoError, invalidInput } from './errors.js';
import { blake2b224 } from './hash.js';

/**
 * Keys follow CIP-3 "Icarus" master key generation and BIP32-Ed25519 V2
 * (Khovratovich–Law) derivation — what every Shelley wallet and
 * cardano-serialization-lib's `Bip32PrivateKey` use.
 *
 * Layouts:
 * - extended private key: 96 bytes `kL(32) ‖ kR(32) ‖ chainCode(32)`
 * - extended public key:  64 bytes `A(32) ‖ chainCode(32)`
 * - signing key:          64 bytes `kL ‖ kR` (a raw extended Ed25519 key)
 */

export const HARDENED = 0x80000000;

/** `harden(1852)` → 0x8000073c. */
export function harden(index: number): number {
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED) {
    throw invalidInput('index out of range for hardening');
  }
  return HARDENED + index;
}

const Point = ed25519.Point;
const N = Point.Fn.ORDER;
const TWO_256 = 1n << 256n;

/** CIP-1852 roles. */
export const Role = {
  External: 0,
  Internal: 1,
  Stake: 2,
  DRep: 3,
  CommitteeCold: 4,
  CommitteeHot: 5,
} as const;
export type Role = (typeof Role)[keyof typeof Role];

function scalarMulBase(scalarLE: Uint8Array): Uint8Array {
  const s = bytesToBigIntLE(scalarLE) % N;
  if (s === 0n) throw new CardanoError('INVALID_INPUT', 'degenerate key');
  return Point.BASE.multiply(s).toBytes();
}

/**
 * CIP-3 Icarus master key from BIP-39 entropy: PBKDF2-HMAC-SHA512(password,
 * salt = entropy, 4096 rounds, 96 bytes), then clamped. Equals CSL
 * `Bip32PrivateKey.from_bip39_entropy(entropy, password)`.
 */
export function rootKeyFromEntropy(
  entropy: Uint8Array,
  password: Uint8Array = new Uint8Array(0),
): Uint8Array {
  // BIP-39 entropy: 12, 15, 18, 21 or 24 words.
  if (![16, 20, 24, 28, 32].includes(entropy.length)) {
    throw invalidInput('entropy must be 16, 20, 24, 28 or 32 bytes (BIP-39)');
  }
  const x = pbkdf2(sha512, password, entropy, { c: 4096, dkLen: 96 });
  x[0] = (x[0] as number) & 0xf8;
  x[31] = ((x[31] as number) & 0x1f) | 0x40;
  return x;
}

function checkXprv(xprv: Uint8Array): void {
  if (xprv.length !== 96)
    throw invalidInput('extended private key must be 96 bytes');
}

/** Ed25519 public key `A = kL·B` of an extended private key (or of a 64-byte signing key). */
export function publicKeyOf(extendedKey: Uint8Array): Uint8Array {
  if (extendedKey.length !== 96 && extendedKey.length !== 64) {
    throw invalidInput('expected a 64- or 96-byte extended key');
  }
  return scalarMulBase(extendedKey.subarray(0, 32));
}

/** Child extended private key (hardened or soft). */
export function derivePrivate(xprv: Uint8Array, index: number): Uint8Array {
  checkXprv(xprv);
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
    throw invalidInput('derivation index out of range');
  }
  const kL = xprv.subarray(0, 32);
  const kR = xprv.subarray(32, 64);
  const cc = xprv.subarray(64, 96);
  const idx = u32le(index);
  const hard = index >= HARDENED;
  let z: Uint8Array;
  let c: Uint8Array;
  if (hard) {
    // The HMAC inputs hold the private key: zero them once hashed.
    const zIn = concatBytes(Uint8Array.of(0x00), kL, kR, idx);
    const cIn = concatBytes(Uint8Array.of(0x01), kL, kR, idx);
    z = hmac(sha512, cc, zIn);
    c = hmac(sha512, cc, cIn);
    zeroize(zIn);
    zeroize(cIn);
  } else {
    const a = scalarMulBase(kL);
    z = hmac(sha512, cc, concatBytes(Uint8Array.of(0x02), a, idx));
    c = hmac(sha512, cc, concatBytes(Uint8Array.of(0x03), a, idx));
  }
  const zL = bytesToBigIntLE(z.subarray(0, 28));
  const zR = bytesToBigIntLE(z.subarray(32, 64));
  // V2: kL' = 8·zL + kL and kR' = zR + kR, both modulo 2^256 (carry beyond 256 bits discarded).
  const nkL = bigIntToBytesLE((8n * zL + bytesToBigIntLE(kL)) % TWO_256, 32);
  const nkR = bigIntToBytesLE((zR + bytesToBigIntLE(kR)) % TWO_256, 32);
  const out = concatBytes(nkL, nkR, c.subarray(32, 64));
  zeroize(z);
  zeroize(c);
  return out;
}

/** Derives along a path of indexes, e.g. `[harden(1852), harden(1815), harden(0), 0, 0]`. */
export function derivePath(
  xprv: Uint8Array,
  path: readonly number[],
): Uint8Array {
  let k = xprv;
  for (const i of path) {
    const next = derivePrivate(k, i);
    if (k !== xprv) zeroize(k);
    k = next;
  }
  return k === xprv ? Uint8Array.from(xprv) : k;
}

/** Extended public key `A ‖ chainCode` of an extended private key. */
export function toExtendedPublic(xprv: Uint8Array): Uint8Array {
  checkXprv(xprv);
  return concatBytes(scalarMulBase(xprv.subarray(0, 32)), xprv.slice(64, 96));
}

/** Soft (non-hardened) child of an extended public key: `A' = A + 8·zL·B`. */
export function derivePublic(xpub: Uint8Array, index: number): Uint8Array {
  if (xpub.length !== 64)
    throw invalidInput('extended public key must be 64 bytes');
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED) {
    throw invalidInput('public derivation needs a soft index');
  }
  const a = xpub.subarray(0, 32);
  const cc = xpub.subarray(32, 64);
  const idx = u32le(index);
  const z = hmac(sha512, cc, concatBytes(Uint8Array.of(0x02), a, idx));
  const c = hmac(sha512, cc, concatBytes(Uint8Array.of(0x03), a, idx));
  const zL8 = (8n * bytesToBigIntLE(z.subarray(0, 28))) % N;
  let A: ReturnType<typeof Point.fromBytes>;
  try {
    A = Point.fromBytes(a);
  } catch {
    throw invalidInput('extended public key is not a valid Ed25519 point');
  }
  const child = zL8 === 0n ? A : A.add(Point.BASE.multiply(zL8));
  if (child.is0())
    throw new CardanoError('INVALID_INPUT', 'degenerate public key');
  return concatBytes(child.toBytes(), c.subarray(32, 64));
}

/**
 * Ed25519 signature with an extended key (`kL ‖ kR`), as CSL `PrivateKey.sign`
 * does for BIP32-Ed25519 keys: `r = H(kR ‖ M)`, `S = r + H(R ‖ A ‖ M)·kL`.
 * The standard `ed25519.sign(seed)` cannot be used: it hashes a seed.
 */
export function signExtended(
  extendedKey: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  if (extendedKey.length !== 64 && extendedKey.length !== 96) {
    throw invalidInput('expected a 64- or 96-byte extended key');
  }
  const kL = extendedKey.subarray(0, 32);
  const kR = extendedKey.subarray(32, 64);
  const A = scalarMulBase(kL);
  const nonceIn = concatBytes(kR, message);
  const r = bytesToBigIntLE(sha512(nonceIn)) % N;
  zeroize(nonceIn);
  if (r === 0n) throw new CardanoError('SIGNATURE', 'degenerate nonce');
  const R = Point.BASE.multiply(r).toBytes();
  const k = bytesToBigIntLE(sha512(concatBytes(R, A, message))) % N;
  const s = (r + k * bytesToBigIntLE(kL)) % N;
  return concatBytes(R, bigIntToBytesLE(s, 32));
}

/** Strict RFC 8032 Ed25519 verification (non-canonical S and small-order keys rejected). */
export function verifyEd25519(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/** blake2b-224 of a verification key: the payment/stake credential hash. */
export function keyHash(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 32)
    throw invalidInput('public key must be 32 bytes');
  return blake2b224(publicKey);
}

/**
 * Anything that can produce an Ed25519 signature for a 32-byte public key.
 * `sign` may be async so a hardware signer can slot in without core changes.
 */
export interface Signer {
  readonly publicKey: Uint8Array;
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export interface LocalSigner extends Signer {
  readonly keyHash: Uint8Array;
  /** Zeroes the key copy held by this signer; later `sign` calls throw. */
  destroy(): void;
}

/**
 * A signer over a copy of a 64-byte (`kL ‖ kR`) or 96-byte extended private
 * key. Every signature is verified before it is returned.
 */
export function localSigner(extendedKey: Uint8Array): LocalSigner {
  if (extendedKey.length !== 64 && extendedKey.length !== 96) {
    throw invalidInput('expected a 64- or 96-byte extended key');
  }
  if (extendedKey.length === 96) {
    // Like CSL's Bip32PrivateKey: kL must be clamped (low 3 bits clear, bit 255 clear, bit 254 set).
    const b0 = extendedKey[0] as number;
    const b31 = extendedKey[31] as number;
    if ((b0 & 0x07) !== 0 || (b31 & 0xc0) !== 0x40) {
      throw invalidInput(
        'extended private key is not a clamped BIP32-Ed25519 key',
      );
    }
  }
  const key = extendedKey.slice(0, 64);
  const publicKey = scalarMulBase(key.subarray(0, 32));
  let destroyed = false;
  return {
    publicKey,
    keyHash: blake2b224(publicKey),
    sign(message: Uint8Array): Uint8Array {
      if (destroyed) throw new CardanoError('SIGNATURE', 'signer destroyed');
      const sig = signExtended(key, message);
      if (!verifyEd25519(publicKey, message, sig)) {
        throw new CardanoError('SIGNATURE', 'signature self-check failed');
      }
      return sig;
    },
    destroy(): void {
      zeroize(key);
      destroyed = true;
    },
  };
}

/** Signs and checks that the signer's key is the one expected and the signature verifies. */
export async function signChecked(
  signer: Signer,
  message: Uint8Array,
): Promise<Uint8Array> {
  const sig = await signer.sign(message);
  if (
    !(sig instanceof Uint8Array) ||
    !verifyEd25519(signer.publicKey, message, sig)
  ) {
    throw new CardanoError('SIGNATURE', 'signer returned an invalid signature');
  }
  return sig;
}

export interface Cip1852Path {
  readonly account?: number;
  readonly role?: Role;
  readonly index?: number;
}

/** `m / 1852' / 1815' / account' / role / index` (defaults: account 0, external, index 0). */
export function cip1852Path({
  account = 0,
  role = Role.External,
  index = 0,
}: Cip1852Path = {}): number[] {
  return [harden(1852), harden(1815), harden(account), role, index];
}

/**
 * Payment and stake keys of a CIP-1852 account, from BIP-39 entropy. The
 * caller owns the returned buffers and should `zeroize` them when done.
 */
export function accountKeysFromEntropy(
  entropy: Uint8Array,
  options: {
    account?: number;
    paymentIndex?: number;
    stakeIndex?: number;
  } = {},
): { payment: Uint8Array; stake: Uint8Array } {
  const root = rootKeyFromEntropy(entropy);
  const account = derivePath(root, [
    harden(1852),
    harden(1815),
    harden(options.account ?? 0),
  ]);
  zeroize(root);
  const payment = derivePath(account, [
    Role.External,
    options.paymentIndex ?? 0,
  ]);
  const stake = derivePath(account, [Role.Stake, options.stakeIndex ?? 0]);
  zeroize(account);
  return { payment, stake };
}

/** Whether a public key's hash equals `hash` (constant-time compare). */
export function keyHashMatches(
  publicKey: Uint8Array,
  hash: Uint8Array,
): boolean {
  return equalBytes(keyHash(publicKey), hash);
}
