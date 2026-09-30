import { createRequire } from 'node:module';
import type * as CslModule from '@emurgo/cardano-serialization-lib-nodejs';
import type * as CmsModule from '@emurgo/cardano-message-signing-nodejs';

/**
 * Dev-only oracles: cardano-serialization-lib 14.1.2 and
 * cardano-message-signing 1.1.0, the versions ZelCore ships today. Never
 * imported by `src/`.
 */
const require = createRequire(import.meta.url);

export const CSL =
  require('@emurgo/cardano-serialization-lib-nodejs') as typeof CslModule;
export const CMS =
  require('@emurgo/cardano-message-signing-nodejs') as typeof CmsModule;

export const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
export const unhex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h, 'hex'));

export const big = (n: bigint): CslModule.BigNum =>
  CSL.BigNum.from_str(n.toString());
