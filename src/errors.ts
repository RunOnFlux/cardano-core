/**
 * Typed errors with a stable machine-readable `code`, so consumers can branch
 * without string matching. Messages never contain keys or signatures.
 */
export type CardanoErrorCode =
  | 'INVALID_INPUT'
  | 'INVALID_CBOR'
  | 'INVALID_ADDRESS'
  | 'WRONG_NETWORK'
  | 'NOT_A_PAYMENT_ADDRESS'
  | 'INVALID_PARAMS'
  | 'INVALID_TRANSACTION'
  | 'INSUFFICIENT_FUNDS'
  | 'INSUFFICIENT_TOKENS'
  | 'INSUFFICIENT_ADA_FOR_CHANGE'
  | 'OUTPUT_BELOW_MIN_ADA'
  | 'VALUE_TOO_LARGE'
  | 'TX_TOO_LARGE'
  | 'FEE_TOO_HIGH'
  | 'INVARIANT_VIOLATION'
  | 'KEY_MISMATCH'
  | 'ADDRESS_NOT_PK'
  | 'CHANGE_ADDRESS_NOT_OWN'
  | 'COLLATERAL_AT_RISK'
  /** A collateral input could not be looked up (`resolvedCollateral`): retry with a fresh lookup. */
  | 'COLLATERAL_UNRESOLVED'
  | 'SIGNATURE'
  | 'UNSUPPORTED';

export class CardanoError extends Error {
  readonly code: CardanoErrorCode;
  constructor(code: CardanoErrorCode, message: string) {
    super(message);
    this.name = 'CardanoError';
    this.code = code;
  }
}

/** Planner failure that also reports how much more ADA (lovelace) would have made it work. */
export class InsufficientFundsError extends CardanoError {
  /** Lovelace still missing, when it can be computed (0n when unknown). */
  readonly shortfall: bigint;
  constructor(
    code:
      | 'INSUFFICIENT_FUNDS'
      | 'INSUFFICIENT_TOKENS'
      | 'INSUFFICIENT_ADA_FOR_CHANGE',
    message: string,
    shortfall = 0n,
  ) {
    super(code, message);
    this.name = 'InsufficientFundsError';
    this.shortfall = shortfall;
  }
}

export const invalidInput = (message: string): CardanoError =>
  new CardanoError('INVALID_INPUT', message);

export const invalidCbor = (message: string): CardanoError =>
  new CardanoError('INVALID_CBOR', message);

export const invalidAddress = (message: string): CardanoError =>
  new CardanoError('INVALID_ADDRESS', message);
