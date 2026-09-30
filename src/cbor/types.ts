/** Byte range `[start, end)` of a decoded item inside its source buffer. */
export interface Span {
  readonly start: number;
  readonly end: number;
}

export interface CborUint {
  readonly type: 'uint';
  readonly value: bigint;
  readonly span?: Span;
}

/** Negative integer; `value` is the (negative) integer itself, -1 … -2^64. */
export interface CborNint {
  readonly type: 'nint';
  readonly value: bigint;
  readonly span?: Span;
}

export interface CborBytes {
  readonly type: 'bytes';
  readonly value: Uint8Array;
  /** Set when decoded from (or to be encoded as) an indefinite-length chunked string. */
  readonly chunks?: readonly Uint8Array[];
  readonly span?: Span;
}

export interface CborText {
  readonly type: 'text';
  readonly value: string;
  readonly chunks?: readonly string[];
  readonly span?: Span;
}

export interface CborArray {
  readonly type: 'array';
  readonly items: readonly CborNode[];
  readonly indefinite?: boolean;
  readonly span?: Span;
}

export interface CborMap {
  readonly type: 'map';
  readonly entries: readonly (readonly [CborNode, CborNode])[];
  readonly indefinite?: boolean;
  readonly span?: Span;
}

export interface CborTag {
  readonly type: 'tag';
  readonly tag: bigint;
  readonly value: CborNode;
  readonly span?: Span;
}

/** Simple values: 20 false, 21 true, 22 null, 23 undefined, others unassigned. */
export interface CborSimple {
  readonly type: 'simple';
  readonly value: number;
  readonly span?: Span;
}

export interface CborFloat {
  readonly type: 'float';
  readonly value: number;
  /** Encoded width in bits when decoded; the encoder otherwise picks the shortest exact width. */
  readonly width?: 16 | 32 | 64;
  readonly span?: Span;
}

/** Encoder-only: already-encoded CBOR spliced in verbatim (used to keep original bytes). */
export interface CborRaw {
  readonly type: 'raw';
  readonly bytes: Uint8Array;
}

export type CborNode =
  | CborUint
  | CborNint
  | CborBytes
  | CborText
  | CborArray
  | CborMap
  | CborTag
  | CborSimple
  | CborFloat;

export type CborEncodable =
  | CborUint
  | CborNint
  | CborBytes
  | CborText
  | (Omit<CborArray, 'items'> & { readonly items: readonly CborEncodable[] })
  | (Omit<CborMap, 'entries'> & {
      readonly entries: readonly (readonly [CborEncodable, CborEncodable])[];
    })
  | (Omit<CborTag, 'value'> & { readonly value: CborEncodable })
  | CborSimple
  | CborFloat
  | CborRaw;
