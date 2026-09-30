import { describe, expect, it } from 'vitest';
import {
  bytesToHex,
  CardanoError,
  cArray,
  cBytes,
  cInt,
  cMap,
  cText,
  decodeCbor,
  decodeCborPrefix,
  encodeCbor,
  hexToBytes,
  rawBytes,
} from '../src/index.js';
import type { CborEncodable, CborNode } from '../src/index.js';
import { Rng } from './helpers/random.js';

/** RFC 8949 Appendix A (bignum tags and non-shortest float forms included). */
const RFC_VECTORS = [
  '00',
  '01',
  '0a',
  '17',
  '1818',
  '1819',
  '1864',
  '1903e8',
  '1a000f4240',
  '1b000000e8d4a51000',
  '1bffffffffffffffff',
  'c249010000000000000000',
  '3bffffffffffffffff',
  'c349010000000000000000',
  '20',
  '29',
  '3863',
  '3903e7',
  'f90000',
  'f98000',
  'f93c00',
  'fb3ff199999999999a',
  'f93e00',
  'f97bff',
  'fa47c35000',
  'fa7f7fffff',
  'fb7e37e43c8800759c',
  'f90001',
  'f90400',
  'f9c400',
  'fbc010666666666666',
  'f97c00',
  'f97e00',
  'f9fc00',
  'fa7f800000',
  'fa7fc00000',
  'faff800000',
  'fb7ff0000000000000',
  'fb7ff8000000000000',
  'fbfff0000000000000',
  'f4',
  'f5',
  'f6',
  'f7',
  'f0',
  'f8ff',
  'c074323031332d30332d32315432303a30343a30305a',
  'c11a514b67b0',
  'c1fb41d452d9ec200000',
  'd74401020304',
  'd818456449455446',
  'd82076687474703a2f2f7777772e6578616d706c652e636f6d',
  '40',
  '4401020304',
  '60',
  '6161',
  '6449455446',
  '62225c',
  '62c3bc',
  '63e6b0b4',
  '64f0908591',
  '80',
  '83010203',
  '8301820203820405',
  '98190102030405060708090a0b0c0d0e0f101112131415161718181819',
  'a0',
  'a201020304',
  'a26161016162820203',
  '826161a161626163',
  'a56161614161626142616361436164614461656145',
  '5f42010243030405ff',
  '7f657374726561646d696e67ff',
  '9fff',
  '9f018202039f0405ffff',
  '9f01820203820405ff',
  '83018202039f0405ff',
  '83019f0203ff820405',
  '9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff',
  'bf61610161629f0203ffff',
  '826161bf61626163ff',
  'bf6346756ef563416d7421ff',
];

describe('CBOR: RFC 8949 Appendix A', () => {
  it('decodes every vector and re-encodes it byte-identically', () => {
    for (const h of RFC_VECTORS) {
      const node = decodeCbor(hexToBytes(h));
      expect(bytesToHex(encodeCbor(node)), h).toBe(h);
    }
  });

  it('reads values correctly', () => {
    const v = (h: string): CborNode => decodeCbor(hexToBytes(h));
    expect(v('1bffffffffffffffff')).toMatchObject({
      type: 'uint',
      value: 18446744073709551615n,
    });
    expect(v('3bffffffffffffffff')).toMatchObject({
      type: 'nint',
      value: -18446744073709551616n,
    });
    expect(v('3903e7')).toMatchObject({ type: 'nint', value: -1000n });
    expect(v('fb3ff199999999999a')).toMatchObject({
      type: 'float',
      value: 1.1,
    });
    expect(v('f90001')).toMatchObject({
      type: 'float',
      value: 5.960464477539063e-8,
    });
    expect(v('f97bff')).toMatchObject({ type: 'float', value: 65504 });
    expect(v('64f0908591')).toMatchObject({ type: 'text', value: '𐅑' });
    expect(v('5f42010243030405ff')).toMatchObject({
      type: 'bytes',
      value: hexToBytes('0102030405'),
    });
    expect(v('7f657374726561646d696e67ff')).toMatchObject({
      type: 'text',
      value: 'streaming',
    });
    expect(v('f8ff')).toMatchObject({ type: 'simple', value: 255 });
  });

  it('canonical mode drops indefinite lengths and sorts keys', () => {
    const indefinite = decodeCbor(hexToBytes('bf6346756ef563416d7421ff'));
    expect(bytesToHex(encodeCbor(indefinite, { canonical: true }))).toBe(
      'a263416d74216346756ef5',
    );
    expect(
      bytesToHex(
        encodeCbor(decodeCbor(hexToBytes('9f018202039f0405ffff')), {
          canonical: true,
        }),
      ),
    ).toBe('8301820203820405');
    // length-first ordering of byte-string keys, like CSL's multi-asset maps
    const m = cMap([
      [cBytes(hexToBytes('ffff')), cInt(1)],
      [cBytes(hexToBytes('00')), cInt(2)],
      [cBytes(hexToBytes('aabbcc')), cInt(3)],
      [cBytes(hexToBytes('01')), cInt(4)],
    ]);
    expect(bytesToHex(encodeCbor(m, { canonical: true }))).toBe(
      'a441000241010442ffff0143aabbcc03',
    );
    // shortest float
    expect(
      bytesToHex(
        encodeCbor(
          { type: 'float', value: 1.5, width: 64 },
          { canonical: true },
        ),
      ),
    ).toBe('f93e00');
  });
});

describe('CBOR: spans', () => {
  it('records the exact source range of every node, including non-minimal heads', () => {
    // {2: 42 as 1a0000002a, 0: [h'01']}
    const src = hexToBytes('a2021a0000002a00814101');
    const node = decodeCbor(src);
    if (node.type !== 'map') throw new Error('map expected');
    const fee = node.entries[0]![1];
    expect(bytesToHex(rawBytes(src, fee))).toBe('1a0000002a');
    expect(bytesToHex(rawBytes(src, node.entries[1]![1]))).toBe('814101');
    expect(bytesToHex(rawBytes(src, node))).toBe(bytesToHex(src));
    // preserve-mode re-encoding normalises the head — exactly why tx ids must hash raw spans
    expect(bytesToHex(encodeCbor(node))).toBe('a202182a00814101');
  });

  it('decodes a prefix and reports where it ended', () => {
    const { node, end } = decodeCborPrefix(hexToBytes('8201020304'));
    expect(end).toBe(3);
    expect(node.type).toBe('array');
  });
});

describe('CBOR: rejects malformed input', () => {
  const bad = (h: string): string => {
    try {
      decodeCbor(hexToBytes(h));
    } catch (e) {
      expect(e).toBeInstanceOf(CardanoError);
      return (e as CardanoError).code;
    }
    throw new Error(`accepted ${h}`);
  };
  it.each([
    ['trailing bytes', '0000'],
    ['truncated', '1a0000'],
    ['truncated string', '4401'],
    ['reserved ai 28', '1c'],
    ['indefinite integer', '1f'],
    ['lone break', 'ff'],
    ['bad chunk type', '5f6161ff'],
    ['nested indefinite chunk', '5f5fffff'],
    ['invalid utf-8', '62c328'],
    ['surrogate in utf-8', '63eda080'],
    ['length beyond input', '9a7fffffff'],
    ['two-byte simple < 32', 'f818'],
    ['unterminated indefinite array', '9f01'],
  ])('%s', (_, h) => {
    expect(bad(h)).toBe('INVALID_CBOR');
  });

  it('rejects duplicate map keys unless asked, including non-minimal duplicates', () => {
    expect(() => decodeCbor(hexToBytes('a201020103'))).toThrow(/duplicate/);
    expect(() => decodeCbor(hexToBytes('a20102180103'))).toThrow(/duplicate/);
    expect(() => decodeCbor(hexToBytes('a2616101616102'))).toThrow(/duplicate/);
    expect(
      decodeCbor(hexToBytes('a201020103'), { allowDuplicateKeys: true }).type,
    ).toBe('map');
  });

  it('limits nesting depth', () => {
    const deep = '81'.repeat(200) + '00';
    expect(() => decodeCbor(hexToBytes(deep))).toThrow(/deep/);
    expect(decodeCbor(hexToBytes(deep), { maxDepth: 300 }).type).toBe('array');
  });
});

describe('CBOR: round-trip fuzz', () => {
  function randomNode(rng: Rng, depth: number): CborEncodable {
    const k = depth > 3 ? rng.int(4) : rng.int(7);
    switch (k) {
      case 0:
        return cInt(rng.bool() ? rng.u64() : -rng.u64() - 1n);
      case 1:
        return cBytes(rng.bytes(rng.int(40)));
      case 2:
        return cText(
          String.fromCharCode(
            ...Array.from(rng.bytes(rng.int(20)), (b) => 32 + (b % 90)),
          ),
        );
      case 3:
        return { type: 'simple', value: rng.pick([20, 21, 22, 23]) };
      case 4:
        return cArray(
          Array.from({ length: rng.int(5) }, () => randomNode(rng, depth + 1)),
        );
      case 5:
        return {
          type: 'array',
          items: Array.from({ length: rng.int(5) }, () =>
            randomNode(rng, depth + 1),
          ),
          indefinite: true,
        };
      default:
        return cMap(
          Array.from(
            { length: rng.int(4) },
            (_, i) => [cInt(i), randomNode(rng, depth + 1)] as const,
          ),
        );
    }
  }

  it('encode → decode → encode is stable', () => {
    const rng = new Rng(0xcb0);
    for (let i = 0; i < 2000; i++) {
      const bytes = encodeCbor(randomNode(rng, 0));
      expect(bytesToHex(encodeCbor(decodeCbor(bytes)))).toBe(bytesToHex(bytes));
    }
  });
});
