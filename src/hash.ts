import { blake2b } from '@noble/hashes/blake2.js';

/** blake2b-224: key hashes, script hashes, policy IDs. */
export function blake2b224(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 28 });
}

/** blake2b-256: transaction IDs, auxiliary data hashes, datum hashes. */
export function blake2b256(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32 });
}

let CRC_TABLE: Uint32Array | undefined;

function crcTable(): Uint32Array {
  if (CRC_TABLE) return CRC_TABLE;
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  CRC_TABLE = t;
  return t;
}

/** CRC-32 (IEEE 802.3), used by Byron addresses. */
export function crc32(data: Uint8Array): number {
  const t = crcTable();
  let c = 0xffffffff;
  for (const b of data) c = (t[(c ^ b) & 0xff] as number) ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
