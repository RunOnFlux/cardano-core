import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import {
  bytesToHex,
  decodeTransaction,
  txIdOfTransaction,
} from '../src/index.js';
import { CSL, hex } from './helpers/csl.js';

/** Mainnet transactions fetched from Koios (scripts/fetch-corpus.mjs); see test/fixtures/mainnet-corpus.json. */
function loadCorpus(): { hash: string; tx: Uint8Array }[] {
  const raw = gunzipSync(
    readFileSync(new URL('./fixtures/mainnet-corpus.bin.gz', import.meta.url)),
  );
  const out: { hash: string; tx: Uint8Array }[] = [];
  let o = 0;
  while (o < raw.length) {
    const hash = raw.subarray(o, o + 32).toString('hex');
    const len = raw.readUInt32BE(o + 32);
    out.push({ hash, tx: new Uint8Array(raw.subarray(o + 36, o + 36 + len)) });
    o += 36 + len;
  }
  return out;
}

const corpus = loadCorpus();

describe('mainnet corpus', () => {
  it('has a meaningful number of transactions', () => {
    expect(corpus.length).toBeGreaterThan(3000);
  });

  it('decodes every transaction and its id equals the on-chain hash (raw body span)', () => {
    const stats = {
      threeElement: 0,
      taggedSets: 0,
      plutus: 0,
      governance: 0,
      indefinite: 0,
      mint: 0,
      certs: 0,
      invalid: 0,
      unknownKeys: 0,
    };
    for (const { hash, tx } of corpus) {
      const d = decodeTransaction(tx);
      expect(bytesToHex(d.txId), hash).toBe(hash);
      expect(bytesToHex(txIdOfTransaction(tx))).toBe(hash);
      if (d.format === 'three-element') stats.threeElement++;
      if (d.body.taggedSets) stats.taggedSets++;
      if (
        d.witnessSet.keys.some((k) => k === 3 || k === 5 || k === 6 || k === 7)
      )
        stats.plutus++;
      if (d.body.votingProcedures || d.body.proposalProcedures)
        stats.governance++;
      if (
        /9f|bf|5f|7f/.test(bytesToHex(d.witnessSetBytes).slice(0, 4)) ||
        bytesToHex(tx).includes('d8799f')
      )
        stats.indefinite++;
      if (d.body.mint.length > 0) stats.mint++;
      if (d.body.certificates.length > 0) stats.certs++;
      if (!d.isValid) stats.invalid++;
      if (d.body.unknownFields.length > 0) stats.unknownKeys++;
    }
    // The corpus must exercise the encodings the decoder has to survive.
    expect(stats.threeElement).toBeGreaterThan(0);
    expect(stats.taggedSets).toBeGreaterThan(0);
    expect(stats.plutus).toBeGreaterThan(100);
    expect(stats.governance).toBeGreaterThan(50);
    expect(stats.indefinite).toBeGreaterThan(100);
    expect(stats.mint).toBeGreaterThan(0);
    expect(stats.certs).toBeGreaterThan(0);
    expect(stats.unknownKeys).toBe(0);
  });

  it('agrees with CSL FixedTransaction on every transaction CSL can parse', () => {
    let compared = 0;
    for (const { hash, tx } of corpus) {
      let cslHash: string;
      try {
        cslHash = hex(
          CSL.FixedTransaction.from_bytes(tx).transaction_hash().to_bytes(),
        );
      } catch {
        continue; // pre-Alonzo 3-element transactions and the like
      }
      compared++;
      expect(cslHash).toBe(hash);
    }
    expect(compared).toBeGreaterThan(corpus.length * 0.9);
  });
});
