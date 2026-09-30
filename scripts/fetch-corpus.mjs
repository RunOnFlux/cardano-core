// Fetches a mainnet transaction corpus from Koios for the tx-id / decoder tests.
//
//   node scripts/fetch-corpus.mjs            # ~2,500 recent txs + older eras + governance
//
// Writes test/fixtures/mainnet-corpus.bin.gz: gzip of repeated records
// [32-byte tx hash][u32 BE length][transaction CBOR], and a manifest JSON.
// Uses the public Koios API gently (one request at a time, 300 ms apart).
import { writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';

const API = 'https://api.koios.rest/api/v1';
const RECENT_TARGET = Number(process.env.CORPUS_RECENT ?? 2500);
const OLD_EPOCHS = [210, 240, 260, 300, 330, 370, 420, 470, 510, 560, 620];
const PER_OLD_EPOCH = 40;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function get(path) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const res = await fetch(`${API}${path}`);
    if (res.ok) {
      await sleep(300);
      return res.json();
    }
    await sleep(2000 * (attempt + 1));
  }
  throw new Error(`GET ${path} failed`);
}

async function post(path, body) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const res = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify(body),
    });
    if (res.ok) {
      await sleep(300);
      return res.json();
    }
    await sleep(2000 * (attempt + 1));
  }
  throw new Error(`POST ${path} failed`);
}

async function txHashesOfBlocks(blockHashes) {
  const out = [];
  for (let i = 0; i < blockHashes.length; i += 20) {
    const rows = await post('/block_txs', {
      _block_hashes: blockHashes.slice(i, i + 20),
    });
    for (const r of rows) out.push(r.tx_hash);
  }
  return out;
}

const hashes = new Set();

// 1. Recent blocks (Conway, DEX/Plutus-heavy).
let offset = 0;
while (hashes.size < RECENT_TARGET) {
  const blocks = await get(
    `/blocks?select=hash,tx_count&tx_count=gt.0&limit=100&offset=${offset}`,
  );
  offset += 100;
  for (const h of await txHashesOfBlocks(blocks.map((b) => b.hash))) {
    hashes.add(h);
    if (hashes.size >= RECENT_TARGET) break;
  }
  process.stdout.write(`\rrecent: ${hashes.size}`);
}
process.stdout.write('\n');

// 2. Older eras (Shelley 3-element txs, Mary multi-assets, Alonzo/Babbage Plutus).
for (const epoch of OLD_EPOCHS) {
  const blocks = await get(
    `/blocks?select=hash,tx_count&epoch_no=eq.${epoch}&tx_count=gt.0&limit=10`,
  );
  const txs = (await txHashesOfBlocks(blocks.map((b) => b.hash))).slice(
    0,
    PER_OLD_EPOCH,
  );
  txs.forEach((h) => hashes.add(h));
  console.log(`epoch ${epoch}: ${txs.length}`);
}

// 3. Governance: votes and proposals.
const votes = await get('/vote_list?select=vote_tx_hash&limit=500');
const voteTxs = [...new Set(votes.map((v) => v.vote_tx_hash))].slice(0, 80);
voteTxs.forEach((h) => hashes.add(h));
const proposals = await get('/proposal_list?select=proposal_tx_hash&limit=200');
const propTxs = [...new Set(proposals.map((p) => p.proposal_tx_hash))];
propTxs.forEach((h) => hashes.add(h));
console.log(
  `governance: ${voteTxs.length} vote txs, ${propTxs.length} proposal txs`,
);

// 4. CBOR.
const all = [...hashes];
const records = [];
for (let i = 0; i < all.length; i += 50) {
  const rows = await post('/tx_cbor', { _tx_hashes: all.slice(i, i + 50) });
  for (const r of rows) {
    const h = Buffer.from(r.tx_hash, 'hex');
    const c = Buffer.from(r.cbor, 'hex');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(c.length);
    records.push(h, len, c);
  }
  process.stdout.write(`\rcbor: ${Math.min(i + 50, all.length)}/${all.length}`);
}
process.stdout.write('\n');
const gz = gzipSync(Buffer.concat(records), { level: 9 });
writeFileSync(
  new URL('../test/fixtures/mainnet-corpus.bin.gz', import.meta.url),
  gz,
);
writeFileSync(
  new URL('../test/fixtures/mainnet-corpus.json', import.meta.url),
  `${JSON.stringify(
    {
      source: 'api.koios.rest tx_cbor',
      fetched: new Date().toISOString().slice(0, 10),
      transactions: records.length / 3,
      recent: RECENT_TARGET,
      oldEpochs: OLD_EPOCHS,
      voteTxs: voteTxs.length,
      proposalTxs: propTxs.length,
      bytesGzipped: gz.length,
    },
    null,
    2,
  )}\n`,
);
console.log(
  `wrote ${records.length / 3} transactions, ${gz.length} bytes gzipped`,
);
