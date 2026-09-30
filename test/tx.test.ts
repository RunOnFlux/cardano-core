import { describe, expect, it } from 'vitest';
import {
  assembleTransaction,
  bytesToHex,
  compareInputs,
  decodeTransaction,
  encodeBody,
  encodeOutput,
  encodeWitnessSet,
  hexToBytes,
  makeValue,
  minAdaForOutput,
  linearFee,
  MAINNET_DEFAULTS,
  referenceScriptFee,
  requiredAda,
  signedSize,
  txIdOfBody,
  txIdOfTransaction,
  encodeCbor,
  encodeValue,
} from '../src/index.js';
import type {
  AssetAmount,
  TxBody,
  TxOutput,
  VkeyWitness,
} from '../src/index.js';
import { big, CSL, hex } from './helpers/csl.js';
import { cases, Rng } from './helpers/random.js';

type CslValue = InstanceType<typeof CSL.Value>;

function randomAssets(rng: Rng, maxPolicies: number): AssetAmount[] {
  const out: AssetAmount[] = [];
  const policies = rng.int(maxPolicies + 1);
  for (let p = 0; p < policies; p++) {
    const policyId = bytesToHex(rng.bytes(28));
    const names = 1 + rng.int(3);
    for (let n = 0; n < names; n++) {
      out.push({
        policyId,
        assetName: bytesToHex(rng.bytes(rng.int(33))),
        quantity: rng.quantity(),
      });
    }
  }
  return out;
}

function cslValue(coin: bigint, assets: readonly AssetAmount[]): CslValue {
  const v = CSL.Value.new(big(coin));
  if (assets.length === 0) return v;
  const ma = CSL.MultiAsset.new();
  for (const a of assets) {
    const policy = CSL.ScriptHash.from_hex(a.policyId);
    const existing = ma.get(policy) ?? CSL.Assets.new();
    const name = CSL.AssetName.new(hexToBytes(a.assetName));
    const prev = existing.get(name);
    existing.insert(
      name,
      prev ? prev.checked_add(big(a.quantity)) : big(a.quantity),
    );
    ma.insert(policy, existing);
  }
  v.set_multiasset(ma);
  return v;
}

function randomAddress(rng: Rng): Uint8Array {
  const kind = rng.int(3);
  const net = 1;
  if (kind === 0) return Uint8Array.of(0x00 | net, ...rng.bytes(56));
  if (kind === 1) return Uint8Array.of(0x60 | net, ...rng.bytes(28));
  return Uint8Array.of(0x10 | net, ...rng.bytes(56));
}

describe('tx: encoding parity with cardano-serialization-lib', () => {
  it('values, outputs and bodies are byte-identical', () => {
    const rng = new Rng(0x7e5);
    for (let i = 0; i < cases(200); i++) {
      const addr = randomAddress(rng);
      const assets = randomAssets(rng, rng.pick([0, 1, 3, 8]));
      const coin = rng.lovelace();
      const value = makeValue(coin, assets);
      const cv = cslValue(coin, assets);
      expect(bytesToHex(encodeCbor(encodeValue(value)))).toBe(
        hex(cv.to_bytes()),
      );

      const output: TxOutput = { address: addr, value, format: 'array' };
      const cOut = CSL.TransactionOutput.new(CSL.Address.from_bytes(addr), cv);
      expect(bytesToHex(encodeOutput(output))).toBe(hex(cOut.to_bytes()));
      expect(minAdaForOutput(output, 4310n)).toBe(
        BigInt(
          CSL.min_ada_for_output(
            cOut,
            CSL.DataCost.new_coins_per_byte(big(4310n)),
          ).to_str(),
        ),
      );

      // body: random inputs (any order), outputs, fee, optional ttl
      const nIn = 1 + rng.int(6);
      const inputs = Array.from({ length: nIn }, () => ({
        txHash: rng.bytes(32),
        index: rng.int(40),
      }));
      const cInputs = CSL.TransactionInputs.new();
      // CSL's builder sorts inputs (the ledger treats them as a set); raw TransactionInputs keeps insertion order.
      for (const inp of [...inputs].sort(compareInputs))
        cInputs.add(
          CSL.TransactionInput.new(
            CSL.TransactionHash.from_bytes(inp.txHash),
            inp.index,
          ),
        );
      const cOuts = CSL.TransactionOutputs.new();
      cOuts.add(cOut);
      const fee = BigInt(rng.range(150_000, 2_000_000));
      const cBody = CSL.TransactionBody.new_tx_body(cInputs, cOuts, big(fee));
      const body: TxBody = { inputs, outputs: [output], fee };
      let ttl: bigint | undefined;
      if (rng.bool()) {
        ttl = BigInt(rng.range(1, 2 ** 31));
        cBody.set_ttl(big(ttl));
      }
      const ours = encodeBody(ttl === undefined ? body : { ...body, ttl });
      expect(bytesToHex(ours)).toBe(hex(cBody.to_bytes()));
      expect(bytesToHex(txIdOfBody(ours))).toBe(
        hex(
          CSL.FixedTransaction.new_from_body_bytes(ours)
            .transaction_hash()
            .to_bytes(),
        ),
      );
    }
  });

  it('witness sets and full transactions are byte-identical', () => {
    const rng = new Rng(0x517);
    for (let i = 0; i < cases(100); i++) {
      const wits: VkeyWitness[] = Array.from(
        { length: 1 + rng.int(3) },
        () => ({
          vkey: rng.bytes(32),
          signature: rng.bytes(64),
        }),
      );
      const cw = CSL.Vkeywitnesses.new();
      for (const w of wits) {
        cw.add(
          CSL.Vkeywitness.new(
            CSL.Vkey.new(CSL.PublicKey.from_bytes(w.vkey)),
            CSL.Ed25519Signature.from_bytes(w.signature),
          ),
        );
      }
      const cws = CSL.TransactionWitnessSet.new();
      cws.set_vkeys(cw);
      expect(bytesToHex(encodeWitnessSet(wits))).toBe(hex(cws.to_bytes()));

      const inputs = [{ txHash: rng.bytes(32), index: rng.int(5) }];
      const output: TxOutput = {
        address: randomAddress(rng),
        value: makeValue(rng.lovelace()),
        format: 'array',
      };
      const bodyBytes = encodeBody({
        inputs,
        outputs: [output],
        fee: 200_000n,
      });
      const tx = assembleTransaction(bodyBytes, encodeWitnessSet(wits));
      const cTx = CSL.Transaction.new(
        CSL.TransactionBody.from_bytes(bodyBytes),
        cws,
        undefined,
      );
      expect(bytesToHex(tx)).toBe(hex(cTx.to_bytes()));
      expect(signedSize(bodyBytes, wits.length)).toBe(tx.length);
      expect(linearFee(tx.length, MAINNET_DEFAULTS)).toBe(
        BigInt(
          CSL.min_fee(cTx, CSL.LinearFee.new(big(44n), big(155381n))).to_str(),
        ),
      );
    }
    expect(bytesToHex(encodeWitnessSet([]))).toBe(
      hex(CSL.TransactionWitnessSet.new().to_bytes()),
    );
  });

  it('map-form outputs with datums and reference scripts decode and re-encode like CSL', () => {
    const rng = new Rng(0xda7);
    for (let i = 0; i < 50; i++) {
      const addr = randomAddress(rng);
      const cv = cslValue(rng.lovelace(), randomAssets(rng, 2));
      const out = CSL.TransactionOutput.new(CSL.Address.from_bytes(addr), cv);
      const choice = rng.int(3);
      if (choice === 0)
        out.set_data_hash(CSL.DataHash.from_bytes(rng.bytes(32)));
      if (choice === 1)
        out.set_plutus_data(
          CSL.PlutusData.new_integer(CSL.BigInt.from_str(String(rng.int(1e6)))),
        );
      if (rng.bool()) {
        out.set_script_ref(
          CSL.ScriptRef.new_native_script(
            CSL.NativeScript.new_timelock_expiry(
              CSL.TimelockExpiry.new_timelockexpiry(big(BigInt(rng.int(1e6)))),
            ),
          ),
        );
      }
      const outBytes = out.to_bytes();
      const body = CSL.TransactionBody.new_tx_body(
        CSL.TransactionInputs.new(),
        (() => {
          const o = CSL.TransactionOutputs.new();
          o.add(out);
          return o;
        })(),
        big(1n),
      );
      const tx = assembleTransaction(body.to_bytes(), encodeWitnessSet([]));
      const d = decodeTransaction(tx);
      const o = d.body.outputs[0]!;
      expect(bytesToHex(o.raw)).toBe(hex(outBytes));
      expect(bytesToHex(encodeOutput(o))).toBe(hex(outBytes));
    }
  });
});

describe('tx: decoding keeps original bytes', () => {
  it('hashes a non-canonical body as sent, like CSL FixedTransaction', () => {
    const addr = hexToBytes('01' + '11'.repeat(56));
    const canonical = encodeBody({
      inputs: [{ txHash: new Uint8Array(32).fill(1), index: 0 }],
      outputs: [
        { address: addr, value: makeValue(2_000_000n), format: 'array' },
      ],
      fee: 42n,
    });
    const hexBody = bytesToHex(canonical);
    expect(hexBody.endsWith('02182a')).toBe(true);
    const nonCanonical = hexToBytes(hexBody.replace(/02182a$/, '021a0000002a'));
    const tx = assembleTransaction(nonCanonical, encodeWitnessSet([]));
    const d = decodeTransaction(tx);
    expect(d.body.fee).toBe(42n);
    expect(bytesToHex(d.bodyBytes)).toBe(bytesToHex(nonCanonical));
    const fixed = CSL.FixedTransaction.from_bytes(tx);
    expect(bytesToHex(d.txId)).toBe(hex(fixed.transaction_hash().to_bytes()));
    expect(bytesToHex(txIdOfTransaction(tx))).toBe(bytesToHex(d.txId));
    expect(bytesToHex(d.txId)).not.toBe(bytesToHex(txIdOfBody(canonical)));
  });

  it('reads Conway fields and keeps unknown keys', () => {
    const txid = '22'.repeat(32);
    // {0: [[txid, 0]], 1: [], 2: 1, 14: [h28], 22: 5, 99: "future"}
    const bodyHex = [
      'a6',
      `00818258 20${txid}00`.replace(' ', ''),
      '0180',
      '0201',
      `0e81581c${'33'.repeat(28)}`,
      '1605',
      '1863',
      '66667574757265',
    ].join('');
    const d = decodeTransaction(hexToBytes(`84${bodyHex}a0f5f6`));
    expect(d.body.requiredSigners.map(bytesToHex)).toEqual(['33'.repeat(28)]);
    expect(d.body.donation).toBe(5n);
    expect(d.body.unknownFields.map((f) => [f.key, bytesToHex(f.raw)])).toEqual(
      [[99n, '66667574757265']],
    );
    expect(d.format).toBe('four-element');
    expect(d.isValid).toBe(true);
  });

  it('refuses duplicate body keys', () => {
    const txid = '22'.repeat(32);
    const bodyHex = `a40081825820${txid}000180020102 03`.replace(' ', '');
    expect(() => decodeTransaction(hexToBytes(`84${bodyHex}a0f5f6`))).toThrow(
      /duplicate/,
    );
  });
});

describe('fees', () => {
  it('reference-script fee follows the ledger tiers', () => {
    const r = { num: 15n, den: 1n };
    expect(referenceScriptFee(0, r)).toBe(0n);
    expect(referenceScriptFee(1000, r)).toBe(15_000n);
    expect(referenceScriptFee(25_600, r)).toBe(384_000n);
    // 25,600 × 15 + 10,000 × 18 = 384,000 + 180,000
    expect(referenceScriptFee(35_600, r)).toBe(564_000n);
    // third tier at 21.6 per byte: 384,000 + 460,800 + 1,000 × 21.6
    expect(referenceScriptFee(52_200, r)).toBe(384_000n + 460_800n + 21_600n);
    // floor once at the end: 15.5 × 3 = 46.5
    expect(referenceScriptFee(3, { num: 31n, den: 2n })).toBe(46n);
  });

  it('requiredAda is coinsPerUtxoByte × (160 + size)', () => {
    const o: TxOutput = {
      address: hexToBytes('61' + '00'.repeat(28)),
      value: makeValue(1_000_000n),
      format: 'array',
    };
    expect(requiredAda(o, 4310n)).toBe(
      4310n * BigInt(160 + encodeOutput(o).length),
    );
  });
});
