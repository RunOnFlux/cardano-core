import { describe, expect, it } from 'vitest';
import {
  addressHex,
  assembleTransaction,
  assessCollateral,
  bytesToHex,
  cArray,
  cBytes,
  cMap,
  coinValue,
  cTag,
  cUint,
  defaultCollateralCap,
  encodeCbor,
  enterpriseAddress,
  decodeTransaction,
  describeTransaction,
  encodeUtxoHex,
  encodeValueHex,
  encodeWitnessSet,
  hexToBytes,
  makeValue,
  parseAddress,
  pickCollateral,
  MAINNET_DEFAULTS,
  requiredSigners,
  resolveDataSigner,
  rewardAddressHex,
  signTxWitnessSet,
  txIdOfBody,
  verifyWitness,
  witnessFor,
} from '../src/index.js';
import type { CborEncodable, Utxo } from '../src/index.js';
import { big, CSL, hex } from './helpers/csl.js';
import { Rng } from './helpers/random.js';
import {
  randomPolicyAssets,
  SNEK,
  testWallet,
  utxo,
  planOwn,
  signTxOwn,
} from './helpers/wallet.js';

/** Every plan needs an expiry slot (or null); tests use a fixed one. */
const TTL = 200_000_000n;

describe('CIP-30 encoders: parity with CSL', () => {
  it('getUtxos / getBalance / addresses', () => {
    const rng = new Rng(0x30);
    for (let i = 0; i < 50; i++) {
      const w = testWallet(rng);
      const u = utxo(
        rng,
        rng.lovelace(),
        rng.bool() ? randomPolicyAssets(rng, 1 + rng.int(4)) : [],
      );
      const value = CSL.Value.new(big(u.value.coin));
      if (u.value.assets.size > 0) {
        const ma = CSL.MultiAsset.new();
        for (const [p, names] of u.value.assets) {
          const a = CSL.Assets.new();
          for (const [n, q] of names)
            a.insert(CSL.AssetName.new(hexToBytes(n)), big(q));
          ma.insert(CSL.ScriptHash.from_hex(p), a);
        }
        value.set_multiasset(ma);
      }
      const ref = CSL.TransactionUnspentOutput.new(
        CSL.TransactionInput.new(
          CSL.TransactionHash.from_hex(u.txHash),
          u.index,
        ),
        CSL.TransactionOutput.new(CSL.Address.from_bech32(w.address), value),
      );
      expect(encodeUtxoHex(u, w.address)).toBe(hex(ref.to_bytes()));
      expect(encodeValueHex(u.value)).toBe(hex(value.to_bytes()));
      expect(addressHex(w.address)).toBe(
        hex(CSL.Address.from_bech32(w.address).to_bytes()),
      );
      const reward = CSL.RewardAddress.new(
        1,
        CSL.Credential.from_keyhash(
          CSL.Ed25519KeyHash.from_bytes(w.stakeKeyHash),
        ),
      ).to_address();
      expect(rewardAddressHex(1, w.stakeKeyHash)).toBe(hex(reward.to_bytes()));
    }
    expect(encodeValueHex(makeValue(0n))).toBe(
      hex(CSL.Value.new(big(0n)).to_bytes()),
    );
  });

  it('pickCollateral takes the first ADA-only UTXO of at least 5 ADA', () => {
    const rng = new Rng(0x31);
    const a = utxo(rng, 4_000_000n);
    const b = utxo(rng, 50_000_000n, [{ ...SNEK, quantity: 1n }]);
    const c = utxo(rng, 6_000_000n);
    const d = utxo(rng, 9_000_000n);
    expect(pickCollateral([a, b, c, d])).toBe(c);
    expect(pickCollateral([a, b])).toBeNull();
  });
});

describe('CIP-30 signTx', () => {
  function dappTx(
    rng: Rng,
    from: string,
    mutate?: (bodyHex: string) => string,
    existing?: Uint8Array,
  ) {
    const w = testWallet(rng);
    const plan = planOwn({
      // no expiry: the fee stays the last body field, which the mutation below relies on
      ttl: null,
      utxos: [utxo(rng, 20_000_000n)],
      to: w.address,
      coin: 3_000_000n,
      changeAddress: from,
      params: MAINNET_DEFAULTS,
    });
    const body = mutate
      ? hexToBytes(mutate(bytesToHex(plan.bodyBytes)))
      : plan.bodyBytes;
    const wits = existing
      ? [
          {
            vkey: existing.subarray(0, 32),
            signature: existing.subarray(32, 96),
          },
        ]
      : [];
    return assembleTransaction(body, encodeWitnessSet(wits));
  }

  it('witnesses the original body bytes like CSL FixedTransaction + make_vkey_witness', async () => {
    const rng = new Rng(0x40);
    const w = testWallet(rng);
    // a dapp encodes the fee non-minimally (8-byte head where 4 bytes suffice)
    const tx = dappTx(rng, w.address, (h) =>
      h.replace(/021a([0-9a-f]{8})$/, (_, f: string) => `021b00000000${f}`),
    );
    const fixed = CSL.FixedTransaction.from_bytes(tx);
    const ours = await signTxOwn(tx, [w.payment]);
    const d = decodeTransaction(tx);
    expect(bytesToHex(d.bodyBytes)).toMatch(/021b00000000[0-9a-f]{8}$/);
    expect(bytesToHex(d.txId)).toBe(hex(fixed.transaction_hash().to_bytes()));
    const ws = CSL.TransactionWitnessSet.from_hex(ours);
    const vk = ws.vkeys()!.get(0);
    expect(
      vk
        .vkey()
        .public_key()
        .verify(fixed.transaction_hash().to_bytes(), vk.signature()),
    ).toBe(true);
    expect(hex(vk.vkey().public_key().as_bytes())).toBe(
      bytesToHex(w.payment.publicKey),
    );
  });

  it('merges verified existing witnesses after ours, without duplicates, dropping bad ones', async () => {
    const rng = new Rng(0x41);
    const w = testWallet(rng);
    const co = testWallet(rng);
    const stranger = testWallet(rng);
    const unsigned = dappTx(rng, w.address);
    const body = decodeTransaction(unsigned).bodyBytes;
    const coWitness = await witnessFor(txIdOfBody(body), co.payment);
    const tx = assembleTransaction(
      body,
      encodeWitnessSet([
        coWitness,
        // a stale signature by our own key and a bogus one by a stranger
        { vkey: w.payment.publicKey, signature: new Uint8Array(64).fill(7) },
        {
          vkey: stranger.payment.publicKey,
          signature: new Uint8Array(64).fill(9),
        },
      ]),
    );
    const merged = decodeTransaction(
      assembleTransaction(
        body,
        hexToBytes(await signTxOwn(tx, [w.payment], { mergeExisting: true })),
      ),
    );
    expect(merged.witnessSet.vkeys.map((v) => bytesToHex(v.vkey))).toEqual([
      bytesToHex(w.payment.publicKey),
      bytesToHex(co.payment.publicKey),
    ]);
    for (const v of merged.witnessSet.vkeys) {
      expect(verifyWitness(merged.txId, v)).toBe(true);
    }
    const partial = decodeTransaction(
      assembleTransaction(
        body,
        hexToBytes(await signTxOwn(tx, [w.payment, w.payment])),
      ),
    );
    expect(partial.witnessSet.vkeys).toHaveLength(1);
  });
});

describe('CIP-30 key choice and required signers', () => {
  it('resolveDataSigner picks the payment or stake key and refuses foreign addresses', () => {
    const rng = new Rng(0x50);
    const w = testWallet(rng);
    const other = testWallet(rng);
    const reward = hexToBytes(rewardAddressHex(1, w.stakeKeyHash));
    const wallet = {
      payment: w.payment,
      stake: w.stake,
      addresses: [w.address, reward],
      network: 1,
    };
    expect(resolveDataSigner(w.address, wallet)).toBe(w.payment);
    expect(resolveDataSigner(reward, wallet)).toBe(w.stake);
    expect(() => resolveDataSigner(other.address, wallet)).toThrow(
      expect.objectContaining({ code: 'ADDRESS_NOT_PK' }),
    );
    expect(() =>
      resolveDataSigner(reward, { payment: w.payment, addresses: [reward] }),
    ).toThrow(expect.objectContaining({ code: 'ADDRESS_NOT_PK' }));
  });

  it('requiredSigners finds our stake key in delegation certificates and withdrawals', () => {
    const rng = new Rng(0x51);
    const w = testWallet(rng);
    const stakeCred = CSL.Credential.from_keyhash(
      CSL.Ed25519KeyHash.from_bytes(w.stakeKeyHash),
    );
    const b = CSL.TransactionBody.new_tx_body(
      CSL.TransactionInputs.new(),
      CSL.TransactionOutputs.new(),
      big(200_000n),
    );
    const certs = CSL.Certificates.new();
    certs.add(
      CSL.Certificate.new_stake_delegation(
        CSL.StakeDelegation.new(
          stakeCred,
          CSL.Ed25519KeyHash.from_bytes(rng.bytes(28)),
        ),
      ),
    );
    b.set_certs(certs);
    const wd = CSL.Withdrawals.new();
    wd.insert(CSL.RewardAddress.new(1, stakeCred), big(1_000_000n));
    b.set_withdrawals(wd);
    const tx = CSL.Transaction.new(
      b,
      CSL.TransactionWitnessSet.new(),
      undefined,
    ).to_bytes();
    const r = requiredSigners(tx, {
      paymentKeyHash: w.paymentKeyHash,
      stakeKeyHash: w.stakeKeyHash,
    });
    expect(r.stake).toBe(true);
    expect(r.reasons).toEqual([
      'certificate stake_delegation (stake)',
      'withdrawal (stake)',
    ]);
    const d = describeTransaction(tx, { addresses: [w.address] });
    expect(d.certificates).toEqual(['stake_delegation']);
    expect(d.withdrawals).toEqual({ own: 1_000_000n, foreign: 0n });
    expect(d.warnings).toContain('withdraws rewards');
    const none = requiredSigners(tx, {
      paymentKeyHash: w.paymentKeyHash,
      stakeKeyHash: testWallet(rng).stakeKeyHash,
    });
    expect(none.stake).toBe(false);
  });

  it('describeTransaction separates own outputs from outflow', () => {
    const rng = new Rng(0x52);
    const w = testWallet(rng);
    const to = testWallet(rng);
    const plan = planOwn({
      ttl: TTL,
      utxos: [utxo(rng, 20_000_000n)],
      to: to.address,
      coin: 3_000_000n,
      changeAddress: w.address,
      params: MAINNET_DEFAULTS,
    });
    const tx = assembleTransaction(plan.bodyBytes, encodeWitnessSet([]));
    const d = describeTransaction(tx, { addresses: [w.address] });
    expect(d.toOthers.coin).toBe(3_000_000n);
    expect(d.outputs.filter((o) => o.own)).toHaveLength(1);
    expect(d.outputs[0]!.address).toBe(to.address);
    expect(d.fee).toBe(plan.fee);
    expect(d.warnings).toEqual([]);
    expect(parseAddress(d.outputs[1]!.address).kind).toBe('base');
  });
});

describe('collateral that cannot be valued: allowUnvalued / allowUnvaluedCollateral', () => {
  const rng = new Rng(0x60);
  const me = testWallet(rng);
  const own = [me.address];
  const ownBytes = parseAddress(me.address).bytes;
  const otherBytes = enterpriseAddress(1, {
    type: 'key',
    hash: rng.bytes(28),
  });
  // A listed UTXO of ours that is not the collateral input.
  const ownUtxo = utxo(rng, 10_000_000n);
  // An own UTXO used as collateral: valued, so the cap applies to it.
  const bigOwn: Utxo = {
    txHash: bytesToHex(rng.bytes(32)),
    index: 0,
    value: coinValue(5_000_000_000n),
  };
  const outpoint = (txHash: Uint8Array, index: number) =>
    cArray([cBytes(txHash), cUint(index)]);
  /**
   * A script-style tx whose collateral input is not among the wallet's UTXOs
   * (dapp-provided, or ours at another address form) unless `collateral` says so.
   */
  const unvaluedTx = (opts: {
    returnTo?: Uint8Array;
    total?: bigint;
    collateral?: Utxo;
  }): Uint8Array => {
    const c = opts.collateral;
    const entries: [CborEncodable, CborEncodable][] = [
      [cUint(0), cTag(258, cArray([outpoint(rng.bytes(32), 0)]))],
      [cUint(1), cArray([cArray([cBytes(otherBytes), cUint(2_000_000n)])])],
      [cUint(2), cUint(250_000n)],
      [
        cUint(13),
        cTag(
          258,
          cArray([
            c
              ? outpoint(hexToBytes(c.txHash), c.index)
              : outpoint(rng.bytes(32), 0),
          ]),
        ),
      ],
    ];
    if (opts.returnTo)
      entries.push([
        cUint(16),
        cArray([cBytes(opts.returnTo), cUint(5_000_000n)]),
      ]);
    if (opts.total !== undefined) entries.push([cUint(17), cUint(opts.total)]);
    return assembleTransaction(encodeCbor(cMap(entries)), encodeWitnessSet([]));
  };
  const assess = (tx: Uint8Array, extra: object) =>
    assessCollateral(decodeTransaction(tx), { ownAddresses: own, ...extra });

  it('accepts collateral it cannot value, with an own return or none, when ownUtxos was given', () => {
    for (const t of [unvaluedTx({ returnTo: ownBytes }), unvaluedTx({})]) {
      for (const ownUtxos of [[ownUtxo], [] as Utxo[]]) {
        const a = assess(t, { ownUtxos, allowUnvalued: true });
        expect(a.atRiskLovelace).toBeNull();
        expect(a.refusal).toBeNull();
        // without the opt-in: refused as before
        expect(assess(t, { ownUtxos }).refusal).toMatch(
          /cannot tell how much collateral is at risk/,
        );
      }
    }
  });

  it('is ignored without ownUtxos (the wallet did not look)', () => {
    const a = assess(unvaluedTx({ returnTo: ownBytes }), {
      allowUnvalued: true,
    });
    expect(a.atRiskLovelace).toBeNull();
    expect(a.refusal).toMatch(/cannot tell how much collateral is at risk/);
  });

  it('keeps the foreign-return refusal', () => {
    const t = unvaluedTx({ returnTo: otherBytes });
    expect(
      assess(t, { ownUtxos: [ownUtxo], allowUnvalued: true }).refusal,
    ).toMatch(/outside this wallet/);
    // a foreign return accepted for dapp collateral stays at 0 at risk
    const a = assess(t, {
      ownUtxos: [ownUtxo],
      allowUnvalued: true,
      allowForeignReturn: true,
    });
    expect(a.atRiskLovelace).toBe(0n);
    expect(a.refusal).toBeNull();
  });

  it('keeps the cap for a stated total and for valued collateral', () => {
    const stated = assess(
      unvaluedTx({ returnTo: ownBytes, total: 30_000_000n }),
      { ownUtxos: [ownUtxo], allowUnvalued: true },
    );
    expect(stated.atRiskLovelace).toBe(30_000_000n);
    expect(stated.refusal).toMatch(/would be lost/);
    const valued = assess(
      unvaluedTx({ returnTo: ownBytes, collateral: bigOwn }),
      { ownUtxos: [ownUtxo, bigOwn], allowUnvalued: true },
    );
    expect(valued.atRiskLovelace).toBe(4_995_000_000n);
    expect(valued.refusal).toMatch(
      new RegExp(
        `would be lost if the scripts fail \\(limit ${defaultCollateralCap()}\\)`,
      ),
    );
  });

  it('signTxWitnessSet signs an unvalued collateral input only with the opt-in and ownUtxos', async () => {
    const raw = unvaluedTx({ returnTo: ownBytes });
    const tx = bytesToHex(raw);
    const opts = { ownAddresses: own, ownUtxos: [ownUtxo] };
    await expect(
      signTxWitnessSet(tx, [me.payment], opts),
    ).rejects.toMatchObject({ code: 'COLLATERAL_AT_RISK' });
    await expect(
      signTxWitnessSet(tx, [me.payment], {
        ownAddresses: own,
        allowUnvaluedCollateral: true,
      }),
    ).rejects.toMatchObject({ code: 'COLLATERAL_AT_RISK' });
    const ws = await signTxWitnessSet(tx, [me.payment], {
      ...opts,
      allowUnvaluedCollateral: true,
    });
    expect(ws).toMatch(/^[0-9a-f]+$/);
    const signed = decodeTransaction(
      assembleTransaction(decodeTransaction(raw).bodyBytes, hexToBytes(ws)),
    );
    expect(signed.witnessSet.vkeys).toHaveLength(1);
    expect(verifyWitness(signed.txId, signed.witnessSet.vkeys[0]!)).toBe(true);
    // the cap and the foreign-return check still hold under the opt-in
    for (const t of [
      unvaluedTx({ returnTo: ownBytes, total: 30_000_000n }),
      unvaluedTx({ returnTo: otherBytes }),
    ]) {
      await expect(
        signTxWitnessSet(t, [me.payment], {
          ...opts,
          allowUnvaluedCollateral: true,
        }),
      ).rejects.toMatchObject({ code: 'COLLATERAL_AT_RISK' });
    }
  });
});
