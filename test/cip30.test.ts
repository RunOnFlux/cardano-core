import { describe, expect, it } from 'vitest';
import {
  addressHex,
  assembleTransaction,
  assessCollateral,
  collateralRisk,
  bytesToHex,
  cArray,
  cBytes,
  cMap,
  coinValue,
  cTag,
  cUint,
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
import type {
  CborEncodable,
  CollateralCheckOptions,
  DescribeOptions,
  Utxo,
  WitnessSetOptions,
} from '../src/index.js';
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

describe('collateral that cannot be valued: allowUnvaluedCollateral with resolvedCollateral', () => {
  const rng = new Rng(0x60);
  const me = testWallet(rng);
  const stranger = testWallet(rng);
  const own = [me.address];
  const ownBytes = parseAddress(me.address).bytes;
  const dappKeyAddr = addressHex(
    enterpriseAddress(1, { type: 'key', hash: rng.bytes(28) }),
  );
  const dappScriptAddr = addressHex(
    enterpriseAddress(1, { type: 'script', hash: rng.bytes(28) }),
  );
  const otherBytes = enterpriseAddress(1, {
    type: 'key',
    hash: rng.bytes(28),
  });
  const byronAddr =
    'Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi';
  // A listed UTXO of ours that is not used as collateral.
  const ownUtxo = utxo(rng, 10_000_000n);
  const outpointOf = (): Utxo => ({
    txHash: bytesToHex(rng.bytes(32)),
    index: 0,
    value: coinValue(0n),
  });
  /** The collateral input, as fetched again from the chain by outpoint. */
  const at = (u: Utxo, address: string, coin: bigint): Utxo => ({
    txHash: u.txHash,
    index: u.index,
    value: coinValue(coin),
    address,
  });
  /** A script-style tx spending `collateral` as collateral (a fresh outpoint by default). */
  const scriptTx = (opts: {
    returnTo?: Uint8Array;
    total?: bigint;
    collateral?: Utxo[];
  }): Uint8Array => {
    const entries: [CborEncodable, CborEncodable][] = [
      [
        cUint(0),
        cTag(258, cArray([cArray([cBytes(rng.bytes(32)), cUint(0)])])),
      ],
      [cUint(1), cArray([cArray([cBytes(otherBytes), cUint(2_000_000n)])])],
      [cUint(2), cUint(250_000n)],
      [
        cUint(13),
        cTag(
          258,
          cArray(
            (opts.collateral ?? [outpointOf()]).map((u) =>
              cArray([cBytes(hexToBytes(u.txHash)), cUint(u.index)]),
            ),
          ),
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

  /** Wallet-level options, as `signTxWitnessSet` takes them. */
  type Wallet = Omit<WitnessSetOptions, 'ownAddresses'> & {
    ownAddresses?: WitnessSetOptions['ownAddresses'];
  };
  const toAssess = (w: Wallet): CollateralCheckOptions => ({
    ownAddresses: w.ownAddresses ?? own,
    ...(w.ownUtxos ? { ownUtxos: w.ownUtxos } : {}),
    ...(w.maxCollateralAtRisk !== undefined
      ? { maxCollateralAtRisk: w.maxCollateralAtRisk }
      : {}),
    ...(w.allowForeignCollateralReturn ? { allowForeignReturn: true } : {}),
    ...(w.allowUnvaluedCollateral ? { allowUnvalued: true } : {}),
    ...(w.resolvedCollateral
      ? { resolvedCollateral: w.resolvedCollateral }
      : {}),
    ...(w.ownKeyHashes ? { ownKeyHashes: w.ownKeyHashes } : {}),
  });
  const toDescribe = (w: Wallet): DescribeOptions => {
    const { ownAddresses, ...rest } = w;
    return { addresses: ownAddresses ?? own, ...rest };
  };
  const sign = (t: Uint8Array, w: Wallet) =>
    signTxWitnessSet(t, [me.payment], {
      ...w,
      ownAddresses: w.ownAddresses ?? own,
    });

  type Outcome = 'ok' | 'retry' | RegExp;
  const CANNOT_TELL = /cannot tell how much collateral is at risk/;
  const CAP = /would be lost if the scripts fail \(limit \d+\)/;

  /**
   * Every entry point that makes the collateral decision, judged on the same
   * case: assessCollateral, collateralRisk, describeTransaction and
   * signTxWitnessSet must agree.
   */
  async function expectEverywhere(
    t: Uint8Array,
    w: Wallet,
    outcome: Outcome,
    atRisk?: bigint | null,
  ) {
    const a = assessCollateral(decodeTransaction(t), toAssess(w));
    if (outcome === 'ok') expect(a.refusal).toBeNull();
    else if (outcome === 'retry') {
      expect(a.refusal).toMatch(/could not be looked up/);
      expect(a.retryable).toBe(true);
    } else expect(a.refusal).toMatch(outcome);
    if (outcome !== 'retry') expect(a.retryable).toBeUndefined();
    if (atRisk !== undefined) expect(a.atRiskLovelace).toBe(atRisk);
    expect(collateralRisk(decodeTransaction(t), toAssess(w))).toBe(a.refusal);
    const d = describeTransaction(t, toDescribe(w));
    expect(d.collateral.refusal).toBe(a.refusal);
    expect(d.collateral.atRiskLovelace).toBe(a.atRiskLovelace);
    expect(d.collateral.retryable).toBe(a.retryable);
    expect(d.collateralAtRisk).toBe(a.atRiskLovelace);
    if (outcome === 'ok') {
      const ws = await sign(t, w);
      const signed = decodeTransaction(
        assembleTransaction(decodeTransaction(t).bodyBytes, hexToBytes(ws)),
      );
      expect(signed.witnessSet.vkeys).toHaveLength(1);
      expect(verifyWitness(signed.txId, signed.witnessSet.vkeys[0]!)).toBe(
        true,
      );
    } else {
      await expect(sign(t, w)).rejects.toMatchObject({
        code:
          outcome === 'retry' ? 'COLLATERAL_UNRESOLVED' : 'COLLATERAL_AT_RISK',
        message: a.refusal,
      });
    }
  }
  const on = { allowUnvaluedCollateral: true } as const;

  it('option off: 0.1.0 behaviour, resolvedCollateral ignored', async () => {
    const c = outpointOf();
    const t = scriptTx({ returnTo: ownBytes, collateral: [c] });
    const resolvedCollateral = [at(c, dappKeyAddr, 5_000_000n)];
    await expectEverywhere(t, { ownUtxos: [ownUtxo] }, CANNOT_TELL, null);
    await expectEverywhere(
      t,
      { ownUtxos: [ownUtxo], resolvedCollateral },
      CANNOT_TELL,
      null,
    );
    expect(
      assessCollateral(decodeTransaction(t), {
        ownAddresses: own,
        ownUtxos: [ownUtxo],
        resolvedCollateral,
        ownKeyHashes: [me.paymentKeyHash],
      }),
    ).toEqual(
      assessCollateral(decodeTransaction(t), {
        ownAddresses: own,
        ownUtxos: [ownUtxo],
      }),
    );
    // a stated total within the cap is still signed without any lookup
    await expectEverywhere(
      scriptTx({ returnTo: ownBytes, total: 2_000_000n }),
      { ownUtxos: [ownUtxo] },
      'ok',
      2_000_000n,
    );
  });

  it('is ignored without ownUtxos (the wallet did not look)', async () => {
    const c = outpointOf();
    await expectEverywhere(
      scriptTx({ returnTo: ownBytes, collateral: [c] }),
      { ...on, resolvedCollateral: [at(c, dappKeyAddr, 5_000_000n)] },
      CANNOT_TELL,
      null,
    );
  });

  it('accepts dapp collateral resolved to an address the wallet cannot spend from', async () => {
    for (const addr of [dappKeyAddr, dappScriptAddr]) {
      for (const ownUtxos of [[ownUtxo], [] as Utxo[]]) {
        const c = outpointOf();
        const w = {
          ...on,
          ownUtxos,
          resolvedCollateral: [at(c, addr, 5_000_000n)],
        };
        await expectEverywhere(
          scriptTx({ returnTo: ownBytes, collateral: [c] }),
          w,
          'ok',
          0n,
        );
        await expectEverywhere(scriptTx({ collateral: [c] }), w, 'ok', 0n);
      }
    }
  });

  it('stale ownUtxos: a wallet input missing from them is valued from the lookup and capped', async () => {
    // our UTXO at another address form (enterprise) or at a listed address, missing from ownUtxos
    for (const addr of [me.enterprise, me.address]) {
      const big = outpointOf();
      await expectEverywhere(
        scriptTx({ returnTo: ownBytes, collateral: [big] }),
        {
          ...on,
          ownUtxos: [ownUtxo],
          resolvedCollateral: [at(big, addr, 5_000_000_000n)],
        },
        CAP,
        4_995_000_000n,
      );
      const small = outpointOf();
      await expectEverywhere(
        scriptTx({ returnTo: ownBytes, collateral: [small] }),
        {
          ...on,
          ownUtxos: [ownUtxo],
          resolvedCollateral: [at(small, addr, 8_000_000n)],
        },
        'ok',
        3_000_000n,
      );
    }
    // a dapp input next to ours adds nothing to what the wallet can lose
    const ours = outpointOf();
    const theirs = outpointOf();
    await expectEverywhere(
      scriptTx({ returnTo: ownBytes, collateral: [ours, theirs] }),
      {
        ...on,
        ownUtxos: [ownUtxo],
        resolvedCollateral: [
          at(ours, me.enterprise, 8_000_000n),
          at(theirs, dappKeyAddr, 900_000_000n),
        ],
      },
      'ok',
      3_000_000n,
    );
  });

  it('stale ownUtxos and no lookup: a retryable refusal (COLLATERAL_UNRESOLVED)', async () => {
    const c = outpointOf();
    const t = scriptTx({ returnTo: ownBytes, collateral: [c] });
    await expectEverywhere(t, { ...on, ownUtxos: [ownUtxo] }, 'retry', null);
    await expectEverywhere(
      t,
      { ...on, ownUtxos: [ownUtxo], resolvedCollateral: [] },
      'retry',
      null,
    );
    // a lookup without the address or the value does not count
    const noAddress: Utxo = {
      txHash: c.txHash,
      index: c.index,
      value: coinValue(5_000_000n),
    };
    await expectEverywhere(
      t,
      { ...on, ownUtxos: [ownUtxo], resolvedCollateral: [noAddress] },
      'retry',
      null,
    );
    // a stated total keeps the rule: every input must still be accounted for
    await expectEverywhere(
      scriptTx({ returnTo: ownBytes, total: 2_000_000n, collateral: [c] }),
      { ...on, ownUtxos: [ownUtxo] },
      'retry',
      2_000_000n,
    );
    // a refusal a retry cannot clear wins: a listed input already over the cap
    const listed: Utxo = { ...outpointOf(), value: coinValue(5_000_000_000n) };
    await expectEverywhere(
      scriptTx({ returnTo: ownBytes, collateral: [listed, c] }),
      { ...on, ownUtxos: [ownUtxo, listed] },
      CAP,
      null,
    );
  });

  it('an ownUtxos entry without a value is refused (wallet-owned and unvalued)', async () => {
    const c = outpointOf();
    const outpointOnly = {
      txHash: c.txHash,
      index: c.index,
    } as unknown as Utxo;
    await expectEverywhere(
      scriptTx({ returnTo: ownBytes, collateral: [c] }),
      {
        ...on,
        ownUtxos: [ownUtxo, outpointOnly],
        resolvedCollateral: [at(c, dappKeyAddr, 5_000_000n)],
      },
      /listed among the wallet's UTXOs without a value/,
      null,
    );
  });

  it('refuses inputs whose spender it cannot tell', async () => {
    const c = outpointOf();
    const t = scriptTx({ returnTo: ownBytes, collateral: [c] });
    await expectEverywhere(
      t,
      {
        ...on,
        ownUtxos: [ownUtxo],
        resolvedCollateral: [at(c, byronAddr, 5_000_000n)],
      },
      /cannot tell whether the wallet can spend collateral input .* \(a byron address\)/,
      null,
    );
    await expectEverywhere(
      t,
      {
        ...on,
        ownUtxos: [ownUtxo],
        resolvedCollateral: [at(c, 'not an address', 5_000_000n)],
      },
      /cannot read the address of collateral input/,
      null,
    );
    await expectEverywhere(
      t,
      {
        ...on,
        ownUtxos: [ownUtxo],
        resolvedCollateral: [
          at(c, dappKeyAddr, 5_000_000n),
          at(c, me.enterprise, 5_000_000n),
        ],
      },
      /resolved twice with different contents/,
      null,
    );
  });

  it('keeps the foreign-return refusal; dapp collateral with allowForeignCollateralReturn needs the lookup too', async () => {
    const c = outpointOf();
    const t = scriptTx({ returnTo: otherBytes, collateral: [c] });
    const dapp = [at(c, dappKeyAddr, 5_000_000n)];
    await expectEverywhere(
      t,
      { ...on, ownUtxos: [ownUtxo], resolvedCollateral: dapp },
      /outside this wallet/,
    );
    const foreign = {
      ...on,
      allowForeignCollateralReturn: true,
      ownUtxos: [ownUtxo],
    };
    await expectEverywhere(
      t,
      { ...foreign, resolvedCollateral: dapp },
      'ok',
      0n,
    );
    await expectEverywhere(t, foreign, 'retry', null);
    await expectEverywhere(
      t,
      { ...foreign, resolvedCollateral: [at(c, me.enterprise, 5_000_000n)] },
      /outside this wallet.*a collateral input is the wallet's own/,
    );
  });

  it('keeps the cap for a stated total', async () => {
    const c = outpointOf();
    await expectEverywhere(
      scriptTx({ returnTo: ownBytes, total: 30_000_000n, collateral: [c] }),
      {
        ...on,
        ownUtxos: [ownUtxo],
        resolvedCollateral: [at(c, dappKeyAddr, 5_000_000n)],
      },
      /30000000 lovelace of collateral would be lost/,
      30_000_000n,
    );
  });

  it('wallet keys: ownAddresses, ownKeyHashes and (when signing) the signers', async () => {
    const c = outpointOf();
    const t = scriptTx({ collateral: [c] });
    const mine = [at(c, me.enterprise, 5_000_000_000n)];
    // the wallet lists another account only: me.enterprise is not its key to judge
    const base = {
      ...on,
      ownAddresses: [stranger.address],
      ownUtxos: [ownUtxo],
      resolvedCollateral: mine,
    };
    expect(
      assessCollateral(decodeTransaction(t), toAssess(base)).refusal,
    ).toBeNull();
    expect(
      describeTransaction(t, toDescribe(base)).collateral.refusal,
    ).toBeNull();
    // ...but the signer is me: signing would authorise spending it, so it is valued and capped
    await expect(sign(t, base)).rejects.toMatchObject({
      code: 'COLLATERAL_AT_RISK',
      message: expect.stringMatching(CAP),
    });
    // ownKeyHashes (bytes or hex) bring assess and describe to the same answer
    for (const h of [me.paymentKeyHash, bytesToHex(me.paymentKeyHash)]) {
      await expectEverywhere(
        t,
        { ...base, ownKeyHashes: [h] },
        CAP,
        5_000_000_000n,
      );
    }
    // no wallet key at all: the option cannot be honoured
    const none = {
      ...on,
      ownAddresses: [],
      ownUtxos: [ownUtxo],
      resolvedCollateral: [at(c, dappKeyAddr, 5_000_000n)],
    };
    expect(
      assessCollateral(decodeTransaction(t), toAssess(none)).refusal,
    ).toMatch(
      /cannot tell whether the wallet can spend collateral input .*: no wallet key hashes/,
    );
    expect(describeTransaction(t, toDescribe(none)).collateral.refusal).toMatch(
      /no wallet key hashes/,
    );
    // a malformed key hash is an input error
    expect(() =>
      assessCollateral(
        decodeTransaction(t),
        toAssess({ ...base, ownKeyHashes: ['abcd'] }),
      ),
    ).toThrow(/28-byte/);
  });
});
