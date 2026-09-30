import { describe, expect, it } from 'vitest';
import {
  addressHex,
  assembleTransaction,
  base58Encode,
  baseAddress,
  bytesToHex,
  CardanoError,
  cArray,
  cBytes,
  cMap,
  cNull,
  coinValue,
  concatBytes,
  cTag,
  cText,
  cUint,
  crc32,
  decodeCbor,
  decodeTransaction,
  derivePublic,
  describeTransaction,
  encodeCbor,
  encodeBody,
  encodeOutput,
  enterpriseAddress,
  linearFee,
  rootKeyFromEntropy,
  signedSize,
  hexToBytes,
  keyBaseAddress,
  localSigner,
  MAINNET_DEFAULTS,
  MIN_COLLATERAL_CAP,
  MAX_DEFAULT_COLLATERAL_CAP,
  defaultCollateralCap,
  maxTransactionFee,
  parseBlockfrostParams,
  parseKoiosParams,
  parseRational,
  makeValue,
  parseAddress,
  parsePaymentAddress,
  planSend,
  pointerAddress,
  requiredAda,
  requiredSigners,
  resolveDataSigner,
  rewardAddress,
  signData,
  signPlan,
  signTxWitnessSet,
  totalInflow,
  totalOutflow,
  verifyData,
  addressToString,
  valueSize,
} from '../src/index.js';
import type { Plan, Utxo, WitnessSetOptions } from '../src/index.js';
import { CSL, hex } from './helpers/csl.js';
import { Rng } from './helpers/random.js';
import {
  randomPolicyAssets,
  testWallet,
  utxo,
  planOwn,
  signOwn,
  signTxOwn,
} from './helpers/wallet.js';

/** Every plan needs an expiry slot (or null); tests use a fixed one. */
const TTL = 200_000_000n;

/**
 * Regressions for the independent review of 2026-09-29 (AUDIT.md §9). Each
 * block ports one of the reviewer's repro scripts.
 */

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof CardanoError) return e.code;
    throw e;
  }
  return 'no error';
}

// CBOR head with a chosen width (0 = inline).
function head(
  major: number,
  n: number | bigint,
  width?: 0 | 1 | 2 | 4 | 8,
): Uint8Array {
  let v = BigInt(n);
  const w =
    width ??
    (v < 24n ? 0 : v < 256n ? 1 : v < 65536n ? 2 : v < 4294967296n ? 4 : 8);
  const m = major << 5;
  if (w === 0) return Uint8Array.of(m | Number(v));
  const out = new Uint8Array(1 + w);
  out[0] = m | ({ 1: 24, 2: 25, 4: 26, 8: 27 } as const)[w];
  for (let i = w; i >= 1; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

describe('review #1 (HIGH): describeTransaction ownership and outflow (repro 07)', () => {
  const rng = new Rng(5);
  const pk = rng.bytes(28);
  const sk = rng.bytes(28);
  const attacker = rng.bytes(28);
  const own = keyBaseAddress(1, pk, sk);
  const ownReward = rewardAddress(1, { type: 'key', hash: sk });
  const franken = keyBaseAddress(1, pk, attacker);
  const ent = enterpriseAddress(1, { type: 'key', hash: pk });
  const attackerReward = rewardAddress(1, { type: 'key', hash: attacker });
  const input = cArray([cBytes(rng.bytes(32)), cUint(0)]);
  const out = (a: Uint8Array, coin: bigint) => cArray([cBytes(a), cUint(coin)]);
  const body = encodeCbor(
    cMap([
      [cUint(0), cTag(258, cArray([input]))],
      [
        cUint(1),
        cArray([
          out(franken, 9_000_000_000n),
          out(ent, 1_000_000_000n),
          out(own, 5_000_000n),
        ]),
      ],
      [cUint(2), cUint(200_000n)],
      [
        cUint(4),
        cTag(
          258,
          cArray([
            // pool registration: our stake key as owner, reward account = attacker, 500 ADA deposit
            cArray([
              cUint(3),
              cBytes(rng.bytes(28)),
              cBytes(rng.bytes(32)),
              cUint(340_000_000n),
              cUint(340_000_000n),
              cTag(30, cArray([cUint(1), cUint(1)])),
              cBytes(attackerReward),
              cTag(258, cArray([cBytes(sk)])),
              cArray([]),
              cNull,
            ]),
            // DRep registration for the attacker's credential: 500 ADA deposit
            cArray([
              cUint(16),
              cArray([cUint(0), cBytes(attacker)]),
              cUint(500_000_000n),
              cNull,
            ]),
          ]),
        ),
      ],
      [cUint(5), cMap([[cBytes(attackerReward), cUint(7_000_000n)]])],
      // proposal: 100,000 ADA deposit returned to the attacker's reward account
      [
        cUint(20),
        cTag(
          258,
          cArray([
            cArray([
              cUint(100_000_000_000n),
              cBytes(attackerReward),
              cArray([cUint(6)]),
              cArray([cText('https://x'), cBytes(new Uint8Array(32))]),
            ]),
          ]),
        ),
      ],
      [cUint(22), cUint(50_000_000n)],
    ]),
  );
  const tx = assembleTransaction(body, encodeCbor(cMap([])));

  it('CSL parses the hostile transaction too', () => {
    expect(() => CSL.Transaction.from_bytes(tx)).not.toThrow();
  });

  it('owns only exact wallet addresses; franken and enterprise forms of our key are outflow', () => {
    const d = describeTransaction(tx, { addresses: [own, ownReward] });
    expect(d.outputs.map((o) => o.own)).toEqual([false, false, true]);
    expect(d.outputs.map((o) => o.ourPaymentKeyForeignAddress)).toEqual([
      true,
      true,
      false,
    ]);
    expect(d.toOthers.coin).toBe(10_000_000_000n);
    expect(
      d.warnings.some((w) => w.includes('payment key but another stake part')),
    ).toBe(true);
  });

  it('counts deposits, proposal deposits and donation in the outflow; withdrawals as inflow', () => {
    const d = describeTransaction(tx, { addresses: [own, ownReward] });
    expect(d.deposits).toBe(MAINNET_DEFAULTS.poolDeposit + 500_000_000n);
    expect(d.proposalDeposits).toBe(100_000_000_000n);
    expect(d.donation).toBe(50_000_000n);
    expect(d.withdrawals).toEqual({ own: 0n, foreign: 7_000_000n });
    expect(totalOutflow(d).coin).toBe(
      10_000_000_000n +
        200_000n +
        500_000_000n +
        500_000_000n +
        100_000_000_000n +
        50_000_000n,
    );
    expect(totalInflow(d)).toBe(7_000_000n);
    expect(d.pools).toHaveLength(1);
    expect(d.pools[0]).toMatch(/^pool1/);
    expect(d.dreps).toEqual([`key:${bytesToHex(attacker)}`]);
    expect(d.foreignRewardAccounts).toEqual([addressToString(attackerReward)]);
    expect(
      d.certificateDetails.map((c) => [
        c.kind,
        c.depositDelta,
        c.ownCredential,
      ]),
    ).toEqual([
      ['pool_registration', MAINNET_DEFAULTS.poolDeposit, false],
      ['reg_drep_cert', 500_000_000n, false],
    ]);
  });

  it('review #8: requiredSigners sees our stake key as a pool owner', () => {
    const r = requiredSigners(tx, { paymentKeyHash: pk, stakeKeyHash: sk });
    expect(r.stake).toBe(true);
    expect(r.reasons).toContain('pool owner (stake)');
  });
});

describe('review #2 and #4: resolveDataSigner (repros 06, 11)', () => {
  const rng = new Rng(21);
  const w = testWallet(rng);
  const reward = rewardAddress(1, { type: 'key', hash: w.stakeKeyHash });
  const wallet = {
    payment: w.payment,
    stake: w.stake,
    addresses: [w.address, reward],
    network: 1,
  };
  const attacker = rng.bytes(28);
  const pk = w.paymentKeyHash;
  const sk = w.stakeKeyHash;

  it('signs only for the wallet’s own addresses on its own network', () => {
    const refused: [string, Uint8Array][] = [
      ['franken (attacker stake key)', keyBaseAddress(1, pk, attacker)],
      [
        'franken (script stake)',
        baseAddress(
          1,
          { type: 'key', hash: pk },
          { type: 'script', hash: attacker },
        ),
      ],
      [
        'our payment key, enterprise',
        enterpriseAddress(1, { type: 'key', hash: pk }),
      ],
      [
        'our payment key, pointer',
        pointerAddress(
          1,
          { type: 'key', hash: pk },
          { slot: 1n, txIndex: 2n, certIndex: 3n },
        ),
      ],
      ['own base on testnet', keyBaseAddress(0, pk, sk)],
      ['own base on network 7', keyBaseAddress(7, pk, sk)],
      ['reward on testnet', rewardAddress(0, { type: 'key', hash: sk })],
      ['attacker payment + our stake key', keyBaseAddress(1, attacker, sk)],
    ];
    for (const [name, a] of refused) {
      expect(
        codeOf(() => resolveDataSigner(a, wallet)),
        name,
      ).toBe('ADDRESS_NOT_PK');
    }
    expect(resolveDataSigner(w.address, wallet)).toBe(w.payment);
    expect(resolveDataSigner(reward, wallet)).toBe(w.stake);
  });

  it('accepts every address form signData accepts (bech32, hex, bytes)', async () => {
    const base = parseAddress(w.address).bytes;
    for (const a of [w.address, bytesToHex(base), base]) {
      expect(resolveDataSigner(a, wallet)).toBe(w.payment);
      await expect(signData(a, 'aa', w.payment)).resolves.toBeDefined();
    }
    expect(resolveDataSigner(bytesToHex(reward), wallet)).toBe(w.stake);
    expect(addressHex(bytesToHex(base))).toBe(bytesToHex(base));
  });

  it('a 0.1.0-style call without an address list refuses instead of crashing', () => {
    const legacy = {
      payment: w.payment,
      stake: w.stake,
    } as unknown as Parameters<typeof resolveDataSigner>[1];
    expect(codeOf(() => resolveDataSigner(w.address, legacy))).toBe(
      'ADDRESS_NOT_PK',
    );
  });
});

describe('review #6: verifyData binds the key to the expected address (repro 06)', () => {
  it('a foreign key "signing for" our address is not valid', async () => {
    const rng = new Rng(22);
    const w = testWallet(rng);
    const other = testWallet(rng);
    const forged = await signData(w.address, 'deadbeef', other.payment);
    const v = verifyData(forged, { address: w.address, payload: 'deadbeef' });
    expect(v.valid).toBe(false);
    expect(v.addressMatchesKey).toBe(false);
    const genuine = await signData(w.address, 'deadbeef', w.payment);
    expect(
      verifyData(genuine, { address: w.address, payload: 'deadbeef' }).valid,
    ).toBe(true);
  });
});

describe('review #3: decoding cost is bounded (repro 02b)', () => {
  function nestedKeyTx(size: number): Uint8Array {
    let k = concatBytes(head(2, size), new Uint8Array(size));
    for (let i = 0; i < 126; i++)
      k = concatBytes(Uint8Array.of(0xa1), k, Uint8Array.of(0x00));
    const body = concatBytes(
      Uint8Array.of(0xa4),
      head(0, 0),
      Uint8Array.of(0x80),
      head(0, 1),
      Uint8Array.of(0x80),
      head(0, 2),
      head(0, 0),
      head(0, 26),
      k,
    );
    return concatBytes(
      Uint8Array.of(0x84),
      body,
      Uint8Array.of(0xa0, 0xf5, 0xf6),
    );
  }

  it('decodeTransaction refuses inputs above 64 KiB before decoding', () => {
    for (const size of [100_000, 1_000_000, 4_000_000]) {
      const t0 = performance.now();
      expect(codeOf(() => decodeTransaction(nestedKeyTx(size)))).toBe(
        'INVALID_CBOR',
      );
      expect(performance.now() - t0).toBeLessThan(500);
    }
  });

  it('generic decoding of deeply nested composite keys is linear', () => {
    let k = concatBytes(head(2, 1_000_000), new Uint8Array(1_000_000));
    for (let i = 0; i < 126; i++)
      k = concatBytes(Uint8Array.of(0xa1), k, Uint8Array.of(0x00));
    const t0 = performance.now();
    decodeCbor(k);
    expect(performance.now() - t0).toBeLessThan(2_000);
  });

  it('many composite keys with colliding fingerprints are still linear and still detected', () => {
    const n = 2000;
    const parts: Uint8Array[] = [head(5, n)];
    for (let i = 0; i < n; i++) {
      const b = new Uint8Array(1000);
      b[500] = i & 0xff;
      b[501] = i >> 8;
      parts.push(Uint8Array.of(0x81), head(2, 1000), b, Uint8Array.of(0x00));
    }
    const t0 = performance.now();
    decodeCbor(concatBytes(...parts));
    expect(performance.now() - t0).toBeLessThan(3_000);
    // and an exact repeat is still a duplicate
    const dup = concatBytes(
      head(5, 2),
      Uint8Array.of(0x81, 0x41, 0x07, 0x00),
      Uint8Array.of(0x81, 0x41, 0x07, 0x01),
    );
    expect(codeOf(() => decodeCbor(dup))).toBe('INVALID_CBOR');
  });
});

describe('review #9: duplicate keys are legal inside Plutus data and metadata (repro 08)', () => {
  const rng = new Rng(9);
  const me = testWallet(rng);
  const body = encodeCbor(
    cMap([
      [
        cUint(0),
        cTag(258, cArray([cArray([cBytes(rng.bytes(32)), cUint(0)])])),
      ],
      [cUint(1), cArray([])],
      [cUint(2), cUint(170000n)],
    ]),
  );
  it('signs a transaction whose Plutus data map repeats a key', async () => {
    const pd = cMap([
      [cUint(1), cUint(2)],
      [cUint(1), cUint(3)],
    ]);
    const tx = assembleTransaction(
      body,
      encodeCbor(cMap([[cUint(4), cTag(258, cArray([pd]))]])),
    );
    expect(() => CSL.Transaction.from_bytes(tx)).not.toThrow();
    await expect(signTxOwn(tx, [me.payment])).resolves.toMatch(/^a1/);
  });
  it('signs a transaction whose nested metadata repeats a key', async () => {
    const aux = encodeCbor(
      cMap([
        [
          cUint(674),
          cMap([
            [cUint(1), cUint(1)],
            [cUint(1), cUint(2)],
          ]),
        ],
      ]),
    );
    const tx = assembleTransaction(body, encodeCbor(cMap([])), {
      auxiliaryData: aux,
    });
    await expect(signTxOwn(tx, [me.payment])).resolves.toMatch(/^a1/);
  });
  it('still refuses duplicates in the maps the wallet interprets', () => {
    const dupBody = concatBytes(
      Uint8Array.of(0xa4),
      hexToBytes('00d9010281825820' + '11'.repeat(32) + '00'),
      Uint8Array.of(0x01, 0x80, 0x02, 0x01, 0x02, 0x02),
    );
    expect(() =>
      decodeTransaction(
        concatBytes(
          Uint8Array.of(0x84),
          dupBody,
          Uint8Array.of(0xa0, 0xf5, 0xf6),
        ),
      ),
    ).toThrow(/transaction body: duplicate map key/);
    // duplicate policy inside an output value
    const policy = '22'.repeat(28);
    const value = hexToBytes(
      `821a001e8480a2581c${policy}a14101015 81c${policy}a1410102`.replace(
        ' ',
        '',
      ),
    );
    const output = concatBytes(
      Uint8Array.of(0x82, 0x58, 0x1d),
      enterpriseAddress(1, { type: 'key', hash: new Uint8Array(28) }),
      value,
    );
    const b2 = concatBytes(
      Uint8Array.of(0xa3),
      hexToBytes('00d9010281825820' + '11'.repeat(32) + '00'),
      Uint8Array.of(0x01, 0x81),
      output,
      Uint8Array.of(0x02, 0x01),
    );
    expect(() =>
      decodeTransaction(
        concatBytes(Uint8Array.of(0x84), b2, Uint8Array.of(0xa0, 0xf5, 0xf6)),
      ),
    ).toThrow(/multiasset: duplicate map key/);
  });
});

describe('review #10: unknown future body keys are refused unless opted in', () => {
  it('signTxWitnessSet refuses keys 23–27, describe warns', async () => {
    const rng = new Rng(10);
    const me = testWallet(rng);
    const body = encodeCbor(
      cMap([
        [
          cUint(0),
          cTag(258, cArray([cArray([cBytes(rng.bytes(32)), cUint(0)])])),
        ],
        [cUint(1), cArray([])],
        [cUint(2), cUint(170000n)],
        [cUint(24), cArray([cUint(1)])],
      ]),
    );
    const tx = assembleTransaction(body, encodeCbor(cMap([])));
    await expect(signTxOwn(tx, [me.payment])).rejects.toMatchObject({
      code: 'UNSUPPORTED',
    });
    await expect(
      signTxOwn(tx, [me.payment], { allowUnknownFields: true }),
    ).resolves.toMatch(/^a1/);
    expect(describeTransaction(tx).warnings).toContain(
      'contains fields this wallet does not understand',
    );
  });
});

describe('review #5: planner scale and splitting (repros 13, 05b, 12)', () => {
  const rng = new Rng(13);
  const me = testWallet(rng);
  const to = testWallet(rng).address;

  it('2,000 small UTXOs: fails fast with TX_TOO_LARGE instead of taking seconds', () => {
    const utxos = Array.from({ length: 2000 }, (_, i) => ({
      ...utxo(rng, 1_500_000n),
      index: i % 5,
    }));
    const t0 = performance.now();
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          utxos,
          to,
          changeAddress: me.address,
          coin: 2_000_000_000n,
          params: MAINNET_DEFAULTS,
        }),
      ),
    ).toBe('TX_TOO_LARGE');
    const plan = planOwn({
      ttl: TTL,
      utxos,
      to,
      changeAddress: me.address,
      coin: 300_000_000n,
      params: MAINNET_DEFAULTS,
    });
    expect(plan.inputs.length).toBeLessThan(300);
    expect(performance.now() - t0).toBeLessThan(3_000);
  });

  it('maxAda and all with 1,000 UTXOs spend what fits and report the rest', async () => {
    const utxos = Array.from({ length: 1000 }, () => utxo(rng, 2_000_000n));
    for (const mode of ['maxAda', 'all'] as const) {
      const t0 = performance.now();
      const plan = planOwn({
        ttl: TTL,
        utxos,
        to,
        changeAddress: me.address,
        mode,
        params: MAINNET_DEFAULTS,
      });
      expect(plan.leftoverUtxos).toBeGreaterThan(0);
      expect(plan.inputs.length + plan.leftoverUtxos).toBe(1000);
      expect(plan.signedSize).toBeLessThanOrEqual(MAINNET_DEFAULTS.maxTxSize);
      expect(performance.now() - t0).toBeLessThan(5_000);
      await expect(signOwn(plan, [me.payment])).resolves.toBeDefined();
    }
  });

  it('all splits a token-heavy recipient value across outputs instead of VALUE_TOO_LARGE', () => {
    const plan = planOwn({
      ttl: TTL,
      utxos: [utxo(rng, 300_000_000n, randomPolicyAssets(rng, 150))],
      to,
      changeAddress: me.address,
      mode: 'all',
      params: MAINNET_DEFAULTS,
    });
    expect(plan.recipients.length).toBeGreaterThan(1);
    expect(plan.change).toHaveLength(0);
    for (const r of plan.recipients)
      expect(valueSize(r.value)).toBeLessThanOrEqual(
        MAINNET_DEFAULTS.maxValueSize,
      );
  });

  it('an asset total above 2^64 − 1 in one output is a typed VALUE_TOO_LARGE', () => {
    const tok = { policyId: '11'.repeat(28), assetName: 'aa' };
    const utxos: Utxo[] = [
      {
        txHash: '1'.repeat(64),
        index: 0,
        value: makeValue(50_000_000n, [{ ...tok, quantity: 2n ** 63n }]),
      },
      {
        txHash: '2'.repeat(64),
        index: 0,
        value: makeValue(50_000_000n, [{ ...tok, quantity: 2n ** 63n }]),
      },
      { txHash: '3'.repeat(64), index: 0, value: coinValue(100_000_000n) },
    ];
    for (const mode of ['maxAda', 'all'] as const) {
      expect(
        codeOf(() =>
          planOwn({
            ttl: TTL,
            utxos,
            to,
            changeAddress: me.address,
            mode,
            params: MAINNET_DEFAULTS,
          }),
        ),
      ).toBe('VALUE_TOO_LARGE');
    }
  });
});

describe('review #7: Byron recipients (repro 04)', () => {
  const rng = new Rng(11);
  function byron(attrs: Uint8Array, type = 0): Uint8Array {
    const payload = concatBytes(
      Uint8Array.of(0x83),
      head(2, 28),
      rng.bytes(28),
      attrs,
      head(0, type),
    );
    return concatBytes(
      Uint8Array.of(0x82),
      head(6, 24),
      head(2, payload.length),
      payload,
      head(0, crc32(payload)),
    );
  }
  it('refuses redeem-type and oversized-attribute Byron addresses as recipients', () => {
    expect(
      codeOf(() =>
        parsePaymentAddress(base58Encode(byron(Uint8Array.of(0xa0), 2)), 1),
      ),
    ).toBe('INVALID_ADDRESS');
    const big = concatBytes(
      Uint8Array.of(0xa1),
      head(0, 1),
      head(2, 90),
      rng.bytes(90),
    );
    expect(codeOf(() => parsePaymentAddress(base58Encode(byron(big)), 1))).toBe(
      'INVALID_ADDRESS',
    );
    expect(
      parsePaymentAddress(base58Encode(byron(Uint8Array.of(0xa0))), 1).kind,
    ).toBe('byron');
  });
  it('treats ANY explicit protocol magic as testnet, like the ledger (review round 2, #2)', () => {
    const magic = concatBytes(
      Uint8Array.of(0xa1),
      head(0, 2),
      head(2, 5),
      head(0, 764824073),
    );
    const a = byron(magic);
    const p = parseAddress(a);
    // The ledger's getNetwork maps any attribute-2 magic to Testnet; CSL disagrees (reports 1),
    // and a mainnet output to this address would be rejected with WrongNetwork.
    expect(p.network).toBe(0);
    expect(p.byronProtocolMagic).toBe(764824073);
    expect(CSL.ByronAddress.from_bytes(a).network_id()).toBe(1);
    expect(codeOf(() => parsePaymentAddress(base58Encode(a), 1))).toBe(
      'WRONG_NETWORK',
    );
  });
});

describe('review #11: signPlan re-verifies the plan', () => {
  const rng = new Rng(12);
  const me = testWallet(rng);
  const other = testWallet(rng);
  const base = (): Plan =>
    planOwn({
      ttl: TTL,
      utxos: [utxo(rng, 20_000_000n)],
      to: other.address,
      coin: 3_000_000n,
      changeAddress: me.address,
      params: MAINNET_DEFAULTS,
    });

  it('refuses a plan whose body bytes were swapped', async () => {
    const a = base();
    const b = base();
    await expect(
      signOwn({ ...a, bodyBytes: b.bodyBytes }, [me.payment]),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });
  });
  it('refuses a plan whose change output was redirected', async () => {
    const a = base();
    const outputs = a.body.outputs.map((o, i) =>
      i === 1 ? { ...o, address: parseAddress(other.address).bytes } : o,
    );
    await expect(
      signOwn({ ...a, body: { ...a.body, outputs } }, [me.payment]),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });
  });
  it('refuses a consistently rebuilt plan whose change pays someone else', async () => {
    const u = utxo(rng, 20_000_000n);
    const a = planOwn({
      ttl: TTL,
      utxos: [u],
      to: other.address,
      coin: 3_000_000n,
      changeAddress: me.address,
      params: MAINNET_DEFAULTS,
    });
    const b = planOwn({
      ttl: TTL,
      utxos: [u],
      to: other.address,
      coin: 3_000_000n,
      changeAddress: other.address,
      params: MAINNET_DEFAULTS,
    });
    const tampered: Plan = {
      ...a,
      body: b.body,
      bodyBytes: b.bodyBytes,
      txId: b.txId,
      txIdHex: b.txIdHex,
      outputs: b.outputs,
      recipient: b.recipient,
      recipients: b.recipients,
      change: b.change,
      fee: b.fee,
      signedSize: b.signedSize,
    };
    await expect(signOwn(tampered, [me.payment])).rejects.toThrow(
      /change output pays the wrong address/,
    );
  });

  it('refuses when the change address is not controlled by a signer', async () => {
    const a = planOwn({
      ttl: TTL,
      utxos: [{ ...utxo(rng, 20_000_000n), address: me.address }],
      to: other.address,
      coin: 3_000_000n,
      changeAddress: other.address,
      params: MAINNET_DEFAULTS,
    });
    await expect(signOwn(a, [me.payment])).rejects.toMatchObject({
      code: 'KEY_MISMATCH',
    });
  });
});

describe('review INFO items', () => {
  it('derivePublic on an invalid point is a typed error', () => {
    const bad = new Uint8Array(64).fill(0xff);
    expect(codeOf(() => derivePublic(bad, 0))).toBe('INVALID_INPUT');
  });
  it('localSigner refuses unclamped 96-byte keys like CSL', () => {
    const unclamped = new Uint8Array(96).fill(0xff);
    expect(() => CSL.Bip32PrivateKey.from_bytes(unclamped)).toThrow();
    expect(codeOf(() => localSigner(unclamped))).toBe('INVALID_INPUT');
  });
  it('map-form outputs keep their form and are priced on it (CSL 14.1.2 rewrites them to array form)', () => {
    const addr = enterpriseAddress(1, {
      type: 'key',
      hash: new Uint8Array(28).fill(1),
    });
    const o = {
      address: addr,
      value: coinValue(2_000_000n),
      format: 'map' as const,
    };
    const ours = encodeOutput(o);
    expect(ours[0]).toBe(0xa2);
    expect(
      hex(CSL.TransactionOutput.from_bytes(ours).to_bytes()).startsWith('82'),
    ).toBe(true);
    expect(requiredAda(o, 4310n)).toBe(4310n * BigInt(160 + ours.length));
  });
  it('hostile input to public entry points only ever throws CardanoError (repro 10)', async () => {
    const rng = new Rng(99);
    const typed = async (f: () => unknown): Promise<void> => {
      try {
        await f();
      } catch (e) {
        expect(e).toBeInstanceOf(CardanoError);
      }
    };
    for (let i = 0; i < 1500; i++) {
      const junk = rng.bytes(rng.int(80));
      const jhex = bytesToHex(junk);
      await typed(() => derivePublic(rng.bytes(64), rng.int(100)));
      await typed(() => decodeTransaction(junk));
      await typed(() =>
        parseAddress(base58Encode(junk.length ? junk : Uint8Array.of(1))),
      );
      await typed(() => verifyData({ signature: jhex, key: jhex }));
      await typed(() => describeTransaction(jhex));
      await typed(() =>
        requiredSigners(jhex, { paymentKeyHash: rng.bytes(28) }),
      );
    }
    await typed(() => parseAddress(123 as unknown as string));
    await typed(() =>
      makeValue(1n, [
        {
          policyId: '11'.repeat(28),
          assetName: '',
          quantity: 5 as unknown as bigint,
        },
      ]),
    );
    await typed(() =>
      planOwn({
        ttl: TTL,
        utxos: [utxo(rng, 10_000_000n)],
        to: testWallet(rng).address,
        changeAddress: testWallet(rng).address,
        coin: 2000000 as unknown as bigint,
        params: MAINNET_DEFAULTS,
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// Second review round (2026-09-30), AUDIT.md §9.2
// ---------------------------------------------------------------------------

describe('review 2 #1 (HIGH) and review 3 #1: collateral theft and destruction (repros v2/07, v3/19)', () => {
  const rng = new Rng(5);
  const me = testWallet(rng);
  const attacker = rng.bytes(28);
  const attackerAddr = enterpriseAddress(1, { type: 'key', hash: attacker });
  const ownReward = rewardAddress(1, { type: 'key', hash: me.stakeKeyHash });
  const own = [me.address, ownReward];
  // A 5,000 ADA UTXO of ours, used as collateral.
  const ownUtxo: Utxo = {
    txHash: bytesToHex(rng.bytes(32)),
    index: 0,
    value: coinValue(5_000_000_000n),
    address: me.address,
  };
  const unlisted: Utxo = {
    txHash: bytesToHex(rng.bytes(32)),
    index: 3,
    value: coinValue(5_000_000_000n),
  };
  const inp = (u: Utxo) =>
    cArray([cBytes(hexToBytes(u.txHash)), cUint(u.index)]);
  const out = (a: Uint8Array | string, coin: bigint) =>
    cArray([
      cBytes(typeof a === 'string' ? parseAddress(a).bytes : a),
      cUint(coin),
    ]);
  function tx(opts: {
    collateral?: Utxo[];
    ret?: [Uint8Array | string, bigint];
    total?: bigint;
    isValid?: boolean;
    fee?: bigint;
  }): Uint8Array {
    const entries: [ReturnType<typeof cUint>, ReturnType<typeof cUint>][] = [
      [
        cUint(0),
        cTag(258, cArray([cArray([cBytes(rng.bytes(32)), cUint(0)])])),
      ],
      [cUint(1), cArray([out(me.address, 2_000_000n)])],
      [cUint(2), cUint(opts.fee ?? 300_000n)],
      [cUint(11), cBytes(rng.bytes(32))],
      [cUint(13), cTag(258, cArray((opts.collateral ?? [ownUtxo]).map(inp)))],
    ];
    if (opts.ret) entries.push([cUint(16), out(opts.ret[0], opts.ret[1])]);
    if (opts.total !== undefined) entries.push([cUint(17), cUint(opts.total)]);
    return assembleTransaction(
      encodeCbor(cMap(entries)),
      encodeCbor(cMap([[cUint(5), cArray([])]])),
      {
        isValid: opts.isValid ?? true,
      },
    );
  }
  const sign = (t: Uint8Array, extra: Partial<WitnessSetOptions> = {}) =>
    signTxWitnessSet(t, [me.payment], { ownAddresses: own, ...extra });

  it('a foreign return is refused and every collateral input counted at risk, whatever is_valid says', async () => {
    const t = tx({ ret: [attackerAddr, 4_999_000_000n], total: 450_000n });
    const flipped = tx({
      ret: [attackerAddr, 4_999_000_000n],
      total: 450_000n,
      isValid: false,
    });
    expect(decodeTransaction(t).body.collateral).toHaveLength(1);
    for (const x of [t, flipped]) {
      const d = describeTransaction(x, { addresses: own, ownUtxos: [ownUtxo] });
      expect(d.collateral.returnIsOwn).toBe(false);
      expect(d.collateralAtRisk).toBe(5_000_000_000n); // the whole input, not total_collateral
      expect(
        d.warnings.some((w) =>
          w.startsWith('COLLATERAL RETURN PAYS SOMEONE ELSE'),
        ),
      ).toBe(true);
      expect(totalOutflow(d).coin).toBe(300_000n); // the valid path is unchanged; collateral is separate
      await expect(sign(x, { ownUtxos: [ownUtxo] })).rejects.toMatchObject({
        code: 'COLLATERAL_AT_RISK',
      });
    }
    // unknown value without ownUtxos
    expect(
      describeTransaction(t, { addresses: own }).collateralAtRisk,
    ).toBeNull();
    // look-alike (franken) return: foreign too
    const franken = keyBaseAddress(1, me.paymentKeyHash, attacker);
    const f = tx({ ret: [franken, 4_999_000_000n] });
    expect(
      describeTransaction(f, { addresses: own }).collateral.return
        ?.ourPaymentKeyForeignAddress,
    ).toBe(true);
    await expect(sign(f, { ownUtxos: [ownUtxo] })).rejects.toMatchObject({
      code: 'COLLATERAL_AT_RISK',
    });
    // the opt-in covers dapp-provided collateral only (review 4 #3)
    await expect(
      sign(t, { allowForeignCollateralReturn: true, ownUtxos: [ownUtxo] }),
    ).rejects.toThrow(/a collateral input is the wallet's own/);
    await expect(
      sign(t, { allowForeignCollateralReturn: true }),
    ).rejects.toThrow(/without ownUtxos/);
  });

  it('an own return with total_collateral within the cap is signed and headlined with its amount', async () => {
    const t = tx({ ret: [me.address, 4_999_550_000n], total: 450_000n });
    const d = describeTransaction(t, { addresses: own });
    expect(d.collateralAtRisk).toBe(450_000n);
    expect(d.collateral.cap).toBe(defaultCollateralCap(MAINNET_DEFAULTS));
    expect(d.warnings).toContain(
      '450000 lovelace of collateral at risk if the scripts fail (the dapp decides that after signing)',
    );
    await expect(sign(t)).resolves.toMatch(/^a1/);
    // without the wallet's addresses the return is not recognised as ours
    await expect(
      signTxWitnessSet(t, [me.payment], { ownAddresses: [] }),
    ).rejects.toMatchObject({ code: 'COLLATERAL_AT_RISK' });
  });

  it('review 3: an own return carrying almost nothing is refused (griefing)', async () => {
    // (a) total_collateral states the loss: 4,999 ADA > cap
    const stated = tx({ ret: [me.address, 1_000_000n], total: 4_999_000_000n });
    expect(
      describeTransaction(stated, { addresses: own }).collateralAtRisk,
    ).toBe(4_999_000_000n);
    expect(describeTransaction(stated, { addresses: own }).warnings).toContain(
      '4999000000 lovelace of collateral at risk if the scripts fail (the dapp decides that after signing)',
    );
    await expect(sign(stated)).rejects.toThrow(
      /4999000000 lovelace of collateral would be lost/,
    );
    // (b) no total: valued from ownUtxos (5,000 ADA in, 1 ADA back)
    const unstated = tx({ ret: [me.address, 1_000_000n] });
    expect(
      describeTransaction(unstated, { addresses: own, ownUtxos: [ownUtxo] })
        .collateralAtRisk,
    ).toBe(4_999_000_000n);
    await expect(sign(unstated, { ownUtxos: [ownUtxo] })).rejects.toMatchObject(
      { code: 'COLLATERAL_AT_RISK' },
    );
    // (c) no total and an input the wallet cannot value: refused
    await expect(sign(unstated)).rejects.toThrow(
      /cannot tell how much collateral is at risk/,
    );
    // (d) the caller can raise the cap on purpose
    await expect(
      sign(stated, { maxCollateralAtRisk: 5_000_000_000n }),
    ).resolves.toMatch(/^a1/);
    // (e) an honest own return: 5,000 ADA in, 4,995 ADA back, no total, all valued: 5 ADA at risk = cap
    await expect(
      sign(tx({ ret: [me.address, 4_995_000_000n] }), { ownUtxos: [ownUtxo] }),
    ).resolves.toMatch(/^a1/);
  });

  it('review 3: no return is refused unless total_collateral is stated and within the cap', async () => {
    // never relies on ownUtxos being complete
    for (const extra of [
      {},
      { ownUtxos: [ownUtxo] },
      { ownUtxos: [] as Utxo[] },
    ]) {
      await expect(
        sign(tx({ collateral: [unlisted] }), extra),
      ).rejects.toMatchObject({ code: 'COLLATERAL_AT_RISK' });
      await expect(sign(tx({}), extra)).rejects.toMatchObject({
        code: 'COLLATERAL_AT_RISK',
      });
    }
    // a small stated total without a return (the input holds exactly that much): fine
    const small: Utxo = { ...unlisted, value: coinValue(4_000_000n) };
    await expect(
      sign(tx({ collateral: [small], total: 4_000_000n })),
    ).resolves.toMatch(/^a1/);
    await expect(
      sign(tx({ collateral: [ownUtxo], total: 5_000_000_000n })),
    ).rejects.toMatchObject({ code: 'COLLATERAL_AT_RISK' });
  });

  // -------------------------------------------------------------------------
  // Fourth review round (2026-09-30), AUDIT.md §9.4
  // -------------------------------------------------------------------------

  it('review 4 #1: the default cap comes from the protocol parameters, not the fee', async () => {
    // Largest fee a valid mainnet tx can need: 16,384 B × 44 + 155,381 +
    // 16.5M mem × 0.0577 + 10G steps × 0.0000721 + 200 KiB of reference scripts.
    expect(maxTransactionFee(MAINNET_DEFAULTS)).toBe(8_884_975n);
    expect(defaultCollateralCap(MAINNET_DEFAULTS)).toBe(13_327_463n);
    expect(defaultCollateralCap()).toBe(13_327_463n);
    // The dapp names a 1,700 ADA fee (paid from its own inputs, never spent when
    // it flips is_valid) so that 3 × fee would allow 4,999 ADA of our collateral.
    const inflated = tx({
      fee: 1_700_000_000n,
      ret: [me.address, 1_000_000n],
      total: 4_999_000_000n,
    });
    const d = describeTransaction(inflated, { addresses: own });
    expect(d.collateral.cap).toBe(13_327_463n);
    await expect(sign(inflated)).rejects.toThrow(
      /4999000000 lovelace of collateral would be lost if the scripts fail \(limit 13327463\)/,
    );
    // Just under / over the default cap
    const at = (total: bigint) =>
      tx({ ret: [me.address, 5_000_000_000n - total], total });
    await expect(sign(at(13_327_463n))).resolves.toMatch(/^a1/);
    await expect(sign(at(13_327_464n))).rejects.toMatchObject({
      code: 'COLLATERAL_AT_RISK',
    });
    // Other parameters move the cap; it never drops below 5 ADA
    const pricey = { ...MAINNET_DEFAULTS, minFeeA: 100n };
    expect(defaultCollateralCap(pricey)).toBe(
      (maxTransactionFee(pricey) * 3n + 1n) / 2n,
    );
    expect(
      describeTransaction(inflated, {
        addresses: own,
        params: { minFeeA: 100n },
      }).collateral.cap,
    ).toBe(defaultCollateralCap(pricey));
    const cheap = {
      ...MAINNET_DEFAULTS,
      minFeeA: 1n,
      minFeeB: 0n,
      maxTxSize: 1_024,
      priceMem: { num: 0n, den: 1n },
      priceStep: { num: 0n, den: 1n },
      minFeeRefScriptCostPerByte: { num: 0n, den: 1n },
    };
    expect(defaultCollateralCap(cheap)).toBe(MIN_COLLATERAL_CAP);
    await expect(sign(at(6_000_000n), { params: cheap })).rejects.toMatchObject(
      { code: 'COLLATERAL_AT_RISK' },
    );
    // parameters outside the bounds are refused, not trusted
    await expect(
      sign(at(1_000_000n), {
        params: { ...MAINNET_DEFAULTS, priceMem: { num: 1n, den: 0n } },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_PARAMS' });
    await expect(
      sign(at(1_000_000n), {
        params: { ...MAINNET_DEFAULTS, maxTxExSteps: 10n ** 14n },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_PARAMS' });
    // maxCollateralAtRisk stays the explicit override
    await expect(
      sign(inflated, { maxCollateralAtRisk: 4_999_000_000n }),
    ).resolves.toMatch(/^a1/);
  });

  it('review 4 #2: old-style collateral (no return, no total) is signed when valued within the cap', async () => {
    const five: Utxo = {
      txHash: bytesToHex(rng.bytes(32)),
      index: 1,
      value: coinValue(5_000_000n),
      address: me.address,
    };
    const old = tx({ collateral: [five] });
    const d = describeTransaction(old, { addresses: own, ownUtxos: [five] });
    expect(d.collateralAtRisk).toBe(5_000_000n);
    expect(d.collateral.refusal).toBeNull();
    await expect(sign(old, { ownUtxos: [five] })).resolves.toMatch(/^a1/);
    // still refused when it cannot be valued or exceeds the cap
    await expect(sign(old)).rejects.toThrow(
      /cannot tell how much collateral is at risk/,
    );
    await expect(sign(old, { ownUtxos: [ownUtxo] })).rejects.toThrow(
      /cannot tell how much collateral is at risk/,
    );
    await expect(sign(tx({}), { ownUtxos: [ownUtxo] })).rejects.toThrow(
      /5000000000 lovelace of collateral would be lost/,
    );
    // several own inputs are summed
    const eight: Utxo = { ...five, index: 2, value: coinValue(8_000_000n) };
    await expect(
      sign(tx({ collateral: [five, eight] }), { ownUtxos: [five, eight] }),
    ).resolves.toMatch(/^a1/);
    const nine: Utxo = { ...five, index: 4, value: coinValue(9_000_000n) };
    await expect(
      sign(tx({ collateral: [five, nine] }), { ownUtxos: [five, nine] }),
    ).rejects.toThrow(/14000000 lovelace of collateral would be lost/);
  });

  it('review 4 #3: allowForeignCollateralReturn skips only the foreign-return rule, for dapp collateral', async () => {
    // Dapp-provided collateral (not among ownUtxos) returned to the dapp: signed.
    const dappCollateral = tx({
      collateral: [unlisted],
      ret: [attackerAddr, 4_999_550_000n],
      total: 450_000n,
    });
    await expect(
      sign(dappCollateral, { ownUtxos: [ownUtxo] }),
    ).rejects.toMatchObject({ code: 'COLLATERAL_AT_RISK' });
    await expect(
      sign(dappCollateral, {
        ownUtxos: [ownUtxo],
        allowForeignCollateralReturn: true,
      }),
    ).resolves.toMatch(/^a1/);
    // Mixed: one of the inputs is ours → refused
    await expect(
      sign(
        tx({
          collateral: [unlisted, ownUtxo],
          ret: [attackerAddr, 9_999_550_000n],
          total: 450_000n,
        }),
        { ownUtxos: [ownUtxo], allowForeignCollateralReturn: true },
      ),
    ).rejects.toThrow(/a collateral input is the wallet's own/);
    // The cap stays in force: griefing with an own return is refused
    const griefing = tx({
      ret: [me.address, 1_000_000n],
      total: 4_999_000_000n,
    });
    await expect(
      sign(griefing, {
        ownUtxos: [ownUtxo],
        allowForeignCollateralReturn: true,
      }),
    ).rejects.toThrow(/4999000000 lovelace of collateral would be lost/);
    // …and so is old-style collateral the wallet cannot value
    await expect(
      sign(tx({ collateral: [unlisted] }), {
        ownUtxos: [ownUtxo],
        allowForeignCollateralReturn: true,
      }),
    ).rejects.toThrow(/cannot tell how much collateral is at risk/);
  });

  // -------------------------------------------------------------------------
  // Fifth review round (2026-09-30), AUDIT.md §9.5
  // -------------------------------------------------------------------------

  it('review 5 #1: parameters within the bounds cannot lift the default cap above 25 ADA (repros v5/26, 26b, 27)', async () => {
    const mainnetJson = {
      min_fee_a: 44,
      min_fee_b: 155381,
      coins_per_utxo_size: '4310',
      max_tx_size: 16384,
      max_val_size: '5000',
      min_fee_ref_script_cost_per_byte: 15,
      key_deposit: '2000000',
      pool_deposit: '500000000',
      price_mem: 0.0577,
      price_step: 0.0000721,
      max_tx_ex_mem: '16500000',
      max_tx_ex_steps: '10000000000',
    };
    expect(MAX_DEFAULT_COLLATERAL_CAP).toBe(25_000_000n);
    expect(defaultCollateralCap(parseBlockfrostParams(mainnetJson))).toBe(
      13_327_463n,
    );
    // each field at its bound (previously 81 … 15,012 ADA), then all of them
    // (previously ~15.2M ADA)
    const atBound: Record<string, unknown> = {
      min_fee_a: 1000,
      min_fee_b: 10_000_000,
      max_tx_size: 1 << 20,
      min_fee_ref_script_cost_per_byte: 10_000,
      price_mem: 10,
      price_step: 1,
      max_tx_ex_mem: '10000000000',
      max_tx_ex_steps: '10000000000000',
    };
    for (const [k, v] of Object.entries(atBound)) {
      const p = parseBlockfrostParams({ ...mainnetJson, [k]: v });
      // unclamped, 1.5 × the bound would exceed the ceiling
      expect((maxTransactionFee(p) * 3n) / 2n).toBeGreaterThan(
        MAX_DEFAULT_COLLATERAL_CAP,
      );
      expect(defaultCollateralCap(p)).toBe(MAX_DEFAULT_COLLATERAL_CAP);
    }
    const worst = parseBlockfrostParams({ ...mainnetJson, ...atBound });
    expect(maxTransactionFee(worst)).toBeGreaterThan(10n ** 13n);
    expect(defaultCollateralCap(worst)).toBe(MAX_DEFAULT_COLLATERAL_CAP);
    // griefing (a) with a lying backend's price_step = 1: refused at 25 ADA
    const liar = parseBlockfrostParams({ ...mainnetJson, price_step: 1 });
    const griefing = tx({
      ret: [me.address, 1_000_000n],
      total: 4_999_000_000n,
    });
    expect(
      describeTransaction(griefing, { addresses: own, params: liar }).collateral
        .cap,
    ).toBe(25_000_000n);
    await expect(
      sign(griefing, { ownUtxos: [ownUtxo], params: liar }),
    ).rejects.toThrow(
      /4999000000 lovelace of collateral would be lost if the scripts fail \(limit 25000000\)/,
    );
    const at = (total: bigint) =>
      tx({ ret: [me.address, 5_000_000_000n - total], total });
    await expect(sign(at(25_000_000n), { params: worst })).resolves.toMatch(
      /^a1/,
    );
    await expect(
      sign(at(25_000_001n), { params: worst }),
    ).rejects.toMatchObject({ code: 'COLLATERAL_AT_RISK' });
    // the explicit override is not clamped
    await expect(
      sign(griefing, { params: worst, maxCollateralAtRisk: 4_999_000_000n }),
    ).resolves.toMatch(/^a1/);
  });

  it('review 5 #2: allowForeignCollateralReturn is refused when ownUtxos is empty (repro v5/27)', async () => {
    // e.g. a failed UTXO fetch: our 5,000 ADA UTXO as collateral, return to the attacker
    const theft = tx({ ret: [attackerAddr, 4_999_550_000n] });
    await expect(
      sign(theft, { ownUtxos: [], allowForeignCollateralReturn: true }),
    ).rejects.toThrow(
      /collateral return pays an address outside this wallet.*ownUtxos is empty/,
    );
    const dappCollateral = tx({
      collateral: [unlisted],
      ret: [attackerAddr, 4_999_550_000n],
      total: 450_000n,
    });
    await expect(
      sign(dappCollateral, {
        ownUtxos: [],
        allowForeignCollateralReturn: true,
      }),
    ).rejects.toMatchObject({ code: 'COLLATERAL_AT_RISK' });
    // a non-empty list still lets dapp-provided collateral through
    await expect(
      sign(dappCollateral, {
        ownUtxos: [ownUtxo],
        allowForeignCollateralReturn: true,
      }),
    ).resolves.toMatch(/^a1/);
  });
});

describe('review 2 #2: Byron attribute size is measured like the ledger (repro v2/04)', () => {
  const rng = new Rng(44);
  function byron(attrs: Uint8Array): Uint8Array {
    const payload = concatBytes(
      Uint8Array.of(0x83),
      head(2, 28),
      rng.bytes(28),
      attrs,
      head(0, 0),
    );
    return concatBytes(
      Uint8Array.of(0x82),
      head(6, 24),
      head(2, payload.length),
      payload,
      head(0, crc32(payload)),
    );
  }
  const hdAttr = (n: number): Uint8Array => {
    const inner = concatBytes(head(2, n), rng.bytes(n)); // attribute 1 = CBOR bytes(HD payload)
    return concatBytes(
      Uint8Array.of(0xa1),
      head(0, 1),
      head(2, inner.length),
      inner,
    );
  };
  it('accepts an HD payload up to 64 bytes and refuses 65', () => {
    expect(parsePaymentAddress(base58Encode(byron(hdAttr(60))), 1).kind).toBe(
      'byron',
    );
    expect(
      parsePaymentAddress(base58Encode(byron(hdAttr(64))), 1)
        .byronAttributesSize,
    ).toBe(64);
    expect(
      codeOf(() => parsePaymentAddress(base58Encode(byron(hdAttr(65))), 1)),
    ).toBe('INVALID_ADDRESS');
  });
  it('refuses an attribute 1 that is not a CBOR byte string (the ledger cannot decode it)', () => {
    const raw = concatBytes(
      Uint8Array.of(0xa1),
      head(0, 1),
      head(2, 40),
      rng.bytes(40),
    );
    expect(codeOf(() => parsePaymentAddress(base58Encode(byron(raw)), 1))).toBe(
      'INVALID_ADDRESS',
    );
  });
});

describe('review 2 #3: upper-case tx hashes (repro v2/14)', () => {
  it('plans and signs, and de-duplicates the same outpoint given in two cases', async () => {
    const rng = new Rng(8);
    const me = testWallet(rng);
    const u: Utxo = {
      txHash: bytesToHex(rng.bytes(32)).toUpperCase(),
      index: 0,
      value: coinValue(50_000_000n),
      address: me.address,
    };
    const plan = planOwn({
      ttl: TTL,
      utxos: [u],
      to: testWallet(rng).address,
      coin: 5_000_000n,
      changeAddress: me.address,
      params: MAINNET_DEFAULTS,
    });
    expect(plan.inputs[0]!.txHash).toBe(u.txHash.toLowerCase());
    await expect(signOwn(plan, [me.payment])).resolves.toBeDefined();
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          utxos: [u, { ...u, txHash: u.txHash.toLowerCase() }],
          to: testWallet(rng).address,
          coin: 60_000_000n,
          changeAddress: me.address,
          params: MAINNET_DEFAULTS,
        }),
      ),
    ).toBe('INSUFFICIENT_FUNDS');
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          utxos: [{ ...u, txHash: 'zz' }],
          to: me.address,
          coin: 2_000_000n,
          changeAddress: me.address,
          params: MAINNET_DEFAULTS,
        }),
      ),
    ).toBe('INVALID_INPUT');
  });
});

describe('review 2 #4: change address and fee ceiling are the wallet’s, not the plan’s (repro v2/14)', () => {
  const rng = new Rng(9);
  const me = testWallet(rng);
  const to = testWallet(rng).address;
  const franken = addressToString(
    keyBaseAddress(1, me.paymentKeyHash, rng.bytes(28)),
  );
  const utxos: Utxo[] = [{ ...utxo(rng, 50_000_000n), address: me.address }];
  const base = {
    ttl: TTL,
    utxos,
    to,
    coin: 5_000_000n,
    params: MAINNET_DEFAULTS,
  };

  it('planSend refuses a franken or enterprise change address when given the wallet’s addresses', () => {
    for (const changeAddress of [franken, me.enterprise]) {
      expect(
        codeOf(() =>
          planOwn({ ...base, changeAddress, ownAddresses: [me.address] }),
        ),
      ).toBe('CHANGE_ADDRESS_NOT_OWN');
    }
    expect(
      planOwn({
        ...base,
        changeAddress: me.address,
        ownAddresses: [me.address],
      }).change,
    ).toHaveLength(1);
  });

  it('signPlan enforces the expected change address, the wallet’s address list and its own fee ceiling', async () => {
    const frankenPlan = planOwn({ ...base, changeAddress: franken });
    await expect(
      signOwn(frankenPlan, [me.payment], {
        expectedChangeAddress: me.address,
      }),
    ).rejects.toMatchObject({
      code: 'CHANGE_ADDRESS_NOT_OWN',
    });
    await expect(
      signOwn(frankenPlan, [me.payment], { ownAddresses: [me.address] }),
    ).rejects.toMatchObject({
      code: 'CHANGE_ADDRESS_NOT_OWN',
    });
    const plan = planOwn({ ...base, changeAddress: me.address });
    await expect(
      signOwn({ ...plan, maxFee: 10n ** 12n }, [me.payment], {
        maxFee: plan.fee - 1n,
      }),
    ).rejects.toMatchObject({
      code: 'FEE_TOO_HIGH',
    });
    await expect(
      signOwn(plan, [me.payment], {
        expectedChangeAddress: me.address,
        ownAddresses: [me.address],
        maxFee: 1_000_000n,
      }),
    ).resolves.toBeDefined();
  });
});

describe('review 2 #5: unknown certificate kinds are refused like unknown fields (repro v2/17)', () => {
  it('describes, warns and refuses to sign unless allowUnknownFields', async () => {
    const rng = new Rng(17);
    const me = testWallet(rng);
    const body = encodeCbor(
      cMap([
        [
          cUint(0),
          cTag(258, cArray([cArray([cBytes(rng.bytes(32)), cUint(0)])])),
        ],
        [cUint(1), cArray([])],
        [cUint(2), cUint(200000n)],
        [
          cUint(4),
          cTag(
            258,
            cArray([
              cArray([
                cUint(19),
                cArray([cUint(0), cBytes(rng.bytes(28))]),
                cUint(1_000_000_000_000n),
              ]),
            ]),
          ),
        ],
      ]),
    );
    const tx = assembleTransaction(body, encodeCbor(cMap([])));
    const d = describeTransaction(tx);
    expect(d.unknownCertificates).toBe(1);
    expect(d.warnings).toContain(
      'contains certificates this wallet does not understand or Conway does not accept (their deposits are not counted)',
    );
    await expect(signTxOwn(tx, [me.payment])).rejects.toMatchObject({
      code: 'UNSUPPORTED',
    });
    await expect(
      signTxOwn(tx, [me.payment], { allowUnknownFields: true }),
    ).resolves.toMatch(/^a1/);
  });
});

describe('review 2 #6: amount mode falls back to the richest inputs (repro v2/16)', () => {
  it('sends 800 ADA from one large token-bearing UTXO instead of TX_TOO_LARGE', async () => {
    const rng = new Rng(16);
    const me = testWallet(rng);
    const small = Array.from({ length: 1000 }, () => ({
      ...utxo(rng, 1_200_000n),
      address: me.address,
    }));
    const token = {
      policyId: bytesToHex(rng.bytes(28)),
      assetName: '',
      quantity: 1n,
    };
    const big: Utxo = {
      ...utxo(rng, 5_000_000_000n, [token]),
      address: me.address,
    };
    const plan = planOwn({
      ttl: TTL,
      utxos: [...small, big],
      to: testWallet(rng).address,
      coin: 800_000_000n,
      changeAddress: me.address,
      params: MAINNET_DEFAULTS,
    });
    expect(plan.inputs.length).toBeLessThan(5);
    // the token comes back as change, never to the fee
    expect(plan.totalChange.assets.size).toBe(1);
    await expect(signOwn(plan, [me.payment])).resolves.toBeDefined();
  });
});

describe('review 2 INFO', () => {
  it('the fee is the true minimum when the change straddles a CBOR width boundary (repro v2/15b)', () => {
    const rng = new Rng(15);
    const me = testWallet(rng);
    const to = testWallet(rng).address;
    let checked = 0;
    for (let i = 0; i < 400; i++) {
      const minFeeA = BigInt(rng.pick([44, 1, 1000, rng.int(1001)]));
      const params = {
        ...MAINNET_DEFAULTS,
        minFeeA,
        minFeeB: BigInt(rng.int(300000)),
      };
      const inCoin =
        (1n << 32n) +
        2_000_000n +
        150_000n +
        BigInt(rng.int(400000)) -
        200_000n +
        1_000_000n * BigInt(rng.int(2));
      const plan = planOwn({
        ttl: null,
        utxos: [utxo(rng, inCoin)],
        to,
        coin: 2_000_000n,
        changeAddress: me.address,
        params,
        maxFee: 10n ** 9n,
      });
      if (plan.dustToFee > 0n || plan.change.length === 0) continue;
      checked++;
      expect(plan.fee).toBe(plan.minFee);
      // no lower fee with the difference moved to the change is also valid
      for (const delta of [1n, 2n, 5n, 100n]) {
        const outs = plan.body.outputs.map((o, k) =>
          k === 1 ? { ...o, value: coinValue(o.value.coin + delta) } : o,
        );
        const b = { ...plan.body, outputs: outs, fee: plan.body.fee - delta };
        expect(linearFee(signedSize(encodeBody(b), 1), params) > b.fee).toBe(
          true,
        );
      }
    }
    expect(checked).toBeGreaterThan(300);
  });

  it('ttl is required (null for no expiry)', () => {
    const rng = new Rng(19);
    const me = testWallet(rng);
    const req = {
      utxos: [utxo(rng, 10_000_000n)],
      to: me.address,
      coin: 2_000_000n,
      changeAddress: me.address,
      params: MAINNET_DEFAULTS,
    };
    expect(
      codeOf(() => planOwn(req as unknown as Parameters<typeof planSend>[0])),
    ).toBe('INVALID_INPUT');
    expect(planOwn({ ...req, ttl: null }).body.ttl).toBeUndefined();
    expect(planOwn({ ...req, ttl: 123n }).body.ttl).toBe(123n);
  });

  it('warns when the recipient is a script address (no datum is attached)', () => {
    const rng = new Rng(20);
    const me = testWallet(rng);
    const script = addressToString(
      enterpriseAddress(1, { type: 'script', hash: rng.bytes(28) }),
    );
    const plan = planOwn({
      ttl: TTL,
      utxos: [utxo(rng, 10_000_000n)],
      to: script,
      coin: 2_000_000n,
      changeAddress: me.address,
      params: MAINNET_DEFAULTS,
    });
    expect(plan.warnings[0]).toMatch(/script address/);
    expect(
      planOwn({
        ttl: TTL,
        utxos: [utxo(rng, 10_000_000n)],
        to: me.address,
        coin: 2_000_000n,
        changeAddress: me.address,
        params: MAINNET_DEFAULTS,
      }).warnings,
    ).toEqual([]);
  });

  it('entropy must be a BIP-39 length', () => {
    for (const n of [15, 17, 33, 64])
      expect(codeOf(() => rootKeyFromEntropy(new Uint8Array(n)))).toBe(
        'INVALID_INPUT',
      );
    for (const n of [16, 20, 24, 28, 32])
      expect(rootKeyFromEntropy(new Uint8Array(n))).toHaveLength(96);
  });
});

describe('review 3 #2: ownership inputs are required', () => {
  const rng = new Rng(31);
  const me = testWallet(rng);
  const to = testWallet(rng).address;
  const req = {
    ttl: TTL,
    utxos: [{ ...utxo(rng, 20_000_000n), address: me.address }],
    to,
    coin: 2_000_000n,
    changeAddress: me.address,
    params: MAINNET_DEFAULTS,
  };

  it('planSend refuses without ownAddresses', () => {
    expect(
      codeOf(() => planSend(req as unknown as Parameters<typeof planSend>[0])),
    ).toBe('INVALID_INPUT');
    expect(
      planSend({ ...req, ownAddresses: [me.address] }).change,
    ).toHaveLength(1);
  });

  it('signPlan refuses without a change-address check, maxFee or params', async () => {
    const plan = planSend({ ...req, ownAddresses: [me.address] });
    const bad = [
      undefined,
      {},
      { maxFee: 5_000_000n, params: MAINNET_DEFAULTS },
      { ownAddresses: [me.address], params: MAINNET_DEFAULTS },
      { expectedChangeAddress: me.address, maxFee: 5_000_000n },
      // review 4 INFO: typeof null === 'object'
      { ownAddresses: [me.address], maxFee: 5_000_000n, params: null },
    ];
    for (const o of bad) {
      await expect(
        signPlan(
          plan,
          [me.payment],
          o as unknown as Parameters<typeof signPlan>[2],
        ),
      ).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });
    }
    await expect(
      signPlan(plan, [me.payment], {
        ownAddresses: [me.address],
        maxFee: 5_000_000n,
        params: MAINNET_DEFAULTS,
      }),
    ).resolves.toBeDefined();
  });

  it('signTxWitnessSet refuses without ownAddresses', async () => {
    const plan = planSend({ ...req, ownAddresses: [me.address] });
    const t = assembleTransaction(plan.bodyBytes, encodeCbor(cMap([])));
    await expect(
      signTxWitnessSet(
        t,
        [me.payment],
        undefined as unknown as WitnessSetOptions,
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      signTxWitnessSet(t, [me.payment], {} as unknown as WitnessSetOptions),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      signTxWitnessSet(t, [me.payment], { ownAddresses: [me.address] }),
    ).resolves.toMatch(/^a1/);
  });
});

describe('review 3 INFO', () => {
  it('obsolete certificates (tags 5 and 6) are refused like unknown ones', async () => {
    const rng = new Rng(32);
    const me = testWallet(rng);
    const mir = cArray([
      cUint(6),
      cArray([
        cUint(0),
        cMap([[cArray([cUint(0), cBytes(rng.bytes(28))]), cUint(1_000_000n)]]),
      ]),
    ]);
    const body = encodeCbor(
      cMap([
        [
          cUint(0),
          cTag(258, cArray([cArray([cBytes(rng.bytes(32)), cUint(0)])])),
        ],
        [cUint(1), cArray([])],
        [cUint(2), cUint(200000n)],
        [cUint(4), cTag(258, cArray([mir]))],
      ]),
    );
    const t = assembleTransaction(body, encodeCbor(cMap([])));
    expect(describeTransaction(t).unknownCertificates).toBe(1);
    await expect(
      signTxWitnessSet(t, [me.payment], { ownAddresses: [me.address] }),
    ).rejects.toMatchObject({
      code: 'UNSUPPORTED',
    });
  });

  it('maxAda and all over 300 NFT UTXOs are fast (repro v3/13)', () => {
    const rng = new Rng(33);
    const me = testWallet(rng);
    const to = testWallet(rng).address;
    const nft: Utxo[] = Array.from({ length: 300 }, () => ({
      ...utxo(rng, 1_300_000n, [
        {
          policyId: bytesToHex(rng.bytes(28)),
          assetName: '4e4654',
          quantity: 1n,
        },
      ]),
      address: me.address,
    }));
    nft.push({ ...utxo(rng, 500_000_000n), address: me.address });
    for (const mode of ['all', 'maxAda'] as const) {
      const t0 = performance.now();
      const plan = planSend({
        ttl: TTL,
        utxos: nft,
        to,
        changeAddress: me.address,
        ownAddresses: [me.address],
        mode,
        params: MAINNET_DEFAULTS,
      });
      expect(plan.inputs.length + plan.leftoverUtxos).toBe(301);
      for (const o of plan.outputs)
        expect(valueSize(o.value)).toBeLessThanOrEqual(
          MAINNET_DEFAULTS.maxValueSize,
        );
      expect(performance.now() - t0).toBeLessThan(1_500);
    }
  });
});

describe('review 4: execution-unit parameters', () => {
  it('parses exponent notation exactly (Koios price_step)', () => {
    expect(parseRational('7.21e-05', 'x')).toEqual({
      num: 721n,
      den: 10_000_000n,
    });
    expect(parseRational(7.21e-5, 'x')).toEqual({
      num: 721n,
      den: 10_000_000n,
    });
    expect(parseRational('0.0577', 'x')).toEqual({ num: 577n, den: 10_000n });
    expect(parseRational('1.5E2', 'x')).toEqual({ num: 1500n, den: 10n });
    for (const bad of ['1e31', '1e-31', '-1', 'e5', '1e', '0x10', 'NaN'])
      expect(codeOf(() => parseRational(bad, 'x'))).toBe('INVALID_PARAMS');
  });

  it('reads and bounds price_mem, price_step, max_tx_ex_mem, max_tx_ex_steps', () => {
    const row = {
      min_fee_a: 44,
      min_fee_b: 155381,
      max_tx_size: 16384,
      max_val_size: '5000',
      coins_per_utxo_size: '4310',
      key_deposit: '2000000',
      pool_deposit: '500000000',
      min_fee_ref_script_cost_per_byte: 15,
      price_mem: 0.0577,
      price_step: 7.21e-5,
      max_tx_ex_mem: '16500000',
      max_tx_ex_steps: '10000000000',
    };
    for (const p of [parseKoiosParams([row]), parseBlockfrostParams(row)]) {
      expect(p.priceMem).toEqual({ num: 577n, den: 10_000n });
      expect(p.priceStep).toEqual({ num: 721n, den: 10_000_000n });
      expect(p.maxTxExMem).toBe(16_500_000n);
      expect(p.maxTxExSteps).toBe(10_000_000_000n);
      expect(maxTransactionFee(p)).toBe(8_884_975n);
    }
    // missing fields fall back to mainnet in the bound
    const bare: Record<string, unknown> = { ...row };
    for (const k of [
      'price_mem',
      'price_step',
      'max_tx_ex_mem',
      'max_tx_ex_steps',
    ])
      bare[k] = null;
    const p = parseKoiosParams(bare);
    expect(p.priceMem).toBeUndefined();
    expect(maxTransactionFee(p)).toBe(8_884_975n);
    // out-of-bounds values are refused
    for (const bad of [
      { price_mem: 11 },
      { price_step: 2 },
      { max_tx_ex_mem: '10000000001' },
      { max_tx_ex_steps: '10000000000001' },
      { price_step: 'cheap' },
    ])
      expect(codeOf(() => parseKoiosParams({ ...row, ...bad }))).toBe(
        'INVALID_PARAMS',
      );
  });
});
