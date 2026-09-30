import { describe, expect, it } from 'vitest';
import {
  assetQuantity,
  CardanoError,
  hasAssets,
  InsufficientFundsError,
  MAINNET_DEFAULTS,
  makeValue,
  planSend,
  signPlan,
  valueSize,
} from '../src/index.js';
import type { PlanSendRequest, Utxo } from '../src/index.js';
import { Rng } from './helpers/random.js';
import {
  cslCheckPlan,
  randomPolicyAssets,
  SNEK,
  testWallet,
  utxo,
  planOwn,
  signOwn,
} from './helpers/wallet.js';

/** Every plan needs an expiry slot (or null); tests use a fixed one. */
const TTL = 200_000_000n;

const params = MAINNET_DEFAULTS;

async function planAndCheck(
  req: Omit<PlanSendRequest, 'ownAddresses'>,
  signers: Parameters<typeof signPlan>[1],
) {
  const full: PlanSendRequest = { ...req, ownAddresses: [req.changeAddress] };
  const plan = planSend(full);
  // The wallet's own values, not the plan's.
  const signed = await signPlan(plan, signers, {
    expectedChangeAddress: req.changeAddress,
    maxFee: req.maxFee ?? 5_000_000n,
    params: req.params,
  });
  cslCheckPlan(plan, signed.bytes, { request: full });
  return plan;
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof CardanoError) return e.code;
    throw e;
  }
  return 'no error';
}

describe('planSend: ADA sends', () => {
  it('sends ADA with change and an exact fee', async () => {
    const rng = new Rng(1);
    const w = testWallet(rng);
    const to = testWallet(rng).address;
    const utxos = [utxo(rng, 10_000_000n), utxo(rng, 5_000_000n)];
    const plan = await planAndCheck(
      {
        utxos,
        to,
        coin: 3_000_000n,
        changeAddress: w.address,
        params,
        ttl: 170_000_000n,
      },
      [w.payment],
    );
    expect(plan.recipient.value.coin).toBe(3_000_000n);
    expect(plan.change).toHaveLength(1);
    expect(plan.fee).toBe(plan.minFee);
    expect(plan.inputs).toHaveLength(1); // the 10 ADA UTXO alone suffices
    expect(plan.body.ttl).toBe(170_000_000n);
  });

  it('prefers ADA-only inputs so change does not pick up tokens', async () => {
    const rng = new Rng(2);
    const w = testWallet(rng);
    const utxos = [
      utxo(rng, 50_000_000n, randomPolicyAssets(rng, 3)),
      utxo(rng, 8_000_000n),
    ];
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos,
        to: testWallet(rng).address,
        coin: 5_000_000n,
        changeAddress: w.address,
        params,
      },
      [w.payment],
    );
    expect(plan.inputs).toHaveLength(1);
    expect(hasAssets(plan.totalChange)).toBe(false);
  });

  it('tops up instead of burning ADA-only dust when another ADA-only input exists', async () => {
    const rng = new Rng(3);
    const w = testWallet(rng);
    // 3.2 ADA − 3 ADA − fee leaves ~0.03 ADA: too little for a change output.
    const utxos = [utxo(rng, 3_200_000n), utxo(rng, 2_000_000n)];
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos,
        to: testWallet(rng).address,
        coin: 3_000_000n,
        changeAddress: w.address,
        params,
        preserveOrder: true,
      },
      [w.payment],
    );
    expect(plan.dustToFee).toBe(0n);
    expect(plan.inputs).toHaveLength(2);
    expect(plan.change).toHaveLength(1);
  });

  it('folds ADA-only dust into the fee when nothing can absorb it', async () => {
    const rng = new Rng(4);
    const w = testWallet(rng);
    const utxos = [utxo(rng, 3_200_000n)];
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos,
        to: testWallet(rng).address,
        coin: 3_000_000n,
        changeAddress: w.address,
        params,
      },
      [w.payment],
    );
    expect(plan.change).toHaveLength(0);
    expect(plan.dustToFee).toBeGreaterThan(0n);
    expect(plan.fee).toBe(200_000n);
  });

  it('rejects a recipient output below the ledger minimum', () => {
    const rng = new Rng(5);
    const w = testWallet(rng);
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          utxos: [utxo(rng, 5_000_000n)],
          to: w.address,
          coin: 500_000n,
          changeAddress: w.address,
          params,
        }),
      ),
    ).toBe('OUTPUT_BELOW_MIN_ADA');
  });

  it('reports the shortfall when funds are insufficient', () => {
    const rng = new Rng(6);
    const w = testWallet(rng);
    try {
      planOwn({
        ttl: TTL,
        utxos: [utxo(rng, 2_000_000n)],
        to: testWallet(rng).address,
        coin: 5_000_000n,
        changeAddress: w.address,
        params,
      });
      throw new Error('should fail');
    } catch (e) {
      expect(e).toBeInstanceOf(InsufficientFundsError);
      expect((e as InsufficientFundsError).code).toBe('INSUFFICIENT_FUNDS');
      expect((e as InsufficientFundsError).shortfall).toBeGreaterThan(
        3_000_000n,
      );
    }
  });

  it('refuses stake addresses, other networks and change addresses without a key credential', () => {
    const rng = new Rng(7);
    const w = testWallet(rng);
    const base = {
      utxos: [utxo(rng, 5_000_000n)],
      coin: 2_000_000n,
      changeAddress: w.address,
      params,
    };
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          ...base,
          to: 'stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw',
        }),
      ),
    ).toBe('NOT_A_PAYMENT_ADDRESS');
    expect(
      codeOf(() =>
        planOwn({ ttl: TTL, ...base, to: testWallet(rng, 0).address }),
      ),
    ).toBe('WRONG_NETWORK');
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          ...base,
          to: w.address,
          changeAddress:
            'addr1w8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcyjy7wx',
        }),
      ),
    ).toBe('INVALID_INPUT');
  });

  it('pays Byron recipients', async () => {
    const rng = new Rng(8);
    const w = testWallet(rng);
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos: [utxo(rng, 10_000_000n)],
        to: 'Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi',
        coin: 2_000_000n,
        changeAddress: w.address,
        params,
      },
      [w.payment],
    );
    expect(plan.recipient.value.coin).toBe(2_000_000n);
  });
});

describe('planSend: token sends (ZelCore regressions)', () => {
  it('returns leftover tokens as change and tops up ADA for that change (was: dropped assets)', async () => {
    const rng = new Rng(10);
    const w = testWallet(rng);
    // The SNEK UTXO also holds 9 other tokens and only 2 ADA.
    const tokenUtxo = utxo(rng, 2_000_000n, [
      { ...SNEK, quantity: 1000n },
      ...randomPolicyAssets(rng, 9),
    ]);
    const utxos = [tokenUtxo, utxo(rng, 5_000_000n)];
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos,
        to: testWallet(rng).address,
        assets: [{ ...SNEK, quantity: 100n }],
        changeAddress: w.address,
        params,
      },
      [w.payment],
    );
    expect(plan.inputs).toHaveLength(2);
    expect(
      assetQuantity(plan.recipient.value, SNEK.policyId, SNEK.assetName),
    ).toBe(100n);
    expect(plan.recipient.value.coin).toBe(1_500_000n);
    expect(assetQuantity(plan.totalChange, SNEK.policyId, SNEK.assetName)).toBe(
      900n,
    );
    expect(plan.dustToFee).toBe(0n);
  });

  it('never folds while assets remain; errors with the ADA shortfall instead', () => {
    const rng = new Rng(11);
    const w = testWallet(rng);
    const utxos = [
      utxo(rng, 2_000_000n, [
        { ...SNEK, quantity: 1000n },
        ...randomPolicyAssets(rng, 9),
      ]),
    ];
    try {
      planOwn({
        ttl: TTL,
        utxos,
        to: testWallet(rng).address,
        assets: [{ ...SNEK, quantity: 100n }],
        changeAddress: w.address,
        params,
      });
      throw new Error('should fail');
    } catch (e) {
      expect((e as CardanoError).code).toBe('INSUFFICIENT_ADA_FOR_CHANGE');
      expect((e as InsufficientFundsError).shortfall).toBeGreaterThan(
        1_000_000n,
      );
    }
  });

  it('prices min-ADA at the live 4310 lovelace/byte (was: 1000)', async () => {
    const rng = new Rng(12);
    const w = testWallet(rng);
    const utxos = [
      utxo(rng, 3_000_000n, [
        { ...SNEK, quantity: 10n },
        ...randomPolicyAssets(rng, 10),
      ]),
      utxo(rng, 20_000_000n),
    ];
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos,
        to: testWallet(rng).address,
        assets: [{ ...SNEK, quantity: 1n }],
        changeAddress: w.address,
        params,
      },
      [w.payment],
    );
    for (const c of plan.change)
      expect(c.value.coin).toBeGreaterThanOrEqual(c.minAda);
    expect(plan.change[0]!.minAda).toBeGreaterThan(2_000_000n);
  });

  it('raises the token output above 1.5 ADA when the ledger needs more', async () => {
    const rng = new Rng(13);
    const w = testWallet(rng);
    const many = randomPolicyAssets(rng, 12);
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos: [utxo(rng, 50_000_000n, many)],
        to: testWallet(rng).address,
        assets: many,
        changeAddress: w.address,
        params,
      },
      [w.payment],
    );
    expect(plan.recipient.value.coin).toBeGreaterThan(1_500_000n);
    expect(plan.recipient.value.coin).toBe(plan.recipient.minAda);
  });

  it('fails with INSUFFICIENT_TOKENS', () => {
    const rng = new Rng(14);
    const w = testWallet(rng);
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          utxos: [utxo(rng, 5_000_000n, [{ ...SNEK, quantity: 5n }])],
          to: w.address,
          assets: [{ ...SNEK, quantity: 6n }],
          changeAddress: w.address,
          params,
        }),
      ),
    ).toBe('INSUFFICIENT_TOKENS');
  });

  it('splits change that would exceed maxValueSize', async () => {
    const rng = new Rng(15);
    const w = testWallet(rng);
    const spam = randomPolicyAssets(rng, 140);
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos: [utxo(rng, 200_000_000n, spam)],
        to: testWallet(rng).address,
        coin: 2_000_000n,
        changeAddress: w.address,
        params,
      },
      [w.payment],
    );
    expect(plan.change.length).toBeGreaterThan(1);
    for (const c of plan.change)
      expect(valueSize(c.value)).toBeLessThanOrEqual(params.maxValueSize);
  });
});

describe('planSend: max and sweep', () => {
  it('maxAda sends all ADA but keeps other tokens in change', async () => {
    const rng = new Rng(20);
    const w = testWallet(rng);
    const utxos = [
      utxo(rng, 10_000_000n, randomPolicyAssets(rng, 2)),
      utxo(rng, 7_000_000n),
    ];
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos,
        to: testWallet(rng).address,
        mode: 'maxAda',
        changeAddress: w.address,
        params,
      },
      [w.payment],
    );
    expect(plan.change).toHaveLength(1);
    expect(plan.change[0]!.value.coin).toBe(plan.change[0]!.minAda);
    expect(
      plan.recipient.value.coin + plan.fee + plan.change[0]!.value.coin,
    ).toBe(17_000_000n);
    expect(hasAssets(plan.recipient.value)).toBe(false);
  });

  it('maxAda without tokens leaves no change', async () => {
    const rng = new Rng(21);
    const w = testWallet(rng);
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos: [utxo(rng, 4_000_000n), utxo(rng, 3_000_000n)],
        to: testWallet(rng).address,
        mode: 'maxAda',
        changeAddress: w.address,
        params,
      },
      [w.payment],
    );
    expect(plan.change).toHaveLength(0);
    expect(plan.recipient.value.coin + plan.fee).toBe(7_000_000n);
  });

  it('all sweeps every asset', async () => {
    const rng = new Rng(22);
    const w = testWallet(rng);
    const assets = randomPolicyAssets(rng, 3);
    const plan = await planAndCheck(
      {
        ttl: TTL,
        utxos: [utxo(rng, 5_000_000n, assets), utxo(rng, 1_000_000n)],
        to: testWallet(rng).address,
        mode: 'all',
        changeAddress: w.address,
        params,
      },
      [w.payment],
    );
    expect(plan.change).toHaveLength(0);
    for (const a of assets)
      expect(assetQuantity(plan.recipient.value, a.policyId, a.assetName)).toBe(
        a.quantity,
      );
  });
});

describe('planSend: input hygiene and limits', () => {
  it('skips reference-script UTXOs unless allowed with a known size, then prices them', async () => {
    const rng = new Rng(30);
    const w = testWallet(rng);
    const ref: Utxo = {
      ...utxo(rng, 100_000_000n),
      referenceScriptHash: 'ab'.repeat(28),
      referenceScriptSize: 3000,
    };
    const plain = utxo(rng, 3_000_000n);
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          utxos: [ref],
          to: testWallet(rng).address,
          coin: 2_000_000n,
          changeAddress: w.address,
          params,
        }),
      ),
    ).toBe('INSUFFICIENT_FUNDS');
    const plan = planOwn({
      ttl: TTL,
      utxos: [ref, plain],
      to: testWallet(rng).address,
      coin: 50_000_000n,
      changeAddress: w.address,
      params,
      allowReferenceScriptInputs: true,
    });
    expect(plan.referenceScriptFee).toBe(45_000n);
    expect(plan.fee).toBeGreaterThanOrEqual(plan.minFee);
    const signed = await signOwn(plan, [w.payment]);
    expect(signed.bytes.length).toBe(plan.signedSize);
  });

  it('de-duplicates UTXOs and skips script-address UTXOs', () => {
    const rng = new Rng(31);
    const w = testWallet(rng);
    const u = utxo(rng, 10_000_000n);
    const scriptUtxo: Utxo = {
      ...utxo(rng, 100_000_000n),
      address: 'addr1w8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcyjy7wx',
    };
    const plan = planOwn({
      ttl: TTL,
      utxos: [u, u, scriptUtxo],
      to: testWallet(rng).address,
      coin: 2_000_000n,
      changeAddress: w.address,
      params,
    });
    expect(plan.inputs).toHaveLength(1);
  });

  it('enforces the fee ceiling', () => {
    const rng = new Rng(32);
    const w = testWallet(rng);
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          utxos: [utxo(rng, 10_000_000n)],
          to: w.address,
          coin: 2_000_000n,
          changeAddress: w.address,
          params,
          maxFee: 100_000n,
        }),
      ),
    ).toBe('FEE_TOO_HIGH');
  });

  it('refuses to sign with the wrong key', async () => {
    const rng = new Rng(33);
    const w = testWallet(rng);
    const other = testWallet(rng);
    const plan = planOwn({
      ttl: TTL,
      utxos: [utxo(rng, 10_000_000n)],
      to: other.address,
      coin: 2_000_000n,
      changeAddress: w.address,
      params,
    });
    await expect(signOwn(plan, [other.payment])).rejects.toMatchObject({
      code: 'KEY_MISMATCH',
    });
  });

  it('rejects nothing-to-send and bad values', () => {
    const rng = new Rng(34);
    const w = testWallet(rng);
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          utxos: [utxo(rng, 10_000_000n)],
          to: w.address,
          changeAddress: w.address,
          params,
        }),
      ),
    ).toBe('INVALID_INPUT');
    expect(() => makeValue(-1n)).toThrow();
  });
});

describe('planSend: dust fold that cannot cover the fee', () => {
  it('reports INSUFFICIENT_FUNDS instead of failing to converge', () => {
    const rng = new Rng(40);
    const w = testWallet(rng);
    // 3.1 ADA − 3 ADA leaves 0.1 ADA: too little for a change output, and too little for the fee.
    expect(
      codeOf(() =>
        planOwn({
          ttl: TTL,
          utxos: [utxo(rng, 3_100_000n)],
          to: testWallet(rng).address,
          coin: 3_000_000n,
          changeAddress: w.address,
          params,
        }),
      ),
    ).toBe('INSUFFICIENT_FUNDS');
  });
});
