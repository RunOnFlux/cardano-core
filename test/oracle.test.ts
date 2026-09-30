import { describe, expect, it } from 'vitest';
import {
  assetList,
  CardanoError,
  MAINNET_DEFAULTS,
  planSend,
  signPlan,
  sumValues,
} from '../src/index.js';
import type {
  AssetAmount,
  PlanSendRequest,
  ProtocolParams,
  SendMode,
  Utxo,
} from '../src/index.js';
import { cases, Rng } from './helpers/random.js';
import {
  cslCheckPlan,
  randomPolicyAssets,
  testWallet,
  utxo,
} from './helpers/wallet.js';
import type { TestWallet } from './helpers/wallet.js';

/**
 * Seeded differential sweep: random wallets, random sends and randomised
 * protocol parameters. Every plan must pass cardano-serialization-lib's own
 * checks (body round-trip, value conservation per asset, min-ADA per output,
 * `min_fee` of the signed tx, tx id, witnesses) plus the request checks in
 * `cslCheckPlan` (recipient gets what was asked, change goes to the change
 * address). Failures must be typed and expected.
 * `yarn oracle` runs 10,000 cases; `yarn test` runs 200.
 */

const EXPECTED_FAILURES = new Set([
  'INSUFFICIENT_FUNDS',
  'INSUFFICIENT_TOKENS',
  'INSUFFICIENT_ADA_FOR_CHANGE',
  'OUTPUT_BELOW_MIN_ADA',
  'TX_TOO_LARGE',
  'VALUE_TOO_LARGE',
  'FEE_TOO_HIGH',
]);

function randomParams(rng: Rng): ProtocolParams {
  if (rng.bool(0.5)) return MAINNET_DEFAULTS;
  return {
    ...MAINNET_DEFAULTS,
    minFeeA: rng.pick([44n, 44n, BigInt(rng.int(200))]),
    minFeeB: rng.pick([155381n, BigInt(rng.int(2_000_000))]),
    coinsPerUtxoByte: rng.pick([4310n, 1n, 34482n, BigInt(1 + rng.int(20000))]),
    maxValueSize: rng.pick([5000, 1000, 300 + rng.int(400)]),
    maxTxSize: rng.pick([16384, 16384, 4096]),
  };
}

function randomWallet(
  rng: Rng,
  owners: readonly TestWallet[],
): { utxos: Utxo[]; tokens: AssetAmount[] } {
  const pool = randomPolicyAssets(rng, 1 + rng.int(12));
  const utxos: Utxo[] = [];
  const n = 1 + rng.int(rng.bool(0.1) ? 60 : 12);
  for (let i = 0; i < n; i++) {
    const assets: AssetAmount[] = [];
    if (rng.bool(0.4)) {
      for (let k = 0; k < 1 + rng.int(rng.bool(0.1) ? 20 : 4); k++) {
        const a = rng.pick(pool);
        assets.push({ ...a, quantity: 1n + (rng.u64() % 1_000_000n) });
      }
    }
    const owner = rng.pick(owners);
    utxos.push({
      ...utxo(rng, (rng.lovelace() % 2_000_000_000n) + 800_000n, assets),
      // Multi-key wallets: UTXOs at several addresses (base or enterprise) of several keys.
      ...(owners.length > 1 || rng.bool(0.3)
        ? { address: rng.bool() ? owner.address : owner.enterprise }
        : {}),
    });
  }
  const tokens = assetList(sumValues(utxos.map((u) => u.value)));
  return { utxos, tokens };
}

describe('oracle: planSend vs cardano-serialization-lib', () => {
  it('every plan passes CSL and request checks; every failure is typed', async () => {
    const rng = new Rng(0x0dac1e);
    const n = cases(200);
    // Key derivation is PBKDF2-heavy; a small pool of wallets keeps the sweep fast.
    const wallets = Array.from({ length: 8 }, () => testWallet(rng));
    let ok = 0;
    let multiKey = 0;
    const failures: Record<string, number> = {};
    for (let i = 0; i < n; i++) {
      const me = rng.pick(wallets);
      const owners = rng.bool(0.2) ? [me, rng.pick(wallets)] : [me];
      const params = randomParams(rng);
      const to = rng.bool(0.9)
        ? rng.pick([rng.pick(wallets).address, rng.pick(wallets).enterprise])
        : 'Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi';
      const { utxos, tokens } = randomWallet(rng, owners);
      const mode: SendMode = rng.pick([
        'amount',
        'amount',
        'amount',
        'maxAda',
        'all',
      ] as const);
      let req: PlanSendRequest = {
        utxos,
        to,
        mode,
        changeAddress: me.address,
        ownAddresses: [me.address],
        params,
        ttl: BigInt(rng.range(100_000_000, 300_000_000)),
        preserveOrder: rng.bool(0.2),
        maxFee: rng.pick([5_000_000n, 100_000_000n]),
        ...(rng.bool(0.3)
          ? { tokenOutputMinCoin: BigInt(rng.int(3_000_000)) }
          : {}),
      };
      if (mode !== 'all') {
        const sendToken = tokens.length > 0 && rng.bool(0.5);
        const pick = sendToken ? rng.pick(tokens) : undefined;
        const assets = pick
          ? [
              {
                ...pick,
                quantity: rng.bool(0.3)
                  ? pick.quantity
                  : 1n + (rng.u64() % pick.quantity),
              },
            ]
          : [];
        if (assets.length) req = { ...req, assets };
        if (mode === 'amount' && (!assets.length || rng.bool(0.3))) {
          req = { ...req, coin: BigInt(rng.range(1_000_000, 900_000_000)) };
        }
      }
      try {
        const plan = planSend(req);
        // Signed against the wallet's own change address, fee ceiling and parameters.
        const signed = await signPlan(
          plan,
          owners.map((o) => o.payment),
          {
            expectedChangeAddress: me.address,
            maxFee: req.maxFee ?? 5_000_000n,
            params,
          },
        );
        cslCheckPlan(plan, signed.bytes, { request: req, params });
        expect(plan.fee).toBe(plan.minFee + plan.dustToFee);
        if (plan.requiredKeyHashes.length > 1) multiKey++;
        ok++;
      } catch (e) {
        if (!(e instanceof CardanoError) || !EXPECTED_FAILURES.has(e.code)) {
          expect.fail(`case ${i}: unexpected ${String(e)}`);
        }
        failures[e.code] = (failures[e.code] ?? 0) + 1;
      }
    }
    if (process.env['CARDANO_ORACLE_CASES']) {
      process.stderr.write(
        `planSend oracle: ${ok} plans verified by CSL (${multiKey} multi-key), typed failures ${JSON.stringify(failures)}\n`,
      );
    }
    // Most random sends should be fundable; a sweep that never succeeds proves nothing.
    expect(ok).toBeGreaterThan(n * 0.5);
    expect(multiKey).toBeGreaterThan(0);
  });
});
