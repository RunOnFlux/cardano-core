import { describe, expect, it } from 'vitest';
import {
  addressFromBytes,
  addressToString,
  baseAddress,
  bech32Encode,
  bytesToHex,
  CardanoError,
  enterpriseAddress,
  hexToBytes,
  isPaymentAddress,
  isValidAddress,
  parseAddress,
  parseAddressHex,
  parsePaymentAddress,
  pointerAddress,
  rewardAddress,
} from '../src/index.js';
import type { Credential } from '../src/index.js';
import { CSL, hex } from './helpers/csl.js';
import { cases, Rng } from './helpers/random.js';

// CIP-19 test vectors (payment key hash 9493315c…, stake key hash 337b62cf…, script hash c37b1b5d…).
const PAY_KEY = '9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e';
const STAKE_KEY = '337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251';
const SCRIPT = 'c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f';
const CIP19: {
  addr: string;
  kind: string;
  network: number;
  payment?: [string, string];
  stake?: [string, string];
}[] = [
  {
    addr: 'addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x',
    kind: 'base',
    network: 1,
    payment: ['key', PAY_KEY],
    stake: ['key', STAKE_KEY],
  },
  {
    addr: 'addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh',
    kind: 'base',
    network: 1,
    payment: ['script', SCRIPT],
    stake: ['key', STAKE_KEY],
  },
  {
    addr: 'addr1yx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerkr0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shs2z78ve',
    kind: 'base',
    network: 1,
    payment: ['key', PAY_KEY],
    stake: ['script', SCRIPT],
  },
  {
    addr: 'addr1x8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gt7r0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shskhj42g',
    kind: 'base',
    network: 1,
    payment: ['script', SCRIPT],
    stake: ['script', SCRIPT],
  },
  {
    addr: 'addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k',
    kind: 'pointer',
    network: 1,
    payment: ['key', PAY_KEY],
  },
  {
    addr: 'addr128phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcrtw79hu',
    kind: 'pointer',
    network: 1,
    payment: ['script', SCRIPT],
  },
  {
    addr: 'addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8',
    kind: 'enterprise',
    network: 1,
    payment: ['key', PAY_KEY],
  },
  {
    addr: 'addr1w8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcyjy7wx',
    kind: 'enterprise',
    network: 1,
    payment: ['script', SCRIPT],
  },
  {
    addr: 'stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw',
    kind: 'reward',
    network: 1,
    stake: ['key', STAKE_KEY],
  },
  {
    addr: 'stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5',
    kind: 'reward',
    network: 1,
    stake: ['script', SCRIPT],
  },
  {
    addr: 'addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae',
    kind: 'base',
    network: 0,
    payment: ['key', PAY_KEY],
    stake: ['key', STAKE_KEY],
  },
  {
    addr: 'addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz',
    kind: 'enterprise',
    network: 0,
    payment: ['key', PAY_KEY],
  },
  {
    addr: 'stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn',
    kind: 'reward',
    network: 0,
    stake: ['key', STAKE_KEY],
  },
];

describe('addresses: CIP-19 vectors', () => {
  for (const v of CIP19) {
    it(v.addr.slice(0, 20), () => {
      const p = parseAddress(v.addr);
      expect(p.kind).toBe(v.kind);
      expect(p.network).toBe(v.network);
      if (v.payment)
        expect([
          p.payment?.type,
          bytesToHex(p.payment?.hash ?? new Uint8Array()),
        ]).toEqual(v.payment);
      if (v.stake)
        expect([
          p.stake?.type,
          bytesToHex(p.stake?.hash ?? new Uint8Array()),
        ]).toEqual(v.stake);
      expect(addressToString(p)).toBe(v.addr);
      expect(bytesToHex(p.bytes)).toBe(
        hex(CSL.Address.from_bech32(v.addr).to_bytes()),
      );
      expect(isPaymentAddress(p)).toBe(v.kind !== 'reward');
    });
  }

  it('decodes the CIP-19 pointer', () => {
    expect(parseAddress(CIP19[4]!.addr).pointer).toEqual({
      slot: 2498243n,
      txIndex: 27n,
      certIndex: 3n,
    });
  });
});

describe('addresses: Byron', () => {
  it('mainnet (no protocol magic)', () => {
    for (const a of [
      'DdzFFzCqrht4PWfBGtmrQz4x1GkZHYLVGbK7aaBkjWxujxzz3L5GxCgPiTsks5RjUr3yX9KvwKjNJBt7ZzPCmS3fUQrGeRvo9Y1YBQKQ',
      'Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi',
    ]) {
      const p = parseAddress(a);
      expect(p.kind).toBe('byron');
      expect(p.network).toBe(1);
      expect(p.byronProtocolMagic).toBeUndefined();
      expect(addressToString(p)).toBe(a);
      expect(bytesToHex(p.bytes)).toBe(
        hex(CSL.ByronAddress.from_base58(a).to_address().to_bytes()),
      );
      expect(isPaymentAddress(a)).toBe(true);
    }
  });

  it('testnet (protocol magic in attributes)', () => {
    const a =
      '37btjrVyb4KDXBNC4haBVPCrro8AQPHwvCMp3RFhhSVWwfFmZ6wwzSK6JK1hY6wHNmtrpTf1kdbva8TCneM2YsiXT7mrzT21EacHnPpz5YyUdj64na';
    const p = parseAddress(a);
    expect(p.network).toBe(0);
    expect(p.byronProtocolMagic).toBe(1097911063);
  });

  it('rejects a corrupted checksum', () => {
    const a = 'Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAj';
    expect(isValidAddress(a)).toBe(false);
  });
});

describe('addresses: validation', () => {
  it('rejects stake addresses as payment recipients and wrong networks', () => {
    const stake = 'stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw';
    expect(() => parsePaymentAddress(stake)).toThrow(CardanoError);
    try {
      parsePaymentAddress(stake);
    } catch (e) {
      expect((e as CardanoError).code).toBe('NOT_A_PAYMENT_ADDRESS');
    }
    try {
      parsePaymentAddress(CIP19[10]!.addr, 1);
    } catch (e) {
      expect((e as CardanoError).code).toBe('WRONG_NETWORK');
    }
  });

  it('rejects a prefix that does not match the network', () => {
    // mainnet bytes under the addr_test prefix
    const bytes = parseAddress(CIP19[0]!.addr).bytes;
    expect(isValidAddress(bech32Encode('addr_test', bytes))).toBe(false);
  });

  it('rejects malformed input', () => {
    for (const bad of [
      '',
      'addr1',
      'addr1qx2fxv2um',
      'hello',
      'stake1abc',
      '0x1234',
    ]) {
      expect(isValidAddress(bad)).toBe(false);
    }
    expect(() =>
      addressFromBytes(hexToBytes('01' + '00'.repeat(55))),
    ).toThrow();
    expect(() =>
      addressFromBytes(hexToBytes('91' + '00'.repeat(28))),
    ).toThrow();
    expect(
      parseAddressHex(bytesToHex(parseAddress(CIP19[6]!.addr).bytes)).kind,
    ).toBe('enterprise');
  });
});

describe('addresses: parity with cardano-serialization-lib', () => {
  it('constructs every Shelley type byte-identically', () => {
    const rng = new Rng(0xadd7);
    const cslCred = (c: Credential) =>
      c.type === 'key'
        ? CSL.Credential.from_keyhash(CSL.Ed25519KeyHash.from_bytes(c.hash))
        : CSL.Credential.from_scripthash(CSL.ScriptHash.from_bytes(c.hash));
    for (let i = 0; i < cases(300); i++) {
      const network = rng.pick([0, 1]);
      const pay: Credential = {
        type: rng.pick(['key', 'script'] as const),
        hash: rng.bytes(28),
      };
      const stk: Credential = {
        type: rng.pick(['key', 'script'] as const),
        hash: rng.bytes(28),
      };
      const ptr = {
        slot: BigInt(rng.int(2 ** 31)),
        txIndex: BigInt(rng.int(1000)),
        certIndex: BigInt(rng.int(20)),
      };
      const pairs: [Uint8Array, InstanceType<typeof CSL.Address>][] = [
        [
          baseAddress(network, pay, stk),
          CSL.BaseAddress.new(network, cslCred(pay), cslCred(stk)).to_address(),
        ],
        [
          enterpriseAddress(network, pay),
          CSL.EnterpriseAddress.new(network, cslCred(pay)).to_address(),
        ],
        [
          rewardAddress(network, stk),
          CSL.RewardAddress.new(network, cslCred(stk)).to_address(),
        ],
        [
          pointerAddress(network, pay, ptr),
          CSL.PointerAddress.new(
            network,
            cslCred(pay),
            CSL.Pointer.new_pointer(
              CSL.BigNum.from_str(ptr.slot.toString()),
              CSL.BigNum.from_str(ptr.txIndex.toString()),
              CSL.BigNum.from_str(ptr.certIndex.toString()),
            ),
          ).to_address(),
        ],
      ];
      for (const [ours, theirs] of pairs) {
        expect(hex(ours)).toBe(hex(theirs.to_bytes()));
        expect(addressToString(ours)).toBe(theirs.to_bech32(undefined));
        const back = parseAddress(addressToString(ours));
        expect(hex(back.bytes)).toBe(hex(ours));
      }
    }
  });
});
