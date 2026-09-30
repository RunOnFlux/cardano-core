import { describe, expect, it } from 'vitest';
import {
  addressToString,
  bytesToHex,
  coseKey,
  hexToBytes,
  parseAddress,
  signData,
  sigStructure,
  protectedHeader,
  utf8,
  verifyData,
} from '../src/index.js';
import { CMS, hex } from './helpers/csl.js';
import { cases, Rng } from './helpers/random.js';
import { testWallet } from './helpers/wallet.js';

/** CMS reference: exactly what ZelCore's sign-cardano.ts builds today. */
function cmsSign(
  addressBytes: Uint8Array,
  payload: Uint8Array,
  sign: (m: Uint8Array) => Uint8Array,
  publicKey: Uint8Array,
) {
  const ph = CMS.HeaderMap.new();
  ph.set_algorithm_id(CMS.Label.from_algorithm_id(CMS.AlgorithmId.EdDSA));
  ph.set_header(
    CMS.Label.new_text('address'),
    CMS.CBORValue.new_bytes(addressBytes),
  );
  const headers = CMS.Headers.new(
    CMS.ProtectedHeaderMap.new(ph),
    CMS.HeaderMap.new(),
  );
  const builder = CMS.COSESign1Builder.new(headers, payload, false);
  const toSign = builder.make_data_to_sign().to_bytes();
  const sign1 = builder.build(sign(toSign));
  const key = CMS.COSEKey.new(CMS.Label.from_key_type(CMS.KeyType.OKP));
  key.set_algorithm_id(CMS.Label.from_algorithm_id(CMS.AlgorithmId.EdDSA));
  key.set_header(
    CMS.Label.new_int(CMS.Int.new_negative(CMS.BigNum.from_str('1'))),
    CMS.CBORValue.new_int(CMS.Int.new_i32(6)),
  );
  key.set_header(
    CMS.Label.new_int(CMS.Int.new_negative(CMS.BigNum.from_str('2'))),
    CMS.CBORValue.new_bytes(publicKey),
  );
  return { toSign, signature: hex(sign1.to_bytes()), key: hex(key.to_bytes()) };
}

describe('CIP-8 signData: parity with cardano-message-signing', () => {
  it('produces byte-identical COSE_Sign1 and COSE_Key', async () => {
    const rng = new Rng(0xc1b8);
    // Key derivation is PBKDF2-heavy; the sweep varies payloads over a pool of wallets.
    const wallets = Array.from({ length: 16 }, () => testWallet(rng));
    for (let i = 0; i < cases(100); i++) {
      const w = rng.pick(wallets);
      const addr = parseAddress(w.address).bytes;
      const payload = rng.bytes(rng.pick([0, 5, 23, 24, 255, 256, 1000]));
      const ours = await signData(w.address, payload, w.payment);
      const ref = cmsSign(
        addr,
        payload,
        (m) => w.payment.sign(m) as Uint8Array,
        w.payment.publicKey,
      );
      expect(bytesToHex(sigStructure(protectedHeader(addr), payload))).toBe(
        hex(ref.toSign),
      );
      expect(ours.signature).toBe(ref.signature);
      expect(ours.key).toBe(ref.key);
      // hex address input gives the same result
      expect(
        (await signData(bytesToHex(addr), bytesToHex(payload), w.payment))
          .signature,
      ).toBe(ref.signature);
    }
  });

  it('matches the documented byte layout', async () => {
    const w = testWallet(new Rng(9));
    const sig = await signData(w.address, utf8('Hello'), w.payment);
    expect(sig.signature.startsWith('845846a201276761646472657373583901')).toBe(
      true,
    );
    expect(sig.signature).toContain('a166686173686564f44548656c6c6f5840');
    expect(sig.key).toBe(
      `a4010103272006215820${bytesToHex(w.payment.publicKey)}`,
    );
    expect(bytesToHex(coseKey(w.payment.publicKey))).toBe(sig.key);
  });
});

describe('CIP-8 verifyData', () => {
  it('verifies our and CMS signatures and reports key/address binding', async () => {
    const rng = new Rng(0xf1);
    const w = testWallet(rng);
    const payload = utf8('login nonce 42');
    const sig = await signData(w.address, payload, w.payment);
    const v = verifyData(sig, { address: w.address, payload });
    expect(v.valid).toBe(true);
    expect(v.addressMatchesKey).toBe(true);
    expect(addressToString(v.address)).toBe(w.address);

    // a stake key signing for the base address: valid signature, but not the address's payment key
    const wrongKey = await signData(w.address, payload, w.stake);
    const v2 = verifyData(wrongKey);
    expect(v2.valid).toBe(true);
    expect(v2.addressMatchesKey).toBe(false);
  });

  it('rejects tampering and mismatched expectations', async () => {
    const rng = new Rng(0xf2);
    const w = testWallet(rng);
    const other = testWallet(rng);
    const payload = utf8('pay me');
    const sig = await signData(w.address, payload, w.payment);
    expect(verifyData(sig, { payload: utf8('pay you') }).valid).toBe(false);
    expect(verifyData(sig, { address: other.address }).valid).toBe(false);
    const tampered = {
      ...sig,
      signature: sig.signature.replace(/..$/, (x) =>
        x === '00' ? '01' : '00',
      ),
    };
    expect(verifyData(tampered).valid).toBe(false);
    const swappedKey = {
      ...sig,
      key: bytesToHex(coseKey(other.payment.publicKey)),
    };
    expect(verifyData(swappedKey).valid).toBe(false);
    expect(() => verifyData({ signature: '80', key: sig.key })).toThrow();
    expect(() =>
      verifyData({
        signature: sig.signature,
        key: bytesToHex(hexToBytes('a0')),
      }),
    ).toThrow();
  });
});
