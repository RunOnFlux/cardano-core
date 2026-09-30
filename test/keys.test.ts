import { describe, expect, it } from 'vitest';
import {
  accountKeysFromEntropy,
  bytesToHex,
  cip1852Path,
  derivePath,
  derivePrivate,
  derivePublic,
  harden,
  hexToBytes,
  keyBaseAddress,
  keyHash,
  addressToString,
  localSigner,
  publicKeyOf,
  Role,
  rootKeyFromEntropy,
  signExtended,
  toExtendedPublic,
  utf8,
  verifyEd25519,
} from '../src/index.js';
import { CSL, hex, unhex } from './helpers/csl.js';
import { cases, Rng } from './helpers/random.js';

// Pinned from CSL 14.1.2 (Bip32PrivateKey.from_bip39_entropy → m/1852'/1815'/0'/0/0), 2026-09-29.
const PINNED = [
  {
    entropy: '000102030405060708090a0b0c0d0e0f',
    root: 'c06a3f6b48d90f0517dbf244da40cc25feaebc91bee5b92e2d9301db51520f45b3469692e2bc05cf27f7e4b749581b3719a37dc3045d69da8c0d826c88b80f5745a302ecb459a48b23bdf5ca1f7c5ff6a46c4fe17c30751fa49f08f4fd564a7a',
    payment:
      '40365d28ab8cc68c95abc8128467bcc9ec82f271fc192834c1a1beaf64520f45397552b74c3841e72fbb39775571f27f01ae15b37913b2ab0335d4d0469beb250e252f76c79d94423b3612af584f60b5c57cbe67be2338724d764bfd44b7837b',
    paymentPub:
      'c2f350a90119b89382e6313f1b57ee38ac3689ab5b0360dd49d079abc1627d28',
    stakePub:
      '4218d1d80e107f9d6f13c58d168da980e2d83e2234d83057940b260ee43110d8',
    address:
      'addr1qxwgyuesfey47tcv459ah347xjhsmekmescgx6e8eqpkarh9zl04f0qd6vy7f4ckqce75dwasyjnhjl87cetfjasnstselpljw',
    sigZelcore:
      'c58071f02cac4ffc1a0fc37ad28fe254c48aadbabbadf1f50dd1337333e8698748dd49f571b343f40280e36b93eb5176386a103ddbeb68184421f7b367f4dc09',
  },
  {
    entropy: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    root: 'c05104afff8b35765fa862267bb3ac325dac7d540d5b67208852144e1c9689420cc85321801f548f06f57a79a3b51e7fa63de2f78ed2c53f851436eeca34c531c3c81ca61635db3464f15301413b92747a37c9c1ddb998f1257496903dc55890',
    payment:
      '485f47d753bcbe8830fff7d2a4fe68af4feafb02fd4c2761ce6364512b9689420d0aeb332c2165cdd53d0ee7fb6034d556ff76281a08c02c11238d4585bf5e66864c096b675f6dda19f6cef0cdce5be4fe039eb119056829626836c802c5ef5f',
    paymentPub:
      '17c1b345186bb3b96b7b6506ed70bf54692bb1e66665326223441580b7d04bdb',
    stakePub:
      '281bf51f81ecb43f058b3b61962682d6be52f80bc0db0bf2ed5d62e1d4847983',
    address:
      'addr1qylrq4h2xvj7x49shr65uxrsgkfmpq65la8lpvmxn06gprl6td4s5g30erqzfhnrx8faqtuxl8ruc4a75rxx99twr7fs8l7684',
    sigZelcore:
      '622c4c1f0cf5c58de62f28bc27f6d02abd3c01febc54d0f2f1f25754f9dd6085cb57d053a43851e695bb1d23d4121dbd8cef1449e2818c4660d08b19dd64610f',
  },
];

describe('keys: pinned vectors', () => {
  for (const v of PINNED) {
    it(`derives and signs for entropy ${v.entropy.slice(0, 8)}…`, () => {
      const root = rootKeyFromEntropy(hexToBytes(v.entropy));
      expect(bytesToHex(root)).toBe(v.root);
      const payment = derivePath(root, cip1852Path());
      expect(bytesToHex(payment)).toBe(v.payment);
      expect(bytesToHex(publicKeyOf(payment))).toBe(v.paymentPub);
      const { payment: p2, stake } = accountKeysFromEntropy(
        hexToBytes(v.entropy),
      );
      expect(bytesToHex(p2)).toBe(v.payment);
      expect(bytesToHex(publicKeyOf(stake))).toBe(v.stakePub);
      const addr = keyBaseAddress(
        1,
        keyHash(publicKeyOf(payment)),
        keyHash(publicKeyOf(stake)),
      );
      expect(addressToString(addr)).toBe(v.address);
      expect(bytesToHex(signExtended(payment, utf8('zelcore')))).toBe(
        v.sigZelcore,
      );
    });
  }
});

describe('keys: parity with cardano-serialization-lib', () => {
  it('root, hardened and soft derivation, public derivation and signatures match', () => {
    const rng = new Rng(0xca7d0);
    const n = cases(100);
    for (let i = 0; i < n; i++) {
      const entropy = rng.bytes(rng.pick([16, 20, 24, 28, 32]));
      const root = rootKeyFromEntropy(entropy);
      let cslKey = CSL.Bip32PrivateKey.from_bip39_entropy(
        entropy,
        new Uint8Array(0),
      );
      expect(hex(root)).toBe(hex(cslKey.as_bytes()));
      let ours = root;
      const path = [
        harden(1852),
        harden(1815),
        harden(rng.int(5)),
        rng.pick([0, 1, 2]),
        rng.int(2 ** 31),
      ];
      if (rng.bool()) path.push(harden(rng.int(2 ** 31)));
      for (const idx of path) {
        ours = derivePrivate(ours, idx);
        cslKey = cslKey.derive(idx);
        expect(hex(ours)).toBe(hex(cslKey.as_bytes()));
      }
      const pub = cslKey.to_public();
      expect(hex(publicKeyOf(ours))).toBe(hex(pub.to_raw_key().as_bytes()));
      expect(hex(toExtendedPublic(ours))).toBe(hex(pub.as_bytes()));
      const soft = rng.int(2 ** 31);
      expect(hex(derivePublic(toExtendedPublic(ours), soft))).toBe(
        hex(pub.derive(soft).as_bytes()),
      );
      expect(hex(derivePublic(toExtendedPublic(ours), soft))).toBe(
        hex(toExtendedPublic(derivePrivate(ours, soft))),
      );
      const msg = rng.bytes(rng.int(200));
      const sig = signExtended(ours, msg);
      expect(hex(sig)).toBe(hex(cslKey.to_raw_key().sign(msg).to_bytes()));
      expect(verifyEd25519(publicKeyOf(ours), msg, sig)).toBe(true);
      expect(hex(keyHash(publicKeyOf(ours)))).toBe(
        hex(pub.to_raw_key().hash().to_bytes()),
      );
    }
  });
});

describe('keys: behaviour', () => {
  it('rejects bad lengths and hardened public derivation', () => {
    expect(() => rootKeyFromEntropy(new Uint8Array(8))).toThrow();
    expect(() => derivePrivate(new Uint8Array(64), 0)).toThrow();
    const xpub = toExtendedPublic(rootKeyFromEntropy(new Uint8Array(16)));
    expect(() => derivePublic(xpub, harden(0))).toThrow();
    expect(() => harden(-1)).toThrow();
  });

  it('verification rejects tampering', () => {
    const k = rootKeyFromEntropy(new Uint8Array(32).fill(7));
    const msg = utf8('hello');
    const sig = signExtended(k, msg);
    const pub = publicKeyOf(k);
    expect(verifyEd25519(pub, msg, sig)).toBe(true);
    const bad = Uint8Array.from(sig);
    bad[10] = (bad[10] as number) ^ 1;
    expect(verifyEd25519(pub, msg, bad)).toBe(false);
    expect(verifyEd25519(pub, utf8('hellp'), sig)).toBe(false);
    expect(verifyEd25519(pub.subarray(1), msg, sig)).toBe(false);
  });

  it('localSigner signs like CSL and refuses after destroy', () => {
    const payment = derivePath(
      rootKeyFromEntropy(new Uint8Array(16).fill(3)),
      cip1852Path({ role: Role.External }),
    );
    const s = localSigner(payment);
    const msg = unhex('00'.repeat(32));
    expect(hex(s.sign(msg) as Uint8Array)).toBe(
      hex(signExtended(payment, msg)),
    );
    expect(hex(s.keyHash)).toBe(hex(keyHash(publicKeyOf(payment))));
    s.destroy();
    expect(() => s.sign(msg)).toThrow(/destroyed/);
  });
});
