# @runonflux/cardano-core

Pure-TypeScript Cardano transaction library: CIP-3 Icarus / BIP32-Ed25519 keys, Shelley and Byron addresses, a span-preserving CBOR codec, Conway transactions, exact fees and min-ADA, coin selection with native assets, CIP-8 message signing and CIP-30 helpers. No WASM, two runtime dependencies (`@noble/curves`, `@noble/hashes`), runs unchanged in browsers, MV3 service workers, Electron, Node 20+ and React Native (Hermes).

Built to replace `@emurgo/cardano-serialization-lib` (2.75 MB WASM) and `@emurgo/cardano-message-signing` (0.28 MB WASM) in ZelCore. The whole library is about 50 KB minified (18 KB gzipped) on top of noble.

> **Status: 0.1.0, pre-release.** Every byte this library produces is checked against cardano-serialization-lib 14.1.2 and cardano-message-signing 1.1.0 in the test suite, and every transaction id against 3,110 mainnet transactions. It has not yet had an independent review or funded mainnet verification — see [AUDIT.md](./AUDIT.md).

## Install

```bash
yarn add @runonflux/cardano-core
```

ESM only (like its noble dependencies).

## Quick start

### Send ADA or a native token

```ts
import {
  accountKeysFromEntropy,
  localSigner,
  planSend,
  signPlan,
  utxosFromBackend,
  MAINNET_DEFAULTS,
  parseBlockfrostParams,
} from '@runonflux/cardano-core';

const { payment } = accountKeysFromEntropy(entropy); // m/1852'/1815'/0'/0/0
const signer = localSigner(payment);

const params = parseBlockfrostParams(
  await api.get('/epochs/latest/parameters'),
); // or MAINNET_DEFAULTS
const plan = planSend({
  utxos: utxosFromBackend(await api.get(`/utxos/${myAddress}`)), // Blockfrost/Koios shape
  to: recipient, // bech32 or Byron base58; stake addresses are refused
  coin: 5_000_000n, // lovelace
  // assets: [{ policyId, assetName, quantity: 100n }],   // token send
  // mode: 'maxAda' | 'all',                               // "max" buttons
  changeAddress: myAddress,
  ownAddresses: [myAddress], // required: change must be one of these, byte for byte
  params,
  ttl: currentSlot + 1800n, // required; null for no expiry
});
// plan.fee, plan.recipients, plan.change, plan.dustToFee, plan.leftoverUtxos: every number a UI shows.
// Required: the wallet's own change address, fee ceiling and parameters —
// not the ones recorded on the plan.
const signed = await signPlan(plan, [signer], {
  expectedChangeAddress: myAddress,
  maxFee: 5_000_000n,
  params,
});
await api.post('/submittx', signed.bytes);
signer.destroy();
```

The plan is a pure function of its inputs and needs no key, so a send form can call `planSend` on every keystroke: the fee shown is the fee that gets signed.

What the planner guarantees, checked again by `checkPlanInvariants` before it returns:

- **Value is conserved** for ADA and every native asset: inputs = outputs + fee.
- **Native assets never go to the fee.** Leftover tokens always come back as change. If there is not enough ADA to carry them, the planner adds inputs, or fails with `INSUFFICIENT_ADA_FOR_CHANGE` and the exact `shortfall`.
- **Every output meets the ledger minimum** (`coinsPerUTxOByte × (160 + size)`), including a token recipient output (at least 1.5 ADA by default, more when the ledger needs it). Recipient and change values that would exceed `maxValueSize` are split across several outputs (`plan.recipients`, `plan.change`).
- **The fee is exact** — the ledger minimum for the signed size (fee-width fixed point, CBOR width boundaries, reference-script tiers included) — and below a ceiling (`maxFee`, default 5 ADA).
- ADA-only change too small to be an output is absorbed by one more ADA-only input when one exists, and only otherwise folded into the fee (`dustToFee`).
- UTXOs holding reference scripts are skipped unless you opt in and give their size. Script-locked and Byron-address UTXOs are skipped.
- **Scale:** selection is linear and stops with `TX_TOO_LARGE` as soon as a transaction cannot fit. `maxAda` and `all` spend as many UTXOs as fit in one transaction (richest first) and report the rest in `plan.leftoverUtxos`.

`signPlan` re-checks the plan from scratch first (tx id recomputed from the body bytes, every invariant, each output paying the address of its role), requires the change address to belong to a signer, and signs only with keys whose hash the plan requires (`KEY_MISMATCH` otherwise).

### Sign a message (CIP-8 / CIP-30 `signData`)

```ts
import {
  signData,
  verifyData,
  resolveDataSigner,
} from '@runonflux/cardano-core';

// addr may be bech32, base58, hex (the CIP-30 wire format) or bytes.
const signer = resolveDataSigner(addr, {
  payment,
  stake,
  addresses: [baseAddress, rewardAddress], // the wallet's own addresses
  network: 1,
}); // ADDRESS_NOT_PK unless addr is exactly one of them and its credential is the key
const { signature, key } = await signData(addr, payloadHex, signer);
verifyData({ signature, key }, { address: addr, payload: payloadHex }).valid; // true
```

The COSE_Sign1 and COSE_Key bytes are identical to cardano-message-signing's. With `expected.address`, `verifyData` is only valid when the address's credential is the signing key.

### Sign a dapp transaction (CIP-30 `signTx`)

```ts
import {
  signTxWitnessSet,
  describeTransaction,
  requiredSigners,
} from '@runonflux/cardano-core';

// Show before signing. Only exact wallet addresses count as own.
const summary = describeTransaction(txHex, {
  addresses: [baseAddress, rewardAddress],
});
// totalOutflow(summary): outputs to others + fee + deposits + proposal deposits + donation.
// totalInflow(summary): withdrawals + refunds. summary.warnings, pools, dreps, foreignRewardAccounts.
const needs = requiredSigners(txHex, { paymentKeyHash, stakeKeyHash });
const witnessSetHex = await signTxWitnessSet(
  txHex,
  needs.stake ? [payment, stake] : [payment],
  // required: the wallet's addresses; ownUtxos (with values) to value collateral
  { ownAddresses: [baseAddress, rewardAddress], ownUtxos },
);
```

The transaction id is blake2b-256 of the body's **original bytes**. A dapp's body is never re-encoded, so non-canonical encodings (indefinite lengths, wide integer heads, untagged sets) hash exactly as the chain does. Transactions with body fields or certificate kinds this library does not know (future eras) are refused unless you pass `{ allowUnknownFields: true }`.

**Collateral.** `is_valid` is not covered by the signature, so a dapp can make its scripts "fail" after you sign; the ledger then keeps the collateral and pays the collateral return. `signTxWitnessSet` refuses (`COLLATERAL_AT_RISK`) when the return does not pay one of `ownAddresses`; when the lovelace at risk cannot be known (no stated `total_collateral` and a collateral input missing from `ownUtxos`); or when it exceeds the cap. The default cap comes from the protocol parameters, never from the transaction: 1.5 × the largest fee a valid transaction can need, clamped to [5 ADA, 25 ADA] (`MAX_DEFAULT_COLLATERAL_CAP`), about 13.3 ADA on mainnet (`defaultCollateralCap(params)`; pass `params` for other networks, or `maxCollateralAtRisk` to set it without the clamp). `allowForeignCollateralReturn: true` accepts a return to someone else only for dapp-provided collateral (no input among `ownUtxos`, which must then be non-empty and list every UTXO at every address form the wallet can sign for); the cap still applies. `allowUnvaluedCollateral: true` signs collateral that cannot be valued (an input not among `ownUtxos`, no stated total) when the return is the wallet's own or absent, only when `ownUtxos` is given; set it only after telling the user the amount at risk is unknown. `describeTransaction(...).collateralAtRisk` is the amount to headline next to `totalOutflow`; `collateral` has the details.

### Other building blocks

- `decodeTransaction(bytes)`: every Conway body field (certificates with their deposits, pools and DReps; withdrawals; mint; voters; proposal deposits), witness-set summary, the original byte range of body, witness set, auxiliary data and each output. Inputs above 64 KiB are refused before decoding. Unknown future body keys are kept as opaque bytes. Duplicate keys are refused in the maps the wallet interprets; Plutus data and metadata stay opaque.
- `decodeCbor` / `encodeCbor`: RFC 8949 with source spans on every node and a core-deterministic mode.
- `parseAddress`, `parsePaymentAddress`, `addressToString`, `baseAddress`, `rewardAddress`, …: all CIP-19 types plus Byron.
- `rootKeyFromEntropy`, `derivePath`, `derivePublic`, `signExtended`, `localSigner`: Icarus keys (CSL `Bip32PrivateKey.from_bip39_entropy`) and BIP32-Ed25519 V2.
- `linearFee`, `referenceScriptFee`, `minAdaForOutput` (same algorithm and result as CSL's `min_ada_for_output`).
- `encodeUtxoHex`, `encodeValueHex`, `addressHex`, `rewardAddressHex`, `pickCollateral`: CIP-30 read methods.

Errors are `CardanoError` with a stable `code` (`INSUFFICIENT_FUNDS`, `INSUFFICIENT_TOKENS`, `INSUFFICIENT_ADA_FOR_CHANGE`, `OUTPUT_BELOW_MIN_ADA`, `NOT_A_PAYMENT_ADDRESS`, `WRONG_NETWORK`, `FEE_TOO_HIGH`, `KEY_MISMATCH`, `ADDRESS_NOT_PK`, `INVALID_CBOR`, …). Planner failures are `InsufficientFundsError` with a `shortfall` in lovelace.

## Protocol parameters

`planSend` needs live `coinsPerUtxoByte` and fee constants. `parseBlockfrostParams` / `parseKoiosParams` read the usual backend shapes and reject values outside sanity bounds (`DEFAULT_PARAM_BOUNDS`), so a lying backend cannot make fees or min-ADA absurd. `MAINNET_DEFAULTS` holds the epoch-658 values as a fallback.

## Scope

In: single-address wallets with key credentials, ADA and native-asset payments, CIP-8, CIP-30 helpers, decoding any Shelley-through-Conway transaction.

Not (yet) in: building Plutus spends, collateral for our own transactions, certificates and governance actions, bootstrap (Byron) witnesses for spending from Byron addresses, hashed CIP-8 payloads, Ledger/Trezor signing (the async `Signer` interface is ready for it).

## Verification

```bash
yarn test     # unit tests, CSL/CMS parity (200 seeded cases per property), 3,110-tx mainnet corpus
yarn oracle   # the same with 10,000 seeded cases per property
yarn corpus   # re-fetch the mainnet corpus from Koios
```

cardano-serialization-lib and cardano-message-signing are **dev dependencies only**, used as oracles. See [AUDIT.md](./AUDIT.md) for what is verified and what is not.

## License

MIT
