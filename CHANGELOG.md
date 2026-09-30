# Changelog

## 0.1.0 — 2026-09-30

First release: the pure-TypeScript replacement for cardano-serialization-lib and cardano-message-signing in ZelCore. Includes the fixes from all five rounds of independent review, 2026-09-29 and 2026-09-30 ([AUDIT.md](./AUDIT.md) §9).

### Added

- **Keys:** CIP-3 Icarus root from entropy, BIP32-Ed25519 V2 private and public derivation, extended-key Ed25519 signing, strict verification, `localSigner` with `destroy()`, and an async-capable `Signer` interface.
- **Addresses:** every CIP-19 type (base, pointer, enterprise, reward) plus Byron (base58, CBOR, CRC-32, protocol magic). `parsePaymentAddress` refuses stake addresses and network mismatches.
- **CBOR:** RFC 8949 decoder with source spans, depth limit and duplicate-key rejection; encoder with a core-deterministic mode.
- **Transactions:** Conway decoder that keeps the original bytes of every part; encoder byte-identical to CSL 14 (tag-258 sets, sorted inputs, canonical multi-assets).
- **Fees:** linear fee, tiered reference-script fee, `minAdaForOutput` identical to CSL.
- **Planner:** `planSend` with `amount`, `maxAda` and `all` modes, token-first selection, multi-asset change (split at `maxValueSize`), exact fee, invariant checks and typed errors with a shortfall. `signPlan` signs only with the required keys.
- **CIP-8 / CIP-30:** `signData` / `verifyData` byte-identical to cardano-message-signing, `signTxWitnessSet`, `requiredSigners`, `resolveDataSigner`, UTXO/value/address encoders, `pickCollateral`, `describeTransaction`.
- **Parameters:** Blockfrost and Koios parsers with sanity bounds; `MAINNET_DEFAULTS`.

### Fixed (relative to ZelCore's CSL code)

- Min-ADA priced at the live 4310 lovelace/byte instead of 1000.
- Token sends no longer fold leftover assets into the fee.
- CIP-8 signing checks that the address belongs to the signing key.

### Security (independent review, 2026-09-29)

- `describeTransaction`: own outputs are exact wallet addresses only; addresses reusing our payment key with another stake part are flagged and counted as outflow. Reports deposits, refunds, proposal deposits, donation, own/foreign withdrawals, pools, DReps and foreign reward accounts. `totalOutflow` includes deposits, proposals and donation; new `totalInflow`.
- `resolveDataSigner` signs only for an address that is byte-for-byte one of the wallet's addresses, on its network. **Breaking:** takes `{ payment, stake?, addresses, network? }`.
- `verifyData` with `expected.address` also requires the address's credential to be the signing key; COSE_Key `alg` must be EdDSA.
- `decodeTransaction` refuses inputs above 64 KiB (`maxBytes`); duplicate-key tracking is linear; duplicates are refused only in structural maps, so Plutus data and metadata keep ledger-legal duplicates.
- `signTxWitnessSet` refuses unknown body fields unless `allowUnknownFields`; merged existing witnesses must verify.
- `signPlan` re-verifies the plan (tx id, invariants, output roles) and requires the change address to belong to a signer.
- `requiredSigners` covers pool owners, voters and DRep/committee certificates (new `drep` flag).
- `parsePaymentAddress` refuses Byron redeem-type addresses and attributes above 64 bytes; an explicit Byron mainnet magic parses as mainnet.
- Planner: linear selection with an immediate `TX_TOO_LARGE`; `maxAda`/`all` spend what fits and report `leftoverUtxos`; recipient values split across outputs (`plan.recipients`); u64 overflow is `VALUE_TOO_LARGE`; the fee settles on the lowest fixed point.
- Keys: typed errors for invalid public points; derivation and signing zeroise key-bearing buffers; `localSigner` enforces CSL's clamping rule on 96-byte keys.
- New: `parseAddressInput` (bytes, hex, bech32, base58) used by every entry point; `assertUniqueKeys`, `MapKeyTracker`, `DEFAULT_MAX_TX_BYTES`.

### Security (independent review, round 2, 2026-09-30)

- **Collateral theft** (high): `describeTransaction` reports `collateral` (the return as a described output, total, input count, what is at risk) whatever `is_valid` says, with loud warnings; `signTxWitnessSet` refuses a foreign or missing collateral return (`COLLATERAL_AT_RISK`) unless `allowForeignCollateralReturn`. New options `ownAddresses` and `ownUtxos`; new `collateralRisk()`.
- Byron: any explicit protocol magic is testnet (as the ledger decides); the attribute limit uses the ledger's HD-payload-plus-unknown-attributes measure.
- Hand-built UTXOs with upper-case hashes are normalised; malformed hashes are `INVALID_INPUT`.
- `signPlan` options `expectedChangeAddress`, `ownAddresses`, `maxFee`, `params`; `planSend` option `ownAddresses`; new error code `CHANGE_ADDRESS_NOT_OWN`.
- Unknown certificate kinds are refused like unknown body fields; `describe.unknownCertificates`.
- Amount mode retries richest-first when the preferred selection does not fit.
- The fee is the true minimum at CBOR width boundaries; `plan.warnings` flags script recipients.

### Breaking (relative to the pre-release API)

- `planSend` requires `ttl` (`bigint`, or `null` for no expiry).
- `rootKeyFromEntropy` / `accountKeysFromEntropy` accept only 16, 20, 24, 28 or 32 bytes.
- `assertUniqueKeys` requires its `source` argument.

### Security (independent review, round 3, 2026-09-30)

- **Collateral destruction** (medium): new `assessCollateral` / `collateralRisk(tx, { ownAddresses, ownUtxos?, maxCollateralAtRisk? })`. The lovelace at risk (`total_collateral`, or valued inputs minus an own return) must be within a cap and must be knowable (cap and no-return rule as revised in round 4, below). `describeTransaction` exposes `collateralAtRisk` and puts the amount in the warning; `collateral` now reports `returnIsOwn`, `atRiskLovelace`, `cap` and `refusal` (replacing the `atRisk` union).
- Obsolete certificate tags 5 and 6 are refused as `UNSUPPORTED`.
- `maxAda` / `all` over hundreds of multi-asset UTXOs: ~35× faster.

### Breaking (round 3)

- `planSend` requires `ownAddresses`.
- `signPlan` requires `{ expectedChangeAddress and/or ownAddresses, maxFee, params }`.
- `signTxWitnessSet` requires `{ ownAddresses }`; `ownUtxos` is now `Utxo[]` (with values), and `maxCollateralAtRisk` is new.
- `describeTransaction(...).collateral.atRisk` is replaced by `atRiskLovelace` / `returnIsOwn` / `cap` / `refusal`; new top-level `collateralAtRisk`.

### Security (independent review, round 4, 2026-09-30)

- **Collateral cap from the protocol parameters** (low–medium): the default cap was max(5 ADA, 3 × the transaction's fee), which a dapp could raise by naming a large fee paid from its own inputs. It is now `defaultCollateralCap(params)` = 1.5 × `maxTransactionFee(params)`, clamped to [5 ADA, 25 ADA] (round 5) — 13,327,463 lovelace on mainnet — and never depends on the transaction. New `maxTransactionFee`, `MAX_REF_SCRIPT_SIZE_PER_TX`, `MAINNET_EXECUTION`, `defaultCollateralCap`; `ProtocolParams` gains optional `priceMem`, `priceStep`, `maxTxExMem`, `maxTxExSteps`, read by both parsers and bounded by `DEFAULT_PARAM_BOUNDS`; `parseRational` accepts exponent notation. `signTxWitnessSet` takes `params`; `describeTransaction`'s `params` accepts any subset of `ProtocolParams`.
- Old-style collateral (no return, no `total_collateral`) is signed when `ownUtxos` values it within the cap.
- `allowForeignCollateralReturn` waives only the foreign-return rule, and only for collateral none of whose inputs are among `ownUtxos` (which it now needs, non-empty since round 5); the cap stays in force.
- `signPlan` with `params: null` is `INVALID_INPUT`.

### Security (independent review, round 5, 2026-09-30)

- The default collateral cap never exceeds `MAX_DEFAULT_COLLATERAL_CAP` (25 ADA, new export), however high parameters within `DEFAULT_PARAM_BOUNDS` would put it; an explicit `maxCollateralAtRisk` is not clamped.
- `allowForeignCollateralReturn` is refused when `ownUtxos` is empty (`COLLATERAL_AT_RISK`); `ownUtxos` must list every UTXO at every address form the wallet can sign for.
