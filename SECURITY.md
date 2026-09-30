# Security policy

`@runonflux/cardano-core` builds and signs transactions that move real funds. Please report vulnerabilities privately.

## Reporting

Use GitHub's private vulnerability reporting on this repository (**Security → Report a vulnerability**) with a description, affected versions and a reproduction if possible. Please do not open a public issue for a suspected vulnerability.

## Supported versions

Only the latest published version receives security fixes while the library is pre-1.0.

## Threat model in one paragraph

The UTXO/parameter backend and any dapp that hands the wallet a transaction are untrusted. The library defends against:

- **Signing a different transaction than the dapp's.** The transaction id is hashed over the body's original bytes; nothing is re-encoded. Duplicate map keys, which would make a field ambiguous, are refused.
- **Losing assets or overpaying.** Plans conserve every asset, never fold tokens into the fee, meet the ledger minimum per output, price the fee exactly and refuse fees above a ceiling. Protocol parameters from a backend are bounds-checked.
- **Signing with the wrong key.** `signPlan` signs only with keys the plan requires. `resolveDataSigner` signs CIP-8 data only for an address whose credential is the signing key.

See [AUDIT.md](./AUDIT.md) for what is verified and what is not.

## Integrator obligations

- Show the user `describeTransaction(...)` (outputs to others, fee, warnings) before signing a dapp transaction.
- Fetch protocol parameters from a backend you control and parse them with `parseBlockfrostParams` / `parseKoiosParams`, which enforce bounds.
- Treat a submit timeout as "maybe broadcast": re-submit the identical signed bytes; never rebuild from different UTXOs.
- Keep entropy and extended keys out of long-lived objects, call `destroy()` on a `localSigner` when done, and provide `crypto.getRandomValues` on React Native (noble needs it only for key generation elsewhere; signing here is deterministic). JavaScript cannot guarantee zeroisation.
