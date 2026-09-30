# Oracles

cardano-core has no Rust oracle binary. The differential oracles are the libraries it replaces, installed as **dev dependencies only** and pinned to the versions ZelCore ships today:

| Oracle                                     | Version | Used for                                                                                                                                                                           |
| ------------------------------------------ | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@emurgo/cardano-serialization-lib-nodejs` | 14.1.2  | keys, derivation, signatures, addresses, value/output/body/witness-set/transaction bytes, `min_ada_for_output`, `min_fee`, `FixedTransaction` tx ids, balance checks of every plan |
| `@emurgo/cardano-message-signing-nodejs`   | 1.1.0   | COSE_Sign1 / COSE_Key bytes of `signData`                                                                                                                                          |
| Cardano mainnet via Koios                  | —       | 3,110 real transactions (`test/fixtures/mainnet-corpus.bin.gz`): tx id from the original body bytes must equal the on-chain hash                                                   |

`yarn test` runs every property with 200 seeded cases (seeds are fixed, so failures reproduce). `yarn oracle` sets `CARDANO_ORACLE_CASES=10000`. `yarn corpus` re-fetches the corpus (see `scripts/fetch-corpus.mjs`).

The oracles are never imported from `src/` and are not in the published package.
