//! # solinv-corpus
//!
//! Mainnet corpus seeder. Ingests real Solana transactions targeting
//! a given program from Triton Yellowstone gRPC or Helius LaserStream,
//! producing seed corpus for coverage-guided fuzzing.
//!
//! Mainnet-realistic corpus is the key differentiator vs Crucible/Trident
//! random byte fuzzing — exercises actual state spaces protocols see in
//! production rather than synthetic inputs.
//!
//! Pipeline:
//! 1. Subscribe to Yellowstone gRPC filtered to target program
//! 2. Ingest txs since specified slot (or LATEST)
//! 3. Persist to local `.solinv/cache/<slot>/` for re-use
//! 4. Expose iterator API to `solinv-fuzz` as seed corpus
