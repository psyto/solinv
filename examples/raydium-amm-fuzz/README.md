# raydium-amm-fuzz — Native production validation

Raydium AMM v0.3.1 harness covering **SwapBaseInV2** (tag 16) and
**SwapBaseOutV2** (tag 17). Phase 2 Days 18-21 result: **25,383
attacks across 4 Critical invariants × 2 ix → 0 violations**. This is
the canonical "production clean-surface" example — invariants confirm
absence of bugs on hardened production code.

`discriminator-skip` is N/A for Native programs (no Anchor-style
8-byte sighash); the other four Critical invariants apply.

## Why "0 detections" is the positive outcome

Day 13 escrow-demo already proved solinv's invariants are sensitive
(detection rates 20-100% on planted bugs). Day 20-21 on Raydium proved
they don't false-positive on production code with hardened account
validation. Both directions of solinv's value are validated.

See [`docs/phase2-day20-raydium-triage.md`](../../docs/phase2-day20-raydium-triage.md)
and [`docs/phase2-day21-raydium-extension.md`](../../docs/phase2-day21-raydium-extension.md)
for the full triage logs.

## External program dependency

Raydium AMM source is Apache-2.0 but kept external to avoid bundling.
Clone separately:

```bash
git clone https://github.com/raydium-io/raydium-amm.git ~/src/raydium-amm
cd ~/src/raydium-amm/program
cargo build-sbf
```

This produces `~/src/raydium-amm/target/deploy/raydium_amm.so`. The
harness loads it via absolute path — see `RAYDIUM_AMM_SO_PATH` in
`fuzz/raydium_amm/src/main.rs` and update if cloned elsewhere.

## Layout

```
raydium-amm-fuzz/
└── fuzz/raydium_amm/
    ├── Cargo.toml          # opt-out of solinv workspace
    └── src/main.rs         # RaydiumAmmFixture + 2 InstructionSpec
```

## Wire format

Raydium AMM is Native and uses **custom byte packing** — not Borsh:

- `data[0]` = u8 enum tag (0-17)
- `data[1..]` = LE primitives in declaration order
- `Option<T>` = 0 bytes if `None` / payload-only if `Some`
  (no discriminant byte — non-standard, see
  `raydium-amm/program/src/instruction.rs:686`)

Solinv's `ix_sighash()` helper does **not** apply. Build `data`
manually with `data.push(tag)` then concatenate LE primitives. The
`raw_call` + AccountMeta flow is identical to the escrow-demo Day 15
pattern.

## Clone-and-mutate: real mainnet pool fixture

By default the fixture hand-crafts a healthy `AmmInfo`. With the
`mainnet_snapshot_fixture` feature, the economic parameters (fees, lot
sizes, order/depth) instead come from a **real Raydium AMM v4 SOL-USDC
pool** committed under `snapshots/accounts/`, so the fuzzer exercises the
pool config real users trade against rather than hand-guessed values.

The snapshot is produced once from mainnet and cached for offline,
reproducible runs via [`solinv-corpus`](../../crates/solinv-corpus):

```rust
// fetch + cache a live pool as a committed fixture (network, one-time)
let snap = solinv_corpus::account::clone_account(
    solinv_corpus::account::MAINNET_BETA,
    std::path::Path::new("snapshots"),
    &pool_pubkey,
)?;
```

`amm_info_baseline()` (feature-gated) casts the 752-byte snapshot to
`AmmInfoMirror`; `setup()` then rewires the cross-reference fields
(vaults / mints / decimals / nonce) to the local synthetic graph so the
swap still executes — only the economic params come from production.

To probe **adversarial edge states**, perturb the baseline before
injection (`AccountSnapshot::data_mut()` + the byte writers in
`solinv-fuzz::bytepoke`, e.g. drive a reserve or fee field to an
extreme) — the states a healthy mainnet clone never reaches on its own.
Refresh the committed snapshot by deleting
`snapshots/accounts/<pool>.json` and re-running `clone_account`.

**Result** (`unchecked-math`, real SOL-USDC pool fixture, 60s × 2
workers): **~8,580 executions / ~237,000 actions → 0 violations.** The
invariant holds on real production pool config, not just the synthetic
baseline — the "tested and found nothing on hardened production" result
extended to live mainnet state. Reproduce:

```bash
RAYDIUM_AMM_SO=/path/to/raydium_amm.so \
  cargo build --release \
  --features mainnet_snapshot_fixture,invariant_unchecked_math_only
crucible run raydium_amm invariant_unchecked_math_only \
  --binary-in target/release/invariant_test \
  --program-so /path/to/raydium_amm.so --timeout 60 -j 2
```

## Solinv-coverage notes

| Invariant | Coverage point in Raydium |
|---|---|
| signer-skip | `processor.rs:3053` — explicit signer check |
| owner-skip | `AmmInfo::load_mut_checked` + SPL Token `unpack` enforce owner |
| pda-forge | `processor.rs:3063` — `authority_id` PDA re-derivation |
| account-swap | vault-key equality + SPL signer-check |

Day 19 surfaced a false-positive on account-swap (the AMM's
`user_destination` account is user-controlled by protocol design).
Resolved Day 20 by encoding "user-controlled" semantics into the
per-ix `swap_alternates` declaration — see Day 20 triage doc.

## Run

```bash
cd ~/src/solinv/examples/raydium-amm-fuzz

crucible run raydium_amm invariant_swap_base_in_v2_only  --release --timeout 30 -j 2
crucible run raydium_amm invariant_swap_base_out_v2_only --release --timeout 30 -j 2
```

Expected (Day 21 regression matrix):

| Invariant | Crashes | Executions | Wall |
|---|---|---|---|
| signer_skip       | **0** |  9,199 | 30s |
| owner_skip        | **0** |  1,784 | 51s |
| pda_forge         | **0** | 11,222 | 30s |
| account_swap      | **0** |  3,178 | 45s |

## Untested surfaces

- `Deposit` (tag 3, 14 accounts)
- `Withdraw` (tag 4, 20 accounts)
- `SwapBaseIn` / `SwapBaseOut` legacy (tags 9 / 11, 18 accounts each
  with orderbook integration)

Day 21 analysis projected ~1.5 days of work for these with expected
yield = 0 detections (same processor validation infrastructure as
SwapV2). Deferred unless solinv adds new invariants that change the
prior.
