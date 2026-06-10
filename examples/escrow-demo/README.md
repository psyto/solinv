# escrow-demo — solinv Critical-tier acceptance test

An Anchor program with **five planted bugs**, one per Critical
invariant, used as solinv's end-to-end acceptance fixture. Days 5-13
of Phase 1 built this up; Day 13 closed the contract with all five
invariants detecting their respective bugs across isolated campaigns.

It doubles as the canonical reference harness for new contributors
adopting solinv on their own protocols.

## Layout

```
escrow-demo/
├── programs/escrow/   # Anchor program — safe + unsafe handlers
└── fuzz/escrow/       # Crucible fuzz harness — fixture + 7 invariant variants
```

## Program — safe and unsafe handlers

The escrow program implements a two-vault timelock (mint A in / mint B
out at unlock slot, etc.). It exposes both **safe** handlers and
**deliberately broken** handlers used to plant each Critical bug.

| Handler | Purpose | Planted bugs |
|---|---|---|
| `deposit` | safe — depositor adds funds | none |
| `withdraw` | safe — depositor recovers before unlock (boundary bug `<=` vs `<`) | timelock (non-solinv) |
| `claim` | safe — beneficiary claims at unlock | none |
| `unsafe_withdraw` | depositor recovers — all five Critical checks omitted | **signer-skip** (depositor is `UncheckedAccount`, not `Signer`), **discriminator-skip**, **pda-forge** (no `seeds = […]`), **account-swap** (no `has_one = depositor`). Owner-skip attempted here Days 10-12 but failed because Solana runtime blocks lamport debits on non-program-owned accounts before the handler runs. |
| `unsafe_set_amount_from_source` | reads `source.data`, writes to `target.amount` | **owner-skip** (Day 13 — read-only attack vector that bypasses the runtime debit-block) |
| `unsafe_accumulate_yield` | wrapping `vault.amount * rate_bps / 10_000 + vault.amount` — pretends to compound interest | **unchecked-math** (Day 33 — wrap on multiply / add corrupts `vault.amount` to large garbage post-state) |
| `unsafe_compute_dos` | O(n) wrapping-arithmetic loop on attacker-controlled `iterations: u32` | **cu-dos** (Day 37 — single ix consumed > declared `cu_budget`, demonstrating compute-budget DoS surface) |

See `programs/escrow/src/lib.rs` for the full source and inline
comments on each planted bug.

## Harness — 7 invariant variants

Cargo features select which invariant runs each campaign. Each is
defined in `fuzz/escrow/src/main.rs`:

| Variant | Detects | Notes |
|---|---|---|
| `invariant_escrow` | timelock boundary bug | original pre-solinv harness; documents the `<=` bug |
| `invariant_signer_skip_only` | signer-skip | Day 11 fee-payer separation |
| `invariant_owner_skip_only` | owner-skip | Day 13 read-only attack ix |
| `invariant_discriminator_skip_only` | discriminator-skip | Day 10 |
| `invariant_pda_forge_only` | pda-forge | Day 12 isolated variant unmask |
| `invariant_account_swap_only` | account-swap | Day 12 multi-trader fixture |
| `invariant_unchecked_math_only` | unchecked-math | Day 33 — first High-tier variant; Gate 1 of the kill criterion |
| `invariant_cu_dos_only` | cu-dos | Day 37 — second High-tier variant; Gate 1 of the cu-dos kill criterion |
| `invariant_solinv_acceptance` | all 5 Critical (first-violation-wins per iteration) | combined contract |

Detection rates:

| Variant | exec/sec | Violation rate | Source |
|---|---|---|---|
| signer_skip | ~500 | high | Day 13 |
| owner_skip | 924 | ~100% | Day 13 |
| discriminator_skip | ~530 | high | Day 13 |
| pda_forge | 1,512 | ~20% (random-pubkey strategy needs passes) | Day 13 |
| account_swap | 1,267 | ~100% | Day 13 |
| unchecked_math | 1,173 | ~4.4% (1,555 / 34,971 in 30s) | Day 33 |
| cu_dos | 795 | ~100% (23,999 / 24,000 in 30s; data_sample-pinned iterations) | Day 37 |

## Prerequisites

- `crucible` CLI on `PATH` — `cargo install --path
  crates/crucible-fuzz-cli` from the Crucible repo root.
- Solana platform-tools **v1.52 or later**. Earlier versions ship
  rustc 1.84 which cannot build the dependency tree (edition2024). If
  `cargo-build-sbf` reports `feature edition2024 is required`, pass
  `--tools-version v1.52`.

## Build and run

From this directory:

```bash
# 1. Build the program → target/deploy/escrow.so
cargo build-sbf --tools-version v1.52 \
    --manifest-path programs/escrow/Cargo.toml

# 2. Run each Critical invariant in isolation (recommended for triage)
for inv in signer_skip owner_skip discriminator_skip pda_forge account_swap; do
    crucible run escrow invariant_${inv}_only --release --timeout 30
done

# Or the combined acceptance variant
crucible run escrow invariant_solinv_acceptance --release --timeout 60
```

Example owner-skip output (truncated):

```
[owner-skip:Esrcw1111…] ix unsafe_set_amount_from_source succeeded
with account 0 owned by 11111111111111111111111111111111
instead of expected Esrcw1111…;
real pubkey 2RvPfFKU… → fake pubkey 13JpWEc…
```

## Inspect and replay crashes

```bash
crucible list escrow invariant_owner_skip_only            # list all crashes
crucible show escrow invariant_owner_skip_only <crash-id> # full action trace
crucible tmin escrow invariant_owner_skip_only <crash-id> # minimize repro
```

## Fix the bugs (verify negative cases)

To verify solinv's invariants are not false-positive, fix each
planted bug in `programs/escrow/src/lib.rs` and rerun the matching
campaign:

- **owner-skip**: in `UnsafeSetAmountFromSource`, change
  `pub source: AccountInfo<'info>` to `pub source: Account<'info,
  Vault>`. → `invariant_owner_skip_only` reports 0.
- **signer-skip**: in `UnsafeWithdraw`, change
  `pub depositor: UncheckedAccount<'info>` to
  `pub depositor: Signer<'info>`. → `invariant_signer_skip_only` reports 0.
- **discriminator-skip / pda-forge / account-swap**: restore the
  corresponding constraints on `UnsafeWithdraw` (typed `Account<'info,
  Vault>` with `seeds = […]` and `has_one = depositor`). Each
  fix flips its respective `invariant_<name>_only` campaign to 0.
- **Timelock boundary**: change `<=` to `<` in `withdraw`'s slot
  check. → `invariant_escrow` reports 0.

The combined `invariant_solinv_acceptance` campaign should reach 0
violations only after all five Critical planted bugs are fixed.
