# Phase 5 Day 60 — bump-seed-canonicalization Gate 1 + Gate 2 (CATALOG 10/10 COMPLETE)

Date: 2026-06-09
Spec: [docs/invariants/bump-seed-canonicalization.md](invariants/bump-seed-canonicalization.md) §9 + §10
Prior: [Day 59 realloc-race Gate 1 + Gate 2 + Solana runtime finding](phase5-day59-realloc-race-gates.md)
Framing: **Phase 2.5 OSS catalog-completion** — null Gate 2 is the
expected publishable result; framing transition inherited verbatim
from cpi-reentrancy.md §10 / realloc-race.md §10. Demonstrated
load-bearing on Day 58 (cpi-reentrancy) and Day 59 (realloc-race).

## Result — Gate 1 PASS, Gate 2 0/75,547

5th and final High-tier invariant landed end-to-end in one session.
Phase 2.5 catalog **10/10 complete**.

## Gate 1 setup

Planted bug (programs/escrow/src/lib.rs):
```rust
pub fn unsafe_withdraw_with_bump(
    ctx: Context<UnsafeWithdrawWithBump>, amount: u64, bump: u8,
) -> Result<()> {
    let derived = Pubkey::create_program_address(
        &[b"vault", ctx.accounts.depositor.key().as_ref(), &[bump]],
        ctx.program_id,
    ).map_err(|_| EscrowError::InvalidAmount)?;
    require_keys_eq!(derived, ctx.accounts.vault.key(), EscrowError::InvalidAmount);
    // ... transfer lamports
    Ok(())
}
```

The bug is the missing canonical-bump check: any `bump` that yields
a valid PDA at any address passes `require_keys_eq!` as long as the
caller also supplies that PDA in the vault slot.

InstructionSpec carries `bump_seed_check: Some(BumpSeedCheckConfig
{ bump_data_offset: Some(16) })` — detector finds alt bump for the
vault seed prefix `[b"vault", depositor]`, pre-creates the alt PDA
with cloned canonical state, patches ix data byte 16 (after sighash
+ amount u64), substitutes alt PDA in AccountMeta, sends.

```bash
cd ~/src/solinv/examples/escrow-demo
cargo build-sbf --tools-version v1.52 --manifest-path programs/escrow/Cargo.toml
cd fuzz/escrow
cargo build --release --features invariant_bump_seed_canonicalization_only
cd ..
crucible run escrow invariant_bump_seed_canonicalization_only --release --timeout 30
```

## Gate 1 result

```
[FUZZ_FINDING] [bump-seed-canonicalization:Esrcw1111…]
  non-canonical bump 252 for account
  6ssKezycTCGTrt7bHmCGN1sZkSe9Ep8qZnieKkCd4kAk accepted
  (canonical was 5cKRWnW2Gi15XUREjNQYKjsuGWWZocJ2XP4KRt66PnW6,
   ix unsafe_withdraw_with_bump)
```

| Metric | Value |
|---|---:|
| Runtime | 30s |
| Executions | 10,926 |
| Detections | **228 (2.1%)** |
| Exec/sec | 358.5 |
| ok rate | 41.5% |
| Edges | 693/4,018 (17.2%) |

Lower detection rate than cpi-reentrancy (99.99%) or realloc-race
(99.99%) because the detector's substitution requires specific
fixture state: the canonical vault must exist (so cloning its state
succeeds), and the depositor signature must propagate through to
the alt-PDA path. Earlier iterations where the vault hasn't been
initialized yet skip cleanly. 228 detections is well past §9's
"≥1 violation in 30s" Gate 1 pass criterion.

## Gate 2 setup

Both Raydium SwapV2 specs now declare
`bump_seed_check: Some(BumpSeedCheckConfig { bump_data_offset: None })`.
`bump_data_offset = None` because SwapV2 doesn't carry a bump byte
in its instruction data; the detector substitutes the alt PDA in
the AccountMeta slot only.

```bash
cd ~/src/solinv/examples/raydium-amm-fuzz/fuzz/raydium_amm
cargo build --release --features invariant_bump_seed_canonicalization_only
cd ..
crucible run raydium_amm invariant_bump_seed_canonicalization_only --release --timeout 30 -j 4
crucible run raydium_amm invariant_bump_seed_canonicalization_only --release --timeout 30 -j 4
```

## Gate 2 result

| Campaign | Workers | Executions | Crashes | ok rate | Edges |
|---|---|---:|---:|---:|---|
| 1 | 4 | 45,806 | **0** | 191,818 / 263,643 = 72.8% | 629/14,696 (4.3%) |
| 2 | 4 | 29,741 | **0** | 198,817 / 248,679 = 79.9% | 629/14,696 (4.3%) |
| **Total** | — | **75,547** | **0** | — | — |

**0 violations across either campaign.** Edge saturation 629/14,696
(4.3%) — **identical** to cu-dos Day 38, unchecked-math Day 34,
cpi-reentrancy Day 58, realloc-race Day 59. Five different High-tier
invariants × same protocol × same coverage saturation across all
five runs.

Raydium AMM SwapV2's PDA is `amm_authority` (seeds = [b"amm authority"]),
verified by Raydium's `processor.rs` against the canonical
derivation. Alt-bump substitution gives a different `amm_authority`
pubkey; Raydium rejects with the standard owner/authority mismatch.
Detector correctly idles.

## Phase 2.5 cumulative calibration dataset (5 invariants — catalog complete)

| Day | Invariant | Mechanism | Exec | Violations |
|---|---|---|---:|---:|
| 34 | unchecked-math | state mutation (Bounded) | 15,380 | 0 |
| 38 | cu-dos | per-ix CU consumption | 25,650 | 0 |
| 58 | cpi-reentrancy | CPI call-tree logs | 27,573 | 0 |
| 59 | realloc-race | runtime err + post-state | 24,381 | 0 |
| **60** | **bump-seed-canonicalization** | **alt-PDA substitution** | **75,547** | **0** |
| | | **Total** | **168,531** | **0** |

Five distinct detection mechanisms, same hardened-production
surface, five null results. The catalog calibration backbone now
spans ~168K executions across 5 High-tier invariants × Raydium AMM
SwapV2. This is the empirical backbone of solinv's "honest tested-
and-found-nothing" framing for the OSS launch.

**Layer-of-responsibility scale across the 5 High-tier invariants**
(updated from Day 59 for the OSS catalog README):

| Invariant | Solana runtime defense | Protocol responsibility |
|---|---|---|
| unchecked-math | none | total |
| cu-dos | per-tx 200K cap only | total within cap |
| cpi-reentrancy | writable-account locks | partial (different-account/proxy) |
| realloc-race | near-total (rent check at tx commit) | intent only |
| **bump-seed-canonicalization** | **none** | **total (use find_program_address + store canonical bump)** |

bump-seed-canonicalization sits at the same "total protocol
responsibility" tier as unchecked-math — Solana's runtime provides
no defense against accepting a non-canonical bump. The Anchor
ecosystem's `seeds::canonical_bumps_only` default (since 0.29)
provides framework-level defense for Anchor programs, but Native
programs and pre-0.29 Anchor programs that opt out are fully
responsible.

## Catalog 10/10 — complete

| Tier | Invariant | Day |
|---|---|---|
| Critical | signer-skip | 1-13 |
| Critical | owner-skip | 13 |
| Critical | discriminator-skip | 11 |
| Critical | pda-forge | 16-17 |
| Critical | account-swap | 12-13 |
| High | unchecked-math | 31-34 |
| High | cu-dos | 35-38 |
| High | cpi-reentrancy | 58 |
| High | realloc-race | 59 |
| **High** | **bump-seed-canonicalization** | **60** |

Phase 2.5 plan from CLAUDE.md "Next session priorities" item #3
(catalog completion, Day 69-78) closed Day 60 — ~10 days ahead of
schedule. Items #1 (README rewrite, Day 53-54) and #2 (toolchain
fork → bytepoke helper, Day 55-57) already done.

**Next per CLAUDE.md Phase 2.5 schedule**: item #4 — **Public
launch prep** (Day 79-83) — security review, CONTRIBUTING.md,
README polish, security disclosure policy. The 5-invariant
calibration dataset now anchors the launch's "honest calibration"
narrative.

## Files changed Day 60

- `docs/invariants/bump-seed-canonicalization.md` (new, 700+ LOC,
  10 sections inc. §9/§10 framing inheritance from realloc-race
  → cpi-reentrancy).
- `crates/solinv-fuzz/src/capability.rs` — added
  `BumpSeedCheckConfig` + `bump_seed_check:
  Option<BumpSeedCheckConfig>` field on InstructionSpec.
- `crates/solinv-fuzz/src/lib.rs` — re-export BumpSeedCheckConfig
  from top + prelude.
- `crates/solinv-core/src/invariants/bump_seed_canonicalization.rs`
  (new, 200+ LOC + 5 unit tests). Includes pub `find_alt_canonical_pda`
  helper for testability.
- `crates/solinv-core/src/invariants/mod.rs` — register module +
  catalog 10/10 note.
- `crates/solinv-core/src/invariants/regression_tests.rs` — add the
  new field to the base fixture helper.
- 16 InstructionSpec literals across 10 example fuzz crates +
  `escrow-demo/programs/escrow/src/lib.rs` (planted ix +
  UnsafeWithdrawWithBump context) +
  `escrow-demo/fuzz/escrow/src/main.rs` (harness wiring +
  withdraw_with_bump_spec + #[invariant_test] fn) +
  `examples/raydium-amm-fuzz/fuzz/raydium_amm/src/main.rs` (Gate 2
  enrollment + #[invariant_test] fn).
- `examples/escrow-demo/fuzz/escrow/Cargo.toml` +
  `examples/raydium-amm-fuzz/fuzz/raydium_amm/Cargo.toml` — new
  `invariant_bump_seed_canonicalization_only` features.
