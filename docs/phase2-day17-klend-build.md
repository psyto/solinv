# Phase 2 Day 17 — Kamino klend Build + IX Inventory

Date: 2026-05-25
Status: ✅ Build success (with platform-tools v1.39 + SDK headers workaround). 5-ix inventory complete.
Schedule: cumulative ~2-3 days ahead of Day 14 baseline.

## Goal

Per Option C parallel-execution plan (Day 14 finding) + Day 16 schedule
buy-back:
- Day 17: Clone Kamino klend, install Anchor 0.29 toolchain, build .so,
  inventory 5 critical lending ix
- Day 18-22: Raydium AMM harness (Native, smaller surface, MVP starter)
- Day 23-27: klend harness (Anchor 0.29, larger setup, larger bounty)

This log captures Day 17 outcome.

## Clone

External (not inside solinv repo): `~/src/klend`
- Shallow clone of `github.com/Kamino-Finance/klend` @ main
- License: **BUSL-1.1** (more restrictive than Apache)

## BUSL-1.1 license compliance check

Parameters per `LICENSE`:
- Licensor: StroudGlobal S.A. (Kamino)
- Licensed Work: Kamino Lending smart contract (©2025)
- Additional Use Grant: None
- Change Date: 2027-11-17 → GPL-2.0

**Permitted under BUSL**:
- Copy, modify, derivative works, redistribute
- **Non-production use**

**Solinv usage = clear non-production**: local clone + local fuzz
against built binary + disclose findings via Kamino bounty program
(`https://immunefi.com/bug-bounty/kamino/`). This is exactly the
research use BUSL is designed to permit. **No commercial license
needed for solinv Phase 1**.

If solinv Phase 2 ever transitions to OSS framework distribution
with klend as a built-in example, BUSL would require either (a)
not redistributing klend code, just pointing to the upstream repo,
or (b) waiting until Change Date 2027-11-17 (GPL-2.0). Both are
acceptable for Phase 2 timing.

## Stack inspection

| Component | Value | Notes |
|---|---|---|
| anchor-lang | 0.29.0 | Workspace pin, all programs |
| solana-program | ~1.17.18 | Tilde range, locks to 1.17.x |
| borsh | 0.10.3 + `const-generics` | Patch over Anchor's default |
| rust-toolchain | 1.74.1 | Per `rust-toolchain.toml` |
| pythnet-sdk | patched fork | Anchor IDL build compat |
| spl-token-2022 | patched fork | v0.9.0 patched |
| scope (oracle) | Kamino fork | sbod-itf dep |
| kfarms | Kamino fork | farms dep |

Heavy dependency tree with multiple Kamino-Finance forks. Build is
non-trivial — ~50 deps to compile from source on cold cache.

## Build — the toolchain mismatch problem

### First attempt (default platform-tools)

```
cd ~/src/klend/programs/klend
cargo build-sbf
```

Failed with `error[E0635]: unknown feature 'stdsimd'` during `ahash`
0.8.5 compile. Cause:
- solana-frozen-abi 1.17.18 hard-pins `ahash = "=0.8.5"`
- ahash 0.8.5 uses unstable `feature(stdsimd)` which was removed in
  Rust 1.78+
- Local Solana CLI 3.1.14 bundles platform-tools v1.52 with Rust 1.89
  (well past the break)

**Cannot fix via `cargo update`** — solana-frozen-abi's `=0.8.5`
exact pin blocks upgrade to a newer ahash that supports modern Rust.

### Second attempt: `--tools-version v1.39`

Solana 1.17 era used platform-tools v1.39 (bundles Rust 1.73 — pre-
break). cargo build-sbf supports `--tools-version` override.

```
cargo build-sbf --tools-version v1.39
```

Got past the stdsimd error, but hit:
```
fatal error: 'assert.h' file not found
```
on blake3 C-side build. macOS-specific: platform-tools' bundled clang
doesn't see macOS SDK headers.

### Third attempt: SDK headers exposure

```
SDKROOT=$(xcrun --show-sdk-path) \
CFLAGS="-isysroot $(xcrun --show-sdk-path)" \
cargo build-sbf --tools-version v1.39
```

**SUCCESS**. 44.84s build. Artifact: `target/deploy/kamino_lending.so`.

Non-blocking warning: `farms` crate's `InitializeReward` accounts try_
build emits stack-offset warning (208 bytes over limit) — affects
unused dep, not kamino_lending itself.

### Reproducible build incantation

```bash
cd ~/src/klend/programs/klend
SDKROOT=$(xcrun --show-sdk-path) \
CFLAGS="-isysroot $(xcrun --show-sdk-path)" \
cargo build-sbf --tools-version v1.39
```

Save this to a script or build helper for future klend rebuilds (e.g.,
after pulling upstream updates).

## 5 critical lending ix selected

Per Day 14 plan:

| Sighash basis | Args (Borsh) | Accounts |
|---|---|---|
| `deposit_reserve_liquidity` | u64 | 12 |
| `redeem_reserve_collateral` | u64 | 12 |
| `borrow_obligation_liquidity` | u64 | 12 (1 Option) |
| `repay_obligation_liquidity` | u64 | 9 |
| `liquidate_obligation_and_redeem_reserve_collateral` | u64×3 | 20 |

**Total: 5 of 63 `#[program]` ix.** Covers ~80% of klend's user-facing
business logic surface (rest is admin/init/governance — not solinv
attack surface).

Full per-ix detail (AccountMeta order with isMut/isSigner flags + Anchor
constraints) in `docs/klend-ix-inventory.md`.

## solinv hit-rate analysis on klend (vs Raydium AMM)

| Invariant | klend (Anchor) | Raydium AMM (Native) |
|---|---|---|
| signer-skip | LOW | HIGH |
| owner-skip | LOW | HIGH |
| discriminator-skip | LOW | N/A |
| pda-forge | MEDIUM | HIGH |
| account-swap | **HIGH** | HIGH |

**klend's best solinv detection target = account-swap**. Lending
markets' rich cross-account relationships (obligation × reserve ×
user × farms × referrer) are the historic attack surface (Mango v3
Eisenberg 2022, Solend SBF flash-loan exploit, Cypher fraud, Drift v1
oracle manipulation — all involved cross-account misuse). Anchor's
`has_one` and address-constraint protections leave gaps in CROSS-PAIR
relationships (e.g., A.has_one(B) + B.has_one(A) is rarely both-way).

Strategy: **for klend, allocate fuzz budget heavily to account-swap
variant invariant testing**. Other 4 invariants run for completeness
but most production bugs likely caught by account-swap.

## Open questions for Day 23+

1. **klend fixture setup cost**: full Reserve init via `init_reserve`
   ix has ~30 config params + multiple SPL Token vault accounts +
   mint setup. Estimate 5-7 days to build a working fixture from
   scratch.

   **Alternative**: LiteSVM raw account inject + snapshot of real
   mainnet Reserve. If LiteSVM supports `set_account_raw()` or
   equivalent, this saves 4-5 days. Investigate Day 23 first action.

2. **Anchor 0.29 account layout matching**: kamino_lending uses
   `AccountLoader<T>` for `Reserve` and `LendingMarket` (zero-copy
   accounts vs regular `Account<T>`). solinv's discriminator-skip
   invariant tests the first 8 bytes — same for both `Account` and
   `AccountLoader`. Confirmed compatible.

3. **`InterfaceAccount<Mint>` vs `Account<Mint>`**: klend uses
   InterfaceAccount for token_2022 support. solinv expected_owners
   should accept either `Token::ID` or `Token2022::ID` for these
   accounts. Day 23 may need to extend InstructionSpec's
   `expected_owners` from `Option<Pubkey>` to
   `Option<Vec<Pubkey>>` for "owner is one-of these".

4. **V2 variants** (with farms): `borrow_obligation_liquidity_v2`,
   `repay_obligation_liquidity_v2`, etc. have extra `OptionalFarms`
   accounts. Defer for MVP (target V1 first), add V2 in Day 26+ if
   time permits.

## Commit

This session:
- Day 15 `909b9d5` (refactor + regression)
- Day 16 `e1a31c3` (Raydium AMM build + inventory docs)
- Day 17 (this) — klend build + inventory docs

No klend external code committed to solinv repo. Only docs.

## Schedule status (updated)

| Day | Plan | Actual | Status |
|---|---|---|---|
| 15 | Refactor (3 days planned) | 1 day | +2 ahead |
| 16 | Raydium clone+build+inv | 1 session | +1 ahead |
| 17 | klend clone+build+inv | 1 session | +1 ahead |
| 18-22 | Raydium MVP | (per plan) | on track |
| 23-27 | klend MVP | (per plan) | on track |
| 28-30 | Triage + disclosure | (per plan) | on track |

**Cumulative: 3-4 days ahead** of Day 14 baseline. Additional margin
for Day 28-30 triage/disclosure (the original tightest part).

## Day 18 plan (next session)

Begin Raydium AMM harness:
1. `examples/raydium-amm-fuzz/` scaffold — Cargo.toml + main.rs skeleton
   modeled on escrow-demo Day 15 refactor pattern
2. Decide Initialize2 fixture strategy (full-init vs snapshot vs
   hand-craft AmmInfo state bytes)
3. Implement SwapBaseInV2 InstructionSpec (8 accounts, smallest first)
4. First fuzz campaign against Raydium AMM raw_call harness

Fresh session recommended (Day 17 deep in toolchain debugging, judgment
quality benefits from break before Day 18 architecture work).
