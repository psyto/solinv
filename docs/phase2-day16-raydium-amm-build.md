# Phase 2 Day 16 — Raydium AMM Build + IX Inventory

Date: 2026-05-25
Status: ✅ Build success, ix inventory complete. Ready for Day 18-22 harness construction.
Schedule: Day 15 buy-back (1 day ahead of original plan).

## Goal

Per Option C parallel-execution plan (Day 14 finding):
- Day 16: Clone Raydium AMM, build .so, inventory 5-7 critical ix
- Day 17: Same for Kamino klend
- Day 18-22: Raydium AMM harness construction (raw_call pattern)

This log captures Day 16 outcome.

## Clone location

External (not inside solinv repo): `~/src/raydium-amm`
- Shallow clone of `github.com/raydium-io/raydium-amm` @ main
- License: Apache-2.0 (compatible with solinv private extraction)
- No code from external repo committed to solinv git history

## Toolchain compatibility — Solana 2.1 pin vs CLI 3.1

**Concern**: Raydium AMM pins `solana-program = "=2.1.0"` while local
Solana CLI is 3.1.14 + platform-tools v1.52 (Agave 3.x era).

**Outcome**: `cargo build-sbf` works without modification. 45-second
build, produces `target/deploy/raydium_amm.so` (667 KB). 3 harmless
warnings:
1. `unexpected cfg condition value: 'custom-heap'` — from old
   `solana_program_entrypoint` macro, not actionable
2. Same for `custom-panic` cfg
3. `non-local impl` from `num_derive::FromPrimitive` — deprecated
   pattern, also not actionable

Solana CLI's platform-tools v1.52 has backward compatibility with
solana-program 2.1.0 pin. No need to install Solana 2.1 alongside.

## Build artifact

```
~/src/raydium-amm/target/deploy/
├── raydium_amm-keypair.json  (228 bytes, build-local keypair, ignore)
└── raydium_amm.so            (667,256 bytes)
```

Solinv harness will reference this `.so` via absolute path or
relative-up path from `solinv/examples/raydium-amm-fuzz/`.

## Wire format finding: NOT Anchor, NOT Borsh — custom byte packing

Raydium AMM is **Native Solana program**. Wire format:
- `data[0]` = u8 instruction tag (enum discriminant 0-17)
- `data[1..]` = args as concatenated **little-endian primitives** in
  declaration order
- `Option<T>` is **0 bytes if None**, payload-only if Some — NO
  discriminant byte (per `pack()` at `instruction.rs:686`)

This is **non-standard** — even other Native programs typically use
Borsh. Harness needs custom encoder for each ix, NOT a generic Borsh
serializer.

**Solinv Day 15 raw_call pattern still applies**, just replace
`ix_sighash("name")` with a single `data.push(tag_byte)`. The rest
(AccountMeta construction, `raw_call(ix).signers(...).send()`)
unchanged.

## 6 ix selected for MVP (out of 18 total)

| Tag | Variant | Accounts | Why selected |
|---|---|---|---|
| 3 | Deposit | 14 | User-facing pool participation |
| 4 | Withdraw | 20 | User-facing exit, largest surface |
| 9 | SwapBaseIn | 18 | Legacy with orderbook, large surface |
| 11 | SwapBaseOut | 18 | Reverse swap |
| **16** | **SwapBaseInV2** | **8** | **Modern, minimum surface, MVP starter** |
| **17** | **SwapBaseOutV2** | **8** | **Modern reverse swap** |

Skipped: Initialize2 (21 accounts + OpenBook dep — too heavy for MVP);
all admin ix (governance, not solinv surface); deprecated ix
(Initialize, PreInitialize); SimulateInfo (view-only); MonitorStep
(state-machine internal).

**MVP starter**: SwapBaseInV2 (tag 16, 8 accounts). Smallest fixture
setup cost, modern dominant trading path, all 4 applicable solinv
Critical invariants active (signer/owner/pda-forge/account-swap).

## solinv invariant applicability — Native vs Anchor

| Invariant | Active on Raydium AMM? | Notes |
|---|---|---|
| signer-skip | ✅ | Native = manual `is_signer` check, full surface |
| owner-skip | ✅ | Native = manual owner check, full surface |
| discriminator-skip | ❌ | Native has no Anchor discriminator |
| pda-forge | ✅ | AMM authority is PDA-derived (`[AUTHORITY_AMM, [nonce]]`) |
| account-swap | ✅ | No `has_one` analog = full swap surface |

**4/5 Critical invariants active** vs typically 1-3 on Anchor programs.
Confirms Day 14 Native-vs-Anchor hit-rate insight quantitatively.

## Full inventory doc

See `docs/raydium-amm-ix-inventory.md` for:
- Full 18-ix enum table with tag bytes + account counts + arg layouts
- Per-ix detail for 6 MVP candidates (wire bytes + AccountMeta table)
- InstructionSpec construction recipe (Day 18+ ready)
- Fixture setup cost estimate + open question (full-init vs snapshot)

## Day 17 plan

Originally: Kamino klend clone + Anchor 0.29 toolchain install + build
+ 5-ix inventory.

Day 16 ran ahead of estimate (~3 hours actual vs full day estimated).
Day 17 timing on track. Tasks:

1. Clone `Kamino-Finance/klend` to `~/src/klend`
2. Determine Anchor 0.29 toolchain install requirement (likely via
   `cargo install --git ... --tag v0.29.0 anchor-cli`)
3. `anchor build` to produce klend `.so` + IDL JSON
4. Inventory 5 critical lending ix:
   - `deposit_reserve_liquidity`
   - `redeem_reserve_collateral`
   - `borrow_obligation_liquidity`
   - `repay_obligation_liquidity`
   - `liquidate_obligation`
5. Write `docs/klend-ix-inventory.md` + `docs/phase2-day17-klend-build.md`

## Day 18-22 plan (Raydium AMM harness — adjusted)

Updated from Day 14 plan based on Day 16 inventory:

- Day 18: `examples/raydium-amm-fuzz/` scaffold (Cargo.toml + harness skeleton)
  - Determine Initialize2 strategy: full-init vs mainnet-snapshot import
- Day 19-20: Build single-ix fixture (SwapBaseInV2 only) + InstructionSpec
  - Implements all 4 applicable invariants (signer/owner/pda-forge/account-swap)
  - First fuzz campaign — confirms solinv works against Native protocol
- Day 21: Expand to Deposit + Withdraw
- Day 22: Add legacy SwapBaseIn/Out (orderbook) if OpenBook fixture
  cost is acceptable, else defer

## Open questions (Day 17-18 to resolve)

1. **AMM pool fixture setup**: Initialize2 has 21 accounts +
   OpenBook market dep. Three options:
   - (A) Implement full Initialize2 in fixture (~2-3 days)
   - (B) Snapshot a real mainnet AMM pool, inject via LiteSVM
   - (C) Skip pool init, build only swap-surface fixture by
     hand-crafting AmmInfo state bytes
   Recommendation: (B) for speed if LiteSVM supports raw account
   injection; else (C) for minimum effort.

2. **AUTHORITY_AMM seed constant**: Read from
   `program/src/state.rs` to confirm `[b"amm authority"]` or
   different bytes. Affects `expected_pda_seeds[2]` for pda-forge
   invariant.

3. **Cross-protocol PDA derivation**: Raydium AMM uses
   `create_program_address` (non-canonical, requires nonce arg)
   not `find_program_address` (canonical, derives bump itself).
   Solinv pda_forge invariant currently tests against
   `find_program_address`. Day 18 to verify whether the invariant
   correctly handles `create_program_address` style.

## Commits

This session:
- Day 15 commit `909b9d5` (refactor + regression, prior session)
- Day 16 commit (this) — docs only, no external code

## Schedule status

| Day | Original | Actual | Status |
|---|---|---|---|
| 15 | Refactor (3 days planned) | 1 day | +2 ahead |
| 16 | Raydium clone+build+inventory | 1 session (~3h) | +1 ahead |
| 17 | klend clone+build+inventory | (next session) | on track |
| 18-22 | Raydium MVP | (per plan) | on track or +1-2 ahead |

Cumulative: **2-3 days ahead of Day 14 schedule**. Buys margin for
Day 28-30 triage + disclosure phase, which was the tightest part
of original Phase 2 Month 1.
