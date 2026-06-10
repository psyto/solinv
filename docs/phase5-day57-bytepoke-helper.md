# Phase 5 Day 57 — bytepoke helper API in solinv-fuzz (toolchain-fork pivot)

Date: 2026-06-09
Prior: [phase5-day56-gateA-result.md](phase5-day56-gateA-result.md)
Decision (Day 57): **Path 1 (byte-poke helper) over Path 2 (LiteSVM
CPI-init shim)** per Day 56 §"Revised Gate B" recommendation.

## Decision

Day 55 set up `litesvm-fork/` as a working baseline (vanilla v0.9.1).
Day 56 Gate A then discovered the depth-gate is **bounded to the
init→CPI path**, not a fundamental ABI mismatch — so Anchor 0.x
**post-init** ixs (the ones solinv actually wants to fuzz) ARE
reachable today via byte-poke account setup, with no LiteSVM work.

The original Day 55-68 toolchain-fork budget (2-3 weeks of LiteSVM
internals work, uncertain H1c/d root cause) is reallocated to **build
the byte-poke helper API in `solinv-fuzz`** (~3-5 days, all in-tree,
zero external-repo risk). The fork directory + `[patch.crates-io]`
directive stay in place for an eventual ergonomics pass after public
launch.

## What landed

New module: `crates/solinv-fuzz/src/bytepoke.rs` (270 LOC + 14 unit
tests, all passing). Re-exported via `solinv_fuzz::*` and
`solinv_fuzz::prelude::*`. Surface:

| Symbol | Use |
|---|---|
| `anchor_account_disc(name) -> [u8; 8]` | sha256("account:Foo")[..8] — was duplicated in klend Day 23 + sanctum Day 56 |
| `anchor_ix_sighash(name) -> [u8; 8]` | sha256("global:bar")[..8] — same duplication |
| `rent_for_raw(bytes)` / `rent_for_anchor_body(body)` | Rent-exempt lamport calc, no `solana_rent` dep |
| `write_u8_at` / `u16` / `u32` / `u64` / `u128` / `i64` / `pubkey` / `bytes` | Offset writers for `#[repr(C)]` byte-pokes |
| `AnchorAccountBuilder::new(type_name, body).owned_by(pid).build()` | One-call discriminator + lamports + owner construction |

Test vectors are anchored against:
- `account_disc("LendingMarket")` — verified against klend Day 23
  `build_lending_market_bytes` output
- `account_disc("Pool")` — sanctum Day 56 reference
- `ix_sighash("initialize")` — Anchor canonical example
- `ix_sighash("swap")` — appears in many AMM IDLs

## Why this is the right artifact for OSS launch

The byte-poke pattern is the **documented Anchor 0.x integration story**
for solinv users until upstream LiteSVM resolves H1. Before this
module, every harness duplicated the disc/sighash math and the byte
writers locally (4 places: klend, sanctum-unstake, sanctum-unstake-fuzz
Day 56, and any future Anchor 0.x harness). After this module, harness
authors write only the target-specific `#[repr(C)]` mirror + field
assignments; the boilerplate moves to `solinv_fuzz::prelude::*`.

This converts the riskiest Phase 2.5 line item ("deep LiteSVM
internals fork, uncertain root cause, 1-2 weeks") into a bounded
shipped artifact (~half-day implementation per the actual landing).
The OSS-launch README ("Adopting solinv on your own Anchor 0.x program"
section) now has a concrete API to point users at.

## Open follow-ups

- **Migrate klend's `build_lending_market_bytes` to use the new helpers**
  (proof-of-concept that the API actually slots in for an existing
  byte-poke harness, not just a green-field one). Estimated ~1 hour.
- **Migrate sanctum-unstake-fuzz Day 56 byte-poke** (the
  set_protocol_fee + Pool/Fee builders). Once both klend and sanctum
  are migrated, the local `account_disc` / `ix_sighash` definitions
  can be deleted; harness Cargo.toml's `sha2 = "0.10"` dep can drop.
- **Add a `mirror!` macro** that wraps `#[repr(C)] struct + offset_of!`
  into a one-call body builder. Currently the offset writers reduce
  one layer of boilerplate but not the mirror struct itself.
- **LiteSVM CPI-init shim still on the table** as a launch-polish item
  (after Path 1 ships) — Day 56 §"Decision needed" option 3 ("both").
  Not committed; the fork directory + patch directive sit dormant.

## Files changed Day 57

- `crates/solinv-fuzz/Cargo.toml` — added `solana-account` + `sha2 = "0.10"` deps
- `crates/solinv-fuzz/src/bytepoke.rs` (new) — 270 LOC + 14 unit tests
- `crates/solinv-fuzz/src/lib.rs` — register module + re-export from
  top + `prelude`
- `docs/phase5-day57-bytepoke-helper.md` (this doc)
