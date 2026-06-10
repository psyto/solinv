# Phase 5 Day 56 — Gate A result: H1 is CPI-during-init bounded, NOT fundamental

Date: 2026-05-28
Prior: [phase5-day55-toolchain-fork-setup.md](phase5-day55-toolchain-fork-setup.md)
Gate A goal: discriminate H1b (fundamental account-layout ABI) vs
H1c/d (CPI/loader-bounded), to decide whether the toolchain fork is
feasible or Phase 2.5 should pivot to "Native + Anchor 1.0+ only".

## Result — bounded, not fundamental

Three Anchor 0.28 ix paths tested against the Sanctum unstake program
under LiteSVM 0.9.1 (the fork, vanilla):

| ix | Anchor path | CPI? | Result |
|---|---|---|---|
| `init_protocol_fee` | `#[account(init, seeds, space)]` | system_program::create_account | **FAILS H1** (access violation 0xFFFF…FFFF size 32) |
| `create_pool` | `#[account(init, mint::authority, mint::decimals)]` | system + spl_token::initialize_mint | **FAILS H1** (same) |
| `set_protocol_fee` | `#[account(mut, has_one, seeds, bump)]` — pure read | **none** | **SUCCESS** (cu=6392) |

`set_protocol_fee` was tested by **byte-poking** a valid ProtocolFee
PDA into the SVM via `write_account` (8-byte `account:ProtocolFee`
discriminator + destination + authority + 2× Rational), then calling
the ix. Anchor deserialized the account, checked the `has_one =
authority` constraint, ran the handler, and returned Success.

**Conclusion**: the Anchor 0.28 account deserialize + constraint-check
+ handler path WORKS under LiteSVM 0.9.1. H1 fires **only on the
`init` → CPI path** (both system-only and spl_token variants). This
**rules out H1b** (fundamental account-layout ABI). H1 is **CPI-
during-init bounded** (H1c/d).

## Correction to Day 45-47 docs

Day 45-46 stated init_protocol_fee "succeeded" in setup(). **It did
not.** The setup() call used `.expect("init_protocol_fee")`, which
only panics on a Result-level `Err`, not on `TxOutcome::ProgramError`.
init_protocol_fee was silently H1-failing the whole time; the
protocol_fee PDA was never created (confirmed: "Account not found"
on read-back). The Sanctum harness has been failing at its FIRST ix
since Day 45. The 1.4% edge coverage came from Anchor's dispatch +
partial init validation before the H1 crash, on every init attempt.

This correction strengthens the Gate A finding: even the *simplest*
Anchor 0.28 init (seeds + space, no SPL Token) trips H1 — but a pure
read does not. So the failing element is the init→CPI mechanism, not
account layout, not SPL Token specifically.

## The bigger implication — a fork-free workaround exists

The set_protocol_fee success is a proof-of-concept: **pre-create the
program's accounts via `write_account` (byte-poke), skip the program's
own init ixs, and the non-init attack surface is reachable.** This is
exactly the [klend Day 24](phase2-day24-klend-reserve.md) mirror-struct
byte-poke pattern.

So the Day 46-47 framing ("Anchor 0.x is unreachable") was too
pessimistic. The accurate framing:

- Anchor 0.x **init ixs** are unreachable under LiteSVM 0.9.1 (H1)
- Anchor 0.x **post-init attack surface** (the ixs solinv actually
  wants to fuzz — swaps, deposits, withdraws, unstakes) IS reachable
  via byte-poke account setup

This changes the toolchain-fork calculus. Two paths now exist:

### Path 1 — byte-poke account setup (NO fork needed)

Reuse the klend Day 24 pattern: `#[repr(C)]` mirror structs +
`offset_of!` + `write_account` to pre-create Pool / Fee / ProtocolFee
/ LP-mint / reserves with correct discriminators + data, bypassing
the broken init. Then fuzz the real surface.

- **Pro**: works today, no LiteSVM internals work, unblocks Anchor
  0.x targets immediately
- **Con**: per-target byte-poke setup cost (klend Day 22-27 showed
  this is ~5-7 days per complex Anchor zero-copy program); harness
  authors must hand-construct account state
- **Precedent**: klend Day 24-27 did exactly this (the depth gate
  there was ReserveConfig completeness, NOT H1 — klend's byte-poke
  reached the handler; it just needed more config fields)

### Path 2 — CPI-init shim in LiteSVM (the fork)

Fix the init→CPI path so Anchor's `init` works directly.

- **Pro**: better ergonomics — harness authors use the program's own
  init ixs instead of byte-poking every account
- **Con**: LiteSVM-internals work; H1c/d root cause still needs to be
  found (the specific CPI/loader mechanism that corrupts the account
  region during create_account invoke). Likely 1-2 weeks.

## Revised Gate B (the toolchain fork decision)

Gate A passes "bounded" → the fork is feasible in principle. But Gate
A *also* revealed that the fork is **not strictly necessary** for
reachability — Path 1 (byte-poke) unblocks Anchor 0.x without it.

So the real Gate B question is no longer "is the fork feasible?" but
"is the fork worth it vs the byte-poke workaround?"

- If the goal is **reach Anchor 0.x targets for the OSS catalog's
  validated-targets table**: Path 1 (byte-poke) gets there faster,
  per-target. No fork.
- If the goal is **contributor ergonomics** (so OSS users can adopt
  solinv on their Anchor 0.x program without hand-byte-poking every
  account): Path 2 (fork) is the better artifact, but it's 1-2 weeks
  and the H1c/d root cause is still unlocated.

Given the Phase 2.5 success criteria (catalog + methodology + launch,
NOT bug extraction), and given Path 1 already exists and is proven
(klend + Day 56 set_protocol_fee), the **leaning recommendation** is:

> **Defer the LiteSVM fork. Document the H1 init-gate + the byte-poke
> workaround as the supported Anchor 0.x integration path. Spend the
> Day 55-68 toolchain-fork budget on byte-poke harness ergonomics
> instead** — e.g., a reusable `solinv-fuzz` helper that takes a
> mirror struct + field values and writes a discriminator-correct
> account, so harness authors get a clean API for the byte-poke
> pattern rather than hand-rolling it per-target.

That converts the riskiest, least-certain Phase 2.5 line item (deep
LiteSVM internals fork, uncertain root cause) into a bounded,
already-proven one (byte-poke helper API on top of a pattern klend +
Day 56 already validated).

## Decision needed (Day 57)

The Gate A finding reshapes the toolchain-fork plan. User should weigh:

1. **Byte-poke helper path** (recommended) — build the
   `solinv-fuzz` byte-poke account-setup API, document it as the
   Anchor 0.x integration story, skip the LiteSVM fork. ~3-5 days.
2. **LiteSVM CPI-init shim** (original fork plan) — find the H1c/d
   root cause + patch the init→CPI path. ~1-2 weeks, uncertain.
3. **Both** — byte-poke helper now (unblocks targets), fork later
   (ergonomics polish before launch).

## Files touched Day 56

- `examples/sanctum-unstake-fuzz/fuzz/sanctum-unstake/src/main.rs` —
  Gate A probe added then reverted; setup()'s init_protocol_fee is now
  an explicit soft-fail with a comment pointing at this finding +
  the byte-poke Day 57 direction. TxOutcome import removed.
- `~/src/litesvm-fork/` — unchanged from Day 55 (experiment 1's
  FeatureSet::default() was reverted to all_enabled() baseline).
- `docs/phase5-day56-gateA-result.md` (this doc).
