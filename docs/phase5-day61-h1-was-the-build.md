# Phase 5 Day 61 — H1 was the build, not LiteSVM

Date: 2026-11-04
Corrects: [phase4-day47-a1-dig.md](phase4-day47-a1-dig.md),
[phase5-day55-toolchain-fork-setup.md](phase5-day55-toolchain-fork-setup.md),
[phase5-day56-gateA-result.md](phase5-day56-gateA-result.md),
[phase5-day57-bytepoke-helper.md](phase5-day57-bytepoke-helper.md)

## Result

H1 ("Access violation at 0xFFFFFFFFFFFFFFFF size 32" on any Anchor 0.28
`init`) is not a LiteSVM incompatibility. It comes from how we built the
program:

- Sanctum unstake (Anchor 0.28) locks **solana-program 1.14.20**. In that
  version `AccountInfo` is not `#[repr(C)]`; the attribute arrived in 1.16
  (solana-labs/solana#30124).
- We built with `cargo build-sbf --tools-version v1.39` (rustc 1.72). Since
  rustc 1.68 the compiler may reorder fields of non-`repr(C)` structs
  (rust-lang/rust#102750, tracked in solana-labs/solana#29852).
- On a CPI the runtime reads the caller's `AccountInfo`s assuming the C
  layout, picks up a garbage `key` pointer and faults reading 32 bytes at
  `0xffff…ffff`. That happens before `invoke [2]` is logged, which is why
  no CPI line ever appeared. Instructions that never CPI (Day 56's
  `set_protocol_fee`) don't hand `AccountInfo`s to the runtime, so they
  worked.

## Evidence

Minimal Anchor 0.28 program with one `#[account(init, payer, space, seeds, bump)]`
instruction (no SPL Token), plus the real Sanctum binary:

| .so | LiteSVM 0.9.1 | LiteSVM 0.18.1 | solana-test-validator 4.1.2 |
|---|---|---|---|
| minimal, solana-program 1.16.25, platform-tools v1.39 | OK, 7003 CU | OK, 6949 CU | OK, 6949 CU |
| minimal, solana-program 1.14.20, v1.39 | FAIL, 5396 CU | FAIL, 5342 CU | FAIL, 5342 CU |
| minimal, solana-program 1.14.20, v1.37 | FAIL, 5702 CU (different garbage address) | FAIL, 5648 CU | not run |
| Sanctum unstake, built locally (v1.39) | FAIL, 6903 CU | FAIL, 6849 CU | FAIL, 6849 CU |
| Sanctum unstake, mainnet binary | **OK, 10296 CU** | **OK, 10242 CU** | not run |

A real validator fails the same way at the same CU, so there was nothing to
fix in LiteSVM, and the toolchain fork of Day 55 could never have helped.

## What changes

- **Use the deployed binary.** `solana program dump -u m <program id> <out>.so`
  gives the build the protocol actually runs. The sanctum-unstake harness
  now does this (see its README). With it, `init_protocol_fee` and
  `create_pool` both succeed in `setup()`, which now asserts they do;
  smoke edge coverage went from 1.4% to 2.8% and `set_fee` reaches Ok.
- **If you must build an old Anchor program yourself**, check its Cargo.lock
  first; if solana-program is below 1.16, move it to 1.16 (Anchor 0.28 accepts
  `>=1.14, <1.17`). Verified on
  the minimal program, not on Sanctum.
- **Byte-poke is still useful**, but for its other reasons (reaching deep
  state quickly, programs whose init needs off-chain setup), not as the only
  way past Anchor 0.x init.
- **klend is a different case.** It locks solana-program 1.17.18, whose
  `AccountInfo` is `repr(C)`, so this cause does not apply. Its harness was
  written against the source build; the deployed binary takes a longer
  `init_reserve` account list and rejects the harness's with
  `AccountNotEnoughKeys (3005)`. The harness used to ignore that failure and
  fuzz with no Reserve (0% ok); `setup()` now asserts `init_reserve`
  succeeds. The Day 47 line "Anchor 0.29 + LiteSVM 0.9.1 also has
  compatibility friction" is not supported.

## Lesson

We fuzzed a binary that differs from the one on mainnet and spent Days 46–57
diagnosing the difference as a VM bug. For production targets, start from the
deployed binary; build from source only when the harness needs a modified
program, and then check the solana-program version first.
