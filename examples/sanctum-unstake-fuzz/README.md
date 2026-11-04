# sanctum-unstake-fuzz — Phase 4 N=2 harness

[Sanctum unstake program](https://github.com/igneous-labs/sanctum-unstake-program)
— Anchor 0.28 instant-unstake LST infrastructure. Selected Day 44
as Phase 4 N=2 target (protocol-size axis re-test; same code-quality
class as Slumlord N=1).

See [`docs/sanctum-unstake-ix-inventory.md`](../../docs/sanctum-unstake-ix-inventory.md)
for full ix surface analysis and solinv-coverage expectations.
Per the Phase 4 plan §"Stopping rule", a Day 49 N=2 = 0 violations
result combined with Day 43 N=1 = 0 binds the protocol-variety
pivot across the High-tier program.

## Pre-fuzz honest framing

Same code-quality posture as Slumlord N=1 — both are igneous-labs
production code with Sec3-audit pedigree (2023-07-24 for unstake).
Pre-fuzz expectation: 0 violations across all 7 invariants. This
is the *expected* outcome that closes the protocol-size axis when
combined with Slumlord N=1's clean negative.

## External program dependency

Use the binary Sanctum deployed on mainnet:

```bash
solana program dump -u m unpXTU2Ndrc7WWNyEhQWe4udTzSibLPi25SXv2xbCHQ unstake.so
export SANCTUM_UNSTAKE_SO=$PWD/unstake.so
```

Don't rebuild it from source with current platform-tools. The program
locks solana-program 1.14.20, whose `AccountInfo` isn't `repr(C)`;
built with rustc ≥ 1.68 (platform-tools ≥ v1.37) every CPI faults with
"Access violation … 0xffffffffffffffff", on a real validator too. That
was the "H1" gate of Days 46–57 — see
[`docs/phase5-day61-h1-was-the-build.md`](../../docs/phase5-day61-h1-was-the-build.md).

## Layout

```
sanctum-unstake-fuzz/
└── fuzz/sanctum-unstake/
    ├── Cargo.toml          # workspace opt-out
    └── src/main.rs         # SanctumUnstakeFixture + 8 invariant variants
```

## Wire format

Anchor 0.28 — 8-byte sighash at `data[0..8]`
(`sha256("global:<ix_name>")[..8]`) + Borsh-encoded args.
Same as klend's Anchor 0.29 idiom; solinv Day 15 `raw_call` pattern
+ `ix_sighash` helper apply directly.

## Solinv coverage (anticipated)

| Invariant | Applicable | Notes |
|---|---|---|
| signer-skip | ✓ | All admin ixs + `unstake` have Signer constraints |
| owner-skip | ✓ | All accounts typed `Account<'info, T>` — Anchor auto-checks |
| discriminator-skip | ✓ | Anchor 8-byte account discriminator on Pool/Fee/ProtocolFee |
| pda-forge | ✓ | Pool sol reserves, fee_account, protocol_fee_account all PDAs |
| account-swap | (deferred) | Limited alternate-context surface — single pool per program |
| unchecked-math | ✓ | LP math + fee math + protocol fee math — `add_liquidity` / `remove_liquidity` / `unstake` |
| cu-dos | ✓ | `unstake` may iterate over remaining_accounts (rebate sources) |

## Day-by-day progress

| Day | Component | Status |
|---|---|---|
| 44 | Target pick + `unstake.so` build smoke + ix inventory | ✓ |
| 45 | Cargo.toml workspace opt-out + minimum-viable compiling skeleton | ✓ — this commit |
| 46 | CreatePool fixture setup + 1-2 InstructionSpec wired (SetFee / AddLiquidity) | ⬜ |
| 47 | Smoke fuzz campaign — confirm harness reaches each ix | ⬜ |
| 48 | Full Gate 1-style 7-invariant × 30s isolated campaigns | ⬜ |
| 49 | Result log + N=2 vs binding decision | ⬜ |

Day 45 deliverable: scaffold + setup() that calls `init_protocol_fee`
once (permissionless, creates global ProtocolFee PDA). No actions or
InstructionSpecs yet beyond an `action_noop` placeholder required by
`#[fuzz_fixture]` macro semantics. 8 invariant variants wired so the
binary builds, but they no-op against the empty InstructionSpec list.

Day 46 closes the gap: real `action_create_pool` /
`action_add_liquidity` / `action_set_fee` + matching
InstructionSpec entries with full `expected_owners` /
`expected_discriminators` / `expected_pda_seeds` metadata so solinv
invariants have a real attack surface.

## Day 45 smoke check

```bash
cd examples/sanctum-unstake-fuzz
crucible run sanctum_unstake invariant_sanctum_unstake_smoke --release --timeout 10
```

→ 4 executions, 0 crashes, setup() reaches init_protocol_fee
successfully. 0% edge coverage (no real attack surface yet) —
confirms the skeleton compiles and runs, gates Day 46 work on
actual InstructionSpec wiring.

Day 61 (2026-11-04), mainnet binary: `setup()` asserts that
`init_protocol_fee` and `create_pool` both succeed. 10 s smoke:
0 crashes, 2.8% edges (was 1.4% against the local build), `set_fee`
reaching Ok.
