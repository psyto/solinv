# Phase 2 Day 15 — Harness raw_call Refactor

Date: 2026-05-25
Status: Refactor complete; regression in progress (5 isolated variants).
Closes: Day 14 architectural finding (`docs/phase2-day14-anchor-version-mismatch.md`).

## Goal

Make `examples/escrow-demo/fuzz/escrow/src/main.rs` Anchor-version-
independent so the **same harness pattern** can be applied to:

- klend (Anchor 0.29) — Day 23-27
- Raydium AMM (Native) — Day 18-22
- Save (Anchor 0.28), Raydium CLMM (Anchor 0.32), etc. — later

This is the **prerequisite refactor** for both Phase 2 targets per
the Option C parallel-execution plan locked 2026-05-25.

## Changes

### Cargo.toml

- **Removed**: `anchor-lang = "1.0.1"` — harness no longer imports
  any `anchor_lang::*` types.
- **Added**: `sha2 = "0.10"` — for runtime sighash computation.

### main.rs

**Imports dropped**:
```rust
use crucible_fuzzer::anchor_lang::system_program;   // was line 1
use escrow::*;                                      // was line 3 (wildcard)
use anchor_lang::Discriminator;                     // was in 3 helper fns
```

**Imports added/changed**:
```rust
use escrow::ID;                                     // only the program id const
use sha2::{Digest, Sha256};
use solana_instruction::{AccountMeta, Instruction}; // Instruction added
```

**New constants/helpers** (top of file):
- `const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);`
  — replaces `anchor_lang::system_program::ID`.
- `fn ix_sighash(name) -> [u8; 8]` — `sha256("global:{name}")[..8]`.
  Replaces `instruction::Foo::DISCRIMINATOR`.
- `fn account_disc(name) -> [u8; 8]` — `sha256("account:{Name}")[..8]`.
  Replaces `Vault::DISCRIMINATOR`.
- 4 `build_<ix>_ix(...) -> Instruction` constructors for
  `initialize`, `deposit`, `withdraw`, `claim`.

**Replaced** (5 call sites in `setup()` + 3 `action_*` methods):

Before:
```rust
self.ctx.program(self.program_id)
    .call(instruction::Deposit { amount })
    .accounts(accounts::Deposit { vault, depositor, system_program })
    .signers(&[&*self.depositor])
    .send()
```

After:
```rust
self.ctx
    .raw_call(build_deposit_ix(self.program_id, self.vault_pda,
                               self.depositor.pubkey(), amount))
    .signers(&[&*self.depositor])
    .send()
```

**Unchanged**:
- `EscrowFixture` struct layout (depositor, depositor_b, beneficiary,
  fee_payer, vault_pda, vault_b_pda).
- `HasContext` / `HasInstructionSet` impls — already raw-data oriented
  (used `instruction::DISCRIMINATOR` for sighash, now use `ix_sighash`
  inside the same helper).
- `InstructionSpec` metadata for `unsafe_withdraw` + `unsafe_set_amount_from_source`
  — same accounts/data layouts as Day 13.
- All 7 `#[invariant_test]` functions (acceptance + 5 isolated + 1
  time-guard).

## Compile verification

```
cargo check               → OK, no errors
cargo build --release --features invariant_signer_skip_only → OK
```

Pre-existing dead-code warnings for `setup`/`action_*` persist (they
are consumed by `#[fuzz_fixture]` proc macro at compile time but
appear unused to the type checker). No new warnings introduced.

## Regression — 5 isolated invariant variants

Each invariant ran in isolation with `-j 2 --timeout 30 --release`.
Crash count = number of times the invariant detected its planted bug
over the 30-second campaign:

| Invariant | Pre-refactor (Day 13) | Post-refactor (Day 15) | Status |
|---|---|---|---|
| signer-skip | ✅ detects | ✅ **15,730 crashes / 29s** | PASS |
| owner-skip | ✅ detects | ✅ **34,642 crashes / 29s** | PASS |
| discriminator-skip | ✅ detects | ✅ **35,485 crashes / 30s** | PASS |
| pda-forge | ✅ detects | ✅ **9,763 crashes / 29s** | PASS |
| account-swap | ✅ detects | ✅ **41,939 crashes / 30s** | PASS |

**Total: 137,559 violations across 5 campaigns in ~2.5 min** (no
degradation vs Day 13 baselines). Refactor preserves full detection
capability. CRITICAL TIER 5/5 still detecting.

### Operational note: sequential, not parallel

Running 4 `crucible run` invocations simultaneously deadlocked (all
4 invariant_test processes went to 0% CPU within seconds of start,
zero stdout, never recovered — likely a shared crucible workspace
lock on the harness binary path). **Run regression campaigns
sequentially** rather than parallel for multi-feature checks.
Single-campaign throughput is fine.

## Why this matters for Phase 2

Per Day 14 finding, every production-protocol candidate on the Phase
2 target list uses **anchor-lang 0.28-0.32**. Pre-refactor, the
harness pattern was **incompatible** with all of them (workspace
pinned anchor 1.0.1).

Post-refactor, the harness pattern depends on **nothing version-
specific** about Anchor — just `sha2`, `solana-instruction`, and the
target program's deployed `.so`. The same workflow now applies to:

- Native programs (Raydium AMM): same `raw_call` + `AccountMeta`
  pattern, just `data[0]` = ix tag byte (no sighash).
- Anchor 0.x programs (klend, Raydium CLMM, Save): pure mechanical
  translation from each protocol's IDL JSON.

## Pattern doc

The reusable pattern is now documented standalone in:

- `docs/harness-pattern-raw-call.md`

This is the reference for Day 18-22 (Raydium AMM) and Day 23-27 (klend).

## Day 16-17 (next sessions)

- Day 16: Clone `raydium-io/raydium-amm`, inventory 5-7 critical ix,
  draft IDL → InstructionSpec mapping. Build `.so` with Solana 2.1
  toolchain.
- Day 17: Clone `Kamino-Finance/klend`, install Anchor 0.29 build
  environment, build `.so`. Draft IDL → InstructionSpec mapping for
  5 critical lending ix.

Both refactor-validated harness pattern + protocol-specific build
infrastructure are needed before InstructionSpec construction
(Day 18+ Raydium / Day 23+ klend).
