# Slumlord ix inventory — Phase 4 N=1 target

Source: `~/src/slumlord/` (cloned from
`https://github.com/igneous-labs/slumlord` Day 40).
Build: `cargo build-sbf --tools-version v1.39` + macOS SDKROOT
incantation → `~/src/slumlord/target/deploy/slumlord.so` (115KB).
On-chain program ID: `s1umBj7CEUA6djs6V1c6o2Nym3QrqF4ryKDr1Nm1FKt`
(per `idl.json:129`).

## Program shape

Native (non-Anchor) Solana program. 4 ix selected by single-byte
discriminator at `data[0]`. Generated client interface via solores
from `idl.json` (Shank-style). Per-ix validation uses
`*_verify_account_keys` + `*_verify_account_privileges` helpers
that the solores-generated `slumlord_interface` crate provides.

Single PDA account (`slumlord`) with seed `["slumlord"]`. The
canonical Slumlord state lives at this PDA. State type:

```rust
pub struct Slumlord {
    pub old_lamports: u64,    // lamports before the active flash borrow
}
```

When `data_is_empty()`, no loan is active. After `Init` and during
an active borrow, the PDA holds 8 bytes of u64 in little-endian.

## Instructions (4)

### 0. Init

| Account | mut | signer | role |
|---|---|---|---|
| `slumlord` | ✓ | | PDA `["slumlord"]` — assigned to program by `assign_invoke_signed` |
| `system_program` | | | invoked for assign |

Permissionless one-shot setup. Idempotent (assign on already-owned
account is a no-op). Pre-req: slumlord PDA already lamport-funded
to rent-exempt baseline; those locked lamports become the flash
loan amount.

### 1. Borrow

| Account | mut | signer | role |
|---|---|---|---|
| `slumlord` | ✓ | | PDA |
| `dst` | ✓ | | destination receives `slumlord_balance - 1` lamports |
| `instructions` | | | sysvar — used to scan for succeeding `CheckRepaid` |

CPI-callable. Logic:

1. Verify a `CheckRepaid` ix follows in the *top-level* tx ix list
   (loops from `curr_ix_idx + 1` upward, returning
   `NoSucceedingCheckRepaid` if none found).
2. If `slumlord.data` is non-empty → `BorrowAlreadyActive` error.
3. Extend `slumlord` data to 8 bytes, write `old_lamports`.
4. Transfer `slumlord_lamports - 1` to `dst` via direct lamport
   increment (`transfer_direct_increment`, not CPI to SystemProgram).

### 2. Repay

| Account | mut | signer | role |
|---|---|---|---|
| `slumlord` | ✓ | | PDA |
| `src` | ✓ | **✓** | system account paying outstanding loan |
| `system_program` | | | invoked for transfer |

Helper utility ix. Computes outstanding loan via
`accounts.slumlord.curr_loan_lamports_outstanding()` and CPIs to
SystemProgram to transfer from `src` to `slumlord`. **Only ix that
requires a signer.**

### 3. CheckRepaid

| Account | mut | signer | role |
|---|---|---|---|
| `slumlord` | ✓ | | PDA |

Top-level-only enforcement (the Borrow ix verifies this is in
top-level ixs, not in CPI). Logic:

1. If `slumlord.data_is_empty()` → no-op success (idempotent).
2. Read current `lamports()` and `old_lamports` from PDA state.
3. If `lamports < old_lamports` → `InsufficientRepay` error.
4. Shrink `slumlord` data to 0 (ending the loan).

## Solinv coverage analysis

### Critical 5

| Invariant | Slumlord surface | Expected outcome |
|---|---|---|
| **signer-skip** | Only `Repay` has a Signer (`src`). solinv would attack `src.is_signer = false`. Slumlord's `repay_verify_account_privileges` checks this explicitly per solores convention. | Likely **0 detection** — privilege check is in the verify-helpers, not in handler body |
| **owner-skip** | All 4 ix consume the slumlord PDA; ownership-by-program is implicit (PDA derivation locks owner). Substitute fake account → `*_verify_account_keys` rejects via Pubkey mismatch before owner is read. | Likely **0 detection** — verify_account_keys is a strict equality check |
| **discriminator-skip** | 1-byte discriminator at `data[0]`, not Anchor 8-byte sighash. Solinv's discriminator-skip is Anchor-shaped; doesn't apply to Native u8 discriminator at PDA data offset 0 (which is `old_lamports` LE, not a discriminator). | **N/A** — like Raydium AMM, this invariant doesn't apply to Native |
| **pda-forge** | The `slumlord` PDA has seed `["slumlord"]`. Forging means passing a non-PDA account at the slumlord position. `*_verify_account_keys` validates pubkey match against the derived address. | Likely **0 detection** — explicit key check |
| **account-swap** | No alternate-context concept — there's only one slumlord PDA in the entire program. `dst` and `src` are user-controlled by design (flash loans are permissionless). | **N/A** — no swap targets exist |

### High tier (implemented)

| Invariant | Slumlord surface | Expected outcome |
|---|---|---|
| **unchecked-math** | Borrow uses `checked_sub` (line 119). Repay uses `curr_loan_lamports_outstanding()` which probably is checked too. Wrapping arithmetic absent from handler bodies. | Likely **0 detection** — but worth declaring Bounded on `slumlord.lamports` as a sanity rail |
| **cu-dos** | Borrow has a `loop` scanning instructions sysvar (lines 94-103) — bounded by tx ix count (max 64 per tx). No unbounded loop on user input. Per-ix CU should be ~3-5K. | Likely **0 detection** — no attacker-controllable iteration |

## What's expected, with honest framing

Slumlord is a **competently-coded simple program**. The "less-hardened"
hypothesis test here is at the *protocol size* axis, not the *code
quality* axis. Even if solinv yields 0 detections on Slumlord, the
N=2 protocol (if pursued) would need to be a different shape entirely
(e.g., hackathon-grade code, mid-tier indie protocol) to falsify the
hypothesis on the right dimension.

Best honest estimate: **N=1 Slumlord = 0 violations**. This counts
as a clean negative data point per the Phase 4 plan §"Stopping
rule": continue to N=2 selection on Day 46+.

## Reusable patterns extracted (preview)

These will go into the Phase 4 retrospective if/when the experiment
closes:

1. **Solores-generated `*_verify_account_keys` + `*_verify_account_privileges`** pattern shipped by Igneous Labs is a competent
   alternative to Anchor's `Account<'info, T>` constraint. Programs
   using this pattern likely pass owner-skip / pda-forge by
   construction.
2. **macOS SDKROOT + platform-tools v1.39** incantation reused from
   klend Day 17 — confirmed reproducible on Slumlord 2026-05-26.
3. **1-byte Native discriminator** wire format is the same shape as
   Raydium AMM tag bytes — solinv's `data_sample.push(disc)` ix
   building works directly.

## Next (Day 41-43)

- Day 41: `examples/slumlord-fuzz/` scaffold + Cargo.toml workspace
  opt-out + `fuzz/slumlord/src/main.rs` skeleton.
- Day 42: Fixture init — create + Init the slumlord PDA, fund it
  with rent-exempt + flash-loan-amount lamports (~1M).
- Day 43: First InstructionSpec wired for Borrow (most-likely
  detection surface). Smoke campaign.
- Day 44: All 4 ix InstructionSpecs + 6-invariant variants wired.
- Day 45: Full Gate 1-style campaigns + result log.

Per-protocol budget guide (Phase 4 plan §"Budget per protocol"):
~5 days total for Native target. Slumlord's simpler surface may
finish in 3-4 days.
