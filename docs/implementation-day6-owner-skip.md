# Phase 1 Day 6 — owner_skip::check Implementation

Date: 2026-05-25
Status: ✅ 2nd concrete invariant compiles. Critical tier 2/5 implemented.

## Outcomes

| Day 6 goal | Status | Evidence |
|---|---|---|
| Implement `owner_skip::check<F>()` | ✅ | ~130 lines, same 7-phase template as signer_skip |
| Multi-pass with wrong owners | ✅ | system_program + attacker-controlled Pubkey::new_unique() |
| Fake account substitution | ✅ | clone data + lamports, swap owner, write_account at new pubkey |
| Update invariants/mod.rs | ✅ | `pub mod owner_skip;` exposed |
| `cargo check --workspace` passes | ✅ | 1.62s incremental |

## Implementation pattern delta vs signer_skip

| Phase | signer_skip | owner_skip |
|---|---|---|
| 1. Save | Same | Same |
| 2. Hash pre | Same | Same |
| 3. Mutate | Set `metas[idx].is_signer = false` | Create fake account at new pubkey with wrong owner, swap `metas[idx].pubkey = fake_pubkey` |
| 4. Signers | Filter-drop target keypair | Unchanged (signers stay) |
| 5. Execute | Same `raw_call` | Same |
| 6. Detect | Same | Same (with different violation message) |
| 7. Restore | Restore originals | Restore originals (fake stays in ctx — minor memory) |

owner_skip is structurally a **substitution** attack (account.pubkey
mutation), while signer_skip is a **flag** attack (is_signer flip).
The 7-phase template handles both cleanly.

## Multi-pass attack strategy

```rust
fn wrong_owners_for(expected: Pubkey) -> Vec<Pubkey> {
    vec![SYSTEM_PROGRAM_ID, Pubkey::new_unique()]
        .into_iter()
        .filter(|p| *p != expected)
        .collect()
}
```

Two wrong-owner candidates:
1. **system_program** (`[0u8; 32]`) — most common real-world attack
   (attacker creates account via system_program, passes to vulnerable
   program)
2. **attacker-controlled random Pubkey** — catches "checks against any
   expected program ID list" bugs

Either pass producing `(success && state_changed)` reports the violation.

## Fake account construction

```rust
let fake_account = Account {
    owner: wrong_owner,
    data: real_account.data.clone(),    // preserve bytes for type check
    lamports: real_account.lamports,    // preserve to pass any rent check
    executable: false,
    rent_epoch: real_account.rent_epoch,
};
```

Preserving **everything except owner** isolates the owner-check
specifically. owner-skip and discriminator-skip remain orthogonal:
- owner-skip = wrong owner, right discriminator (data preserved)
- discriminator-skip = right owner, wrong discriminator (data[0..8]
  corrupted)

Quintuple-bug fixture orthogonality preserved by design.

## Minor implementation notes

- `Pubkey::default() == SYSTEM_PROGRAM_ID` (both = 32 zero bytes).
  Used `const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32])`
  for clarity rather than `Pubkey::default()` magic
- Fake account persists in ctx at unique pubkey after restore.
  Acceptable: no other action/invariant references it, memory pressure
  is negligible across normal fuzz campaigns. Could close via
  `write_account(zero-data)` if needed (Day 11+ optimization)
- `idx >= spec.accounts.len()` guard added defensively (handles
  fixture setup errors gracefully without panic)

## Day 1-6 cumulative

| Day | Item | Commit |
|---|---|---|
| 1 | Crucible install + escrow fuzz + bytecode LCOV | `3ce0fdf` |
| 2 | Source-level LCOV via DWARF 3-binary workflow | `7217257` |
| 3 | Internals deep-read + 7 design corrections | `0dd5f3b` |
| 4 | solinv-fuzz capability skeleton compiles | `7805cfc` |
| 5 | signer_skip::check (1st concrete invariant) | `ebb6773` |
| 6 | owner_skip::check (2nd concrete invariant) | (this commit) |

Critical tier implementation status:
- ✅ 1/5 signer_skip
- ✅ 2/5 owner_skip
- ⬜ 3/5 discriminator_skip (Day 7)
- ⬜ 4/5 pda_forge (Day 8)
- ⬜ 5/5 account_swap (Day 9)
- ⬜ 6/6 openhl-solana test fixture validation (Day 10)

## Day 7 plan

discriminator_skip implementation. Similar to owner_skip (substitution
attack) but:
- Preserve owner correctness, corrupt only `data[0..8]`
- Multi-pass with 3 wrong discriminators (sentinel 0xDEADBEEF…,
  all-zeros, all-ones)
- New util: `corrupt_discriminator(data: &mut Vec<u8>, bad: [u8; 8])`

Estimated ~110 lines following same template.
