# solinv Invariant Catalog

17 baseline + 3 stretch Solana-aware bug class auto-detectors. Each
invariant fires without user-written `fuzz_assert!` — solinv's wedge
vs Crucible/Trident (which require manual invariant authoring).

> **Current status (2026-05-26)**: Critical tier 5/5 implemented +
> end-to-end detecting (Days 5-13). Phase 2 production validation
> complete (Raydium + klend, Days 14-27). Phase 3:
> [unchecked-math](unchecked-math.md) shipped Day 31-34 — Gate 1
> PASS on escrow, Gate 2 **FAIL** on Raydium SwapV2
> ([phase3-day34-unchecked-math-gate2.md](../phase3-day34-unchecked-math-gate2.md)).
> [cu-dos](cu-dos.md) follows as a second gated experiment (Day 35-38)
> per user-confirmed Day 34 follow-on; this is the last High-tier
> invariant under the current strategy unless Gate 2 here passes.

## Status

### Critical (target: 7 invariants)

| # | Name | Status | Bug class |
|---|---|---|---|
| 1 | [signer-skip](signer-skip.md) | ✓ spec written | Missing `is_signer` check on authorization-required account |
| 2 | [owner-skip](owner-skip.md) | ✓ spec written | Missing `account.owner == expected_program` check |
| 3 | [discriminator-skip](discriminator-skip.md) | ✓ spec written | Missing Anchor account discriminator check |
| 4 | [pda-forge](pda-forge.md) | ✓ spec written | PDA seed not verified, attacker forges arbitrary PDA |
| 5 | [account-swap](account-swap.md) | ✓ spec written | Real PDA from wrong context (wrong user/market/epoch) — missing context-binding check |
| 6 | sysprogram-substitution | ⬜ pending | Fake system / token program passed for CPI target |
| 7 | token-account-confusion | ⬜ pending | Token-2022 extension confusion |

### Critical tier accumulated InstructionSpec (5 specs filled this in)

```rust
pub struct InstructionSpec {
    pub program_id: Pubkey,
    pub name: String,
    pub accounts: Vec<AccountMeta>,
    pub signer_indices: Vec<usize>,                    // signer-skip
    pub optional_signer_indices: Vec<usize>,           // signer-skip
    pub expected_owners: Vec<Option<Pubkey>>,          // owner-skip
    pub expected_discriminators: Vec<Option<[u8; 8]>>, // discriminator-skip
    pub expected_pda_seeds: Vec<Option<Vec<Vec<u8>>>>, // pda-forge
    pub creates_indices: Vec<usize>,                   // pda-forge
    pub swap_alternates: Vec<Vec<Pubkey>>,             // account-swap
    pub data_sample: Vec<u8>,
}
```

### Critical tier acceptance test contract

**Quintuple-bug fixture** in openhl-solana `process_close_position`:
plant all 5 Critical bugs simultaneously, solinv must report **5
independent violations**. Each invariant catches ONE missing assertion;
no false sharing between them. This is the end-state contract for the
account-validation invariant family.

### High (target: 8 invariants — expanded from 5 per Helius blog 2026-05-25)

| # | Name | Status | Bug class | Source |
|---|---|---|---|---|
| 8 | cpi-reentrancy | ⬜ pending | Re-entry through CPI to caller program | Day 13 plan |
| 9 | [cu-dos](cu-dos.md) | ✓ spec written (Day 35, second gated experiment — see §9 + §10) | Single ix consumes >limit CU → permanent DoS | Day 13 plan |
| 10 | [unchecked-math](unchecked-math.md) | ✓ spec + impl + Gate 1 PASS / Gate 2 FAIL (Day 31-34) | Saturating vs wrapping vs checked confusion | Day 13 plan |
| 11 | realloc-race | ⬜ pending | `realloc()` race / overflow / rent invariant break | Day 13 plan |
| 12 | token-2022-hook | ⬜ pending | Transfer hook violation / extension mishandling | Day 13 plan |
| 13 | **bump-seed-canonicalization** | ⬜ pending | Non-canonical bump 受容 → 同 seed で複数 PDA、authority bypass cascade | **Helius "Hitchhiker's Guide" 2026-05** |
| 14 | **account-reload-after-cpi** | ⬜ pending | `&mut` borrow を CPI 跨ぎで保持 → stale data/lamports 読み | **Helius 2026-05** |
| 15 | **pda-sharing** | ⬜ pending | 同 PDA が複数 role の authority、構造 bug | **Helius 2026-05** |
| 15b | (arbitrary-cpi) | bonus | CPI 先 program-ID 未検証 → 任意 program 呼出可 | Helius; owner-skip と同系で cheap addition |

**Source**: Helius "A Hitchhiker's Guide to Solana Program Security"
(https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
documented these patterns as top-tier program-security concerns;
solinv original 5 High plan didn't include them.

**OtterSec Anchor SECURITY.md** validates solinv's Critical 5 as
"ownership, discriminator, memory safety" Critical tier (118-1176 SOL),
confirming the Critical catalog design is correct.

### Medium (target: 5 invariants — renumbered after High tier expansion)

| # | Name | Status | Bug class |
|---|---|---|---|
| 16 | close-reopen | ⬜ pending | Account close-and-reopen with different data |
| 17 | sysvar-manipulation | ⬜ pending | Clock/Rent sysvar override unhandled |
| 18 | permissionless-misuse | ⬜ pending | "Anyone can call" ix mis-used in privileged context |
| 19 | rent-exemption | ⬜ pending | Rent exempt state unauthorized transition |
| 20 | account-init-race | ⬜ pending | Re-init of allocated account |

### Stretch (Phase 1.5+)

| # | Name | Status | Bug class |
|---|---|---|---|
| 18 | oracle-staleness | ⬜ pending | Oracle price staleness not validated |
| 19 | math-precision-loss | ⬜ pending | Lossy division order causing 0-share-mint |
| 20 | upgrade-authority-leak | ⬜ pending | Program upgrade authority retention |

Total: 17 baseline + 3 stretch = 20 max.

## Spec format

Each invariant gets one markdown file with sections:

1. **Bug class** — what it is, why it matters in Solana
2. **Mainnet precedent + audit findings** — real-world examples
3. **Detection algorithm** — high-level pseudocode
4. **Capability trait + implementation** — Rust code
5. **False-positive risks + mitigations** — table
6. **Severity classification** — Critical/High/Medium with rationale
7. **Test fixture in openhl-solana** — planted bug example
8. **References** — URLs to disclosures, audit reports, blog posts

`signer-skip.md` is the canonical template — copy structure for new specs.

## Implementation order (Phase 1)

Days 16-25 of Month 1:
- Days 16-18: signer-skip (template invariant, refines `solinv-fuzz` API)
- Days 19-20: owner-skip
- Days 21-22: discriminator-skip
- Days 23-24: pda-forge
- Day 25: account-swap

By Month 1 end: 5/17 baseline invariants implemented + working against
openhl-solana with planted bugs.

Days 31-60 (Month 2): remaining 12 invariants + cheat / corpus / disclose
modules.

## Why these specific 15-20?

Source material for catalog:
- Neodyme's "Common Pitfalls in Solana" — top 10 audit findings
- Sec3 public audit summaries — recurring patterns across Anchor reviews
- Trail of Bits Anchor security guidelines
- OtterSec public retrospectives
- Hiro's openhl-solana implementation experience (26 ix, knows where
  signer/owner/discriminator checks live)

solinv's catalog ≈ the union of "what audit firms manually check" +
"what's missing from Trident/Crucible's auto-detection" (= the same set,
since Trident/Crucible auto-detect almost nothing).

## Not in catalog (intentional)

- Oracle manipulation / economic attacks — not invariant-checkable in
  general (requires economic model, not pattern matching)
- Liquidation cascades — requires simulation across many actors
- MEV / sandwich attacks — Tier 3 stretch (separate framework)
- Formal verification / symbolic execution — Tier 1 future work, not
  Phase 1 scope
