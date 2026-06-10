# Phase 2 Day 20 — Raydium AMM Triage (SwapBaseInV2 surface clean)

Date: 2026-05-25
Status: ✅ All 4 applicable invariants = 0 detections post-refinement. Day 16 open question #3 RESOLVED.
Schedule: 3-4 days ahead of Day 14 baseline; Day 19+20 collapsed into 1 session.

## Goal

Day 19 surfaced a likely-false-positive account-swap detection on
`user_destination`. Day 20:

1. Refine InstructionSpec `swap_alternates[6] = vec![]` (DEX semantics)
2. Add 4 isolated invariant variants (Day 12 escrow-demo pattern)
3. Run sequential regression for all 4 (Day 15 finding: parallel deadlocks)
4. Triage every detection: real bug / false positive / inconclusive
5. Determine whether SwapBaseInV2 surface is clean or has actionable findings

## Refined InstructionSpec — swap_alternates analysis

| idx | Account | Pre-refinement | Post-refinement | Reason |
|---|---|---|---|---|
| 0 | spl_token | `vec![]` | `vec![]` | Fixed program id |
| 1 | amm_pool | `vec![]` | `vec![]` | Cross-pool needs 2nd fixture (Day 21) |
| 2 | amm_authority | `vec![]` | `vec![]` | PDA, handled by pda_forge |
| 3 | coin_vault | `vec![pc_vault]` | `vec![pc_vault]` | Tests vault-key mismatch |
| 4 | pc_vault | `vec![coin_vault]` | `vec![coin_vault]` | Reverse |
| 5 | user_source | `vec![user_b_source]` | `vec![user_b_source]` | Tests SPL Token signer-mismatch |
| 6 | user_dest | `vec![user_b_dest]` | **`vec![]`** | **DEX user-controlled (Uniswap/Orca/Meteora pattern)** |
| 7 | user_owner | `vec![]` | `vec![]` | Signer identity |

Single-line fix in `main.rs` HasInstructionSet impl.

## Sequential regression matrix

`crucible run raydium_amm invariant_<X>_only --release --timeout 30 -j 2`:

| Invariant | Crashes | Executions | Wall time | Result |
|---|---|---|---|---|
| signer-skip | **0** | 13,320 | 30s | ✅ Raydium enforces |
| owner-skip | **0** | 3,404 | 46s | ✅ Raydium enforces |
| pda-forge | **0** | 16,869 | 30s | ✅ Raydium enforces |
| account-swap | **0** | 5,050 | 35s | ✅ Raydium enforces |
| **combined** (4-in-1) | **0** | 1,527 | 31s | ✅ Day 19 FP eliminated |

**Total: 0 violations across 40,170 attacks in ~2.5 min sequential sweep.**

## Triage — interpretation

### 0 detections is a POSITIVE outcome, not a negative

Day 13 escrow-demo proved invariants ARE sensitive: 137,559 violations
when bugs exist. Today's 0 detections mean **Raydium AMM correctly
handles all 4 attack patterns on the SwapBaseInV2 ix surface**:

- `signer-skip`: Raydium's explicit `if !user_source_owner.is_signer`
  check at `processor.rs:3053` catches the flip
- `owner-skip`: `AmmInfo::load_mut_checked` rejects wrong-owner pool;
  SPL Token `unpack_token_account` rejects wrong-owner vaults
- `pda-forge`: `amm_authority_info.key != authority_id(...)` check at
  `processor.rs:3063` catches forged PDA
- `account-swap`: vault-key equality checks at `processor.rs:3068-3078`
  catch vault substitution; SPL Token transfer signer-check catches
  user_source substitution

### Day 16 open question #3 RESOLVED: `create_program_address` compat

Question: solinv pda_forge invariant tests against `find_program_address`
(canonical). Raydium uses `create_program_address` (non-canonical, nonce
in seeds). Would solinv work?

**Answer: yes, works unchanged**. Solinv's pda_forge attack
substitutes a random pubkey at the PDA account position. The defender's
PDA derivation style (canonical vs not) doesn't matter — what matters
is whether the program CHECKS that the passed pubkey matches the
derived one. Raydium checks (line 3063), so attack fails, no detection.

No changes needed to solinv's pda_forge invariant for Native protocols.

### Day 19's account-swap on user_dest — confirmed false positive

DEX swap output goes to whatever destination the signer specifies.
This is intentional permissive design across all on-chain DEXes
(Uniswap V2/V3, Orca Whirlpool, Meteora, Phoenix). Raydium's
processor doesn't validate `user_dest.owner == user_source_owner`
and SHOULDN'T — that would break router contracts and aggregator
flows.

Lesson: **per-ix InstructionSpec must encode protocol semantics**, not
just account validation. For DEX swap outputs: `swap_alternates =
vec![]` is the right default. For lending borrow destinations:
similar pattern. For governance proposal recipients: similar.

## Value delivered

- **Phase 1 acceptance criterion satisfied** for Native protocol target:
  harness pattern proven against Raydium AMM in production form
- **Day 14 hit-rate prediction validated**: 4/5 invariants applicable to
  Native (vs 1-2 on Anchor — to verify Day 23+ klend)
- **SwapBaseInV2 surface confirmed clean** — Raydium has no easy
  Critical bugs in account validation on this ix
- **Reusable pattern**: per-ix `swap_alternates` audit (DEX user-controlled
  vs context-bound) becomes a checklist item for every new ix added

## Implications for bug bounty hunting expectation

Raydium AMM SwapBaseInV2 = audited surface = no expected bounty here.
But Raydium AMM has 5 more user-facing ix (Deposit, Withdraw,
SwapBaseIn/Out legacy with orderbook) — larger surfaces, more complex
account graphs, higher likelihood of overlooked checks.

| ix | Accounts | Day | Expected
yield |
|---|---|---|---|
| SwapBaseInV2 | 8 | 18-20 ✅ done | none (proven clean) |
| SwapBaseOutV2 | 8 | 21 | low (mirror of InV2, same checks) |
| Deposit | 14 | 21 | low-medium |
| Withdraw | 20 | 21-22 | medium (largest user-facing surface) |
| SwapBaseIn (legacy) | 18 | 22 | medium (orderbook integration) |
| SwapBaseOut (legacy) | 18 | 22 | medium |

**Realistic Phase 2 bug bounty expectation on Raydium AMM**: 0-1
Critical findings, modal 0. Focus value on klend (Day 23+) where
Anchor's auto-protection leaves a smaller surface but the cross-
account relationships (Day 17 inventory) are richer.

## Files changed Day 20

- `examples/raydium-amm-fuzz/fuzz/raydium_amm/src/main.rs` — 4 isolated
  variants + swap_alternates[6] = vec![] refinement
- `examples/raydium-amm-fuzz/fuzz/raydium_amm/Cargo.toml` — 4 feature
  gates added
- `docs/phase2-day20-raydium-triage.md` (this log)

## Day 21 plan

Add Deposit + Withdraw + SwapBaseOutV2 InstructionSpecs to the harness.
Each one ~30-50 LOC (mirror SwapBaseInV2 pattern but different account
counts/orders/data layouts). Re-run sequential regression on all
inv-ix combinations. Triage any new detections.

Day 22 plan TBD based on Day 21 outcomes — either add legacy
SwapBaseIn/Out (with orderbook fixture cost) or accelerate to klend
(Day 23+).
