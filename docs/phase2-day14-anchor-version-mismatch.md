# Phase 2 Day 14 — Anchor Version Mismatch Discovery

Date: 2026-05-25
Status: Architectural finding — solinv harness pattern requires refactor before production protocol integration.

## Summary

All major Phase 2 candidate protocols use **Anchor 0.x** (production reality),
while solinv was built pinning Anchor 1.0.1 (mirroring Crucible v0.1.0
workspace). The escrow-demo harness worked because we authored escrow
ourselves on Anchor 1.0.1 — but **production Solana DeFi protocols
have not migrated to Anchor 1.0+ yet**.

Day 14 deliverable is therefore the **discovery + refactor plan**,
not klend harness setup. The refactor is straightforward (~2-3 days)
because solinv's invariant detection paths already use `raw_call`
(per Day 3 internals finding) — only the harness's "canonical
untampered" `action_*` call paths import Anchor types.

## Production protocol Anchor version survey

| Protocol | Anchor version | Solana version | ix count | Last update | Repo |
|---|---|---|---|---|---|
| **klend** (Kamino Lend) | 0.29.0 | ~1.17.18 | 623 `pub fn` | 2026-05-13 | github.com/Kamino-Finance/klend |
| **Raydium AMM** | native (no Anchor) | =2.1.0 | 143 `pub fn` | 2025-09-22 | github.com/raydium-io/raydium-amm |
| **Raydium CLMM** | 0.32.1 | workspace | — | recent | github.com/raydium-io/raydium-clmm |
| **Save / Solend** | 0.28.0 | ≥1.9 | — | 2025-07-02 | github.com/solendprotocol/solana-program-library |
| **solinv stack** | **1.0.1** | **3.0** | — | escrow-demo (toy) |

**Conclusion**: solinv's Anchor 1.0.1 pinning is incompatible with
every production protocol on the Phase 2 candidate list.

## Why escrow-demo worked but production won't

escrow-demo's harness uses Anchor IDL-driven typed builders:
```rust
self.ctx.program(self.program_id)
    .call(instruction::Initialize { ... })       // Anchor IDL types
    .accounts(accounts::Initialize { ... })      // Anchor IDL types
    .signers(&[&*depositor])
    .send()
```

This requires the harness Cargo.toml to depend on the same `anchor-lang`
version as the target program. escrow was built by us on 1.0.1, so this
worked. For klend (0.29), the Anchor types are not API-compatible —
`instruction::DepositReserveLiquidity` from anchor 0.29 won't compile
in a workspace pinning anchor 1.0.1.

## The solution (already designed in solinv invariants)

Per Day 3 internals deep-read, solinv's invariant detection paths use
`raw_call(Instruction)` — they manually construct `AccountMeta` lists +
raw ix data bytes. This is **Anchor version-independent** because
`Instruction` is a `solana-program` (or `solana-instruction`) primitive,
not an Anchor concept.

Already-correct invariant pattern (Day 5-9 code):
```rust
let ix = Instruction {
    program_id: spec.program_id,
    accounts: mutated_metas,
    data: spec.data_sample.clone(),  // raw bytes, no Anchor types
};
fixture.ctx_mut()
    .raw_call(ix)
    .fee_payer(&*fee_payer)
    .signers(&signer_refs)
    .send()
```

The harness's `action_*` methods need the same refactor — drop
Anchor IDL-typed builders, manually construct ix data:

```rust
fn action_deposit_reserve_liquidity(&mut self, amount: u64) -> bool {
    let mut data = Vec::with_capacity(8 + 8);
    data.extend_from_slice(&deposit_reserve_sighash());  // sha256("global:deposit_reserve_liquidity")[..8]
    data.extend_from_slice(&amount.to_le_bytes());

    let ix = Instruction {
        program_id: self.program_id,
        accounts: vec![
            AccountMeta::new(self.user_token_account, false),
            AccountMeta::new(self.reserve_pda, false),
            AccountMeta::new_readonly(self.user, true),
            // ... rest of klend's deposit_reserve_liquidity accounts ...
        ],
        data,
    };

    self.ctx.raw_call(ix)
        .fee_payer(&self.fee_payer)
        .signers(&[&*self.user_kp])
        .send()
        .map(|o| o.is_success())
        .unwrap_or(false)
}
```

This pattern is **slightly more verbose** but **completely
version-independent**. solinv-fuzz harness can target Anchor 0.29
klend from a solinv-fuzz/Anchor 1.0.1 workspace because nothing in
the harness imports klend's Anchor types.

## Anchor sighash + arg layout sourcing

For each ix to be added:

1. **Sighash**: `sha256(format!("global:{}", ix_name))[..8]` —
   computable at harness build time from ix name string

2. **Arg layout**: read from the protocol's published IDL JSON
   (klend has `programs/klend/idl/klend.json` or similar in repo).
   Borsh-encode args according to that layout

3. **Account metas**: from IDL or by reading the protocol's source.
   Order + writability flags + signer flags matter

These three are mechanical translation from IDL, **no Anchor runtime
needed in harness**.

## Revised Phase 2 timeline

| Days | Original plan | Revised |
|---|---|---|
| 14 | Kamino harness setup | ✅ Architecture discovery + refactor plan |
| 15-17 | klend harness Day 1-3 | **Harness raw_call refactor** (escrow-demo as test bed) |
| 18-20 | klend harness Day 4-6 | **klend program build** (`cargo build-sbf` on Anchor 0.29 toolchain) + IDL sourcing |
| 21-25 | klend MVP | **klend 5-8 critical ix InstructionSpec construction** (deposit/withdraw/borrow/repay/liquidate) |
| 26-30 | Campaign + triage | Campaign + triage (unchanged) |

klend MVP delayed by ~3 days for refactor, total Phase 2 Month 1 timeline still achievable.

## klend ix selection (5-8 critical of 623)

Focus on lending business logic ix where account-validation bugs would
yield highest bounty:

| Priority | ix name | Why |
|---|---|---|
| 1 | `deposit_reserve_liquidity` | core user deposit, account-validation heavy |
| 2 | `redeem_reserve_collateral` | core user withdrawal |
| 3 | `deposit_obligation_collateral` | borrow position setup, has-one binding critical |
| 4 | `withdraw_obligation_collateral` | reverse, often vulnerable |
| 5 | `borrow_obligation_liquidity` | core debt, oracle + account binding critical |
| 6 | `repay_obligation_liquidity` | reverse of borrow |
| 7 | `liquidate_obligation` | privilege-heavy, complex account graph |
| (8) | `flash_borrow_reserve_liquidity` | flash loan path, classic attack surface |

These 7-8 ix cover ~80% of klend's business logic surface. Remaining
615+ ix are admin/metadata/view = solinv invariants don't apply.

## Meta-lesson for solinv Phase 1 retrospective

solinv's Anchor 1.0.1 pin was inherited from Crucible v0.1.0 workspace
without questioning production reality. escrow-demo gave false
confidence because escrow was authored by us on matching version.

**Future Phase 2+ should validate harness pattern against real
production protocol versions before declaring "ready"**. Add to Phase
1 acceptance contract: "Harness pattern proven against at least one
real protocol on Anchor 0.x" (vs current criterion of "5 invariants
detect planted bugs in self-authored Anchor 1.0.1 escrow").

This is a real **discovery cost paid in Phase 2 Day 14** rather than
Phase 1 Day 13. Acceptable but worth noting for future projects.

## Day 15+ first actions

1. Refactor `examples/escrow-demo/fuzz/escrow/src/main.rs`:
   - Remove `instruction::UnsafeSetAmountFromSource::DISCRIMINATOR` calls
   - Remove `accounts::Foo { ... }` typed builders
   - Replace with manual `sha256` sighash + manual AccountMeta construction
   - Verify 5 isolated test variants still detect (regression)

2. Document the harness raw_call pattern as `docs/harness-pattern-raw-call.md`
   for solinv users (Phase 2 OSS preparation)

3. Begin klend SBF build (next session, fresh Anchor 0.29 toolchain
   environment setup)

## Sources

- klend: github.com/Kamino-Finance/klend (Anchor 0.29, Solana 1.17, BUSL-1.1)
- raydium-amm: github.com/raydium-io/raydium-amm (native, Solana 2.1, Apache-2.0)
- raydium-clmm: github.com/raydium-io/raydium-clmm (Anchor 0.32)
- Solend: github.com/solendprotocol/solana-program-library (Anchor 0.28)
- Anchor sighash spec: anchor-lang Discriminator trait derivation
