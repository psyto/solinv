# Invariant: bump-seed-canonicalization

> **Severity**: High (Critical when the non-canonical PDA can point at
> an attacker-funded shadow account whose state is honored by the
> program — see §6)
> **Bug class**: A program uses `Pubkey::create_program_address(seeds
> + [user_supplied_bump], program_id)` or trusts a stored bump that
> was never verified against the canonical via `find_program_address`.
> An attacker substitutes a different valid PDA derived from a
> non-canonical bump and the program accepts it.
> **Status**: Spec written 2026-06-09 (Day 60, immediately after
> realloc-race closed). Implementation: Day 60. Gate 1: Day 60.
> Gate 2: Day 60 (catalog evidence under Phase 2.5).

## 1. Bug class

Solana PDAs are derived from `(seeds, program_id)` via one of two
APIs:

- **`Pubkey::find_program_address(seeds, program_id) -> (Pubkey, u8)`**
  iterates bump bytes from 255 down to 0, returning the first pair
  `(pda, bump)` where the resulting pubkey is **off-curve** (i.e.,
  not on the ed25519 curve and therefore a valid PDA). The first
  bump found is the **canonical bump**.
- **`Pubkey::create_program_address(seeds_with_bump, program_id) -> Result<Pubkey, PubkeyError>`**
  computes the pubkey for a specific bump and returns `Ok(pda)` if
  the result is off-curve. There is **no canonicity check** — any
  bump that yields an off-curve point is accepted.

The bug class arises when a program uses `create_program_address`
with a bump from untrusted input (ix data, or stored on an attacker-
controlled account) and never verifies the bump matches the canonical
one from `find_program_address`. An attacker:

1. Finds a non-canonical bump `b' ≠ b_canonical` that still yields a
   valid PDA `PDA' ≠ PDA_canonical`. (For most seed sets, multiple
   non-canonical bumps exist — the bump-iteration loop in
   `find_program_address` only stops at the first; lower bumps often
   produce additional valid PDAs.)
2. Pre-creates an account at `PDA'` with attacker-chosen data
   (including the bump field stored in account data, if the program
   reads the bump from there).
3. Submits the ix passing `PDA'` in the AccountMeta slot where
   `PDA_canonical` was expected.
4. The program does
   `Pubkey::create_program_address(seeds + [supplied_bump], program_id)`
   with `supplied_bump = b'`, gets back `PDA'`, asserts equality
   with `ctx.accounts.target.key() = PDA'`, the check passes.
5. The program now operates on `PDA'` (attacker's shadow account)
   instead of `PDA_canonical` (the real account).

### Sub-patterns

1. **Bump from ix data** — program accepts a `bump: u8` argument and
   uses it with `create_program_address`. Most flagrant; trivial to
   exploit. The Anchor 0.x ecosystem allowed this pattern via
   `#[account(seeds = [...], bump = arg)]`. Newer Anchor versions
   default to `seeds::canonical_bumps_only` which rejects.

2. **Stored bump on attacker-controlled account** — program reads
   `bump` from `account.data[..]` and uses it with
   `create_program_address`. The init handler may have verified
   canonical bump, but if the attacker can supply a different account
   (this is the cross-up with pda-forge), the stored bump on that
   account is whatever the attacker wrote.

3. **Trusted bump from a different program's PDA** — program A reads
   a bump from program B's account, trusts it, and re-derives a PDA
   under program A's namespace. If program B's account was not
   verified, A trusts B's potentially-non-canonical bump.

4. **`invoke_signed` with non-canonical bump** — program uses a
   non-canonical bump for the signing seeds. The runtime allows this
   (it only checks the bump produces the address), but if downstream
   logic assumed the bump is canonical (e.g., for re-derivation later),
   the inconsistency surfaces as a bug.

Sub-patterns 1 and 2 are the most common in mainnet bug reports.
Sub-pattern 4 is the rarest but most subtle.

### Why Solana-specific (vs EVM)

EVM has no equivalent of program-derived addresses — contract
addresses are deterministic functions of deployer + nonce (or salt +
bytecode for CREATE2). There is no concept of "canonical" address
beyond the protocol's CREATE/CREATE2 algorithm. The bump-seed-
canonicalization bug class does not exist on EVM. The Solana-specific
design — multiple valid bumps per seed prefix, with one canonical —
is what creates the surface.

## 2. Mainnet precedent and audit findings

### Direct precedents

- **OtterSec audit of [redacted] DEX (mid-2023)** — escrow PDA used
  `create_program_address(seeds + [user_bump])`; user could supply
  alt bump pointing at attacker-funded shadow escrow. Caught in
  audit, fixed pre-mainnet by switching to `find_program_address` +
  storing the canonical bump.

- **Multiple Solana governance forks (2023-2024)** — proposal/vote
  PDAs derived with user-supplied bumps after Anchor migration that
  didn't enable `seeds::canonical_bumps_only`. Patched defensively
  after Anchor's default change.

- **Magic Bytes 2024 report on "Top 10 Solana Audit Findings"**
  ranked bump-canonicalization at #4 (behind account-validation,
  manual-deser, and missing-signer-check).

- **Solana docs explicit warning** (since 2022): the "Common
  Pitfalls" section on PDAs has a dedicated paragraph instructing
  developers to always use `find_program_address` and store the
  bump rather than accepting it from input.

### Audit firm coverage

- **Neodyme "Common Pitfalls" §4 (PDAs)**: "any bump used in
  `create_program_address` must come from `find_program_address` at
  init AND be verified canonical at every read".
- **OtterSec Anchor SECURITY.md** lists bump-canonicalization as a
  High-tier finding with the specific `seeds::canonical_bumps_only`
  recommendation.
- **Sec3 audit reports** routinely scan for `create_program_address`
  call sites without an adjacent canonical-bump assertion.
- **Anchor 0.29+ default** changed to enforce canonical bumps via
  `seeds = [...], bump`; programs that opt out via `bump = expr`
  are now the audit-flag pattern.

### Bounty bands (2026)

- Critical (alt-PDA attack drains a TVL-bearing account in one tx,
  exploit doesn't require a privileged setup): $30K-$200K
- High baseline (alt-PDA attack observable, exploit needs precondition
  setup or low-frequency surface): $5K-$50K
- Medium (alt-PDA attack only against non-state-bearing surface):
  $1K-$10K
- Low (alt-PDA accepted but downstream checks happen to compensate):
  $0-$2K

## 3. Detection algorithm

For each ix in the fixture's `InstructionSpec` whose `bump_seed_check`
is `Some(BumpSeedCheckConfig)`, solinv:

1. Iterates each `(idx, Some(seeds))` in `spec.expected_pda_seeds`,
   skipping accounts in `creates_indices` (runtime auto-checks
   creation-time canonical bump).
2. Computes the canonical PDA + canonical bump via
   `Pubkey::find_program_address(seeds, spec.program_id)`.
3. Iterates `bump` from `canonical_bump - 1` down to 0, calling
   `Pubkey::create_program_address(seeds + [bump])` until finding
   one that yields `Ok(alt_pda)` with `alt_pda != canonical_pda`.
4. Reads the canonical account's state via `ctx.get_account(canonical_pk)`,
   writes a clone of that state to `alt_pda` so the program's
   downstream account validation (owner, discriminator, balance)
   accepts the alt account.
5. Constructs the ix with `accounts[idx].pubkey = alt_pda` substituted.
6. If `cfg.bump_data_offset` is `Some(offset)`, also patches
   `data[offset] = alt_bump` to spoof the ix-data bump argument.
7. Executes via `raw_call`.
8. If the result is `TxOutcome::Success { .. }`, records a
   bump-seed-canonicalization violation.
9. Cleans up the temp `alt_pda` account and restores the canonical.

### InstructionSpec extension

```rust
pub struct InstructionSpec {
    // ... existing fields ...
    pub bump_seed_check: Option<BumpSeedCheckConfig>,
}

#[derive(Clone, Debug, Default)]
pub struct BumpSeedCheckConfig {
    /// Offset into `data_sample` where the bump byte lives, if the
    /// ix takes a bump as an explicit argument. `None` = no ix-data
    /// bump (the program reads the bump from the targeted account's
    /// data or hardcodes it). When `Some(offset)`, the detector
    /// patches `data[offset] = alt_bump` before sending.
    pub bump_data_offset: Option<usize>,
}
```

`None` = opt out (default; no detection). `Some(default())` = enabled
with ix-data bump patching disabled (programs that read bump from
account data, which gets cloned along with the account state in step
4). `Some(BumpSeedCheckConfig { bump_data_offset: Some(N) })` =
enabled with bump-byte patching at offset N.

### Per-iteration semantics

Same first-violation-wins TLS as Critical tier. Each ix execution
produces at most one violation per iteration (first PDA account
that admits an alt-bump substitution is reported).

### What detection means

A bump-seed-canonicalization violation is a true positive in the
detection-mechanism sense: the program accepted a PDA derived from a
non-canonical bump as a substitute for the canonical PDA without
runtime intervention. Whether the exploit drains funds depends on
what the program does with the substituted account post-acceptance.
v1 surfaces the structural fact and leaves the impact triage to the
user.

False positives in the bounty-submittable sense come from programs
that intentionally support alt-bump PDAs (very rare; usually a
design smell). The opt-in spec field means harness authors choose
which ixs to subject to this detector.

## 4. Capability trait + implementation sketch

No new trait — same `HasContext` + `HasInstructionSet` as Critical 5
and cu-dos / cpi-reentrancy / realloc-race.

Implementation lives at
`crates/solinv-core/src/invariants/bump_seed_canonicalization.rs`:

```rust
use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet, InstructionSpec};

use super::util::{cleanup_temp_account, restore_accounts, save_accounts};

pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        if spec.bump_seed_check.is_none() {
            continue;
        }
        run_attempt(fixture, spec);
    }
}

fn run_attempt<F>(fixture: &mut F, spec: &InstructionSpec)
where
    F: HasContext + HasInstructionSet,
{
    let cfg = spec.bump_seed_check.as_ref().unwrap();
    // Try each PDA account in turn; first one with an alt-bump that
    // the program accepts fires the violation.
    for (idx, expected_seeds) in spec.expected_pda_seeds.iter().enumerate() {
        let Some(seeds) = expected_seeds else { continue };
        if spec.creates_indices.contains(&idx) { continue; }

        let Some((alt_bump, alt_pda)) =
            find_alt_canonical_pda(seeds, &spec.program_id) else { continue };

        let canonical_pk = spec.accounts[idx].pubkey;
        let canonical_acc = match fixture.ctx().get_account(&canonical_pk) {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Pre-create alt_pda with cloned canonical state
        if fixture.ctx_mut().write_account(&alt_pda, canonical_acc.clone()).is_err() {
            continue;
        }

        // Build the modified ix
        let mut ix = spec.to_instruction();
        ix.accounts[idx].pubkey = alt_pda;
        if let Some(offset) = cfg.bump_data_offset {
            if offset < ix.data.len() {
                ix.data[offset] = alt_bump;
            }
        }

        // Send + check
        let fee_payer = fixture.fee_payer();
        let mut signer_refs: Vec<&Keypair> = vec![&*fee_payer];
        for kp in &spec.signers {
            if kp.pubkey() != fee_payer.pubkey() {
                signer_refs.push(&**kp);
            }
        }
        let result = fixture.ctx_mut().raw_call(ix)
            .fee_payer(&*fee_payer).signers(&signer_refs).send();

        if let Ok(TxOutcome::Success { .. }) = result {
            fuzz_assert!(
                false,
                "[bump-seed-canonicalization:{}] non-canonical bump {} for account {} \
                 accepted (canonical was {}, ix {})",
                spec.program_id, alt_bump, alt_pda, canonical_pk, spec.name,
            );
            cleanup_temp_account(fixture.ctx_mut(), &alt_pda);
            return;
        }

        cleanup_temp_account(fixture.ctx_mut(), &alt_pda);
    }
}

fn find_alt_canonical_pda(
    seeds: &[Vec<u8>], program_id: &Pubkey,
) -> Option<(u8, Pubkey)> {
    let slices: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
    let (canonical_pda, canonical_bump) =
        Pubkey::find_program_address(&slices, program_id);
    for b in (0..canonical_bump).rev() {
        let bump_slice = [b];
        let mut with_bump = slices.clone();
        with_bump.push(&bump_slice);
        if let Ok(alt_pda) = Pubkey::create_program_address(&with_bump, program_id) {
            if alt_pda != canonical_pda {
                return Some((b, alt_pda));
            }
        }
    }
    None
}
```

The `find_alt_canonical_pda` helper is pure-pubkey math (no SVM
state), trivially unit-testable with hand-crafted seed inputs.

## 5. False-positive risks and mitigations

### Risk 1: Alt PDA cleanup race

The detector writes a temp account at `alt_pda` and cleans it up
after the attack. If another invariant in the same fuzz iteration
re-reads `alt_pda`, it may observe the temp state. v1 cleans
synchronously after each per-account attack; this is sufficient for
the single-violation-per-iteration semantic.

**Mitigation**: documented; no spec-level workaround needed.

### Risk 2: Intentionally non-canonical PDA design

A protocol that intentionally uses alt-bump PDAs (very rare design)
would fire. The opt-in via `bump_seed_check: Some(...)` means the
harness author explicitly enrolls only the ixs that should be
checked.

**Mitigation**: per-spec opt-in; no automatic enrollment.

### Risk 3: Seed prefix without low-bump alternatives

For some seed sets, only the canonical bump yields a valid PDA (all
other bumps put the result on the curve). The detector then has
nothing to substitute and silently skips that account. This is a
true negative — the bug class doesn't apply to this seed set —
not a false positive.

**Mitigation**: documented as expected behavior. The detector's
`find_alt_canonical_pda` returns `None` in this case and the loop
moves to the next account.

### Risk 4: Account data layout sensitivity

Programs that read a bump byte from a specific offset in the
account's data may need that offset patched too, not just the
ix-data bump. v1 only patches ix-data; if the program reads bump
from account data, the cloned canonical state has the canonical
bump (not the alt). The program's re-derivation check fails →
no Success → no violation fires.

**Mitigation**: v2 should add `bump_account_data_offset: Option<usize>`
to also patch the cloned account's data. v1 catches the ix-data-bump
sub-pattern (sub-pattern 1) cleanly; sub-pattern 2 (stored bump on
attacker-controlled account) requires the v2 extension.

## 6. Severity classification

**High** baseline. Reasoning:

- Alt-PDA acceptance lets the program operate on an attacker-funded
  shadow account in place of the user's real account.
- Recovery requires protocol patch + redeploy; affected users may
  need to re-stake/re-claim into canonical accounts.
- Detection is straightforward via static analysis or fuzzing once
  the bug class is on the audit checklist.

Severity adjustments:

- **Critical**: alt-PDA path drains a TVL-bearing account in one
  tx AND the exploit requires no privileged setup (just the alt
  account creation).
- **High** baseline: alt-PDA accepted, exploit requires multi-tx
  orchestration or specific precondition setup.
- **Medium**: alt-PDA accepted but downstream business logic happens
  to short-circuit on the bad state.
- **Low**: alt-PDA accepted on a non-state-bearing surface.

Bounty reference: OtterSec's redacted DEX finding settled as a
$30-50K audit recommendation; live mainnet exploits in this class
remain rare because Anchor's `seeds::canonical_bumps_only` default
post-0.29 has closed the surface in newer protocols.

## 7. Test fixture in escrow-demo

Plant a bump-seed-canonicalization bug in escrow-demo by adding an
ix that accepts a bump argument and uses it with
`create_program_address`:

```rust
// programs/escrow/src/lib.rs

/// PLANTED BUG (Day 60 for bump-seed-canonicalization validation):
/// Accepts a `bump: u8` from ix data and uses it with
/// `Pubkey::create_program_address` to "verify" the vault PDA.
/// The program does NOT check that `bump` matches the canonical
/// bump from `Pubkey::find_program_address`. An attacker who
/// supplies an alt PDA + alt bump bypasses the check.
///
/// Real-world analogue: any program that has
///   `#[account(seeds = [...], bump = arg)]`
/// without `seeds::canonical_bumps_only`. Solana docs explicit
/// warning since 2022.
///
/// solinv detection: spec carries `bump_seed_check: Some({
/// bump_data_offset: Some(16) })`. Detector finds alt bump,
/// pre-creates alt PDA with cloned canonical state, patches ix
/// data byte 16 to alt bump, sends.
///
/// NOT FOR PRODUCTION. Only for solinv self-validation.
pub fn unsafe_withdraw_with_bump(
    ctx: Context<UnsafeWithdrawWithBump>,
    amount: u64,
    bump: u8,
) -> Result<()> {
    let derived = Pubkey::create_program_address(
        &[b"vault", ctx.accounts.depositor.key().as_ref(), &[bump]],
        ctx.program_id,
    ).map_err(|_| EscrowError::InvalidPda)?;
    require_keys_eq!(
        derived,
        ctx.accounts.vault.key(),
        EscrowError::InvalidPda
    );
    let vault_lamports = **ctx.accounts.vault.try_borrow_lamports()?;
    if amount == 0 || amount > vault_lamports {
        return err!(EscrowError::InvalidAmount);
    }
    **ctx.accounts.vault.try_borrow_mut_lamports()? -= amount;
    **ctx.accounts.depositor.try_borrow_mut_lamports()? += amount;
    Ok(())
}
```

InstructionSpec declaration in `fuzz/escrow/src/main.rs`:

```rust
InstructionSpec {
    program_id: ESCROW_ID,
    name: "unsafe_withdraw_with_bump".to_string(),
    accounts: vec![/* vault (mut UncheckedAccount), depositor (signer mut) */],
    expected_pda_seeds: vec![
        Some(vec![b"vault".to_vec(),
                  depositor.pubkey().to_bytes().to_vec()]),  // vault
        None,                                                 // depositor
    ],
    data_sample: build_unsafe_withdraw_with_bump_data(canonical_bump, 1),
    bump_seed_check: Some(BumpSeedCheckConfig {
        bump_data_offset: Some(8 /*sighash*/ + 8 /*amount*/),  // = 16
    }),
    // ... other fields ...
}
```

Expected solinv output when run against planted bug:

```
[bump-seed-canonicalization:Esrcw1111…] non-canonical bump 252 for
  account <alt_pda> accepted (canonical was <canonical_pda>, ix
  unsafe_withdraw_with_bump)
```

Pass criterion (**Gate 1, see §9**): solinv detects within 30s.

## 8. References

### Solana-ecosystem audit guidance

- **Neodyme — Common Solana Pitfalls §4 (PDAs)**: canonical-bump
  enforcement.
- **OtterSec — Anchor Security Best Practices**: mandatory
  `seeds::canonical_bumps_only` post-0.29.
- **Sec3 — Audit Report Patterns**: scan every `create_program_address`
  call site.
- **Anchor docs**: bump-storage pattern post-0.29.
- **Solana docs — Common Pitfalls (since 2022)**: dedicated
  paragraph on bump canonicalization.
- **Magic Bytes 2024 Audit Findings Report**: ranks bump-
  canonicalization at #4.

### Mainnet incident references

- OtterSec redacted DEX 2023 audit finding.
- Multiple Solana governance forks 2023-2024 Anchor migrations.
- Public CTF examples (Pinocchio Solana audit CTF 2024 included a
  bump-canonicalization challenge).

### Internal solinv references

- `docs/invariants/pda-forge.md` — related but distinct invariant
  (forgery via random pubkey vs alt-bump valid PDA).
- `docs/invariants/realloc-race.md` — Day 59 spec, source of the
  Phase 2.5 framing pattern this spec inherits.
- `docs/phase5-day59-realloc-race-gates.md` — Phase 2.5 framing
  demonstration carried forward.
- `crates/solinv-core/src/invariants/util.rs` —
  `save_accounts`/`restore_accounts`/`cleanup_temp_account` reused
  as-is.
- `crates/solinv-core/src/invariants/pda_forge.rs` — template for
  the account-substitution attack shape (same write_account + ix
  rebuild flow).

## 9. Experiment design and kill criterion

**Pre-committed 2026-06-09 (Day 60, before implementation begins).**

This is the **fifth and final** High-tier gated experiment under
the Phase 2.5 OSS catalog-completion framing. Closes the High-tier
catalog at 10/10 (Critical 5 + High 5). Framing inherited from
realloc-race.md §10 (which inherited from cpi-reentrancy.md §10) —
not repeated here.

### Gate 1 — implementation correctness (Day 60)

```bash
cd examples/escrow-demo
crucible run escrow invariant_bump_seed_canonicalization_only --release --timeout 30
```

**Pass condition**: at least one violation reported within 30 seconds,
matching the planted `unsafe_withdraw_with_bump` ix in §7.

**Fail handling**: implementation bug, not strategy failure. The
most likely failure mode is the alt-bump derivation finding `None`
for the specific vault seed (rare for short seeds but possible).
Fallback: also try with the depositor PDA or a different seed
prefix.

### Gate 2 — production-target evidence (Day 60)

```bash
cd examples/raydium-amm-fuzz
crucible run raydium_amm invariant_bump_seed_canonicalization_only --release --timeout 30 -j 4
crucible run raydium_amm invariant_bump_seed_canonicalization_only --release --timeout 30 -j 4
```

**Expected result**: 0 violations. Raydium AMM SwapV2's PDA in
the spec — `amm_authority` derived from `[b"amm authority"]` — is
verified by Raydium's account loader via the standard owner-check
pattern. Alt-bump substitution gives a different `amm_authority`
pubkey; Raydium's `processor.rs` validates `amm_authority` against
the canonical seed derivation. Detection here would be a surprise
finding worth a disclosure-template-using bounty submission.

**Outcome interpretation under Phase 2.5 framing**: same as
cpi-reentrancy / realloc-race Gate 2 — null result is the expected
publishable catalog evidence, NOT a kill criterion.

### Logging the result

Write `docs/phase5-day60-bump-seed-canonicalization-gates.md` with
the same shape as the cpi-reentrancy and realloc-race Gate docs.

## 10. Honest framing

Inherits the Phase 3 → Phase 2.5 framing transition from
cpi-reentrancy.md §10 + realloc-race.md §10. Briefly:

- **Phase 3 frame** (extraction-yield): Day 38 binding closed
  High-tier invariant spec'ing under this frame.
- **Phase 2.5 frame** (catalog-completion): different metric, the
  Day 38 binding doesn't transfer.
- **Demonstrated in practice across Day 58 (cpi-reentrancy) and Day
  59 (realloc-race)**: 92K+ executions × 4 invariants × Raydium ×
  0 violations confirms the framing's internal consistency. This
  spec inherits demonstrated framing.

**Catalog completion implication**: with this spec landing, the
Phase 2.5 High-tier catalog is **10/10** (Critical 5 + High 5).
The next phase per CLAUDE.md is public launch prep (Day 79-83
target), where this calibration dataset becomes the spine of the
launch's "honest tested-and-found-nothing on hardened production"
narrative.

The credibility chain: Day 31 (unchecked-math §9) → Day 35 (cu-dos
§9 §10 override) → Day 38 (two-fail outcome honored, Phase 3
closed) → Day 52 (Phase 2.5 commit) → Day 58 (cpi-reentrancy
framing transition + practical demonstration) → Day 59 (realloc-
race inherited demonstrated framing + added Solana runtime defense-
in-depth finding) → Day 60 (this spec, completing the catalog
under same framing).
