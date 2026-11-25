# From a solinv finding to a Lean proof

solinv says where an account check is missing or was dropped. It does not say that the fix closes
the hole. This page shows how we took one finding further: we stated in Lean that the hole is real,
and proved that the fix closes it. The proof is on top of
[Solanalib](https://github.com/solana-foundation/leanprover-solanalib), Solana Foundation's Lean
models of the Solana runtime and of the crates programs use.

We did this once, on one of our own Anchor programs (private). Below is the shape of what we did,
not a tool that does it for you.

## The finding

A `Signer` that nothing ties to stored state. In the map it is an account that has to sign but
whose key nothing checks, so any key that signs passes:

```rust
#[derive(Accounts)]
pub struct Settle<'info> {
    pub operator: Signer<'info>,          // before: any signer settles
    ...
}
```

The fix ties the key to the stored authority:

```rust
    #[account(constraint = operator.key() == platform_config.authority @ MyError::Unauthorized)]
    pub operator: Signer<'info>,
```

## The statements

Solanalib models `Signer` validation (`validate .signer` in
`Solanalib.Specs.Core.AnchorLifecycleValidation`). It does not model the body that
`#[derive(Accounts)]` generates, so the fixed version is written by hand as "the `Signer` check, then
the constraint":

```lean
def settleOperatorV1 (types : ValidationTypes) (authority : Pubkey)
    (unauthorized : types.toBase.Error) :
    types.toBase.Run ReferenceArgs (Except types.toBase.Error AnchorAccount.Signer) :=
  fun before args outcome =>
    ∃ checked, validate .signer .borrowed types before args checked ∧
      match checked with
      | .returned (.ok signer) state =>
        if signer.info.key = authority then outcome = .returned (.ok signer) state
        else outcome = .returned (.error unauthorized) state
      | other => outcome = other
```

The two theorems:

- **The hole is real.** In any state and for any stored authority, the version before the fix
  accepts a signer with another key (an explicit witness: `isSigner = true`, `key ≠ authority`).
- **The fix closes it.** If the fixed validation succeeds, the account signed and its key is the
  stored authority.

Both are proved with no `sorry`, and both depend only on `propext`. The file is 107 lines, and it
type-checks in about a second once Solanalib is built.

## What it does not cover

- Only the one field. The other checks in the struct are left out: account status, mint, and the
  vault and fee token accounts.
- The generated check order and the error Anchor builds are our reading of the macro, not a model
  reviewed against anchor-syn. We asked upstream whether they want that modeled:
  [solana-foundation/leanprover-solanalib#13](https://github.com/solana-foundation/leanprover-solanalib/issues/13).
- It is a proof about a Lean model, not about the compiled program.

## Next

Most of the real holes solinv's map found in our programs were mints not tied to stored state
(see [Where we use it ourselves](../README.md#where-we-use-it-ourselves)). `address = …` and
`token::mint = …` are the next constraints to state in the same way.
