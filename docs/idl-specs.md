# Specs from an Anchor IDL

`solinv-fuzz::idl` turns an Anchor IDL plus a fixture's post-setup
state into the account-validation fields of an `InstructionSpec`, and
`solinv idl` reads the same IDL with no fixture at all. This note
records why it is split the way it is, and what it does not do.

## The IDL alone finds nothing on Anchor

What an Anchor IDL declares, Anchor's macros enforce: `signer: true`
is a `Signer<'info>`, `pda.seeds` is a `seeds = [...]` constraint. A
spec built from the IDL alone asks the program to honour checks it
generated itself, so on Anchor code the Critical 5 cannot fire on it.
The account-validation bugs live in slots the IDL is silent about —
an `UncheckedAccount` or `AccountInfo` that the handler is supposed to
validate by hand. Expectations for those slots can only come from what
the fixture put there.

## Facts and candidates

| pass | adds | basis |
|---|---|---|
| `build()` | accounts, signers, PDA seeds, data | the IDL |
| `infer_from_state` | owner + discriminator of seeded slots; created accounts | a seeded slot pins one address |
| `infer_candidates` | owner + discriminator, PDA seeds, signer for silent slots | fixture state |

`infer_candidates` proposes, for a slot the IDL leaves unconstrained:

- **owner / discriminator** when it holds a program-owned account
  carrying an IDL discriminator;
- **PDA seeds** when a seed pattern declared elsewhere in the IDL
  (evaluated inside the composite it was declared in) re-derives the
  slot's exact address;
- **signer** when the instruction has no signer, writes a program-owned
  account, and that account's data contains the slot's pubkey — and a
  keypair for the slot was bound.

These describe what the fixture passed, not what the instruction must
require. The standing counterexample: a correct permissionless crank
that pays a stored `beneficiary` satisfies the signer rule. So:

- the two passes are separate calls, and a harness can stop after the
  first;
- every candidate is listed in `IdlSpec::candidates()`;
- `IdlSpec::candidate_log()` emits `[SOLINV_CANDIDATES] ix=… account=…`
  lines. Findings name the instruction and account index but carry no
  provenance — `InstructionSpec` has no field for it, and its `name`
  keys the reachability ledger — so the log is where a finding on a
  candidate is told apart from one on a fact.

## What is left out, and said so

`IdlSpec::unresolved()` lists what neither pass could fill:
`swap_alternates` (a semantic relation, always), seeds that read
account data (`vault.authority`), seeds derived under another program,
unbound `arg` seeds, discriminators that are not 8 bytes long
(discriminator-skip compares 8; the owner is still set), and seed
patterns that could not be evaluated for a typed slot.

Also listed, as information rather than gaps: `IdlSpec::defaulted()`
names slots bound by name because the IDL gave no address —
`system_program` and `associated_token_program` only. A name is a
convention, not a declaration: a program-owned account may be called
`clock`, and `token_program` may be SPL Token or Token-2022, so those are
never guessed. A program id that differs from the
IDL's `address` is an `unresolved()` entry, since the `.so` must
`declare_id!` the id it is loaded at or Anchor rejects every instruction
with `DeclaredProgramIdMismatch`. Jito's tip-distribution hit both: its
shipped IDL has no `system_program` address, and its `.so` built
without `--features mainnet` declares the testnet id.

Assumptions accepted as limitations:

- the facts pass takes a seeded slot to hold one type;
- skipped seed patterns are reported only for typed slots, since every
  wallet slot would otherwise report them.

## Formats

Anchor 0.30+ IDLs, built with PDA resolution on (`anchor build` does
this; a bare `cargo test --features idl-build` needs
`ANCHOR_IDL_BUILD_RESOLUTION=TRUE`). `Idl::from_json` takes that format
only; `Idl::from_json_any` (used by `solinv idl` and `solinv diff
--base-idl`) also reads legacy (pre-0.30) IDLs, converted as `anchor idl
convert` does except for its two bugs (anchor#5255 seed quotes, anchor#5256
relations on the wrong account; fixed on master by anchor#5257, not yet
released). Shank IDLs are rejected as unsupported. Composite
accounts bind by dotted path (`group_a.authority`) or by a leaf name
that is unique in the instruction; an unbound optional account is
encoded as the program id and signs nothing.

## What `solinv idl` is for

The static report lists every slot's declared constraints and names
the instructions with no signer that write an unconstrained slot.

The IDL cannot say whether an unconstrained slot is a typed account or
an `UncheckedAccount`: Anchor drops the `/// CHECK:` line from `docs`,
and typed accounts carry ordinary doc comments too, so `docs` is no
signal either way. `--src <dir>` reads the declared types from the
`#[derive(Accounts)]` structs, joined to instructions through the
handlers' `Context<..>` (composites by dotted path), and marks each slot
`U` or `T`. It is a line-based reader, not a parser. Comments and string
literals are stripped first; `T` is given only for Anchor's typed
wrappers (`Account`, `AccountLoader`, `InterfaceAccount`, `Signer`,
`Program`, `Interface`, `Sysvar`, `SystemAccount`), `U` for
`UncheckedAccount` and `AccountInfo`, and `t` for a typed data account
(`Account`, `AccountLoader`, `InterfaceAccount`) whose identity no
`seeds`, `address`, `has_one`, `associated_token::*` or `.key()`
comparison fixes (on it, or on
another slot naming it) and that `init` does not create — the summary
lists the writable ones as `account-swap` candidates; a key check at
the top level of the handler body counts, one in a function the
handler calls is not read; any other type — type aliases
included, since what an alias names depends on module scope and
imports — a struct name defined twice, or a field type split over
lines leaves the slot unplaced, and the report counts it as not found. When
nothing under `--src` can be placed, the CLI says so instead of
printing the IDL-only report silently. The unsigned-writer flag
does not use it — a missing authority check is as missing on a typed
account as on an unchecked one (escrow's `unsafe_set_amount_from_source`
writes a typed `Vault` with no signer).
On escrow-demo's planted program those are exactly its three planted
account-validation bugs. On audited production IDLs (marginfi, klend,
whirlpool, pump) they are mostly instructions that are permissionless
by design (`..._permissionless`, `refresh_*`, `accrue_*`): the report
maps the permissionless surface to review, it does not find bugs.

## Measured on production programs

Timed 2026-11-03 on three open-source production Anchor programs, from
starting the fixture to a first Crucible result, by someone who knows
solinv. Build times are `cargo build-sbf`.

| program | build | fixture → first result | findings | candidates |
|---|---|---|---|---|
| Jito tip-payment (Anchor 0.31) | 27 s | 6 min | 0 | 20 |
| Jito tip-distribution (Anchor 0.31) | 4 s | 6 min | 0 | 10 |
| Raydium cp-swap (Anchor 1.0) | 67 s | 11 min | 0 | 13 |

Every candidate sat on a typed `Account<'info, T>`, which Anchor already
checks, so 0 is the expected answer; each harness's canonical sends were
confirmed to land, so the 0 is not a silent harness. Most of the time
went into setup — the accounts that must exist before an instruction
can run — which the IDL does not shorten. What got in the way, and what
changed because of it:

- **Shipped IDLs built without PDA resolution.** Jito's carry no seeds
  and no `system_program` address, so the facts pass adds nothing and
  everything rests on candidates. `system_program` and
  `associated_token_program` are now bound by name (`defaulted()`).
- **IDL address ≠ the loaded `.so`'s id.** tip-distribution's IDL says
  mainnet; built without `--features mainnet` the `.so` declares testnet
  and Anchor rejects every instruction. Specs now get an `unresolved()`
  entry naming `DeclaredProgramIdMismatch`.
- **Typed accounts counted as unchecked.** The static report could not
  tell them apart, hence `--src`.
- **Admin keys hard-coded to mainnet.** cp-swap's `create_amm_config`
  cannot be signed in a test, so setup writes the `AmmConfig` account
  directly and places a token account at the fixed create-pool-fee
  address. Nothing in solinv can remove that step; it is the kind of
  setup cost to expect.

The harnesses are not in this repository.

## Evidence

`scripts/idl-specs-parity.sh` runs escrow-demo's Critical 5 with the
hand-written specs and with `--features idl_specs`, and fails unless
each detector fires on the same instruction in both modes and the
clean twin reports nothing under `invariant_all`. The IDL-built specs
are inferred once per fixture, at the end of `setup()`; re-inferring
per call both cost about half the throughput and read state that a
detector was midway through tampering with.
