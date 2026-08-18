# Field schema + relation invariants

Design note for `solinv_fuzz::schema` and
`StateInvariantKind::Relation`. Unlike the files beside it this is not
a detector spec — it adds no new bug class. It changes how the existing
state-invariant detector is *declared*, for two reasons: the current
declaration form has a silent failure mode, and it cannot express the
shape most protocol-specific invariants actually take.

## 1. The problem: a wrong offset is indistinguishable from a clean run

Before this change a state invariant named its field by byte offset:

```rust
StateInvariant {
    name: "deposits grow".into(),
    kind: StateInvariantKind::Monotonic {
        field_offset: 40,      // ← what is at 40?
        field_size: 8,
        direction: MonotonicDir::NonDecreasing,
    },
    accounts: vec![0],
}
```

If `40` is wrong the detector does not error. It reads eight bytes that
belong to some other field, those bytes move in a plausible direction,
nothing fires, and the campaign reports zero violations. If the offset
is past the end of the account, `read_field_widened` returns `None` and
the invariant returns early — also silently.

This matters more for solinv than for most tools, because solinv's
headline result *is* a null result. "168,531 executions / 0 violations"
is only evidence if every one of those executions was checking the
bytes it claimed to check. A mis-declared offset does not weaken that
claim, it voids it, and it does so invisibly.

The `examples/pinocchio-bench-fuzz` harnesses show the same pressure
from the other side: their W4/W5 structural checks are inline Rust
against hard-coded offsets, with the comment "same offsets as
`matching/`" carrying the correctness argument. That comment is the
specification, and nothing checks it.

## 2. The fix, and why it stops at a closed grammar

`AccountSchema` moves the layout into one declaration:

```rust
let pool = AccountSchema::anchor("Pool")   // cursor starts past the 8-byte disc
    .field("authority", 32)                // declared for its offset only
    .field("total_deposits", 8)
    .field("total_borrows", 8);

pool.validate_len(account.data.len())?;    // check the claim against reality

let inv = pool.monotonic(
    "deposits grow", vec![0], "total_deposits", MonotonicDir::NonDecreasing,
)?;
```

Three failures become impossible or loud rather than silent:

| Mistake | Before | After |
|---|---|---|
| Offset off by one field | silent wrong read | `UnknownField`, listing the real names |
| Asserting on a 32-byte pubkey | silent truncation to 8 | `UnreadableWidth` |
| Layout drifted from the program | silent wrong read | `ShortAccount` from `validate_len` |

`UnknownField` carries the schema's full field list. That is for two
readers: a human seeing `total_deposit` vs `total_deposits`, and a
generator being corrected by a feedback loop. Both are far better served
by an error that says what *is* available than by one that says no.

The grammar deliberately stays closed. `StateInvariantKind` remains a
handful of variants built from integers and an operator, so a candidate
invariant — hand-written or generated — can be checked before it is ever
executed. A general expression language would buy expressiveness at the
cost of the property that makes candidates checkable at all. Ratios
(`fee <= total / 100`) are therefore not expressible in v1; that is a
known limit, not an oversight.

What the schema does **not** do: it is still written by hand, so it can
still disagree with the program. What it buys is that the disagreement
now lives in one place and is checkable against real account data,
instead of being smeared across every invariant declaration. Deriving
schemas from Anchor IDLs is the natural next step and is not
implemented.

## 3. Relation — the shape the other three kinds cannot express

`SumConservation`, `Monotonic` and `Bounded` all read *one* field
geometry across a *uniform* list of accounts. Most real protocol
invariants are not that shape:

- `reserve.liquidity + reserve.borrowed == reserve.total` — three
  different fields on one account
- `sum(user.deposits) <= vault.balance` — different fields on
  different accounts, compared across the two sides

`Relation` covers both: two sides, each a sum of terms, compared with
`==`, `<=`, `<`, `>=` or `>`. Terms are summed, never multiplied.

```rust
let inv = relation(
    "liquidity + borrowed == total",
    vec![reserve.term(0, "liquidity")?, reserve.term(0, "borrowed")?],
    RelOp::Eq,
    vec![reserve.term(0, "total")?],
    0,
)?;
```

`tolerance` applies to `Eq` only. On an ordering operator a tolerance
would silently widen the asserted property, so it is rejected at
declaration time rather than honored.

## 4. Pre-gating, and the diagnostic that keeps it honest

A `Relation` fires only when it **held before the ix and failed after
it**. A relation that was already false pre-state indicts the
declaration or the fixture's initial state, not the instruction that
happened to run next; firing on it would attribute a pre-existing
condition to an arbitrary ix and produce a false positive with a
confidently wrong cause.

That gate creates its own hazard: a relation that never holds also never
fires, and a permanently-silent invariant is indistinguishable from a
passing one — the exact failure this document opens with. So the
pre-state failure is **reported**, once per site per process:

```
[solinv][declaration] ix swap invariant 'liquidity + borrowed == total':
relation does not hold in the pre-state (lhs 900, rhs 1000) — it cannot
fire until the declaration or the fixture's initial state is corrected
```

The same treatment covers unreadable fields, on both the pre- and
post-state read. Unlike the transition-coverage metrics these
diagnostics are **not** env-gated. A harness that is silently checking
nothing has to say so by default; requiring a flag to discover it puts
the burden in the wrong place.

## 5. Compatibility

Additive. `StateInvariantKind` gains a variant and the schema layer is
a new module; existing declarations by raw offset still compile and
behave identically. The Day 31+ escrow-demo and pinocchio-bench
harnesses are unchanged.

## 6. Status

Implemented and unit-tested (`solinv-fuzz::schema`, 15 tests;
`solinv-core::invariants::unchecked_math`, 6 relation tests). **Not yet
exercised end-to-end against a live target** — no harness in this
repository has been migrated to schema-backed declarations, and
`Relation` has no planted-bug fixture. Until an acceptance run exists,
the correct claim is that the API is implemented and unit-tested, not
that it is validated: the same standard the catalog's §9 gates hold
themselves to.
