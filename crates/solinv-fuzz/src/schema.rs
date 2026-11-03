//! # Field schema — naming account fields instead of counting bytes
//!
//! A [`StateInvariant`] ultimately reads a little-endian integer at a
//! byte offset. Declaring that offset by hand is the single most
//! error-prone part of adopting solinv on a real program, and it is
//! error-prone in the worst possible way: **a wrong offset fails
//! silently**. The detector reads eight bytes that happen to be some
//! other field, the values move in a plausible direction, nothing
//! fires, and the campaign reports a clean run. A harness that checks
//! the wrong bytes is indistinguishable from one that found no bug.
//!
//! `AccountSchema` closes that gap by making the layout a declaration
//! in its own right. Fields are named and sized once; invariants then
//! refer to `pool.total_deposits` and the offset is computed. Three
//! classes of mistake stop being possible:
//!
//! | Mistake | Without a schema | With one |
//! |---|---|---|
//! | Offset off by a field | silent wrong read | `UnknownField` at build |
//! | Field wider/narrower than declared | silent truncation | `UnreadableWidth` |
//! | Layout drifted from the program | silent wrong read | [`AccountSchema::validate_len`] |
//!
//! ## Why the errors carry the available field names
//!
//! [`SchemaError::UnknownField`] lists every field the schema does
//! know. That is deliberate: the intended consumers of this API are a
//! human reading a compile-time error and a generator being corrected
//! by a feedback loop, and both are far better served by "no field
//! `total_deposit`; did you mean one of `total_deposits`, `total_borrows`?"
//! than by a bare failure.
//!
//! ## What this layer does not do
//!
//! It does not read the layout from an IDL or a `#[repr(C)]` struct —
//! the schema is still written by hand, so it can still disagree with
//! the program. What it buys is that the disagreement is now stated in
//! one place and checkable against real account data
//! ([`AccountSchema::validate_len`]) rather than smeared across every
//! invariant declaration. Deriving schemas from Anchor IDLs is the
//! natural next step and is not implemented here.
//!
//! See `docs/invariants/field-schema.md` for the design rationale.

use crate::capability::{
    MonotonicDir, RelOp, RelTerm, StateInvariant, StateInvariantKind,
};
use std::fmt;

/// Widths the state-invariant readers can decode. Mirrors
/// `read_field_widened` in solinv-core: little-endian u64 and u128.
pub const READABLE_WIDTHS: [usize; 2] = [8, 16];

/// Byte length of an Anchor account discriminator, the default base
/// offset for [`AccountSchema::anchor`].
pub const ANCHOR_DISCRIMINATOR_LEN: usize = 8;

/// A named field within an account layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaField {
    /// Field name as written in the program's account struct.
    pub name: String,
    /// Absolute byte offset from the start of the account's `data`,
    /// including any discriminator or header the schema declared.
    pub offset: usize,
    /// Width in bytes. Fields of any width may be declared so that
    /// later offsets are computed correctly; only the widths in
    /// [`READABLE_WIDTHS`] may back an invariant.
    pub size: usize,
}

/// An account's byte layout, declared once and referred to by name.
///
/// Built fluently, in declaration order:
///
/// ```ignore
/// let pool = AccountSchema::anchor("Pool")
///     .field("authority", 32)          // declared for its offset only
///     .field("total_deposits", 8)
///     .field("total_borrows", 8)
///     .pad(7)                          // explicit alignment padding
///     .field("bump", 1);
/// ```
#[derive(Clone, Debug, Default)]
pub struct AccountSchema {
    /// Account type name, surfaced in errors and violation messages.
    pub name: String,
    /// Declared fields, in offset order.
    pub fields: Vec<SchemaField>,
    /// Next offset a fluent `field()` call will occupy.
    cursor: usize,
}

impl AccountSchema {
    /// Schema for an Anchor account: the cursor starts past the 8-byte
    /// discriminator, so the first declared field lands where Anchor
    /// actually writes it.
    pub fn anchor(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            cursor: ANCHOR_DISCRIMINATOR_LEN,
        }
    }

    /// Schema for a native / zero-copy account whose first field sits
    /// at offset 0.
    pub fn raw(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            cursor: 0,
        }
    }

    /// Append a field at the current cursor and advance by `size`.
    ///
    /// Declare fields you will never assert on (pubkeys, flags) too —
    /// they are what keep the offsets of the fields you *do* assert on
    /// correct.
    #[must_use]
    pub fn field(mut self, name: impl Into<String>, size: usize) -> Self {
        self.fields.push(SchemaField {
            name: name.into(),
            offset: self.cursor,
            size,
        });
        self.cursor += size;
        self
    }

    /// Advance the cursor without naming a field, for alignment padding
    /// or reserved bytes.
    #[must_use]
    pub fn pad(mut self, bytes: usize) -> Self {
        self.cursor += bytes;
        self
    }

    /// Append a field at an explicit offset, for layouts that are not
    /// described well by a running cursor. Does not move the cursor
    /// backwards: it is set to `max(cursor, offset + size)` so a later
    /// fluent `field()` still lands after everything declared so far.
    #[must_use]
    pub fn field_at(mut self, name: impl Into<String>, offset: usize, size: usize) -> Self {
        self.fields.push(SchemaField {
            name: name.into(),
            offset,
            size,
        });
        self.cursor = self.cursor.max(offset + size);
        self
    }

    /// Total declared length: the end of the furthest field, including
    /// any trailing `pad`.
    pub fn len(&self) -> usize {
        self.cursor
    }

    /// Whether the schema declares no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Every field name, in declaration order. Used to build helpful
    /// [`SchemaError::UnknownField`] messages.
    pub fn field_names(&self) -> Vec<String> {
        self.fields.iter().map(|f| f.name.clone()).collect()
    }

    /// Resolve a field name to `(offset, size)` without checking that
    /// the width is readable — use this when you need the geometry of
    /// a field an invariant cannot assert on.
    pub fn resolve(&self, field: &str) -> Result<(usize, usize), SchemaError> {
        self.fields
            .iter()
            .find(|f| f.name == field)
            .map(|f| (f.offset, f.size))
            .ok_or_else(|| SchemaError::UnknownField {
                schema: self.name.clone(),
                field: field.to_string(),
                available: self.field_names(),
            })
    }

    /// Resolve a field and require that its width is one an invariant
    /// reader can decode.
    ///
    /// This is where a 32-byte pubkey or a 1-byte bump is rejected: it
    /// is perfectly valid to *declare* those so offsets line up, and
    /// never valid to assert an arithmetic invariant over them.
    pub fn resolve_readable(&self, field: &str) -> Result<(usize, usize), SchemaError> {
        let (offset, size) = self.resolve(field)?;
        if !READABLE_WIDTHS.contains(&size) {
            return Err(SchemaError::UnreadableWidth {
                schema: self.name.clone(),
                field: field.to_string(),
                size,
            });
        }
        Ok((offset, size))
    }

    /// Check the schema against the length of real account data.
    ///
    /// The schema is a claim about a program's layout, and a claim that
    /// nothing checks is how a harness ends up reading the wrong bytes
    /// for an entire campaign. Call this in fixture setup against an
    /// account the program itself wrote.
    ///
    /// A longer account than declared is accepted — trailing fields the
    /// schema does not model are harmless. A *shorter* one is not: some
    /// declared field lies past the end and will never read.
    pub fn validate_len(&self, actual: usize) -> Result<(), SchemaError> {
        if actual < self.len() {
            return Err(SchemaError::ShortAccount {
                schema: self.name.clone(),
                declared: self.len(),
                actual,
            });
        }
        Ok(())
    }

    /// One [`RelTerm::Field`] naming this schema's `field` on the
    /// account at `account` (an index into `InstructionSpec.accounts`).
    pub fn term(&self, account: usize, field: &str) -> Result<RelTerm, SchemaError> {
        let (field_offset, field_size) = self.resolve_readable(field)?;
        Ok(RelTerm::Field {
            account,
            field_offset,
            field_size,
        })
    }

    /// A [`StateInvariantKind::Monotonic`] over `field`, asserted on
    /// each account in `accounts`.
    pub fn monotonic(
        &self,
        name: impl Into<String>,
        accounts: Vec<usize>,
        field: &str,
        direction: MonotonicDir,
    ) -> Result<StateInvariant, SchemaError> {
        let (field_offset, field_size) = self.resolve_readable(field)?;
        Ok(StateInvariant {
            name: name.into(),
            kind: StateInvariantKind::Monotonic {
                field_offset,
                field_size,
                direction,
            },
            accounts,
        })
    }

    /// A [`StateInvariantKind::Bounded`] over `field`.
    pub fn bounded(
        &self,
        name: impl Into<String>,
        accounts: Vec<usize>,
        field: &str,
        min: u128,
        max: u128,
    ) -> Result<StateInvariant, SchemaError> {
        if min > max {
            return Err(SchemaError::EmptyBound { min, max });
        }
        let (field_offset, field_size) = self.resolve_readable(field)?;
        Ok(StateInvariant {
            name: name.into(),
            kind: StateInvariantKind::Bounded {
                field_offset,
                field_size,
                min,
                max,
            },
            accounts,
        })
    }

    /// A [`StateInvariantKind::SumConservation`] over `field` across
    /// `accounts`.
    pub fn sum_conservation(
        &self,
        name: impl Into<String>,
        accounts: Vec<usize>,
        field: &str,
        tolerance: u64,
    ) -> Result<StateInvariant, SchemaError> {
        let (field_offset, field_size) = self.resolve_readable(field)?;
        Ok(StateInvariant {
            name: name.into(),
            kind: StateInvariantKind::SumConservation {
                field_offset,
                field_size,
                tolerance,
            },
            accounts,
        })
    }
}

/// Assemble a [`StateInvariantKind::Relation`].
///
/// Terms usually come from more than one schema, so this is a free
/// function rather than a method: build each side with
/// [`AccountSchema::term`] and combine them here.
///
/// ```ignore
/// let inv = relation(
///     "liquidity + borrowed == total",
///     vec![reserve.term(0, "liquidity")?, reserve.term(0, "borrowed")?],
///     RelOp::Eq,
///     vec![reserve.term(0, "total")?],
///     0,
/// )?;
/// ```
pub fn relation(
    name: impl Into<String>,
    lhs: Vec<RelTerm>,
    op: RelOp,
    rhs: Vec<RelTerm>,
    tolerance: u64,
) -> Result<StateInvariant, SchemaError> {
    if lhs.is_empty() || rhs.is_empty() {
        return Err(SchemaError::EmptyRelationSide);
    }
    if tolerance != 0 && op != RelOp::Eq {
        return Err(SchemaError::ToleranceOnOrdering { op });
    }
    Ok(StateInvariant {
        name: name.into(),
        kind: StateInvariantKind::Relation {
            lhs,
            op,
            rhs,
            tolerance,
        },
        // Relation carries its accounts per-term; the parent list is
        // unused and left empty so a reader is not misled into
        // thinking it participates.
        accounts: Vec::new(),
    })
}

/// Why a schema-backed declaration could not be built.
///
/// Every variant is raised at declaration time, before any fuzzing
/// runs. That is the entire point: these are the mistakes that would
/// otherwise be invisible for a whole campaign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// No such field. Carries the schema's full field list so the
    /// message can suggest the intended one.
    UnknownField {
        schema: String,
        field: String,
        available: Vec<String>,
    },
    /// The field exists but is not 8 or 16 bytes, so no invariant
    /// reader can decode it.
    UnreadableWidth {
        schema: String,
        field: String,
        size: usize,
    },
    /// Real account data is shorter than the schema claims.
    ShortAccount {
        schema: String,
        declared: usize,
        actual: usize,
    },
    /// A relation with nothing on one side.
    EmptyRelationSide,
    /// A tolerance was set on an ordering operator, where it would
    /// silently weaken the asserted property.
    ToleranceOnOrdering { op: RelOp },
    /// `Bounded` with `min > max`, which can never hold.
    EmptyBound { min: u128, max: u128 },
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::UnknownField {
                schema,
                field,
                available,
            } => write!(
                f,
                "schema '{schema}' has no field '{field}'; declared fields: [{}]",
                available.join(", ")
            ),
            SchemaError::UnreadableWidth {
                schema,
                field,
                size,
            } => write!(
                f,
                "schema '{schema}' field '{field}' is {size} bytes; state invariants read \
                 only 8- or 16-byte little-endian unsigned fields. Declaring the field is \
                 still correct — it keeps later offsets right — but it cannot back an \
                 arithmetic invariant."
            ),
            SchemaError::ShortAccount {
                schema,
                declared,
                actual,
            } => write!(
                f,
                "schema '{schema}' declares {declared} bytes but the account holds {actual}; \
                 fields past the end would read nothing and the invariant would never fire"
            ),
            SchemaError::EmptyRelationSide => {
                write!(f, "a relation needs at least one term on each side")
            }
            SchemaError::ToleranceOnOrdering { op } => write!(
                f,
                "tolerance applies to Eq only; on '{}' it would silently widen the \
                 asserted property",
                op.symbol()
            ),
            SchemaError::EmptyBound { min, max } => {
                write!(f, "Bounded range [{min}, {max}] is empty (min > max)")
            }
        }
    }
}

impl std::error::Error for SchemaError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> AccountSchema {
        AccountSchema::anchor("Pool")
            .field("authority", 32)
            .field("total_deposits", 8)
            .field("total_borrows", 8)
            .field("bump", 1)
    }

    #[test]
    fn anchor_schema_starts_past_the_discriminator() {
        let s = pool();
        assert_eq!(s.resolve("authority").unwrap(), (8, 32));
        assert_eq!(s.resolve("total_deposits").unwrap(), (40, 8));
        assert_eq!(s.resolve("total_borrows").unwrap(), (48, 8));
        assert_eq!(s.resolve("bump").unwrap(), (56, 1));
        assert_eq!(s.len(), 57);
    }

    #[test]
    fn raw_schema_starts_at_zero() {
        let s = AccountSchema::raw("Market").field("sequence", 8);
        assert_eq!(s.resolve("sequence").unwrap(), (0, 8));
    }

    #[test]
    fn pad_advances_without_naming() {
        let s = AccountSchema::raw("S").field("a", 8).pad(4).field("b", 8);
        assert_eq!(s.resolve("b").unwrap(), (12, 8));
        assert_eq!(s.field_names(), vec!["a", "b"]);
    }

    #[test]
    fn field_at_never_rewinds_the_cursor() {
        let s = AccountSchema::raw("S")
            .field("a", 8)
            .field_at("early", 0, 4)
            .field("after", 8);
        // `early` overlaps `a` deliberately; the cursor stays at 8
        // rather than rewinding to 4, so `after` still lands past `a`.
        assert_eq!(s.resolve("early").unwrap(), (0, 4));
        assert_eq!(s.resolve("after").unwrap(), (8, 8));
    }

    #[test]
    fn field_at_beyond_the_cursor_advances_it() {
        let s = AccountSchema::raw("S")
            .field("a", 8)
            .field_at("far", 64, 8)
            .field("after", 8);
        assert_eq!(s.resolve("after").unwrap(), (72, 8));
        assert_eq!(s.len(), 80);
    }

    #[test]
    fn unknown_field_lists_what_is_available() {
        let err = pool().resolve("total_deposit").unwrap_err();
        match &err {
            SchemaError::UnknownField { available, .. } => {
                assert!(available.contains(&"total_deposits".to_string()));
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("total_deposits"), "message should suggest: {msg}");
    }

    #[test]
    fn declared_but_unreadable_widths_are_rejected_for_invariants() {
        // 32-byte pubkey: legal to declare, illegal to assert on.
        assert_eq!(pool().resolve("authority").unwrap(), (8, 32));
        assert!(matches!(
            pool().resolve_readable("authority"),
            Err(SchemaError::UnreadableWidth { size: 32, .. })
        ));
        assert!(matches!(
            pool().resolve_readable("bump"),
            Err(SchemaError::UnreadableWidth { size: 1, .. })
        ));
    }

    #[test]
    fn validate_len_accepts_longer_and_rejects_shorter() {
        let s = pool();
        assert!(s.validate_len(57).is_ok());
        assert!(s.validate_len(200).is_ok(), "trailing unmodelled bytes are fine");
        assert!(matches!(
            s.validate_len(40),
            Err(SchemaError::ShortAccount { declared: 57, actual: 40, .. })
        ));
    }

    #[test]
    fn monotonic_resolves_the_named_field() {
        let inv = pool()
            .monotonic("deposits grow", vec![0], "total_deposits", MonotonicDir::NonDecreasing)
            .unwrap();
        match inv.kind {
            StateInvariantKind::Monotonic {
                field_offset,
                field_size,
                direction,
            } => {
                assert_eq!((field_offset, field_size), (40, 8));
                assert_eq!(direction, MonotonicDir::NonDecreasing);
            }
            other => panic!("wrong kind: {other:?}"),
        }
        assert_eq!(inv.accounts, vec![0]);
    }

    #[test]
    fn bounded_rejects_an_empty_range() {
        assert!(matches!(
            pool().bounded("b", vec![0], "total_deposits", 100, 10),
            Err(SchemaError::EmptyBound { .. })
        ));
    }

    #[test]
    fn relation_builds_from_terms_across_accounts() {
        let s = pool();
        let inv = relation(
            "deposits <= vault",
            vec![s.term(1, "total_deposits").unwrap(), s.term(2, "total_deposits").unwrap()],
            RelOp::Le,
            vec![s.term(0, "total_borrows").unwrap()],
            0,
        )
        .unwrap();
        match inv.kind {
            StateInvariantKind::Relation { lhs, op, rhs, .. } => {
                assert_eq!(lhs.len(), 2);
                assert_eq!(rhs.len(), 1);
                assert_eq!(op, RelOp::Le);
            }
            other => panic!("wrong kind: {other:?}"),
        }
        // The parent account list stays empty — terms carry their own.
        assert!(inv.accounts.is_empty());
    }

    #[test]
    fn relation_rejects_an_empty_side() {
        let s = pool();
        assert!(matches!(
            relation("x", vec![], RelOp::Eq, vec![s.term(0, "total_borrows").unwrap()], 0),
            Err(SchemaError::EmptyRelationSide)
        ));
    }

    #[test]
    fn relation_rejects_tolerance_on_an_ordering_operator() {
        let s = pool();
        assert!(matches!(
            relation(
                "x",
                vec![s.term(0, "total_deposits").unwrap()],
                RelOp::Le,
                vec![s.term(0, "total_borrows").unwrap()],
                5,
            ),
            Err(SchemaError::ToleranceOnOrdering { .. })
        ));
    }

    #[test]
    fn relation_terms_reject_unreadable_widths() {
        assert!(matches!(
            pool().term(0, "authority"),
            Err(SchemaError::UnreadableWidth { .. })
        ));
    }

    #[test]
    fn rel_op_tolerance_applies_to_eq_only() {
        assert!(RelOp::Eq.holds(100, 98, 2));
        assert!(!RelOp::Eq.holds(100, 97, 2));
        // Ordering operators ignore tolerance entirely.
        assert!(!RelOp::Le.holds(100, 98, 5));
        assert!(RelOp::Le.holds(98, 100, 0));
        assert!(RelOp::Lt.holds(97, 98, 0));
        assert!(!RelOp::Lt.holds(98, 98, 0));
        assert!(RelOp::Ge.holds(98, 98, 0));
        assert!(RelOp::Gt.holds(99, 98, 0));
    }
}
