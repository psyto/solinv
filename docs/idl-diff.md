# `solinv diff --base-idl`: what an IDL upgrade loosened

`solinv diff --base-src` reads two versions of a program's source. `--base-idl` reads two versions of its Anchor IDL instead: the build an audit saw against the one on chain (`anchor idl fetch <program>`), or each upgrade against the one before it. It needs no source, which helps when the source is not published or not pinned to the deployed build.

The IDL declares less than the source: no `owner`, no `constraint`, no account types, and nothing from the handler. What it can show is a slot that stops being a signer, loses its seeds or fixed address, or loses a `has_one`. A removal it shows may have moved into a `constraint` or the handler, where the IDL cannot see. Treat each finding as "confirm in the source", and see the real case below.

The code is in `crates/solinv-static/src/idl_diff.rs`. The same function runs in the browser in [solinv check](https://solinv-check.meowna-server.workers.dev), which rebuilds a program's whole on-chain IDL history and diffs each upgrade.

## What is reported

The rule: **anything loosened produces output.** A removal solinv is sure of is `REMOVED`, which exits 1 in CI. Anything it had to guess about is `WARNING`. Nothing loosened is silent.

| Change, slot by slot | Reported as |
|---|---|
| `signer` true → false | REMOVED, "no longer a signer" |
| `pda` (seeds) gone | REMOVED, "seeds removed" |
| fixed `address` gone | REMOVED, "fixed address removed" |
| a `has_one` gone (see relations below), while the slot that declared it is still there | REMOVED |
| a `has_one` gone because the slot that declared it was removed or renamed | WARNING |
| seeds or address changed to other values | WARNING |
| slot became `optional` | WARNING |
| slot removed, with checks of its own | WARNING (a slot with only a fixed address, such as a sysvar, is not reported: dropping it loosens nothing) |
| instruction now has no signer and writes an unchecked slot, or fewer signers than before | WARNING |
| new instruction with no signer that writes an unchecked slot | WARNING |
| instruction removed while new ones appeared, if it had checks | WARNING naming the closest new one ("if `X` replaces it…") |

Seeds compare by what derives the address, not by the type name an account seed carries.

## Relations

Anchor 0.30+ lists `relations` on the slot a `has_one` names. `authority: ["vault"]` means `vault` declares `has_one = authority`. The legacy format puts them the other way round (see below). Messages say it the source way: "`vault` no longer declares `has_one = authority`".

## Renames

A renamed slot or instruction would otherwise read as one removed and one added. So solinv pairs slots that appear only in the base with slots that appear only in the head, and compares each pair:

- **Slots** pair one to one, and only when signer and writable agree. A "rename" that drops the signer stays a removed slot, which keeps it loud. Pairs are scored by relations first (the slots that list the old name now list the new one), then by composite, seeds and address. They are assigned best first, so slot order does not decide.
- **Instructions** pair when their argument names match and at least 3/4 of their slot names do (9/10 when neither takes arguments).

A finding through a pairing is a WARNING, never REMOVED, because the pairing is a guess. A pairing that is not plainly a rename is reported itself: "taken to be renamed to `X`, a guess from its shape". A plain rename means one slot gone and one slot new in that struct, backed by a relation, or a slot that checked nothing itself. This line keeps a guess from silently excusing a lost check. For example, a new slot that happens to carry the `has_one` the old one lost is reported, not taken as proof the check survived. One guessed rename in several instructions is one line.

## IDLs built without account resolution

Anchor writes seeds, addresses and relations only when the IDL is built with account resolution, and then every fixed-address slot (`system_program`, a sysvar) carries its `address`. Some head IDLs have none of the three anywhere. If the base had a fixed address (or, for a legacy base, seeds or relations), the head changed its build, not necessarily its checks. In that case one warning says so, and seeds, addresses and `has_one` are not compared. Signers and `optional` still are.

A small IDL that loses its only `has_one`, with no seeds or addresses anywhere, cannot be told apart from such a build. It gets the same warning, not silence.

## Legacy (pre-0.30) IDLs

`Idl::from_json_any`, which `solinv idl` and `solinv diff --base-idl` use, reads legacy IDLs. It converts them the way `anchor idl convert` does, with two fixes, both reported upstream:

- A string const seed becomes its UTF-8 bytes. `anchor idl convert` keeps the JSON quotes ([anchor#5255](https://github.com/otter-sec/anchor/issues/5255)).
- `relations` move from the declaring slot to the slot they name. `anchor idl convert` copies them unchanged, so every legacy `has_one` reads backwards ([anchor#5256](https://github.com/otter-sec/anchor/issues/5256)).

Const seeds convert to the bytes Anchor derives from: a string's UTF-8, a byte array as it is, an integer little-endian at its width (up to 128 bits), a public key's 32 bytes. A type this does not convert keeps the PDA as a marked seed, so a later change to it is reported. The mark counts only on a side converted from legacy, so a current IDL that holds the same bytes is not mistaken for it.

A legacy IDL has no fixed addresses, so addresses are not compared when either side is legacy.

Do not pre-convert with `anchor idl convert`: its output has the two bugs above.

## A real case

marginfi's on-chain IDL has 10 versions, from 2024-03 onwards. 3 of its 9 upgrades have REMOVED findings: 2025-10 (2), 2026-01 (8) and 2026-03 (2). All but one are `marginfi_account` no longer declaring `has_one = authority`, in instructions such as `lending_account_withdraw` and `lending_account_borrow`. The other is `marginfi_group` dropping `has_one = admin` on `configure_deleverage_withdrawal_limit`. For the `authority` case, the source shows the check moved into a `constraint` (`is_signer_authorized(...)`) that also admits delegated and receivership signers. That change was intended, and the IDL alone points straight at where who-can-act widened, which is what a reviewer or a curator wants to look at.
