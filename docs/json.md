# `--format json`

`solinv diff --format json` and `solinv check --format json` print one JSON object for a program to
read: an AI agent checking its own edit, a CI script. The MCP server (`solinv mcp`) returns the same
object from its `diff` and `check` tools. `--format text` and `--format github` are unchanged.

## Stability

`schema_version` is `1`. Within a version, a field or a `check` value may be added; a field is never
renamed or removed and never changes meaning. Anything else is a new `schema_version`. Read the
fields you need and ignore the rest.

## Shape

```json
{
  "schema_version": 1,
  "solinv_version": "0.1.10",
  "command": "diff",
  "compared": [
    { "base": "programs/vault/src@HEAD", "head": "programs/vault/src", "mode": "anchor", "note": null }
  ],
  "summary": { "removed": 1, "widened": 0, "warning": 0 },
  "findings": [
    {
      "status": "removed",
      "check": "type",
      "instruction": "withdraw",
      "account": "vault",
      "file": "programs/vault/src/lib.rs",
      "line": 153,
      "message": "was Account, now UncheckedAccount: Anchor no longer checks its owner and type; and …",
      "before": {
        "file": "programs/vault/src/lib.rs",
        "line": 141,
        "text": "#[account(\n    mut,\n    seeds = [b\"vault\", depositor.key().as_ref()],\n    bump,\n    has_one = depositor,\n)]\npub vault: Account<'info, Vault>,"
      },
      "after": {
        "file": "programs/vault/src/lib.rs",
        "line": 148,
        "text": "#[account(\n    mut,\n    seeds = [b\"vault\", depositor.key().as_ref()],\n    bump,\n)]\npub vault: UncheckedAccount<'info>,"
      }
    }
  ]
}
```

| Field | |
|---|---|
| `command` | `diff` or `check` |
| `compared[]` | each program read. `base` is null for `check`; `mode` is `anchor`, `native` (native or Pinocchio) or `idl`. From the MCP server, a path is `<dir>@<rev>` when read from a revision, `<dir>` from the working tree. `note` says why one was not compared (a program new since the base), else null |
| `summary` | how many findings have each `status` |
| `findings[].status` | `removed`: a check the base had is gone. `widened`: the old check kept as one side of a new `\|\|` (`has_one = x` → `constraint = a.x == x.key() \|\| …`): still a removal, for whoever takes the new way. `warning`: something to read (a slot or instruction renamed, a type changed, a native program's check gone) |
| `findings[].check` | which check, below |
| `findings[].instruction` | the instruction (a native program: the fn) or, for `check`, the function the finding is in; null for a whole program |
| `findings[].account` | the account slot (dotted in a composite: `accts.vault`); null for an instruction's or a program's finding |
| `file`, `line` | where to look in the head version: the slot, else the handler. Null for an IDL diff |
| `message` | the sentence the text output prints |
| `before` | where the check was in the base version, and its source: a slot with its attributes, or the handler line with the check. Null when not known (an IDL diff, a new instruction). `text` is null when the file could not be read |
| `after` | the slot as it now reads, for a finding on an Anchor slot; null otherwise (the check is gone, or `file`/`line` point at it) |

`check` values:

| | |
|---|---|
| `type` | `Account<'info, T>` loosened to `UncheckedAccount` / `AccountInfo`, or changed to another type. The checks on its data that went with it are listed in `message` |
| `signer` | no longer required to sign; a new instruction that writes with no signer |
| `owner`, `seeds`, `address`, `has_one`, `constraint`, `close` | that `#[account(..)]` constraint |
| `token` | `token::mint` / `token::authority` |
| `handler` | a `require!` / `require_keys_eq!` / `if .. { return err }` in the handler |
| `validate` | a line of a vipers `validate()` |
| `optional` | now `Option<..>`: the instruction runs without it |
| `slot`, `instruction`, `program` | a slot, an instruction or a whole program gone or renamed: its checks are not compared |
| `multiple` | several at once (an IDL slot's) |
| `native_signer`, `native_owner`, `native_key`, `native_writable`, `native_executable` | a native or Pinocchio program's `if !a.is_signer()` and the like |
| `signer_seeds_without_bump`, `hook_unreachable`, `hook_fallback_skips_execute`, `entry_not_scoped_to_gate` | program-wide findings (`solinv check`, and `solinv diff` when the head adds one) |

What could not be compared is an `error` instead of the report, still on stdout:

```json
{ "schema_version": 1, "solinv_version": "0.1.10", "command": "diff", "error": { "message": "no commit nope in this repository" } }
```

## Exit codes

| | `diff` | `check` |
|---|---|---|
| 0 | nothing `removed` or `widened` (warnings alone are 0); always with `--no-fail` | nothing `removed` |
| 1 | a check `removed` or `widened` | a transfer hook that cannot run (`hook_*`) |
| 2 | could not compare: bad arguments, a source that cannot be read, no program found | could not read |

The same in every `--format`. Before 0.1.10 a failure to compare also exited 1.
