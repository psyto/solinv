# Mutation campaign — raydium-amm

- **Gate**: FAIL
- **Score**: 0.0% (0 killed / 18 reached)
- **Excluded from the denominator**: 0 not reached, 1 failed to build, 0 harness error (5% of 19 mutants produced no evidence)
- **Attribution**: 0 killed by the predicted invariant, 0 by another
- **Not covered by any v1 operator**: cu-dos, cpi-reentrancy, realloc-race, account-swap
- **Before excluding equivalent mutants**: 0.0% (0 killed / 20 reached)

## Pre-committed criterion

> Native 本番コードでの検出器能力の測定。ハーネスが駆動する2命令のハンドラ本体に限定した到達可能集合。80% 未満なら実コードに対する盲点である

PASS requires score ≥ 0.80 over ≥ 10 reached mutants.

## Per invariant

| Invariant | Killed | Reached | Score | Not reached | Build failed | Harness error |
|---|---:|---:|---:|---:|---:|---:|
| precondition-skip | 0 | 15 | 0% | 0 | 0 | 0 |
| unchecked-math | 0 | 3 | 0% | 0 | 1 | 0 |

## Survivors

Mutants that executed and that no invariant caught. Each is either a detector blind spot or a bug class the catalog does not model.

- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3053#57`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3081#58`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3111#59`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3182#60`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3185#61`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3191#62`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3231#63`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3297#64`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3328#65`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3361#66`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3430#67`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3433#68`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3436#69`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3442#70`
- `native-guard-neutralize@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3482#71`
- `checked-to-wrapping@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3411#20`
- `checked-to-wrapping@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3478#21`
- `checked-to-wrapping@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3518#22`

## Excluded as equivalent

Mutants ruled incapable of producing incorrect behaviour, and so removed from the denominator. Each exclusion raises the score, so each one is stated with its argument — check them.

- `signer-check-drop@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3053#6`
  - the guard is redundant with the SPL Token program underneath it. user_source_owner is passed as the authority of the token_transfer CPI (processor.rs:3199, 3239), so the transfer is rejected without its signature whether or not Raydium checks is_signer itself. Same shape as escrow-clean's deposit, found independently on production code.
- `signer-check-drop@/Users/hiroyusai/src/raydium-amm/program/src/processor.rs:3297#7`
  - the guard is redundant with the SPL Token program underneath it. user_source_owner is passed as the authority of the token_transfer CPI (processor.rs:3199, 3239), so the transfer is rejected without its signature whether or not Raydium checks is_signer itself. Same shape as escrow-clean's deposit, found independently on production code.
