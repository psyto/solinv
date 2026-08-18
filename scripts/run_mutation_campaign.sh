#!/usr/bin/env bash
set -euo pipefail

# Drive a solinv mutation campaign end to end.
#
# For each mutant in a plan: patch the source, rebuild the SBF program,
# run the invariant harness, and classify the outcome. Emits a results
# JSON that `solinv mutate score` turns into a report.
#
# The classification is the load-bearing part, so it is spelled out:
#
#   build fails                       -> build_failed  (excluded)
#   harness reports violation         -> killed        (by the named invariant)
#   enclosing ix never executed       -> not_reached   (excluded)
#   otherwise                         -> survived
#
# "Never reached" cannot be inferred from a silent run: a detector that
# was never asked and one that was asked and said nothing look identical
# from outside. The two halves that make the distinction possible are
#
#   - `solinv mutate plan` records each mutant's `enclosing_fn`
#   - solinv emits `[solinv][reached] ix=<name>` under
#     SOLINV_REACHABILITY=1 when a canonical instruction executes
#
# and this script joins them by name. The join is sound in one
# direction only: if the enclosing function's ix never ran, the mutation
# certainly did not. The converse does not hold — the ix may have run
# without taking the mutated branch — so a mutant whose ix *did* run is
# classified `survived`, never promoted on that evidence alone. That
# errs against the detector, which is the direction to err in.
#
# A mutant with no `enclosing_fn`, or whose name matches no instruction,
# is also treated as `survived` for the same reason.

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -lt 4 ]]; then
  cat <<'EOF'
Usage:
  run_mutation_campaign.sh <plan.json> <manifest-path> <invariant-target> <results.json>

Arguments:
  plan.json         campaign produced by `solinv mutate plan`
  manifest-path     Cargo.toml of the program to rebuild per mutant
  invariant-target  crucible target name to run (e.g. escrow)
  results.json      where to write the results array

Environment:
  SOLINV_TIMEOUT    per-mutant fuzz timeout in seconds (default 30)
  SOLINV_BIN        path to the solinv binary (default ./target/release/solinv)
EOF
  exit 0
fi

PLAN="$1"
MANIFEST="$2"
TARGET="$3"
RESULTS="$4"
TIMEOUT="${SOLINV_TIMEOUT:-30}"
SOLINV="${SOLINV_BIN:-./target/release/solinv}"

command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 1; }
[[ -x "$SOLINV" ]] || { echo "error: solinv binary not found at $SOLINV" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mapfile -t IDS < <(jq -r '.mutants[].id' "$PLAN")
echo "campaign: ${#IDS[@]} mutants against $TARGET"
echo "[" > "$RESULTS"
FIRST=1

for id in "${IDS[@]}"; do
  file=$(jq -r --arg id "$id" '.mutants[] | select(.id==$id) | .file' "$PLAN")
  killer=$(jq -r --arg id "$id" '.mutants[] | select(.id==$id) | .expected_killer' "$PLAN")
  encl=$(jq -r --arg id "$id" \
    '.mutants[] | select(.id==$id) | .enclosing_fn // ""' "$PLAN")

  cp "$file" "$WORK/orig.rs"
  # Restore the pristine source no matter how this iteration exits.
  restore() { cp "$WORK/orig.rs" "$file"; }

  if ! "$SOLINV" mutate apply --plan "$PLAN" --mutant "$id" --out "$file" >/dev/null 2>&1; then
    restore
    outcome='{"outcome":"build_failed","reason":"apply failed (stale plan?)"}'
  elif ! cargo build-sbf --tools-version v1.52 --manifest-path "$MANIFEST" \
        >"$WORK/build.log" 2>&1; then
    restore
    outcome=$(jq -n --arg r "$(tail -c 400 "$WORK/build.log")" \
      '{outcome:"build_failed", reason:$r}')
  else
    restore
    SOLINV_REACHABILITY=1 SOLINV_MUTANT_ID="$id" \
      crucible run "$TARGET" "invariant_all" \
      --release --timeout "$TIMEOUT" >"$WORK/run.log" 2>&1 || true

    # The invariant name is taken from solinv's own violation prefix,
    # e.g. "[unchecked-math:<pid>] ...". Attribution matters: a mutant
    # killed by an unexpected detector is still dead, but the report
    # separates the two.
    by=$(grep -oE '\[(signer-skip|owner-skip|discriminator-skip|pda-forge|account-swap|unchecked-math|cu-dos|cpi-reentrancy|realloc-race|bump-seed-canonicalization):' \
      "$WORK/run.log" | head -1 | tr -d '[:' || true)

    if [[ -n "$by" ]]; then
      outcome=$(jq -n --arg by "$by" '{outcome:"killed", by:$by}')
    elif [[ -n "$encl" ]] && grep -q '\[solinv\]\[reached\]' "$WORK/run.log" \
         && ! grep -qE "\[solinv\]\[reached\] ix=${encl}( |$)" "$WORK/run.log"; then
      # The ledger reported *some* instruction as reached but not this
      # mutant's, so this code did not execute. Requiring at least one
      # `[reached]` line first matters: a run that emitted none tells us
      # the ledger is not wired up, not that nothing ran, and inferring
      # not_reached from that would empty the denominator on a
      # misconfiguration.
      outcome='{"outcome":"not_reached"}'
    else
      outcome='{"outcome":"survived"}'
    fi
  fi

  [[ $FIRST -eq 1 ]] || echo "," >> "$RESULTS"
  FIRST=0
  jq -n --arg id "$id" --arg k "$killer" --argjson o "$outcome" \
    '{mutant_id:$id, expected_killer:$k} + $o' >> "$RESULTS"
  echo "  $id -> $(echo "$outcome" | jq -r .outcome)"
done

echo "]" >> "$RESULTS"
echo
echo "results written to $RESULTS"
echo "score it with:"
echo "  $SOLINV mutate score --plan $PLAN --results $RESULTS"
