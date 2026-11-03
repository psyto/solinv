#!/usr/bin/env bash
# Run escrow-demo's account-validation detectors twice — hand-written
# specs, then specs built from idl/*.json (`--features idl_specs`) — and
# print one line per run. Needs crucible + the two .so files built per
# the README quickstart. Not part of `cargo test`: it drives SBF code.
#
# Expected: every planted row reports the same detector on the same ix
# in both modes; both clean rows report 0.
set -euo pipefail
cd "$(dirname "$0")/../examples/escrow-demo/fuzz"
secs="${SECS:-20}"
out="$(pwd)/../target/idl-parity/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$out"

run() { # harness feature mode extra-flags...
  local h="$1" f="$2" mode="$3"; shift 3
  local feats="$f"; [ "$mode" = idl ] && feats="$f,idl_specs"
  (cd "$h" && cargo build --release -q --features "$feats")
  local bin="$out/${h}-${f}-${mode}.bin" dir="$out/${h}-${f}-${mode}"
  cp "$h/target/release/invariant_test" "$bin"; mkdir -p "$dir"
  (cd "$h" && crucible run "$h" "$f" --binary-in "$bin" --seed 1 \
      --crashes-out "$dir" "$@" >"$dir.log" 2>&1) || true
  local n hit
  n=$(find "$dir" -type f ! -name '*.meta.json' | wc -l | tr -d ' ')
  hit=$(grep -m1 -o 'summary:\[[a-z-]*:[^]]*\] ix [a-z_]*' "$dir.log" \
        | sed -E 's/summary:\[([a-z-]+):[^]]*\]/\1/' || true)
  printf '%-13s %-40s %-4s crashes=%s %s\n' "$h" "$f" "$mode" "$n" "$hit"
}

for inv in signer_skip owner_skip discriminator_skip pda_forge account_swap; do
  for mode in hand idl; do
    run escrow "invariant_${inv}_only" "$mode" --timeout "$secs" --stop-on-crash
  done
done
for mode in hand idl; do
  run escrow_clean invariant_all "$mode" --timeout "$((secs * 3))"
done
echo "logs: $out"
