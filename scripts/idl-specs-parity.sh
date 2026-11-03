#!/usr/bin/env bash
# Run escrow-demo's account-validation detectors twice — hand-written
# specs, then specs built from idl/*.json (`--features idl_specs`) — and
# print one line per run. Needs crucible + the two .so files built per
# the README quickstart. Not part of `cargo test`: it drives SBF code.
#
# Exits non-zero unless every planted row reports a finding, the same
# detector on the same ix in both modes, and both clean rows report 0.
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
  # crucible exits non-zero on a crash; the log is checked instead.
  (cd "$h" && crucible run "$h" "$f" --binary-in "$bin" --seed 1 \
      --crashes-out "$dir" "$@" >"$dir.log" 2>&1) || true
  grep -q 'Using seed' "$dir.log" || { echo "run did not start: $dir.log"; exit 1; }
  local n hit
  n=$(find "$dir" -type f ! -name '*.meta.json' | wc -l | tr -d ' ')
  hit=$(grep -m1 -o 'summary:\[[a-z-]*:[^]]*\] ix [a-z_]*' "$dir.log" \
        | sed -E 's/summary:\[([a-z-]+):[^]]*\]/\1/' || true)
  printf '%-13s %-40s %-4s crashes=%s %s\n' "$h" "$f" "$mode" "$n" "$hit"
  RESULT="$n $hit"
}

fail=0

for inv in signer_skip owner_skip discriminator_skip pda_forge account_swap; do
  run escrow "invariant_${inv}_only" hand --timeout "$secs" --stop-on-crash; hand="$RESULT"
  run escrow "invariant_${inv}_only" idl --timeout "$secs" --stop-on-crash; idl="$RESULT"
  if [ "$hand" != "$idl" ] || [ "${hand%% *}" = 0 ]; then echo "  MISMATCH $inv"; fail=1; fi
done
for mode in hand idl; do
  run escrow_clean invariant_all "$mode" --timeout "$((secs * 3))"
  if [ "${RESULT%% *}" != 0 ]; then echo "  CLEAN TWIN FIRED ($mode)"; fail=1; fi
done
echo "logs: $out"
[ "$fail" = 0 ] && echo PASS || { echo FAIL; exit 1; }
