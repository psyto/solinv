#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage:
  run_day3_checkpoint.sh <target> [timeout_sec]

Example:
  run_day3_checkpoint.sh raydium_amm 120

Runs two campaigns:
  - invariant_unchecked_math_only
  - invariant_cu_dos_only

Then runs:
  - bandit_decide.sh
  - append_bandit_snapshot.sh
EOF
  exit 0
fi

if [[ "$#" -lt 1 ]]; then
  echo "error: target is required" >&2
  exit 1
fi

target="$1"
timeout_sec="${2:-120}"
today="$(date +%F)"
ts="$(date +%H%M%S)"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "${repo_root}/logs"

log_unchecked="${repo_root}/logs/${today}_${target}_unchecked-math_${ts}.log"
log_cudos="${repo_root}/logs/${today}_${target}_cu-dos_${ts}.log"

run_dir="${repo_root}"
if [[ "${target}" == "raydium_amm" ]]; then
  run_dir="${repo_root}/examples/raydium-amm-fuzz"
fi

echo "[run] target=${target} timeout=${timeout_sec}s"
echo "[run] workdir=${run_dir}"
echo "[run] unchecked-math -> ${log_unchecked}"
(cd "${run_dir}" && SOLINV_BANDIT_METRICS=1 \
crucible run "${target}" invariant_unchecked_math_only --release --timeout "${timeout_sec}") 2>&1 | tee "${log_unchecked}"

echo "[run] cu-dos -> ${log_cudos}"
(cd "${run_dir}" && SOLINV_BANDIT_METRICS=1 \
crucible run "${target}" invariant_cu_dos_only --release --timeout "${timeout_sec}") 2>&1 | tee "${log_cudos}"

echo "[analyze] ${repo_root}/scripts/bandit_decide.sh ${log_unchecked} ${log_cudos}"
"${repo_root}/scripts/bandit_decide.sh" "${log_unchecked}" "${log_cudos}"

echo "[append] ${repo_root}/scripts/append_bandit_snapshot.sh ${log_unchecked} ${log_cudos}"
"${repo_root}/scripts/append_bandit_snapshot.sh" "${log_unchecked}" "${log_cudos}"

echo "[done] checkpoint complete"
