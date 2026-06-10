#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage:
  bandit_decide.sh <log_file> [more_logs...]

Runs:
  1) aggregate_bandit_metrics.sh
  2) recommend_bandit_allocation.sh
EOF
  exit 0
fi

if [[ "$#" -lt 1 ]]; then
  echo "error: provide at least one log file" >&2
  exit 1
fi

./scripts/aggregate_bandit_metrics.sh "$@"
echo
./scripts/recommend_bandit_allocation.sh "$@"
