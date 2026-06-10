#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage:
  append_bandit_snapshot.sh <log_file> [more_logs...]

Appends a rendered snapshot to:
  docs/day3-bandit-allocation-policy.md
EOF
  exit 0
fi

if [[ "$#" -lt 1 ]]; then
  echo "error: provide at least one log file" >&2
  exit 1
fi

out_file="docs/day3-bandit-allocation-policy.md"
{
  echo
  ./scripts/render_bandit_snapshot.sh "$@"
} >> "$out_file"

echo "appended snapshot to $out_file"
