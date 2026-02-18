#!/usr/bin/env bash
set -euo pipefail

# Wrapper for the rubric-oriented E2E test and bulk evaluation.
# Usage:
#   Single submission: ./grade_a2.sh [submission_dir] [extra args...]
#   Bulk evaluation:   ./grade_a2.sh --bulk [bulk_root] [extra args...]
#
# Examples:
#   ./grade_a2.sh .
#   MAIN_SERVER=Server MAIN_HOST=IntermediateHost MAIN_CLIENT=Client ./grade_a2.sh .
#   JAVA_OPTS="-Xmx256m" TIMEOUT_SECONDS=35 ./grade_a2.sh .
#   ./grade_a2.sh --bulk /path/to/bulk-folder --report /tmp/a2_bulk.html

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" == "--bulk" ]]; then
  shift
  BULK_ROOT="${1:-.}"
  shift || true
  python3 "$SCRIPT_DIR/grade_a2_bulk.py" --bulk-root "$BULK_ROOT" "$@"
else
  ROOT="${1:-.}"
  shift || true
  python3 "$SCRIPT_DIR/grade_a2.py" --root "$ROOT" --keep-logs "$@"
fi
