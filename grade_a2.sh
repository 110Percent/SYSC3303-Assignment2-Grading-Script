#!/usr/bin/env bash
set -euo pipefail

# Wrapper for the rubric-oriented E2E test.
# Usage:
#   ./grade_a2.sh [submission_dir]
#
# Examples:
#   ./grade_a2.sh .
#   MAIN_SERVER=Server MAIN_HOST=IntermediateHost MAIN_CLIENT=Client ./grade_a2.sh .
#   JAVA_OPTS="-Xmx256m" TIMEOUT_SECONDS=35 ./grade_a2.sh .
#   ./grade_a2.sh . --seed 123 --no-color

ROOT="${1:-.}"
shift || true
python3 "$(dirname "$0")/grade_a2.py" --root "$ROOT" --keep-logs "$@"
