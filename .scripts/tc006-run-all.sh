#!/usr/bin/env bash
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

echo "Ensuring a local PostgreSQL 16 is available (may provision via conda on first run)..."
if ! bash "$HERE/tc006-ensure-postgres.sh"; then
  echo "PostgreSQL could not be started. See .logs/tc006-ensure-postgres.log."
  exit 1
fi

echo "TC-006 stage runner. Running in audit-plan order. Do not interrupt."
echo "Stage 2: baseline RED reproduction"
bash "$HERE/tc006-red-baseline.sh"
echo "Stage 3: paired GREEN verification"
bash "$HERE/tc006-green-verify.sh"
echo "Stage 4: V40 migration acceptance"
bash "$HERE/tc006-migration-verify.sh"
echo "Stage 5: repository-wide classification"
bash "$HERE/tc006-full-classify.sh"
echo "Done. Review the .logs/tc006-* directories and the classification summary."
