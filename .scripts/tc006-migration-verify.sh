#!/usr/bin/env bash
set -uo pipefail

REPO="/home/pc/Downloads/slot_app/slotting_admin"
LOGS="$REPO/.logs/tc006-migration"
FIXTURE_SRC="$REPO/.scripts/tc006-migration-repro/Tc006MigrationAcceptanceTest.kt"
FIXTURE_DST="$REPO/src/test/kotlin/com/slotting/admin/gameprovider/Tc006MigrationAcceptanceTest.kt"

mkdir -p "$LOGS"

if ! bash "$REPO/.scripts/tc006-ensure-postgres.sh"; then
  echo "PostgreSQL is unavailable; aborting Stage 4 before producing invalid evidence." | tee "$LOGS/tc006-migration.log"
  exit 1
fi

rm -rf "$LOGS/junit-xml" "$LOGS/reports-html"

export SLOTTING_ADMIN_DATABASE_HOST="127.0.0.1"
export SLOTTING_ADMIN_DATABASE_PORT="5432"
export SLOTTING_ADMIN_DATABASE_USERNAME="ci_runner"
export SLOTTING_ADMIN_DATABASE_PASSWORD="ci_test_password_ephemeral"
export SLOTTING_ADMIN_DATABASE_URL="jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"

cp "$FIXTURE_SRC" "$FIXTURE_DST"

{
  echo "Stage 4 V40 migration acceptance"
  echo "Git HEAD: $(git -C "$REPO" rev-parse HEAD)"
  echo "Fixture: $FIXTURE_SRC sha256=$(sha256sum "$FIXTURE_SRC" | cut -d' ' -f1)"
  echo "Disposable databases: slotting_admin_tc006_mig_empty, slotting_admin_tc006_mig_upgrade"
  echo "JDK: $(java -version 2>&1 | head -1)"
  echo "Runtime UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "---"
} > "$LOGS/tc006-migration.log"

cd "$REPO"
./gradlew test --tests 'com.slotting.admin.gameprovider.Tc006MigrationAcceptanceTest' --rerun-tasks --console=plain >> "$LOGS/tc006-migration.log" 2>&1
migration_status=$?
echo "migration_exit=$migration_status" | tee -a "$LOGS/tc006-migration.log"

mkdir -p "$LOGS/junit-xml"
cp "$REPO"/build/test-results/test/TEST-*Tc006MigrationAcceptanceTest.xml "$LOGS/junit-xml/" 2>/dev/null
cp -r "$REPO"/build/reports/tests/test "$LOGS/reports-html" 2>/dev/null

if ! ls "$LOGS"/junit-xml/TEST-*Tc006MigrationAcceptanceTest.xml >/dev/null 2>&1; then
  echo "No migration JUnit XML produced; the migration fixture did not execute." | tee -a "$LOGS/tc006-migration.log"
fi

rm -f "$FIXTURE_DST"
echo "migration_exit=$migration_status" > "$LOGS/exit-status.txt"
echo "Artifacts: $LOGS/tc006-migration.log, $LOGS/junit-xml, $LOGS/exit-status.txt"
echo "Temporary fixture removed from the working tree: $FIXTURE_DST"
