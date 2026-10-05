#!/usr/bin/env bash
set -uo pipefail

REPO="/home/pc/Downloads/slot_app/slotting_admin"
LOGS="$REPO/.logs/tc006-green"
GREEN_DB="slotting_admin_tc006_green"

mkdir -p "$LOGS" /tmp/opencode

if ! bash "$REPO/.scripts/tc006-ensure-postgres.sh"; then
  echo "PostgreSQL is unavailable; aborting Stage 3 before producing invalid evidence." | tee "$LOGS/tc006-green.log"
  exit 1
fi

rm -rf "$LOGS/junit-xml" "$LOGS/reports-html"

JAR=$(find "$HOME/.gradle/caches/modules-2/files-2.1/org.postgresql/postgresql" -name 'postgresql-*.jar' 2>/dev/null | grep -v sources | head -1)
cat > /tmp/opencode/EnsureTc006GreenDb.java <<'JAVA'
import java.sql.*;
public class EnsureTc006GreenDb {
    public static void main(String[] args) throws Exception {
        Class.forName("org.postgresql.Driver");
        try (Connection c = DriverManager.getConnection("jdbc:postgresql://127.0.0.1:5432/postgres", "ci_runner", "");
             Statement s = c.createStatement()) {
            s.executeUpdate("drop database if exists " + args[0] + " with (force)");
            s.executeUpdate("create database " + args[0] + " owner ci_runner");
            System.out.println("recreated database " + args[0]);
        }
    }
}
JAVA
if ! java -cp "$JAR" /tmp/opencode/EnsureTc006GreenDb.java "$GREEN_DB" > "$LOGS/db-setup.log" 2>&1; then
  echo "Failed to recreate green database $GREEN_DB; see $LOGS/db-setup.log" | tee "$LOGS/tc006-green.log"
  exit 1
fi

export SLOTTING_ADMIN_DATABASE_URL="jdbc:postgresql://127.0.0.1:5432/$GREEN_DB"
export SLOTTING_ADMIN_DATABASE_USERNAME="ci_runner"
export SLOTTING_ADMIN_DATABASE_PASSWORD="ci_test_password_ephemeral"

{
  echo "Stage 3 paired GREEN verification (current TC-005/TC-006 working tree)"
  echo "Git HEAD: $(git -C "$REPO" rev-parse HEAD)"
  echo "Green database: $GREEN_DB (freshly recreated, clean Flyway history)"
  echo "JDK: $(java -version 2>&1 | head -1)"
  echo "Runtime UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "---"
} > "$LOGS/tc006-green.log"

cd "$REPO"

echo "Compiling main and test sources..." | tee -a "$LOGS/tc006-green.log"
./gradlew compileKotlin compileTestKotlin --console=plain >> "$LOGS/tc006-green.log" 2>&1
compile_status=$?
echo "compile_exit=$compile_status" | tee -a "$LOGS/tc006-green.log"

echo "Running focused TC-006 suite with --rerun-tasks (must execute, not restore from cache)..." | tee -a "$LOGS/tc006-green.log"
./gradlew test --tests 'com.slotting.admin.gameprovider.AviatorCommandClaimPostgresTest' --rerun-tasks --console=plain >> "$LOGS/tc006-green.log" 2>&1
focused_status=$?
echo "focused_exit=$focused_status" | tee -a "$LOGS/tc006-green.log"

echo "Running related TC-006 suites in one task invocation..." | tee -a "$LOGS/tc006-green.log"
./gradlew test \
  --tests 'com.slotting.admin.gameprovider.AviatorCommandClaimPostgresTest' \
  --tests 'com.slotting.admin.gameprovider.AviatorCommandSequencePostgresTest' \
  --tests 'com.slotting.admin.infra.PostgresMigrationIntegrationTest' \
  --tests 'com.slotting.admin.ledger.PersistentDoubleEntryLedgerContractTest' \
  --tests 'com.slotting.admin.gameprovider.DurableGameWagerAndSettlementAuthorityContractTest' \
  --rerun-tasks --console=plain >> "$LOGS/tc006-green.log" 2>&1
related_status=$?
echo "related_exit=$related_status" | tee -a "$LOGS/tc006-green.log"

mkdir -p "$LOGS/junit-xml"
cp "$REPO"/build/test-results/test/*.xml "$LOGS/junit-xml/" 2>/dev/null
cp -r "$REPO"/build/reports/tests/test "$LOGS/reports-html" 2>/dev/null

{
  echo "compile_exit=$compile_status"
  echo "focused_exit=$focused_status"
  echo "related_exit=$related_status"
} > "$LOGS/exit-status.txt"

echo "Artifacts: $LOGS/tc006-green.log, $LOGS/junit-xml, $LOGS/exit-status.txt"
