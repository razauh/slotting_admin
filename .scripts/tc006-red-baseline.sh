#!/usr/bin/env bash
set -uo pipefail

REPO="/home/pc/Downloads/slot_app/slotting_admin"
BASELINE="/tmp/opencode/tc006-baseline"
LOGS="$REPO/.logs/tc006-red-baseline"
BASELINE_REV="b26bb0f98b3363efb40d71d73207cd58360aef70"
BASELINE_DB="slotting_admin_tc006_baseline_red"
FIXTURE_SRC="$REPO/.scripts/tc006-baseline-repro/Tc006BaselineRedReproductionTest.kt"
FIXTURE_DST="$BASELINE/src/test/kotlin/com/slotting/admin/gameprovider/Tc006BaselineRedReproductionTest.kt"

mkdir -p "$LOGS" /tmp/opencode

if ! bash "$REPO/.scripts/tc006-ensure-postgres.sh"; then
  echo "PostgreSQL is unavailable; aborting Stage 2 before producing invalid evidence." | tee "$LOGS/tc006-red-baseline.log"
  exit 1
fi

rm -rf "$LOGS/junit-xml" "$LOGS/reports-html"

git -C "$REPO" worktree prune
rm -rf "$BASELINE"
if ! git -C "$REPO" worktree add --force --detach "$BASELINE" "$BASELINE_REV"; then
  echo "Failed to create baseline worktree at $BASELINE" | tee "$LOGS/tc006-red-baseline.log"
  exit 1
fi

if ! git -C "$BASELINE" checkout --detach "$BASELINE_REV"; then
  echo "Failed to check out baseline revision $BASELINE_REV" | tee -a "$LOGS/tc006-red-baseline.log"
  exit 1
fi
if ! cp "$FIXTURE_SRC" "$FIXTURE_DST"; then
  echo "Failed to copy baseline RED fixture into $FIXTURE_DST" | tee -a "$LOGS/tc006-red-baseline.log"
  exit 1
fi
if [ ! -f "$FIXTURE_DST" ]; then
  echo "Baseline RED fixture missing after copy: $FIXTURE_DST" | tee -a "$LOGS/tc006-red-baseline.log"
  exit 1
fi

JAR=$(find "$HOME/.gradle/caches/modules-2/files-2.1/org.postgresql/postgresql" -name 'postgresql-*.jar' 2>/dev/null | grep -v sources | head -1)
cat > /tmp/opencode/EnsureTc006RedDb.java <<'JAVA'
import java.sql.*;
public class EnsureTc006RedDb {
    public static void main(String[] args) throws Exception {
        Class.forName("org.postgresql.Driver");
        try (Connection c = DriverManager.getConnection("jdbc:postgresql://127.0.0.1:5432/postgres", "ci_runner", "");
             Statement s = c.createStatement()) {
            try {
                s.executeUpdate("create database " + args[0] + " owner ci_runner");
                System.out.println("created database " + args[0]);
            } catch (SQLException e) {
                System.out.println("database " + args[0] + " already present or not created: " + e.getMessage());
            }
        }
    }
}
JAVA
java -cp "$JAR" /tmp/opencode/EnsureTc006RedDb.java "$BASELINE_DB" > "$LOGS/db-setup.log" 2>&1

export SLOTTING_ADMIN_DATABASE_URL="jdbc:postgresql://127.0.0.1:5432/$BASELINE_DB"
export SLOTTING_ADMIN_DATABASE_USERNAME="ci_runner"
export SLOTTING_ADMIN_DATABASE_PASSWORD="ci_test_password_ephemeral"

{
  echo "Stage 2 baseline RED reproduction"
  echo "Baseline revision: $BASELINE_REV (detached, no TC-005/TC-006 changes)"
  echo "Baseline database: $BASELINE_DB (separate database, no shared schema or Flyway history)"
  echo "Fixture source: $FIXTURE_SRC"
  echo "Fixture sha256: $(sha256sum "$FIXTURE_SRC" | cut -d' ' -f1)"
  echo "JDK: $(java -version 2>&1 | head -1)"
  echo "Runtime UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Expected RED behaviors:"
  echo "  RED-1 deterministic place-bet ledger key instead of random UUID key"
  echo "  RED-2 receipt-first lock order instead of late receipt write"
  echo "  RED-3 transaction-private PENDING claim representation"
  echo "Expected GREEN guard:"
  echo "  GREEN baseline golden money vectors (regression guard, not a defect RED)"
  echo "---"
} > "$LOGS/tc006-red-baseline.log"

if ! cd "$BASELINE"; then
  echo "Cannot enter baseline worktree $BASELINE" | tee -a "$LOGS/tc006-red-baseline.log"
  exit 1
fi
./gradlew test --tests 'com.slotting.admin.gameprovider.Tc006BaselineRedReproductionTest' --rerun-tasks --console=plain >> "$LOGS/tc006-red-baseline.log" 2>&1
red_status=$?
echo "red_exit=$red_status" | tee -a "$LOGS/tc006-red-baseline.log"

mkdir -p "$LOGS/junit-xml"
cp "$BASELINE"/build/test-results/test/TEST-*Tc006BaselineRedReproductionTest.xml "$LOGS/junit-xml/" 2>/dev/null
cp -r "$BASELINE"/build/reports/tests/test "$LOGS/reports-html" 2>/dev/null

if ! ls "$LOGS"/junit-xml/TEST-*Tc006BaselineRedReproductionTest.xml >/dev/null 2>&1; then
  echo "No baseline RED JUnit XML produced; the baseline fixture did not execute." | tee -a "$LOGS/tc006-red-baseline.log"
  exit 1
fi
echo "Artifacts: $LOGS/tc006-red-baseline.log, $LOGS/junit-xml, $LOGS/reports-html"
