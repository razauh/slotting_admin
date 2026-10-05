#!/usr/bin/env bash
set -uo pipefail

REPO="/home/pc/Downloads/slot_app/slotting_admin"
LOGS="$REPO/.logs/tc006-full-run"
FULL_DB="slotting_admin_tc006_full"
R4_DIR="$REPO/.logs/tc006-evidence-r4"
R3_DIR="$REPO/.logs/tc006-evidence-r3-baseline"

mkdir -p "$LOGS" /tmp/opencode

if ! bash "$REPO/.scripts/tc006-ensure-postgres.sh"; then
  echo "PostgreSQL is unavailable; aborting Stage 5 before producing invalid evidence." | tee "$LOGS/tc006-full.log"
  exit 1
fi

rm -rf "$LOGS/junit-xml" "$LOGS/reports-html"

JAR=$(find "$HOME/.gradle/caches/modules-2/files-2.1/org.postgresql/postgresql" -name 'postgresql-*.jar' 2>/dev/null | grep -v sources | head -1)
cat > /tmp/opencode/EnsureTc006FullDb.java <<'JAVA'
import java.sql.*;
public class EnsureTc006FullDb {
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
if ! java -cp "$JAR" /tmp/opencode/EnsureTc006FullDb.java "$FULL_DB" > "$LOGS/db-setup.log" 2>&1; then
  echo "Failed to recreate full-suite database $FULL_DB; see $LOGS/db-setup.log" | tee "$LOGS/tc006-full.log"
  exit 1
fi

export SLOTTING_ADMIN_DATABASE_URL="jdbc:postgresql://127.0.0.1:5432/$FULL_DB"
export SLOTTING_ADMIN_DATABASE_USERNAME="ci_runner"
export SLOTTING_ADMIN_DATABASE_PASSWORD="ci_test_password_ephemeral"

{
  echo "Stage 5 repository-wide classification"
  echo "Git HEAD: $(git -C "$REPO" rev-parse HEAD)"
  echo "Full-suite database: $FULL_DB (freshly recreated)"
  echo "Baseline comparison source: $R4_DIR/failure-identities.txt (identical to r3)"
  echo "Runtime UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "---"
} > "$LOGS/tc006-full.log"

cd "$REPO"
./gradlew test --console=plain >> "$LOGS/tc006-full.log" 2>&1
full_status=$?
echo "full_exit=$full_status" | tee -a "$LOGS/tc006-full.log"

mkdir -p "$LOGS/junit-xml"
cp "$REPO"/build/test-results/test/*.xml "$LOGS/junit-xml/" 2>/dev/null
cp -r "$REPO"/build/reports/tests/test "$LOGS/reports-html" 2>/dev/null

extract_ids() {
  local dir="$1"
  (cd "$dir" 2>/dev/null && grep -l '<failure' *.xml 2>/dev/null | while read -r f; do
    grep '<testcase ' "$f" | grep -v '/>$' | sed -E 's/.*name="([^"]*)" classname="([^"]*)".*/\2#\1/'
  done | sort -u)
}

extract_ids "$LOGS/junit-xml" > "$LOGS/failure-identities-current.txt"
extract_ids "$R3_DIR" > "$LOGS/failure-identities-r3.txt"

count_v40() {
  local dir="$1"
  grep -l '<failure' "$dir"/*.xml 2>/dev/null | while read -r f; do
    grep -o 'message="[^"]*V40[^"]*"' "$f"
  done | wc -l
}

CURRENT_COUNT=$(wc -l < "$LOGS/failure-identities-current.txt")
BASELINE_COUNT=$(wc -l < "$LOGS/failure-identities-r3.txt")
ONLY_CURRENT=$(comm -23 "$LOGS/failure-identities-current.txt" "$LOGS/failure-identities-r3.txt" | wc -l)
ONLY_BASELINE=$(comm -13 "$LOGS/failure-identities-current.txt" "$LOGS/failure-identities-r3.txt" | wc -l)
V40_CURRENT=$(count_v40 "$LOGS/junit-xml")
V40_BASELINE=$(count_v40 "$R3_DIR")

{
  echo "full_exit=$full_status"
  echo "current_failing_identities=$CURRENT_COUNT"
  echo "baseline_r3_failing_identities=$BASELINE_COUNT"
  echo "only_current=$ONLY_CURRENT"
  echo "only_baseline=$ONLY_BASELINE"
  echo "v40_messages_current=$V40_CURRENT"
  echo "v40_messages_baseline_r3=$V40_BASELINE"
} > "$LOGS/classification-summary.txt"

echo "Artifacts: $LOGS/classification-summary.txt, $LOGS/failure-identities-current.txt, $LOGS/tc006-full.log"
