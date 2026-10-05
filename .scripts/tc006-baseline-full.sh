#!/usr/bin/env bash
set -uo pipefail

REPO="/home/pc/Downloads/slot_app/slotting_admin"
BASELINE="/tmp/opencode/tc006-baseline"
LOGS="$REPO/.logs"
BASELINE_DB="slotting_admin_tc006_baseline"
mkdir -p "$LOGS" /tmp/opencode

if [ ! -e "$BASELINE/.git" ]; then
  git -C "$REPO" worktree add --detach "$BASELINE" HEAD
fi

JAR=$(find "$HOME/.gradle/caches/modules-2/files-2.1/org.postgresql/postgresql" -name 'postgresql-*.jar' 2>/dev/null | grep -v sources | head -1)
cat > /tmp/opencode/EnsureTc006BaselineDb.java <<'JAVA'
import java.sql.*;
public class EnsureTc006BaselineDb {
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
java -cp "$JAR" /tmp/opencode/EnsureTc006BaselineDb.java "$BASELINE_DB"

export SLOTTING_ADMIN_DATABASE_URL="jdbc:postgresql://127.0.0.1:5432/$BASELINE_DB"
export SLOTTING_ADMIN_DATABASE_USERNAME="ci_runner"
export SLOTTING_ADMIN_DATABASE_PASSWORD="ci_test_password_ephemeral"

echo "Baseline revision: $(git -C "$BASELINE" rev-parse HEAD) (detached HEAD, no TC-005/TC-006 changes)" > "$LOGS/tc006-baseline-full.log"
echo "Baseline database: $BASELINE_DB (separate database, not a schema of slotting_admin_ci)" >> "$LOGS/tc006-baseline-full.log"

cd "$BASELINE"
./gradlew test --console=plain >> "$LOGS/tc006-baseline-full.log" 2>&1
echo "baseline_exit=$?" | tee -a "$LOGS/tc006-baseline-full.log"
