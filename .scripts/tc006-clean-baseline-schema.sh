#!/usr/bin/env bash
set -uo pipefail
JAR=$(find "$HOME/.gradle/caches/modules-2/files-2.1/org.postgresql/postgresql" -name 'postgresql-*.jar' 2>/dev/null | grep -v sources | head -1)
mkdir -p /tmp/opencode
cat > /tmp/opencode/DropTc006BaselineSchema.java <<'JAVA'
import java.sql.*;
public class DropTc006BaselineSchema {
    public static void main(String[] args) throws Exception {
        Class.forName("org.postgresql.Driver");
        try (Connection c = DriverManager.getConnection("jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci", "ci_runner", "ci_test_password_ephemeral");
             Statement s = c.createStatement()) {
            s.executeUpdate("drop schema if exists tc006_baseline_head cascade");
            System.out.println("dropped schema tc006_baseline_head if it existed");
        }
    }
}
JAVA
java -cp "$JAR" /tmp/opencode/DropTc006BaselineSchema.java
