package com.slotting.admin.migration

import org.flywaydb.core.Flyway
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.sql.DriverManager
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FlywayFoldInTest {
    private val url = System.getenv("BB10_FLYWAY_URL")
        ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"

    @Test
    fun `V68 to V75 apply on the purpose-applied CI schema with no object diff`() {
        assumeTrue(System.getenv("BB10_FLYWAY") == "1", "BB10_FLYWAY not enabled")
        val flyway = Flyway.configure()
            .dataSource(url, "ci_runner", "")
            .locations("classpath:db/migration")
            .baselineOnMigrate(true)
            .baselineVersion("67")
            .cleanDisabled(true)
            .load()

        val beforeVersion = flyway.info().current()?.version?.version
        val before = snapshot()
        val migrated = flyway.migrate()
        flyway.validate()
        val after = snapshot()

        assertEquals(if (beforeVersion == "75") 0 else 8, migrated.migrationsExecuted)
        assertEquals("75", flyway.info().current()?.version?.version)
        assertEquals(before, after)

        val versions = history()
        listOf("68", "69", "70", "71", "72", "73", "74", "75").forEach { version ->
            assertTrue(versions.contains(version), "missing successful migration V$version")
        }

        val replayed = flyway.migrate()
        assertEquals(0, replayed.migrationsExecuted)
        assertEquals(after, snapshot())
    }

    private fun snapshot(): String {
        val parts = listOf(
            "tables:" + query("select table_name from information_schema.tables where table_schema = 'public' and table_name <> 'flyway_schema_history' order by table_name"),
            "views:" + query("select table_name from information_schema.views where table_schema = 'public' order by table_name"),
            "policies:" + query("select schemaname || '.' || tablename || '.' || policyname from pg_policies where schemaname in ('public','storage','realtime') order by 1"),
            "functions:" + query("select n.nspname || '.' || p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('api','public') order by 1"),
        )
        return MessageDigest.getInstance("SHA-256")
            .digest(parts.joinToString("|").toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    private fun history(): Set<String> =
        DriverManager.getConnection(url, "ci_runner", "").use { connection ->
            connection.prepareStatement("select version from flyway_schema_history where success = true").use { statement ->
                statement.executeQuery().use { rows ->
                    buildSet { while (rows.next()) add(rows.getString(1)) }
                }
            }
        }

    private fun query(sql: String): String =
        DriverManager.getConnection(url, "ci_runner", "").use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.executeQuery().use { rows ->
                    buildList { while (rows.next()) add(rows.getString(1)) }.joinToString(",")
                }
            }
        }
}
