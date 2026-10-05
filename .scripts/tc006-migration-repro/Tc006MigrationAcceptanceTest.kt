package com.slotting.admin.gameprovider

import org.flywaydb.core.Flyway
import org.flywaydb.core.api.MigrationVersion
import org.junit.jupiter.api.Test
import java.sql.Connection
import java.sql.DriverManager
import java.sql.SQLException
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Tc006MigrationAcceptanceTest {

    private val host = System.getenv("SLOTTING_ADMIN_DATABASE_HOST") ?: "127.0.0.1"
    private val port = System.getenv("SLOTTING_ADMIN_DATABASE_PORT") ?: "5432"
    private val user = System.getenv("SLOTTING_ADMIN_DATABASE_USERNAME") ?: "ci_runner"
    private val password = System.getenv("SLOTTING_ADMIN_DATABASE_PASSWORD") ?: "ci_test_password_ephemeral"
    private val locations = "classpath:db/migration"

    private val emptyDb = "slotting_admin_tc006_mig_empty"
    private val upgradeDb = "slotting_admin_tc006_mig_upgrade"

    private fun serverConnection(): Connection =
        DriverManager.getConnection("jdbc:postgresql://$host:$port/postgres", user, password)

    private fun dbUrl(name: String) = "jdbc:postgresql://$host:$port/$name"

    private fun connection(name: String): Connection = DriverManager.getConnection(dbUrl(name), user, password)

    private fun recreateDatabase(name: String) {
        serverConnection().use { server ->
            server.createStatement().use { st ->
                st.executeUpdate("drop database if exists $name with (force)")
                st.executeUpdate("create database $name owner $user")
            }
        }
    }

    private fun flyway(name: String): Flyway = Flyway.configure()
        .dataSource(dbUrl(name), user, password)
        .locations(locations)
        .load()

    private fun scalarString(conn: Connection, sql: String, vararg args: Any): String? =
        conn.prepareStatement(sql).use { ps ->
            args.forEachIndexed { i, a -> ps.setObject(i + 1, a) }
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }

    private fun scalarLong(conn: Connection, sql: String, vararg args: Any): Long =
        conn.prepareStatement(sql).use { ps ->
            args.forEachIndexed { i, a -> ps.setObject(i + 1, a) }
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getLong(1) }
        }

    @Test
    fun `empty installation migrates through V40 and validates with the supported schema version`() {
        recreateDatabase(emptyDb)
        val result = flyway(emptyDb).migrate()
        assertTrue(result.success, "Empty install migration must succeed")

        connection(emptyDb).use { conn ->
            val latest = scalarString(
                conn,
                "select version from flyway_schema_history where success order by installed_rank desc limit 1"
            )
            assertEquals("40", latest, "Latest applied migration must be V40")
            val supported = scalarString(
                conn,
                "select is_nullable from information_schema.columns where table_name = 'game_command_receipt' and column_name = 'response_json'"
            )
            assertEquals("YES", supported, "response_json must be nullable after V40")
        }

        flyway(emptyDb).validate()
    }

    @Test
    fun `representative upgrade to V40 preserves terminal rows and enforces the early claim lifecycle`() {
        recreateDatabase(upgradeDb)
        val preV40 = Flyway.configure()
            .dataSource(dbUrl(upgradeDb), user, password)
            .locations(locations)
            .target(MigrationVersion.fromVersion("39"))
            .load()
        preV40.migrate()
        assertEquals(
            "39",
            connection(upgradeDb).use { scalarString(it, "select version from flyway_schema_history where success order by installed_rank desc limit 1") },
            "Pre-V40 state must stop at V39",
        )

        val tenant = "tenant-tc006-upgrade"
        val terminalCommandId = "cmd-tc006-upgrade-terminal"
        val terminalReceiptId = UUID.randomUUID().toString()
        val terminalSequence = 7L
        val terminalResponse = "{\"status\":\"ACCEPTED\",\"sequenceId\":7}"

        connection(upgradeDb).use { conn ->
            conn.prepareStatement(
                """
                insert into game_command_receipt (
                    receipt_id, tenant_id, owner_id, game_id, command_id, round_id, hand_id,
                    action, status, fingerprint, response_json, causation_id, correlation_id,
                    server_sequence_id, round_version, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, 'PLACE_BET', 'ACCEPTED', ?, ?, ?, ?, ?, 1, now())
                """.trimIndent()
            ).use { ps ->
                ps.setObject(1, UUID.fromString(terminalReceiptId))
                ps.setString(2, tenant)
                ps.setString(3, "player-upgrade")
                ps.setString(4, "AVIATOR")
                ps.setString(5, terminalCommandId)
                ps.setString(6, "round-upgrade")
                ps.setString(7, "hand_primary")
                ps.setString(8, "fp-upgrade")
                ps.setString(9, terminalResponse)
                ps.setString(10, "caus-upgrade")
                ps.setString(11, "corr-upgrade")
                ps.setLong(12, terminalSequence)
                ps.executeUpdate()
            }
            conn.prepareStatement(
                "insert into game_command_sequence (tenant_id, last_sequence_id, updated_at) values (?, ?, now())"
            ).use { ps ->
                ps.setString(1, tenant)
                ps.setLong(2, terminalSequence)
                ps.executeUpdate()
            }
        }

        val receiptCountBefore = connection(upgradeDb).use {
            scalarLong(it, "select count(*) from game_command_receipt where tenant_id = ?", tenant)
        }
        val sequenceBefore = connection(upgradeDb).use {
            scalarLong(it, "select last_sequence_id from game_command_sequence where tenant_id = ?", tenant)
        }

        flyway(upgradeDb).migrate()

        connection(upgradeDb).use { conn ->
            assertTrue(
                flyway(upgradeDb).info().current()?.version?.version == "40",
                "Upgrade must reach V40",
            )
            assertEquals(
                "ACCEPTED",
                scalarString(conn, "select status from game_command_receipt where command_id = ?", terminalCommandId),
                "Terminal status must be preserved",
            )
            assertEquals(
                terminalResponse,
                scalarString(conn, "select response_json from game_command_receipt where command_id = ?", terminalCommandId),
                "Terminal response must be preserved",
            )
            assertEquals(
                terminalSequence,
                scalarLong(conn, "select server_sequence_id from game_command_receipt where command_id = ?", terminalCommandId),
                "Terminal sequence must be preserved",
            )
            assertEquals(
                "YES",
                scalarString(
                    conn,
                    "select is_nullable from information_schema.columns where table_name = 'game_command_receipt' and column_name = 'server_sequence_id'"
                ),
                "server_sequence_id must become nullable",
            )
            assertEquals(
                receiptCountBefore,
                scalarLong(conn, "select count(*) from game_command_receipt where tenant_id = ?", tenant),
                "No receipt rows may be deleted by V40",
            )
            assertEquals(
                sequenceBefore,
                scalarLong(conn, "select last_sequence_id from game_command_sequence where tenant_id = ?", tenant),
                "No sequence counter may be renumbered by V40",
            )
        }

        val statusConstraint = connection(upgradeDb).use { conn ->
            scalarString(
                conn,
                """
                select pg_get_constraintdef(oid) from pg_constraint
                where conrelid = 'game_command_receipt'::regclass
                  and conname = 'game_command_receipt_status_check'
                """.trimIndent()
            )
        }
        assertNotNull(statusConstraint, "V40 status constraint must exist")
        assertTrue(statusConstraint.contains("PENDING"), "Status constraint must accept PENDING: $statusConstraint")
        assertTrue(statusConstraint.contains("ACCEPTED"), "Status constraint must accept terminal values: $statusConstraint")

        val incompleteCommandId = "cmd-tc006-upgrade-incomplete"
        connection(upgradeDb).use { conn ->
            conn.autoCommit = false
            conn.prepareStatement(
                """
                insert into game_command_receipt (
                    receipt_id, tenant_id, owner_id, game_id, command_id, round_id, hand_id,
                    action, status, fingerprint, response_json, causation_id, correlation_id,
                    server_sequence_id, round_version, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, 'PLACE_BET', 'PENDING', ?, null, ?, ?, null, 1, now())
                """.trimIndent()
            ).use { ps ->
                ps.setObject(1, UUID.randomUUID())
                ps.setString(2, tenant)
                ps.setString(3, "player-upgrade")
                ps.setString(4, "AVIATOR")
                ps.setString(5, incompleteCommandId)
                ps.setString(6, "round-upgrade")
                ps.setString(7, "hand_primary")
                ps.setString(8, "fp-upgrade-incomplete")
                ps.setString(9, "caus-upgrade-incomplete")
                ps.setString(10, "corr-upgrade-incomplete")
                ps.executeUpdate()
            }
            assertFails("Committing an incomplete PENDING receipt must be rejected") { conn.commit() }
            conn.rollback()
            conn.autoCommit = true
        }
        connection(upgradeDb).use { conn ->
            assertEquals(
                0,
                scalarLong(conn, "select count(*) from game_command_receipt where command_id = ?", incompleteCommandId),
                "Rollback must leave no PENDING receipt",
            )
        }

        val completedCommandId = "cmd-tc006-upgrade-completed"
        connection(upgradeDb).use { conn ->
            conn.autoCommit = false
            conn.prepareStatement(
                """
                insert into game_command_receipt (
                    receipt_id, tenant_id, owner_id, game_id, command_id, round_id, hand_id,
                    action, status, fingerprint, response_json, causation_id, correlation_id,
                    server_sequence_id, round_version, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, 'PLACE_BET', 'PENDING', ?, null, ?, ?, null, 1, now())
                """.trimIndent()
            ).use { ps ->
                ps.setObject(1, UUID.randomUUID())
                ps.setString(2, tenant)
                ps.setString(3, "player-upgrade")
                ps.setString(4, "AVIATOR")
                ps.setString(5, completedCommandId)
                ps.setString(6, "round-upgrade")
                ps.setString(7, "hand_primary")
                ps.setString(8, "fp-upgrade-completed")
                ps.setString(9, "caus-upgrade-completed")
                ps.setString(10, "corr-upgrade-completed")
                ps.executeUpdate()
            }
            conn.prepareStatement(
                "update game_command_receipt set status = 'ACCEPTED', response_json = ?, server_sequence_id = ? where command_id = ?"
            ).use { ps ->
                ps.setString(1, "{\"status\":\"ACCEPTED\"}")
                ps.setLong(2, 8L)
                ps.setString(3, completedCommandId)
                ps.executeUpdate()
            }
            conn.commit()
            conn.autoCommit = true
        }
        connection(upgradeDb).use { conn ->
            assertEquals(
                "ACCEPTED",
                scalarString(conn, "select status from game_command_receipt where command_id = ?", completedCommandId),
                "A claim completed in the same transaction must commit",
            )
        }

        flyway(upgradeDb).validate()
    }

    @Test
    fun `upgrade rollback discards a rejected PENDING receipt without touching existing money or sequence state`() {
        recreateDatabase(upgradeDb)
        val preV40 = Flyway.configure()
            .dataSource(dbUrl(upgradeDb), user, password)
            .locations(locations)
            .target(MigrationVersion.fromVersion("39"))
            .load()
        preV40.migrate()

        val tenant = "tenant-tc006-rollback"
        connection(upgradeDb).use { conn ->
            conn.prepareStatement(
                "insert into game_command_sequence (tenant_id, last_sequence_id, updated_at) values (?, ?, now())"
            ).use { ps ->
                ps.setString(1, tenant)
                ps.setLong(2, 11L)
                ps.executeUpdate()
            }
        }
        val sequenceBefore = connection(upgradeDb).use {
            scalarLong(it, "select last_sequence_id from game_command_sequence where tenant_id = ?", tenant)
        }

        flyway(upgradeDb).migrate()

        val rollbackCommandId = "cmd-tc006-upgrade-rollback"
        connection(upgradeDb).use { conn ->
            conn.autoCommit = false
            conn.prepareStatement(
                """
                insert into game_command_receipt (
                    receipt_id, tenant_id, owner_id, game_id, command_id, round_id, hand_id,
                    action, status, fingerprint, response_json, causation_id, correlation_id,
                    server_sequence_id, round_version, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, 'PLACE_BET', 'PENDING', ?, null, ?, ?, null, 1, now())
                """.trimIndent()
            ).use { ps ->
                ps.setObject(1, UUID.randomUUID())
                ps.setString(2, tenant)
                ps.setString(3, "player-rollback")
                ps.setString(4, "AVIATOR")
                ps.setString(5, rollbackCommandId)
                ps.setString(6, "round-rollback")
                ps.setString(7, "hand_primary")
                ps.setString(8, "fp-rollback")
                ps.setString(9, "caus-rollback")
                ps.setString(10, "corr-rollback")
                ps.executeUpdate()
            }
            conn.rollback()
            conn.autoCommit = true
        }

        connection(upgradeDb).use { conn ->
            assertEquals(
                0,
                scalarLong(conn, "select count(*) from game_command_receipt where command_id = ?", rollbackCommandId),
                "Rolled-back claim must leave no PENDING receipt",
            )
            assertEquals(
                sequenceBefore,
                scalarLong(conn, "select last_sequence_id from game_command_sequence where tenant_id = ?", tenant),
                "Rolled-back claim must not consume a sequence value",
            )
        }
    }
}
