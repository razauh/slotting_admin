package com.slotting.admin.migration

import com.slotting.admin.infra.IsolatedPostgresSchema
import com.slotting.admin.infra.PostgresIntegrationSupport
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.MigrationVersion
import java.sql.Connection
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

class MigrationSafetyHarness private constructor(
    private val schema: IsolatedPostgresSchema,
) : AutoCloseable {
    val jdbc = schema.jdbc
    val schemaName = schema.schemaName

    fun migrateTo(version: String? = null) {
        flyway(version).migrate()
    }

    fun currentVersion(): String? = jdbc.queryForObject(
        "select version from flyway_schema_history where success order by installed_rank desc limit 1",
        String::class.java,
    )

    fun seedProductionLikeData(
        roundVersions: List<Long> = listOf(1L, 2L, 3L),
        forceFailure: Boolean = false,
        malformedRoundVersion: Boolean = false,
    ) {
        require(roundVersions.isNotEmpty() || malformedRoundVersion)
        val tenantId = "tenant-tc04-$schemaName"
        val now = Timestamp.from(Instant.parse("2026-10-12T00:00:00Z"))
        schema.dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                seedWallet(connection, tenantId, now)
                if (forceFailure) seedWallet(connection, tenantId, now)
                seedLedger(connection, tenantId, now)
                seedDeposit(connection, tenantId, now)
                seedFraudRows(connection, tenantId, now)
                seedGameEvents(connection, tenantId, now, roundVersions, malformedRoundVersion)
                connection.commit()
            } catch (failure: Throwable) {
                connection.rollback()
                throw failure
            }
        }
    }

    fun legacyRowCounts(): Map<String, Int> = listOf(
        "wallet_projection",
        "ledger_account",
        "ledger_transaction",
        "ledger_leg",
        "admin_deposit_intent",
        "fraud_risk_events",
        "fraud_cases",
        "game_event_journal",
    ).associateWith { table -> jdbc.queryForObject("select count(*) from $table", Int::class.java) ?: 0 }

    fun roundVersionBackfillViolationCount(): Int = jdbc.queryForObject(
        ROUND_VERSION_BACKFILL_VIOLATIONS,
        Int::class.java,
    ) ?: 0

    fun backfilledRoundVersions(): List<Long> = jdbc.queryForList(
        "select round_version from game_event_journal order by sequence_id",
        Long::class.java,
    )

    fun lifecycleAttemptJournalExists(): Boolean = jdbc.queryForObject(
        "select to_regclass(?) is not null",
        Boolean::class.java,
        "$schemaName.lifecycle_attempt_journal",
    ) ?: false

    fun successfulMigrationCount(version: String): Int = jdbc.queryForObject(
        "select count(*) from flyway_schema_history where version = ? and success",
        Int::class.java,
        version,
    ) ?: 0

    fun assertCurrentVersion(expected: String) {
        check(currentVersion() == expected) {
            "Expected Flyway version $expected but found ${currentVersion()} in schema $schemaName"
        }
    }

    override fun close() = schema.close()

    private fun flyway(targetVersion: String?): Flyway {
        val configuration = Flyway.configure()
            .dataSource(schema.dataSource)
            .schemas(schemaName)
            .defaultSchema(schemaName)
            .locations("classpath:db/migration")
            .validateOnMigrate(true)
            .cleanDisabled(true)
        if (targetVersion != null) configuration.target(MigrationVersion.fromVersion(targetVersion))
        return configuration.load()
    }

    private fun seedWallet(connection: Connection, tenantId: String, now: Timestamp) {
        connection.prepareStatement(
            "insert into wallet_projection (projection_id, tenant_id, owner_reference, currency_code, balance_minor_units, ledger_version, server_version, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?)",
        ).use { statement ->
            statement.setObject(1, UUID.randomUUID())
            statement.setString(2, tenantId)
            statement.setString(3, "player:wallet:$schemaName")
            statement.setString(4, "PKR")
            statement.setLong(5, 25_000L)
            statement.setLong(6, 1L)
            statement.setLong(7, 1L)
            statement.setTimestamp(8, now)
            statement.executeUpdate()
        }
    }

    private fun seedLedger(connection: Connection, tenantId: String, now: Timestamp) {
        val cashAccount = "cash:$schemaName"
        val walletAccount = "player:wallet:$schemaName"
        for (account in listOf(cashAccount, walletAccount)) {
            connection.prepareStatement(
                "insert into ledger_account (account_id, tenant_id, account_reference, currency_code, account_type, status, created_at) values (?, ?, ?, ?, ?, ?, ?)",
            ).use { statement ->
                statement.setObject(1, UUID.randomUUID())
                statement.setString(2, tenantId)
                statement.setString(3, account)
                statement.setString(4, "PKR")
                statement.setString(5, "STANDARD")
                statement.setString(6, "ACTIVE")
                statement.setTimestamp(7, now)
                statement.executeUpdate()
            }
        }
        val transactionId = UUID.randomUUID()
        connection.prepareStatement(
            "insert into ledger_transaction (transaction_id, tenant_id, transaction_reference, currency_code, total_debits_minor_units, total_credits_minor_units, is_balanced, status, entry_count, idempotency_key, correlation_id, causation_id, posted_by, posted_at, effective_at, ledger_version, evidence_reference) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).use { statement ->
            statement.setObject(1, transactionId)
            statement.setString(2, tenantId)
            statement.setString(3, "tc04-ledger-$schemaName")
            statement.setString(4, "PKR")
            statement.setLong(5, 25_000L)
            statement.setLong(6, 25_000L)
            statement.setBoolean(7, true)
            statement.setString(8, "POSTED")
            statement.setInt(9, 2)
            statement.setString(10, "tc04-ledger-idem-$schemaName")
            statement.setString(11, "tc04-correlation-$schemaName")
            statement.setString(12, "tc04-causation-$schemaName")
            statement.setString(13, "tc04-test")
            statement.setTimestamp(14, now)
            statement.setTimestamp(15, now)
            statement.setLong(16, 1L)
            statement.setString(17, "tc04-ledger-evidence")
            statement.executeUpdate()
        }
        listOf("DEBIT" to cashAccount, "CREDIT" to walletAccount).forEachIndexed { index, (direction, account) ->
            connection.prepareStatement(
                "insert into ledger_leg (leg_id, transaction_id, tenant_id, account_reference, direction, amount_minor_units, currency_code, line_order, created_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ).use { statement ->
                statement.setObject(1, UUID.randomUUID())
                statement.setObject(2, transactionId)
                statement.setString(3, tenantId)
                statement.setString(4, account)
                statement.setString(5, direction)
                statement.setLong(6, 25_000L)
                statement.setString(7, "PKR")
                statement.setInt(8, index + 1)
                statement.setTimestamp(9, now)
                statement.executeUpdate()
            }
        }
    }

    private fun seedDeposit(connection: Connection, tenantId: String, now: Timestamp) {
        connection.prepareStatement(
            "insert into admin_deposit_intent (intent_id, tenant_id, player_id, method_id, provider_id, amount_minor_units, currency_code, status, provider_reference, idempotency_key, correlation_id, causation_id, expires_at, server_version, created_at, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).use { statement ->
            statement.setObject(1, UUID.randomUUID())
            statement.setString(2, tenantId)
            statement.setObject(3, UUID.randomUUID())
            statement.setString(4, "TC04_BANK_TRANSFER")
            statement.setString(5, "TC04_PROVIDER")
            statement.setLong(6, 25_000L)
            statement.setString(7, "PKR")
            statement.setString(8, "PROVIDER_PENDING")
            statement.setString(9, "tc04-deposit-ref-$schemaName")
            statement.setString(10, "tc04-deposit-idem-$schemaName")
            statement.setString(11, "tc04-deposit-correlation-$schemaName")
            statement.setString(12, "tc04-deposit-causation-$schemaName")
            statement.setTimestamp(13, now)
            statement.setLong(14, 1L)
            statement.setTimestamp(15, now)
            statement.setTimestamp(16, now)
            statement.executeUpdate()
        }
    }

    private fun seedFraudRows(connection: Connection, tenantId: String, now: Timestamp) {
        connection.prepareStatement(
            "insert into fraud_risk_events (event_id, tenant_id, subject_reference, event_type, source, confidence, event_timestamp, ingest_timestamp, idempotency_key, correlation_id, causation_id, metadata_json) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).use { statement ->
            statement.setObject(1, UUID.randomUUID())
            statement.setString(2, tenantId)
            statement.setString(3, "player:$schemaName")
            statement.setString(4, "DEPOSIT_REVIEW")
            statement.setString(5, "PAYMENT")
            statement.setString(6, "MEDIUM")
            statement.setTimestamp(7, now)
            statement.setTimestamp(8, now)
            statement.setString(9, "tc04-fraud-event-idem-$schemaName")
            statement.setString(10, "tc04-fraud-event-correlation-$schemaName")
            statement.setString(11, "tc04-fraud-event-causation-$schemaName")
            statement.setString(12, "{}")
            statement.executeUpdate()
        }
        connection.prepareStatement(
            "insert into fraud_cases (case_id, tenant_id, subject_reference, case_reference, state, severity, risk_decision_refs_json, detected_reasons_json, admin_notes_json, created_at, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).use { statement ->
            statement.setObject(1, UUID.randomUUID())
            statement.setString(2, tenantId)
            statement.setString(3, "player:$schemaName")
            statement.setString(4, "tc04-fraud-case-$schemaName")
            statement.setString(5, "OPEN")
            statement.setString(6, "MEDIUM")
            statement.setString(7, "[]")
            statement.setString(8, "[\"migration-safety-seed\"]")
            statement.setString(9, "{}")
            statement.setTimestamp(10, now)
            statement.setTimestamp(11, now)
            statement.executeUpdate()
        }
    }

    private fun seedGameEvents(
        connection: Connection,
        tenantId: String,
        now: Timestamp,
        roundVersions: List<Long>,
        malformedRoundVersion: Boolean,
    ) {
        connection.prepareStatement(
            "insert into game_event_journal (event_id, tenant_id, game_id, round_id, sequence_id, event_name, payload_json, target_scope, target_owner_id, timestamp_millis, created_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).use { statement ->
            val payloads = roundVersions.map { "{\"roundVersion\":$it}" } +
                if (malformedRoundVersion) listOf("{\"other\":1}") else emptyList()
            payloads.forEachIndexed { index, payload ->
                statement.setObject(1, UUID.randomUUID())
                statement.setString(2, tenantId)
                statement.setString(3, "AVIATOR")
                statement.setString(4, "round-$index-$schemaName")
                statement.setLong(5, index.toLong() + 1L)
                statement.setString(6, "ROUND_UPDATED")
                statement.setString(7, payload)
                statement.setString(8, "BROADCAST")
                statement.setNull(9, java.sql.Types.VARCHAR)
                statement.setLong(10, now.time)
                statement.setTimestamp(11, now)
                statement.addBatch()
            }
            statement.executeBatch()
        }
    }

    companion object {
        const val LEGACY_MIGRATION_VERSION = "46"
        const val CURRENT_MIGRATION_VERSION = "59"
        const val ROUND_VERSION_BACKFILL_VIOLATIONS = """
            select count(*)
            from game_event_journal
            where round_version is null
               or round_version < 1
               or round_version <> case
                   when (payload_json::jsonb ->> 'roundVersion') ~ '^[1-9][0-9]*$'
                       then (payload_json::jsonb ->> 'roundVersion')::bigint
                   else null
               end
        """

        fun open(): MigrationSafetyHarness {
            val schemaName = "tc04_${UUID.randomUUID().toString().replace("-", "").take(12)}"
            return MigrationSafetyHarness(PostgresIntegrationSupport.createIsolatedSchema(schemaName))
        }
    }
}
