package com.slotting.admin.ledger

import com.slotting.admin.infra.PostgresIntegrationSupport
import org.junit.jupiter.api.Test
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DataSourceTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LegacyCurrencyTransitionTest {

    private fun newSchema(): com.slotting.admin.infra.IsolatedPostgresSchema =
        PostgresIntegrationSupport.createIsolatedSchema(
            "tc04_${UUID.randomUUID().toString().replace("-", "").take(12)}",
        )

    private fun createMinimalSchema(jdbc: JdbcTemplate) {
        jdbc.execute(
            """
            create table ledger_account (
                account_id uuid primary key,
                tenant_id varchar(128) not null,
                account_reference varchar(128) not null,
                currency_code varchar(3) not null,
                account_type varchar(32) not null default 'STANDARD',
                status varchar(32) not null default 'ACTIVE'
            )
            """.trimIndent(),
        )
        jdbc.execute(
            """
            create table ledger_leg (
                leg_id uuid primary key,
                tenant_id varchar(128) not null,
                account_reference varchar(128) not null,
                direction varchar(16) not null,
                amount_minor_units bigint not null,
                currency_code varchar(3) not null,
                line_order integer not null
            )
            """.trimIndent(),
        )
        jdbc.execute(
            """
            create table wallet_projection (
                projection_id uuid primary key,
                tenant_id varchar(128) not null,
                owner_reference varchar(128) not null,
                currency_code varchar(3) not null,
                balance_minor_units bigint not null
            )
            """.trimIndent(),
        )
        jdbc.execute(
            """
            create table admin_deposit_intent (
                intent_id uuid primary key,
                tenant_id varchar(128) not null,
                currency_code varchar(3) not null,
                amount_minor_units bigint not null
            )
            """.trimIndent(),
        )
    }

    private fun seed(jdbc: JdbcTemplate, tenantId: String, currency: String, playerId: String, amount: Long) {
        jdbc.update(
            "insert into ledger_account(account_id, tenant_id, account_reference, currency_code, status) values (?, ?, ?, ?, 'ACTIVE')",
            UUID.randomUUID(),
            tenantId,
            "PLAYER:$playerId",
            currency,
        )
        jdbc.update(
            "insert into ledger_leg(leg_id, tenant_id, account_reference, direction, amount_minor_units, currency_code, line_order) values (?, ?, ?, 'CREDIT', ?, ?, 1)",
            UUID.randomUUID(),
            tenantId,
            "PLAYER:$playerId",
            amount,
            currency,
        )
        jdbc.update(
            "insert into wallet_projection(projection_id, tenant_id, owner_reference, currency_code, balance_minor_units) values (?, ?, ?, ?, ?)",
            UUID.randomUUID(),
            tenantId,
            playerId,
            currency,
            amount,
        )
        jdbc.update(
            "insert into admin_deposit_intent(intent_id, tenant_id, currency_code, amount_minor_units) values (?, ?, ?, ?)",
            UUID.randomUUID(),
            tenantId,
            currency,
            amount,
        )
    }

    @Test
    fun `TC-008-R1 dry run reports per-currency totals and leaves database checksum unchanged`() {
        newSchema().use { schema ->
            createMinimalSchema(schema.jdbc)
            seed(schema.jdbc, "tenant-a", "INR", "player-inr", 12_345L)
            seed(schema.jdbc, "tenant-a", "PKR", "player-pkr", 10_000L)
            seed(schema.jdbc, "tenant-a", "USD", "player-usd", 2_500L)
            val service = LegacyCurrencyTransitionService(schema.jdbc)
            val before = service.databaseChecksum()

            val report = service.inventory("disposable-restored-snapshot")

            assertEquals(12_345L, report.totalsByCurrency["INR"])
            assertEquals(10_000L, report.totalsByCurrency["PKR"])
            assertEquals(2_500L, report.totalsByCurrency["USD"])
            assertTrue(report.environmentClassified)
            assertEquals(before, service.databaseChecksum())
            assertTrue(report.discrepancies.isEmpty())
        }
    }

    @Test
    fun `TC-008-R2 unknown environment provenance blocks activation and records the reason`() {
        newSchema().use { schema ->
            createMinimalSchema(schema.jdbc)
            seed(schema.jdbc, "tenant-a", "INR", "player-inr", 12_345L)
            val service = LegacyCurrencyTransitionService(schema.jdbc)

            val report = service.inventory(null)
            val decision = service.evaluateActivation(report, provenanceApproved = true)

            assertFalse(report.environmentClassified)
            assertFalse(decision.allowed)
            assertEquals("UNKNOWN_PROVENANCE", decision.reason)
        }
    }

    @Test
    fun `TC-008-R3 legacy INR journal keeps INR and exact amount after PKR activation`() {
        newSchema().use { schema ->
            createMinimalSchema(schema.jdbc)
            seed(schema.jdbc, "tenant-a", "INR", "player-inr", 12_345L)
            val service = LegacyCurrencyTransitionService(schema.jdbc)

            val result = service.applyDefaultTransition("disposable-restored-snapshot", provenanceApproved = true)

            assertTrue(result.decision.allowed)
            assertTrue(result.quarantinedAccounts >= 1)
            val amount = schema.jdbc.queryForObject(
                "select amount_minor_units from ledger_leg where currency_code = 'INR'",
                Long::class.java,
            )
            val currency = schema.jdbc.queryForObject(
                "select currency_code from ledger_leg where account_reference = 'PLAYER:player-inr'",
                String::class.java,
            )
            val state = schema.jdbc.queryForObject(
                "select status from ledger_account where account_reference = 'PLAYER:player-inr'",
                String::class.java,
            )
            assertEquals(12_345L, amount)
            assertEquals("INR", currency)
            assertEquals("QUARANTINED", state)
        }
    }

    @Test
    fun `TC-008-R4 rollback rehearsal restores original totals and references without live writes`() {
        newSchema().use { schema ->
            createMinimalSchema(schema.jdbc)
            seed(schema.jdbc, "tenant-a", "INR", "player-inr", 12_345L)
            val service = LegacyCurrencyTransitionService(schema.jdbc)
            val before = service.databaseChecksum()
            val transaction = TransactionTemplate(DataSourceTransactionManager(schema.dataSource))

            runCatching {
                transaction.executeWithoutResult {
                    service.applyDefaultTransition("disposable-restored-snapshot", provenanceApproved = true)
                    throw IllegalStateException("rehearsal rollback")
                }
            }
            assertEquals(before, service.databaseChecksum())
            val state = schema.jdbc.queryForObject(
                "select status from ledger_account where account_reference = 'PLAYER:player-inr'",
                String::class.java,
            )
            assertEquals("ACTIVE", state)
        }
    }
}
