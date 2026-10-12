package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import com.slotting.admin.infra.PostgresIntegrationSupport
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorFinancialConnectionRecoveryPostgresTest {
    @MockBean
    private lateinit var snapshotAndEventService: AuthoritativeGameSnapshotAndEventService

    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            PostgresIntegrationSupport.configureProperties(registry)
        }
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    @Autowired
    private lateinit var txManager: PlatformTransactionManager

    @Autowired
    private lateinit var ledgerStore: JdbcLedgerJournalStore

    @Autowired
    private lateinit var dataSource: javax.sql.DataSource

    @Test
    fun givenConnectionTerminatedAfterJournalWrites_whenTransactionRetries_thenOneDurablePostingExists() {
        val tenantId = "tenant-tc033-connection-${System.nanoTime()}"
        val command = PostTransactionCommand(
            principal = AuthenticatedPrincipal(
                id = "admin-tc033-connection",
                tenantId = tenantId,
                kind = PrincipalKind.ADMIN,
                roles = setOf(AdminRole.SUPER_ADMIN),
            ),
            tenantId = tenantId,
            transactionReference = "TX-TC033-CONNECTION",
            currencyCode = "INR",
            entries = listOf(
                JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 101L, "INR"),
                JournalEntryDraft("PLAYER:tc033-test", JournalEntryDirection.CREDIT, 101L, "INR"),
            ),
            idempotencyKey = "tc033-connection-retry",
            correlationId = "corr-tc033-connection",
            causationId = "caus-tc033-connection",
        )
        val ledgerService = LedgerPostingService(ledgerStore)
        val transactionEntered = CountDownLatch(1)
        val allowCommitAttempt = CountDownLatch(1)
        val transactionConnection = AtomicReference<java.sql.Connection>()
        val executor = Executors.newSingleThreadExecutor()
        val attempt = executor.submit {
            TransactionTemplate(txManager).execute<Unit> {
                ledgerService.postTransaction(command)
                transactionConnection.set(org.springframework.jdbc.datasource.DataSourceUtils.getConnection(dataSource))
                transactionEntered.countDown()
                assertTrue(allowCommitAttempt.await(10, TimeUnit.SECONDS))
            }
        }

        try {
            assertTrue(transactionEntered.await(10, TimeUnit.SECONDS))
            val connection = transactionConnection.get()
            assertNotNull(connection)
            connection.abort(Executor { task -> task.run() })
            allowCommitAttempt.countDown()
            try {
                attempt.get(10, TimeUnit.SECONDS)
            } catch (_: ExecutionException) {
            }
        } finally {
            allowCommitAttempt.countDown()
            executor.shutdownNow()
        }

        val preRetryCount = jdbc.queryForObject(
            "select count(*) from ledger_transaction where tenant_id = ? and idempotency_key = ?",
            Int::class.java,
            tenantId,
            command.idempotencyKey,
        ) ?: 0
        assertEquals(0, preRetryCount)

        ledgerService.postTransaction(command)

        val stored = ledgerStore.findByIdempotency(tenantId, command.idempotencyKey)
        assertNotNull(stored)
        assertEquals(command.transactionReference, stored.second.transactionReference)
        assertEquals(
            1,
            jdbc.queryForObject(
                "select count(*) from ledger_transaction where tenant_id = ? and idempotency_key = ?",
                Int::class.java,
                tenantId,
                command.idempotencyKey,
            ),
        )
        assertEquals(
            2,
            jdbc.queryForObject(
                "select count(*) from ledger_leg where tenant_id = ? and transaction_id = ?",
                Int::class.java,
                tenantId,
                stored.second.resultId,
            ),
        )
    }
}
