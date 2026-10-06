package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.identity.ServerEligibilityStore
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import java.math.BigDecimal
import java.sql.Timestamp
import java.time.Instant
import java.time.LocalDate
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.NONE,
    properties = [
        "slotting.aviator.service.enabled=true",
        "spring.datasource.hikari.maximum-pool-size=6",
    ],
)
class AviatorServiceCompositionTest {

    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            PostgresIntegrationSupport.configureProperties(registry)
        }
    }

    @TestConfiguration
    class CompositionEligibilityConfiguration {
        @Bean
        fun compositionEligibilityStore(): ServerEligibilityStore = InMemoryServerEligibilityStore()
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    @Autowired
    private lateinit var gameService: DurableGameWagerAndSettlementService

    @Autowired
    private lateinit var ledgerService: LedgerPostingService

    @Autowired
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority

    @Autowired
    private lateinit var eligibilityStore: ServerEligibilityStore

    @Autowired
    private lateinit var systemPrincipal: AuthenticatedPrincipal

    @Autowired
    private lateinit var applicationContext: ApplicationContext

    private val tenantId = "tenant-tc008-composition"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()
    private val now = Instant.parse("2026-10-05T10:00:00Z")

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "test-composition-admin",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerIdStr,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT),
    )

    @BeforeEach
    fun setUp() {
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
        jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)
        jdbc.update("delete from player_credential where tenant_id = ?", tenantId)

        jdbc.update(
            """
            insert into player_credential (
                player_id, tenant_id, identifier, password_hash, password_algo,
                password_salt, iterations, status, version, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_id, identifier) do nothing
            """.trimIndent(),
            playerUuid,
            tenantId,
            playerIdStr,
            "pbkdf2_sha256_hash",
            "pbkdf2_sha256",
            "salt",
            10000,
            "ACTIVE",
            1L,
            Timestamp.from(now.minusSeconds(86400)),
            Timestamp.from(now.minusSeconds(86400)),
        )

        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerUuid,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 5, 5),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerUuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 500000L,
                    dailyWagerLimitMinor = 2000000L,
                    currentDailyWagerMinor = 0L,
                ),
            )
        )
        assertEquals("system", systemPrincipal.tenantId, "Composition must inject the system principal")
        assertNotEquals(tenantId, systemPrincipal.tenantId, "Wager tenant must differ from the composed principal tenant")
    }

    @Test
    fun `Composed service accepts a wager for a non-system tenant and posts the ledger`() {
        val startingBalance = 50000L
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC008-COMP-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, startingBalance, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, startingBalance, currency),
                ),
                idempotencyKey = "IDEM-TC008-COMP-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc008-comp-seed",
                causationId = "caus-tc008-comp-seed",
            )
        )

        val roundId = "rnd-tc008-composition"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal("1.0000"),
            )
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = "salt-$roundId",
            )
        )

        val ack = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc008-composition",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 60L,
                currency = currency,
                correlationId = "corr-tc008-composition",
            )
        )

        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status, "Composed service must accept a wager for a non-system tenant")
        assertEquals(startingBalance - 60L, ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertTrue(
            applicationContext.getBeanNamesForType(AviatorGameRestController::class.java).isEmpty(),
            "Aviator controller must require both the wager service and the snapshot service",
        )
    }
}
