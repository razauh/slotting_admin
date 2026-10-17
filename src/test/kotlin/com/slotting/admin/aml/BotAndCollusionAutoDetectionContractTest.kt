package com.slotting.admin.aml

import com.slotting.admin.infra.PostgresIntegrationSupport
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class BotAndCollusionAutoDetectionContractTest {
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
    private lateinit var detectionStore: PlayAbuseDetectionStore

    private val tenantId = "tenant-play-abuse"
    private val baseTime = Instant.parse("2026-10-16T10:00:00Z")

    @BeforeEach
    fun clearData() {
        jdbc.update("delete from play_abuse_alert where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_aml_review_queue where tenant_id = ? and case_reference like 'AUTO-%'", tenantId)
        jdbc.update("delete from play_cashout_detection_event where tenant_id = ?", tenantId)
        jdbc.update("delete from player_account_link where tenant_id = ?", tenantId)
    }

    @Test
    fun machineRegularCashoutTimingRaisesBotAlert() {
        repeat(4) { index -> saveEvent("player-bot", baseTime.plusSeconds(index * 10L), "round-bot", index) }
        val alerts = detectionStore.evaluateCashOut(input("player-bot", baseTime.plusSeconds(40), "round-bot", 4))
        assertTrue(alerts.any { it.rule == PlayAbuseRule.BOT_TIMING })
        assertEquals(1, jdbc.queryForObject("select count(*) from play_abuse_alert where tenant_id = ? and rule_code = 'BOT_TIMING'", Int::class.java, tenantId))
    }

    @Test
    fun cashoutVelocityAboveCapRaisesVelocityAlertAndFlagsSession() {
        repeat(7) { index -> saveEvent("player-fast", baseTime.plusSeconds(index * 20L), "round-fast", index) }
        val alerts = detectionStore.evaluateCashOut(input("player-fast", baseTime.plusSeconds(140), "round-fast", 7))
        assertTrue(alerts.any { it.rule == PlayAbuseRule.CASHOUT_VELOCITY })
        assertTrue(jdbc.queryForObject("select session_flagged from play_abuse_alert where tenant_id = ? and player_id = ?", Boolean::class.java, tenantId, "player-fast")!!)
    }

    @Test
    fun correlatedAccountsRaiseCollusionAlertWithLinkedReferences() {
        jdbc.update("insert into player_account_link(tenant_id, player_id, linked_player_id, created_at) values (?, ?, ?, ?)", tenantId, "player-a", "player-b", baseTime)
        saveEvent("player-b", baseTime.plusSeconds(1), "round-linked", 1)
        val alerts = detectionStore.evaluateCashOut(input("player-a", baseTime.plusSeconds(2), "round-linked", 2))
        val alert = alerts.single { it.rule == PlayAbuseRule.LINKED_ACCOUNT_COLLUSION }
        assertEquals(listOf("player-b"), alert.linkedPlayerReferences)
    }

    @Test
    fun normalHumanPlayRaisesNoAlert() {
        val intervals = listOf(1L, 17L, 42L, 78L)
        intervals.forEachIndexed { index, second -> saveEvent("player-human", baseTime.plusSeconds(second), "round-human-$index", index) }
        val alerts = detectionStore.evaluateCashOut(input("player-human", baseTime.plusSeconds(139), "round-human", 4))
        assertTrue(alerts.isEmpty())
    }

    @Test
    fun repeatEvaluationDoesNotDuplicateAlert() {
        repeat(4) { index -> saveEvent("player-repeat", baseTime.plusSeconds(index * 10L), "round-repeat", index) }
        val event = input("player-repeat", baseTime.plusSeconds(40), "round-repeat", 4)
        assertTrue(detectionStore.evaluateCashOut(event).any { it.rule == PlayAbuseRule.BOT_TIMING })
        assertTrue(detectionStore.evaluateCashOut(event).none { it.rule == PlayAbuseRule.BOT_TIMING })
    }

    private fun saveEvent(playerId: String, at: Instant, roundId: String, index: Int) {
        jdbc.update(
            "insert into play_cashout_detection_event(event_id, tenant_id, player_id, game_id, round_id, hand_id, occurred_at) values (?, ?, ?, ?, ?, ?, ?)",
            UUID.randomUUID(), tenantId, playerId, "AVIATOR", roundId, "hand-$index", at
        )
    }

    private fun input(playerId: String, at: Instant, roundId: String, index: Int) = CashOutDetectionInput(
        tenantId = tenantId,
        playerId = playerId,
        gameId = "AVIATOR",
        roundId = roundId,
        handId = "hand-$index",
        eventId = UUID.randomUUID(),
        occurredAt = at
    )
}
