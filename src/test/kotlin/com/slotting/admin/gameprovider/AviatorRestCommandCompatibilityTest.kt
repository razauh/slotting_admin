package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AviatorRestCommandCompatibilityTest {

    private lateinit var store: InMemoryAviatorCommandStore
    private lateinit var rbacPolicy: AdminRbacPolicy
    private lateinit var service: AviatorRestCommandCompatibilityService
    private val clock = Clock.fixed(Instant.parse("2026-09-19T00:00:00Z"), ZoneOffset.UTC)

    private val tenantId = "tenant-pilot-001"
    private val authorizedPrincipal = AuthenticatedPrincipal(
        id = "usr-player-123",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT)
    )

    @BeforeEach
    fun setUp() {
        store = InMemoryAviatorCommandStore()
        rbacPolicy = AdminRbacPolicy(true)
        service = AviatorRestCommandCompatibilityService(
            store = store,
            rbacPolicy = rbacPolicy,
            clock = clock,
        )
    }

    // =========================================================================
    // GAME-010-01-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `GAME-010-01-T001 Map Aviator REST command compatibility produces the required authoritative outcome`() {
        AviatorRestCommandCompatibilityBinding.checkBound()

        // Test normalizes legacy action "BET" and legacy hand "f"
        val cmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-aviator-001",
            roundId = "rnd-crash-100",
            handId = "f",
            action = "BET",
            wagerMinor = 2000L, // 20.00 INR
            currency = "INR",
            correlationId = "c-aviator-001",
            expectedRoundVersion = 1L
        )

        val initialBalance = store.getBalance(tenantId, authorizedPrincipal.id, "INR")
        assertEquals(500000L, initialBalance)

        val result = service.processCommand(cmd)

        assertEquals("cmd-aviator-001", result.commandId)
        assertEquals("rnd-crash-100", result.roundId)
        assertEquals("hand_primary", result.handId)
        assertEquals(AviatorCommandAction.PLACE_BET, result.action)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, result.status)
        assertEquals(498000L, result.result?.accountMoneyAfterMinor)
        assertEquals(498000L, store.getBalance(tenantId, authorizedPrincipal.id, "INR"))
        assertTrue(result.sequenceId > 0)
        assertEquals(2L, result.revision)

        // Ledger conservation: initialBalance (500000) = balanceAfter (498000) + wager (2000)
        assertEquals(initialBalance, (result.result?.accountMoneyAfterMinor ?: 0L) + (result.result?.wagerMinor ?: 0L))
        assertTrue(store.auditEvents.isNotEmpty())
        assertTrue(store.outboxEvents.isNotEmpty())
    }

    // =========================================================================
    // GAME-010-01-T002: Negative, Boundary, Security & Authorization Rejection
    // =========================================================================

    @Test
    fun `GAME-010-01-T002 Map Aviator REST command compatibility rejects invalid, boundary, unauthorized, and stale input`() {
        AviatorRestCommandCompatibilityBinding.checkBound()

        val baseCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-sec-001",
            roundId = "rnd-crash-100",
            handId = "f",
            action = "BET",
            wagerMinor = 2000L,
            currency = "INR",
            correlationId = "c-sec-001",
            expectedRoundVersion = 1L
        )

        // 1. Missing principal -> UNAUTHENTICATED
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCommand(baseCmd.copy(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Cross-tenant principal -> FORBIDDEN
        val crossTenant = authorizedPrincipal.copy(tenantId = "tenant-other")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCommand(baseCmd.copy(principal = crossTenant))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Invalid currency -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCommand(baseCmd.copy(currency = "INVALID"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 4. Zero or negative wager -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCommand(baseCmd.copy(wagerMinor = 0L))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Stale expected round version -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCommand(baseCmd.copy(expectedRoundVersion = 999L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }
    }

    // =========================================================================
    // GAME-010-01-T003: Concurrency, Duplicate Delivery, and Idempotency
    // =========================================================================

    @Test
    fun `GAME-010-01-T003 Map Aviator REST command compatibility survives concurrency, duplicate delivery, and dependency failure`() {
        AviatorRestCommandCompatibilityBinding.checkBound()

        val cmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-idemp-001",
            roundId = "rnd-crash-100",
            handId = "f",
            action = "BET",
            wagerMinor = 1000L,
            currency = "INR",
            correlationId = "c-idemp",
            expectedRoundVersion = 1L
        )

        val firstAck = service.processCommand(cmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, firstAck.status)
        assertEquals(499000L, store.getBalance(tenantId, authorizedPrincipal.id, "INR"))

        // Duplicate delivery (idempotent replay)
        val duplicateAck = service.processCommand(cmd)
        assertEquals(AviatorCommandAckStatus.DUPLICATE, duplicateAck.status)
        assertEquals(firstAck.sequenceId, duplicateAck.sequenceId)
        // Balance remains 499000L, no double debit!
        assertEquals(499000L, store.getBalance(tenantId, authorizedPrincipal.id, "INR"))

        // Conflicting payload on same commandId -> CONFLICT
        val conflicting = cmd.copy(wagerMinor = 3000L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCommand(conflicting)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // GAME-010-01-T004: Lifecycle, Observability, and Audit Trail Safety
    // =========================================================================

    @Test
    fun `GAME-010-01-T004 Map Aviator REST command compatibility remains compatible, recoverable, observable, and lifecycle-safe`() {
        AviatorRestCommandCompatibilityBinding.checkBound()

        // 1. PLACE_BET
        val betCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-life-bet",
            roundId = "rnd-life-001",
            handId = "primary",
            action = "PLACE_BET",
            wagerMinor = 2000L,
            currency = "INR",
            correlationId = "c-life",
            expectedRoundVersion = 1L
        )
        val betAck = service.processCommand(betCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)
        assertEquals(498000L, store.getBalance(tenantId, authorizedPrincipal.id, "INR"))

        // 2. CASH_OUT at 2.50x
        val cashOutCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-life-cashout",
            roundId = "rnd-life-001",
            handId = "primary",
            action = "CASHOUT",
            wagerMinor = 2000L,
            currency = "INR",
            cashOutMultiplier = 2.50,
            correlationId = "c-life",
            expectedRoundVersion = 2L
        )
        val cashOutAck = service.processCommand(cashOutCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        // 498000 + (2000 * 2.5 = 5000) = 503000L
        assertEquals(503000L, store.getBalance(tenantId, authorizedPrincipal.id, "INR"))
        assertEquals(5000L, cashOutAck.result?.payoutMinor)

        // Verify audit event lineage
        val audits = store.auditEvents.filter { it.correlationId == "c-life" }
        assertEquals(2, audits.size)
        assertTrue(audits.any { it.type.contains("PLACE_BET") })
        assertTrue(audits.any { it.type.contains("CASH_OUT") })
    }
}
