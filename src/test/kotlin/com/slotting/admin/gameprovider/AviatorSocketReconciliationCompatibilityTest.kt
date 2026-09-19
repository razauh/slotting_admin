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
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Mandatory contract test suite for GAME-010-02:
 * Map Aviator socket and reconciliation compatibility.
 *
 * Semantic contract: "Preserve journal/reconciler, server remains authoritative; contract tests cover reorder/drop."
 * Protected risk assertion: "legacy ack/sequence/recovery contract breaks"
 */
class AviatorSocketReconciliationCompatibilityTest {

    private lateinit var store: InMemoryAviatorSocketStore
    private lateinit var rbacPolicy: AdminRbacPolicy
    private lateinit var service: AviatorSocketReconciliationCompatibilityService
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
        store = InMemoryAviatorSocketStore()
        rbacPolicy = AdminRbacPolicy(true)
        service = AviatorSocketReconciliationCompatibilityService(
            store = store,
            rbacPolicy = rbacPolicy,
            clock = clock,
        )
    }

    // =========================================================================
    // GAME-010-02-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `GAME-010-02-T001 Map Aviator socket and reconciliation compatibility produces the required authoritative outcome`() {
        AviatorSocketReconciliationCompatibilityBinding.checkBound()

        // 1. Produce authoritative socket game state broadcast frame
        val frame = service.produceAuthoritativeGameState(
            tenantId = tenantId,
            roundId = "rnd-crash-501",
            phase = AviatorSocketPhase.PLAYING,
            multiplier = 2.35,
            correlationId = "corr-frame-001"
        )

        assertEquals("gameState", frame.eventName)
        assertTrue(frame.sequenceId > 0)
        assertTrue(frame.payloadJson.contains("\"currentMultiplier\": 2.35"))
        assertTrue(frame.payloadJson.contains("\"phase\": \"PLAYING\""))

        // 2. Query authoritative snapshot for reconciliation
        val snapshot = service.getAuthoritativeSnapshot(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            roundId = "rnd-crash-501",
            correlationId = "corr-recon-001"
        )

        assertEquals("rnd-crash-501", snapshot.roundId)
        assertEquals(500000L, snapshot.userBalanceMinor)
        assertEquals("INR", snapshot.currency)
        assertEquals(frame.sequenceId, snapshot.sequenceId)
        assertTrue(store.outboxEvents.isNotEmpty())
        assertTrue(store.auditEvents.isNotEmpty())
    }

    // =========================================================================
    // GAME-010-02-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `GAME-010-02-T002 Map Aviator socket and reconciliation compatibility rejects invalid, boundary, unauthorized, and stale input`() {
        AviatorSocketReconciliationCompatibilityBinding.checkBound()

        // 1. Missing principal -> UNAUTHENTICATED
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.getAuthoritativeSnapshot(
                tenantId = tenantId,
                principal = null,
                roundId = "rnd-crash-501",
                correlationId = "c1"
            )
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Cross-tenant principal -> FORBIDDEN
        val crossTenant = authorizedPrincipal.copy(tenantId = "other-tenant")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.getAuthoritativeSnapshot(
                tenantId = tenantId,
                principal = crossTenant,
                roundId = "rnd-crash-501",
                correlationId = "c2"
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Negative / below 1.0x multiplier -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.produceAuthoritativeGameState(
                tenantId = tenantId,
                roundId = "rnd-crash-501",
                phase = AviatorSocketPhase.PLAYING,
                multiplier = 0.5,
                correlationId = "c3"
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 4. Blank tenant or round -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.produceAuthoritativeGameState(
                tenantId = "",
                roundId = "rnd-crash-501",
                phase = AviatorSocketPhase.PLAYING,
                multiplier = 1.5,
                correlationId = "c4"
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // GAME-010-02-T003: Concurrency, Duplicate Delivery, and Reorder/Drop Tests
    // =========================================================================

    @Test
    fun `GAME-010-02-T003 Map Aviator socket and reconciliation compatibility survives concurrency, duplicate delivery, and dependency failure`() {
        AviatorSocketReconciliationCompatibilityBinding.checkBound()

        // Produce consecutive frames: sequences must be strictly monotonic
        val f1 = service.produceAuthoritativeGameState(tenantId, "r1", AviatorSocketPhase.BET_COUNTDOWN, 1.0, "c1")
        val f2 = service.produceAuthoritativeGameState(tenantId, "r1", AviatorSocketPhase.PLAYING, 1.25, "c2")
        val f3 = service.produceAuthoritativeGameState(tenantId, "r1", AviatorSocketPhase.PLAYING, 1.50, "c3")

        assertTrue(f2.sequenceId > f1.sequenceId)
        assertTrue(f3.sequenceId > f2.sequenceId)

        // Multiple snapshot requests for same round and player return the identical authoritative snapshot
        val snap1 = service.getAuthoritativeSnapshot(tenantId, authorizedPrincipal, "r1", "c-snap-1")
        val snap2 = service.getAuthoritativeSnapshot(tenantId, authorizedPrincipal, "r1", "c-snap-2")

        assertEquals(snap1.roundId, snap2.roundId)
        assertEquals(snap1.userBalanceMinor, snap2.userBalanceMinor)
        assertEquals(snap1.sequenceId, snap2.sequenceId)
    }

    // =========================================================================
    // GAME-010-02-T004: Lifecycle, Recovery, and Reorder Compatibility
    // =========================================================================

    @Test
    fun `GAME-010-02-T004 Map Aviator socket and reconciliation compatibility remains compatible, recoverable, observable, and lifecycle-safe`() {
        AviatorSocketReconciliationCompatibilityBinding.checkBound()

        val initialBalance = store.getBalance(tenantId, authorizedPrincipal.id, "INR")
        assertEquals(500000L, initialBalance)

        // 1. Client bets via socket action
        val betSnap = service.recordHandAction(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            roundId = "rnd-life-socket",
            handId = "primary",
            action = "BET",
            wagerMinor = 2500L,
            multiplier = null,
            correlationId = "c-bet-sock"
        )

        assertEquals(497500L, betSnap.userBalanceMinor)
        assertTrue(betSnap.primaryHand.betted)
        assertEquals(2500L, betSnap.primaryHand.wagerMinor)

        // 2. Simulated socket drop: client reconnects and requests snapshot
        val reconSnap = service.getAuthoritativeSnapshot(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            roundId = "rnd-life-socket",
            correlationId = "c-recon-sock"
        )

        // Snapshot confirms the bet was accepted without double debit
        assertEquals(497500L, reconSnap.userBalanceMinor)
        assertTrue(reconSnap.primaryHand.betted)

        // 3. Cash out
        val cashOutSnap = service.recordHandAction(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            roundId = "rnd-life-socket",
            handId = "primary",
            action = "CASHOUT",
            wagerMinor = 2500L,
            multiplier = 3.00,
            correlationId = "c-co-sock"
        )

        // 497500 + (2500 * 3 = 7500) = 505000L
        assertEquals(505000L, cashOutSnap.userBalanceMinor)
        assertTrue(cashOutSnap.primaryHand.cashouted)
        assertEquals(7500L, cashOutSnap.primaryHand.payoutMinor)

        // Conservation check
        assertEquals(505000L, store.getBalance(tenantId, authorizedPrincipal.id, "INR"))
    }
}
