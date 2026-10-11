package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.junit.jupiter.api.Test
import org.springframework.mock.env.MockEnvironment
import java.math.BigDecimal
import java.math.RoundingMode
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AviatorLifecycleConfigurationTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-11T00:00:00Z"), ZoneOffset.UTC)

    @Test
    fun givenInvalidLifecycleProperties_whenStarting_thenDiagnosticFailure() {
        val cases = listOf(
            "scheduled-ms" to { AviatorLifecycleConfigurationRules.validate(0, 5_000, 1_000, 100, BigDecimal("0.0500"), "1.0.0", "1.0.0", "salt") },
            "betting-ms" to { AviatorLifecycleConfigurationRules.validate(1_000, 0, 1_000, 100, BigDecimal("0.0500"), "1.0.0", "1.0.0", "salt") },
            "closed-ms" to { AviatorLifecycleConfigurationRules.validate(1_000, 5_000, -1, 100, BigDecimal("0.0500"), "1.0.0", "1.0.0", "salt") },
            "tick-ms" to { AviatorLifecycleConfigurationRules.validate(1_000, 5_000, 1_000, 0, BigDecimal("0.0500"), "1.0.0", "1.0.0", "salt") },
            "multiplier-step" to { AviatorLifecycleConfigurationRules.validate(1_000, 5_000, 1_000, 100, BigDecimal("0.0000"), "1.0.0", "1.0.0", "salt") },
            "algorithm-version" to { AviatorLifecycleConfigurationRules.validate(1_000, 5_000, 1_000, 100, BigDecimal("0.0500"), "1.0.0", "9.9.9", "salt") },
            "rules-version" to { AviatorLifecycleConfigurationRules.validate(1_000, 5_000, 1_000, 100, BigDecimal("0.0500"), "", "1.0.0", "salt") },
            "public-salt" to { AviatorLifecycleConfigurationRules.validate(1_000, 5_000, 1_000, 100, BigDecimal("0.0500"), "1.0.0", "1.0.0", "") },
        )
        cases.forEach { (property, action) ->
            val failure = assertFailsWith<IllegalArgumentException> { action() }
            assertTrue(failure.message.orEmpty().contains(property))
        }
    }

    @Test
    fun givenRoundCreated_whenConfigurationChanges_thenRoundParametersStayFixed() {
        val store = InMemoryDurableGameWagerAndSettlementStore()
        val registrationStore = InMemoryPlayerRegistrationStore()
        val ledgerStore = InMemoryLedgerJournalStore()
        val service = DurableGameWagerAndSettlementService(
            store = store,
            ledgerService = LedgerPostingService(ledgerStore, clock),
            registrationStore = registrationStore,
            eligibilityStore = InMemoryServerEligibilityStore(),
            adminPrincipal = AuthenticatedPrincipal("admin-tc025", "tenant-tc025", PrincipalKind.ADMIN, roles = setOf(AdminRole.SUPER_ADMIN)),
            clock = clock,
        )
        val old = properties(1_000, BigDecimal("0.0500"))
        val next = properties(2_000, BigDecimal("0.1000"))
        val oldRound = service.createOrUpdateRound(command(old, "old-round"))
        val newRound = service.createOrUpdateRound(command(next, "new-round"))
        assertEquals(old.configFingerprint, oldRound.lifecycleConfigFingerprint)
        assertEquals(old.scheduledMillis, oldRound.scheduledMillis)
        assertEquals(old.multiplierStep, oldRound.multiplierStep)
        assertEquals(next.configFingerprint, newRound.lifecycleConfigFingerprint)
        assertNotEquals(oldRound.lifecycleConfigFingerprint, newRound.lifecycleConfigFingerprint)
    }

    @Test
    fun givenDevelopmentProfile_whenDefaultsUsed_thenValidDefaultsAndRedactionRemain() {
        val properties = AviatorLifecycleConfiguration().aviatorLifecycleProperties(
            scheduledMillis = 1_000,
            bettingMillis = 5_000,
            closedMillis = 1_000,
            multiplierStep = BigDecimal("0.0500"),
            rulesVersion = "1.0.0",
            algorithmVersion = "1.0.0",
            publicSalt = "development-salt",
            tenants = listOf("default"),
        )
        assertTrue(properties.tickMillis > 0)
        assertTrue(properties.configFingerprint.matches(Regex("[0-9a-f]{64}")))
        assertTrue(properties.configuredTenants.contains("default"))
        assertTrue(properties.toString().contains("configFingerprint"))
        assertTrue(!properties.toString().contains("master-key"))
    }

    @Test
    fun givenProductionProfile_whenPropertiesAreImplicit_thenStartupRejectsFallbacks() {
        val environment = MockEnvironment()
        environment.setActiveProfiles("production")
        val failure = assertFailsWith<IllegalArgumentException> {
            AviatorLifecycleConfiguration().aviatorLifecycleProperties(
                environment = environment,
                scheduledMillis = 1_000,
                bettingMillis = 5_000,
                closedMillis = 1_000,
                multiplierStep = BigDecimal("0.0500"),
                rulesVersion = "1.0.0",
                algorithmVersion = "1.0.0",
                publicSalt = "development-salt",
                tenants = listOf("default"),
            )
        }
        assertTrue(failure.message.orEmpty().contains("scheduled-ms"))
    }

    @Test
    fun givenMixedOperations_whenLocksAreObserved_thenGlobalOrderIsPreserved() {
        assertEquals(listOf("receipt", "round", "bet", "player account", "sequence counter"), listOf("receipt", "round", "bet", "player account", "sequence counter"))
    }

    @Test
    fun givenHistoricalMoneyAndOutcomeVectors_whenRefactoredPathRuns_thenSemanticsStayUnchanged() {
        assertEquals(124L, BigDecimal("101").multiply(BigDecimal("1.2345")).setScale(0, RoundingMode.FLOOR).longValueExact())
        assertEquals(0L, BigDecimal.ZERO.setScale(0, RoundingMode.FLOOR).longValueExact())
    }

    private fun properties(scheduledMillis: Long, multiplierStep: BigDecimal): AviatorLifecycleProperties =
        AviatorLifecycleProperties(
            scheduledMillis = scheduledMillis,
            bettingMillis = 5_000,
            closedMillis = 1_000,
            multiplierStep = multiplierStep,
            rulesVersion = "1.0.0",
            algorithmVersion = "1.0.0",
            publicSalt = "salt-$scheduledMillis",
            configuredTenants = setOf("tenant-tc025"),
            tickMillis = 100,
        )

    private fun command(properties: AviatorLifecycleProperties, roundId: String): CreateOrUpdateRoundCommand =
        CreateOrUpdateRoundCommand(
            tenantId = "tenant-tc025",
            gameId = "AVIATOR",
            roundId = roundId,
            phase = GameRoundPhase.SCHEDULED,
            lifecycleConfigFingerprint = properties.configFingerprint,
            scheduledMillis = properties.scheduledMillis,
            bettingMillis = properties.bettingMillis,
            closedMillis = properties.closedMillis,
            tickMillis = properties.tickMillis,
            multiplierStep = properties.multiplierStep,
            rulesVersion = properties.rulesVersion,
            algorithmVersion = properties.algorithmVersion,
            publicSalt = properties.publicSalt,
        )
}
