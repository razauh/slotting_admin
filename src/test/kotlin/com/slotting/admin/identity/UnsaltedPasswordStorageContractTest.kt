package com.slotting.admin.identity

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PasswordKdfService
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class UnsaltedPasswordStorageContractTest {
    private val phoneSequence = AtomicInteger()
    private val clock = Clock.fixed(Instant.parse("2026-10-12T00:00:00Z"), ZoneOffset.UTC)

    private fun command(email: String, password: String) = RegisterPlayerCommand(
        tenantId = "tc09-tenant",
        email = email,
        phone = "+1555123${phoneSequence.incrementAndGet().toString().padStart(7, '0')}",
        jurisdiction = "DEFAULT",
        rawPassword = password,
        idempotencyKey = UUID.randomUUID().toString(),
        correlationId = UUID.randomUUID().toString(),
        causationId = UUID.randomUUID().toString(),
    )

    @Test
    fun blankPasswordRegistrationIsRejected() {
        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            PlayerRegistrationService(InMemoryPlayerRegistrationStore(), clock = clock)
                .register(command("blank@example.com", "  "))
        }
        assertEquals(AuthErrorCode.INVALID, failure.code)
    }

    @Test
    fun samePasswordProducesDistinctPepperedKdfVerifiers() {
        val store = InMemoryPlayerRegistrationStore()
        val service = PlayerRegistrationService(store, clock = clock)
        service.register(command("one@example.com", "StrongUniquePass934!"))
        service.register(command("two@example.com", "StrongUniquePass934!"))
        val records = store.players.values.toList()
        assertEquals(2, records.size)
        assertNotEquals(records[0].passwordHash, records[1].passwordHash)
        assertNotEquals(records[0].passwordSalt, records[1].passwordSalt)
        assertTrue(records.all { it.passwordAlgo == PasswordKdfService.PEPPERED_PBKDF2_ALGO })
        assertTrue(records.all { it.passwordIterations >= PasswordKdfService.DEFAULT_ITERATIONS })
    }

    @Test
    fun legacySha256VerifierIsMarkedForRehashAfterSuccessfulVerification() {
        val legacy = java.security.MessageDigest.getInstance("SHA-256")
            .digest("LegacyPassword934!".toByteArray())
            .joinToString("") { "%02x".format(it) }
        val verified = PasswordKdfService.verifyPassword(
            "LegacyPassword934!",
            legacy,
            "",
            0,
            PasswordKdfService.LEGACY_SHA256_ALGO,
        )
        assertTrue(verified.valid)
        assertTrue(verified.needsRehash)
    }

    @Test
    fun registrationCodesUseIndependentSaltedDigests() {
        val store = InMemoryPlayerRegistrationStore()
        val service = PlayerRegistrationService(store, clock = clock)
        val first = service.register(command("codes-one@example.com", "StrongUniquePass934!"))
        val second = service.register(command("codes-two@example.com", "StrongUniquePass934!"))
        val firstCodes = store.verificationCodes.values.filter { it.playerId == first.playerId }
        val secondCodes = store.verificationCodes.values.filter { it.playerId == second.playerId }
        assertEquals(2, firstCodes.size)
        assertEquals(2, secondCodes.size)
        assertTrue((firstCodes + secondCodes).all { it.salt.isNotBlank() })
        assertEquals(4, (firstCodes + secondCodes).map { it.codeHash }.toSet().size)
        assertTrue((firstCodes + secondCodes).all { it.expiresAt == clock.instant().plusSeconds(900) })
    }
}
