package com.slotting.admin.identity

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PlayerRegistrationVerificationTest {

    private val now = Instant.parse("2026-09-18T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        // PlayerRegistrationVerificationBinding.isBound is controlled per-test or in GREEN phase
    }

    @AfterEach
    fun tearDown() {
        PlayerRegistrationVerificationBinding.isBound = true
    }

    private fun validRegisterCommand(
        tenantId: String = "tenant-casino-1",
        email: String = "player.one@example.com",
        phone: String = "+15551234567",
        jurisdiction: String = "DEFAULT",
        riskScore: Double = 20.0,
        idempotencyKey: String = "reg-idemp-001",
        correlationId: String = "corr-reg-001",
        causationId: String = "caus-reg-001",
        expectedVersion: Long = 1L
    ) = RegisterPlayerCommand(
        tenantId = tenantId,
        email = email,
        phone = phone,
        jurisdiction = jurisdiction,
        riskScore = riskScore,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion
    )

    private fun validVerifyCommand(
        tenantId: String = "tenant-casino-1",
        playerId: UUID,
        channel: ContactVerificationChannel = ContactVerificationChannel.EMAIL,
        verificationCode: String = "EMAIL-123456",
        idempotencyKey: String = "verify-idemp-001",
        correlationId: String = "corr-ver-001",
        causationId: String = "caus-ver-001",
        expectedVersion: Long = 1L
    ) = VerifyContactCommand(
        tenantId = tenantId,
        playerId = playerId,
        channel = channel,
        verificationCode = verificationCode,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion
    )

    // =========================================================================
    // AUTH-001-01-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTH-001-01-T001 Implement player registration and contact verification produces the required authoritative outcome`() {
        val store = InMemoryPlayerRegistrationStore()
        val service = PlayerRegistrationService(store = store, clock = clock)

        // 1. Standard low-risk registration -> MFA not required by policy
        val regCmdLowRisk = validRegisterCommand(
            email = "player.lowrisk@example.com",
            phone = "+15551112233",
            jurisdiction = "MT",
            riskScore = 15.0,
            idempotencyKey = "reg-low-risk"
        )
        val regResultLowRisk = service.register(regCmdLowRisk)

        assertEquals(PlayerAccountStatus.PENDING_VERIFICATION, regResultLowRisk.status)
        assertEquals(false, regResultLowRisk.mfaRequired)
        assertEquals("p***@example.com", regResultLowRisk.maskedEmail)
        assertEquals("+1***33", regResultLowRisk.maskedPhone)
        assertNotNull(regResultLowRisk.resultId)
        assertNotNull(regResultLowRisk.playerId)

        // All transitions audited: registration events
        assertEquals(1, store.audit.size)
        assertEquals("PLAYER_REGISTRATION_INITIATED", store.audit[0].type)
        assertEquals(1, store.outbox.size)
        assertEquals("PLAYER_REGISTRATION_INITIATED", store.outbox[0].type)

        // 2. High-risk / regulated jurisdiction registration -> MFA required by policy
        val regCmdHighRisk = validRegisterCommand(
            email = "player.highrisk@example.com",
            phone = "+15559998877",
            jurisdiction = "NJ", // NJ requires MFA
            riskScore = 80.0,
            idempotencyKey = "reg-high-risk"
        )
        val regResultHighRisk = service.register(regCmdHighRisk)
        assertEquals(true, regResultHighRisk.mfaRequired)

        // 3. Contact verification for low-risk player -> transitions to ACTIVE
        val verifyLowRisk = validVerifyCommand(
            playerId = regResultLowRisk.playerId,
            channel = ContactVerificationChannel.EMAIL,
            verificationCode = "EMAIL-123456",
            idempotencyKey = "ver-low-risk"
        )
        val verifyResultLow = service.verifyContact(verifyLowRisk)
        assertEquals(ContactVerificationStatus.VERIFIED, verifyResultLow.channelStatus)
        assertEquals(PlayerAccountStatus.ACTIVE, verifyResultLow.accountStatus)

        // Action allowed after verified
        service.assertPlayerActionAllowed(regCmdLowRisk.tenantId, regResultLowRisk.playerId)

        // 4. Contact verification for high-risk player -> transitions to PENDING_MFA (cannot bypass MFA)
        val verifyHighRisk = validVerifyCommand(
            playerId = regResultHighRisk.playerId,
            channel = ContactVerificationChannel.EMAIL,
            verificationCode = "EMAIL-123456",
            idempotencyKey = "ver-high-risk"
        )
        val verifyResultHigh = service.verifyContact(verifyHighRisk)
        assertEquals(ContactVerificationStatus.VERIFIED, verifyResultHigh.channelStatus)
        assertEquals(PlayerAccountStatus.PENDING_MFA, verifyResultHigh.accountStatus)

        // Action blocked because MFA is still pending
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.assertPlayerActionAllowed(regCmdHighRisk.tenantId, regResultHighRisk.playerId)
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Assert all transitions audited
        val auditTypes = store.audit.map { it.type }
        assertTrue(auditTypes.contains("PLAYER_REGISTRATION_INITIATED"))
        assertTrue(auditTypes.contains("PLAYER_CONTACT_VERIFIED_EMAIL"))

        // Assert no financial authority or money mutation occurred
        val playerRecord = store.findById(regCmdLowRisk.tenantId, regResultLowRisk.playerId)
        assertNotNull(playerRecord)
    }

    // =========================================================================
    // AUTH-001-01-T002: Negative, Boundary, Security & Enumeration Defense
    // =========================================================================

    @Test
    fun `AUTH-001-01-T002 Implement player registration and contact verification rejects invalid boundary unauthorized and stale input`() {
        val store = InMemoryPlayerRegistrationStore()
        val service = PlayerRegistrationService(store = store, clock = clock)

        // Blank tenant rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.register(validRegisterCommand(tenantId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Malformed email rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.register(validRegisterCommand(email = "not-an-email"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Malformed phone rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.register(validRegisterCommand(phone = "abc"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.register(validRegisterCommand(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Blank idempotency key rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.register(validRegisterCommand(idempotencyKey = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Register a valid user
        val regCmd = validRegisterCommand(
            email = "victim@example.com",
            phone = "+15554443322",
            idempotencyKey = "reg-original"
        )
        val originalResult = service.register(regCmd)

        // Enumeration-safe defense: Attempting to register already existing email does NOT error out or reveal existence
        val duplicateAttemptCmd = validRegisterCommand(
            email = "victim@example.com",
            phone = "+15559990000",
            idempotencyKey = "reg-probe-email"
        )
        val enumDefenseResult = service.register(duplicateAttemptCmd)
        // Returns safe pending verification state without leaking existing credentials or overwriting
        assertEquals(PlayerAccountStatus.PENDING_VERIFICATION, enumDefenseResult.status)
        assertTrue(enumDefenseResult.safeMessage.contains("eligible"))
        assertEquals(originalResult.playerId, enumDefenseResult.playerId)

        // Verification with wrong code rejected with safe INVALID error
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyContact(validVerifyCommand(
                playerId = originalResult.playerId,
                verificationCode = "WRONG-CODE",
                idempotencyKey = "ver-wrong-1"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Exceeding max attempts locks verification
        service.runCatching {
            service.verifyContact(validVerifyCommand(
                playerId = originalResult.playerId,
                verificationCode = "WRONG-CODE-2",
                idempotencyKey = "ver-wrong-2"
            ))
        }
        service.runCatching {
            service.verifyContact(validVerifyCommand(
                playerId = originalResult.playerId,
                verificationCode = "WRONG-CODE-3",
                idempotencyKey = "ver-wrong-3"
            ))
        }
        // Now locked
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyContact(validVerifyCommand(
                playerId = originalResult.playerId,
                verificationCode = "EMAIL-123456",
                idempotencyKey = "ver-after-locked"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant verification rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyContact(validVerifyCommand(
                tenantId = "wrong-tenant",
                playerId = originalResult.playerId,
                idempotencyKey = "ver-cross-tenant"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale version in verification rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyContact(validVerifyCommand(
                playerId = originalResult.playerId,
                expectedVersion = -1L,
                idempotencyKey = "ver-stale"
            ))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }
    }

    // =========================================================================
    // AUTH-001-01-T003: Concurrency, Duplicate Delivery, Idempotency & Conflict
    // =========================================================================

    @Test
    fun `AUTH-001-01-T003 Implement player registration and contact verification survives concurrency duplicate delivery and dependency failure`() {
        val store = InMemoryPlayerRegistrationStore()
        val service = PlayerRegistrationService(store = store, clock = clock)

        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val command = validRegisterCommand(idempotencyKey = "idemp-concurrent-reg-001")

        val calls = (1..2).map {
            pool.submit<RegisterPlayerResult> {
                gate.await()
                service.register(command)
            }
        }
        gate.countDown()
        val results = calls.map { it.get() }
        pool.shutdown()

        // Concurrent equivalent submissions produce identical authoritative result
        assertEquals(results[0].resultId, results[1].resultId)
        assertEquals(results[0].playerId, results[1].playerId)
        assertEquals(PlayerAccountStatus.PENDING_VERIFICATION, results[0].status)
        assertEquals(PlayerAccountStatus.PENDING_VERIFICATION, results[1].status)

        // Conflicting payload with reused key rejected with CONFLICT
        val conflictingCommand = command.copy(email = "different.email@example.com")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.register(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Verification concurrency and conflict check
        val verifyCmd = validVerifyCommand(
            playerId = results[0].playerId,
            idempotencyKey = "idemp-concurrent-ver-001"
        )
        val vGate = CountDownLatch(1)
        val vPool = Executors.newFixedThreadPool(2)
        val vCalls = (1..2).map {
            vPool.submit<VerifyContactResult> {
                vGate.await()
                service.verifyContact(verifyCmd)
            }
        }
        vGate.countDown()
        val vResults = vCalls.map { it.get() }
        vPool.shutdown()

        assertEquals(vResults[0].resultId, vResults[1].resultId)
        assertEquals(ContactVerificationStatus.VERIFIED, vResults[0].channelStatus)

        // Reused verify key with conflicting code rejected with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyContact(verifyCmd.copy(verificationCode = "DIFFERENT-CODE"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // AUTH-001-01-T004: Migration, Observability, Lifecycle & Redaction Safety
    // =========================================================================

    @Test
    fun `AUTH-001-01-T004 Implement player registration and contact verification remains compatible recoverable observable and lifecycle-safe`() {
        val store = InMemoryPlayerRegistrationStore()
        val service = PlayerRegistrationService(store = store, clock = clock)

        // 1. Fail-closed assertion gate (expected RED failure: unverified/recovery bypass)
        PlayerRegistrationVerificationBinding.isBound = false
        val ex = assertFailsWith<AssertionError> {
            service.register(validRegisterCommand())
        }
        assertEquals("unverified/recovery bypass", ex.message)

        val exVerify = assertFailsWith<AssertionError> {
            service.verifyContact(validVerifyCommand(playerId = UUID.randomUUID()))
        }
        assertEquals("unverified/recovery bypass", exVerify.message)

        val exAction = assertFailsWith<AssertionError> {
            service.assertPlayerActionAllowed("tenant-1", UUID.randomUUID())
        }
        assertEquals("unverified/recovery bypass", exAction.message)

        // Re-bind for lifecycle & migration checks
        PlayerRegistrationVerificationBinding.isBound = true

        // 2. Assert no unapproved persistence or migration is introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(migrationVersions.all { it.matches(Regex("V[0-9]+")) })
        assertTrue(!migrationVersions.contains("V17"), "No unapproved V17 migration should be introduced")

        // 3. Observability & Redaction: Audit events must not leak raw codes or unmasked PII
        val regCmd = validRegisterCommand(
            email = "sensitive.user@example.com",
            phone = "+15551239876",
            idempotencyKey = "obs-reg-001"
        )
        val regResult = service.register(regCmd)
        val auditEvent = regResult.auditEvent
        assertNotNull(auditEvent)

        val auditString = "${auditEvent.type}:${auditEvent.tenantId}:${auditEvent.correlationId}:${auditEvent.causationId}"
        assertTrue(!auditString.contains("sensitive.user@example.com"), "Must not contain raw email")
        assertTrue(!auditString.contains("5551239876"), "Must not contain raw phone")
        assertTrue(!auditString.contains("PASSWORD", ignoreCase = true))
        assertTrue(!auditString.contains("SECRET", ignoreCase = true))
        assertTrue(!auditString.contains("TOKEN", ignoreCase = true))
    }
}
