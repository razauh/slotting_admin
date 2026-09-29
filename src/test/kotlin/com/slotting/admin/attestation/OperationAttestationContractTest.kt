package com.slotting.admin.attestation

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors

/**
 * TC-033: Operation-Bound Attestation and Replay Protection Contract Test Suite.
 *
 * Verifies provider-independent security invariants:
 * - One-time cryptographically secure challenges bound to tenant, user, session, and operation
 * - Strict 5-minute TTL and single-use consumption (atomic CAS)
 * - Durable replay resistance surviving backend restarts and cache loss
 * - Session, operation, user, tenant, and package identity enforcement (resolving XREP-004)
 * - Clock skew, malformed payload, and rate abuse guardrails
 * - Production composition rejection of test-only fake verifiers
 * - Provider-independent baseline policy when no external hardware attestation provider is bound
 */
class OperationAttestationContractTest {

    private lateinit var clock: MutableClock
    private lateinit var challengeStore: InMemoryOperationChallengeStore
    private lateinit var appConfig: AttestationAppIdentityConfig
    private lateinit var verifier: OperationAttestationVerifier
    private lateinit var service: OperationAttestationService

    private val tenantId = "tenant-tc033"
    private val userId = "player-auth-1"
    private val sessionId = "sess-login-99"
    private val baseNow = Instant.parse("2026-09-26T12:00:00Z")

    @BeforeEach
    fun setUp() {
        clock = MutableClock(baseNow)
        challengeStore = InMemoryOperationChallengeStore()
        appConfig = AttestationAppIdentityConfig(
            expectedPackageName = "com.slotting.game.connected", // XREP-004 fix
            allowedSignerDigests = setOf("sha256:release-signer-digest-2026"),
            requireSignerVerification = true,
        )
        verifier = ProviderIndependentAttestationVerifier()
        service = OperationAttestationService(
            challengeStore = challengeStore,
            appIdentityConfig = appConfig,
            verifier = verifier,
            clock = clock,
            isProduction = false,
        )
    }

    // -------------------------------------------------------------
    // Scenario 1: Normal First-Use Flow
    // -------------------------------------------------------------
    @Test
    fun `Scenario 1 - normal first-use flow issues challenge and successfully verifies operation`() {
        // 1. Client requests challenge for WAGER operation
        val challenge = service.issueChallenge(
            tenantId = tenantId,
            userId = userId,
            sessionId = sessionId,
            operation = ProtectedOperation.WAGER,
        )

        assertNotNull(challenge.challengeId)
        assertTrue(challenge.nonceValue.isNotBlank())
        assertEquals(tenantId, challenge.tenantId)
        assertEquals(userId, challenge.userId)
        assertEquals(sessionId, challenge.sessionId)
        assertEquals(ProtectedOperation.WAGER, challenge.operation)
        assertFalse(challenge.consumed)
        assertEquals(Duration.ofMinutes(5).seconds, Duration.between(challenge.issuedAt, challenge.expiresAt).seconds)

        // 2. Client submits attestation payload bound to the challenge
        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow.plusSeconds(2),
        )

        val result = service.verifyOperationAttestation(
            tenantId = tenantId,
            userId = userId,
            sessionId = sessionId,
            operation = ProtectedOperation.WAGER,
            payload = payload,
            operationRef = "wager-round-101",
            idempotencyKey = "idem-op-1",
            correlationId = "corr-1",
            causationId = "cause-1",
        )

        assertEquals(AttestationDecision.ALLOW, result.decision)
        assertEquals(AttestationFailureReason.CHALLENGE_VALID, result.reason)
        assertNotNull(result.evidenceReference)
        // Redaction verification: raw tokens or sensitive internals must not be in audit details
        assertFalse(result.detailsRedacted.contains("token"))

        // 3. Challenge is now marked consumed in durable store
        val storedChallenge = challengeStore.findChallenge(tenantId, challenge.nonceValue)
        assertNotNull(storedChallenge)
        assertTrue(storedChallenge!!.consumed)
        assertEquals("wager-round-101", storedChallenge.consumedByOperationRef)
    }

    // -------------------------------------------------------------
    // Scenario 2: Token / Challenge Replay
    // -------------------------------------------------------------
    @Test
    fun `Scenario 2 - challenge replay is rejected, one challenge cannot authorize two operations`() {
        val challenge = service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.WITHDRAWAL)

        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow,
        )

        // First use: ALLOW
        val firstResult = service.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.WITHDRAWAL,
            payload, "withdraw-req-1", "idem-first", "c-1", "cause-1"
        )
        assertEquals(AttestationDecision.ALLOW, firstResult.decision)

        // Second use with different operationRef / new attempt: REJECTED with REPLAY_DETECTED
        val replayedResult = service.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.WITHDRAWAL,
            payload, "withdraw-req-2", "idem-second", "c-2", "cause-2"
        )
        assertEquals(AttestationDecision.DENY, replayedResult.decision)
        assertEquals(AttestationFailureReason.CHALLENGE_ALREADY_CONSUMED, replayedResult.reason)
    }

    // -------------------------------------------------------------
    // Scenario 3: Expired Challenge
    // -------------------------------------------------------------
    @Test
    fun `Scenario 3 - challenge is invalid after expiry TTL`() {
        val challenge = service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.DEPOSIT)

        // Advance clock past 5-minute TTL (301 seconds)
        clock.advance(Duration.ofSeconds(301))

        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = clock.instant(),
        )

        val result = service.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.DEPOSIT,
            payload, "deposit-intent-1", "idem-exp", "c-exp", "cause-exp"
        )
        assertEquals(AttestationDecision.DENY, result.decision)
        assertEquals(AttestationFailureReason.CHALLENGE_EXPIRED, result.reason)
    }

    // -------------------------------------------------------------
    // Scenario 4: Clock Skew
    // -------------------------------------------------------------
    @Test
    fun `Scenario 4 - client clock skew beyond tolerance is rejected`() {
        val challenge = service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.WAGER)

        // Client timestamp is skewed by 10 minutes into the future
        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow.plusSeconds(600),
        )

        val result = service.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.WAGER,
            payload, "wager-skew", "idem-skew", "c-skew", "cause-skew"
        )
        assertEquals(AttestationDecision.DENY, result.decision)
        assertEquals(AttestationFailureReason.CLOCK_SKEW_EXCESSIVE, result.reason)
    }

    // -------------------------------------------------------------
    // Scenario 5: Session Change
    // -------------------------------------------------------------
    @Test
    fun `Scenario 5 - challenge issued for session A cannot be used in session B`() {
        val challenge = service.issueChallenge(tenantId, userId, "session-A", ProtectedOperation.WAGER)

        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow,
        )

        // Attempt verification under session-B
        val result = service.verifyOperationAttestation(
            tenantId, userId, "session-B", ProtectedOperation.WAGER,
            payload, "wager-sess", "idem-sess", "c-sess", "cause-sess"
        )
        assertEquals(AttestationDecision.DENY, result.decision)
        assertEquals(AttestationFailureReason.SESSION_MISMATCH, result.reason)
    }

    // -------------------------------------------------------------
    // Scenario 6: User and Tenant Mismatch
    // -------------------------------------------------------------
    @Test
    fun `Scenario 6 - challenge cannot be cross-claimed by another user or tenant`() {
        val challenge = service.issueChallenge(tenantId, "user-victim", sessionId, ProtectedOperation.WITHDRAWAL)

        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow,
        )

        // Different user attempt
        val userMismatch = service.verifyOperationAttestation(
            tenantId, "user-attacker", sessionId, ProtectedOperation.WITHDRAWAL,
            payload, "withdraw-user-mis", "idem-u", "c-u", "cause-u"
        )
        assertEquals(AttestationDecision.DENY, userMismatch.decision)
        assertEquals(AttestationFailureReason.USER_MISMATCH, userMismatch.reason)

        // Different tenant attempt
        val tenantMismatch = service.verifyOperationAttestation(
            "foreign-tenant", "user-victim", sessionId, ProtectedOperation.WITHDRAWAL,
            payload, "withdraw-t-mis", "idem-t", "c-t", "cause-t"
        )
        assertEquals(AttestationDecision.DENY, tenantMismatch.decision)
        assertEquals(AttestationFailureReason.TENANT_MISMATCH, tenantMismatch.reason)
    }

    // -------------------------------------------------------------
    // Scenario 7: Operation Mismatch
    // -------------------------------------------------------------
    @Test
    fun `Scenario 7 - challenge issued for WAGER cannot authorize WITHDRAWAL`() {
        val challenge = service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.WAGER)

        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow,
        )

        val result = service.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.WITHDRAWAL,
            payload, "withdraw-hijack", "idem-op-mis", "c-op", "cause-op"
        )
        assertEquals(AttestationDecision.DENY, result.decision)
        assertEquals(AttestationFailureReason.OPERATION_MISMATCH, result.reason)
    }

    // -------------------------------------------------------------
    // Scenario 8: Malformed Request / Payload
    // -------------------------------------------------------------
    @Test
    fun `Scenario 8 - blank or malformed nonce is rejected`() {
        val payload = OperationAttestationPayload(
            nonceValue = "   ",
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow,
        )

        val result = service.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.WAGER,
            payload, "wager-malformed", "idem-malformed", "c-mal", "cause-mal"
        )
        assertEquals(AttestationDecision.DENY, result.decision)
        assertEquals(AttestationFailureReason.MALFORMED_PAYLOAD, result.reason)
    }

    // -------------------------------------------------------------
    // Scenario 9: Backend Restart and Durable Replay Persistence
    // -------------------------------------------------------------
    @Test
    fun `Scenario 9 - backend restart preserves consumed nonces, consumed challenge remains unusable`() {
        val challenge = service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.WAGER)

        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow,
        )

        // Consume before restart
        val res1 = service.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.WAGER,
            payload, "wager-pre-restart", "idem-pre", "c-pre", "cause-pre"
        )
        assertEquals(AttestationDecision.ALLOW, res1.decision)

        // Simulate backend service restart by instantiating new service instance with same durable store
        val restartedService = OperationAttestationService(
            challengeStore = challengeStore,
            appIdentityConfig = appConfig,
            verifier = verifier,
            clock = clock,
            isProduction = false,
        )

        // Attempt to replay consumed challenge against restarted backend
        val res2 = restartedService.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.WAGER,
            payload, "wager-post-restart", "idem-post", "c-post", "cause-post"
        )
        assertEquals(AttestationDecision.DENY, res2.decision)
        assertEquals(AttestationFailureReason.CHALLENGE_ALREADY_CONSUMED, res2.reason)
    }

    // -------------------------------------------------------------
    // Scenario 10: Package Identity Mismatch (Fixes XREP-004)
    // -------------------------------------------------------------
    @Test
    fun `Scenario 10 - package mismatch rejects legacy com slotting game and requires com slotting game connected`() {
        val challenge = service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.NEW_GAME_SESSION)

        // Legacy / incorrect package name: com.slotting.game
        val legacyPayload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow,
        )

        val legacyResult = service.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.NEW_GAME_SESSION,
            legacyPayload, "session-launch-1", "idem-legacy", "c-leg", "cause-leg"
        )
        assertEquals(AttestationDecision.DENY, legacyResult.decision)
        assertEquals(AttestationFailureReason.PACKAGE_MISMATCH, legacyResult.reason)
    }

    // -------------------------------------------------------------
    // Scenario 11: Release Signing Mismatch
    // -------------------------------------------------------------
    @Test
    fun `Scenario 11 - unknown or unapproved signer digest is rejected`() {
        val challenge = service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.WAGER)

        val forgedSignerPayload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:unauthorized-tampered-signer",
            clientTimestamp = baseNow,
        )

        val result = service.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.WAGER,
            forgedSignerPayload, "wager-tamper", "idem-tamper", "c-tamp", "cause-tamp"
        )
        assertEquals(AttestationDecision.DENY, result.decision)
        assertEquals(AttestationFailureReason.SIGNER_DIGEST_MISMATCH, result.reason)
    }

    // -------------------------------------------------------------
    // Scenario 12: Rate Abuse Guardrail
    // -------------------------------------------------------------
    @Test
    fun `Scenario 12 - rapid challenge generation is rate-limited`() {
        // Issue up to limit (e.g. 5 active unconsumed challenges per user)
        for (i in 1..5) {
            val c = service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.WAGER)
            assertNotNull(c)
        }

        // 6th challenge request exceeds active limit
        val ex = assertThrows(IllegalStateException::class.java) {
            service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.WAGER)
        }
        assertTrue(ex.message!!.contains("Rate limit exceeded"))
    }

    // -------------------------------------------------------------
    // Scenario 13: Concurrent Reuse of Same Challenge
    // -------------------------------------------------------------
    @Test
    fun `Scenario 13 - concurrent race on same challenge grants exactly one success and denies others`() {
        val challenge = service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.WAGER)

        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow,
        )

        val threadCount = 6
        val pool = Executors.newFixedThreadPool(threadCount)
        val startGate = CountDownLatch(1)
        val finishGate = CountDownLatch(threadCount)
        val successes = ConcurrentLinkedQueue<AttestationVerificationResult>()
        val denials = ConcurrentLinkedQueue<AttestationVerificationResult>()

        for (i in 1..threadCount) {
            pool.submit {
                try {
                    startGate.await()
                    val res = service.verifyOperationAttestation(
                        tenantId = tenantId,
                        userId = userId,
                        sessionId = sessionId,
                        operation = ProtectedOperation.WAGER,
                        payload = payload,
                        operationRef = "wager-race-$i",
                        idempotencyKey = "idem-race-$i",
                        correlationId = "c-race-$i",
                        causationId = "cause-race-$i",
                    )
                    if (res.decision == AttestationDecision.ALLOW) {
                        successes.add(res)
                    } else {
                        denials.add(res)
                    }
                } finally {
                    finishGate.countDown()
                }
            }
        }

        startGate.countDown()
        finishGate.await()
        pool.shutdown()

        assertEquals(1, successes.size, "Exactly one concurrent thread can consume the challenge")
        assertEquals(threadCount - 1, denials.size, "All other concurrent attempts must be denied")
        assertTrue(denials.all { it.reason == AttestationFailureReason.CHALLENGE_ALREADY_CONSUMED })
    }

    // -------------------------------------------------------------
    // Scenario 14: Production Composition Rejects Test-Only Fake Verifiers
    // -------------------------------------------------------------
    @Test
    fun `Scenario 14 - production composition rejects test-only fake verifiers`() {
        val insecureFakeVerifier = InsecureAlwaysAllowTestVerifier()

        val prodService = OperationAttestationService(
            challengeStore = challengeStore,
            appIdentityConfig = appConfig,
            verifier = insecureFakeVerifier,
            clock = clock,
            isProduction = true, // Production mode active!
        )

        val challenge = prodService.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.WAGER)
        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow,
        )

        val ex = assertThrows(IllegalStateException::class.java) {
            prodService.verifyOperationAttestation(
                tenantId, userId, sessionId, ProtectedOperation.WAGER,
                payload, "wager-prod-test", "idem-prod", "c-prod", "cause-prod"
            )
        }
        assertTrue(ex.message!!.contains("Unapproved test-only attestation verifier selected in production"))
    }

    // -------------------------------------------------------------
    // Scenario 15: Absence of External Attestation Provider
    // -------------------------------------------------------------
    @Test
    fun `Scenario 15 - absence of external provider operates under provider-independent policy without claiming fake Google verification`() {
        val challenge = service.issueChallenge(tenantId, userId, sessionId, ProtectedOperation.NEW_GAME_SESSION)
        val payload = OperationAttestationPayload(
            nonceValue = challenge.nonceValue,
            clientReportedPackageName = "com.slotting.game.connected",
            clientReportedSignerDigest = "sha256:release-signer-digest-2026",
            clientTimestamp = baseNow,
            externalAttestationToken = null, // No Google Play Integrity token provided
        )

        val result = service.verifyOperationAttestation(
            tenantId, userId, sessionId, ProtectedOperation.NEW_GAME_SESSION,
            payload, "session-independent", "idem-indep", "c-indep", "cause-indep"
        )

        assertEquals(AttestationDecision.ALLOW, result.decision)
        assertEquals(AttestationFailureReason.CHALLENGE_VALID, result.reason)
        // Must never fabricate Google Play Integrity verdict claims
        assertFalse(result.detailsRedacted.contains("MEETS_DEVICE_INTEGRITY"))
        assertFalse(result.detailsRedacted.contains("GOOGLE_PLAY"))
    }
}

/** Simple mutable clock helper for deterministic time shifting */
class MutableClock(private var currentInstant: Instant) : Clock() {
    override fun getZone(): ZoneOffset = ZoneOffset.UTC
    override fun withZone(zone: java.time.ZoneId?): Clock = this
    override fun instant(): Instant = currentInstant
    fun advance(duration: Duration) {
        currentInstant = currentInstant.plus(duration)
    }
}
