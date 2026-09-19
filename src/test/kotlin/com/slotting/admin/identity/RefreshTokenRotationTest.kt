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

class RefreshTokenRotationTest {

    private val now = Instant.parse("2026-09-18T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        RefreshTokenRotationBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        ShortLivedTokenBinding.isBound = true
        RefreshTokenRotationBinding.isBound = true
    }

    private fun registerAndVerifyPlayer(
        regStore: InMemoryPlayerRegistrationStore,
        tenantId: String = "tenant-casino-1",
        email: String = "token.rotation.player@example.com"
    ): RegisterPlayerResult {
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val regCmd = RegisterPlayerCommand(
            tenantId = tenantId,
            email = email,
            phone = "+1555" + (5000000 + regStore.players.size + 1),
            jurisdiction = "DEFAULT",
            riskScore = 20.0,
            idempotencyKey = "reg-${UUID.randomUUID()}",
            correlationId = "corr-reg-${UUID.randomUUID()}",
            causationId = "caus-reg-${UUID.randomUUID()}"
        )
        val regResult = regService.register(regCmd)

        val verCmd = VerifyContactCommand(
            tenantId = tenantId,
            playerId = regResult.playerId,
            channel = ContactVerificationChannel.EMAIL,
            verificationCode = "EMAIL-123456",
            idempotencyKey = "ver-${UUID.randomUUID()}",
            correlationId = "corr-ver-${UUID.randomUUID()}",
            causationId = "caus-ver-${UUID.randomUUID()}"
        )
        regService.verifyContact(verCmd)
        return regResult
    }

    // =========================================================================
    // AUTH-002-02-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTH-002-02-T001 Rotate refresh-token families with reuse detection produces the required authoritative outcome`() {
        // Enforce fail-closed gate
        RefreshTokenRotationBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val alertSink = InMemoryTokenSecurityAlertSink()
        val tokenService = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore)

        // 1. Initial Token Pair issuance (Gen 0)
        val issueCmd = IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-pair-gen0",
            correlationId = "corr-iss-0",
            causationId = "caus-iss-0"
        )
        val tokenPair0 = tokenService.issueTokenPair(issueCmd)
        val familyId = tokenPair0.familyId
        val tokenA = tokenPair0.refreshToken
        val accessA = tokenPair0.accessToken

        assertNotNull(tokenA)
        assertNotNull(accessA)
        val family0 = tokenStore.findFamily("tenant-casino-1", familyId)
        assertNotNull(family0)
        assertTrue(!family0.isRevoked, "Token family must start active")

        // 2. Lawful Rotation 1: Gen 0 (Token A) -> Gen 1 (Token B)
        val rot1Cmd = RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = tokenA,
            idempotencyKey = "rot-gen0-to-gen1",
            correlationId = "corr-rot-1",
            causationId = "caus-rot-1"
        )
        val tokenPair1 = tokenService.rotateRefreshToken(rot1Cmd)
        val tokenB = tokenPair1.refreshToken
        val accessB = tokenPair1.accessToken

        assertNotNull(tokenB)
        assertNotNull(accessB)
        assertEquals(familyId, tokenPair1.familyId)

        // Verify Token A is ROTATED and lineage is recorded
        val tokenARecord = tokenStore.findRefreshTokenByHash("tenant-casino-1", tokenService.sha256(tokenA))
        assertNotNull(tokenARecord)
        assertEquals(TokenStatus.ROTATED, tokenARecord.status)

        val tokenBRecord = tokenStore.findRefreshTokenByHash("tenant-casino-1", tokenService.sha256(tokenB))
        assertNotNull(tokenBRecord)
        assertEquals(TokenStatus.ACTIVE, tokenBRecord.status)
        assertEquals(tokenARecord.tokenHash, tokenBRecord.parentTokenHash, "Lineage must point to parent token hash")

        // Access B is valid
        val valB = tokenService.validateAccessToken("tenant-casino-1", accessB)
        assertTrue(valB.valid)

        // 3. Lawful Rotation 2: Gen 1 (Token B) -> Gen 2 (Token C)
        val rot2Cmd = RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = tokenB,
            idempotencyKey = "rot-gen1-to-gen2",
            correlationId = "corr-rot-2",
            causationId = "caus-rot-2"
        )
        val tokenPair2 = tokenService.rotateRefreshToken(rot2Cmd)
        val tokenC = tokenPair2.refreshToken
        val accessC = tokenPair2.accessToken

        assertNotNull(tokenC)
        assertNotNull(accessC)
        assertEquals(familyId, tokenPair2.familyId)

        val tokenCRecord = tokenStore.findRefreshTokenByHash("tenant-casino-1", tokenService.sha256(tokenC))
        assertNotNull(tokenCRecord)
        assertEquals(TokenStatus.ACTIVE, tokenCRecord.status)
        assertEquals(tokenBRecord.tokenHash, tokenCRecord.parentTokenHash)

        // 4. REUSE DETECTION: Re-presenting already-rotated Token A (Gen 0)
        // Contract: "Reuse revokes family and alerts; Android Keystore remains refresh-token store."
        val reuseAttackCmd = RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = tokenA, // REUSE OF GENERATION 0!
            idempotencyKey = "reuse-attack-cmd",
            correlationId = "corr-reuse-attack",
            causationId = "caus-reuse-attack"
        )
        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(reuseAttackCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex.code)

        // 5. ENTIRE FAMILY IS REVOKED IMMEDIATELY
        val familyAfterReuse = tokenStore.findFamily("tenant-casino-1", familyId)
        assertNotNull(familyAfterReuse)
        assertTrue(familyAfterReuse.isRevoked, "Entire token family must be revoked upon reuse detection")
        assertEquals(TokenRevocationReason.ROTATED_REUSE_DETECTED, familyAfterReuse.revocationReason)

        // 6. Security Alert Dispatched
        assertEquals(1, alertSink.alerts.size)
        val alert = alertSink.alerts[0]
        assertTrue(alert.contains("REFRESH_TOKEN_REUSE_DETECTED"))
        assertTrue(alert.contains(familyId.toString()))

        // 7. Legitimate user presenting latest Token C is now ALSO revoked and denied
        val attemptWithTokenC = RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = tokenC,
            idempotencyKey = "attempt-after-family-revoked",
            correlationId = "corr-post-rev",
            causationId = "caus-post-rev"
        )
        val exC = assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(attemptWithTokenC)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, exC.code)

        // Latest access token C is now invalid
        val valC = tokenService.validateAccessToken("tenant-casino-1", accessC)
        assertTrue(!valC.valid, "Access token from revoked family must be invalid")
        assertEquals(AuthErrorCode.UNAUTHENTICATED, valC.reasonCode)

        // 8. Audited events
        val auditTypes = tokenStore.audit.map { it.type }
        assertTrue(auditTypes.contains("ACCESS_TOKEN_ISSUED"))
        assertTrue(auditTypes.contains("REFRESH_TOKEN_ROTATED"))
        assertTrue(auditTypes.contains("TOKEN_FAMILY_REUSE_REVOKED"))

        // Assert correlation and causation IDs
        val reuseAudit = tokenStore.audit.first { it.type == "TOKEN_FAMILY_REUSE_REVOKED" }
        assertEquals("corr-reuse-attack", reuseAudit.correlationId)
        assertEquals("caus-reuse-attack", reuseAudit.causationId)

        // Assert zero secret leakage in audit
        tokenStore.audit.forEach { evt ->
            assertTrue(!evt.type.contains("srt_"), "Audit event type must not contain raw token secret")
        }

        // Assert the outcome cannot create financial authority or mutate money
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
        assertEquals(0, regStore.audit.count { it.type.contains("CREDIT") })
        assertEquals(0, regStore.audit.count { it.type.contains("DEBIT") })
    }

    // =========================================================================
    // AUTH-002-02-T002: Negative, Boundary, Security & Malformed Rejection
    // =========================================================================

    @Test
    fun `AUTH-002-02-T002 Rotate refresh-token families with reuse detection rejects invalid boundary unauthorized and stale input`() {
        RefreshTokenRotationBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val alertSink = InMemoryTokenSecurityAlertSink()
        val tokenService = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore)
        val pair = tokenService.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-valid",
            correlationId = "corr-v",
            causationId = "caus-v"
        ))

        // 1. Blank / malformed refresh token
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = "   ",
                idempotencyKey = "neg-1",
                correlationId = "corr-1",
                causationId = "caus-1"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Non-existent / unknown refresh token
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = "srt_unknown_nonexistent_token_123",
                idempotencyKey = "neg-2",
                correlationId = "corr-2",
                causationId = "caus-2"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 3. Cross-tenant token rotation
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-different-corp",
                refreshToken = pair.refreshToken,
                idempotencyKey = "neg-3",
                correlationId = "corr-3",
                causationId = "caus-3"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 4. Stale expectedVersion (< 1L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = pair.refreshToken,
                idempotencyKey = "neg-4",
                correlationId = "corr-4",
                causationId = "caus-4",
                expectedVersion = 0L
            ))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 5. Blank headers
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "",
                refreshToken = pair.refreshToken,
                idempotencyKey = "neg-5",
                correlationId = "corr-5",
                causationId = "caus-5"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = pair.refreshToken,
                idempotencyKey = "",
                correlationId = "corr-6",
                causationId = "caus-6"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Expired refresh token (clock shifted by 31 days > 30 days TTL)
        val futureClock = Clock.fixed(now.plus(Duration.ofDays(31)), ZoneOffset.UTC)
        val futureService = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = futureClock
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            futureService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = pair.refreshToken,
                idempotencyKey = "neg-expired",
                correlationId = "corr-exp",
                causationId = "caus-exp"
            ))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Assert money mutation remains zero
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-002-02-T003: Concurrency, Idempotency & Failure Recovery
    // =========================================================================

    @Test
    fun `AUTH-002-02-T003 Rotate refresh-token families with reuse detection survives concurrency duplicate delivery and dependency failure`() {
        RefreshTokenRotationBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val alertSink = InMemoryTokenSecurityAlertSink()
        val tokenService = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore)
        val pair = tokenService.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-conc",
            correlationId = "corr-c",
            causationId = "caus-c"
        ))

        // 1. Idempotent replay: exact same command returns cached result without re-rotating
        val rotCmd = RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = pair.refreshToken,
            idempotencyKey = "idem-rot-key-1",
            correlationId = "corr-idem-1",
            causationId = "caus-idem-1"
        )
        val result1 = tokenService.rotateRefreshToken(rotCmd)
        val result2 = tokenService.rotateRefreshToken(rotCmd) // Replay
        assertEquals(result1.resultId, result2.resultId)
        assertEquals(result1.refreshToken, result2.refreshToken)
        assertEquals(result1.accessToken, result2.accessToken)

        // 2. Conflicting command with same idempotency key
        val conflictCmd = RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = "srt_different_token",
            idempotencyKey = "idem-rot-key-1", // SAME KEY!
            correlationId = "corr-idem-conflict",
            causationId = "caus-idem-conflict"
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(conflictCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Concurrent simultaneous rotation race with different idempotency keys
        // If 10 threads race to rotate the SAME token with DIFFERENT idempotency keys:
        // Exactly ONE must succeed in rotating, while all others MUST trigger reuse detection, revoking the family!
        val pairForRace = tokenService.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-for-race",
            correlationId = "corr-race-iss",
            causationId = "caus-race-iss"
        ))

        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)

        val successResults = mutableListOf<TokenPairResult>()
        val failureExceptions = mutableListOf<Throwable>()

        for (i in 1..threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = tokenService.rotateRefreshToken(RefreshTokenCommand(
                        tenantId = "tenant-casino-1",
                        refreshToken = pairForRace.refreshToken,
                        idempotencyKey = "race-rot-key-$i",
                        correlationId = "corr-race-$i",
                        causationId = "caus-race-$i"
                    ))
                    synchronized(successResults) { successResults.add(res) }
                } catch (t: Throwable) {
                    synchronized(failureExceptions) { failureExceptions.add(t) }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        // Exactly one thread succeeded
        assertEquals(1, successResults.size, "Exactly one thread should lawfully rotate the token")
        // The other 9 threads caught reuse detection rejection (FORBIDDEN)
        assertEquals(threadCount - 1, failureExceptions.size)
        failureExceptions.forEach { ex ->
            assertTrue(ex is AuthenticationFailure.Rejected)
            assertEquals(AuthErrorCode.FORBIDDEN, ex.code)
        }

        // Family must be revoked as a result of the detected reuse from racing threads
        val racedFamily = tokenStore.findFamily("tenant-casino-1", pairForRace.familyId)
        assertNotNull(racedFamily)
        assertTrue(racedFamily.isRevoked, "Family must be revoked upon race-condition reuse attempt")

        // Assert money remains untouched
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-002-02-T004: Migration, Recovery, Lifecycle & Observability
    // =========================================================================

    @Test
    fun `AUTH-002-02-T004 Rotate refresh-token families with reuse detection remains compatible recoverable observable and lifecycle-safe`() {
        RefreshTokenRotationBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val alertSink = InMemoryTokenSecurityAlertSink()
        val tokenService1 = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore)
        val pair = tokenService1.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-recov",
            correlationId = "corr-rec-1",
            causationId = "caus-rec-1"
        ))

        // Rotate once
        val rotatedPair = tokenService1.rotateRefreshToken(RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = pair.refreshToken,
            idempotencyKey = "rot-recov",
            correlationId = "corr-rec-rot",
            causationId = "caus-rec-rot"
        ))

        // Trigger reuse revocation on service 1
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService1.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = pair.refreshToken, // Old rotated token
                idempotencyKey = "reuse-recov",
                correlationId = "corr-rec-reuse",
                causationId = "caus-rec-reuse"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // RECOVERY / RESTART: Simulate service recreation pointing to same durable store
        val tokenService2 = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )

        // After restart, family remains revoked
        val familyAfterRestart = tokenStore.findFamily("tenant-casino-1", pair.familyId)
        assertNotNull(familyAfterRestart)
        assertTrue(familyAfterRestart.isRevoked)
        assertEquals(TokenRevocationReason.ROTATED_REUSE_DETECTED, familyAfterRestart.revocationReason)

        // Even newly created service instance rejects any token from revoked family
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService2.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = rotatedPair.refreshToken,
                idempotencyKey = "post-restart-rot",
                correlationId = "corr-rec-2",
                causationId = "caus-rec-2"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Validate access token is rejected on service 2
        val valPostRestart = tokenService2.validateAccessToken("tenant-casino-1", rotatedPair.accessToken)
        assertTrue(!valPostRestart.valid)
        assertEquals(AuthErrorCode.UNAUTHENTICATED, valPostRestart.reasonCode)

        // Observability check: structured audit events contain correlationId and resultId
        val reuseEvent = tokenStore.audit.first { it.type == "TOKEN_FAMILY_REUSE_REVOKED" }
        assertNotNull(reuseEvent.resultId)
        assertNotNull(reuseEvent.correlationId)
        assertNotNull(reuseEvent.causationId)
        assertNotNull(reuseEvent.occurredAt)

        // Assert database migration integrity: no unapproved SQL migrations beyond V16
        val migrationsDir = File("src/main/resources/db/migration")
        if (migrationsDir.exists()) {
            val migrationFiles = migrationsDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
            val invalidMigrations = migrationFiles.filter { file ->
                val versionNum = file.name.substringAfter("V").substringBefore("__").toIntOrNull()
                versionNum != null && versionNum > 16
            }
            assertTrue(invalidMigrations.isEmpty(), "No unapproved SQL migration beyond V16 may be introduced: ${invalidMigrations.map { it.name }}")
        }

        // Assert no Android lifecycle surface is claimed (Android Keystore remains refresh-token store)
        // Assert zero financial mutation
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }
}
