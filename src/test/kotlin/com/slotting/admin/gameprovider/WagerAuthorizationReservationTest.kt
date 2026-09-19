package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import com.slotting.admin.identity.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class WagerAuthorizationReservationTest {

    private val now = Instant.parse("2026-09-19T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-casino-wager"
    private val providerId = "prov-playngo"
    private val gameId = "game-book-of-dead"
    private val jurisdictionMt = "MT"
    private val currencyUsd = "USD"
    private val currencyEur = "EUR"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-wager-lead",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPPORT),
    )

    private lateinit var regStore: InMemoryPlayerRegistrationStore
    private lateinit var eligStore: InMemoryServerEligibilityStore
    private lateinit var catalogStore: WagerTestCatalogStore
    private lateinit var jurStore: WagerTestJurisdictionStore
    private lateinit var roundTxStore: InMemoryRoundProviderTransactionStore
    private lateinit var reservationStore: InMemoryWagerAuthorizationReservationStore
    private lateinit var alertSink: InMemoryWagerAlertSink
    private lateinit var sessionDirectory: WagerTestSessionDirectory

    private lateinit var operatorService: OperatorJurisdictionEnablementService
    private lateinit var roundMapService: RoundProviderTransactionMapService
    private lateinit var wagerService: WagerAuthorizationReservationService

    @BeforeEach
    fun setUp() {
        WagerAuthorizationReservationBinding.isBound = true
        RoundProviderTransactionBinding.isBound = true
        OperatorJurisdictionEnablementBinding.isBound = true
        AuthoritativeCatalogSyncBinding.isBound = true
        ServerEligibilityBinding.isBound = true

        regStore = InMemoryPlayerRegistrationStore()
        eligStore = InMemoryServerEligibilityStore()
        catalogStore = WagerTestCatalogStore()
        jurStore = WagerTestJurisdictionStore()
        roundTxStore = InMemoryRoundProviderTransactionStore()
        reservationStore = InMemoryWagerAuthorizationReservationStore()
        alertSink = InMemoryWagerAlertSink()
        sessionDirectory = WagerTestSessionDirectory()

        operatorService = OperatorJurisdictionEnablementService(
            policy = AdminRbacPolicy(true),
            sessions = sessionDirectory,
            catalogStore = catalogStore,
            store = jurStore,
            clock = clock,
        )

        roundMapService = RoundProviderTransactionMapService(
            store = roundTxStore,
            clock = clock,
        )

        wagerService = WagerAuthorizationReservationService(
            roundTransactionMapService = roundMapService,
            operatorEnablementService = operatorService,
            registrationStore = regStore,
            eligibilityStore = eligStore,
            reservationStore = reservationStore,
            alertSink = alertSink,
            clock = clock,
            reservationTtlSeconds = 60L,
        )

        setupCatalogAndJurisdiction()
    }

    @AfterEach
    fun tearDown() {
        WagerAuthorizationReservationBinding.isBound = true
        RoundProviderTransactionBinding.isBound = true
        OperatorJurisdictionEnablementBinding.isBound = true
        AuthoritativeCatalogSyncBinding.isBound = true
        ServerEligibilityBinding.isBound = true
    }

    private fun setupCatalogAndJurisdiction() {
        val game = CatalogGameEntry(
            tenantId = tenantId,
            providerId = providerId,
            gameId = gameId,
            gameTitle = "Book of Dead",
            gameType = CasinoProviderType.SLOTS,
            supportedJurisdictions = setOf(jurisdictionMt, "UK", "NV"),
            rtpPercent = 96.21,
            minBetMinorUnits = 10L,
            maxBetMinorUnits = 10000L,
            enablementStatus = GameEnablementStatus.ENABLED,
            lastSynchronizedAt = now,
            staleSyncThresholdSeconds = 86400L,
            version = 1L,
        )
        catalogStore.saveGame(game)

        operatorService.configureJurisdictionPolicy(
            ConfigureJurisdictionPolicyCommand(
                principal = adminPrincipal,
                sessionId = "admin-sess-1",
                tenantId = tenantId,
                jurisdictionCode = jurisdictionMt,
                status = JurisdictionComplianceStatus.ACTIVE,
                allowedGameTypes = setOf(CasinoProviderType.SLOTS),
                maxBetLimitMinorUnits = 50000L,
                rtpFloorPercent = 90.0,
                restrictedGameIds = emptySet(),
                effectiveFrom = now.minusSeconds(86400),
                effectiveUntil = now.plusSeconds(86400 * 365),
                complianceSigner = "MGA-OFFICER-2",
                idempotencyKey = "pol-idemp-wager",
                correlationId = "corr-pol",
                causationId = "cause-pol",
                expectedVersion = 1L,
            )
        )
    }

    private fun setupPlayerAccount(
        playerId: UUID = UUID.randomUUID(),
        initialBalance: Long = 5000L,
        currency: String = currencyUsd,
        selfExcluded: Boolean = false,
        coolOffUntil: Instant? = null,
        singleWagerLimit: Long? = 10000L,
        dailyWagerLimit: Long? = 50000L,
        currentDailyWager: Long = 0L,
    ): UUID {
        regStore.players[playerId] = PlayerRegistrationRecord(
            playerId = playerId,
            tenantId = tenantId,
            emailHash = "email-$playerId",
            phoneHash = "phone-$playerId",
            maskedEmail = "player-$playerId@example.com",
            maskedPhone = "+1555123456",
            jurisdiction = jurisdictionMt,
            riskScore = 10.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            emailVerified = true,
            phoneVerified = true,
            createdAt = now.minusSeconds(86400 * 30),
            updatedAt = now.minusSeconds(86400 * 30),
        )

        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerId,
                tenantId = tenantId,
                dateOfBirth = LocalDate.ofInstant(now, ZoneOffset.UTC).minusYears(25),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = jurisdictionMt,
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerId,
                    selfExcluded = selfExcluded,
                    coolOffUntil = coolOffUntil,
                    singleWagerLimitMinor = singleWagerLimit,
                    dailyWagerLimitMinor = dailyWagerLimit,
                    currentDailyWagerMinor = currentDailyWager,
                ),
            )
        )

        reservationStore.saveWalletBalance(
            PlayerWalletBalanceRecord(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = currency,
                availableBalanceMinorUnits = initialBalance,
                reservedBalanceMinorUnits = 0L,
            )
        )

        return playerId
    }

    // =========================================================================
    // GAME-006-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `GAME-006-T001 Wager authorization and reservation produces the required authoritative outcome`() {
        // 1. Prove fail-closed gate throws expected RED assertion error when unbound
        WagerAuthorizationReservationBinding.isBound = false
        val playerId = setupPlayerAccount(initialBalance = 5000L)

        val betCmd = AuthorizeAndReserveWagerCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            externalRoundId = "rnd-wag-001",
            externalTransactionId = "tx-wag-001",
            amountMinorUnits = 500L,
            currencyCode = currencyUsd,
            jurisdictionCode = jurisdictionMt,
            idempotencyKey = "idemp-wag-001",
            correlationId = "corr-wag-001",
            causationId = "cause-wag-001",
        )

        val redError = assertFailsWith<AssertionError> {
            wagerService.authorizeAndReserveWager(betCmd)
        }
        assertEquals("insufficient/self-excluded/duplicate/concurrent bet", redError.message)

        // Bind the gate
        WagerAuthorizationReservationBinding.isBound = true

        // 2. Perform authoritative wager authorization and reservation
        val result = wagerService.authorizeAndReserveWager(betCmd)

        // Assert: One idempotency key→one reservation; server owns amount/limits/round eligibility.
        assertNotNull(result)
        assertEquals(tenantId, result.tenantId)
        assertEquals(playerId, result.playerId)
        assertEquals(providerId, result.providerId)
        assertEquals(gameId, result.gameId)
        assertEquals("rnd-wag-001", result.externalRoundId)
        assertEquals("tx-wag-001", result.externalTransactionId)
        assertEquals(500L, result.amountMinorUnits)
        assertEquals(currencyUsd, result.currencyCode)
        assertEquals(WagerReservationStatus.RESERVED, result.status)
        assertEquals(4500L, result.availableBalanceMinorUnits)
        assertEquals(500L, result.reservedBalanceMinorUnits)
        assertEquals(now.plusSeconds(60L), result.expiresAt)

        // Verify wallet state in store: solvency conserved
        val wallet = reservationStore.findWalletBalance(tenantId, playerId, currencyUsd)
        assertNotNull(wallet)
        assertEquals(4500L, wallet.availableBalanceMinorUnits)
        assertEquals(500L, wallet.reservedBalanceMinorUnits)
        assertEquals(5000L, wallet.availableBalanceMinorUnits + wallet.reservedBalanceMinorUnits)

        // Verify reservation stored
        val storedRes = reservationStore.findReservation(tenantId, result.reservationId)
        assertNotNull(storedRes)
        assertEquals(WagerReservationStatus.RESERVED, storedRes.status)

        // Verify round mapped in RoundProviderTransactionStore
        val round = roundTxStore.findRoundByExternalId(tenantId, providerId, "rnd-wag-001")
        assertNotNull(round)
        assertEquals(CanonicalRoundStatus.OPEN, round.status)
        assertEquals(500L, round.totalDebitMinorUnits)

        // Verify audit and outbox events
        val audit = reservationStore.auditEvents.find { it.type == "WAGER_RESERVATION_AUTHORIZED" }
        assertNotNull(audit)
        assertEquals("corr-wag-001", audit.correlationId)
        assertEquals("cause-wag-001", audit.causationId)

        val outbox = reservationStore.outboxEvents.find { it.type == "WAGER_RESERVATION_AUTHORIZED" }
        assertNotNull(outbox)
        assertEquals(tenantId, outbox.tenantId)
    }

    // =========================================================================
    // GAME-006-T002: Negative, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `GAME-006-T002 Wager authorization and reservation rejects invalid, boundary, unauthorized, and stale input`() {
        val playerId = setupPlayerAccount(initialBalance = 1000L)

        // 1. Invalid / malformed inputs
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = "",
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-1",
                    externalTransactionId = "tx-1",
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "k1",
                    correlationId = "c1",
                    causationId = "c1",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Negative or zero wager amount
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-1",
                    externalTransactionId = "tx-1",
                    amountMinorUnits = 0L,
                    currencyCode = currencyUsd,
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "k2",
                    correlationId = "c2",
                    causationId = "c2",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-1",
                    externalTransactionId = "tx-1",
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "k3",
                    correlationId = "c3",
                    causationId = "c3",
                    expectedVersion = 2L,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 2. Insufficient Balance (Protected Risk: insufficient bet)
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-overdraft",
                    externalTransactionId = "tx-od-1",
                    amountMinorUnits = 2500L, // 2500 > balance 1000
                    currencyCode = currencyUsd,
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "k-insufficient",
                    correlationId = "c-ins",
                    causationId = "cause-ins",
                )
            )
        }.also {
            assertEquals(AuthErrorCode.FORBIDDEN, it.code)
            assertTrue(alertSink.alerts.any { a -> a.contains("INSUFFICIENT_FUNDS_WAGER_ATTEMPT") })
        }

        // 3. Self-Excluded Player (Protected Risk: self-excluded bet)
        val selfExcludedPlayer = setupPlayerAccount(initialBalance = 5000L, selfExcluded = true)
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = tenantId,
                    playerId = selfExcludedPlayer,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-self-ex",
                    externalTransactionId = "tx-se-1",
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "k-self-ex",
                    correlationId = "c-se",
                    causationId = "cause-se",
                )
            )
        }.also {
            assertEquals(AuthErrorCode.FORBIDDEN, it.code)
            assertTrue(alertSink.alerts.any { a -> a.contains("SELF_EXCLUDED_WAGER_ATTEMPT") })
        }

        // 4. Cool-off period active
        val coolOffPlayer = setupPlayerAccount(initialBalance = 5000L, coolOffUntil = now.plusSeconds(3600))
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = tenantId,
                    playerId = coolOffPlayer,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-co",
                    externalTransactionId = "tx-co-1",
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "k-cool-off",
                    correlationId = "c-co",
                    causationId = "cause-co",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Exceeds Single Wager Limit
        val limitPlayer = setupPlayerAccount(initialBalance = 50000L, singleWagerLimit = 2000L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = tenantId,
                    playerId = limitPlayer,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-limit",
                    externalTransactionId = "tx-limit-1",
                    amountMinorUnits = 2500L, // 2500 > 2000 limit
                    currencyCode = currencyUsd,
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "k-single-limit",
                    correlationId = "c-sl",
                    causationId = "cause-sl",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Exceeds Game Min/Max Bet Limits
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-min-bet",
                    externalTransactionId = "tx-min-1",
                    amountMinorUnits = 5L, // 5 < minBet 10
                    currencyCode = currencyUsd,
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "k-min-bet",
                    correlationId = "c-mb",
                    causationId = "cause-mb",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Duplicate External Transaction ID (Protected Risk: duplicate bet)
        val validBet = wagerService.authorizeAndReserveWager(
            AuthorizeAndReserveWagerCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                externalRoundId = "rnd-dup-test",
                externalTransactionId = "tx-unique-1",
                amountMinorUnits = 100L,
                currencyCode = currencyUsd,
                jurisdictionCode = jurisdictionMt,
                idempotencyKey = "k-dup-initial",
                correlationId = "c-dup-1",
                causationId = "cause-dup-1",
            )
        )
        assertNotNull(validBet)

        // Attempting to reuse same externalTransactionId with another key must fail with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-dup-test",
                    externalTransactionId = "tx-unique-1", // Reused external ID!
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "k-dup-second-attempt",
                    correlationId = "c-dup-2",
                    causationId = "cause-dup-2",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 8. Currency Mismatch with Player Wallet
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-curr",
                    externalTransactionId = "tx-curr-1",
                    amountMinorUnits = 100L,
                    currencyCode = currencyEur, // Player wallet only exists in USD
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "k-curr-mismatch",
                    correlationId = "c-cm",
                    causationId = "cause-cm",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    // =========================================================================
    // GAME-006-T003: Concurrency, Duplicate Delivery, and Dependency Failure
    // =========================================================================

    @Test
    fun `GAME-006-T003 Wager authorization and reservation survives concurrency, duplicate delivery, and dependency failure`() {
        val playerId = setupPlayerAccount(initialBalance = 1000L)

        // 1. Idempotent request replay (same key, identical payload) returns identical reservation
        val cmd = AuthorizeAndReserveWagerCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            externalRoundId = "rnd-conc-replay",
            externalTransactionId = "tx-conc-rep-1",
            amountMinorUnits = 200L,
            currencyCode = currencyUsd,
            jurisdictionCode = jurisdictionMt,
            idempotencyKey = "idemp-conc-repeat",
            correlationId = "c-cr",
            causationId = "cause-cr",
        )
        val initial = wagerService.authorizeAndReserveWager(cmd)
        val replay = wagerService.authorizeAndReserveWager(cmd)
        assertEquals(initial.reservationId, replay.reservationId)
        assertEquals(initial.canonicalTransactionId, replay.canonicalTransactionId)
        assertEquals(initial.availableBalanceMinorUnits, replay.availableBalanceMinorUnits)

        // Changed payload with same key fails with CONFLICT
        val conflictCmd = cmd.copy(amountMinorUnits = 400L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            wagerService.authorizeAndReserveWager(conflictCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 2. Concurrent Bet Race on Limited Balance (Protected Risk: concurrent bet / solvency)
        // Player has remaining 800 available balance.
        // Two threads race to reserve 500 minor units simultaneously. Only one can succeed!
        val raceThreads = 2
        val executor = Executors.newFixedThreadPool(raceThreads)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(raceThreads)
        val successCount = AtomicInteger(0)
        val insufficientCount = AtomicInteger(0)

        for (i in 1..raceThreads) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = wagerService.authorizeAndReserveWager(
                        AuthorizeAndReserveWagerCommand(
                            tenantId = tenantId,
                            playerId = playerId,
                            providerId = providerId,
                            gameId = gameId,
                            externalRoundId = "rnd-race-$i",
                            externalTransactionId = "tx-race-$i",
                            amountMinorUnits = 500L, // 500 * 2 = 1000 > available 800
                            currencyCode = currencyUsd,
                            jurisdictionCode = jurisdictionMt,
                            idempotencyKey = "idemp-race-bet-$i",
                            correlationId = "c-race-$i",
                            causationId = "cause-race-$i",
                        )
                    )
                    if (res.status == WagerReservationStatus.RESERVED) {
                        successCount.incrementAndGet()
                    }
                } catch (e: AuthenticationFailure.Rejected) {
                    if (e.code == AuthErrorCode.FORBIDDEN) {
                        insufficientCount.incrementAndGet()
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        // Exactly 1 thread must succeed and 1 thread must fail with insufficient funds
        assertEquals(1, successCount.get(), "Only exactly 1 thread may reserve funds when balance is insufficient for both")
        assertEquals(1, insufficientCount.get(), "Losing thread must be rejected with FORBIDDEN")

        // Final wallet balances: initial was 1000, 200 reserved earlier + 500 reserved in race = 700 reserved, 300 available
        val wallet = reservationStore.findWalletBalance(tenantId, playerId, currencyUsd)
        assertNotNull(wallet)
        assertEquals(300L, wallet.availableBalanceMinorUnits)
        assertEquals(700L, wallet.reservedBalanceMinorUnits)
        assertEquals(1000L, wallet.availableBalanceMinorUnits + wallet.reservedBalanceMinorUnits)

        // 3. Dependency failure fails closed
        val failingRegStore = WagerFailingRegistrationStore()
        val failingWagerService = WagerAuthorizationReservationService(
            roundTransactionMapService = roundMapService,
            operatorEnablementService = operatorService,
            registrationStore = failingRegStore,
            eligibilityStore = eligStore,
            reservationStore = reservationStore,
            alertSink = alertSink,
            clock = clock,
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            failingWagerService.authorizeAndReserveWager(
                AuthorizeAndReserveWagerCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-dep-fail",
                    externalTransactionId = "tx-df-1",
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    jurisdictionCode = jurisdictionMt,
                    idempotencyKey = "idemp-df",
                    correlationId = "c-df",
                    causationId = "cause-df",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    // =========================================================================
    // GAME-006-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `GAME-006-T004 Wager authorization and reservation remains compatible, recoverable, observable, and lifecycle-safe`() {
        val playerId = setupPlayerAccount(initialBalance = 5000L)

        // 1. Initial Reservation
        val betCmd = AuthorizeAndReserveWagerCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            externalRoundId = "rnd-life-001",
            externalTransactionId = "tx-life-001",
            amountMinorUnits = 1000L,
            currencyCode = currencyUsd,
            jurisdictionCode = jurisdictionMt,
            idempotencyKey = "idemp-life-bet",
            correlationId = "corr-life-bet",
            causationId = "cause-life-bet",
        )
        val betResult = wagerService.authorizeAndReserveWager(betCmd)

        // 2. Re-instantiate service (simulating application restart / migration)
        val restartedService = WagerAuthorizationReservationService(
            roundTransactionMapService = roundMapService,
            operatorEnablementService = operatorService,
            registrationStore = regStore,
            eligibilityStore = eligStore,
            reservationStore = reservationStore,
            alertSink = alertSink,
            clock = clock,
        )

        // 3. Commit Reservation (settling the wager debit)
        val commitCmd = CommitWagerReservationCommand(
            tenantId = tenantId,
            reservationId = betResult.reservationId,
            idempotencyKey = "idemp-life-commit",
            correlationId = "corr-life-commit",
            causationId = "cause-life-commit",
        )
        val commitResult = restartedService.commitReservation(commitCmd)
        assertEquals(WagerReservationStatus.COMMITTED, commitResult.status)
        assertEquals(4000L, commitResult.availableBalanceMinorUnits)
        assertEquals(0L, commitResult.reservedBalanceMinorUnits) // Reserved balance cleared

        // Idempotent commit replay
        val commitReplay = restartedService.commitReservation(commitCmd)
        assertEquals(commitResult.reservationId, commitReplay.reservationId)
        assertEquals(commitResult.status, commitReplay.status)

        // 4. Test Release Reservation Lifecycle
        val bet2 = restartedService.authorizeAndReserveWager(
            AuthorizeAndReserveWagerCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                externalRoundId = "rnd-life-002",
                externalTransactionId = "tx-life-002",
                amountMinorUnits = 500L,
                currencyCode = currencyUsd,
                jurisdictionCode = jurisdictionMt,
                idempotencyKey = "idemp-life-bet2",
                correlationId = "c-lb2",
                causationId = "cause-lb2",
            )
        )
        assertEquals(3500L, bet2.availableBalanceMinorUnits)
        assertEquals(500L, bet2.reservedBalanceMinorUnits)

        // Release reservation (game cancelled or rollback)
        val releaseCmd = ReleaseWagerReservationCommand(
            tenantId = tenantId,
            reservationId = bet2.reservationId,
            reason = "Game cancelled by player disconnect",
            idempotencyKey = "idemp-life-release",
            correlationId = "c-rel",
            causationId = "cause-rel",
        )
        val releaseResult = restartedService.releaseReservation(releaseCmd)
        assertEquals(WagerReservationStatus.RELEASED, releaseResult.status)
        assertEquals(4000L, releaseResult.availableBalanceMinorUnits) // Funds restored to available balance
        assertEquals(0L, releaseResult.reservedBalanceMinorUnits)

        // 5. Test Expire Reservation Lifecycle (WALLET-003: expiry is worker command, never silent deletion)
        val bet3 = restartedService.authorizeAndReserveWager(
            AuthorizeAndReserveWagerCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                externalRoundId = "rnd-life-003",
                externalTransactionId = "tx-life-003",
                amountMinorUnits = 1000L,
                currencyCode = currencyUsd,
                jurisdictionCode = jurisdictionMt,
                idempotencyKey = "idemp-life-bet3",
                correlationId = "c-lb3",
                causationId = "cause-lb3",
            )
        )
        assertEquals(3000L, bet3.availableBalanceMinorUnits)
        assertEquals(1000L, bet3.reservedBalanceMinorUnits)

        val expireCmd = ExpireWagerReservationCommand(
            tenantId = tenantId,
            reservationId = bet3.reservationId,
            correlationId = "c-exp",
            causationId = "cause-exp",
        )
        val expireResult = restartedService.expireReservation(expireCmd)
        assertEquals(WagerReservationStatus.EXPIRED, expireResult.status)
        assertEquals(4000L, expireResult.availableBalanceMinorUnits) // Restored funds
        assertEquals(0L, expireResult.reservedBalanceMinorUnits)

        // 6. Observability Checks
        val auditEvents = reservationStore.auditEvents
        val outboxEvents = reservationStore.outboxEvents
        assertTrue(auditEvents.any { it.type == "WAGER_RESERVATION_AUTHORIZED" })
        assertTrue(auditEvents.any { it.type == "WAGER_RESERVATION_COMMITTED" })
        assertTrue(auditEvents.any { it.type == "WAGER_RESERVATION_RELEASED" })
        assertTrue(auditEvents.any { it.type == "WAGER_RESERVATION_EXPIRED" })

        for (event in auditEvents) {
            assertNotNull(event.eventId)
            assertNotNull(event.tenantId)
            assertNotNull(event.type)
            assertNotNull(event.occurredAt)
            assertNotNull(event.correlationId)
            assertNotNull(event.causationId)
        }

        for (event in outboxEvents) {
            assertNotNull(event.eventId)
            assertNotNull(event.tenantId)
            assertNotNull(event.type)
            assertNotNull(event.createdAt)
        }
    }
}

// =============================================================================
// Test Fakes & In-Memory Helpers
// =============================================================================

class WagerTestSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-19T18:00:00Z"),
        )
}

class WagerTestJurisdictionStore : OperatorJurisdictionEnablementStore {
    private val policies = mutableMapOf<String, JurisdictionCompliancePolicy>()
    private val policyIdempotency = mutableMapOf<String, Pair<String, JurisdictionPolicyResult>>()
    private val enablementIdempotency = mutableMapOf<String, Pair<String, OperatorEnablementResult>>()
    private val launchIdempotency = mutableMapOf<String, Pair<String, AuthoritativeGameLaunchResult>>()

    override fun findPolicy(tenantId: String, jurisdictionCode: String): JurisdictionCompliancePolicy? =
        synchronized(this) { policies["$tenantId:$jurisdictionCode"] }

    override fun savePolicy(
        policy: JurisdictionCompliancePolicy,
        result: JurisdictionPolicyResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        policies["$tenantId:${policy.jurisdictionCode}"] = policy
        policyIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }

    override fun findPolicyByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, JurisdictionPolicyResult>? =
        synchronized(this) { policyIdempotency["$tenantId:$idempotencyKey"] }

    override fun findEnablementByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, OperatorEnablementResult>? =
        synchronized(this) { enablementIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveEnablement(
        result: OperatorEnablementResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        enablementIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }

    override fun findLaunchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AuthoritativeGameLaunchResult>? =
        synchronized(this) { launchIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveLaunch(
        result: AuthoritativeGameLaunchResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        launchIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

class WagerTestCatalogStore : AuthoritativeCatalogStore {
    private val games = mutableMapOf<String, CatalogGameEntry>()
    private val syncIdempotency = mutableMapOf<String, Pair<String, CatalogSyncResult>>()
    private val enablementIdempotency = mutableMapOf<String, Pair<String, GameEnablementResult>>()
    private val launchIdempotency = mutableMapOf<String, Pair<String, GameLaunchAuthorizationResult>>()

    override fun findGame(tenantId: String, providerId: String, gameId: String): CatalogGameEntry? =
        synchronized(this) { games["$tenantId:$providerId:$gameId"] }

    override fun listGames(tenantId: String, providerId: String): List<CatalogGameEntry> =
        synchronized(this) { games.values.filter { it.tenantId == tenantId && it.providerId == providerId } }

    override fun saveGame(game: CatalogGameEntry) =
        synchronized(this) { games["${game.tenantId}:${game.providerId}:${game.gameId}"] = game }

    override fun findSyncByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CatalogSyncResult>? =
        synchronized(this) { syncIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveSync(
        result: CatalogSyncResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        syncIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }

    override fun findEnablementByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameEnablementResult>? =
        synchronized(this) { enablementIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveEnablement(
        result: GameEnablementResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        enablementIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }

    override fun findLaunchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameLaunchAuthorizationResult>? =
        synchronized(this) { launchIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveLaunch(
        result: GameLaunchAuthorizationResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        launchIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

class WagerFailingRegistrationStore : PlayerRegistrationStore {
    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? {
        throw RuntimeException("Database connection timeout")
    }

    override fun saveRegistration(
        command: RegisterPlayerCommand,
        result: RegisterPlayerResult,
        record: PlayerRegistrationRecord,
        verificationCodes: List<VerificationCodeRecord>
    ) {
        throw RuntimeException("Database connection timeout")
    }

    override fun saveVerification(
        command: VerifyContactCommand,
        result: VerifyContactResult,
        record: PlayerRegistrationRecord,
        verificationCode: VerificationCodeRecord
    ) {
        throw RuntimeException("Database connection timeout")
    }

    override fun findByEmailHash(tenantId: String, emailHash: String): PlayerRegistrationRecord? {
        throw RuntimeException("Database connection timeout")
    }

    override fun findByPhoneHash(tenantId: String, phoneHash: String): PlayerRegistrationRecord? {
        throw RuntimeException("Database connection timeout")
    }

    override fun findById(tenantId: String, playerId: UUID): PlayerRegistrationRecord? {
        throw RuntimeException("Database connection timeout")
    }

    override fun findVerificationCode(tenantId: String, playerId: UUID, channel: ContactVerificationChannel): VerificationCodeRecord? {
        throw RuntimeException("Database connection timeout")
    }

    override fun currentVersion(tenantId: String, playerId: UUID): Long {
        throw RuntimeException("Database connection timeout")
    }
}
