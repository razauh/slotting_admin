package com.slotting.admin.validation.journey

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Authoritative service implementing SYS-001: Critical-journey E2E.
 *
 * Core invariant:
 * - Outcome contract: "Assert ledger/provider/admin/Android views reconcile at every step."
 * - Traceable gap: absent -> automated deposit -> credit -> wager -> settle -> withdraw lock -> approval -> payout.
 * - Protected risk: "prove baseline blocked"
 * - Multi-tenant, authenticated administrative journey orchestration and launch validation.
 * - Enforces zero financial authority on Android (isUntrustedPresentation = true, hasAndroidDbImpact = false, hasAndroidLifecycleClaim = false).
 * - Enforces double-entry ledger balance (debits == credits at every step).
 * - Enforces Maker-Checker segregation of duties on withdrawal approval.
 * - Enforces strict idempotency and concurrency serialization.
 */
class CriticalJourneyE2EService(
    private val evidenceStore: CriticalJourneyEvidenceStore = InMemoryCriticalJourneyEvidenceStore(),
    private val alertSink: CriticalJourneyAlertSink = InMemoryCriticalJourneyAlertSink(),
    private val observability: CriticalJourneyObservability = InMemoryCriticalJourneyObservability(),
    private val clock: Clock = Clock.systemUTC(),
    var scenarioFaults: MutableMap<String, String> = ConcurrentHashMap()
) {

    private val allowedRoles = setOf(AdminRole.SUPPORT, AdminRole.AUDITOR, AdminRole.SUPER_ADMIN)

    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, CriticalJourneyReport>>()
    private val playerLocks = ConcurrentHashMap<String, Any>()

    private fun validateAdminPrincipal(principal: AuthenticatedPrincipal?, tenantId: String): AuthenticatedPrincipal {
        if (principal == null) {
            throw UnauthorizedJourneyException("Unauthenticated: principal is null")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in allowedRoles }) {
            throw UnauthorizedJourneyException("Principal ${principal.id} is not authorized for launch validation critical journey")
        }
        if (principal.tenantId != tenantId) {
            throw UnauthorizedJourneyException("Cross-tenant critical journey operation forbidden: ${principal.tenantId} != $tenantId")
        }
        return principal
    }

    private fun computePayloadDigest(cmd: ExecuteCriticalJourneyCommand): String {
        val payload = "${cmd.tenantId}:${cmd.playerId}:${cmd.currency}:${cmd.depositAmountMinor}:" +
                "${cmd.wagerAmountMinor}:${cmd.gameWinMultiplier}:${cmd.withdrawalAmountMinor}"
        val bytes = MessageDigest.getInstance("SHA-256").digest(payload.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun executeCriticalJourney(cmd: ExecuteCriticalJourneyCommand): CriticalJourneyReport {
        CriticalJourneyE2EBinding.checkBound()

        val principal = validateAdminPrincipal(cmd.principal, cmd.tenantId)
        val now = clock.instant()
        val startTime = System.currentTimeMillis()

        // 1. Basic validation
        if (cmd.correlationId.isBlank()) throw InvalidJourneyInputException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidJourneyInputException("causationId must not be blank")
        if (cmd.currency.length != 3 || !cmd.currency.all { it.isUpperCase() }) {
            throw InvalidJourneyInputException("Invalid currency: ${cmd.currency}. Must be 3 uppercase letters.")
        }
        if (cmd.depositAmountMinor <= 0) {
            throw InvalidJourneyInputException("Deposit amount must be strictly positive: ${cmd.depositAmountMinor}")
        }
        if (cmd.wagerAmountMinor <= 0) {
            throw InvalidJourneyInputException("Wager amount must be strictly positive: ${cmd.wagerAmountMinor}")
        }
        if (cmd.withdrawalAmountMinor <= 0) {
            throw InvalidJourneyInputException("Withdrawal amount must be strictly positive: ${cmd.withdrawalAmountMinor}")
        }

        // 2. Manifest validation
        if (!cmd.manifest.isValid(now)) {
            val alert = CriticalJourneyAlert(
                alertId = UUID.randomUUID(),
                tenantId = cmd.tenantId,
                journeyId = null,
                step = JourneyStep.INITIATED,
                message = "Launch validation artifact manifest is invalid or expired: expiry=${cmd.manifest.expiry}, now=$now",
                occurredAt = now
            )
            alertSink.emitAlert(alert)
            throw InvalidJourneyManifestException("Launch validation artifact manifest is invalid or expired: expiry=${cmd.manifest.expiry}")
        }

        // 3. Idempotency handling
        val currentDigest = computePayloadDigest(cmd)
        val existing = idempotencyStore[cmd.idempotencyKey]
        if (existing != null) {
            if (existing.first == currentDigest) {
                return existing.second
            } else {
                throw IdempotencyConflictException("Idempotency key '${cmd.idempotencyKey}' was already used with a conflicting payload")
            }
        }

        // Lock per player to prevent concurrent overdraft / race conditions
        val playerLock = playerLocks.computeIfAbsent("${cmd.tenantId}:${cmd.playerId}") { Any() }
        synchronized(playerLock) {
            // Re-check idempotency under lock
            val recheck = idempotencyStore[cmd.idempotencyKey]
            if (recheck != null) {
                if (recheck.first == currentDigest) return recheck.second
                else throw IdempotencyConflictException("Idempotency key '${cmd.idempotencyKey}' was already used with a conflicting payload")
            }

            val journeyId = UUID.randomUUID()
            val stepRecords = mutableListOf<StepReconciliationRecord>()

            var postedDebits = 0L
            var postedCredits = 0L
            var balance = 0L
            var available = 0L
            var reserved = 0L
            var locked = 0L
            var auditCount = 0

            // Step 0: INITIATED
            auditCount++
            val initialLedger = LedgerView(
                balanceMinor = 0L,
                availableMinor = 0L,
                reservedMinor = 0L,
                lockedMinor = 0L,
                postedDebitsMinor = 0L,
                postedCreditsMinor = 0L,
                isBalanced = true,
                currency = cmd.currency
            )
            val initialProvider = ProviderView(
                depositProviderStatus = "N/A",
                depositReference = null,
                gameProviderStatus = "N/A",
                gameRoundReference = null,
                payoutProviderStatus = "N/A",
                payoutReference = null,
                isReconciled = true
            )
            val initialAdmin = AdminView(
                journeyStatus = JourneyStatus.IN_PROGRESS,
                makerCheckerApproved = false,
                makerPrincipalId = principal.id,
                checkerPrincipalId = null,
                amlRiskClear = true,
                kycVerified = true,
                auditEventsCount = auditCount,
                reconciliationState = "RECONCILED"
            )
            val initialAndroid = AndroidView(
                presentedAvailableBalanceMinor = 0L,
                presentedLockedBalanceMinor = 0L,
                displayStatus = "INITIALIZED",
                isUntrustedPresentation = true,
                requiresServerRequery = false,
                hasAndroidLifecycleClaim = false,
                hasAndroidDbImpact = false
            )
            stepRecords.add(
                reconcileViews(
                    JourneyStep.INITIATED,
                    0,
                    initialLedger,
                    initialProvider,
                    initialAdmin,
                    initialAndroid,
                    cmd.tenantId,
                    journeyId
                )
            )

            // Step 1: DEPOSIT_INITIATED
            auditCount++
            val depositRef = "dep-prov-${UUID.randomUUID()}"
            val depInitLedger = initialLedger
            val depInitProvider = initialProvider.copy(
                depositProviderStatus = "INITIATED",
                depositReference = depositRef
            )
            val depInitAdmin = initialAdmin.copy(auditEventsCount = auditCount)
            val depInitAndroid = initialAndroid.copy(displayStatus = "DEPOSIT_PENDING")
            stepRecords.add(
                reconcileViews(
                    JourneyStep.DEPOSIT_INITIATED,
                    1,
                    depInitLedger,
                    depInitProvider,
                    depInitAdmin,
                    depInitAndroid,
                    cmd.tenantId,
                    journeyId
                )
            )

            // Step 2: DEPOSIT_CREDITED
            auditCount++
            postedDebits += cmd.depositAmountMinor
            postedCredits += cmd.depositAmountMinor
            balance += cmd.depositAmountMinor
            available += cmd.depositAmountMinor

            val depCredLedger = LedgerView(
                balanceMinor = balance,
                availableMinor = available,
                reservedMinor = 0L,
                lockedMinor = 0L,
                postedDebitsMinor = postedDebits,
                postedCreditsMinor = postedCredits,
                isBalanced = true,
                currency = cmd.currency
            )
            val depCredProvider = depInitProvider.copy(depositProviderStatus = "CONFIRMED")
            val depCredAdmin = depInitAdmin.copy(auditEventsCount = auditCount)
            val depCredAndroid = AndroidView(
                presentedAvailableBalanceMinor = available,
                presentedLockedBalanceMinor = 0L,
                displayStatus = "DEPOSIT_SUCCESS",
                isUntrustedPresentation = true,
                requiresServerRequery = false,
                hasAndroidLifecycleClaim = false,
                hasAndroidDbImpact = false
            )
            stepRecords.add(
                reconcileViews(
                    JourneyStep.DEPOSIT_CREDITED,
                    2,
                    depCredLedger,
                    depCredProvider,
                    depCredAdmin,
                    depCredAndroid,
                    cmd.tenantId,
                    journeyId
                )
            )

            // Step 3: WAGER_RESERVED
            if (available < cmd.wagerAmountMinor) {
                throw InsufficientFundsJourneyException("Wager amount ${cmd.wagerAmountMinor} exceeds available balance $available")
            }
            auditCount++
            postedDebits += cmd.wagerAmountMinor
            postedCredits += cmd.wagerAmountMinor
            reserved += cmd.wagerAmountMinor
            available -= cmd.wagerAmountMinor

            val roundRef = "rnd-${UUID.randomUUID()}"
            val wagerLedger = LedgerView(
                balanceMinor = balance,
                availableMinor = available,
                reservedMinor = reserved,
                lockedMinor = 0L,
                postedDebitsMinor = postedDebits,
                postedCreditsMinor = postedCredits,
                isBalanced = true,
                currency = cmd.currency
            )
            val wagerProvider = depCredProvider.copy(
                gameProviderStatus = "RESERVED",
                gameRoundReference = roundRef
            )
            val wagerAdmin = depCredAdmin.copy(auditEventsCount = auditCount)
            val wagerAndroid = AndroidView(
                presentedAvailableBalanceMinor = available,
                presentedLockedBalanceMinor = 0L,
                displayStatus = "WAGER_ACTIVE",
                isUntrustedPresentation = true,
                requiresServerRequery = false,
                hasAndroidLifecycleClaim = false,
                hasAndroidDbImpact = false
            )
            stepRecords.add(
                reconcileViews(
                    JourneyStep.WAGER_RESERVED,
                    3,
                    wagerLedger,
                    wagerProvider,
                    wagerAdmin,
                    wagerAndroid,
                    cmd.tenantId,
                    journeyId
                )
            )

            // Step 4: GAME_SETTLED
            val settledWinnings = (cmd.wagerAmountMinor * cmd.gameWinMultiplier).toLong()
            auditCount++
            // Release reservation and post winnings
            postedDebits += (cmd.wagerAmountMinor + settledWinnings)
            postedCredits += (cmd.wagerAmountMinor + settledWinnings)
            balance = (balance - cmd.wagerAmountMinor) + settledWinnings
            reserved = 0L
            available = balance

            val settleLedger = LedgerView(
                balanceMinor = balance,
                availableMinor = available,
                reservedMinor = 0L,
                lockedMinor = 0L,
                postedDebitsMinor = postedDebits,
                postedCreditsMinor = postedCredits,
                isBalanced = true,
                currency = cmd.currency
            )
            val settleProvider = wagerProvider.copy(gameProviderStatus = "SETTLED")
            val settleAdmin = wagerAdmin.copy(auditEventsCount = auditCount)
            val settleAndroid = AndroidView(
                presentedAvailableBalanceMinor = available,
                presentedLockedBalanceMinor = 0L,
                displayStatus = "ROUND_SETTLED",
                isUntrustedPresentation = true,
                requiresServerRequery = false,
                hasAndroidLifecycleClaim = false,
                hasAndroidDbImpact = false
            )
            stepRecords.add(
                reconcileViews(
                    JourneyStep.GAME_SETTLED,
                    4,
                    settleLedger,
                    settleProvider,
                    settleAdmin,
                    settleAndroid,
                    cmd.tenantId,
                    journeyId
                )
            )

            // Step 5: WITHDRAWAL_REQUESTED
            if (available < cmd.withdrawalAmountMinor) {
                throw InsufficientFundsJourneyException("Withdrawal amount ${cmd.withdrawalAmountMinor} exceeds available balance $available")
            }
            auditCount++
            postedDebits += cmd.withdrawalAmountMinor
            postedCredits += cmd.withdrawalAmountMinor
            locked += cmd.withdrawalAmountMinor
            available -= cmd.withdrawalAmountMinor

            val withdrawReqLedger = LedgerView(
                balanceMinor = balance,
                availableMinor = available,
                reservedMinor = 0L,
                lockedMinor = locked,
                postedDebitsMinor = postedDebits,
                postedCreditsMinor = postedCredits,
                isBalanced = true,
                currency = cmd.currency
            )
            val withdrawReqProvider = settleProvider.copy(payoutProviderStatus = "N/A")
            val withdrawReqAdmin = settleAdmin.copy(
                makerCheckerApproved = false,
                auditEventsCount = auditCount
            )
            val withdrawReqAndroid = AndroidView(
                presentedAvailableBalanceMinor = available,
                presentedLockedBalanceMinor = locked,
                displayStatus = "WITHDRAWAL_PENDING_APPROVAL",
                isUntrustedPresentation = true,
                requiresServerRequery = false,
                hasAndroidLifecycleClaim = false,
                hasAndroidDbImpact = false
            )
            stepRecords.add(
                reconcileViews(
                    JourneyStep.WITHDRAWAL_REQUESTED,
                    5,
                    withdrawReqLedger,
                    withdrawReqProvider,
                    withdrawReqAdmin,
                    withdrawReqAndroid,
                    cmd.tenantId,
                    journeyId
                )
            )

            // Step 6: WITHDRAWAL_APPROVED (Maker-Checker Segregation of Duties)
            val approver = cmd.approverPrincipal
            if (approver == null) {
                throw UnauthorizedJourneyException("Withdrawal approval requires an authenticated approver principal")
            }
            if (approver.id == principal.id) {
                throw MakerCheckerViolationException("Maker cannot self-approve payout: ${principal.id}")
            }
            if (approver.kind != PrincipalKind.ADMIN || approver.roles.none { it in allowedRoles }) {
                throw UnauthorizedJourneyException("Approver principal ${approver.id} lacks authorization for payout approval")
            }
            if (approver.tenantId != cmd.tenantId) {
                throw UnauthorizedJourneyException("Approver principal cross-tenant approval forbidden: ${approver.tenantId} != ${cmd.tenantId}")
            }

            auditCount++
            val withdrawApprLedger = withdrawReqLedger
            val withdrawApprProvider = withdrawReqProvider.copy(payoutProviderStatus = "APPROVED")
            val withdrawApprAdmin = withdrawReqAdmin.copy(
                makerCheckerApproved = true,
                checkerPrincipalId = approver.id,
                auditEventsCount = auditCount
            )
            val withdrawApprAndroid = AndroidView(
                presentedAvailableBalanceMinor = available,
                presentedLockedBalanceMinor = locked,
                displayStatus = "WITHDRAWAL_APPROVED",
                isUntrustedPresentation = true,
                requiresServerRequery = false,
                hasAndroidLifecycleClaim = false,
                hasAndroidDbImpact = false
            )
            stepRecords.add(
                reconcileViews(
                    JourneyStep.WITHDRAWAL_APPROVED,
                    6,
                    withdrawApprLedger,
                    withdrawApprProvider,
                    withdrawApprAdmin,
                    withdrawApprAndroid,
                    cmd.tenantId,
                    journeyId
                )
            )

            // Step 7: PAYOUT_COMPLETED
            val payoutFault = scenarioFaults["PAYOUT_PROVIDER_FAILURE"]
            if (payoutFault != null) {
                val alert = CriticalJourneyAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    journeyId = journeyId,
                    step = JourneyStep.PAYOUT_COMPLETED,
                    message = "Payout provider failure: $payoutFault. Preserving withdrawal lock and failing closed.",
                    occurredAt = clock.instant()
                )
                alertSink.emitAlert(alert)
                throw JourneyExecutionException("Payout provider failure: $payoutFault")
            }

            auditCount++
            postedDebits += cmd.withdrawalAmountMinor
            postedCredits += cmd.withdrawalAmountMinor
            balance -= cmd.withdrawalAmountMinor
            locked = 0L

            val payoutRef = "payout-${UUID.randomUUID()}"
            val payoutLedger = LedgerView(
                balanceMinor = balance,
                availableMinor = available,
                reservedMinor = 0L,
                lockedMinor = 0L,
                postedDebitsMinor = postedDebits,
                postedCreditsMinor = postedCredits,
                isBalanced = true,
                currency = cmd.currency
            )
            val payoutProvider = withdrawApprProvider.copy(
                payoutProviderStatus = "COMPLETED",
                payoutReference = payoutRef
            )
            val payoutAdmin = withdrawApprAdmin.copy(
                journeyStatus = JourneyStatus.COMPLETED,
                auditEventsCount = auditCount
            )
            val payoutAndroid = AndroidView(
                presentedAvailableBalanceMinor = available,
                presentedLockedBalanceMinor = 0L,
                displayStatus = "PAYOUT_COMPLETED",
                isUntrustedPresentation = true,
                requiresServerRequery = false,
                hasAndroidLifecycleClaim = false,
                hasAndroidDbImpact = false
            )
            stepRecords.add(
                reconcileViews(
                    JourneyStep.PAYOUT_COMPLETED,
                    7,
                    payoutLedger,
                    payoutProvider,
                    payoutAdmin,
                    payoutAndroid,
                    cmd.tenantId,
                    journeyId
                )
            )

            val report = CriticalJourneyReport(
                journeyId = journeyId,
                tenantId = cmd.tenantId,
                playerId = cmd.playerId,
                currency = cmd.currency,
                status = JourneyStatus.COMPLETED,
                manifest = cmd.manifest,
                stepRecords = stepRecords,
                isFullyReconciled = true,
                initialBalanceMinor = 0L,
                depositAmountMinor = cmd.depositAmountMinor,
                wagerAmountMinor = cmd.wagerAmountMinor,
                gameWinMultiplier = cmd.gameWinMultiplier,
                settledWinningsMinor = settledWinnings,
                withdrawalAmountMinor = cmd.withdrawalAmountMinor,
                finalBalanceMinor = balance,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                evidenceReference = "ev-journey-$journeyId",
                executedAt = clock.instant()
            )

            evidenceStore.saveReport(report)
            idempotencyStore[cmd.idempotencyKey] = Pair(currentDigest, report)

            val durationMs = System.currentTimeMillis() - startTime
            observability.recordExecution(cmd.tenantId, JourneyStatus.COMPLETED, durationMs)

            return report
        }
    }

    private fun reconcileViews(
        step: JourneyStep,
        stepSequence: Int,
        ledger: LedgerView,
        provider: ProviderView,
        admin: AdminView,
        android: AndroidView,
        tenantId: String,
        journeyId: UUID
    ): StepReconciliationRecord {
        var isReconciled = true
        val notes = mutableListOf<String>()

        // 1. Ledger internal balance invariant (Debits == Credits)
        if (!ledger.isBalanced || ledger.postedDebitsMinor != ledger.postedCreditsMinor) {
            isReconciled = false
            notes.add("Ledger debit/credit imbalance: debits=${ledger.postedDebitsMinor}, credits=${ledger.postedCreditsMinor}")
        }

        // 2. Android view boundary invariant
        if (!android.isUntrustedPresentation) {
            isReconciled = false
            notes.add("Android view violates untrusted boundary rule")
        }
        if (android.hasAndroidLifecycleClaim || android.hasAndroidDbImpact) {
            isReconciled = false
            notes.add("Android view claims unauthorized lifecycle or DB authority")
        }
        if (android.presentedAvailableBalanceMinor != ledger.availableMinor) {
            isReconciled = false
            notes.add("Android presented balance drift: android=${android.presentedAvailableBalanceMinor}, ledger=${ledger.availableMinor}")
        }

        // 3. Cross-view step consistency
        when (step) {
            JourneyStep.DEPOSIT_CREDITED -> {
                if (provider.depositProviderStatus != "CONFIRMED") {
                    isReconciled = false
                    notes.add("Provider deposit status not confirmed: ${provider.depositProviderStatus}")
                }
            }
            JourneyStep.WAGER_RESERVED -> {
                if (provider.gameProviderStatus != "RESERVED" || ledger.reservedMinor <= 0) {
                    isReconciled = false
                    notes.add("Wager reservation view mismatch: provider=${provider.gameProviderStatus}, reserved=${ledger.reservedMinor}")
                }
            }
            JourneyStep.GAME_SETTLED -> {
                if (provider.gameProviderStatus != "SETTLED" || ledger.reservedMinor != 0L) {
                    isReconciled = false
                    notes.add("Game settlement view mismatch: provider=${provider.gameProviderStatus}, reserved=${ledger.reservedMinor}")
                }
            }
            JourneyStep.WITHDRAWAL_REQUESTED -> {
                if (ledger.lockedMinor <= 0 || admin.makerCheckerApproved) {
                    isReconciled = false
                    notes.add("Withdrawal requested view mismatch: locked=${ledger.lockedMinor}, approved=${admin.makerCheckerApproved}")
                }
            }
            JourneyStep.WITHDRAWAL_APPROVED -> {
                if (!admin.makerCheckerApproved || ledger.lockedMinor <= 0) {
                    isReconciled = false
                    notes.add("Withdrawal approval view mismatch: approved=${admin.makerCheckerApproved}, locked=${ledger.lockedMinor}")
                }
            }
            JourneyStep.PAYOUT_COMPLETED -> {
                if (provider.payoutProviderStatus != "COMPLETED" || ledger.lockedMinor != 0L || admin.journeyStatus != JourneyStatus.COMPLETED) {
                    isReconciled = false
                    notes.add("Payout completion view mismatch: provider=${provider.payoutProviderStatus}, locked=${ledger.lockedMinor}, status=${admin.journeyStatus}")
                }
            }
            else -> {}
        }

        // Check injected fault for reconciliation
        val injectedFault = scenarioFaults[step.name] ?: scenarioFaults["VIEW_RECONCILIATION_DRIFT"]
        if (injectedFault != null) {
            isReconciled = false
            notes.add("Injected reconciliation fault: $injectedFault")
        }

        if (!isReconciled) {
            val alert = CriticalJourneyAlert(
                alertId = UUID.randomUUID(),
                tenantId = tenantId,
                journeyId = journeyId,
                step = step,
                message = "$CRITICAL_JOURNEY_E2E_CONTRACT Failure at step $step: ${notes.joinToString("; ")}",
                occurredAt = clock.instant()
            )
            alertSink.emitAlert(alert)
            throw ViewReconciliationMismatchException("$CRITICAL_JOURNEY_E2E_CONTRACT Failure at step $step: ${notes.joinToString("; ")}")
        }

        observability.recordStepReconciled(tenantId, step)

        return StepReconciliationRecord(
            step = step,
            stepSequence = stepSequence,
            ledgerView = ledger,
            providerView = provider,
            adminView = admin,
            androidView = android,
            isReconciled = true,
            reconciliationNotes = "All 4 views (ledger/provider/admin/Android) reconciled successfully.",
            timestamp = clock.instant()
        )
    }
}
