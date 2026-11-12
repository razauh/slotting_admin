package com.slotting.admin.deposit

import com.slotting.admin.auth.*
import com.slotting.admin.ledger.*
import com.slotting.admin.provider.*
import com.slotting.admin.provider.port.*
import com.slotting.admin.provider.port.KmsProviderCredentialsResolver
import com.slotting.admin.provider.port.ProviderCredentialVersionStatus
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import org.slf4j.LoggerFactory
import io.micrometer.core.instrument.MeterRegistry
import org.springframework.transaction.annotation.Transactional

open class DurableDepositWorkflowService(
    private val workflowStore: DepositWorkflowStore,
    private val paymentMethodStore: PaymentMethodStore,
    private val sessions: AdminSessionDirectory,
    private val ledgerPostingService: LedgerPostingService,
    private val providerPorts: Map<String, PaymentProviderPort> = emptyMap(),
    private val credentialsResolver: ProviderCredentialsResolver = ProviderCredentialsResolver { _, _ -> null },
    private val configResolver: (tenantId: String, providerId: String) -> ProviderConfiguration? = { _, _ -> null },
    private val clock: Clock = Clock.systemUTC(),
    private val reconciliationAlerts: DepositReconciliationAlertSink = InMemoryDepositReconciliationAlertSink(),
    private val meterRegistry: MeterRegistry? = null,
    val financialAudit: com.slotting.admin.observability.FinancialAuditProjector =
        com.slotting.admin.observability.NoOpFinancialAuditProjector,
    val testerGate: com.slotting.admin.observability.AlphaTesterGate = com.slotting.admin.observability.NoOpAlphaTesterGate,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val intentLocks = ConcurrentHashMap<UUID, Any>()

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(cmd: CreateDepositIntentCommand): String {
        return sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.methodId}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.customerIdentifier}:${cmd.methodExpectedVersion}")
    }

    private fun getOrCreateLock(intentId: UUID): Any =
        intentLocks.computeIfAbsent(intentId) { Any() }

    open fun createIntent(command: CreateDepositIntentCommand): CreateDepositIntentResult {
        testerGate.assertTesterAllowed(command.principal)
        // 1. Authentication check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        // 2. Tenant isolation
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Session validation
        val session = sessions.find(principal.tenantId, principal.id, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        val fp = fingerprint(command)

        // 4. Idempotency replay check before execution
        val existing = workflowStore.findIntentByIdempotencyKey(command.tenantId, command.idempotencyKey)
        if (existing != null) {
            if (existing.requestFingerprint != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return CreateDepositIntentResult(
                intentId = existing.intentId,
                tenantId = existing.tenantId,
                playerId = existing.playerId,
                methodId = existing.methodId,
                providerId = existing.providerId,
                amountMinorUnits = existing.amountMinorUnits,
                currencyCode = existing.currencyCode,
                status = existing.status,
                providerReference = existing.providerReference,
                redirectUrl = existing.redirectUrl,
                expiresAt = existing.expiresAt,
                createdAt = existing.createdAt,
            )
        }

        // 5. Authoritative payment method revalidation
        val evaluator = PaymentMethodAvailabilityEvaluator(paymentMethodStore, clock = clock)
        val method = evaluator.requireAvailable(
            tenantId = command.tenantId,
            subjectId = command.playerId.toString(),
            methodId = command.methodId,
            expectedVersion = command.methodExpectedVersion,
            transactionType = TransactionType.DEPOSIT,
            currency = command.currencyCode,
            amountMinorUnits = command.amountMinorUnits,
        )

        val port = providerPorts[method.providerId]
            ?: throw IllegalStateException("Payment provider port '${method.providerId}' is not configured")
        val config = resolveProviderConfiguration(command.tenantId, method.providerId)
        val credentials = resolveProviderCredentials(command.tenantId, method.providerId)
        if (!port.capabilities.supportsDeposit) {
            throw IllegalStateException("Payment provider port '${method.providerId}' does not declare deposit capability")
        }
        ProductionProviderGuard.assertProductionReady(port, config.environment.name)

        val intentId = UUID.randomUUID()
        val now = clock.instant()
        val expiresAt = now.plus(Duration.ofMinutes(15))

        // 6. Durable persistence of intent before dispatching to provider
        val initialRecord = DepositIntentRecord(
            intentId = intentId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            methodId = command.methodId,
            providerId = method.providerId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            status = DepositIntentStatus.DISPATCH_PENDING,
            idempotencyKey = command.idempotencyKey,
            requestFingerprint = fp,
            providerReference = null,
            providerCredentialVersion = (credentialsResolver as? KmsProviderCredentialsResolver)
                ?.listVersions(command.tenantId, method.providerId)
                ?.lastOrNull { it.status != ProviderCredentialVersionStatus.REVOKED }
                ?.credentialVersion,
            redirectUrl = null,
            clientSecret = null,
            failureReason = null,
            ledgerTransactionReference = null,
            settledAt = null,
            expiresAt = expiresAt,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )
        workflowStore.saveIntent(initialRecord)

        // 7. Dispatch to payment provider
        val providerCmd = ProviderDepositCommand(
            tenantId = command.tenantId,
            operationId = intentId,
            idempotencyKey = command.idempotencyKey,
            providerId = method.providerId,
            methodId = command.methodId,
            amountMinorUnits = command.amountMinorUnits,
            currency = command.currencyCode,
            customerIdentifier = command.customerIdentifier,
            callbackUrl = "https://api.slotting.internal/api/v1/tenants/${command.tenantId}/deposits/callback/${method.providerId}",
            correlationId = command.correlationId,
            metadata = mapOf(
                "intentId" to intentId.toString(),
                "playerId" to command.playerId.toString(),
            ),
        )

        val outcome = try {
            port.deposit(providerCmd, config, credentials)
        } catch (e: Exception) {
            ProviderOutcome.ambiguous(
                operationId = intentId,
                code = "DISPATCH_EXCEPTION",
                reason = e.message ?: "Exception during provider deposit dispatch",
            )
        }

        // 8. Transition intent based on provider outcome
        val (finalStatus, providerRef, redirectUrl, failureReason) = when (outcome.status) {
            ProviderOutcomeStatus.ACCEPTED, ProviderOutcomeStatus.PENDING -> {
                Quad(
                    DepositIntentStatus.PROVIDER_PENDING,
                    outcome.providerReference ?: "prov-ref-$intentId",
                    outcome.evidence["redirectUrl"] ?: outcome.evidence["approvalUrl"],
                    null,
                )
            }
            ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS, ProviderOutcomeStatus.UNAVAILABLE -> {
                Quad(
                    DepositIntentStatus.AMBIGUOUS_RECONCILING,
                    outcome.providerReference,
                    null,
                    outcome.safeReason ?: "Ambiguous response or provider unavailable",
                )
            }
            ProviderOutcomeStatus.DECLINED, ProviderOutcomeStatus.FAILED -> {
                Quad(
                    DepositIntentStatus.FAILED,
                    outcome.providerReference,
                    null,
                    outcome.safeReason ?: outcome.rawResponseCode ?: "Deposit declined by provider",
                )
            }
        }

        val updatedRecord = initialRecord.copy(
            status = finalStatus,
            providerReference = providerRef,
            redirectUrl = redirectUrl,
            failureReason = failureReason,
            serverVersion = initialRecord.serverVersion + 1,
            updatedAt = clock.instant(),
        )
        workflowStore.updateIntent(updatedRecord, expectedVersion = initialRecord.serverVersion)
        financialAudit.project(
            com.slotting.admin.observability.FinancialAuditEvent(
                tenantId = updatedRecord.tenantId,
                eventType = "DEPOSIT_INITIATED",
                outcome = when (updatedRecord.status) {
                    DepositIntentStatus.PROVIDER_PENDING -> com.slotting.admin.observability.FinancialAuditOutcome.PENDING
                    DepositIntentStatus.FAILED, DepositIntentStatus.AMBIGUOUS_RECONCILING -> com.slotting.admin.observability.FinancialAuditOutcome.FAILED
                    else -> com.slotting.admin.observability.FinancialAuditOutcome.INITIATED
                },
                correlationId = "corr-${updatedRecord.intentId}",
                paymentId = updatedRecord.intentId.toString(),
                providerReference = updatedRecord.providerReference,
                amountMinorUnits = updatedRecord.amountMinorUnits,
                currency = updatedRecord.currencyCode,
                safeDetail = "Deposit intent persisted before provider transport",
            )
        )

        return CreateDepositIntentResult(
            intentId = updatedRecord.intentId,
            tenantId = updatedRecord.tenantId,
            playerId = updatedRecord.playerId,
            methodId = updatedRecord.methodId,
            providerId = updatedRecord.providerId,
            amountMinorUnits = updatedRecord.amountMinorUnits,
            currencyCode = updatedRecord.currencyCode,
            status = updatedRecord.status,
            providerReference = updatedRecord.providerReference,
            redirectUrl = updatedRecord.redirectUrl,
            expiresAt = updatedRecord.expiresAt,
            createdAt = updatedRecord.createdAt,
        )
    }

    @Transactional
    open fun processCallback(command: DepositCallbackCommand): DepositCallbackResult {
        val providerEventId = command.providerEventId.trim()
        if (providerEventId.isEmpty() || providerEventId.length > 128) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        // 1. Locate provider port
        val port = providerPorts[command.providerId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val config = resolveProviderConfiguration(command.tenantId, command.providerId)
        if (config.callbackIpAllowlist.isNotEmpty() && command.sourceIp !in config.callbackIpAllowlist) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        ProductionProviderGuard.assertProductionReady(port, config.environment.name)

        // 2. Cryptographically verify signature against the bound credential version when available
        val payload = ProviderCallbackPayload(
            providerId = command.providerId,
            rawBody = command.rawBody,
            headers = command.headers,
            queryParams = command.queryParams,
        )

        var verification: CallbackVerificationResult? = null
        var verifiedCredentialVersion: Long? = null
        for ((version, credentials) in resolveCallbackCredentialCandidates(command.tenantId, command.providerId)) {
            val candidate = port.verifyCallback(payload, config, credentials)
            if (candidate.isValid) {
                verification = candidate
                verifiedCredentialVersion = version
                break
            }
        }
        val validVerification = verification
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // 4. Resolve associated deposit intent
        val candidateIntent = when {
            validVerification.providerReference != null ->
                workflowStore.findIntentByProviderReference(command.tenantId, validVerification.providerReference!!)
                    ?: validVerification.operationId?.let { workflowStore.findIntent(command.tenantId, it) }
            validVerification.operationId != null ->
                workflowStore.findIntent(command.tenantId, validVerification.operationId!!)
            else -> null
        } ?: throw IllegalStateException("Could not match callback to an existing deposit intent")

        if (candidateIntent.providerCredentialVersion != null && verifiedCredentialVersion != null &&
            candidateIntent.providerCredentialVersion != verifiedCredentialVersion
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Deduplicate in inbox
        val payloadIdentity = buildString {
            append(command.rawBody)
            command.queryParams.toSortedMap().forEach { (key, value) ->
                append('\n').append(key.length).append(':').append(key).append(value.length).append(':').append(value)
            }
        }
        val payloadHash = sha256(payloadIdentity)
        val inboxRecord = DepositInboxRecord(
            inboxId = UUID.randomUUID(),
            tenantId = command.tenantId,
            providerId = command.providerId,
            providerEventId = providerEventId,
            intentId = candidateIntent.intentId,
            status = "PROCESSING",
            signatureVerified = true,
            payloadHash = payloadHash,
            receivedAt = clock.instant(),
            processedAt = null,
        )
        val isNewInboxEvent = workflowStore.recordInboxEvent(inboxRecord)
        var ownsInboxClaim = isNewInboxEvent
        if (!isNewInboxEvent) {
            val existingInboxEvent = workflowStore.findInboxEvent(
                command.tenantId,
                command.providerId,
                providerEventId,
            ) ?: throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            if (existingInboxEvent.payloadHash != payloadHash || existingInboxEvent.intentId != candidateIntent.intentId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            ownsInboxClaim = when (existingInboxEvent.status) {
                "PROCESSED", "QUARANTINED" -> false
                "RECEIVED" -> workflowStore.claimInboxEvent(
                    command.tenantId,
                    command.providerId,
                    providerEventId,
                    "RECEIVED",
                    "PROCESSING",
                )
                else -> throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            if (!ownsInboxClaim && existingInboxEvent.status == "RECEIVED") {
                val latest = workflowStore.findInboxEvent(command.tenantId, command.providerId, providerEventId)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                if (latest.status !in setOf("PROCESSED", "QUARANTINED")) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                }
            }
        }

        // 5. Concurrency-safe, exactly-once ledger credit under per-intent lock
        synchronized(getOrCreateLock(candidateIntent.intentId)) {
            val currentIntent = workflowStore.findIntentForUpdate(candidateIntent.tenantId, candidateIntent.intentId)
                ?: throw IllegalStateException("Deposit intent ${candidateIntent.intentId} disappeared during callback processing")

            if (!ownsInboxClaim) {
                logger.info(
                    "deposit_callback_replay provider={} eventId={} intentId={} status={} ledgerReference={}",
                    command.providerId,
                    providerEventId,
                    currentIntent.intentId,
                    currentIntent.status,
                    currentIntent.ledgerTransactionReference,
                )
                financialAudit.project(
                    com.slotting.admin.observability.FinancialAuditEvent(
                        tenantId = currentIntent.tenantId,
                        eventType = "DEPOSIT_CALLBACK_REPLAYED",
                        outcome = com.slotting.admin.observability.FinancialAuditOutcome.REPLAYED,
                        correlationId = "corr-${currentIntent.intentId}",
                        paymentId = currentIntent.intentId.toString(),
                        providerReference = currentIntent.providerReference,
                        ledgerReference = currentIntent.ledgerTransactionReference,
                        amountMinorUnits = currentIntent.amountMinorUnits,
                        currency = currentIntent.currencyCode,
                        safeDetail = "Replayed verified callback returned the committed ledger reference without a second credit",
                    )
                )
                return DepositCallbackResult(
                    intentId = currentIntent.intentId,
                    providerTransactionId = currentIntent.providerReference,
                    status = currentIntent.status,
                    alreadyProcessed = true,
                    ledgerTransactionReference = currentIntent.ledgerTransactionReference,
                )
            }

            // If already settled, idempotent return with existing ledger reference
            if (currentIntent.status == DepositIntentStatus.SETTLED) {
                workflowStore.updateInboxEvent(inboxRecord.copy(status = "PROCESSED", processedAt = clock.instant()))
                financialAudit.project(
                    com.slotting.admin.observability.FinancialAuditEvent(
                        tenantId = currentIntent.tenantId,
                        eventType = "DEPOSIT_CALLBACK_REPLAYED",
                        outcome = com.slotting.admin.observability.FinancialAuditOutcome.REPLAYED,
                        correlationId = "corr-${currentIntent.intentId}",
                        paymentId = currentIntent.intentId.toString(),
                        providerReference = currentIntent.providerReference,
                        ledgerReference = currentIntent.ledgerTransactionReference,
                        amountMinorUnits = currentIntent.amountMinorUnits,
                        currency = currentIntent.currencyCode,
                        safeDetail = "Replayed verified callback returned the committed ledger reference without a second credit",
                    )
                )
                return DepositCallbackResult(
                    intentId = currentIntent.intentId,
                    providerTransactionId = currentIntent.providerReference,
                    status = DepositIntentStatus.SETTLED,
                    alreadyProcessed = true,
                    ledgerTransactionReference = currentIntent.ledgerTransactionReference,
                )
            }

            if (currentIntent.status == DepositIntentStatus.QUARANTINED) {
                workflowStore.updateInboxEvent(inboxRecord.copy(status = "QUARANTINED", processedAt = clock.instant()))
                return DepositCallbackResult(
                    intentId = currentIntent.intentId,
                    providerTransactionId = currentIntent.providerReference,
                    status = DepositIntentStatus.QUARANTINED,
                    alreadyProcessed = true,
                    ledgerTransactionReference = currentIntent.ledgerTransactionReference,
                )
            }

            val evidence = validVerification.outcome?.evidence.orEmpty()
            val receivedAmount = evidence["amountMinorUnits"]?.toLongOrNull()
            val receivedCurrency = evidence["currency"]
            val receivedStatus = evidence["status"] ?: evidence["responseCode"] ?: validVerification.outcome?.rawResponseCode
            val successStatuses = setOf("PAID", "SUCCESS", "SUCCEEDED", "SETTLED", "RTP_SETTLED", "000")
            val reason = when {
                receivedStatus.isNullOrBlank() || !successStatuses.contains(receivedStatus.uppercase()) -> "CALLBACK_STATUS_NOT_SUCCESS"
                receivedAmount == null || receivedAmount <= 0L -> "CALLBACK_AMOUNT_MISSING_OR_INVALID"
                receivedAmount != currentIntent.amountMinorUnits -> "CALLBACK_AMOUNT_MISMATCH"
                receivedCurrency.isNullOrBlank() -> "CALLBACK_CURRENCY_MISSING"
                !receivedCurrency.equals(currentIntent.currencyCode, ignoreCase = true) -> "CALLBACK_CURRENCY_MISMATCH"
                else -> null
            }
            if (reason != null) {
                val detail = "expectedAmount=${currentIntent.amountMinorUnits},receivedAmount=${receivedAmount ?: "missing"},expectedCurrency=${currentIntent.currencyCode},receivedCurrency=${receivedCurrency ?: "missing"},receivedStatus=${receivedStatus ?: "missing"}"
                val quarantined = currentIntent.copy(
                    status = DepositIntentStatus.QUARANTINED,
                    failureReason = "$reason:$detail",
                    serverVersion = currentIntent.serverVersion + 1,
                    updatedAt = clock.instant(),
                )
                workflowStore.updateIntent(quarantined, expectedVersion = currentIntent.serverVersion)
                workflowStore.recordReconciliation(
                    DepositReconciliationRecord(
                        reconciliationId = UUID.randomUUID(),
                        tenantId = currentIntent.tenantId,
                        intentId = currentIntent.intentId,
                        actionType = "CALLBACK_QUARANTINED",
                        previousStatus = currentIntent.status,
                        newStatus = DepositIntentStatus.QUARANTINED,
                        performedBy = "provider:${command.providerId}",
                        occurredAt = clock.instant(),
                        notes = "$reason:$detail",
                    )
                )
                reconciliationAlerts.sendAlert(currentIntent.tenantId, currentIntent.intentId, reason, detail)
                workflowStore.updateInboxEvent(inboxRecord.copy(status = "QUARANTINED", processedAt = clock.instant()))
                financialAudit.project(
                    com.slotting.admin.observability.FinancialAuditEvent(
                        tenantId = quarantined.tenantId,
                        eventType = "DEPOSIT_CALLBACK_MISMATCH",
                        outcome = com.slotting.admin.observability.FinancialAuditOutcome.MISMATCH,
                        correlationId = "corr-${quarantined.intentId}",
                        paymentId = quarantined.intentId.toString(),
                        providerReference = quarantined.providerReference,
                        amountMinorUnits = quarantined.amountMinorUnits,
                        currency = quarantined.currencyCode,
                        safeDetail = "$reason:${quarantined.failureReason ?: ""}".take(200),
                        severity = com.slotting.admin.observability.DiagnosticEventSeverity.WARN,
                    )
                )
                return DepositCallbackResult(
                    intentId = quarantined.intentId,
                    providerTransactionId = quarantined.providerReference,
                    status = DepositIntentStatus.QUARANTINED,
                    alreadyProcessed = false,
                    ledgerTransactionReference = null,
                )
            }

            // Post double-entry transaction to authoritative ledger
            val ledgerTxRef = "TX-DEP-${currentIntent.intentId}"
            val adminPrincipal = AuthenticatedPrincipal(
                id = "sys-deposit-workflow",
                tenantId = currentIntent.tenantId,
                kind = PrincipalKind.ADMIN,
                roles = setOf(AdminRole.SUPER_ADMIN),
            )

            val postCmd = PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = currentIntent.tenantId,
                transactionReference = ledgerTxRef,
                currencyCode = currentIntent.currencyCode,
                entries = listOf(
                    JournalEntryDraft(
                        accountReference = "gateway:clearing:${currentIntent.providerId}",
                        direction = JournalEntryDirection.DEBIT,
                        amountMinorUnits = currentIntent.amountMinorUnits,
                        currencyCode = currentIntent.currencyCode,
                        narration = "Deposit gateway clearing debit for intent ${currentIntent.intentId}",
                    ),
                    JournalEntryDraft(
                        accountReference = "PLAYER:${currentIntent.playerId}",
                        direction = JournalEntryDirection.CREDIT,
                        amountMinorUnits = currentIntent.amountMinorUnits,
                        currencyCode = currentIntent.currencyCode,
                        narration = "Deposit wallet credit for intent ${currentIntent.intentId}",
                    ),
                ),
                idempotencyKey = "LEDGER-DEP-${currentIntent.intentId}",
                correlationId = "corr-${currentIntent.intentId}",
                causationId = "caus-${currentIntent.intentId}",
            )

            val postingResult = ledgerPostingService.postTransaction(postCmd)
            financialAudit.project(
                com.slotting.admin.observability.FinancialAuditEvent(
                    tenantId = currentIntent.tenantId,
                    eventType = "DEPOSIT_CREDITED",
                    outcome = com.slotting.admin.observability.FinancialAuditOutcome.CONFIRMED,
                    correlationId = "corr-${currentIntent.intentId}",
                    paymentId = currentIntent.intentId.toString(),
                    operationId = validVerification.providerReference,
                    providerReference = currentIntent.providerReference,
                    ledgerReference = postingResult.transactionReference,
                    amountMinorUnits = currentIntent.amountMinorUnits,
                    currency = currentIntent.currencyCode,
                    safeDetail = "Verified callback credited the wallet through the authoritative ledger",
                )
            )

            // Update intent to SETTLED
            val settledRecord = currentIntent.copy(
                status = DepositIntentStatus.SETTLED,
                settledAt = clock.instant(),
                ledgerTransactionReference = postingResult.transactionReference,
                serverVersion = currentIntent.serverVersion + 1,
                updatedAt = clock.instant(),
            )
            workflowStore.updateIntent(settledRecord, expectedVersion = currentIntent.serverVersion)

            // Mark inbox event as processed
            workflowStore.updateInboxEvent(
                inboxRecord.copy(status = "PROCESSED", processedAt = clock.instant())
            )

            return DepositCallbackResult(
                intentId = settledRecord.intentId,
                providerTransactionId = settledRecord.providerReference,
                status = DepositIntentStatus.SETTLED,
                alreadyProcessed = false,
                ledgerTransactionReference = postingResult.transactionReference,
            )
        }
    }

    open fun reconcile(command: DepositReconciliationCommand): DepositReconciliationResult {
        // 1. Authorize principal
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = sessions.find(principal.tenantId, principal.id, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        // 2. Locate intent
        val candidateIntent = workflowStore.findIntent(command.tenantId, command.intentId)
            ?: throw IllegalArgumentException("Deposit intent ${command.intentId} not found")

        synchronized(getOrCreateLock(candidateIntent.intentId)) {
            val currentIntent = workflowStore.findIntent(candidateIntent.tenantId, candidateIntent.intentId)
                ?: candidateIntent

            if (currentIntent.status == DepositIntentStatus.SETTLED) {
                return DepositReconciliationResult(
                    intentId = currentIntent.intentId,
                    previousStatus = DepositIntentStatus.SETTLED,
                    status = DepositIntentStatus.SETTLED,
                    actionTaken = "ALREADY_SETTLED",
                    ledgerTransactionReference = currentIntent.ledgerTransactionReference,
                )
            }

            // 3. Query status from provider port
            val port = providerPorts[currentIntent.providerId]

            val config = resolveProviderConfiguration(command.tenantId, currentIntent.providerId)
            val credentials = resolveProviderCredentialsForIntent(currentIntent)

            val query = ProviderStatusQuery(
                tenantId = command.tenantId,
                operationId = currentIntent.intentId,
                providerId = currentIntent.providerId,
                providerReference = currentIntent.providerReference,
                idempotencyKey = currentIntent.idempotencyKey,
                expectedAmountMinorUnits = currentIntent.amountMinorUnits,
                expectedCurrency = currentIntent.currencyCode,
            )

            val outcome = if (port == null) {
                ProviderOutcome.unavailable(
                    operationId = currentIntent.intentId,
                    reason = "Provider status adapter is not configured",
                    code = "STATUS_ADAPTER_UNAVAILABLE",
                )
            } else if (runCatching {
                    ProductionProviderGuard.assertProductionReady(port, config.environment.name)
                }.isFailure
            ) {
                ProviderOutcome.unavailable(
                    operationId = currentIntent.intentId,
                    reason = "Provider status adapter is not certified for production settlement",
                    code = "PROVIDER_NOT_PRODUCTION_READY",
                )
            } else {
                try {
                    port.queryStatus(query, config, credentials)
                } catch (e: Exception) {
                    ProviderOutcome.ambiguous(
                        operationId = currentIntent.intentId,
                        code = "QUERY_EXCEPTION",
                        reason = e.message ?: "Exception querying status",
                    )
                }
            }

            val previousStatus = currentIntent.status
            if (outcome.status == ProviderOutcomeStatus.ACCEPTED) {
                val proof = outcome.verifiedStatus
                val mismatch = when {
                    proof == null -> null
                    outcome.operationId != currentIntent.intentId -> "STATUS_OPERATION_MISMATCH"
                    !proof.signatureVerified -> "STATUS_SIGNATURE_INVALID"
                    proof.providerReference.isBlank() -> "STATUS_REFERENCE_MISSING"
                    outcome.providerReference != proof.providerReference -> "STATUS_REFERENCE_UNBOUND"
                    currentIntent.providerReference != null && currentIntent.providerReference != proof.providerReference -> "STATUS_REFERENCE_MISMATCH"
                    proof.amountMinorUnits != currentIntent.amountMinorUnits -> "STATUS_AMOUNT_MISMATCH"
                    !proof.currency.equals(currentIntent.currencyCode, ignoreCase = true) -> "STATUS_CURRENCY_MISMATCH"
                    else -> null
                }
                if (proof == null || mismatch != null) {
                    val quarantine = proof != null
                    val reason = mismatch ?: "STATUS_EVIDENCE_UNVERIFIED"
                    reconciliationAlerts.sendAlert(command.tenantId, currentIntent.intentId, reason, outcome.safeReason)
                    logger.error("Deposit reconciliation blocked for intent {}: {}", currentIntent.intentId, reason)
                    val nextStatus = if (quarantine) DepositIntentStatus.QUARANTINED else currentIntent.status
                    if (quarantine) {
                        workflowStore.updateIntent(
                            currentIntent.copy(
                                status = nextStatus,
                                failureReason = reason,
                                serverVersion = currentIntent.serverVersion + 1,
                                updatedAt = clock.instant(),
                            ),
                            expectedVersion = currentIntent.serverVersion,
                        )
                    }
                    workflowStore.recordReconciliation(
                        DepositReconciliationRecord(
                            reconciliationId = UUID.randomUUID(),
                            tenantId = command.tenantId,
                            intentId = currentIntent.intentId,
                            actionType = if (quarantine) "QUARANTINED_STATUS_MISMATCH" else "INQUIRY_REMAINS_UNVERIFIED",
                            previousStatus = previousStatus,
                            newStatus = nextStatus,
                            performedBy = principal.id,
                            occurredAt = clock.instant(),
                            notes = reason,
                        )
                    )
                    return DepositReconciliationResult(
                        intentId = currentIntent.intentId,
                        previousStatus = previousStatus,
                        status = nextStatus,
                        actionTaken = if (quarantine) "QUARANTINED_STATUS_MISMATCH" else "INQUIRY_REMAINS_UNVERIFIED",
                        ledgerTransactionReference = null,
                    )
                }
            } else if (outcome.status == ProviderOutcomeStatus.UNAVAILABLE || outcome.status == ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS) {
                reconciliationAlerts.sendAlert(command.tenantId, currentIntent.intentId, outcome.rawResponseCode ?: "STATUS_INQUIRY_UNAVAILABLE", outcome.safeReason)
                logger.error("Deposit reconciliation inquiry unavailable for intent {}: {}", currentIntent.intentId, outcome.rawResponseCode)
            }
            return when (outcome.status) {
                ProviderOutcomeStatus.ACCEPTED -> {
                    // Provider confirms payment settled: post ledger credit
                    val ledgerTxRef = "TX-DEP-${currentIntent.intentId}"
                    val adminPrincipal = AuthenticatedPrincipal(
                        id = "sys-deposit-reconcile",
                        tenantId = currentIntent.tenantId,
                        kind = PrincipalKind.ADMIN,
                        roles = setOf(AdminRole.SUPER_ADMIN),
                    )

                    val postCmd = PostTransactionCommand(
                        principal = adminPrincipal,
                        tenantId = currentIntent.tenantId,
                        transactionReference = ledgerTxRef,
                        currencyCode = currentIntent.currencyCode,
                        entries = listOf(
                            JournalEntryDraft(
                                accountReference = "gateway:clearing:${currentIntent.providerId}",
                                direction = JournalEntryDirection.DEBIT,
                                amountMinorUnits = currentIntent.amountMinorUnits,
                                currencyCode = currentIntent.currencyCode,
                                narration = "Deposit reconciliation debit for intent ${currentIntent.intentId}",
                            ),
                            JournalEntryDraft(
                                accountReference = "PLAYER:${currentIntent.playerId}",
                                direction = JournalEntryDirection.CREDIT,
                                amountMinorUnits = currentIntent.amountMinorUnits,
                                currencyCode = currentIntent.currencyCode,
                                narration = "Deposit reconciliation credit for intent ${currentIntent.intentId}",
                            ),
                        ),
                        idempotencyKey = "LEDGER-DEP-${currentIntent.intentId}",
                        correlationId = "corr-${currentIntent.intentId}",
                        causationId = "caus-${currentIntent.intentId}",
                    )

                    val postingResult = ledgerPostingService.postTransaction(postCmd)

                    val settledRecord = currentIntent.copy(
                        status = DepositIntentStatus.SETTLED,
                        providerReference = outcome.providerReference ?: currentIntent.providerReference,
                        settledAt = clock.instant(),
                        ledgerTransactionReference = postingResult.transactionReference,
                        serverVersion = currentIntent.serverVersion + 1,
                        updatedAt = clock.instant(),
                    )
                    workflowStore.updateIntent(settledRecord, expectedVersion = currentIntent.serverVersion)

                    workflowStore.recordReconciliation(
                        DepositReconciliationRecord(
                            reconciliationId = UUID.randomUUID(),
                            tenantId = command.tenantId,
                            intentId = currentIntent.intentId,
                            actionType = "SETTLED_VIA_RECONCILIATION",
                            previousStatus = previousStatus,
                            newStatus = DepositIntentStatus.SETTLED,
                            performedBy = principal.id,
                            occurredAt = clock.instant(),
                            notes = command.reason,
                        )
                    )

                    DepositReconciliationResult(
                        intentId = currentIntent.intentId,
                        previousStatus = previousStatus,
                        status = DepositIntentStatus.SETTLED,
                        actionTaken = "SETTLED_VIA_RECONCILIATION",
                        ledgerTransactionReference = postingResult.transactionReference,
                    )
                }

                ProviderOutcomeStatus.DECLINED, ProviderOutcomeStatus.FAILED -> {
                    val failedRecord = currentIntent.copy(
                        status = DepositIntentStatus.FAILED,
                        failureReason = outcome.safeReason ?: "Declined by provider upon status check",
                        serverVersion = currentIntent.serverVersion + 1,
                        updatedAt = clock.instant(),
                    )
                    workflowStore.updateIntent(failedRecord, expectedVersion = currentIntent.serverVersion)

                    workflowStore.recordReconciliation(
                        DepositReconciliationRecord(
                            reconciliationId = UUID.randomUUID(),
                            tenantId = command.tenantId,
                            intentId = currentIntent.intentId,
                            actionType = "FAILED_VIA_RECONCILIATION",
                            previousStatus = previousStatus,
                            newStatus = DepositIntentStatus.FAILED,
                            performedBy = principal.id,
                            occurredAt = clock.instant(),
                            notes = command.reason,
                        )
                    )

                    DepositReconciliationResult(
                        intentId = currentIntent.intentId,
                        previousStatus = previousStatus,
                        status = DepositIntentStatus.FAILED,
                        actionTaken = "FAILED_VIA_RECONCILIATION",
                        ledgerTransactionReference = null,
                    )
                }

                else -> {
                    // Ambiguous or still pending
                    workflowStore.recordReconciliation(
                        DepositReconciliationRecord(
                            reconciliationId = UUID.randomUUID(),
                            tenantId = command.tenantId,
                            intentId = currentIntent.intentId,
                            actionType = "INQUIRY_REMAINS_AMBIGUOUS",
                            previousStatus = previousStatus,
                            newStatus = currentIntent.status,
                            performedBy = principal.id,
                            occurredAt = clock.instant(),
                            notes = outcome.safeReason,
                        )
                    )

                    DepositReconciliationResult(
                        intentId = currentIntent.intentId,
                        previousStatus = previousStatus,
                        status = currentIntent.status,
                        actionTaken = "INQUIRY_REMAINS_AMBIGUOUS",
                        ledgerTransactionReference = null,
                    )
                }
            }
        }
    }

    private fun resolveProviderConfiguration(tenantId: String, providerId: String): ProviderConfiguration {
        val config = configResolver(tenantId, providerId)
            ?: run {
                logger.warn("deposit.config.missing tenantId={} providerId={}", tenantId, providerId)
                meterRegistry?.counter("deposit_config_fail_closed_total")?.increment()
                throw IllegalStateException("Provider configuration missing for tenant $tenantId")
            }
        require(config.providerId == providerId) { "Provider configuration does not match provider $providerId" }
        config.validateNetworkSafety()
        return config
    }

    private fun resolveProviderCredentials(tenantId: String, providerId: String): ProviderCredentials =
        credentialsResolver.resolveCredentials(tenantId, providerId)
            ?: run {
                logger.warn("deposit.credentials.missing tenantId={} providerId={}", tenantId, providerId)
                meterRegistry?.counter("deposit_credentials_fail_closed_total")?.increment()
                throw IllegalStateException("Provider credentials missing for tenant $tenantId")
            }

    private fun resolveProviderCredentialsForIntent(intent: DepositIntentRecord): ProviderCredentials {
        val version = intent.providerCredentialVersion
        val resolver = credentialsResolver
        if (version != null && resolver is KmsProviderCredentialsResolver) {
            resolver.resolveCredentials(intent.tenantId, intent.providerId, version)?.let { return it }
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        return resolveProviderCredentials(intent.tenantId, intent.providerId)
    }

    private fun resolveCallbackCredentialCandidates(
        tenantId: String,
        providerId: String,
    ): List<Pair<Long?, ProviderCredentials>> {
        val resolver = credentialsResolver
        if (resolver is KmsProviderCredentialsResolver) {
            val versions = resolver.listVersions(tenantId, providerId)
                .filter { it.status != ProviderCredentialVersionStatus.REVOKED }
            if (versions.isNotEmpty()) {
                return versions.mapNotNull { versioned ->
                    resolver.resolveCredentials(tenantId, providerId, versioned.credentialVersion)
                        ?.let { versioned.credentialVersion to it }
                }
            }
        }
        return listOf(null to resolveProviderCredentials(tenantId, providerId))
    }

    /**
     * Rejects all attempts to settle an intent or credit balances via Android/browser return URL.
     * The return URL is strictly presentation/informational; settlement requires authenticated
     * server webhook callback or authoritative reconciliation.
     */
    open fun handleClientReturn(
        tenantId: String,
        intentId: UUID,
        returnUrlParams: Map<String, String>,
        principal: AuthenticatedPrincipal?,
    ) {
        throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
    }

    open fun getIntent(
        tenantId: String,
        intentId: UUID,
        requestingPlayerId: UUID,
    ): DepositIntentRecord {
        val record = workflowStore.findIntent(tenantId, intentId)
            ?: throw IllegalArgumentException("Deposit intent $intentId not found")
        if (record.playerId != requestingPlayerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        return record
    }

    open fun getAdminIntent(
        tenantId: String,
        intentId: UUID,
    ): DepositIntentRecord {
        return workflowStore.findIntent(tenantId, intentId)
            ?: throw IllegalArgumentException("Deposit intent $intentId not found")
    }

    private data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
}
