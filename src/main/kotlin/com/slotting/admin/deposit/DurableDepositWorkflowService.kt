package com.slotting.admin.deposit

import com.slotting.admin.auth.*
import com.slotting.admin.ledger.*
import com.slotting.admin.provider.*
import com.slotting.admin.provider.port.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

open class DurableDepositWorkflowService(
    private val workflowStore: DepositWorkflowStore,
    private val paymentMethodStore: PaymentMethodStore,
    private val sessions: AdminSessionDirectory,
    private val ledgerPostingService: LedgerPostingService,
    private val providerPorts: Map<String, PaymentProviderPort> = emptyMap(),
    private val credentialsResolver: (tenantId: String, providerId: String) -> ProviderCredentials? = { _, _ -> null },
    private val configResolver: (tenantId: String, providerId: String) -> ProviderConfiguration? = { _, _ -> null },
    private val clock: Clock = Clock.systemUTC(),
) {
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
        val port = providerPorts[method.providerId]
            ?: throw IllegalStateException("Payment provider port '${method.providerId}' is not configured")

        val config = configResolver(command.tenantId, method.providerId)
            ?: ProviderConfiguration(
                providerId = method.providerId,
                environment = ProviderEnvironment.SANDBOX,
                baseUrl = "https://sandbox.api.test/v1",
            )
        val credentials = credentialsResolver(command.tenantId, method.providerId)

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

    open fun processCallback(command: DepositCallbackCommand): DepositCallbackResult {
        // 1. Locate provider port
        val port = providerPorts[command.providerId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val config = configResolver(command.tenantId, command.providerId)
            ?: ProviderConfiguration(
                providerId = command.providerId,
                environment = ProviderEnvironment.SANDBOX,
                baseUrl = "https://sandbox.api.test/v1",
            )
        val credentials = credentialsResolver(command.tenantId, command.providerId)

        // 2. Cryptographically verify signature
        val payload = ProviderCallbackPayload(
            providerId = command.providerId,
            rawBody = command.rawBody,
            headers = command.headers,
            queryParams = command.queryParams,
        )

        val verification = port.verifyCallback(payload, config, credentials)
        if (!verification.isValid) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Deduplicate in inbox
        val payloadHash = sha256(command.rawBody)
        val inboxRecord = DepositInboxRecord(
            inboxId = UUID.randomUUID(),
            tenantId = command.tenantId,
            providerId = command.providerId,
            providerEventId = command.providerEventId,
            intentId = verification.operationId,
            status = "RECEIVED",
            signatureVerified = true,
            payloadHash = payloadHash,
            receivedAt = clock.instant(),
            processedAt = null,
        )
        val isNewInboxEvent = workflowStore.recordInboxEvent(inboxRecord)

        // 4. Resolve associated deposit intent
        val candidateIntent = when {
            verification.providerReference != null ->
                workflowStore.findIntentByProviderReference(command.tenantId, verification.providerReference!!)
                    ?: verification.operationId?.let { workflowStore.findIntent(command.tenantId, it) }
            verification.operationId != null ->
                workflowStore.findIntent(command.tenantId, verification.operationId!!)
            else -> null
        } ?: throw IllegalStateException("Could not match callback to an existing deposit intent")

        // 5. Concurrency-safe, exactly-once ledger credit under per-intent lock
        synchronized(getOrCreateLock(candidateIntent.intentId)) {
            val currentIntent = workflowStore.findIntent(candidateIntent.tenantId, candidateIntent.intentId)
                ?: candidateIntent

            // If already settled, idempotent return with existing ledger reference
            if (currentIntent.status == DepositIntentStatus.SETTLED) {
                return DepositCallbackResult(
                    intentId = currentIntent.intentId,
                    providerTransactionId = currentIntent.providerReference,
                    status = DepositIntentStatus.SETTLED,
                    alreadyProcessed = true,
                    ledgerTransactionReference = currentIntent.ledgerTransactionReference,
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
                        accountReference = "player:wallet:${currentIntent.playerId}",
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
                ?: throw IllegalStateException("Payment provider port '${currentIntent.providerId}' is not configured")

            val config = configResolver(command.tenantId, currentIntent.providerId)
                ?: ProviderConfiguration(
                    providerId = currentIntent.providerId,
                    environment = ProviderEnvironment.SANDBOX,
                    baseUrl = "https://sandbox.api.test/v1",
                )
            val credentials = credentialsResolver(command.tenantId, currentIntent.providerId)

            val query = ProviderStatusQuery(
                tenantId = command.tenantId,
                operationId = currentIntent.intentId,
                providerId = currentIntent.providerId,
                providerReference = currentIntent.providerReference,
                idempotencyKey = currentIntent.idempotencyKey,
            )

            val outcome = try {
                port.queryStatus(query, config, credentials)
            } catch (e: Exception) {
                ProviderOutcome.ambiguous(
                    operationId = currentIntent.intentId,
                    code = "QUERY_EXCEPTION",
                    reason = e.message ?: "Exception querying status",
                )
            }

            val previousStatus = currentIntent.status
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
                                accountReference = "player:wallet:${currentIntent.playerId}",
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
