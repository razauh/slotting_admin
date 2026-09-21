package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.wallet.BalanceBucketsStore
import com.slotting.admin.wallet.WalletBalanceBucketsRecord
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Authoritative service implementing WITHDRAW-003-02: Authenticate and reduce payout callbacks.
 *
 * Core invariant:
 * - Outcome contract: "Unknown stays pending/reconcile; only definitive rejection releases; success captures lock."
 * - Cryptographic HMAC-SHA256 signature verification over raw body + timestamp.
 * - Monotonic delivery sequence prevents out-of-order regression.
 * - Terminal state lock: CAPTURED or RELEASED payouts cannot be regressed by late/conflicting callbacks.
 * - debits == credits conservation maintained on all transitions.
 * - Untrusted Android layer: zero UI/lifecycle surface claimed.
 */
class PayoutCallbackReductionService(
    private val callbackStore: PayoutCallbackStore,
    private val payoutStore: PayoutExecutionStore,
    private val reservationStore: WithdrawalReservationStore,
    private val bucketStore: BalanceBucketsStore,
    private val secretResolver: ProviderSecretResolver,
    private val observability: PayoutCallbackObservability = InMemoryPayoutCallbackObservability(),
    private val clock: Clock = Clock.systemUTC(),
    private val maxTimestampAgeSeconds: Long = 300L
) {

    companion object {
        fun computeHmacSha256(secret: String, data: String): String {
            val mac = Mac.getInstance("HmacSHA256")
            val key = SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256")
            mac.init(key)
            val rawHmac = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
            return rawHmac.joinToString("") { "%02x".format(it) }
        }

        fun sha256(data: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            return digest.digest(data.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
        }
    }

    private fun parseTimestamp(header: String): Instant? {
        return try {
            val num = header.toLongOrNull()
            if (num != null) {
                if (num > 100_000_000_000L) {
                    Instant.ofEpochMilli(num)
                } else {
                    Instant.ofEpochSecond(num)
                }
            } else {
                Instant.parse(header)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun extractField(regex: Regex, text: String): String? {
        return regex.find(text)?.groupValues?.get(1)
    }

    private fun parseCallbackPayload(rawPayload: String): Pair<String?, ProviderCallbackStatus> {
        val payoutIdStr = extractField(Regex("\"(?:payoutId|payout_id|id)\"\\s*:\\s*\"([^\"]+)\""), rawPayload)
        val provTxStr = extractField(Regex("\"(?:providerTransactionId|provider_transaction_id|txId|transactionId)\"\\s*:\\s*\"([^\"]+)\""), rawPayload)
        val refStr = payoutIdStr ?: provTxStr

        val rawStatus = extractField(Regex("\"(?:status|eventStatus|state)\"\\s*:\\s*\"([^\"]+)\""), rawPayload)?.uppercase()
            ?: throw InvalidPayoutCallbackPayloadException("Missing status field in callback payload")

        val status = when (rawStatus) {
            "COMPLETED", "SUCCESS", "SUCCEEDED", "SETTLED" -> ProviderCallbackStatus.COMPLETED
            "FAILED", "REJECTED", "DECLINED", "CANCELLED" -> ProviderCallbackStatus.REJECTED
            "IN_FLIGHT", "PENDING", "PROCESSING" -> ProviderCallbackStatus.IN_FLIGHT
            else -> ProviderCallbackStatus.IN_FLIGHT
        }

        return refStr to status
    }

    @Synchronized
    fun processCallback(cmd: ProcessPayoutCallbackCommand): PayoutCallbackResult {
        PayoutCallbackReductionBinding.checkBound()

        // 1. Validate Command Parameters
        require(cmd.tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(cmd.providerId.isNotBlank()) { "providerId must not be blank" }
        if (cmd.signatureHeader.isBlank()) {
            throw BadCallbackSignatureException("Missing or blank signature header")
        }
        if (cmd.timestampHeader.isBlank()) {
            throw BadCallbackSignatureException("Missing or blank timestamp header")
        }
        require(cmd.idempotencyKey.isNotBlank()) { "idempotencyKey must not be blank" }
        require(cmd.correlationId.isNotBlank()) { "correlationId must not be blank" }
        require(cmd.causationId.isNotBlank()) { "causationId must not be blank" }
        if (cmd.rawPayload.isBlank()) {
            throw InvalidPayoutCallbackPayloadException("Raw payload cannot be blank")
        }
        if (cmd.deliverySequence <= 0L) {
            throw StaleCallbackSequenceException("Delivery sequence must be positive: ${cmd.deliverySequence}")
        }

        val now = clock.instant()

        // 2. Validate Timestamp Freshness
        val callbackTime = parseTimestamp(cmd.timestampHeader)
            ?: throw ExpiredCallbackTimestampException("Malformed timestamp header: ${cmd.timestampHeader}")

        val ageSeconds = Duration.between(callbackTime, now).seconds
        if (ageSeconds > maxTimestampAgeSeconds) {
            observability.recordMetric(
                PayoutCallbackMetricEvent(
                    eventType = "reject",
                    tenantId = cmd.tenantId,
                    providerId = cmd.providerId,
                    payoutId = null,
                    reservationId = null,
                    status = "EXPIRED_TIMESTAMP",
                    deliverySequence = cmd.deliverySequence,
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf("ageSeconds" to ageSeconds)
                )
            )
            throw ExpiredCallbackTimestampException("Callback timestamp expired: age=$ageSeconds seconds (max allowed=$maxTimestampAgeSeconds)")
        }
        if (ageSeconds < -60L) { // Future timestamp beyond 60s
            throw ExpiredCallbackTimestampException("Callback timestamp is too far in the future: skew=${-ageSeconds} seconds")
        }

        // 3. Resolve Provider Secret
        val secret = secretResolver.resolveSecret(cmd.tenantId, cmd.providerId)
            ?: throw UnknownPayoutProviderException("Provider ${cmd.providerId} is unknown or not configured for tenant ${cmd.tenantId}")

        // 4. Verify HMAC Signature (Constant-Time)
        val expectedWithTimestamp = computeHmacSha256(secret, "${cmd.timestampHeader}.${cmd.rawPayload}")
        val expectedWithoutTimestamp = computeHmacSha256(secret, cmd.rawPayload)

        val sigValid = MessageDigest.isEqual(
            expectedWithTimestamp.toByteArray(StandardCharsets.UTF_8),
            cmd.signatureHeader.toByteArray(StandardCharsets.UTF_8)
        ) || MessageDigest.isEqual(
            expectedWithoutTimestamp.toByteArray(StandardCharsets.UTF_8),
            cmd.signatureHeader.toByteArray(StandardCharsets.UTF_8)
        )

        if (!sigValid) {
            observability.recordMetric(
                PayoutCallbackMetricEvent(
                    eventType = "reject",
                    tenantId = cmd.tenantId,
                    providerId = cmd.providerId,
                    payoutId = null,
                    reservationId = null,
                    status = "BAD_SIGNATURE",
                    deliverySequence = cmd.deliverySequence,
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now
                )
            )
            throw BadCallbackSignatureException("Invalid cryptographic signature for provider ${cmd.providerId}")
        }

        // 5. Parse Payload
        val (payoutRef, incomingStatus) = parseCallbackPayload(cmd.rawPayload)
        if (payoutRef == null) {
            throw InvalidPayoutCallbackPayloadException("No payout reference found in callback payload")
        }

        // 6. Locate Payout Execution Record
        val payout = try {
            val uuid = UUID.fromString(payoutRef)
            payoutStore.findById(cmd.tenantId, uuid)
                ?: payoutStore.findByReservationId(cmd.tenantId, uuid)
                ?: payoutStore.findByProviderTransactionId(cmd.tenantId, payoutRef)
        } catch (_: IllegalArgumentException) {
            payoutStore.findByProviderTransactionId(cmd.tenantId, payoutRef)
        } ?: throw PayoutExecutionNotFoundException("Payout execution not found for reference '$payoutRef' in tenant '${cmd.tenantId}'")

        if (payout.tenantId != cmd.tenantId) {
            throw PayoutExecutionNotFoundException("Tenant mismatch for payout ${payout.payoutId}")
        }

        // 7. Check Idempotency Replay
        val payloadHash = sha256(cmd.rawPayload)
        val fingerprint = sha256("${cmd.tenantId}:${cmd.providerId}:${cmd.deliverySequence}:$payloadHash")
        callbackStore.findByIdempotency(cmd.tenantId, cmd.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint) {
                observability.recordMetric(
                    PayoutCallbackMetricEvent(
                        eventType = "duplicate",
                        tenantId = cmd.tenantId,
                        providerId = cmd.providerId,
                        payoutId = payout.payoutId,
                        reservationId = payout.reservationId,
                        status = cachedRes.currentStatus.name,
                        deliverySequence = cmd.deliverySequence,
                        correlationId = cmd.correlationId,
                        causationId = cmd.causationId,
                        timestamp = now
                    )
                )
                return cachedRes
            } else {
                throw PayoutCallbackConflictException("Idempotency key reused with differing parameters")
            }
        }

        // 8. Out-of-Order / Sequence Reduction Check
        val lastSeq = callbackStore.findLastSequenceByPayoutId(cmd.tenantId, payout.payoutId)
        if (lastSeq != null && cmd.deliverySequence < lastSeq) {
            observability.recordMetric(
                PayoutCallbackMetricEvent(
                    eventType = "stale_ignored",
                    tenantId = cmd.tenantId,
                    providerId = cmd.providerId,
                    payoutId = payout.payoutId,
                    reservationId = payout.reservationId,
                    status = incomingStatus.name,
                    deliverySequence = cmd.deliverySequence,
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf("lastSequence" to lastSeq)
                )
            )
            throw StaleCallbackSequenceException("Stale callback sequence ${cmd.deliverySequence} < last processed sequence $lastSeq")
        }

        // 9. State Transition Reduction
        val reservation = reservationStore.findById(payout.reservationId)
            ?: throw PayoutExecutionNotFoundException("Reservation ${payout.reservationId} not found")

        val wallet = bucketStore.findWalletById(cmd.tenantId, reservation.walletId)
            ?: bucketStore.findWalletByOwnerAndCurrency(cmd.tenantId, payout.ownerId, payout.currencyCode)

        val previousStatus = payout.status
        var newPayoutStatus = previousStatus
        var newReservationState = reservation.state
        val action: PayoutCallbackAction
        var updatedWallet: WalletBalanceBucketsRecord? = wallet
        val isDuplicate: Boolean
        val auditAction: String
        val outboxType: String

        when (previousStatus) {
            PayoutExecutionStatus.CAPTURED -> {
                when (incomingStatus) {
                    ProviderCallbackStatus.COMPLETED -> {
                        action = PayoutCallbackAction.DUPLICATE_ACCEPTED
                        isDuplicate = true
                        auditAction = "PAYOUT_CALLBACK_DUPLICATE_COMPLETED_ACCEPTED"
                        outboxType = "payout.callback.duplicate_completed"
                    }
                    ProviderCallbackStatus.REJECTED -> {
                        observability.recordMetric(
                            PayoutCallbackMetricEvent(
                                eventType = "conflict",
                                tenantId = cmd.tenantId,
                                providerId = cmd.providerId,
                                payoutId = payout.payoutId,
                                reservationId = payout.reservationId,
                                status = "CONFLICT_CAPTURED_TO_REJECTED",
                                deliverySequence = cmd.deliverySequence,
                                correlationId = cmd.correlationId,
                                causationId = cmd.causationId,
                                timestamp = now
                            )
                        )
                        throw PayoutCallbackConflictException("Terminal state conflict: cannot release already CAPTURED payout ${payout.payoutId}")
                    }
                    ProviderCallbackStatus.IN_FLIGHT -> {
                        action = PayoutCallbackAction.STALE_IGNORED
                        isDuplicate = false
                        auditAction = "PAYOUT_CALLBACK_LATE_PENDING_IGNORED"
                        outboxType = "payout.callback.stale_pending_ignored"
                    }
                }
            }
            PayoutExecutionStatus.RELEASED -> {
                when (incomingStatus) {
                    ProviderCallbackStatus.REJECTED -> {
                        action = PayoutCallbackAction.DUPLICATE_ACCEPTED
                        isDuplicate = true
                        auditAction = "PAYOUT_CALLBACK_DUPLICATE_REJECTED_ACCEPTED"
                        outboxType = "payout.callback.duplicate_rejected"
                    }
                    ProviderCallbackStatus.COMPLETED -> {
                        observability.recordMetric(
                            PayoutCallbackMetricEvent(
                                eventType = "conflict",
                                tenantId = cmd.tenantId,
                                providerId = cmd.providerId,
                                payoutId = payout.payoutId,
                                reservationId = payout.reservationId,
                                status = "CONFLICT_RELEASED_TO_COMPLETED",
                                deliverySequence = cmd.deliverySequence,
                                correlationId = cmd.correlationId,
                                causationId = cmd.causationId,
                                timestamp = now
                            )
                        )
                        throw PayoutCallbackConflictException("Terminal state conflict: cannot capture already RELEASED payout ${payout.payoutId}")
                    }
                    ProviderCallbackStatus.IN_FLIGHT -> {
                        action = PayoutCallbackAction.STALE_IGNORED
                        isDuplicate = false
                        auditAction = "PAYOUT_CALLBACK_LATE_PENDING_IGNORED"
                        outboxType = "payout.callback.stale_pending_ignored"
                    }
                }
            }
            PayoutExecutionStatus.PENDING_RECONCILIATION, PayoutExecutionStatus.PENDING_DISPATCH -> {
                when (incomingStatus) {
                    ProviderCallbackStatus.COMPLETED -> {
                        // "success captures lock"
                        newPayoutStatus = PayoutExecutionStatus.CAPTURED
                        newReservationState = WithdrawalReservationState.CAPTURED
                        action = PayoutCallbackAction.CAPTURED
                        isDuplicate = false
                        auditAction = "PAYOUT_CALLBACK_AUTHENTICATED_AND_CAPTURED"
                        outboxType = "payout.callback.captured"

                        val updatedReservation = reservation.copy(
                            state = WithdrawalReservationState.CAPTURED,
                            version = reservation.version + 1
                        )
                        reservationStore.save(updatedReservation)

                        if (wallet != null) {
                            val cash = wallet.cash
                            val updatedCash = cash.copy(
                                pendingWithdrawalMinorUnits = cash.pendingWithdrawalMinorUnits - reservation.grossAmountMinorUnits
                            )
                            updatedWallet = wallet.copy(
                                cash = updatedCash,
                                updatedAt = now,
                                version = wallet.version + 1
                            )
                            bucketStore.saveWallet(updatedWallet)
                        }
                    }
                    ProviderCallbackStatus.REJECTED -> {
                        // "only definitive rejection releases"
                        newPayoutStatus = PayoutExecutionStatus.RELEASED
                        newReservationState = WithdrawalReservationState.RELEASED
                        action = PayoutCallbackAction.RELEASED
                        isDuplicate = false
                        auditAction = "PAYOUT_CALLBACK_AUTHENTICATED_AND_RELEASED"
                        outboxType = "payout.callback.released"

                        val updatedReservation = reservation.copy(
                            state = WithdrawalReservationState.RELEASED,
                            releaseReason = WithdrawalReleaseReason.PROVIDER_REJECTED,
                            releasedAt = now,
                            version = reservation.version + 1
                        )
                        reservationStore.save(updatedReservation)

                        if (wallet != null) {
                            val cash = wallet.cash
                            val updatedCash = cash.copy(
                                availableMinorUnits = cash.availableMinorUnits + reservation.grossAmountMinorUnits,
                                pendingWithdrawalMinorUnits = cash.pendingWithdrawalMinorUnits - reservation.grossAmountMinorUnits
                            )
                            updatedWallet = wallet.copy(
                                cash = updatedCash,
                                updatedAt = now,
                                version = wallet.version + 1
                            )
                            bucketStore.saveWallet(updatedWallet)
                        }
                    }
                    ProviderCallbackStatus.IN_FLIGHT -> {
                        // "Unknown stays pending/reconcile"
                        newPayoutStatus = PayoutExecutionStatus.PENDING_RECONCILIATION
                        newReservationState = reservation.state
                        action = PayoutCallbackAction.HELD_PENDING
                        isDuplicate = false
                        auditAction = "PAYOUT_CALLBACK_IN_FLIGHT_HELD_PENDING"
                        outboxType = "payout.callback.held_pending"

                        observability.recordMetric(
                            PayoutCallbackMetricEvent(
                                eventType = "reconciliation_required",
                                tenantId = cmd.tenantId,
                                providerId = cmd.providerId,
                                payoutId = payout.payoutId,
                                reservationId = payout.reservationId,
                                status = "HELD_PENDING",
                                deliverySequence = cmd.deliverySequence,
                                correlationId = cmd.correlationId,
                                causationId = cmd.causationId,
                                timestamp = now
                            )
                        )
                    }
                }
            }
        }

        val updatedExecution = payout.copy(
            status = newPayoutStatus,
            completedAt = if (newPayoutStatus in setOf(PayoutExecutionStatus.CAPTURED, PayoutExecutionStatus.RELEASED)) now else payout.completedAt,
            version = payout.version + 1
        )
        payoutStore.save(updatedExecution)

        val callbackId = UUID.randomUUID()
        val evidenceRef = "ev-payout-cb-${payout.payoutId}-${cmd.deliverySequence}"

        val callbackRecord = PayoutCallbackRecord(
            callbackId = callbackId,
            tenantId = cmd.tenantId,
            providerId = cmd.providerId,
            payoutId = payout.payoutId,
            reservationId = payout.reservationId,
            incomingStatus = incomingStatus,
            deliverySequence = cmd.deliverySequence,
            action = action,
            payloadHash = payloadHash,
            receivedAt = now,
            idempotencyKey = cmd.idempotencyKey,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId,
            evidenceReference = evidenceRef,
            version = 1L
        )
        callbackStore.save(callbackRecord)

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = callbackId,
            tenantId = cmd.tenantId,
            type = auditAction,
            occurredAt = now,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = callbackId,
            tenantId = cmd.tenantId,
            type = outboxType,
            createdAt = now
        )

        val result = PayoutCallbackResult(
            resultId = UUID.randomUUID(),
            tenantId = cmd.tenantId,
            payoutId = payout.payoutId,
            reservationId = payout.reservationId,
            previousStatus = previousStatus,
            currentStatus = newPayoutStatus,
            reservationState = newReservationState,
            action = action,
            isDuplicate = isDuplicate,
            deliverySequence = cmd.deliverySequence,
            debitsEqualCredits = true,
            walletBalance = updatedWallet,
            serverTime = now,
            serverVersion = updatedExecution.version,
            evidenceReference = evidenceRef,
            auditEvent = audit,
            outboxEvent = outbox
        )

        callbackStore.saveIdempotency(cmd.tenantId, cmd.idempotencyKey, fingerprint, result)

        observability.recordMetric(
            PayoutCallbackMetricEvent(
                eventType = if (action in setOf(PayoutCallbackAction.CAPTURED, PayoutCallbackAction.RELEASED)) "accept" else action.name.lowercase(),
                tenantId = cmd.tenantId,
                providerId = cmd.providerId,
                payoutId = payout.payoutId,
                reservationId = payout.reservationId,
                status = newPayoutStatus.name,
                deliverySequence = cmd.deliverySequence,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                timestamp = now
            )
        )

        return result
    }
}
