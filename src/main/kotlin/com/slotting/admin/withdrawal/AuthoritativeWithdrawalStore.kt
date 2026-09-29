package com.slotting.admin.withdrawal

import com.slotting.admin.infra.VersionedCasHelper
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

interface AuthoritativeWithdrawalStore {
    fun saveDestination(dest: PayoutDestinationRecord)
    fun findDestination(tenantId: String, destinationId: UUID): PayoutDestinationRecord?

    fun saveQuote(quote: AuthoritativeWithdrawalQuote)
    fun findQuote(tenantId: String, quoteId: UUID): AuthoritativeWithdrawalQuote?
    fun findQuoteByIdempotency(tenantId: String, idempotencyKey: String): AuthoritativeWithdrawalQuote?

    fun saveStepUpAssertion(assertion: StepUpAssertionRecord)
    fun findStepUpAssertion(tenantId: String, token: String): StepUpAssertionRecord?
    fun consumeStepUpAssertion(tenantId: String, token: String, consumedAt: Instant): Boolean

    fun saveRequest(request: AuthoritativeWithdrawalRequest)
    fun findRequest(tenantId: String, requestId: UUID): AuthoritativeWithdrawalRequest?
    fun findRequestByIdempotency(tenantId: String, idempotencyKey: String): AuthoritativeWithdrawalRequest?
    fun updateRequest(request: AuthoritativeWithdrawalRequest, expectedVersion: Long): AuthoritativeWithdrawalRequest

    fun saveReservation(reservation: AuthoritativeWithdrawalReservation)
    fun findReservation(tenantId: String, reservationId: UUID): AuthoritativeWithdrawalReservation?

    fun getAuthoritativeBalance(tenantId: String, ownerId: UUID, currencyCode: String): Long
    fun tryReserveBalance(tenantId: String, ownerId: UUID, currencyCode: String, amount: Long): Boolean
    fun releaseReservedBalance(tenantId: String, ownerId: UUID, currencyCode: String, amount: Long)
}

class InMemoryAuthoritativeWithdrawalStore : AuthoritativeWithdrawalStore {
    private val destinations = ConcurrentHashMap<String, PayoutDestinationRecord>()
    private val quotesById = ConcurrentHashMap<String, AuthoritativeWithdrawalQuote>()
    private val quotesByIdemp = ConcurrentHashMap<String, AuthoritativeWithdrawalQuote>()
    private val stepUpAssertions = ConcurrentHashMap<String, StepUpAssertionRecord>()
    private val requestsById = ConcurrentHashMap<String, AuthoritativeWithdrawalRequest>()
    private val requestsByIdemp = ConcurrentHashMap<String, AuthoritativeWithdrawalRequest>()
    private val reservations = ConcurrentHashMap<String, AuthoritativeWithdrawalReservation>()
    private val balances = ConcurrentHashMap<String, Long>()

    private fun destKey(tenantId: String, id: UUID) = "$tenantId:$id"
    private fun quoteKey(tenantId: String, id: UUID) = "$tenantId:$id"
    private fun quoteIdempKey(tenantId: String, key: String) = "$tenantId:$key"
    private fun stepUpKey(tenantId: String, token: String) = "$tenantId:$token"
    private fun reqKey(tenantId: String, id: UUID) = "$tenantId:$id"
    private fun reqIdempKey(tenantId: String, key: String) = "$tenantId:$key"
    private fun resKey(tenantId: String, id: UUID) = "$tenantId:$id"
    private fun balKey(tenantId: String, ownerId: UUID, curr: String) = "$tenantId:$ownerId:$curr"

    fun setAuthoritativeBalance(tenantId: String, ownerId: UUID, currencyCode: String, amount: Long) {
        balances[balKey(tenantId, ownerId, currencyCode)] = amount
    }

    @Synchronized
    override fun saveDestination(dest: PayoutDestinationRecord) {
        destinations[destKey(dest.tenantId, dest.destinationId)] = dest.copy()
    }

    @Synchronized
    override fun findDestination(tenantId: String, destinationId: UUID): PayoutDestinationRecord? {
        return destinations[destKey(tenantId, destinationId)]?.copy()
    }

    @Synchronized
    override fun saveQuote(quote: AuthoritativeWithdrawalQuote) {
        quotesById[quoteKey(quote.tenantId, quote.quoteId)] = quote.copy()
        quotesByIdemp[quoteIdempKey(quote.tenantId, quote.idempotencyKey)] = quote.copy()
    }

    @Synchronized
    override fun findQuote(tenantId: String, quoteId: UUID): AuthoritativeWithdrawalQuote? {
        return quotesById[quoteKey(tenantId, quoteId)]?.copy()
    }

    @Synchronized
    override fun findQuoteByIdempotency(tenantId: String, idempotencyKey: String): AuthoritativeWithdrawalQuote? {
        return quotesByIdemp[quoteIdempKey(tenantId, idempotencyKey)]?.copy()
    }

    @Synchronized
    override fun saveStepUpAssertion(assertion: StepUpAssertionRecord) {
        stepUpAssertions[stepUpKey(assertion.tenantId, assertion.token)] = assertion.copy()
    }

    @Synchronized
    override fun findStepUpAssertion(tenantId: String, token: String): StepUpAssertionRecord? {
        return stepUpAssertions[stepUpKey(tenantId, token)]?.copy()
    }

    @Synchronized
    override fun consumeStepUpAssertion(tenantId: String, token: String, consumedAt: Instant): Boolean {
        val key = stepUpKey(tenantId, token)
        val existing = stepUpAssertions[key] ?: return false
        if (existing.isConsumed) return false
        stepUpAssertions[key] = existing.copy(isConsumed = true, consumedAt = consumedAt)
        return true
    }

    @Synchronized
    override fun saveRequest(request: AuthoritativeWithdrawalRequest) {
        requestsById[reqKey(request.tenantId, request.requestId)] = request.copy()
        requestsByIdemp[reqIdempKey(request.tenantId, request.idempotencyKey)] = request.copy()
    }

    @Synchronized
    override fun findRequest(tenantId: String, requestId: UUID): AuthoritativeWithdrawalRequest? {
        return requestsById[reqKey(tenantId, requestId)]?.copy()
    }

    @Synchronized
    override fun findRequestByIdempotency(tenantId: String, idempotencyKey: String): AuthoritativeWithdrawalRequest? {
        return requestsByIdemp[reqIdempKey(tenantId, idempotencyKey)]?.copy()
    }

    @Synchronized
    override fun updateRequest(request: AuthoritativeWithdrawalRequest, expectedVersion: Long): AuthoritativeWithdrawalRequest {
        val key = reqKey(request.tenantId, request.requestId)
        val existing = requestsById[key]
            ?: throw IllegalStateException("Request ${request.requestId} does not exist")
        if (existing.requestVersion != expectedVersion) {
            throw IllegalStateException("CAS update failed for request ${request.requestId}: expected $expectedVersion but found ${existing.requestVersion}")
        }
        requestsById[key] = request.copy()
        requestsByIdemp[reqIdempKey(request.tenantId, request.idempotencyKey)] = request.copy()
        return request
    }

    @Synchronized
    override fun saveReservation(reservation: AuthoritativeWithdrawalReservation) {
        reservations[resKey(reservation.tenantId, reservation.reservationId)] = reservation.copy()
    }

    @Synchronized
    override fun findReservation(tenantId: String, reservationId: UUID): AuthoritativeWithdrawalReservation? {
        return reservations[resKey(tenantId, reservationId)]?.copy()
    }

    @Synchronized
    override fun getAuthoritativeBalance(tenantId: String, ownerId: UUID, currencyCode: String): Long {
        return balances[balKey(tenantId, ownerId, currencyCode)] ?: 0L
    }

    @Synchronized
    override fun tryReserveBalance(tenantId: String, ownerId: UUID, currencyCode: String, amount: Long): Boolean {
        require(amount > 0L) { "Amount must be positive: $amount" }
        val key = balKey(tenantId, ownerId, currencyCode)
        val current = balances[key] ?: 0L
        if (current < amount) {
            return false
        }
        balances[key] = Math.subtractExact(current, amount)
        return true
    }

    @Synchronized
    override fun releaseReservedBalance(tenantId: String, ownerId: UUID, currencyCode: String, amount: Long) {
        require(amount >= 0L) { "Amount cannot be negative: $amount" }
        val key = balKey(tenantId, ownerId, currencyCode)
        val current = balances[key] ?: 0L
        balances[key] = Math.addExact(current, amount)
    }
}

@Repository
class JdbcAuthoritativeWithdrawalStore(private val jdbc: JdbcTemplate) : AuthoritativeWithdrawalStore {

    @Transactional
    override fun saveDestination(dest: PayoutDestinationRecord) {
        jdbc.update(
            """
            INSERT INTO admin_payout_destination (
                destination_id, tenant_id, owner_id, payment_method, destination_reference,
                account_holder_name, verification_method, status, registered_at, verified_at,
                rejection_reason, verification_evidence_reference, idempotency_key, server_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
            """.trimIndent(),
            dest.destinationId,
            dest.tenantId,
            dest.ownerId,
            dest.paymentMethod.name,
            dest.destinationReference,
            dest.accountHolderName,
            dest.verificationMethod.name,
            dest.status.name,
            Timestamp.from(dest.registeredAt),
            dest.verifiedAt?.let { Timestamp.from(it) },
            dest.rejectionReason,
            dest.verificationEvidenceReference,
            dest.idempotencyKey,
            dest.version,
        )
    }

    override fun findDestination(tenantId: String, destinationId: UUID): PayoutDestinationRecord? {
        return jdbc.query(
            "SELECT * FROM admin_payout_destination WHERE tenant_id = ? AND destination_id = ?",
            { rs, _ -> rs.toDestinationRecord() },
            tenantId,
            destinationId,
        ).firstOrNull()
    }

    @Transactional
    override fun saveQuote(quote: AuthoritativeWithdrawalQuote) {
        jdbc.update(
            """
            INSERT INTO admin_withdrawal_quote (
                quote_id, tenant_id, owner_id, currency, method_id, destination_reference,
                gross_amount_minor_units, fixed_fee_minor_units, percentage_fee_bps, total_fee_minor_units,
                net_payout_minor_units, step_up_required, status, quoted_at, expires_at, consumed_at,
                idempotency_key, server_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            quote.quoteId,
            quote.tenantId,
            quote.ownerId,
            quote.currencyCode,
            quote.methodId,
            quote.destinationReference,
            quote.grossAmountMinorUnits,
            quote.fixedFeeMinorUnits,
            quote.percentageFeeBps,
            quote.totalFeeMinorUnits,
            quote.netPayoutMinorUnits,
            quote.stepUpRequired,
            quote.status.name,
            Timestamp.from(quote.quotedAt),
            Timestamp.from(quote.expiresAt),
            quote.consumedAt?.let { Timestamp.from(it) },
            quote.idempotencyKey,
            quote.serverVersion,
        )
    }

    override fun findQuote(tenantId: String, quoteId: UUID): AuthoritativeWithdrawalQuote? {
        return jdbc.query(
            "SELECT * FROM admin_withdrawal_quote WHERE tenant_id = ? AND quote_id = ?",
            { rs, _ -> rs.toQuoteRecord() },
            tenantId,
            quoteId,
        ).firstOrNull()
    }

    override fun findQuoteByIdempotency(tenantId: String, idempotencyKey: String): AuthoritativeWithdrawalQuote? {
        return jdbc.query(
            "SELECT * FROM admin_withdrawal_quote WHERE tenant_id = ? AND idempotency_key = ?",
            { rs, _ -> rs.toQuoteRecord() },
            tenantId,
            idempotencyKey,
        ).firstOrNull()
    }

    @Transactional
    override fun saveStepUpAssertion(assertion: StepUpAssertionRecord) {
        jdbc.update(
            """
            INSERT INTO admin_withdrawal_step_up_assertion (
                assertion_id, tenant_id, owner_id, session_id, destination_reference,
                gross_amount_minor_units, currency, method_id, operation_type, bound_digest,
                token, is_consumed, issued_at, expires_at, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            assertion.assertionId,
            assertion.tenantId,
            assertion.ownerId,
            assertion.sessionId,
            assertion.destinationReference,
            assertion.grossAmountMinorUnits,
            assertion.currencyCode,
            assertion.methodId,
            assertion.operationType,
            assertion.boundDigest,
            assertion.token,
            assertion.isConsumed,
            Timestamp.from(assertion.issuedAt),
            Timestamp.from(assertion.expiresAt),
            assertion.consumedAt?.let { Timestamp.from(it) },
        )
    }

    override fun findStepUpAssertion(tenantId: String, token: String): StepUpAssertionRecord? {
        return jdbc.query(
            "SELECT * FROM admin_withdrawal_step_up_assertion WHERE tenant_id = ? AND token = ?",
            { rs, _ -> rs.toStepUpRecord() },
            tenantId,
            token,
        ).firstOrNull()
    }

    @Transactional
    override fun consumeStepUpAssertion(tenantId: String, token: String, consumedAt: Instant): Boolean {
        val updated = jdbc.update(
            """
            UPDATE admin_withdrawal_step_up_assertion
            SET is_consumed = TRUE, consumed_at = ?
            WHERE tenant_id = ? AND token = ? AND is_consumed = FALSE
            """.trimIndent(),
            Timestamp.from(consumedAt),
            tenantId,
            token,
        )
        return updated > 0
    }

    @Transactional
    override fun saveRequest(request: AuthoritativeWithdrawalRequest) {
        jdbc.update(
            """
            INSERT INTO admin_authoritative_withdrawal_request (
                request_id, tenant_id, owner_id, quote_id, reservation_id, method_id,
                destination_reference, gross_amount_minor_units, fee_minor_units, net_payout_amount_minor_units,
                currency, step_up_assertion_id, immutable_digest, status, review_state,
                denial_reason_code, denial_message, dual_control_receipt_id, idempotency_key,
                server_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            request.requestId,
            request.tenantId,
            request.ownerId,
            request.quoteId,
            request.reservationId,
            request.methodId,
            request.destinationReference,
            request.grossAmountMinorUnits,
            request.feeMinorUnits,
            request.netPayoutAmountMinorUnits,
            request.currencyCode,
            request.stepUpAssertionId,
            request.immutableDigest,
            request.status.name,
            request.reviewState.name,
            request.denialReasonCode,
            request.denialMessage,
            request.dualControlReceiptId,
            request.idempotencyKey,
            request.requestVersion,
            Timestamp.from(request.createdAt),
            Timestamp.from(request.updatedAt),
        )
    }

    override fun findRequest(tenantId: String, requestId: UUID): AuthoritativeWithdrawalRequest? {
        return jdbc.query(
            "SELECT * FROM admin_authoritative_withdrawal_request WHERE tenant_id = ? AND request_id = ?",
            { rs, _ -> rs.toRequestRecord() },
            tenantId,
            requestId,
        ).firstOrNull()
    }

    override fun findRequestByIdempotency(tenantId: String, idempotencyKey: String): AuthoritativeWithdrawalRequest? {
        return jdbc.query(
            "SELECT * FROM admin_authoritative_withdrawal_request WHERE tenant_id = ? AND idempotency_key = ?",
            { rs, _ -> rs.toRequestRecord() },
            tenantId,
            idempotencyKey,
        ).firstOrNull()
    }

    @Transactional
    override fun updateRequest(request: AuthoritativeWithdrawalRequest, expectedVersion: Long): AuthoritativeWithdrawalRequest {
        val updated = jdbc.update(
            """
            UPDATE admin_authoritative_withdrawal_request
            SET status = ?, review_state = ?, denial_reason_code = ?, denial_message = ?,
                dual_control_receipt_id = ?, server_version = ?, updated_at = ?
            WHERE tenant_id = ? AND request_id = ? AND server_version = ?
            """.trimIndent(),
            request.status.name,
            request.reviewState.name,
            request.denialReasonCode,
            request.denialMessage,
            request.dualControlReceiptId,
            request.requestVersion,
            Timestamp.from(request.updatedAt),
            request.tenantId,
            request.requestId,
            expectedVersion,
        )
        VersionedCasHelper.requireUpdated(updated)
        return request
    }

    @Transactional
    override fun saveReservation(reservation: AuthoritativeWithdrawalReservation) {
        jdbc.update(
            """
            INSERT INTO admin_authoritative_withdrawal_reservation (
                reservation_id, tenant_id, owner_id, request_id, amount_minor_units,
                currency, status, ledger_journal_reference, server_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            reservation.reservationId,
            reservation.tenantId,
            reservation.ownerId,
            reservation.requestId,
            reservation.amountMinorUnits,
            reservation.currencyCode,
            reservation.status.name,
            reservation.ledgerJournalReference,
            reservation.serverVersion,
            Timestamp.from(reservation.createdAt),
            Timestamp.from(reservation.updatedAt),
        )
    }

    override fun findReservation(tenantId: String, reservationId: UUID): AuthoritativeWithdrawalReservation? {
        return jdbc.query(
            "SELECT * FROM admin_authoritative_withdrawal_reservation WHERE tenant_id = ? AND reservation_id = ?",
            { rs, _ -> rs.toReservationRecord() },
            tenantId,
            reservationId,
        ).firstOrNull()
    }

    override fun getAuthoritativeBalance(tenantId: String, ownerId: UUID, currencyCode: String): Long {
        val sql = "SELECT balance_minor_units FROM wallet_projection WHERE tenant_id = ? AND owner_reference = ? AND currency_code = ?"
        return jdbc.query(sql, { rs, _ -> rs.getLong("balance_minor_units") }, tenantId, ownerId.toString(), currencyCode)
            .firstOrNull() ?: 0L
    }

    @Transactional
    override fun tryReserveBalance(tenantId: String, ownerId: UUID, currencyCode: String, amount: Long): Boolean {
        val updated = jdbc.update(
            """
            UPDATE wallet_projection
            SET balance_minor_units = balance_minor_units - ?, updated_at = NOW()
            WHERE tenant_id = ? AND owner_reference = ? AND currency_code = ? AND balance_minor_units >= ?
            """.trimIndent(),
            amount,
            tenantId,
            ownerId.toString(),
            currencyCode,
            amount,
        )
        return updated > 0
    }

    @Transactional
    override fun releaseReservedBalance(tenantId: String, ownerId: UUID, currencyCode: String, amount: Long) {
        require(amount >= 0L) { "Amount cannot be negative: $amount" }
        jdbc.update(
            """
            UPDATE wallet_projection
            SET balance_minor_units = balance_minor_units + ?, updated_at = NOW()
            WHERE tenant_id = ? AND owner_reference = ? AND currency_code = ?
            """.trimIndent(),
            amount,
            tenantId,
            ownerId.toString(),
            currencyCode,
        )
    }

    private fun ResultSet.toDestinationRecord() = PayoutDestinationRecord(
        destinationId = getObject("destination_id", UUID::class.java),
        tenantId = getString("tenant_id"),
        ownerId = getObject("owner_id", UUID::class.java),
        paymentMethod = WithdrawalPaymentMethod.valueOf(getString("payment_method")),
        destinationReference = getString("destination_reference"),
        accountHolderName = getString("account_holder_name"),
        verificationMethod = DestinationVerificationMethod.valueOf(getString("verification_method")),
        status = DestinationVerificationStatus.valueOf(getString("status")),
        registeredAt = getTimestamp("registered_at").toInstant(),
        verifiedAt = getTimestamp("verified_at")?.toInstant(),
        rejectionReason = getString("rejection_reason"),
        verificationEvidenceReference = getString("verification_evidence_reference"),
        idempotencyKey = getString("idempotency_key"),
        correlationId = "corr-dest",
        causationId = "caus-dest",
        version = getLong("server_version"),
    )

    private fun ResultSet.toQuoteRecord() = AuthoritativeWithdrawalQuote(
        quoteId = getObject("quote_id", UUID::class.java),
        tenantId = getString("tenant_id"),
        ownerId = getObject("owner_id", UUID::class.java),
        currencyCode = getString("currency"),
        methodId = getString("method_id"),
        destinationId = UUID.randomUUID(),
        destinationReference = getString("destination_reference"),
        grossAmountMinorUnits = getLong("gross_amount_minor_units"),
        fixedFeeMinorUnits = getLong("fixed_fee_minor_units"),
        percentageFeeBps = getLong("percentage_fee_bps"),
        totalFeeMinorUnits = getLong("total_fee_minor_units"),
        netPayoutMinorUnits = getLong("net_payout_minor_units"),
        stepUpRequired = getBoolean("step_up_required"),
        status = WithdrawalQuoteStatus.valueOf(getString("status")),
        quotedAt = getTimestamp("quoted_at").toInstant(),
        expiresAt = getTimestamp("expires_at").toInstant(),
        consumedAt = getTimestamp("consumed_at")?.toInstant(),
        idempotencyKey = getString("idempotency_key"),
        serverVersion = getLong("server_version"),
    )

    private fun ResultSet.toStepUpRecord() = StepUpAssertionRecord(
        assertionId = getObject("assertion_id", UUID::class.java),
        tenantId = getString("tenant_id"),
        ownerId = getObject("owner_id", UUID::class.java),
        sessionId = getString("session_id"),
        destinationReference = getString("destination_reference"),
        grossAmountMinorUnits = getLong("gross_amount_minor_units"),
        currencyCode = getString("currency"),
        methodId = getString("method_id"),
        operationType = getString("operation_type"),
        boundDigest = getString("bound_digest"),
        token = getString("token"),
        isConsumed = getBoolean("is_consumed"),
        issuedAt = getTimestamp("issued_at").toInstant(),
        expiresAt = getTimestamp("expires_at").toInstant(),
        consumedAt = getTimestamp("consumed_at")?.toInstant(),
    )

    private fun ResultSet.toRequestRecord() = AuthoritativeWithdrawalRequest(
        requestId = getObject("request_id", UUID::class.java),
        tenantId = getString("tenant_id"),
        ownerId = getObject("owner_id", UUID::class.java),
        quoteId = getObject("quote_id", UUID::class.java),
        reservationId = getObject("reservation_id", UUID::class.java),
        methodId = getString("method_id"),
        destinationId = UUID.randomUUID(),
        destinationReference = getString("destination_reference"),
        grossAmountMinorUnits = getLong("gross_amount_minor_units"),
        feeMinorUnits = getLong("fee_minor_units"),
        netPayoutAmountMinorUnits = getLong("net_payout_amount_minor_units"),
        currencyCode = getString("currency"),
        stepUpAssertionId = getObject("step_up_assertion_id", UUID::class.java),
        immutableDigest = getString("immutable_digest"),
        status = WithdrawalRequestStatus.valueOf(getString("status")),
        reviewState = WithdrawalReviewState.valueOf(getString("review_state")),
        denialReasonCode = getString("denial_reason_code"),
        denialMessage = getString("denial_message"),
        dualControlReceiptId = getObject("dual_control_receipt_id", UUID::class.java),
        idempotencyKey = getString("idempotency_key"),
        requestVersion = getLong("server_version"),
        createdAt = getTimestamp("created_at").toInstant(),
        updatedAt = getTimestamp("updated_at").toInstant(),
    )

    private fun ResultSet.toReservationRecord() = AuthoritativeWithdrawalReservation(
        reservationId = getObject("reservation_id", UUID::class.java),
        tenantId = getString("tenant_id"),
        ownerId = getObject("owner_id", UUID::class.java),
        requestId = getObject("request_id", UUID::class.java),
        amountMinorUnits = getLong("amount_minor_units"),
        currencyCode = getString("currency"),
        status = AuthoritativeReservationStatus.valueOf(getString("status")),
        ledgerJournalReference = getString("ledger_journal_reference"),
        serverVersion = getLong("server_version"),
        createdAt = getTimestamp("created_at").toInstant(),
        updatedAt = getTimestamp("updated_at").toInstant(),
    )
}
