package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class LedgerLegDirection { DEBIT, CREDIT }
enum class LedgerTransactionType { TRANSFER, DEPOSIT, WITHDRAWAL, GAME_SETTLEMENT, COMPENSATION }

data class LedgerLeg(
    val accountReference: String,
    val direction: LedgerLegDirection,
    val amountMinorUnits: Long,
    val currencyCode: String,
)

data class LedgerDesignCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val transactionReference: String,
    val transactionType: LedgerTransactionType,
    val currencyCode: String,
    val legs: List<LedgerLeg>,
    val compensationForTransactionReference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 0L,
)

data class LedgerDesignVerificationResult(
    val resultId: UUID,
    val transactionReference: String,
    val currencyCode: String,
    val totalDebitsMinorUnits: Long,
    val totalCreditsMinorUnits: Long,
    val isBalanced: Boolean,
    val isCompensation: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
)

interface LedgerDesignStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, LedgerDesignVerificationResult>?
    fun findTransaction(tenantId: String, transactionReference: String): LedgerDesignVerificationResult?
    fun save(
        result: LedgerDesignVerificationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class LedgerDesignService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: LedgerDesignStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun operate(command: LedgerDesignCommand): LedgerDesignVerificationResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.transactionReference.isBlank() || command.transactionReference.length > 128 ||
            command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank() ||
            !command.currencyCode.matches(Regex("[A-Z]{3}")) || command.legs.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = Instant.now(clock)
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        if (session == null || !session.active || !session.expiresAt.isAfter(now)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Minor units and currency partition checks
        if (command.legs.any { it.amountMinorUnits <= 0L || it.currencyCode != command.currencyCode || it.accountReference.isBlank() }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Conservation check: sum(debits) must equal sum(credits) and be > 0
        val debits = command.legs.filter { it.direction == LedgerLegDirection.DEBIT }.sumOf { it.amountMinorUnits }
        val credits = command.legs.filter { it.direction == LedgerLegDirection.CREDIT }.sumOf { it.amountMinorUnits }
        if (debits != credits || debits <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Compensation validation
        val isCompensation = command.transactionType == LedgerTransactionType.COMPENSATION
        if (isCompensation) {
            val targetRef = command.compensationForTransactionReference
            if (targetRef.isNullOrBlank()) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            val original = store.findTransaction(command.tenantId, targetRef)
                ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val resultId = UUID.randomUUID()
        val result = LedgerDesignVerificationResult(
            resultId = resultId,
            transactionReference = command.transactionReference,
            currencyCode = command.currencyCode,
            totalDebitsMinorUnits = debits,
            totalCreditsMinorUnits = credits,
            isBalanced = true,
            isCompensation = isCompensation,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ledger-design:$resultId",
        )

        val type = "LEDGER_DESIGN_${command.transactionType.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        store.save(result, command.tenantId, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprint(command: LedgerDesignCommand): String = listOf(
        command.tenantId,
        command.transactionReference,
        command.transactionType,
        command.currencyCode,
        command.compensationForTransactionReference,
        command.legs.joinToString(",") { "${it.accountReference}:${it.direction}:${it.amountMinorUnits}:${it.currencyCode}" },
        command.expectedVersion,
    ).joinToString("|") { sha256(it.toString()) }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
