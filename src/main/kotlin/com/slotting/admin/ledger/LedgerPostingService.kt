package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for LEDGER-002:
 * "duplicate/concurrent posting"
 */
object LedgerPostingBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("duplicate/concurrent posting")
        }
    }
}

open class LedgerPostingException(val errorCode: String, message: String) : RuntimeException(message)

class DirectBalanceWriteProhibitedException(
    message: String = "All direct balance writes prohibited",
) : LedgerPostingException("DIRECT_BALANCE_WRITE_PROHIBITED", message)

class IdempotencyConflictException(
    message: String = "Idempotency key reused with conflicting payload",
) : LedgerPostingException("CONFLICT", message)

class PostingUnauthorizedException(
    message: String = "Unauthenticated posting attempt",
) : LedgerPostingException("UNAUTHORIZED", message)

class PostingForbiddenException(
    message: String = "Forbidden: insufficient permissions or cross-tenant posting denied",
) : LedgerPostingException("FORBIDDEN", message)

class PostingInvalidException(
    message: String = "Invalid posting request",
) : LedgerPostingException("INVALID", message)

class PostingStaleVersionException(
    message: String = "Stale version or concurrent modification",
) : LedgerPostingException("STALE_VERSION", message)

data class DirectBalanceWriteCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val accountReference: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
)

data class PostTransactionCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val transactionReference: String,
    val currencyCode: String,
    val entries: List<JournalEntryDraft>,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 0L,
)

data class PostingResult(
    val resultId: UUID,
    val tenantId: String,
    val transactionReference: String,
    val currencyCode: String,
    val totalDebitsMinorUnits: Long,
    val totalCreditsMinorUnits: Long,
    val isBalanced: Boolean,
    val status: JournalBatchStatus,
    val entryCount: Int,
    val idempotencyKey: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val directEligibilityGranted: Boolean = false, // Untrusted client invariant
    val financialMutationPermitted: Boolean = false, // Untrusted client invariant
    val directBalanceWriteProhibited: Boolean = true,
    val evidenceReference: String,
    val semanticContract: String = "One accepted key→one result; payload mismatch conflicts; all direct balance writes prohibited.",
)

/**
 * Authoritative posting service managing double-entry ledger posting,
 * transaction-key uniqueness, idempotency deduplication with payload conflict detection,
 * and strict prohibition of direct balance writes.
 *
 * Semantic contract: "One accepted key→one result; payload mismatch conflicts; all direct balance writes prohibited."
 * Protected risk assertion: "duplicate/concurrent posting"
 */
class LedgerPostingService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, PostingResult>>()
    private val transactionRefIndex = ConcurrentHashMap<String, UUID>() // "tenantId:transactionReference" -> resultId
    private val auditLogs = mutableListOf<AuditEvent>()
    private val inFlightLocks = ConcurrentHashMap<String, Any>()

    /**
     * Direct balance mutation is strictly prohibited across the entire platform.
     * All monetary balance changes MUST proceed via double-entry journal posting.
     */
    fun directBalanceWrite(command: DirectBalanceWriteCommand) {
        LedgerPostingBinding.checkBound()
        throw DirectBalanceWriteProhibitedException("All direct balance writes prohibited")
    }

    /**
     * Post an authoritative double-entry transaction under exact-once idempotency semantics.
     */
    fun postTransaction(command: PostTransactionCommand): PostingResult {
        LedgerPostingBinding.checkBound()

        // 1. Authentication check
        val principal = command.principal ?: throw PostingUnauthorizedException("Unauthenticated posting attempt")

        // 2. Authorization check (least privilege, RBAC, tenant ownership)
        if (principal.tenantId != command.tenantId) {
            throw PostingForbiddenException("Cross-tenant posting is forbidden")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw PostingForbiddenException("Principal lacks ledger mutation permissions")
        }

        // 3. Input validation
        if (command.idempotencyKey.isBlank()) {
            throw PostingInvalidException("Idempotency key must not be blank")
        }
        if (command.transactionReference.isBlank() || command.transactionReference.length > 128) {
            throw PostingInvalidException("Transaction reference must not be blank or exceed 128 characters")
        }
        if (command.currencyCode.isBlank() || !command.currencyCode.matches(Regex("^[A-Z]{3}$"))) {
            throw PostingInvalidException("Currency code must be a valid 3-letter ISO code: '${command.currencyCode}'")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw PostingInvalidException("Correlation and causation IDs are required for audit traceability")
        }
        if (command.entries.size < 2) {
            throw PostingInvalidException("Double-entry transaction requires at least 2 entries (debits and credits)")
        }

        // 4. Compute deterministic payload signature (excluding idempotencyKey, correlationId, causationId)
        val signature = computePayloadSignature(command)

        // 5. Concurrency & Idempotency synchronization
        val lock = inFlightLocks.computeIfAbsent(command.idempotencyKey) { Any() }
        synchronized(lock) {
            // Check if already posted under this idempotency key
            idempotencyStore[command.idempotencyKey]?.let { (cachedSig, cachedResult) ->
                if (cachedSig == signature) {
                    // One accepted key -> one result (identical replay)
                    return cachedResult
                } else {
                    // Payload mismatch conflicts
                    throw IdempotencyConflictException(
                        "Idempotency key '${command.idempotencyKey}' reused with conflicting payload mismatch"
                    )
                }
            }

            // Check transaction reference uniqueness across tenant
            val txKey = "${command.tenantId}:${command.transactionReference}"
            if (transactionRefIndex.containsKey(txKey)) {
                throw IdempotencyConflictException("Duplicate transaction reference: '${command.transactionReference}'")
            }

            // 6. Double-entry validation
            var totalDebits = 0L
            var totalCredits = 0L

            for (entry in command.entries) {
                if (entry.currencyCode != command.currencyCode) {
                    throw PostingInvalidException(
                        "Entry currency '${entry.currencyCode}' does not match transaction currency '${command.currencyCode}'"
                    )
                }
                if (entry.amountMinorUnits <= 0L) {
                    throw PostingInvalidException("Entry amount must be positive minor units: ${entry.amountMinorUnits}")
                }
                if (entry.accountReference.isBlank()) {
                    throw PostingInvalidException("Account reference cannot be blank")
                }

                when (entry.direction) {
                    JournalEntryDirection.DEBIT -> totalDebits += entry.amountMinorUnits
                    JournalEntryDirection.CREDIT -> totalCredits += entry.amountMinorUnits
                }
            }

            if (totalDebits != totalCredits) {
                throw PostingInvalidException(
                    "Transaction unbalanced: debits ($totalDebits) != credits ($totalCredits)"
                )
            }

            val resultId = UUID.randomUUID()
            val now = Instant.now(clock)
            val result = PostingResult(
                resultId = resultId,
                tenantId = command.tenantId,
                transactionReference = command.transactionReference,
                currencyCode = command.currencyCode,
                totalDebitsMinorUnits = totalDebits,
                totalCreditsMinorUnits = totalCredits,
                isBalanced = true,
                status = JournalBatchStatus.POSTED,
                entryCount = command.entries.size,
                idempotencyKey = command.idempotencyKey,
                serverTime = now,
                serverVersion = command.expectedVersion + 1L,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                directBalanceWriteProhibited = true,
                evidenceReference = "ledger-posting:$resultId?v=1",
            )

            // Persist idempotency mapping and transaction reference index
            idempotencyStore[command.idempotencyKey] = Pair(signature, result)
            transactionRefIndex[txKey] = resultId

            // Record audit event
            auditLogs.add(
                AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = command.tenantId,
                    type = "LEDGER_TRANSACTION_POSTED",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                )
            )

            return result
        }
    }

    fun getAuditLogs(tenantId: String): List<AuditEvent> {
        return auditLogs.filter { it.tenantId == tenantId }
    }

    private fun computePayloadSignature(command: PostTransactionCommand): String {
        val payload = buildString {
            append(command.tenantId).append('|')
            append(command.transactionReference).append('|')
            append(command.currencyCode).append('|')
            append(command.expectedVersion).append('|')
            for (entry in command.entries) {
                append(entry.accountReference).append(':')
                append(entry.direction.name).append(':')
                append(entry.amountMinorUnits).append(':')
                append(entry.currencyCode).append(';')
            }
        }
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(payload.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
