package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for LEDGER-001:
 * "unbalanced/mutable/post without currency"
 */
object JournalSchemaBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unbalanced/mutable/post without currency")
        }
    }
}

enum class JournalEntryDirection {
    DEBIT,
    CREDIT,
}

enum class JournalBatchStatus {
    PENDING,
    POSTED,
    COMPENSATED,
    REJECTED,
}

data class JournalEntryDraft(
    val accountReference: String,
    val direction: JournalEntryDirection,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val narration: String? = null,
)

data class JournalEntryRecord(
    val entryId: UUID,
    val batchId: UUID,
    val tenantId: String,
    val accountReference: String,
    val direction: JournalEntryDirection,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val lineOrder: Int,
    val narration: String? = null,
    val createdAt: Instant,
)

data class JournalBatchRecord(
    val batchId: UUID,
    val tenantId: String,
    val batchReference: String,
    val currencyCode: String,
    val totalDebitsMinorUnits: Long,
    val totalCreditsMinorUnits: Long,
    val status: JournalBatchStatus,
    val entries: List<JournalEntryRecord>,
    val compensationForBatchReference: String? = null,
    val postedAt: Instant,
    val postedBy: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val serverVersion: Long = 1L,
    val createdAt: Instant,
)

data class PostJournalBatchCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val batchReference: String,
    val currencyCode: String,
    val entries: List<JournalEntryDraft>,
    val compensationForBatchReference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 0L,
)

data class PostJournalBatchResult(
    val batchId: UUID,
    val batchReference: String,
    val currencyCode: String,
    val totalDebitsMinorUnits: Long,
    val totalCreditsMinorUnits: Long,
    val isBalanced: Boolean,
    val status: JournalBatchStatus,
    val entryCount: Int,
    val serverTime: Instant,
    val serverVersion: Long,
    val directEligibilityGranted: Boolean = false, // Untrusted client invariant
    val financialMutationPermitted: Boolean = false, // Client presentation invariant
    val evidenceReference: String,
    val message: String = "Sum debits=credits per currency/batch; posted rows update/delete denied.",
)

data class CompensateJournalBatchCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val targetBatchReference: String,
    val compensatingBatchReference: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 0L,
)

open class JournalSchemaException(val errorCode: String, message: String) : RuntimeException(message)
class UnbalancedJournalBatchException(message: String) : JournalSchemaException("UNBALANCED_BATCH", message)
class InvalidCurrencyException(message: String) : JournalSchemaException("INVALID_CURRENCY", message)
class CurrencyMismatchException(message: String) : JournalSchemaException("CURRENCY_MISMATCH", message)
class InvalidJournalEntryException(message: String) : JournalSchemaException("INVALID_ENTRY", message)
class ImmutableJournalException(message: String) : JournalSchemaException("MUTATION_DENIED", message)
class JournalBatchNotFoundException(message: String) : JournalSchemaException("BATCH_NOT_FOUND", message)
class UnauthorizedException(message: String) : JournalSchemaException("UNAUTHORIZED", message)
class IdorForbiddenException(message: String) : JournalSchemaException("FORBIDDEN_IDOR", message)
class ConcurrencyConflictException(message: String) : JournalSchemaException("CONFLICT", message)

/**
 * Authoritative service managing double-entry journal batches,
 * mathematical debit=credit conservation per currency, posted row immutability,
 * and immutable compensation.
 *
 * Semantic contract: "Sum debits=credits per currency/batch; posted rows update/delete denied."
 * Protected risk assertion: "unbalanced/mutable/post without currency"
 */
class JournalSchemaService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val batchesStore = ConcurrentHashMap<UUID, JournalBatchRecord>()
    private val batchRefIndex = ConcurrentHashMap<String, UUID>() // "tenantId:batchReference" -> UUID
    private val entriesStore = ConcurrentHashMap<UUID, JournalEntryRecord>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, PostJournalBatchResult>>()
    private val auditLogs = mutableListOf<AuditEvent>()

    /**
     * Authoritatively validate, conserve, balance, and post a double-entry journal batch.
     */
    @Synchronized
    fun postBatch(command: PostJournalBatchCommand): PostJournalBatchResult {
        JournalSchemaBinding.checkBound()

        // 1. Authentication & Permission validation
        val principal = command.principal ?: throw UnauthorizedException("Unauthenticated journal post attempt")
        if (principal.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant journal post forbidden")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw IdorForbiddenException("Principal lacks financial mutation authority for journal posting")
        }

        // 2. Idempotency handling
        val sig = computePayloadSignature(command)
        idempotencyStore[command.idempotencyKey]?.let { (cachedSig, cachedResult) ->
            if (cachedSig == sig) {
                return cachedResult
            } else {
                throw ConcurrencyConflictException("Idempotency key reused with conflicting payload")
            }
        }

        // 3. Batch reference uniqueness
        val refKey = "${command.tenantId}:${command.batchReference}"
        if (batchRefIndex.containsKey(refKey)) {
            throw ConcurrencyConflictException("Duplicate batch reference: ${command.batchReference}")
        }

        // 4. Currency validation (ISO 4217, 3 capital letters, non-blank)
        if (command.currencyCode.isBlank() || !command.currencyCode.matches(Regex("^[A-Z]{3}$"))) {
            throw InvalidCurrencyException("Post without valid 3-letter ISO currency code is forbidden: '${command.currencyCode}'")
        }

        // 5. Entry quantity check (at least 2 entries required for double-entry bookkeeping)
        if (command.entries.size < 2) {
            throw InvalidJournalEntryException("Double-entry batch requires at least 2 entries (debit and credit)")
        }

        // 6. Inspect entries: currency must match batch, amount > 0, account reference non-blank
        var totalDebits = 0L
        var totalCredits = 0L
        val entryRecords = mutableListOf<JournalEntryRecord>()
        val batchId = UUID.randomUUID()
        val now = clock.instant()

        for ((index, draft) in command.entries.withIndex()) {
            if (draft.currencyCode != command.currencyCode) {
                throw CurrencyMismatchException("Entry currency '${draft.currencyCode}' does not match batch currency '${command.currencyCode}'")
            }
            if (draft.amountMinorUnits <= 0L) {
                throw InvalidJournalEntryException("Entry amount must be positive minor units; received: ${draft.amountMinorUnits}")
            }
            if (draft.accountReference.isBlank()) {
                throw InvalidJournalEntryException("Entry account reference cannot be blank")
            }

            when (draft.direction) {
                JournalEntryDirection.DEBIT -> totalDebits += draft.amountMinorUnits
                JournalEntryDirection.CREDIT -> totalCredits += draft.amountMinorUnits
            }

            val entryId = UUID.randomUUID()
            entryRecords.add(
                JournalEntryRecord(
                    entryId = entryId,
                    batchId = batchId,
                    tenantId = command.tenantId,
                    accountReference = draft.accountReference,
                    direction = draft.direction,
                    amountMinorUnits = draft.amountMinorUnits,
                    currencyCode = draft.currencyCode,
                    lineOrder = index + 1,
                    narration = draft.narration,
                    createdAt = now,
                )
            )
        }

        // 7. Conservation & Balance assertion: sum(debits) == sum(credits)
        if (totalDebits != totalCredits || totalDebits <= 0L) {
            throw UnbalancedJournalBatchException("Journal batch is unbalanced: debits ($totalDebits) != credits ($totalCredits)")
        }

        // 8. Atomic persistence of batch and entries
        val batchRecord = JournalBatchRecord(
            batchId = batchId,
            tenantId = command.tenantId,
            batchReference = command.batchReference,
            currencyCode = command.currencyCode,
            totalDebitsMinorUnits = totalDebits,
            totalCreditsMinorUnits = totalCredits,
            status = JournalBatchStatus.POSTED,
            entries = entryRecords,
            compensationForBatchReference = command.compensationForBatchReference,
            postedAt = now,
            postedBy = principal.id,
            idempotencyKey = command.idempotencyKey,
            correlationId = command.correlationId,
            causationId = command.causationId,
            serverVersion = 1L,
            createdAt = now,
        )

        batchesStore[batchId] = batchRecord
        batchRefIndex[refKey] = batchId
        entryRecords.forEach { entriesStore[it.entryId] = it }

        // 9. Record audit event
        auditLogs.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = batchId,
                tenantId = command.tenantId,
                type = "JOURNAL_BATCH_POSTED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        val result = PostJournalBatchResult(
            batchId = batchId,
            batchReference = command.batchReference,
            currencyCode = command.currencyCode,
            totalDebitsMinorUnits = totalDebits,
            totalCreditsMinorUnits = totalCredits,
            isBalanced = true,
            status = JournalBatchStatus.POSTED,
            entryCount = entryRecords.size,
            serverTime = now,
            serverVersion = 1L,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = "evidence://ledger/batch/$batchId?v=1",
        )

        idempotencyStore[command.idempotencyKey] = sig to result
        return result
    }

    /**
     * Immutability enforcement: Attempting to update a posted batch is denied.
     */
    fun updatePostedBatch(batchId: UUID, newReference: String) {
        JournalSchemaBinding.checkBound()
        throw ImmutableJournalException("Sum debits=credits per currency/batch; posted rows update/delete denied.")
    }

    /**
     * Immutability enforcement: Attempting to delete a posted batch is denied.
     */
    fun deletePostedBatch(batchId: UUID) {
        JournalSchemaBinding.checkBound()
        throw ImmutableJournalException("Sum debits=credits per currency/batch; posted rows update/delete denied.")
    }

    /**
     * Immutability enforcement: Attempting to update a posted entry is denied.
     */
    fun updatePostedEntry(entryId: UUID, newAmount: Long) {
        JournalSchemaBinding.checkBound()
        throw ImmutableJournalException("Sum debits=credits per currency/batch; posted rows update/delete denied.")
    }

    /**
     * Immutability enforcement: Attempting to delete a posted entry is denied.
     */
    fun deletePostedEntry(entryId: UUID) {
        JournalSchemaBinding.checkBound()
        throw ImmutableJournalException("Sum debits=credits per currency/batch; posted rows update/delete denied.")
    }

    /**
     * Authoritatively compensate an existing posted batch by posting an inverted compensating batch.
     * Original batch is never updated or deleted.
     */
    @Synchronized
    fun compensateBatch(command: CompensateJournalBatchCommand): PostJournalBatchResult {
        JournalSchemaBinding.checkBound()

        val refKey = "${command.tenantId}:${command.targetBatchReference}"
        val targetBatchId = batchRefIndex[refKey]
            ?: throw JournalBatchNotFoundException("Target batch '${command.targetBatchReference}' not found")

        val targetBatch = batchesStore[targetBatchId]
            ?: throw JournalBatchNotFoundException("Target batch record not found")

        // Build inverted entries
        val invertedEntries = targetBatch.entries.map { entry ->
            JournalEntryDraft(
                accountReference = entry.accountReference,
                direction = if (entry.direction == JournalEntryDirection.DEBIT) JournalEntryDirection.CREDIT else JournalEntryDirection.DEBIT,
                amountMinorUnits = entry.amountMinorUnits,
                currencyCode = entry.currencyCode,
                narration = "Compensation for ${targetBatch.batchReference}: ${command.reason}",
            )
        }

        return postBatch(
            PostJournalBatchCommand(
                principal = command.principal,
                tenantId = command.tenantId,
                batchReference = command.compensatingBatchReference,
                currencyCode = targetBatch.currencyCode,
                entries = invertedEntries,
                compensationForBatchReference = targetBatch.batchReference,
                idempotencyKey = command.idempotencyKey,
                correlationId = command.correlationId,
                causationId = command.causationId,
                expectedVersion = targetBatch.serverVersion,
            )
        )
    }

    fun getBatch(tenantId: String, batchId: UUID): JournalBatchRecord? {
        val record = batchesStore[batchId] ?: return null
        if (record.tenantId != tenantId) return null
        return record
    }

    fun getBatchByReference(tenantId: String, reference: String): JournalBatchRecord? {
        val batchId = batchRefIndex["$tenantId:$reference"] ?: return null
        return getBatch(tenantId, batchId)
    }

    private fun computePayloadSignature(command: PostJournalBatchCommand): String {
        val entriesSig = command.entries.joinToString(";") { "${it.accountReference}:${it.direction}:${it.amountMinorUnits}:${it.currencyCode}" }
        val raw = "${command.tenantId}:${command.batchReference}:${command.currencyCode}:$entriesSig:${command.compensationForBatchReference}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
