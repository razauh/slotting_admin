package com.slotting.admin.ledger

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.RedactedEventJson
import com.slotting.admin.infra.VersionedCasHelper
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

interface LedgerJournalStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PostingResult>?
    fun findByTransactionReference(tenantId: String, transactionReference: String): PostingResult?
    fun findLegs(tenantId: String, transactionId: UUID): List<JournalEntryRecord>
    fun findAllLegsForTenant(tenantId: String): List<JournalEntryRecord>
    fun findBalance(tenantId: String, accountReference: String, currencyCode: String): Long
    fun lockAccount(tenantId: String, accountReference: String, currencyCode: String): Boolean {
        return true
    }
    fun nextLedgerVersion(tenantId: String): Long
    fun save(
        result: PostingResult,
        legs: List<JournalEntryRecord>,
        payloadDigest: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

open class InMemoryLedgerJournalStore : LedgerJournalStore {
    private val transactions = ConcurrentHashMap<String, PostingResult>() // "tenantId:txRef" -> PostingResult
    private val receipts = ConcurrentHashMap<String, Pair<String, PostingResult>>() // "tenantId:idempotencyKey" -> (digest, PostingResult)
    private val legsStore = ConcurrentHashMap<UUID, MutableList<JournalEntryRecord>>() // txId -> legs
    private val orderedLegs = java.util.concurrent.CopyOnWriteArrayList<JournalEntryRecord>()
    private val tenantVersions = ConcurrentHashMap<String, Long>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PostingResult>? {
        return receipts["$tenantId:$idempotencyKey"]
    }

    override fun findByTransactionReference(tenantId: String, transactionReference: String): PostingResult? {
        return transactions["$tenantId:$transactionReference"]
    }

    override fun findLegs(tenantId: String, transactionId: UUID): List<JournalEntryRecord> {
        return legsStore[transactionId]?.filter { it.tenantId == tenantId } ?: emptyList()
    }

    override fun findAllLegsForTenant(tenantId: String): List<JournalEntryRecord> {
        return orderedLegs.filter { it.tenantId == tenantId }
    }

    override fun findBalance(tenantId: String, accountReference: String, currencyCode: String): Long {
        var balance = 0L
        for (leg in findAllLegsForTenant(tenantId)) {
            if (leg.accountReference == accountReference && leg.currencyCode == currencyCode) {
                if (leg.direction == JournalEntryDirection.CREDIT) {
                    balance = Math.addExact(balance, leg.amountMinorUnits)
                } else {
                    balance = Math.subtractExact(balance, leg.amountMinorUnits)
                }
            }
        }
        return balance
    }

    override fun nextLedgerVersion(tenantId: String): Long {
        return tenantVersions.compute(tenantId) { _, v -> (v ?: 0L) + 1L }!!
    }

    @Synchronized
    override fun save(
        result: PostingResult,
        legs: List<JournalEntryRecord>,
        payloadDigest: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        val refKey = "${result.tenantId}:${result.transactionReference}"
        val idemKey = "${result.tenantId}:${result.idempotencyKey}"

        if (transactions.containsKey(refKey)) {
            throw IdempotencyConflictException("Duplicate transaction reference: '${result.transactionReference}'")
        }
        receipts[idemKey]?.let { (existingDigest, _) ->
            if (existingDigest != payloadDigest) {
                throw IdempotencyConflictException("Idempotency key reused with conflicting payload")
            }
        }

        transactions[refKey] = result
        receipts[idemKey] = Pair(payloadDigest, result)
        legsStore[result.resultId] = legs.toMutableList()
        orderedLegs.addAll(legs)
    }
}

@Repository
open class JdbcLedgerJournalStore(
    private val jdbc: JdbcTemplate,
    private val lockWaitMillis: Long = 5000L,
) : LedgerJournalStore {

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PostingResult>? {
        val query = """
            select r.payload_digest, t.*
            from ledger_idempotency_receipt r
            join ledger_transaction t on r.transaction_id = t.transaction_id and r.tenant_id = t.tenant_id
            where r.tenant_id = ? and r.idempotency_key = ?
        """.trimIndent()
        return jdbc.query(query, { rs, _ ->
            val digest = rs.getString("payload_digest")
            val tx = rs.toPostingResult()
            Pair(digest, tx)
        }, tenantId, idempotencyKey).firstOrNull()
    }

    override fun findByTransactionReference(tenantId: String, transactionReference: String): PostingResult? {
        val query = "select * from ledger_transaction where tenant_id = ? and transaction_reference = ?"
        return jdbc.query(query, { rs, _ -> rs.toPostingResult() }, tenantId, transactionReference).firstOrNull()
    }

    override fun findLegs(tenantId: String, transactionId: UUID): List<JournalEntryRecord> {
        val query = "select * from ledger_leg where tenant_id = ? and transaction_id = ? order by line_order"
        return jdbc.query(query, { rs, _ -> rs.toJournalEntryRecord() }, tenantId, transactionId)
    }

    override fun findAllLegsForTenant(tenantId: String): List<JournalEntryRecord> {
        val query = "select * from ledger_leg where tenant_id = ? order by created_at, line_order"
        return jdbc.query(query, { rs, _ -> rs.toJournalEntryRecord() }, tenantId)
    }

    override fun findBalance(tenantId: String, accountReference: String, currencyCode: String): Long {
        val query = """
            select coalesce(
                sum(case when direction = 'CREDIT' then amount_minor_units else -amount_minor_units end),
                0
            ) as balance
            from ledger_leg
            where tenant_id = ? and account_reference = ? and currency_code = ?
        """.trimIndent()
        return jdbc.queryForObject(query, Long::class.java, tenantId, accountReference, currencyCode) ?: 0L
    }

    override fun lockAccount(tenantId: String, accountReference: String, currencyCode: String): Boolean {
        val key = "$tenantId:$accountReference:$currencyCode"
        val deadline = System.nanoTime() + lockWaitMillis * 1_000_000L
        while (true) {
            val acquired = jdbc.queryForObject(
                "select pg_try_advisory_xact_lock(hashtext(?))",
                Boolean::class.java,
                key,
            ) ?: false
            if (acquired) {
                return true
            }
            if (System.nanoTime() >= deadline) {
                return false
            }
            Thread.sleep(20)
        }
    }

    @Transactional
    override fun nextLedgerVersion(tenantId: String): Long {
        jdbc.update("""
            insert into ledger_version_tracker (tenant_id, latest_version, updated_at)
            values (?, 1, now())
            on conflict (tenant_id) do update
            set latest_version = ledger_version_tracker.latest_version + 1, updated_at = now()
        """.trimIndent(), tenantId)
        return jdbc.queryForObject(
            "select latest_version from ledger_version_tracker where tenant_id = ?",
            Long::class.java,
            tenantId
        ) ?: 1L
    }

    @Transactional
    override fun save(
        result: PostingResult,
        legs: List<JournalEntryRecord>,
        payloadDigest: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        // 1. Insert transaction
        val txCount = jdbc.update("""
            insert into ledger_transaction (
                transaction_id, tenant_id, transaction_reference, currency_code,
                total_debits_minor_units, total_credits_minor_units, is_balanced, status,
                entry_count, idempotency_key, correlation_id, causation_id,
                posted_by, posted_at, effective_at, ledger_version,
                compensation_for_reference, evidence_reference
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent(),
            result.resultId, result.tenantId, result.transactionReference, result.currencyCode,
            result.totalDebitsMinorUnits, result.totalCreditsMinorUnits, result.isBalanced, result.status.name,
            legs.size, result.idempotencyKey, audit.correlationId, audit.causationId,
            audit.eventId.toString(), Timestamp.from(result.serverTime), Timestamp.from(result.effectiveTime), result.serverVersion,
            result.compensationForReference, result.evidenceReference
        )
        VersionedCasHelper.requireUpdated(txCount)

        // 2. Insert legs & ensure accounts
        for (leg in legs) {
            jdbc.update("""
                insert into ledger_account (account_id, tenant_id, account_reference, currency_code, account_type, status, created_at)
                values (?, ?, ?, ?, 'STANDARD', 'ACTIVE', ?)
                on conflict (tenant_id, account_reference, currency_code) do nothing
            """.trimIndent(),
                UUID.randomUUID(), result.tenantId, leg.accountReference, leg.currencyCode, Timestamp.from(leg.createdAt)
            )

            val legCount = jdbc.update("""
                insert into ledger_leg (
                    leg_id, transaction_id, tenant_id, account_reference,
                    direction, amount_minor_units, currency_code, line_order, narration, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
                leg.entryId, result.resultId, result.tenantId, leg.accountReference,
                leg.direction.name, leg.amountMinorUnits, leg.currencyCode, leg.lineOrder, leg.narration, Timestamp.from(leg.createdAt)
            )
            VersionedCasHelper.requireUpdated(legCount)
        }

        // 3. Insert idempotency receipt
        val receiptCount = jdbc.update("""
            insert into ledger_idempotency_receipt (
                receipt_id, tenant_id, idempotency_key, payload_digest, transaction_id, transaction_reference, created_at
            ) values (?, ?, ?, ?, ?, ?, ?)
        """.trimIndent(),
                UUID.randomUUID(), result.tenantId, result.idempotencyKey, payloadDigest, result.resultId, result.transactionReference, Timestamp.from(result.serverTime)
        )
        VersionedCasHelper.requireUpdated(receiptCount)

        // 4. Insert shared admin operation
        jdbc.update("""
            insert into admin_operation (result_id, tenant_id, operation_type, created_at)
            values (?, ?, 'LEDGER_TRANSACTION_POSTED', ?)
            on conflict (result_id) do nothing
        """.trimIndent(),
            result.resultId, result.tenantId, Timestamp.from(result.serverTime)
        )

        // 5. Insert audit event
        jdbc.update("""
            insert into admin_audit_event (
                event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details
            ) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))
        """.trimIndent(),
            audit.eventId, result.resultId, result.tenantId, audit.type, Timestamp.from(audit.occurredAt), audit.correlationId, audit.causationId, RedactedEventJson.audit(audit)
        )

        // 6. Insert outbox event
        jdbc.update("""
            insert into admin_outbox_event (
                event_id, result_id, tenant_id, event_type, created_at, payload
            ) values (?, ?, ?, ?, ?, cast(? as jsonb))
        """.trimIndent(),
            outbox.eventId, result.resultId, result.tenantId, outbox.type, Timestamp.from(outbox.createdAt), RedactedEventJson.outbox(outbox, audit)
        )
    }

    private fun ResultSet.toPostingResult(): PostingResult {
        val txId = getObject("transaction_id", UUID::class.java)
        val debits = getLong("total_debits_minor_units")
        val credits = getLong("total_credits_minor_units")
        val version = getLong("ledger_version")
        val postedAt = getTimestamp("posted_at").toInstant()
        val effectiveAt = getTimestamp("effective_at")?.toInstant() ?: postedAt
        val compRef = getString("compensation_for_reference")

        return PostingResult(
            resultId = txId,
            tenantId = getString("tenant_id"),
            transactionReference = getString("transaction_reference"),
            currencyCode = getString("currency_code"),
            totalDebitsMinorUnits = debits,
            totalCreditsMinorUnits = credits,
            isBalanced = getBoolean("is_balanced"),
            status = JournalBatchStatus.valueOf(getString("status")),
            entryCount = getInt("entry_count"),
            idempotencyKey = getString("idempotency_key"),
            serverTime = postedAt,
            serverVersion = version,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            directBalanceWriteProhibited = true,
            evidenceReference = getString("evidence_reference"),
            effectiveTime = effectiveAt,
            recordedTime = postedAt,
            operationId = txId,
            committedVersion = version,
            compensationForReference = compRef,
        )
    }

    private fun ResultSet.toJournalEntryRecord(): JournalEntryRecord {
        return JournalEntryRecord(
            entryId = getObject("leg_id", UUID::class.java),
            batchId = getObject("transaction_id", UUID::class.java),
            tenantId = getString("tenant_id"),
            accountReference = getString("account_reference"),
            direction = JournalEntryDirection.valueOf(getString("direction")),
            amountMinorUnits = getLong("amount_minor_units"),
            currencyCode = getString("currency_code"),
            lineOrder = getInt("line_order"),
            narration = getString("narration"),
            createdAt = getTimestamp("created_at").toInstant(),
        )
    }
}
