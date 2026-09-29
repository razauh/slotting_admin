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

import java.time.Clock

interface PayoutDispatchStore {
    fun saveIntent(intent: PayoutDispatchIntentRecord): PayoutDispatchIntentRecord
    fun findIntent(tenantId: String, intentId: UUID): PayoutDispatchIntentRecord?
    fun findIntentByRequestId(tenantId: String, requestId: UUID): PayoutDispatchIntentRecord?
    fun findIntentByIdempotency(tenantId: String, idempotencyKey: String): PayoutDispatchIntentRecord?
    fun acquireLease(tenantId: String, intentId: UUID, workerId: String, leaseExpiresAt: Instant): Boolean
    fun findNextDispatchable(workerId: String, leaseExpiresAt: Instant, now: Instant): PayoutDispatchIntentRecord?
    fun updateIntent(intent: PayoutDispatchIntentRecord, expectedVersion: Long): PayoutDispatchIntentRecord
    fun recordAudit(audit: PayoutReconciliationAuditRecord)
}

class InMemoryPayoutDispatchStore(private val clock: Clock = Clock.systemUTC()) : PayoutDispatchStore {
    private val intentsById = ConcurrentHashMap<String, PayoutDispatchIntentRecord>()
    private val intentsByRequest = ConcurrentHashMap<String, PayoutDispatchIntentRecord>()
    private val intentsByIdemp = ConcurrentHashMap<String, PayoutDispatchIntentRecord>()
    private val audits = mutableListOf<PayoutReconciliationAuditRecord>()

    private fun idKey(tenantId: String, id: UUID) = "$tenantId:$id"
    private fun reqKey(tenantId: String, id: UUID) = "$tenantId:$id"
    private fun idempKey(tenantId: String, key: String) = "$tenantId:$key"

    @Synchronized
    override fun saveIntent(intent: PayoutDispatchIntentRecord): PayoutDispatchIntentRecord {
        intentsById[idKey(intent.tenantId, intent.intentId)] = intent.copy()
        intentsByRequest[reqKey(intent.tenantId, intent.requestId)] = intent.copy()
        intentsByIdemp[idempKey(intent.tenantId, intent.idempotencyKey)] = intent.copy()
        return intent
    }

    @Synchronized
    override fun findIntent(tenantId: String, intentId: UUID): PayoutDispatchIntentRecord? {
        return intentsById[idKey(tenantId, intentId)]?.copy()
    }

    @Synchronized
    override fun findIntentByRequestId(tenantId: String, requestId: UUID): PayoutDispatchIntentRecord? {
        return intentsByRequest[reqKey(tenantId, requestId)]?.copy()
    }

    @Synchronized
    override fun findIntentByIdempotency(tenantId: String, idempotencyKey: String): PayoutDispatchIntentRecord? {
        return intentsByIdemp[idempKey(tenantId, idempotencyKey)]?.copy()
    }

    @Synchronized
    override fun acquireLease(tenantId: String, intentId: UUID, workerId: String, leaseExpiresAt: Instant): Boolean {
        val key = idKey(tenantId, intentId)
        val existing = intentsById[key] ?: return false
        val isLeaseExpired = existing.leaseExpiresAt == null || existing.leaseExpiresAt.isBefore(clock.instant())
        if (existing.leaseWorkerId != null && !isLeaseExpired && existing.leaseWorkerId != workerId) {
            return false
        }
        val updated = existing.copy(
            leaseWorkerId = workerId,
            leaseExpiresAt = leaseExpiresAt,
            serverVersion = existing.serverVersion + 1,
        )
        intentsById[key] = updated
        intentsByRequest[reqKey(tenantId, existing.requestId)] = updated
        intentsByIdemp[idempKey(tenantId, existing.idempotencyKey)] = updated
        return true
    }

    @Synchronized
    override fun findNextDispatchable(workerId: String, leaseExpiresAt: Instant, now: Instant): PayoutDispatchIntentRecord? {
        val candidate = intentsById.values.firstOrNull { intent ->
            val canDispatch = intent.status in setOf(
                PayoutDispatchStatus.DISPATCH_READY,
                PayoutDispatchStatus.SENT_PENDING,
                PayoutDispatchStatus.AMBIGUOUS_RECONCILING,
            )
            val isLeaseAvailable = intent.leaseWorkerId == null ||
                    intent.leaseExpiresAt == null ||
                    intent.leaseExpiresAt.isBefore(now)
            canDispatch && isLeaseAvailable
        } ?: return null

        val leased = candidate.copy(
            leaseWorkerId = workerId,
            leaseExpiresAt = leaseExpiresAt,
            status = PayoutDispatchStatus.SENT_PENDING,
            attemptCount = candidate.attemptCount + 1,
            serverVersion = candidate.serverVersion + 1,
            updatedAt = now,
        )
        val key = idKey(leased.tenantId, leased.intentId)
        intentsById[key] = leased
        intentsByRequest[reqKey(leased.tenantId, leased.requestId)] = leased
        intentsByIdemp[idempKey(leased.tenantId, leased.idempotencyKey)] = leased
        return leased
    }

    @Synchronized
    override fun updateIntent(intent: PayoutDispatchIntentRecord, expectedVersion: Long): PayoutDispatchIntentRecord {
        val key = idKey(intent.tenantId, intent.intentId)
        val existing = intentsById[key] ?: throw IllegalStateException("Intent ${intent.intentId} does not exist")
        if (existing.serverVersion != expectedVersion) {
            throw IllegalStateException("CAS failure on intent ${intent.intentId}: expected $expectedVersion but found ${existing.serverVersion}")
        }
        intentsById[key] = intent.copy()
        intentsByRequest[reqKey(intent.tenantId, intent.requestId)] = intent.copy()
        intentsByIdemp[idempKey(intent.tenantId, intent.idempotencyKey)] = intent.copy()
        return intent
    }

    @Synchronized
    override fun recordAudit(audit: PayoutReconciliationAuditRecord) {
        audits.add(audit.copy())
    }

    @Synchronized
    fun getAudits(): List<PayoutReconciliationAuditRecord> = audits.toList()
}

@Repository
class JdbcPayoutDispatchStore(private val jdbc: JdbcTemplate) : PayoutDispatchStore {

    private fun ResultSet.toIntentRecord(): PayoutDispatchIntentRecord = PayoutDispatchIntentRecord(
        intentId = getObject("intent_id", UUID::class.java),
        tenantId = getString("tenant_id"),
        requestId = getObject("request_id", UUID::class.java),
        ownerId = getObject("owner_id", UUID::class.java),
        reservationId = getObject("reservation_id", UUID::class.java),
        methodId = getString("method_id"),
        providerId = getString("provider_id"),
        destinationReference = getString("destination_reference"),
        grossAmountMinorUnits = getLong("gross_amount_minor_units"),
        feeMinorUnits = getLong("fee_minor_units"),
        netPayoutAmountMinorUnits = getLong("net_payout_amount_minor_units"),
        currencyCode = getString("currency"),
        idempotencyKey = getString("idempotency_key"),
        providerReference = getString("provider_reference"),
        status = PayoutDispatchStatus.valueOf(getString("status")),
        leaseWorkerId = getString("lease_worker_id"),
        leaseExpiresAt = getTimestamp("lease_expires_at")?.toInstant(),
        attemptCount = getInt("attempt_count"),
        ledgerTransactionReference = getString("ledger_transaction_reference"),
        failureReason = getString("failure_reason"),
        serverVersion = getLong("server_version"),
        createdAt = getTimestamp("created_at").toInstant(),
        updatedAt = getTimestamp("updated_at").toInstant(),
    )

    @Transactional
    override fun saveIntent(intent: PayoutDispatchIntentRecord): PayoutDispatchIntentRecord {
        val inserted = jdbc.update(
            """
            INSERT INTO admin_payout_dispatch_intent (
                intent_id, tenant_id, request_id, owner_id, reservation_id,
                method_id, provider_id, destination_reference, gross_amount_minor_units,
                fee_minor_units, net_payout_amount_minor_units, currency, idempotency_key,
                provider_reference, status, lease_worker_id, lease_expires_at,
                attempt_count, ledger_transaction_reference, failure_reason,
                server_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            intent.intentId,
            intent.tenantId,
            intent.requestId,
            intent.ownerId,
            intent.reservationId,
            intent.methodId,
            intent.providerId,
            intent.destinationReference,
            intent.grossAmountMinorUnits,
            intent.feeMinorUnits,
            intent.netPayoutAmountMinorUnits,
            intent.currencyCode,
            intent.idempotencyKey,
            intent.providerReference,
            intent.status.name,
            intent.leaseWorkerId,
            intent.leaseExpiresAt?.let { Timestamp.from(it) },
            intent.attemptCount,
            intent.ledgerTransactionReference,
            intent.failureReason,
            intent.serverVersion,
            Timestamp.from(intent.createdAt),
            Timestamp.from(intent.updatedAt),
        )
        VersionedCasHelper.requireUpdated(inserted)
        return intent
    }

    override fun findIntent(tenantId: String, intentId: UUID): PayoutDispatchIntentRecord? {
        return jdbc.query(
            "SELECT * FROM admin_payout_dispatch_intent WHERE tenant_id = ? AND intent_id = ?",
            { rs, _ -> rs.toIntentRecord() },
            tenantId,
            intentId,
        ).firstOrNull()
    }

    override fun findIntentByRequestId(tenantId: String, requestId: UUID): PayoutDispatchIntentRecord? {
        return jdbc.query(
            "SELECT * FROM admin_payout_dispatch_intent WHERE tenant_id = ? AND request_id = ?",
            { rs, _ -> rs.toIntentRecord() },
            tenantId,
            requestId,
        ).firstOrNull()
    }

    override fun findIntentByIdempotency(tenantId: String, idempotencyKey: String): PayoutDispatchIntentRecord? {
        return jdbc.query(
            "SELECT * FROM admin_payout_dispatch_intent WHERE tenant_id = ? AND idempotency_key = ?",
            { rs, _ -> rs.toIntentRecord() },
            tenantId,
            idempotencyKey,
        ).firstOrNull()
    }

    @Transactional
    override fun acquireLease(tenantId: String, intentId: UUID, workerId: String, leaseExpiresAt: Instant): Boolean {
        val updated = jdbc.update(
            """
            UPDATE admin_payout_dispatch_intent
            SET lease_worker_id = ?, lease_expires_at = ?, server_version = server_version + 1, updated_at = NOW()
            WHERE tenant_id = ? AND intent_id = ? AND (lease_worker_id IS NULL OR lease_expires_at < NOW() OR lease_worker_id = ?)
            """.trimIndent(),
            workerId,
            Timestamp.from(leaseExpiresAt),
            tenantId,
            intentId,
            workerId,
        )
        return updated > 0
    }

    @Transactional
    override fun findNextDispatchable(workerId: String, leaseExpiresAt: Instant, now: Instant): PayoutDispatchIntentRecord? {
        val selectSql = """
            SELECT intent_id, tenant_id FROM admin_payout_dispatch_intent
            WHERE status IN ('DISPATCH_READY', 'SENT_PENDING', 'AMBIGUOUS_RECONCILING')
              AND (lease_worker_id IS NULL OR lease_expires_at < ?)
            ORDER BY created_at ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        """.trimIndent()

        val candidate = jdbc.query(
            selectSql,
            { rs, _ -> rs.getString("tenant_id") to rs.getObject("intent_id", UUID::class.java) },
            Timestamp.from(now),
        ).firstOrNull() ?: return null

        val updated = jdbc.update(
            """
            UPDATE admin_payout_dispatch_intent
            SET lease_worker_id = ?, lease_expires_at = ?, status = 'SENT_PENDING',
                attempt_count = attempt_count + 1, server_version = server_version + 1, updated_at = ?
            WHERE tenant_id = ? AND intent_id = ?
            """.trimIndent(),
            workerId,
            Timestamp.from(leaseExpiresAt),
            Timestamp.from(now),
            candidate.first,
            candidate.second,
        )
        if (updated == 0) return null
        return findIntent(candidate.first, candidate.second)
    }

    @Transactional
    override fun updateIntent(intent: PayoutDispatchIntentRecord, expectedVersion: Long): PayoutDispatchIntentRecord {
        val updated = jdbc.update(
            """
            UPDATE admin_payout_dispatch_intent
            SET status = ?, provider_reference = ?, lease_worker_id = ?,
                lease_expires_at = ?, attempt_count = ?, ledger_transaction_reference = ?,
                failure_reason = ?, server_version = ?, updated_at = ?
            WHERE tenant_id = ? AND intent_id = ? AND server_version = ?
            """.trimIndent(),
            intent.status.name,
            intent.providerReference,
            intent.leaseWorkerId,
            intent.leaseExpiresAt?.let { Timestamp.from(it) },
            intent.attemptCount,
            intent.ledgerTransactionReference,
            intent.failureReason,
            intent.serverVersion,
            Timestamp.from(intent.updatedAt),
            intent.tenantId,
            intent.intentId,
            expectedVersion,
        )
        VersionedCasHelper.requireUpdated(updated)
        return intent
    }

    @Transactional
    override fun recordAudit(audit: PayoutReconciliationAuditRecord) {
        jdbc.update(
            """
            INSERT INTO admin_payout_reconciliation_audit (
                audit_id, tenant_id, intent_id, action_type, previous_status,
                new_status, operator_id, notes, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            audit.auditId,
            audit.tenantId,
            audit.intentId,
            audit.actionType,
            audit.previousStatus.name,
            audit.newStatus.name,
            audit.operatorId,
            audit.notes,
            Timestamp.from(audit.occurredAt),
        )
    }
}
