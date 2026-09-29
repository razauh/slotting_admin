package com.slotting.admin.deposit

import com.slotting.admin.infra.VersionedCasHelper
import org.springframework.dao.DuplicateKeyException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.sql.Timestamp
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

interface DepositWorkflowStore {
    fun saveIntent(record: DepositIntentRecord): DepositIntentRecord
    fun findIntent(tenantId: String, intentId: UUID): DepositIntentRecord?
    fun findIntentByIdempotencyKey(tenantId: String, idempotencyKey: String): DepositIntentRecord?
    fun findIntentByProviderReference(tenantId: String, providerReference: String): DepositIntentRecord?
    fun updateIntent(record: DepositIntentRecord, expectedVersion: Long): DepositIntentRecord
    fun recordInboxEvent(inbox: DepositInboxRecord): Boolean
    fun findInboxEvent(tenantId: String, providerId: String, providerEventId: String): DepositInboxRecord?
    fun updateInboxEvent(inbox: DepositInboxRecord)
    fun recordReconciliation(record: DepositReconciliationRecord)
}

class InMemoryDepositWorkflowStore : DepositWorkflowStore {
    private val intentsById = ConcurrentHashMap<String, DepositIntentRecord>()
    private val intentsByIdempotency = ConcurrentHashMap<String, DepositIntentRecord>()
    private val intentsByProviderRef = ConcurrentHashMap<String, DepositIntentRecord>()
    private val inboxEvents = ConcurrentHashMap<String, DepositInboxRecord>()
    private val reconciliations = mutableListOf<DepositReconciliationRecord>()

    private fun idKey(tenantId: String, intentId: UUID) = "$tenantId:$intentId"
    private fun idemKey(tenantId: String, idempotencyKey: String) = "$tenantId:$idempotencyKey"
    private fun provKey(tenantId: String, ref: String) = "$tenantId:$ref"
    private fun inboxKey(tenantId: String, providerId: String, eventId: String) = "$tenantId:$providerId:$eventId"

    @Synchronized
    override fun saveIntent(record: DepositIntentRecord): DepositIntentRecord {
        val iKey = idKey(record.tenantId, record.intentId)
        val imKey = idemKey(record.tenantId, record.idempotencyKey)
        if (intentsByIdempotency.containsKey(imKey)) {
            throw IllegalArgumentException("Intent with idempotencyKey ${record.idempotencyKey} already exists")
        }
        intentsById[iKey] = record.copy()
        intentsByIdempotency[imKey] = record.copy()
        record.providerReference?.let {
            intentsByProviderRef[provKey(record.tenantId, it)] = record.copy()
        }
        return record
    }

    @Synchronized
    override fun findIntent(tenantId: String, intentId: UUID): DepositIntentRecord? {
        return intentsById[idKey(tenantId, intentId)]?.copy()
    }

    @Synchronized
    override fun findIntentByIdempotencyKey(tenantId: String, idempotencyKey: String): DepositIntentRecord? {
        return intentsByIdempotency[idemKey(tenantId, idempotencyKey)]?.copy()
    }

    @Synchronized
    override fun findIntentByProviderReference(tenantId: String, providerReference: String): DepositIntentRecord? {
        return intentsByProviderRef[provKey(tenantId, providerReference)]?.copy()
    }

    @Synchronized
    override fun updateIntent(record: DepositIntentRecord, expectedVersion: Long): DepositIntentRecord {
        val iKey = idKey(record.tenantId, record.intentId)
        val existing = intentsById[iKey]
            ?: throw IllegalStateException("Intent ${record.intentId} does not exist")
        if (existing.serverVersion != expectedVersion) {
            throw IllegalStateException("CAS update failed for intent ${record.intentId}: expected $expectedVersion but found ${existing.serverVersion}")
        }
        intentsById[iKey] = record.copy()
        intentsByIdempotency[idemKey(record.tenantId, record.idempotencyKey)] = record.copy()
        record.providerReference?.let {
            intentsByProviderRef[provKey(record.tenantId, it)] = record.copy()
        }
        return record
    }

    @Synchronized
    override fun recordInboxEvent(inbox: DepositInboxRecord): Boolean {
        val key = inboxKey(inbox.tenantId, inbox.providerId, inbox.providerEventId)
        if (inboxEvents.containsKey(key)) {
            return false
        }
        inboxEvents[key] = inbox.copy()
        return true
    }

    @Synchronized
    override fun findInboxEvent(tenantId: String, providerId: String, providerEventId: String): DepositInboxRecord? {
        return inboxEvents[inboxKey(tenantId, providerId, providerEventId)]?.copy()
    }

    @Synchronized
    override fun updateInboxEvent(inbox: DepositInboxRecord) {
        val key = inboxKey(inbox.tenantId, inbox.providerId, inbox.providerEventId)
        inboxEvents[key] = inbox.copy()
    }

    @Synchronized
    override fun recordReconciliation(record: DepositReconciliationRecord) {
        reconciliations.add(record.copy())
    }

    @Synchronized
    fun getReconciliations(): List<DepositReconciliationRecord> = reconciliations.toList()
}

@Repository
class JdbcDepositWorkflowStore(private val jdbc: JdbcTemplate) : DepositWorkflowStore {

    private fun ResultSet.toIntentRecord(): DepositIntentRecord = DepositIntentRecord(
        intentId = getObject("intent_id", UUID::class.java),
        tenantId = getString("tenant_id"),
        playerId = getObject("player_id", UUID::class.java),
        methodId = getString("method_id"),
        providerId = getString("provider_id"),
        amountMinorUnits = getLong("amount_minor_units"),
        currencyCode = getString("currency"),
        status = DepositIntentStatus.valueOf(getString("status")),
        idempotencyKey = getString("idempotency_key"),
        requestFingerprint = getString("request_fingerprint"),
        providerReference = getString("provider_reference"),
        redirectUrl = getString("redirect_url"),
        clientSecret = getString("client_secret"),
        failureReason = getString("failure_reason"),
        ledgerTransactionReference = getString("ledger_transaction_reference"),
        settledAt = getTimestamp("settled_at")?.toInstant(),
        expiresAt = getTimestamp("expires_at").toInstant(),
        serverVersion = getLong("server_version"),
        createdAt = getTimestamp("created_at").toInstant(),
        updatedAt = getTimestamp("updated_at").toInstant(),
    )

    private fun ResultSet.toInboxRecord(): DepositInboxRecord = DepositInboxRecord(
        inboxId = getObject("inbox_id", UUID::class.java),
        tenantId = getString("tenant_id"),
        providerId = getString("provider_id"),
        providerEventId = getString("provider_event_id"),
        intentId = getObject("intent_id", UUID::class.java),
        status = getString("status"),
        signatureVerified = getBoolean("signature_verified"),
        payloadHash = getString("payload_hash"),
        receivedAt = getTimestamp("received_at").toInstant(),
        processedAt = getTimestamp("processed_at")?.toInstant(),
    )

    @Transactional
    override fun saveIntent(record: DepositIntentRecord): DepositIntentRecord {
        val inserted = jdbc.update(
            """
            INSERT INTO admin_deposit_intent (
                intent_id, tenant_id, player_id, method_id, provider_id,
                amount_minor_units, currency, status, idempotency_key, request_fingerprint,
                provider_reference, redirect_url, client_secret, failure_reason,
                ledger_transaction_reference, settled_at, expires_at, server_version,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            record.intentId,
            record.tenantId,
            record.playerId,
            record.methodId,
            record.providerId,
            record.amountMinorUnits,
            record.currencyCode,
            record.status.name,
            record.idempotencyKey,
            record.requestFingerprint,
            record.providerReference,
            record.redirectUrl,
            record.clientSecret,
            record.failureReason,
            record.ledgerTransactionReference,
            record.settledAt?.let { Timestamp.from(it) },
            Timestamp.from(record.expiresAt),
            record.serverVersion,
            Timestamp.from(record.createdAt),
            Timestamp.from(record.updatedAt),
        )
        VersionedCasHelper.requireUpdated(inserted)
        return record
    }

    override fun findIntent(tenantId: String, intentId: UUID): DepositIntentRecord? {
        return jdbc.query(
            "SELECT * FROM admin_deposit_intent WHERE tenant_id = ? AND intent_id = ?",
            { rs, _ -> rs.toIntentRecord() },
            tenantId,
            intentId,
        ).firstOrNull()
    }

    override fun findIntentByIdempotencyKey(tenantId: String, idempotencyKey: String): DepositIntentRecord? {
        return jdbc.query(
            "SELECT * FROM admin_deposit_intent WHERE tenant_id = ? AND idempotency_key = ?",
            { rs, _ -> rs.toIntentRecord() },
            tenantId,
            idempotencyKey,
        ).firstOrNull()
    }

    override fun findIntentByProviderReference(tenantId: String, providerReference: String): DepositIntentRecord? {
        return jdbc.query(
            "SELECT * FROM admin_deposit_intent WHERE tenant_id = ? AND provider_reference = ?",
            { rs, _ -> rs.toIntentRecord() },
            tenantId,
            providerReference,
        ).firstOrNull()
    }

    @Transactional
    override fun updateIntent(record: DepositIntentRecord, expectedVersion: Long): DepositIntentRecord {
        val updated = jdbc.update(
            """
            UPDATE admin_deposit_intent
            SET status = ?,
                provider_reference = ?,
                redirect_url = ?,
                client_secret = ?,
                failure_reason = ?,
                ledger_transaction_reference = ?,
                settled_at = ?,
                expires_at = ?,
                server_version = ?,
                updated_at = ?
            WHERE tenant_id = ? AND intent_id = ? AND server_version = ?
            """.trimIndent(),
            record.status.name,
            record.providerReference,
            record.redirectUrl,
            record.clientSecret,
            record.failureReason,
            record.ledgerTransactionReference,
            record.settledAt?.let { Timestamp.from(it) },
            Timestamp.from(record.expiresAt),
            record.serverVersion,
            Timestamp.from(record.updatedAt),
            record.tenantId,
            record.intentId,
            expectedVersion,
        )
        VersionedCasHelper.requireUpdated(updated)
        return record
    }

    @Transactional
    override fun recordInboxEvent(inbox: DepositInboxRecord): Boolean {
        return try {
            val inserted = jdbc.update(
                """
                INSERT INTO admin_deposit_inbox (
                    inbox_id, tenant_id, provider_id, provider_event_id, intent_id,
                    status, signature_verified, payload_hash, received_at, processed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, provider_id, provider_event_id) DO NOTHING
                """.trimIndent(),
                inbox.inboxId,
                inbox.tenantId,
                inbox.providerId,
                inbox.providerEventId,
                inbox.intentId,
                inbox.status,
                inbox.signatureVerified,
                inbox.payloadHash,
                Timestamp.from(inbox.receivedAt),
                inbox.processedAt?.let { Timestamp.from(it) },
            )
            inserted > 0
        } catch (e: DuplicateKeyException) {
            false
        }
    }

    override fun findInboxEvent(tenantId: String, providerId: String, providerEventId: String): DepositInboxRecord? {
        return jdbc.query(
            "SELECT * FROM admin_deposit_inbox WHERE tenant_id = ? AND provider_id = ? AND provider_event_id = ?",
            { rs, _ -> rs.toInboxRecord() },
            tenantId,
            providerId,
            providerEventId,
        ).firstOrNull()
    }

    @Transactional
    override fun updateInboxEvent(inbox: DepositInboxRecord) {
        jdbc.update(
            """
            UPDATE admin_deposit_inbox
            SET status = ?, processed_at = ?
            WHERE tenant_id = ? AND provider_id = ? AND provider_event_id = ?
            """.trimIndent(),
            inbox.status,
            inbox.processedAt?.let { Timestamp.from(it) },
            inbox.tenantId,
            inbox.providerId,
            inbox.providerEventId,
        )
    }

    @Transactional
    override fun recordReconciliation(record: DepositReconciliationRecord) {
        jdbc.update(
            """
            INSERT INTO admin_deposit_reconciliation (
                reconciliation_id, tenant_id, intent_id, action_type,
                previous_status, new_status, performed_by, occurred_at, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            record.reconciliationId,
            record.tenantId,
            record.intentId,
            record.actionType,
            record.previousStatus.name,
            record.newStatus.name,
            record.performedBy,
            Timestamp.from(record.occurredAt),
            record.notes,
        )
    }
}
