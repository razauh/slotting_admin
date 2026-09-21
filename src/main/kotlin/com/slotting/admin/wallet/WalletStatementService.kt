package com.slotting.admin.wallet

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * Authoritative backend service providing balance snapshots and cursor-paginated statements.
 *
 * Implements WALLET-004:
 * Semantic contract: "Snapshot includes as-of/version; statements map postings, never local activity."
 * Protected risk assertion: "ownership leak/inconsistent page"
 */
class WalletStatementService(
    private val bucketStore: BalanceBucketsStore,
    private val statementStore: WalletStatementStore,
    private val clock: Clock = Clock.systemUTC(),
    private val observability: WalletStatementObservability = InMemoryWalletStatementObservability()
) {

    // =========================================================================
    // 1. Authoritative Balance Snapshot Query
    // =========================================================================

    fun getBalanceSnapshot(query: BalanceSnapshotQuery): BalanceSnapshotResult {
        WalletStatementBinding.checkBound()

        observability.recordMetric(
            StatementMetricEvent(
                eventType = "attempt",
                tenantId = query.tenantId,
                ownerId = query.ownerId,
                correlationId = query.correlationId,
                causationId = query.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "GET_BALANCE_SNAPSHOT", "currency" to query.currencyCode)
            )
        )

        // 1. Authentication Check
        val principal = query.principal ?: throw UnauthorizedWalletAccessException(
            "Authentication required for balance snapshot"
        )

        // 2. Tenant Boundary
        if (principal.tenantId != query.tenantId) {
            observability.recordMetric(
                StatementMetricEvent(
                    eventType = "reject",
                    tenantId = query.tenantId,
                    ownerId = query.ownerId,
                    correlationId = query.correlationId,
                    causationId = query.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "CROSS_TENANT_ACCESS_DENIED")
                )
            )
            throw CrossTenantAccessException(
                "Cross-tenant balance access denied: principal ${principal.tenantId} != query ${query.tenantId}"
            )
        }

        // 3. Ownership Leak Protection (IDOR Prevention)
        if (principal.kind == PrincipalKind.PLAYER && principal.id != query.ownerId.toString()) {
            observability.recordMetric(
                StatementMetricEvent(
                    eventType = "reject",
                    tenantId = query.tenantId,
                    ownerId = query.ownerId,
                    correlationId = query.correlationId,
                    causationId = query.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "IDOR_FORBIDDEN", "principalId" to principal.id, "targetOwner" to query.ownerId.toString())
                )
            )
            throw IdorForbiddenException(
                "ownership leak/inconsistent page: cross-owner balance access denied for principal ${principal.id}"
            )
        }

        // 4. Authoritative Wallet Lookup
        val wallet = if (query.walletId != null) {
            bucketStore.findWalletById(query.tenantId, query.walletId)
        } else {
            bucketStore.findWalletByOwnerAndCurrency(query.tenantId, query.ownerId, query.currencyCode)
        } ?: throw WalletNotFoundException(
            "Authoritative wallet not found for owner ${query.ownerId} and currency ${query.currencyCode}"
        )

        if (wallet.tenantId != query.tenantId) {
            throw CrossTenantAccessException("Wallet tenant ${wallet.tenantId} != query ${query.tenantId}")
        }
        if (wallet.ownerId != query.ownerId) {
            throw IdorForbiddenException("ownership leak/inconsistent page: wallet owner does not match query owner")
        }

        val asOf = clock.instant()
        val evidenceRef = "EVID-SNAP-${wallet.walletId}-${wallet.version}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = wallet.walletId,
            tenantId = query.tenantId,
            type = "WALLET_BALANCE_SNAPSHOT_ACCESSED",
            occurredAt = asOf,
            correlationId = query.correlationId,
            causationId = query.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = wallet.walletId,
            tenantId = query.tenantId,
            type = "WALLET_BALANCE_SNAPSHOT_ACCESSED",
            createdAt = asOf
        )

        observability.recordMetric(
            StatementMetricEvent(
                eventType = "accept",
                tenantId = query.tenantId,
                ownerId = query.ownerId,
                correlationId = query.correlationId,
                causationId = query.causationId,
                timestamp = asOf,
                details = mapOf("version" to wallet.version, "total" to wallet.totalBalanceMinorUnits)
            )
        )

        return BalanceSnapshotResult(
            walletId = wallet.walletId,
            tenantId = wallet.tenantId,
            ownerId = wallet.ownerId,
            currencyCode = wallet.currencyCode,
            asOfTime = asOf,
            version = wallet.version,
            totalBalanceMinorUnits = wallet.totalBalanceMinorUnits,
            availableBalanceMinorUnits = wallet.availableWageringMinorUnits,
            lockedBalanceMinorUnits = wallet.lockedBalanceMinorUnits,
            pendingBalanceMinorUnits = wallet.pendingBalanceMinorUnits,
            withdrawableCashMinorUnits = wallet.withdrawableCashMinorUnits,
            cash = wallet.cash,
            bonus = wallet.bonus,
            evidenceReference = evidenceRef,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent,
            hasAndroidDbImpact = false,
            hasAndroidLifecycleClaim = false
        )
    }

    // =========================================================================
    // 2. Authoritative Statement Query (Keyset / Cursor Pagination)
    // =========================================================================

    fun getStatement(query: GetStatementQuery): StatementPageResult {
        WalletStatementBinding.checkBound()

        observability.recordMetric(
            StatementMetricEvent(
                eventType = "attempt",
                tenantId = query.tenantId,
                ownerId = query.ownerId,
                correlationId = query.correlationId,
                causationId = query.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "GET_STATEMENT", "limit" to query.limit)
            )
        )

        // 1. Authentication Check
        val principal = query.principal ?: throw UnauthorizedWalletAccessException(
            "Authentication required for statement query"
        )

        // 2. Tenant Boundary
        if (principal.tenantId != query.tenantId) {
            observability.recordMetric(
                StatementMetricEvent(
                    eventType = "reject",
                    tenantId = query.tenantId,
                    ownerId = query.ownerId,
                    correlationId = query.correlationId,
                    causationId = query.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "CROSS_TENANT_ACCESS_DENIED")
                )
            )
            throw CrossTenantAccessException(
                "Cross-tenant statement access denied: principal ${principal.tenantId} != query ${query.tenantId}"
            )
        }

        // 3. Ownership Leak Protection (IDOR Prevention)
        if (principal.kind == PrincipalKind.PLAYER && principal.id != query.ownerId.toString()) {
            observability.recordMetric(
                StatementMetricEvent(
                    eventType = "reject",
                    tenantId = query.tenantId,
                    ownerId = query.ownerId,
                    correlationId = query.correlationId,
                    causationId = query.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "IDOR_FORBIDDEN", "principalId" to principal.id, "targetOwner" to query.ownerId.toString())
                )
            )
            throw IdorForbiddenException(
                "ownership leak/inconsistent page: cross-owner statement access denied for principal ${principal.id}"
            )
        }

        // 4. Input Boundary Validation
        if (query.limit <= 0 || query.limit > 100) {
            observability.recordMetric(
                StatementMetricEvent(
                    eventType = "reject",
                    tenantId = query.tenantId,
                    ownerId = query.ownerId,
                    correlationId = query.correlationId,
                    causationId = query.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "INVALID_LIMIT", "limit" to query.limit)
                )
            )
            throw InvalidStatementRequestException(
                "Page limit must be between 1 and 100 inclusive, requested ${query.limit}"
            )
        }

        // 5. Decode Keyset Cursor to prevent inconsistent pages
        val afterSeq = query.cursor?.let { decodeCursor(it, query.tenantId, query.ownerId, query.currencyCode) }

        // 6. Query limit + 1 entries to accurately determine hasMore
        val rawEntries = statementStore.queryEntries(
            tenantId = query.tenantId,
            ownerId = query.ownerId,
            currencyCode = query.currencyCode,
            afterSeq = afterSeq,
            limit = query.limit + 1,
            fromTime = query.fromTime,
            toTime = query.toTime
        )

        val hasMore = rawEntries.size > query.limit
        val pageEntries = if (hasMore) rawEntries.take(query.limit) else rawEntries

        val nextCursor = if (hasMore && pageEntries.isNotEmpty()) {
            encodeCursor(query.tenantId, query.ownerId, query.currencyCode, pageEntries.last().sequenceNumber)
        } else {
            null
        }

        // Resolve current wallet version for authoritative snapshot timestamp
        val wallet = bucketStore.findWalletByOwnerAndCurrency(query.tenantId, query.ownerId, query.currencyCode)
        val asOf = clock.instant()
        val currentVersion = wallet?.version ?: 1L
        val evidenceRef = "EVID-STMT-${query.tenantId}-${query.ownerId}-$currentVersion"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = UUID.randomUUID(),
            tenantId = query.tenantId,
            type = "WALLET_STATEMENT_ACCESSED",
            occurredAt = asOf,
            correlationId = query.correlationId,
            causationId = query.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = UUID.randomUUID(),
            tenantId = query.tenantId,
            type = "WALLET_STATEMENT_ACCESSED",
            createdAt = asOf
        )

        observability.recordMetric(
            StatementMetricEvent(
                eventType = "query",
                tenantId = query.tenantId,
                ownerId = query.ownerId,
                correlationId = query.correlationId,
                causationId = query.causationId,
                timestamp = asOf,
                details = mapOf("entriesReturned" to pageEntries.size, "hasMore" to hasMore)
            )
        )

        return StatementPageResult(
            entries = pageEntries,
            nextCursor = nextCursor,
            hasMore = hasMore,
            pageSize = pageEntries.size,
            asOfTime = asOf,
            version = currentVersion,
            evidenceReference = evidenceRef,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent,
            hasAndroidDbImpact = false,
            hasAndroidLifecycleClaim = false
        )
    }

    // =========================================================================
    // Cursor Encoding / Decoding (Keyset Pagination)
    // =========================================================================

    private fun encodeCursor(
        tenantId: String,
        ownerId: UUID,
        currencyCode: String,
        sequenceNumber: Long
    ): String {
        val raw = "$tenantId:$ownerId:$currencyCode:$sequenceNumber"
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.toByteArray(StandardCharsets.UTF_8))
    }

    private fun decodeCursor(
        cursor: String,
        expectedTenantId: String,
        expectedOwnerId: UUID,
        expectedCurrencyCode: String
    ): Long {
        val decoded = try {
            String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8)
        } catch (e: Exception) {
            throw InvalidCursorException("ownership leak/inconsistent page: malformed cursor encoding")
        }

        val parts = decoded.split(":")
        if (parts.size != 4) {
            throw InvalidCursorException("ownership leak/inconsistent page: invalid cursor token format")
        }

        val (tenant, ownerStr, currency, seqStr) = parts
        if (tenant != expectedTenantId || ownerStr != expectedOwnerId.toString() || currency != expectedCurrencyCode) {
            throw InvalidCursorException("ownership leak/inconsistent page: cursor tenant/owner/currency mismatch")
        }

        return seqStr.toLongOrNull()
            ?: throw InvalidCursorException("ownership leak/inconsistent page: invalid cursor sequence number")
    }
}
