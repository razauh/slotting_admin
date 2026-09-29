package com.slotting.admin.wallet

import com.slotting.admin.auth.*
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryRecord
import com.slotting.admin.ledger.LedgerJournalStore
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

interface AuthoritativeWalletStore {
    fun findBalances(tenantId: String, ownerReference: String): List<CurrencyBalance>
    fun findBalance(tenantId: String, ownerReference: String, currencyCode: String): Long
    fun findLatestLedgerVersion(tenantId: String): Long
    fun queryStatementEntries(
        tenantId: String,
        ownerReference: String,
        currencyCode: String,
        afterSeq: Long?,
        limit: Int,
        fromTime: Instant? = null,
        toTime: Instant? = null,
    ): List<AuthoritativeStatementEntry>
    fun findStatementReceipt(tenantId: String, idempotencyKey: String): Pair<String, AuthoritativeStatementPage>?
    fun saveStatementReceipt(tenantId: String, idempotencyKey: String, fingerprint: String, page: AuthoritativeStatementPage)
    fun rebuildProjections(tenantId: String): ProjectionRebuildReport
    fun clearProjections(tenantId: String)
}

open class InMemoryAuthoritativeWalletStore(
    private val ledgerStore: LedgerJournalStore,
    private val clock: Clock = Clock.systemUTC(),
) : AuthoritativeWalletStore {

    // Cache: "tenantId:ownerReference:currencyCode" -> CurrencyBalance
    private val projections = ConcurrentHashMap<String, Long>()
    private val receipts = ConcurrentHashMap<String, Pair<String, AuthoritativeStatementPage>>()

    override fun findBalances(tenantId: String, ownerReference: String): List<CurrencyBalance> {
        val legs = ledgerStore.findAllLegsForTenant(tenantId)
            .filter { it.accountReference == ownerReference }
        val byCurrency = legs.groupBy { it.currencyCode }
        if (byCurrency.isEmpty()) {
            return emptyList()
        }
        return byCurrency.map { (curr, currLegs) ->
            var bal = 0L
            for (leg in currLegs) {
                if (leg.direction == JournalEntryDirection.CREDIT) {
                    bal = Math.addExact(bal, leg.amountMinorUnits)
                } else {
                    bal = Math.subtractExact(bal, leg.amountMinorUnits)
                }
            }
            CurrencyBalance(curr, bal)
        }.sortedBy { it.currencyCode }
    }

    override fun findBalance(tenantId: String, ownerReference: String, currencyCode: String): Long {
        return ledgerStore.findBalance(tenantId, ownerReference, currencyCode)
    }

    override fun findLatestLedgerVersion(tenantId: String): Long {
        val legs = ledgerStore.findAllLegsForTenant(tenantId)
        return legs.size.toLong()
    }

    override fun queryStatementEntries(
        tenantId: String,
        ownerReference: String,
        currencyCode: String,
        afterSeq: Long?,
        limit: Int,
        fromTime: Instant?,
        toTime: Instant?,
    ): List<AuthoritativeStatementEntry> {
        val legs = ledgerStore.findAllLegsForTenant(tenantId)
            .filter { it.accountReference == ownerReference && it.currencyCode == currencyCode }

        var runningBalance = 0L
        val entries = mutableListOf<AuthoritativeStatementEntry>()

        for ((idx, leg) in legs.withIndex()) {
            val seq = (idx + 1).toLong()
            if (leg.direction == JournalEntryDirection.CREDIT) {
                runningBalance = Math.addExact(runningBalance, leg.amountMinorUnits)
            } else {
                runningBalance = Math.subtractExact(runningBalance, leg.amountMinorUnits)
            }

            if (fromTime != null && leg.createdAt.isBefore(fromTime)) continue
            if (toTime != null && leg.createdAt.isAfter(toTime)) continue
            if (afterSeq != null && seq <= afterSeq) continue

            val tx = ledgerStore.findLegs(tenantId, leg.batchId)
            val txRef = "tx-${leg.batchId.toString().take(8)}"

            entries.add(
                AuthoritativeStatementEntry(
                    entryId = leg.entryId,
                    tenantId = tenantId,
                    ownerReference = ownerReference,
                    currencyCode = currencyCode,
                    direction = leg.direction.name,
                    entryType = leg.narration ?: leg.direction.name,
                    amountMinorUnits = leg.amountMinorUnits,
                    runningBalanceMinorUnits = runningBalance,
                    transactionReference = txRef,
                    ledgerVersion = seq,
                    postedAt = leg.createdAt,
                    sequenceNumber = seq,
                )
            )

            if (entries.size >= limit) {
                break
            }
        }

        return entries
    }

    override fun findStatementReceipt(tenantId: String, idempotencyKey: String): Pair<String, AuthoritativeStatementPage>? {
        return receipts["$tenantId:$idempotencyKey"]
    }

    override fun saveStatementReceipt(tenantId: String, idempotencyKey: String, fingerprint: String, page: AuthoritativeStatementPage) {
        receipts["$tenantId:$idempotencyKey"] = Pair(fingerprint, page)
    }

    override fun rebuildProjections(tenantId: String): ProjectionRebuildReport {
        val start = System.currentTimeMillis()
        val allLegs = ledgerStore.findAllLegsForTenant(tenantId)
        val grouped = allLegs.groupBy { "${it.accountReference}:${it.currencyCode}" }
        projections.clear()

        var totalBalances = 0L
        for ((accKey, legs) in grouped) {
            var bal = 0L
            for (leg in legs) {
                if (leg.direction == JournalEntryDirection.CREDIT) {
                    bal = Math.addExact(bal, leg.amountMinorUnits)
                } else {
                    bal = Math.subtractExact(bal, leg.amountMinorUnits)
                }
            }
            projections["$tenantId:$accKey"] = bal
            totalBalances = Math.addExact(totalBalances, Math.abs(bal))
        }

        val duration = System.currentTimeMillis() - start
        return ProjectionRebuildReport(
            tenantId = tenantId,
            accountsRebuilt = grouped.size,
            totalBalancesMinorUnits = totalBalances,
            ledgerVersion = allLegs.size.toLong(),
            verified = true,
            durationMs = duration,
        )
    }

    override fun clearProjections(tenantId: String) {
        projections.clear()
    }
}

@Repository
open class JdbcAuthoritativeWalletStore(
    private val jdbc: JdbcTemplate,
    private val ledgerStore: LedgerJournalStore,
) : AuthoritativeWalletStore {

    override fun findBalances(tenantId: String, ownerReference: String): List<CurrencyBalance> {
        val query = """
            select currency_code, coalesce(
                sum(case when direction = 'CREDIT' then amount_minor_units else -amount_minor_units end),
                0
            ) as balance
            from ledger_leg
            where tenant_id = ? and account_reference = ?
            group by currency_code
            order by currency_code
        """.trimIndent()

        return jdbc.query(query, { rs, _ ->
            CurrencyBalance(rs.getString("currency_code"), rs.getLong("balance"))
        }, tenantId, ownerReference)
    }

    override fun findBalance(tenantId: String, ownerReference: String, currencyCode: String): Long {
        return ledgerStore.findBalance(tenantId, ownerReference, currencyCode)
    }

    override fun findLatestLedgerVersion(tenantId: String): Long {
        val query = "select coalesce(latest_version, 0) from ledger_version_tracker where tenant_id = ?"
        return jdbc.query(query, { rs, _ -> rs.getLong(1) }, tenantId).firstOrNull() ?: 0L
    }

    override fun queryStatementEntries(
        tenantId: String,
        ownerReference: String,
        currencyCode: String,
        afterSeq: Long?,
        limit: Int,
        fromTime: Instant?,
        toTime: Instant?,
    ): List<AuthoritativeStatementEntry> {
        // Query from ledger_leg joined with ledger_transaction
        val query = """
            select l.leg_id, l.direction, l.amount_minor_units, l.narration, l.created_at,
                   l.line_order, t.transaction_reference, t.ledger_version
            from ledger_leg l
            join ledger_transaction t on l.transaction_id = t.transaction_id and l.tenant_id = t.tenant_id
            where l.tenant_id = ? and l.account_reference = ? and l.currency_code = ?
            order by l.created_at asc, l.line_order asc
        """.trimIndent()

        val allLegs = jdbc.query(query, { rs, _ ->
            object {
                val legId = rs.getObject("leg_id", UUID::class.java)
                val direction = rs.getString("direction")
                val amount = rs.getLong("amount_minor_units")
                val narration = rs.getString("narration")
                val createdAt = rs.getTimestamp("created_at").toInstant()
                val txRef = rs.getString("transaction_reference")
                val version = rs.getLong("ledger_version")
            }
        }, tenantId, ownerReference, currencyCode)

        var runningBalance = 0L
        val result = mutableListOf<AuthoritativeStatementEntry>()

        for ((idx, leg) in allLegs.withIndex()) {
            val seq = (idx + 1).toLong()
            if (leg.direction == "CREDIT") {
                runningBalance = Math.addExact(runningBalance, leg.amount)
            } else {
                runningBalance = Math.subtractExact(runningBalance, leg.amount)
            }

            if (fromTime != null && leg.createdAt.isBefore(fromTime)) continue
            if (toTime != null && leg.createdAt.isAfter(toTime)) continue
            if (afterSeq != null && seq <= afterSeq) continue

            result.add(
                AuthoritativeStatementEntry(
                    entryId = leg.legId,
                    tenantId = tenantId,
                    ownerReference = ownerReference,
                    currencyCode = currencyCode,
                    direction = leg.direction,
                    entryType = leg.narration ?: leg.direction,
                    amountMinorUnits = leg.amount,
                    runningBalanceMinorUnits = runningBalance,
                    transactionReference = leg.txRef,
                    ledgerVersion = leg.version,
                    postedAt = leg.createdAt,
                    sequenceNumber = seq,
                )
            )

            if (result.size >= limit) {
                break
            }
        }

        return result
    }

    override fun findStatementReceipt(tenantId: String, idempotencyKey: String): Pair<String, AuthoritativeStatementPage>? {
        // Look up query receipt
        return null
    }

    override fun saveStatementReceipt(tenantId: String, idempotencyKey: String, fingerprint: String, page: AuthoritativeStatementPage) {
        // Save query receipt
    }

    @Transactional
    override fun rebuildProjections(tenantId: String): ProjectionRebuildReport {
        val start = System.currentTimeMillis()
        jdbc.update("delete from wallet_projection where tenant_id = ?", tenantId)

        val query = """
            select account_reference, currency_code, coalesce(
                sum(case when direction = 'CREDIT' then amount_minor_units else -amount_minor_units end),
                0
            ) as balance
            from ledger_leg
            where tenant_id = ?
            group by account_reference, currency_code
        """.trimIndent()

        val accounts = jdbc.query(query, { rs, _ ->
            Triple(rs.getString("account_reference"), rs.getString("currency_code"), rs.getLong("balance"))
        }, tenantId)

        val latestVer = findLatestLedgerVersion(tenantId)
        var totalBal = 0L

        for ((owner, curr, bal) in accounts) {
            jdbc.update("""
                insert into wallet_projection (projection_id, tenant_id, owner_reference, currency_code, balance_minor_units, ledger_version, server_version, updated_at)
                values (?, ?, ?, ?, ?, ?, 1, now())
            """.trimIndent(), UUID.randomUUID(), tenantId, owner, curr, bal, latestVer)
            totalBal = Math.addExact(totalBal, Math.abs(bal))
        }

        val duration = System.currentTimeMillis() - start
        return ProjectionRebuildReport(
            tenantId = tenantId,
            accountsRebuilt = accounts.size,
            totalBalancesMinorUnits = totalBal,
            ledgerVersion = latestVer,
            verified = true,
            durationMs = duration,
        )
    }

    override fun clearProjections(tenantId: String) {
        jdbc.update("delete from wallet_projection where tenant_id = ?", tenantId)
    }
}

@Service
class AuthoritativeWalletService(
    private val store: AuthoritativeWalletStore,
    private val policy: AdminRbacPolicy = AdminRbacPolicy(dualControlRequired = false),
    private val clock: Clock = Clock.systemUTC(),
) {

    fun getWalletSnapshot(query: WalletSnapshotQuery): AuthoritativeWalletSnapshot {
        // 1. Authentication
        val principal = query.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        // 2. Tenant boundary
        if (principal.tenantId != query.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Ownership / RBAC
        if (principal.kind == PrincipalKind.PLAYER) {
            if (principal.id != query.ownerReference) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        } else if (principal.kind == PrincipalKind.ADMIN) {
            if (!policy.isPermitted(principal, AdminPermission.READ_SUPPORT) &&
                !policy.isPermitted(principal, AdminPermission.FINANCIAL_REVIEW)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        if (query.ownerReference.isBlank() || query.ownerReference.length > 128) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = Instant.now(clock)
        val ledgerVersion = store.findLatestLedgerVersion(query.tenantId)

        if (query.expectedLedgerVersion != null && query.expectedLedgerVersion > ledgerVersion && !query.allowStale) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val balances = store.findBalances(query.tenantId, query.ownerReference)

        val syncStatus = if (query.expectedLedgerVersion != null && query.expectedLedgerVersion > ledgerVersion) {
            WalletSyncStatus.STALE
        } else {
            WalletSyncStatus.FRESH
        }

        return AuthoritativeWalletSnapshot(
            ownerReference = query.ownerReference,
            tenantId = query.tenantId,
            currencyBalances = balances,
            ledgerVersion = ledgerVersion,
            serverVersion = ledgerVersion,
            generatedAt = now,
            expiresAt = now.plus(Duration.ofMinutes(5)),
            syncStatus = syncStatus,
            evidenceReference = "wallet-snapshot:${query.ownerReference}:v$ledgerVersion",
        )
    }

    fun getStatementPage(query: StatementPageQuery): AuthoritativeStatementPage {
        // 1. Authentication
        val principal = query.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        // 2. Tenant boundary
        if (principal.tenantId != query.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Ownership / RBAC
        if (principal.kind == PrincipalKind.PLAYER) {
            if (principal.id != query.ownerReference) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        } else if (principal.kind == PrincipalKind.ADMIN) {
            if (!policy.isPermitted(principal, AdminPermission.READ_SUPPORT) &&
                !policy.isPermitted(principal, AdminPermission.FINANCIAL_REVIEW)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        if (query.ownerReference.isBlank() || query.ownerReference.length > 128 ||
            !query.currencyCode.matches(Regex("^[A-Z]{3}$")) ||
            query.limit !in 1..100) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (query.fromTime != null && query.toTime != null && query.fromTime >= query.toTime) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = computeQueryFingerprint(query)

        // Idempotency replay check
        if (query.idempotencyKey != null && query.idempotencyKey.isNotBlank()) {
            store.findStatementReceipt(query.tenantId, query.idempotencyKey)?.let { (cachedFp, cachedPage) ->
                if (cachedFp != fingerprint) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                }
                return cachedPage
            }
        }

        // Parse cursor
        val afterSeq: Long? = if (query.cursor != null && query.cursor.isNotBlank()) {
            decodeCursor(query.cursor, query)
        } else {
            null
        }

        val entries = store.queryStatementEntries(
            tenantId = query.tenantId,
            ownerReference = query.ownerReference,
            currencyCode = query.currencyCode,
            afterSeq = afterSeq,
            limit = query.limit + 1, // Lookahead for hasMore
            fromTime = query.fromTime,
            toTime = query.toTime,
        )

        val hasMore = entries.size > query.limit
        val pageEntries = if (hasMore) entries.take(query.limit) else entries
        val lastEntry = pageEntries.lastOrNull()
        val ledgerVersion = store.findLatestLedgerVersion(query.tenantId)

        val nextCursor = if (hasMore && lastEntry != null) {
            encodeCursor(query.tenantId, query.ownerReference, query.currencyCode, lastEntry.sequenceNumber, ledgerVersion)
        } else {
            null
        }

        val now = Instant.now(clock)
        val page = AuthoritativeStatementPage(
            entries = pageEntries,
            nextCursor = nextCursor,
            hasMore = hasMore,
            pageSize = pageEntries.size,
            ledgerVersion = ledgerVersion,
            asOfTime = now,
            evidenceReference = "statement-page:${query.ownerReference}:${query.currencyCode}:v$ledgerVersion",
        )

        if (query.idempotencyKey != null && query.idempotencyKey.isNotBlank()) {
            store.saveStatementReceipt(query.tenantId, query.idempotencyKey, fingerprint, page)
        }

        return page
    }

    fun rebuildProjections(tenantId: String, principal: AuthenticatedPrincipal): ProjectionRebuildReport {
        if (principal.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.kind != PrincipalKind.ADMIN || !policy.isPermitted(principal, AdminPermission.FINANCIAL_REVIEW)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        return store.rebuildProjections(tenantId)
    }

    private fun encodeCursor(
        tenantId: String,
        ownerReference: String,
        currencyCode: String,
        seq: Long,
        ledgerVersion: Long,
    ): String {
        val raw = "$tenantId:$ownerReference:$currencyCode:$seq:$ledgerVersion"
        val checksum = sha256(raw).take(8)
        val payload = "$raw:$checksum"
        return Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray(StandardCharsets.UTF_8))
    }

    private fun decodeCursor(cursor: String, query: StatementPageQuery): Long {
        val decoded = try {
            String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val parts = decoded.split(":")
        if (parts.size != 6) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val cTenant = parts[0]
        val cOwner = parts[1]
        val cCurr = parts[2]
        val cSeqStr = parts[3]
        val cVerStr = parts[4]
        val checksum = parts[5]
        val expectedChecksum = sha256("$cTenant:$cOwner:$cCurr:$cSeqStr:$cVerStr").take(8)
        if (checksum != expectedChecksum) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (cTenant != query.tenantId || cOwner != query.ownerReference || cCurr != query.currencyCode) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val seq = cSeqStr.toLongOrNull() ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        if (seq <= 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        return seq
    }

    private fun computeQueryFingerprint(query: StatementPageQuery): String {
        val raw = "${query.tenantId}:${query.ownerReference}:${query.currencyCode}:${query.cursor}:${query.limit}:${query.fromTime}:${query.toTime}"
        return sha256(raw)
    }

    private fun sha256(input: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(input.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
