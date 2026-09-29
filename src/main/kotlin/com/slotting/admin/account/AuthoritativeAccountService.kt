package com.slotting.admin.account

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerRegistrationStore
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.WalletSnapshotQuery
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

@Service
open class AuthoritativeAccountService(
    private val accountStore: AccountWorkflowStore,
    private val registrationStore: PlayerRegistrationStore,
    private val walletService: AuthoritativeWalletService,
    private val sessions: AdminSessionDirectory,
    private val clock: Clock = Clock.systemUTC(),
) {

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun redactPiiAndSecrets(text: String): String {
        var redacted = text
        // Redact 16-digit credit card / account numbers
        redacted = redacted.replace(Regex("""\b(?:\d[ -]*?){13,16}\b"""), "[REDACTED_CARD]")
        // Redact explicit secret tokens
        redacted = redacted.replace(Regex("""(?i)\b(secret|token|password|pin)\s*[:=]?\s*\S+"""), "[REDACTED_SECRET]")
        return redacted
    }

    private fun validateAuthAndSession(
        principal: AuthenticatedPrincipal?,
        sessionId: String?,
        tenantId: String,
        targetOwner: UUID,
    ) {
        val p = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (p.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (p.kind == PrincipalKind.PLAYER && p.id != targetOwner.toString()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val sessionStatus = try {
            sessions.find(tenantId, p.id, sessionId ?: "")
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        if (sessionStatus == null || !sessionStatus.active || !sessionStatus.expiresAt.isAfter(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }
    }

    open fun getProfile(
        principal: AuthenticatedPrincipal?,
        sessionId: String?,
        tenantId: String,
        ownerUserId: UUID,
    ): PlayerProfileDto {
        validateAuthAndSession(principal, sessionId, tenantId, ownerUserId)

        val player = registrationStore.findById(tenantId, ownerUserId)
        val maskedEmail = player?.maskedEmail ?: "u***@internal"
        val maskedPhone = player?.maskedPhone ?: "****"
        val status = player?.status?.name ?: "ACTIVE"
        val kycStatus = if (player?.emailVerified == true && player.phoneVerified) "UNVERIFIED" else "PENDING"
        val version = player?.version ?: 1L
        val createdAtMs = player?.createdAt?.toEpochMilli() ?: clock.instant().toEpochMilli()
        val updatedAtMs = player?.updatedAt?.toEpochMilli() ?: clock.instant().toEpochMilli()

        return PlayerProfileDto(
            userId = ownerUserId.toString(),
            username = "player-${ownerUserId.toString().take(8)}",
            maskedEmail = maskedEmail,
            maskedPhone = maskedPhone,
            kycStatus = kycStatus,
            accountStatus = status,
            accountTier = "STANDARD",
            serverVersion = version,
            createdAtEpochMillis = createdAtMs,
            updatedAtEpochMillis = updatedAtMs,
        )
    }

    open fun createSupportCase(command: CreateSupportCaseCommand): SupportCaseDto {
        validateAuthAndSession(command.principal, null, command.tenantId, command.ownerUserId)

        val fp = sha256("${command.tenantId}:${command.ownerUserId}:${command.category}:${command.subject}:${command.description}:${command.roundId}")

        accountStore.findSupportCaseByIdempotency(command.tenantId, command.idempotencyKey)?.let { existing ->
            if (existing.requestFingerprint != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return toSupportCaseDto(existing)
        }

        val now = clock.instant()
        val sanitizedSubject = redactPiiAndSecrets(command.subject)
        val sanitizedDescription = redactPiiAndSecrets(command.description)

        val record = SupportCaseRecord(
            caseId = UUID.randomUUID(),
            tenantId = command.tenantId,
            ownerUserId = command.ownerUserId,
            category = command.category,
            subject = sanitizedSubject,
            description = sanitizedDescription,
            roundId = command.roundId,
            status = SupportCaseStatus.SUBMITTED,
            resolutionSummary = null,
            idempotencyKey = command.idempotencyKey,
            requestFingerprint = fp,
            correlationId = command.correlationId,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )

        accountStore.saveSupportCase(record)
        return toSupportCaseDto(record)
    }

    open fun getSupportCase(
        principal: AuthenticatedPrincipal?,
        sessionId: String?,
        tenantId: String,
        caseId: UUID,
    ): SupportCaseDto {
        val p = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val case = accountStore.findSupportCase(tenantId, caseId)
            ?: throw IllegalArgumentException("Support case $caseId not found")

        validateAuthAndSession(p, sessionId, tenantId, case.ownerUserId)
        return toSupportCaseDto(case)
    }

    open fun listSupportCases(
        principal: AuthenticatedPrincipal?,
        sessionId: String?,
        tenantId: String,
        ownerUserId: UUID,
    ): List<SupportCaseDto> {
        validateAuthAndSession(principal, sessionId, tenantId, ownerUserId)
        return accountStore.findSupportCasesByOwner(tenantId, ownerUserId).map { toSupportCaseDto(it) }
    }

    open fun requestAccountClosure(command: SubmitAccountClosureCommand): AccountClosureResultDto {
        validateAuthAndSession(command.principal, null, command.tenantId, command.ownerUserId)

        val fp = sha256("${command.tenantId}:${command.ownerUserId}:${command.reason}:${command.reasonDetails}:${command.settlementAcknowledgment}")

        accountStore.findClosureRecordByIdempotency(command.tenantId, command.idempotencyKey)?.let { existing ->
            if (existing.requestFingerprint != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return toClosureDto(existing)
        }

        // Query authoritative wallet balance
        val snapshot = try {
            walletService.getWalletSnapshot(
                WalletSnapshotQuery(
                    principal = command.principal,
                    tenantId = command.tenantId,
                    ownerReference = command.ownerUserId.toString(),
                )
            )
        } catch (_: Exception) { null }

        val totalPendingBalance = snapshot?.currencyBalances?.sumOf { it.balanceMinorUnits } ?: 0L

        // Anti-dark-pattern check: positive balance requires settlement acknowledgment
        if (totalPendingBalance > 0L && !command.settlementAcknowledgment) {
            throw PositiveBalanceUnacknowledgedException(
                "Settlement acknowledgment is strictly required when account holds an outstanding balance of $totalPendingBalance minor units"
            )
        }

        val hasPendingOps = accountStore.hasPendingFinancialOperations(command.tenantId, command.ownerUserId)
        val (hasLegalHold, holdReason) = accountStore.hasLegalHold(command.tenantId, command.ownerUserId)

        val now = clock.instant()
        val closureId = UUID.randomUUID()

        val (status, retentionRef, closedAt) = when {
            hasLegalHold -> Triple(
                ClosureStatus.LEGAL_HOLD,
                "LEGAL_HOLD_ACTIVE:${holdReason ?: "STATUTORY_RETENTION"}",
                null
            )
            hasPendingOps -> Triple(
                ClosureStatus.PENDING_SETTLEMENT,
                "PENDING_FINANCIAL_RECONCILIATION",
                null
            )
            else -> {
                // Terminate registration account status authoritatively
                registrationStore.findById(command.tenantId, command.ownerUserId)?.let { reg ->
                    reg.status = PlayerAccountStatus.CLOSED
                    reg.updatedAt = now
                }
                Triple(
                    ClosureStatus.CLOSED,
                    "STANDARD_FINANCIAL_RETENTION_TC036",
                    now
                )
            }
        }

        val serverReceipt = "RCP-CLOSURE-${command.tenantId}-${command.ownerUserId}-${closureId.toString().take(8)}"

        val record = AccountClosureRecord(
            closureId = closureId,
            tenantId = command.tenantId,
            ownerUserId = command.ownerUserId,
            reason = command.reason,
            reasonDetails = command.reasonDetails,
            status = status,
            pendingBalanceMinorUnits = totalPendingBalance,
            settlementAcknowledged = command.settlementAcknowledgment,
            hasPendingFinancialOps = hasPendingOps,
            hasLegalHold = hasLegalHold,
            retentionPolicyReference = retentionRef,
            serverReceipt = serverReceipt,
            idempotencyKey = command.idempotencyKey,
            requestFingerprint = fp,
            correlationId = command.correlationId,
            closedAt = closedAt,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )

        accountStore.saveClosureRecord(record)
        return toClosureDto(record)
    }

    open fun getClosureStatus(
        principal: AuthenticatedPrincipal?,
        sessionId: String?,
        tenantId: String,
        ownerUserId: UUID,
    ): AccountClosureResultDto? {
        validateAuthAndSession(principal, sessionId, tenantId, ownerUserId)
        val record = accountStore.findLatestClosureByOwner(tenantId, ownerUserId) ?: return null
        return toClosureDto(record)
    }

    open fun getRestrictionsSummary(
        principal: AuthenticatedPrincipal?,
        sessionId: String?,
        tenantId: String,
        ownerUserId: UUID,
    ): AccountRestrictionsSummaryDto {
        validateAuthAndSession(principal, sessionId, tenantId, ownerUserId)

        val player = registrationStore.findById(tenantId, ownerUserId)
        val accountStatus = player?.status?.name ?: "ACTIVE"
        val coolingOff = accountStore.getCoolingOffUntil(tenantId, ownerUserId)
        val selfExclusion = accountStore.getSelfExclusionUntil(tenantId, ownerUserId)

        val restrictionTypes = mutableListOf<String>()
        val now = clock.instant()

        if (accountStatus != "ACTIVE") {
            restrictionTypes.add("ACCOUNT_$accountStatus")
        }
        if (coolingOff != null && coolingOff.isAfter(now)) {
            restrictionTypes.add("COOLING_OFF")
        }
        if (selfExclusion != null && selfExclusion.isAfter(now)) {
            restrictionTypes.add("SELF_EXCLUSION")
        }

        return AccountRestrictionsSummaryDto(
            userId = ownerUserId.toString(),
            tenantId = tenantId,
            isRestricted = restrictionTypes.isNotEmpty(),
            accountStatus = accountStatus,
            restrictionTypes = restrictionTypes,
            coolingOffUntil = coolingOff,
            selfExcludedUntil = selfExclusion,
            realityCheckIntervalMinutes = 60,
            serverTime = now,
            serverVersion = 1L,
        )
    }

    private fun toSupportCaseDto(r: SupportCaseRecord) = SupportCaseDto(
        caseId = r.caseId.toString(),
        ownerUserId = r.ownerUserId.toString(),
        category = r.category,
        subject = r.subject,
        description = r.description,
        roundId = r.roundId,
        idempotencyKey = r.idempotencyKey,
        correlationId = r.correlationId,
        status = r.status.name,
        resolutionSummary = r.resolutionSummary,
        createdAtEpochMs = r.createdAt.toEpochMilli(),
    )

    private fun toClosureDto(r: AccountClosureRecord) = AccountClosureResultDto(
        closureId = r.closureId.toString(),
        ownerUserId = r.ownerUserId.toString(),
        reason = r.reason,
        reasonDetails = r.reasonDetails,
        idempotencyKey = r.idempotencyKey,
        correlationId = r.correlationId,
        status = r.status.name,
        pendingBalanceMinorUnits = r.pendingBalanceMinorUnits,
        settlementAcknowledgment = r.settlementAcknowledged,
        hasPendingFinancialOps = r.hasPendingFinancialOps,
        hasLegalHold = r.hasLegalHold,
        retentionPolicyReference = r.retentionPolicyReference,
        serverReceipt = r.serverReceipt,
        closedAtEpochMs = r.closedAt?.toEpochMilli(),
        createdAtEpochMs = r.createdAt.toEpochMilli(),
    )
}
