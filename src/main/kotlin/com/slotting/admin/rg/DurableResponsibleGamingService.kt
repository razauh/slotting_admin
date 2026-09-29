package com.slotting.admin.rg

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.restriction.DurableServerRestrictionStore
import com.slotting.admin.restriction.RestrictionScope
import com.slotting.admin.restriction.RestrictionSource
import com.slotting.admin.restriction.ServerRestrictionRecord
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.DayOfWeek
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAdjusters
import java.util.UUID

class DurableResponsibleGamingService(
    private val store: DurableResponsibleGamingStore,
    private val restrictionStore: DurableServerRestrictionStore? = null,
    private val clock: Clock = Clock.systemUTC(),
    private val coolingOffDuration: Duration = Duration.ofHours(24)
) {
    init {
        // Activate RG invariant binding
        ResponsibleGamingLimitsBinding.isBound = true
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun calculatePeriodWindow(period: RgLimitPeriod, timezoneStr: String, now: Instant): Pair<Instant, Instant> {
        val zone = try {
            ZoneId.of(timezoneStr)
        } catch (e: Exception) {
            ZoneId.of("UTC")
        }

        val zdt = now.atZone(zone)
        return when (period) {
            RgLimitPeriod.DAILY -> {
                val start = zdt.truncatedTo(ChronoUnit.DAYS).toInstant()
                val end = zdt.truncatedTo(ChronoUnit.DAYS).plusDays(1).toInstant()
                start to end
            }
            RgLimitPeriod.WEEKLY -> {
                val start = zdt.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY)).truncatedTo(ChronoUnit.DAYS).toInstant()
                val end = zdt.with(TemporalAdjusters.next(DayOfWeek.MONDAY)).truncatedTo(ChronoUnit.DAYS).toInstant()
                start to end
            }
            RgLimitPeriod.MONTHLY -> {
                val start = zdt.with(TemporalAdjusters.firstDayOfMonth()).truncatedTo(ChronoUnit.DAYS).toInstant()
                val end = zdt.with(TemporalAdjusters.firstDayOfNextMonth()).truncatedTo(ChronoUnit.DAYS).toInstant()
                start to end
            }
            RgLimitPeriod.PER_SESSION -> {
                val start = now.minus(Duration.ofHours(1))
                val end = now.plus(Duration.ofHours(1))
                start to end
            }
        }
    }

    private fun resolveActiveConfig(config: RgLimitConfig, now: Instant): RgLimitConfig {
        if (config.pendingIncreaseValueMinorUnits != null &&
            config.pendingIncreaseEffectiveAt != null &&
            !now.isBefore(config.pendingIncreaseEffectiveAt)
        ) {
            val promoted = config.copy(
                limitValueMinorUnits = config.pendingIncreaseValueMinorUnits,
                pendingIncreaseValueMinorUnits = null,
                pendingIncreaseEffectiveAt = null,
                version = config.version + 1L,
                updatedAt = now
            )
            store.saveLimitConfig(promoted, config.version)
            return promoted
        }
        return config
    }

    @Synchronized
    fun changeLimit(command: ChangeLimitCommand): RgLimitChangeReceipt {
        ResponsibleGamingLimitsBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.limitValueMinor <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        val fp = sha256("${command.tenantId}:${command.playerId}:${command.limitType}:${command.period}:${command.limitValueMinor}:${command.expectedVersion}")

        val existingIdemp = store.findIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult as RgLimitChangeReceipt
        }

        val rawExisting = store.findLimitConfig(command.tenantId, command.playerId, command.limitType)
        val existingConfig = if (rawExisting != null) resolveActiveConfig(rawExisting, now) else null

        if (existingConfig != null) {
            if (existingConfig.version != command.expectedVersion) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }
        } else {
            if (command.expectedVersion != 1L) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }
        }

        val newVersion = (existingConfig?.version ?: 0L) + 1L
        val receiptId = UUID.randomUUID()
        val receiptRef = "EVID-RG-LIMIT-$receiptId-v$newVersion"

        val receipt: RgLimitChangeReceipt
        val newConfig: RgLimitConfig

        if (existingConfig == null) {
            // First time setting limit -> immediate
            newConfig = RgLimitConfig(
                limitId = UUID.randomUUID(),
                tenantId = command.tenantId,
                playerId = command.playerId,
                limitType = command.limitType,
                period = command.period,
                limitValueMinorUnits = command.limitValueMinor,
                timezone = command.timezone,
                productScope = "ALL_PRODUCTS",
                active = true,
                version = newVersion,
                createdAt = now,
                updatedAt = now
            )
            receipt = RgLimitChangeReceipt(
                receiptId = receiptId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                limitType = command.limitType,
                period = command.period,
                effectiveLimitValueMinor = command.limitValueMinor,
                pendingIncreaseValueMinor = null,
                pendingIncreaseEffectiveAt = null,
                isImmediate = true,
                coolingOffDurationHours = 0L,
                version = newVersion,
                serverTime = now,
                receiptReference = receiptRef
            )
        } else if (command.limitValueMinor <= existingConfig.limitValueMinorUnits) {
            // Limit decrease -> immediate
            newConfig = existingConfig.copy(
                limitValueMinorUnits = command.limitValueMinor,
                pendingIncreaseValueMinorUnits = null,
                pendingIncreaseEffectiveAt = null,
                period = command.period,
                timezone = command.timezone,
                version = newVersion,
                updatedAt = now
            )
            receipt = RgLimitChangeReceipt(
                receiptId = receiptId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                limitType = command.limitType,
                period = command.period,
                effectiveLimitValueMinor = command.limitValueMinor,
                pendingIncreaseValueMinor = null,
                pendingIncreaseEffectiveAt = null,
                isImmediate = true,
                coolingOffDurationHours = 0L,
                version = newVersion,
                serverTime = now,
                receiptReference = receiptRef
            )
        } else {
            // Limit increase -> delayed with cooling off period
            val effectiveAt = now.plus(coolingOffDuration)
            newConfig = existingConfig.copy(
                pendingIncreaseValueMinorUnits = command.limitValueMinor,
                pendingIncreaseEffectiveAt = effectiveAt,
                period = command.period,
                timezone = command.timezone,
                version = newVersion,
                updatedAt = now
            )
            receipt = RgLimitChangeReceipt(
                receiptId = receiptId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                limitType = command.limitType,
                period = command.period,
                effectiveLimitValueMinor = existingConfig.limitValueMinorUnits,
                pendingIncreaseValueMinor = command.limitValueMinor,
                pendingIncreaseEffectiveAt = effectiveAt,
                isImmediate = false,
                coolingOffDurationHours = coolingOffDuration.toHours(),
                version = newVersion,
                serverTime = now,
                receiptReference = receiptRef
            )
        }

        store.saveLimitConfig(newConfig, existingConfig?.version)
        store.saveIdempotency(command.tenantId, command.idempotencyKey, fp, receipt)
        return receipt
    }

    @Synchronized
    fun applyExclusion(command: ApplyPlayerExclusionCommand): ApplyPlayerExclusionResult {
        ResponsibleGamingLimitsBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        val fp = sha256("${command.tenantId}:${command.playerId}:${command.exclusionType}:${command.durationDays}:${command.reason}")

        val existingIdemp = store.findIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ApplyPlayerExclusionResult
            return res.copy(isDuplicate = true)
        }

        val exclusionId = UUID.randomUUID()
        val evidenceRef = "EVID-RG-EXCL-$exclusionId"
        val expiresAt = if (command.exclusionType == DurableExclusionType.SELF_EXCLUSION_PERMANENT) {
            null
        } else {
            now.plus(Duration.ofDays(command.durationDays!!.toLong()))
        }

        val record = DurableExclusionRecord(
            exclusionId = exclusionId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            exclusionType = command.exclusionType,
            status = DurableExclusionStatus.ACTIVE,
            effectiveFrom = now,
            expiresAt = expiresAt,
            reason = command.reason,
            requestedBy = command.principal?.id ?: command.playerId,
            version = 1L,
            createdAt = now,
            updatedAt = now,
            evidenceReference = evidenceRef
        )

        store.saveExclusion(record)

        // Project into server restriction store per TC-026 policy matrix
        val restriction = ServerRestrictionRecord(
            restrictionId = UUID.randomUUID(),
            tenantId = command.tenantId,
            subjectReference = command.playerId,
            source = RestrictionSource.RESPONSIBLE_GAMING,
            reasonCode = "RESPONSIBLE_GAMING_${command.exclusionType.name}",
            safeUserMessage = "Responsible gaming exclusion active: ${command.reason}",
            scope = RestrictionScope.WholeAccount,
            effectiveFrom = now,
            expiresAt = expiresAt,
            evidenceReference = evidenceRef,
            ruleVersion = 1L,
            issuer = command.principal?.id ?: "PLAYER"
        )
        restrictionStore?.saveRestriction(restriction)

        val result = ApplyPlayerExclusionResult(
            receiptId = UUID.randomUUID(),
            exclusion = record,
            serverTime = now,
            isDuplicate = false,
            receiptReference = evidenceRef
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fp, result)
        return result
    }

    @Synchronized
    fun reserveUsage(
        tenantId: String,
        playerId: String,
        limitType: RgLimitType,
        amountMinor: Long,
        product: String = "CASINO",
        referenceId: String,
        idempotencyKey: String,
        correlationId: String,
        causationId: String,
        timezone: String = "UTC"
    ): EnforceRgLimitResult {
        ResponsibleGamingLimitsBinding.checkBound()

        if (tenantId.isBlank() || playerId.isBlank() || idempotencyKey.isBlank() || referenceId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (amountMinor < 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        val evalId = UUID.randomUUID()

        // 1. Check for active exclusion
        val activeExclusion = store.findActiveExclusion(tenantId, playerId, now)
        if (activeExclusion != null) {
            return EnforceRgLimitResult(
                evaluationId = evalId,
                tenantId = tenantId,
                playerId = playerId,
                limitType = limitType,
                outcome = LimitEnforcementOutcome.EXCEEDED_LIMIT,
                limitValueMinorUnits = 0L,
                proposedAmountMinorUnits = amountMinor,
                consumedBeforeMinorUnits = 0L,
                consumedAfterMinorUnits = 0L,
                remainingMinorUnits = 0L,
                periodStart = now,
                periodEnd = now,
                timezone = timezone,
                product = product,
                serverTime = now,
                isDuplicate = false,
                evidenceReference = "EVID-RG-EXCLUDED-$evalId"
            )
        }

        // 2. Find limit config
        val rawConfig = store.findLimitConfig(tenantId, playerId, limitType)
        val config = if (rawConfig != null) resolveActiveConfig(rawConfig, now) else null

        if (config == null || !config.active) {
            // No limit configured -> ALLOWED
            return EnforceRgLimitResult(
                evaluationId = evalId,
                tenantId = tenantId,
                playerId = playerId,
                limitType = limitType,
                outcome = LimitEnforcementOutcome.ALLOWED,
                limitValueMinorUnits = Long.MAX_VALUE,
                proposedAmountMinorUnits = amountMinor,
                consumedBeforeMinorUnits = 0L,
                consumedAfterMinorUnits = 0L,
                remainingMinorUnits = Long.MAX_VALUE,
                periodStart = now,
                periodEnd = now,
                timezone = timezone,
                product = product,
                serverTime = now,
                isDuplicate = false,
                evidenceReference = "EVID-NO-LIMIT-$evalId"
            )
        }

        val (periodStart, periodEnd) = calculatePeriodWindow(config.period, config.timezone, now)
        val currentUsage = store.findUsage(tenantId, playerId, limitType, periodStart)
        val consumedBefore = currentUsage?.consumedMinorUnits ?: 0L
        val limitValue = config.limitValueMinorUnits

        if (consumedBefore + amountMinor > limitValue) {
            return EnforceRgLimitResult(
                evaluationId = evalId,
                tenantId = tenantId,
                playerId = playerId,
                limitType = limitType,
                outcome = LimitEnforcementOutcome.EXCEEDED_LIMIT,
                limitValueMinorUnits = limitValue,
                proposedAmountMinorUnits = amountMinor,
                consumedBeforeMinorUnits = consumedBefore,
                consumedAfterMinorUnits = consumedBefore,
                remainingMinorUnits = (limitValue - consumedBefore).coerceAtLeast(0L),
                periodStart = periodStart,
                periodEnd = periodEnd,
                timezone = config.timezone,
                product = product,
                serverTime = now,
                isDuplicate = false,
                evidenceReference = "EVID-LIMIT-EXCEEDED-$evalId"
            )
        }

        val consumedAfter = consumedBefore + amountMinor
        val remaining = limitValue - consumedAfter

        val updatedUsage = RgLimitUsageRecord(
            usageId = currentUsage?.usageId ?: UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            limitType = limitType,
            period = config.period,
            periodStart = periodStart,
            periodEnd = periodEnd,
            timezone = config.timezone,
            consumedMinorUnits = consumedAfter,
            version = (currentUsage?.version ?: 0L) + 1L,
            updatedAt = now
        )

        store.saveUsage(updatedUsage, currentUsage?.version)

        return EnforceRgLimitResult(
            evaluationId = evalId,
            tenantId = tenantId,
            playerId = playerId,
            limitType = limitType,
            outcome = LimitEnforcementOutcome.ALLOWED,
            limitValueMinorUnits = limitValue,
            proposedAmountMinorUnits = amountMinor,
            consumedBeforeMinorUnits = consumedBefore,
            consumedAfterMinorUnits = consumedAfter,
            remainingMinorUnits = remaining,
            periodStart = periodStart,
            periodEnd = periodEnd,
            timezone = config.timezone,
            product = product,
            serverTime = now,
            isDuplicate = false,
            evidenceReference = "EVID-LIMIT-ALLOWED-$evalId"
        )
    }

    @Synchronized
    fun getPlayerRgStatus(tenantId: String, playerId: String): PlayerRgStatus {
        val now = clock.instant()
        val activeExclusion = store.findActiveExclusion(tenantId, playerId, now)
        val isExcluded = activeExclusion != null

        val rawConfigs = store.listLimitConfigs(tenantId, playerId)
        val configs = rawConfigs.map { resolveActiveConfig(it, now) }
        val usages = store.listUsages(tenantId, playerId)

        val canAccessGame = !isExcluded
        val canWager = !isExcluded
        val canDeposit = !isExcluded
        val canWithdraw = true // Per TC-026 matrix: withdrawal of unwagered balance is allowed
        val isPromotionSuppressed = isExcluded

        return PlayerRgStatus(
            playerId = playerId,
            tenantId = tenantId,
            activeExclusion = activeExclusion,
            isExcluded = isExcluded,
            limits = configs,
            currentUsages = usages,
            canAccessGame = canAccessGame,
            canWager = canWager,
            canDeposit = canDeposit,
            canWithdraw = canWithdraw,
            isPromotionSuppressed = isPromotionSuppressed,
            serverTime = now
        )
    }
}
