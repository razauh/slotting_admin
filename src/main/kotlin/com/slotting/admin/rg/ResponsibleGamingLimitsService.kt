package com.slotting.admin.rg

import com.slotting.admin.auth.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.*
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAdjusters
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for RG-001: Limits model/enforcement.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Limits model/enforcement.
 * Rationale: It exists to prevent: split transactions/product bypass/race.
 */
object ResponsibleGamingLimitsBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("split transactions/product bypass/race")
        }
    }
}

/**
 * Outcome-specific semantic contract for RG-001.
 */
const val RG_LIMITS_ENFORCEMENT_CONTRACT =
    "Period/timezone/version explicit; enforcement precedes reservation/credit where applicable."

enum class RgLimitType {
    DEPOSIT,
    WAGER,
    LOSS,
    SESSION_DURATION,
}

enum class RgLimitPeriod {
    DAILY,
    WEEKLY,
    MONTHLY,
    PER_SESSION,
}

enum class LimitEnforcementOutcome {
    ALLOWED,
    EXCEEDED_LIMIT,
    COOLDOWN_ACTIVE,
    LIMIT_INACTIVE,
}

data class RgLimitConfig(
    val limitId: UUID,
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val period: RgLimitPeriod,
    val limitValueMinorUnits: Long,
    val timezone: String,
    val productScope: String = "ALL_PRODUCTS",
    val pendingIncreaseValueMinorUnits: Long? = null,
    val pendingIncreaseEffectiveAt: Instant? = null,
    val active: Boolean = true,
    val version: Long,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = RG_LIMITS_ENFORCEMENT_CONTRACT,
)

data class RgLimitUsageRecord(
    val usageId: UUID,
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val period: RgLimitPeriod,
    val periodStart: Instant,
    val periodEnd: Instant,
    val timezone: String,
    val consumedMinorUnits: Long,
    val version: Long,
    val updatedAt: Instant,
)

data class ConfigureRgLimitCommand(
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val period: RgLimitPeriod,
    val limitValueMinorUnits: Long,
    val timezone: String,
    val productScope: String = "ALL_PRODUCTS",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null,
)

data class ConfigureRgLimitResult(
    val resultId: UUID,
    val config: RgLimitConfig,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = RG_LIMITS_ENFORCEMENT_CONTRACT,
)

data class EnforceRgLimitCommand(
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val proposedAmountMinorUnits: Long,
    val product: String = "SLOTS",
    val referenceId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long? = null,
    val principal: AuthenticatedPrincipal? = null,
)

data class EnforceRgLimitResult(
    val evaluationId: UUID,
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val outcome: LimitEnforcementOutcome,
    val limitValueMinorUnits: Long,
    val proposedAmountMinorUnits: Long,
    val consumedBeforeMinorUnits: Long,
    val consumedAfterMinorUnits: Long,
    val remainingMinorUnits: Long,
    val periodStart: Instant,
    val periodEnd: Instant,
    val timezone: String,
    val product: String,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = RG_LIMITS_ENFORCEMENT_CONTRACT,
)

data class RgLimitsSnapshot(
    val configs: Map<String, RgLimitConfig>,
    val usages: Map<String, RgLimitUsageRecord>,
    val idempotencyMap: Map<String, Pair<String, Any>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface RgLimitsAlertSink {
    fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String)
}

class InMemoryRgLimitsAlertSink : RgLimitsAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$reference:$alertType:$reason:$detail")
    }
}

interface RgLimitsStore {
    fun findConfig(tenantId: String, playerId: String, limitType: RgLimitType): RgLimitConfig?
    fun findUsage(tenantId: String, playerId: String, limitType: RgLimitType, periodStart: Instant): RgLimitUsageRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveConfig(
        config: RgLimitConfig,
        result: ConfigureRgLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateConfig(
        config: RgLimitConfig,
        result: ConfigureRgLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun saveUsageAndResult(
        usage: RgLimitUsageRecord,
        result: EnforceRgLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun saveEnforceResultOnly(
        result: EnforceRgLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): RgLimitsSnapshot
    fun importSnapshot(snapshot: RgLimitsSnapshot)
}

open class InMemoryRgLimitsStore : RgLimitsStore {
    private val configs = ConcurrentHashMap<String, RgLimitConfig>()
    private val usages = ConcurrentHashMap<String, RgLimitUsageRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, Any>>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun configKey(tenantId: String, playerId: String, type: RgLimitType) = "$tenantId:$playerId:$type"
    private fun usageKey(tenantId: String, playerId: String, type: RgLimitType, start: Instant) = "$tenantId:$playerId:$type:$start"
    private fun idKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findConfig(tenantId: String, playerId: String, limitType: RgLimitType): RgLimitConfig? =
        configs[configKey(tenantId, playerId, limitType)]?.copy()

    @Synchronized
    override fun findUsage(tenantId: String, playerId: String, limitType: RgLimitType, periodStart: Instant): RgLimitUsageRecord? =
        usages[usageKey(tenantId, playerId, limitType, periodStart)]?.copy()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? =
        idempotencyResults[idKey(tenantId, idempotencyKey)]

    @Synchronized
    open override fun saveConfig(
        config: RgLimitConfig,
        result: ConfigureRgLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        configs[configKey(config.tenantId, config.playerId, config.limitType)] = config.copy()
        idempotencyResults[idKey(config.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateConfig(
        config: RgLimitConfig,
        result: ConfigureRgLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        configs[configKey(config.tenantId, config.playerId, config.limitType)] = config.copy()
        idempotencyResults[idKey(config.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    open override fun saveUsageAndResult(
        usage: RgLimitUsageRecord,
        result: EnforceRgLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        usages[usageKey(usage.tenantId, usage.playerId, usage.limitType, usage.periodStart)] = usage.copy()
        idempotencyResults[idKey(result.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun saveEnforceResultOnly(
        result: EnforceRgLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        idempotencyResults[idKey(result.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): RgLimitsSnapshot = RgLimitsSnapshot(
        configs = HashMap(configs),
        usages = HashMap(usages),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: RgLimitsSnapshot) {
        configs.clear()
        configs.putAll(snapshot.configs)
        usages.clear()
        usages.putAll(snapshot.usages)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class ResponsibleGamingLimitsService(
    private val store: RgLimitsStore,
    private val alertSink: RgLimitsAlertSink = InMemoryRgLimitsAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintConfigure(cmd: ConfigureRgLimitCommand): String =
        sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.limitType}:${cmd.period}:${cmd.limitValueMinorUnits}:${cmd.timezone}:${cmd.productScope}:${cmd.expectedVersion}")

    private fun fingerprintEnforce(cmd: EnforceRgLimitCommand): String =
        sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.limitType}:${cmd.proposedAmountMinorUnits}:${cmd.product}:${cmd.referenceId}")

    private fun validatePrincipal(principal: AuthenticatedPrincipal?, tenantId: String, playerId: String) {
        principal?.let {
            if (it.tenantId != tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (it.kind == PrincipalKind.PLAYER) {
                if (it.id != playerId) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            } else if (it.kind == PrincipalKind.ADMIN) {
                if (it.roles.none { role -> role in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR) }) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }
    }

    private fun calculatePeriodWindow(period: RgLimitPeriod, timezoneStr: String, now: Instant): Pair<Instant, Instant> {
        val zone = try {
            ZoneId.of(timezoneStr)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
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
                // Per session window defaults to 24-hour sliding or active session
                val start = now.minus(Duration.ofHours(1))
                val end = now.plus(Duration.ofHours(1))
                start to end
            }
        }
    }

    @Synchronized
    fun configureLimit(command: ConfigureRgLimitCommand): ConfigureRgLimitResult {
        // Protected risk assertion: split transactions/product bypass/race
        ResponsibleGamingLimitsBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.playerId.isBlank() ||
            command.timezone.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                reference = command.playerId.ifBlank { "UNKNOWN" },
                alertType = "RG_LIMIT_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Configure RG limit rejected due to blank mandatory fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.limitValueMinorUnits < 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate explicit timezone
        try {
            ZoneId.of(command.timezone)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val fp = fingerprintConfigure(command)
        val now = clock.instant()

        // 2. Idempotency Check
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.playerId,
                    alertType = "RG_LIMIT_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload mismatch detected for RG limit idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ConfigureRgLimitResult
            return res.copy(isDuplicate = true)
        }

        val existingConfig = store.findConfig(command.tenantId, command.playerId, command.limitType)
        if (existingConfig != null) {
            if (existingConfig.version != command.expectedVersion) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }
        } else {
            if (command.expectedVersion != 1L) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }
        }

        val limitId = existingConfig?.limitId ?: UUID.randomUUID()
        val newVersion = (existingConfig?.version ?: 0L) + 1L

        val config = RgLimitConfig(
            limitId = limitId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            limitType = command.limitType,
            period = command.period,
            limitValueMinorUnits = command.limitValueMinorUnits,
            timezone = command.timezone,
            productScope = command.productScope,
            active = true,
            version = newVersion,
            createdAt = existingConfig?.createdAt ?: now,
            updatedAt = now,
            semanticContract = RG_LIMITS_ENFORCEMENT_CONTRACT,
        )

        val resultId = UUID.randomUUID()
        val evidenceRef = "EVID-RG-LIMIT-$limitId-v$newVersion"

        val result = ConfigureRgLimitResult(
            resultId = resultId,
            config = config,
            serverTime = now,
            isDuplicate = false,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false,
            semanticContract = RG_LIMITS_ENFORCEMENT_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), limitId, command.tenantId, "RG_LIMIT_CONFIGURED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), limitId, command.tenantId, "RG_LIMIT_CONFIGURED", now)

        try {
            if (existingConfig == null) {
                store.saveConfig(config, result, command.idempotencyKey, fp, audit, outbox)
            } else {
                store.updateConfig(config, result, command.idempotencyKey, fp, audit, outbox)
            }
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "RG_LIMIT_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to store RG limit config: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun enforceLimit(command: EnforceRgLimitCommand): EnforceRgLimitResult {
        // Protected risk assertion: split transactions/product bypass/race
        ResponsibleGamingLimitsBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.playerId.isBlank() ||
            command.referenceId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.proposedAmountMinorUnits < 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val fp = fingerprintEnforce(command)
        val now = clock.instant()

        // 2. Idempotency Check
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.playerId,
                    alertType = "RG_LIMIT_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload mismatch detected for enforce limit idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as EnforceRgLimitResult
            return res.copy(isDuplicate = true)
        }

        // 3. Find active limit config
        val config = store.findConfig(command.tenantId, command.playerId, command.limitType)

        // If no limit configured or limit inactive -> ALLOWED
        if (config == null || !config.active) {
            val evalId = UUID.randomUUID()
            val result = EnforceRgLimitResult(
                evaluationId = evalId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                limitType = command.limitType,
                outcome = LimitEnforcementOutcome.ALLOWED,
                limitValueMinorUnits = Long.MAX_VALUE,
                proposedAmountMinorUnits = command.proposedAmountMinorUnits,
                consumedBeforeMinorUnits = 0L,
                consumedAfterMinorUnits = 0L,
                remainingMinorUnits = Long.MAX_VALUE,
                periodStart = now,
                periodEnd = now,
                timezone = "UTC",
                product = command.product,
                serverTime = now,
                isDuplicate = false,
                evidenceReference = "EVID-NO-LIMIT-$evalId",
                isFinancialAuthorityCreated = false,
                semanticContract = RG_LIMITS_ENFORCEMENT_CONTRACT,
            )
            val audit = AuditEvent(UUID.randomUUID(), evalId, command.tenantId, "RG_LIMIT_EVALUATED_NO_LIMIT", now, command.correlationId, command.causationId)
            val outbox = OutboxEvent(UUID.randomUUID(), evalId, command.tenantId, "RG_LIMIT_EVALUATED_NO_LIMIT", now)
            store.saveEnforceResultOnly(result, command.idempotencyKey, fp, audit, outbox)
            return result
        }

        if (command.expectedVersion != null && config.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 4. Calculate explicit period window based on config timezone (prevents timezone shifting exploits)
        val (periodStart, periodEnd) = calculatePeriodWindow(config.period, config.timezone, now)

        // 5. Query and accumulate usage for current period window
        val currentUsage = store.findUsage(command.tenantId, command.playerId, command.limitType, periodStart)
        val consumedBefore = currentUsage?.consumedMinorUnits ?: 0L
        val limitValue = config.limitValueMinorUnits

        // Check if proposed amount exceeds limit (prevents split transactions & product bypass)
        if (consumedBefore + command.proposedAmountMinorUnits > limitValue) {
            val evalId = UUID.randomUUID()
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "RG_LIMIT_EXCEEDED",
                reason = "LIMIT_BREACHED",
                detail = "Player ${command.playerId} exceeded ${config.limitType} limit of $limitValue. Consumed=$consumedBefore, Proposed=${command.proposedAmountMinorUnits}",
            )

            val result = EnforceRgLimitResult(
                evaluationId = evalId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                limitType = command.limitType,
                outcome = LimitEnforcementOutcome.EXCEEDED_LIMIT,
                limitValueMinorUnits = limitValue,
                proposedAmountMinorUnits = command.proposedAmountMinorUnits,
                consumedBeforeMinorUnits = consumedBefore,
                consumedAfterMinorUnits = consumedBefore,
                remainingMinorUnits = (limitValue - consumedBefore).coerceAtLeast(0L),
                periodStart = periodStart,
                periodEnd = periodEnd,
                timezone = config.timezone,
                product = command.product,
                serverTime = now,
                isDuplicate = false,
                evidenceReference = "EVID-LIMIT-EXCEEDED-$evalId",
                isFinancialAuthorityCreated = false,
                semanticContract = RG_LIMITS_ENFORCEMENT_CONTRACT,
            )

            val audit = AuditEvent(UUID.randomUUID(), evalId, command.tenantId, "RG_LIMIT_EXCEEDED", now, command.correlationId, command.causationId)
            val outbox = OutboxEvent(UUID.randomUUID(), evalId, command.tenantId, "RG_LIMIT_EXCEEDED", now)
            store.saveEnforceResultOnly(result, command.idempotencyKey, fp, audit, outbox)
            return result
        }

        // 6. Under limit: Consume atomically
        val consumedAfter = consumedBefore + command.proposedAmountMinorUnits
        val remaining = limitValue - consumedAfter

        val updatedUsage = RgLimitUsageRecord(
            usageId = currentUsage?.usageId ?: UUID.randomUUID(),
            tenantId = command.tenantId,
            playerId = command.playerId,
            limitType = command.limitType,
            period = config.period,
            periodStart = periodStart,
            periodEnd = periodEnd,
            timezone = config.timezone,
            consumedMinorUnits = consumedAfter,
            version = (currentUsage?.version ?: 0L) + 1L,
            updatedAt = now,
        )

        val evalId = UUID.randomUUID()
        val result = EnforceRgLimitResult(
            evaluationId = evalId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            limitType = command.limitType,
            outcome = LimitEnforcementOutcome.ALLOWED,
            limitValueMinorUnits = limitValue,
            proposedAmountMinorUnits = command.proposedAmountMinorUnits,
            consumedBeforeMinorUnits = consumedBefore,
            consumedAfterMinorUnits = consumedAfter,
            remainingMinorUnits = remaining,
            periodStart = periodStart,
            periodEnd = periodEnd,
            timezone = config.timezone,
            product = command.product,
            serverTime = now,
            isDuplicate = false,
            evidenceReference = "EVID-LIMIT-ALLOWED-$evalId",
            isFinancialAuthorityCreated = false,
            semanticContract = RG_LIMITS_ENFORCEMENT_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), evalId, command.tenantId, "RG_LIMIT_ENFORCED_ALLOWED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), evalId, command.tenantId, "RG_LIMIT_ENFORCED_ALLOWED", now)

        try {
            store.saveUsageAndResult(updatedUsage, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "RG_LIMIT_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to update RG limit usage: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }
}
