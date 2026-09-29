package com.slotting.admin.rg

import java.time.Instant
import java.util.UUID

interface DurableResponsibleGamingStore {
    fun findLimitConfig(tenantId: String, playerId: String, limitType: RgLimitType): RgLimitConfig?
    fun listLimitConfigs(tenantId: String, playerId: String): List<RgLimitConfig>
    fun saveLimitConfig(config: RgLimitConfig, expectedVersion: Long?): Boolean
    fun findUsage(tenantId: String, playerId: String, limitType: RgLimitType, periodStart: Instant): RgLimitUsageRecord?
    fun listUsages(tenantId: String, playerId: String): List<RgLimitUsageRecord>
    fun saveUsage(usage: RgLimitUsageRecord, expectedVersion: Long?): Boolean
    fun findActiveExclusion(tenantId: String, playerId: String, now: Instant): DurableExclusionRecord?
    fun listExclusions(tenantId: String, playerId: String): List<DurableExclusionRecord>
    fun saveExclusion(exclusion: DurableExclusionRecord): Boolean
    fun updateExclusion(exclusion: DurableExclusionRecord, expectedVersion: Long?): Boolean
    fun findIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any)
}

open class InMemoryDurableResponsibleGamingStore : DurableResponsibleGamingStore {
    private val configs = mutableMapOf<String, RgLimitConfig>()
    private val usages = mutableMapOf<String, RgLimitUsageRecord>()
    private val exclusions = mutableMapOf<UUID, DurableExclusionRecord>()
    private val idempotency = mutableMapOf<String, Pair<String, Any>>()

    private fun configKey(tenantId: String, playerId: String, limitType: RgLimitType) = "$tenantId:$playerId:$limitType"
    private fun usageKey(tenantId: String, playerId: String, limitType: RgLimitType, start: Instant) = "$tenantId:$playerId:$limitType:$start"
    private fun idempKey(tenantId: String, key: String) = "$tenantId:$key"

    @Synchronized
    override fun findLimitConfig(tenantId: String, playerId: String, limitType: RgLimitType): RgLimitConfig? =
        configs[configKey(tenantId, playerId, limitType)]

    @Synchronized
    override fun listLimitConfigs(tenantId: String, playerId: String): List<RgLimitConfig> =
        configs.values.filter { it.tenantId == tenantId && it.playerId == playerId }

    @Synchronized
    override fun saveLimitConfig(config: RgLimitConfig, expectedVersion: Long?): Boolean {
        val key = configKey(config.tenantId, config.playerId, config.limitType)
        val existing = configs[key]
        if (expectedVersion != null && existing?.version != expectedVersion) {
            return false
        }
        configs[key] = config
        return true
    }

    @Synchronized
    override fun findUsage(tenantId: String, playerId: String, limitType: RgLimitType, periodStart: Instant): RgLimitUsageRecord? =
        usages[usageKey(tenantId, playerId, limitType, periodStart)]

    @Synchronized
    override fun listUsages(tenantId: String, playerId: String): List<RgLimitUsageRecord> =
        usages.values.filter { it.tenantId == tenantId && it.playerId == playerId }

    @Synchronized
    override fun saveUsage(usage: RgLimitUsageRecord, expectedVersion: Long?): Boolean {
        val key = usageKey(usage.tenantId, usage.playerId, usage.limitType, usage.periodStart)
        val existing = usages[key]
        if (expectedVersion != null && existing?.version != expectedVersion) {
            return false
        }
        usages[key] = usage
        return true
    }

    @Synchronized
    override fun findActiveExclusion(tenantId: String, playerId: String, now: Instant): DurableExclusionRecord? =
        exclusions.values.find {
            it.tenantId == tenantId && it.playerId == playerId && it.isEffectiveAt(now)
        }

    @Synchronized
    override fun listExclusions(tenantId: String, playerId: String): List<DurableExclusionRecord> =
        exclusions.values.filter { it.tenantId == tenantId && it.playerId == playerId }

    @Synchronized
    override fun saveExclusion(exclusion: DurableExclusionRecord): Boolean {
        exclusions[exclusion.exclusionId] = exclusion
        return true
    }

    @Synchronized
    override fun updateExclusion(exclusion: DurableExclusionRecord, expectedVersion: Long?): Boolean {
        val existing = exclusions[exclusion.exclusionId] ?: return false
        if (expectedVersion != null && existing.version != expectedVersion) {
            return false
        }
        exclusions[exclusion.exclusionId] = exclusion
        return true
    }

    @Synchronized
    override fun findIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? =
        idempotency[idempKey(tenantId, idempotencyKey)]

    @Synchronized
    override fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any) {
        idempotency[idempKey(tenantId, idempotencyKey)] = fingerprint to result
    }
}
