package com.slotting.admin.analytics

import java.time.Instant
import java.time.LocalDate
import java.util.concurrent.ConcurrentHashMap

interface AnalyticsStore {
    fun saveFact(fact: AnalyticsFact): Boolean
    fun findFactBySource(tenantId: String, sourceEventId: String): AnalyticsFact?
    fun listFactsForTenant(tenantId: String): List<AnalyticsFact>
    fun saveOrUpdateProjection(projection: DailyProjectionRecord)
    fun findProjection(
        tenantId: String,
        dateBucket: LocalDate,
        currency: String,
        dimensionType: String = "OVERALL",
        dimensionValue: String = "ALL"
    ): DailyProjectionRecord?
    fun queryProjections(
        tenantId: String,
        startDate: LocalDate,
        endDate: LocalDate,
        currency: String? = null,
        dimensionType: String = "OVERALL",
        dimensionValue: String = "ALL"
    ): List<DailyProjectionRecord>
    fun recordUniquePlayer(tenantId: String, dateBucket: LocalDate, userId: String, activityAt: Instant): Boolean
    fun countUniquePlayers(tenantId: String, startDate: LocalDate, endDate: LocalDate): Long
    fun clearProjectionsForTenant(tenantId: String)
}

class InMemoryAnalyticsStore : AnalyticsStore {
    private val facts = ConcurrentHashMap<String, AnalyticsFact>()
    private val projections = ConcurrentHashMap<String, DailyProjectionRecord>()
    private val uniquePlayers = ConcurrentHashMap<String, Instant>()

    private fun factKey(tenantId: String, sourceEventId: String): String = "$tenantId:$sourceEventId"
    private fun projKey(tenantId: String, date: LocalDate, currency: String, dimType: String, dimVal: String): String =
        "$tenantId:$date:$currency:$dimType:$dimVal"
    private fun uniqueKey(tenantId: String, date: LocalDate, userId: String): String =
        "$tenantId:$date:$userId"

    @Synchronized
    override fun saveFact(fact: AnalyticsFact): Boolean {
        val key = factKey(fact.tenantId, fact.sourceEventId)
        return facts.putIfAbsent(key, fact) == null
    }

    override fun findFactBySource(tenantId: String, sourceEventId: String): AnalyticsFact? {
        return facts[factKey(tenantId, sourceEventId)]
    }

    override fun listFactsForTenant(tenantId: String): List<AnalyticsFact> {
        return facts.values
            .filter { it.tenantId == tenantId }
            .sortedBy { it.occurredAt }
    }

    @Synchronized
    override fun saveOrUpdateProjection(projection: DailyProjectionRecord) {
        val key = projKey(
            projection.tenantId,
            projection.dateBucket,
            projection.currency,
            projection.dimensionType,
            projection.dimensionValue
        )
        projections[key] = projection
    }

    override fun findProjection(
        tenantId: String,
        dateBucket: LocalDate,
        currency: String,
        dimensionType: String,
        dimensionValue: String
    ): DailyProjectionRecord? {
        val key = projKey(tenantId, dateBucket, currency, dimensionType, dimensionValue)
        return projections[key]
    }

    override fun queryProjections(
        tenantId: String,
        startDate: LocalDate,
        endDate: LocalDate,
        currency: String?,
        dimensionType: String,
        dimensionValue: String
    ): List<DailyProjectionRecord> {
        return projections.values.filter {
            it.tenantId == tenantId &&
                !it.dateBucket.isBefore(startDate) &&
                !it.dateBucket.isAfter(endDate) &&
                (currency == null || it.currency == currency) &&
                it.dimensionType == dimensionType &&
                it.dimensionValue == dimensionValue
        }.sortedBy { it.dateBucket }
    }

    @Synchronized
    override fun recordUniquePlayer(tenantId: String, dateBucket: LocalDate, userId: String, activityAt: Instant): Boolean {
        val key = uniqueKey(tenantId, dateBucket, userId)
        return uniquePlayers.putIfAbsent(key, activityAt) == null
    }

    override fun countUniquePlayers(tenantId: String, startDate: LocalDate, endDate: LocalDate): Long {
        val prefix = "$tenantId:"
        val usersInWindow = mutableSetOf<String>()
        for ((key, _) in uniquePlayers) {
            if (key.startsWith(prefix)) {
                val parts = key.removePrefix(prefix).split(":")
                if (parts.size == 2) {
                    val date = LocalDate.parse(parts[0])
                    val userId = parts[1]
                    if (!date.isBefore(startDate) && !date.isAfter(endDate)) {
                        usersInWindow.add(userId)
                    }
                }
            }
        }
        return usersInWindow.size.toLong()
    }

    @Synchronized
    override fun clearProjectionsForTenant(tenantId: String) {
        val prefix = "$tenantId:"
        projections.keys.removeIf { it.startsWith(prefix) }
        uniquePlayers.keys.removeIf { it.startsWith(prefix) }
    }
}
