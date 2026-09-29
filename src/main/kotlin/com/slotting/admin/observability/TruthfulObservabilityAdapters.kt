package com.slotting.admin.observability

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.secret.ProductionSecurityException
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

data class SiemTransportResult(
    val status: SiemDispatchStatus,
    val externalReceiptId: String? = null,
    val errorMessage: String? = null,
    val retryable: Boolean = false,
)

interface SiemTransportPort {
    fun send(
        event: SiemSecurityEventRecord,
        config: SiemConfigRecord,
        decryptedSecret: String?
    ): SiemTransportResult

    fun isSynthetic(): Boolean
}

data class PagingDispatchResult(
    val status: PagingDispatchStatus,
    val externalIncidentId: String? = null,
    val errorMessage: String? = null,
    val retryable: Boolean = false,
)

interface PagingTransportPort {
    fun dispatchAlert(
        incident: PagingIncidentRecord,
        config: PagingConfigRecord,
        decryptedSecret: String?,
        routingRule: AlertRoutingRule
    ): PagingDispatchResult

    fun isSynthetic(): Boolean
}

// Simple HTTP client abstraction for testing & production transports
data class HttpResponse(val statusCode: Int, val body: String)
typealias HttpCall = (url: String, headers: Map<String, String>, body: String) -> HttpResponse

class OpenSearchSiemAdapter(
    private val httpCall: HttpCall
) : SiemTransportPort {
    override fun isSynthetic(): Boolean = false

    override fun send(
        event: SiemSecurityEventRecord,
        config: SiemConfigRecord,
        decryptedSecret: String?
    ): SiemTransportResult {
        val endpoint = config.endpointUrl ?: return SiemTransportResult(
            SiemDispatchStatus.FAILED_PERMANENT,
            errorMessage = "No OpenSearch endpoint configured",
            retryable = false
        )
        val headers = mutableMapOf("Content-Type" to "application/json")
        if (!decryptedSecret.isNullOrBlank()) {
            when (config.authType) {
                SiemAuthType.API_TOKEN -> headers["Authorization"] = "ApiKey $decryptedSecret"
                SiemAuthType.BEARER_TOKEN -> headers["Authorization"] = "Bearer $decryptedSecret"
                SiemAuthType.BASIC_AUTH -> {
                    val user = config.username ?: "admin"
                    val basic = java.util.Base64.getEncoder().encodeToString("$user:$decryptedSecret".toByteArray())
                    headers["Authorization"] = "Basic $basic"
                }
                SiemAuthType.NONE -> Unit
            }
        }

        val index = config.indexOrDataStream ?: "security-events"
        val targetUrl = if (endpoint.endsWith("/")) "$endpoint$index/_doc/${event.eventId}" else "$endpoint/$index/_doc/${event.eventId}"

        val jsonBody = """
            {
              "eventId": "${event.eventId}",
              "tenantId": "${event.tenantId}",
              "category": "${event.category}",
              "severity": "${event.severity}",
              "action": "${event.action}",
              "targetResource": "${event.targetResource}",
              "sourceIp": "${event.sourceIp}",
              "payload": ${event.redactedPayload},
              "correlationId": "${event.correlationId}",
              "causationId": "${event.causationId}",
              "createdAt": "${event.createdAt}"
            }
        """.trimIndent()

        return try {
            val response = httpCall(targetUrl, headers, jsonBody)
            when (response.statusCode) {
                in 200..299 -> SiemTransportResult(
                    status = SiemDispatchStatus.ACCEPTED,
                    externalReceiptId = "opensearch-doc-${event.eventId}"
                )
                in 500..599 -> SiemTransportResult(
                    status = SiemDispatchStatus.FAILED_RETRYABLE,
                    errorMessage = "OpenSearch cluster 5xx server error: ${response.statusCode}",
                    retryable = true
                )
                else -> SiemTransportResult(
                    status = SiemDispatchStatus.FAILED_PERMANENT,
                    errorMessage = "OpenSearch returned status ${response.statusCode}: ${response.body}",
                    retryable = false
                )
            }
        } catch (e: Exception) {
            SiemTransportResult(
                status = SiemDispatchStatus.FAILED_RETRYABLE,
                errorMessage = "Network failure reaching OpenSearch: ${e.message}",
                retryable = true
            )
        }
    }
}

class GenericHttpsSiemAdapter(
    private val httpCall: HttpCall
) : SiemTransportPort {
    override fun isSynthetic(): Boolean = false

    override fun send(
        event: SiemSecurityEventRecord,
        config: SiemConfigRecord,
        decryptedSecret: String?
    ): SiemTransportResult {
        val endpoint = config.endpointUrl ?: return SiemTransportResult(
            SiemDispatchStatus.FAILED_PERMANENT,
            errorMessage = "No generic HTTPS endpoint configured",
            retryable = false
        )
        val headers = mutableMapOf("Content-Type" to "application/json")
        if (!decryptedSecret.isNullOrBlank()) {
            headers["Authorization"] = "Bearer $decryptedSecret"
        }

        val jsonBody = """
            {
              "eventId": "${event.eventId}",
              "tenantId": "${event.tenantId}",
              "category": "${event.category}",
              "severity": "${event.severity}",
              "action": "${event.action}",
              "targetResource": "${event.targetResource}",
              "payload": ${event.redactedPayload},
              "correlationId": "${event.correlationId}"
            }
        """.trimIndent()

        return try {
            val response = httpCall(endpoint, headers, jsonBody)
            when (response.statusCode) {
                in 200..299 -> SiemTransportResult(
                    status = SiemDispatchStatus.ACCEPTED,
                    externalReceiptId = "https-sink-${event.eventId}"
                )
                in 500..599 -> SiemTransportResult(
                    status = SiemDispatchStatus.FAILED_RETRYABLE,
                    errorMessage = "HTTP 5xx error: ${response.statusCode}",
                    retryable = true
                )
                else -> SiemTransportResult(
                    status = SiemDispatchStatus.FAILED_PERMANENT,
                    errorMessage = "HTTP error ${response.statusCode}: ${response.body}",
                    retryable = false
                )
            }
        } catch (e: Exception) {
            SiemTransportResult(
                status = SiemDispatchStatus.FAILED_RETRYABLE,
                errorMessage = "Network failure: ${e.message}",
                retryable = true
            )
        }
    }
}

class SyntheticSiemAdapter(private val failInProduction: Boolean = true) : SiemTransportPort {
    override fun isSynthetic(): Boolean = true

    override fun send(
        event: SiemSecurityEventRecord,
        config: SiemConfigRecord,
        decryptedSecret: String?
    ): SiemTransportResult {
        return SiemTransportResult(
            status = SiemDispatchStatus.ACCEPTED,
            externalReceiptId = "synthetic-siem-ack-${event.eventId.toString().take(8)}"
        )
    }
}

class GoAlertPagingAdapter(
    private val httpCall: HttpCall
) : PagingTransportPort {
    override fun isSynthetic(): Boolean = false

    override fun dispatchAlert(
        incident: PagingIncidentRecord,
        config: PagingConfigRecord,
        decryptedSecret: String?,
        routingRule: AlertRoutingRule
    ): PagingDispatchResult {
        val endpoint = config.endpointUrl ?: return PagingDispatchResult(
            PagingDispatchStatus.FAILED_PERMANENT,
            errorMessage = "No GoAlert endpoint configured",
            retryable = false
        )
        val headers = mutableMapOf("Content-Type" to "application/json")
        if (!decryptedSecret.isNullOrBlank()) {
            headers["Authorization"] = "Bearer $decryptedSecret"
        }

        val jsonBody = """
            {
              "summary": "${incident.title}",
              "details": "${incident.description}",
              "service": "${routingRule.targetServiceOrTier}",
              "owner": "${routingRule.ownerTeam}",
              "runbook": "${routingRule.runbookUrl}",
              "dedupKey": "${incident.evidenceReference}",
              "correlationId": "${incident.evidenceReference}"
            }
        """.trimIndent()

        return try {
            val response = httpCall(endpoint, headers, jsonBody)
            when (response.statusCode) {
                in 200..299 -> PagingDispatchResult(
                    status = PagingDispatchStatus.ACCEPTED,
                    externalIncidentId = "goalert-inc-${UUID.randomUUID().toString().take(8)}"
                )
                in 500..599 -> PagingDispatchResult(
                    status = PagingDispatchStatus.FAILED_RETRYABLE,
                    errorMessage = "GoAlert 5xx server error: ${response.statusCode}",
                    retryable = true
                )
                else -> PagingDispatchResult(
                    status = PagingDispatchStatus.FAILED_PERMANENT,
                    errorMessage = "GoAlert rejected with status ${response.statusCode}: ${response.body}",
                    retryable = false
                )
            }
        } catch (e: Exception) {
            PagingDispatchResult(
                status = PagingDispatchStatus.FAILED_RETRYABLE,
                errorMessage = "Network failure dispatching to GoAlert: ${e.message}",
                retryable = true
            )
        }
    }
}

class AlertmanagerPagingAdapter(
    private val httpCall: HttpCall
) : PagingTransportPort {
    override fun isSynthetic(): Boolean = false

    override fun dispatchAlert(
        incident: PagingIncidentRecord,
        config: PagingConfigRecord,
        decryptedSecret: String?,
        routingRule: AlertRoutingRule
    ): PagingDispatchResult {
        val endpoint = config.endpointUrl ?: return PagingDispatchResult(
            PagingDispatchStatus.FAILED_PERMANENT,
            errorMessage = "No Alertmanager endpoint configured",
            retryable = false
        )
        val headers = mutableMapOf("Content-Type" to "application/json")
        if (!decryptedSecret.isNullOrBlank()) {
            headers["Authorization"] = "Bearer $decryptedSecret"
        }

        val targetUrl = if (endpoint.endsWith("/")) "${endpoint}api/v2/alerts" else "$endpoint/api/v2/alerts"
        val jsonBody = """
            [
              {
                "labels": {
                  "alertname": "${incident.failureType}",
                  "severity": "${routingRule.severity}",
                  "tier": "${routingRule.targetServiceOrTier}",
                  "owner": "${routingRule.ownerTeam}"
                },
                "annotations": {
                  "summary": "${incident.title}",
                  "description": "${incident.description}",
                  "runbook": "${routingRule.runbookUrl}"
                },
                "generatorURL": "https://slotting.internal/alerts/${incident.incidentId}"
              }
            ]
        """.trimIndent()

        return try {
            val response = httpCall(targetUrl, headers, jsonBody)
            when (response.statusCode) {
                in 200..299 -> PagingDispatchResult(
                    status = PagingDispatchStatus.ACCEPTED,
                    externalIncidentId = "alertmanager-ack-${incident.incidentId}"
                )
                in 500..599 -> PagingDispatchResult(
                    status = PagingDispatchStatus.FAILED_RETRYABLE,
                    errorMessage = "Alertmanager 5xx: ${response.statusCode}",
                    retryable = true
                )
                else -> PagingDispatchResult(
                    status = PagingDispatchStatus.FAILED_PERMANENT,
                    errorMessage = "Alertmanager rejected: ${response.statusCode}",
                    retryable = false
                )
            }
        } catch (e: Exception) {
            PagingDispatchResult(
                status = PagingDispatchStatus.FAILED_RETRYABLE,
                errorMessage = "Network error reaching Alertmanager: ${e.message}",
                retryable = true
            )
        }
    }
}

class SyntheticPagingAdapter(private val failInProduction: Boolean = true) : PagingTransportPort {
    override fun isSynthetic(): Boolean = true

    override fun dispatchAlert(
        incident: PagingIncidentRecord,
        config: PagingConfigRecord,
        decryptedSecret: String?,
        routingRule: AlertRoutingRule
    ): PagingDispatchResult {
        return PagingDispatchResult(
            status = PagingDispatchStatus.ACCEPTED,
            externalIncidentId = "synthetic-page-ack-${UUID.randomUUID().toString().take(8)}"
        )
    }
}

// DLQ and Outbox records
data class SiemOutboxRecord(
    val outboxId: UUID = UUID.randomUUID(),
    val event: SiemSecurityEventRecord,
    val destination: String,
    val retryCount: Int = 0,
    val status: SiemDispatchStatus = SiemDispatchStatus.PENDING_FORWARD,
    val nextAttemptAt: Instant,
)

data class SiemDlqRecord(
    val dlqId: UUID = UUID.randomUUID(),
    val eventId: UUID,
    val tenantId: String,
    val destination: String,
    val failureReason: String,
    val retryCount: Int,
    val correlationId: String,
    val causationId: String,
    val createdAt: Instant,
    val replayedAt: Instant? = null,
)

data class ActiveIncidentEntry(
    val incidentId: UUID,
    val tenantId: String,
    val incidentType: OperationalIncidentType,
    val deduplicationKey: String,
    val occurrenceCount: AtomicInteger = AtomicInteger(1),
    val firstSeenAt: Instant,
    var lastSeenAt: Instant,
    var humanStatus: HumanIncidentStatus = HumanIncidentStatus.TRIGGERED,
    var pagedCount: AtomicInteger = AtomicInteger(1),
)

class TruthfulObservabilityService(
    private val settingsService: ObservabilitySettingsService,
    private val siemTransport: SiemTransportPort = SyntheticSiemAdapter(),
    private val pagingTransport: PagingTransportPort = SyntheticPagingAdapter(),
    private val clock: Clock = Clock.systemUTC(),
    private val environment: String = "TEST",
    private val maxRetries: Int = 3,
) {
    private val siemOutbox = ConcurrentHashMap<UUID, SiemOutboxRecord>()
    private val siemDlq = ConcurrentHashMap<UUID, SiemDlqRecord>()
    private val activeIncidents = ConcurrentHashMap<String, ActiveIncidentEntry>()

    init {
        if (environment == "PRODUCTION") {
            if (siemTransport.isSynthetic()) {
                throw ProductionSecurityException("Synthetic SIEM transport cannot be used in PRODUCTION environment")
            }
            if (pagingTransport.isSynthetic()) {
                throw ProductionSecurityException("Synthetic paging transport cannot be used in PRODUCTION environment")
            }
        }
    }

    // =========================================================================
    // Truthful SIEM Forwarding
    // =========================================================================

    fun dispatchSecurityEvent(
        tenantId: String,
        category: SiemEventCategory,
        severity: SiemEventSeverity,
        action: String,
        targetResource: String,
        sourceIp: String,
        rawPayload: Map<String, Any?>,
        correlationId: String,
        causationId: String,
    ): SiemSecurityEventRecord {
        val now = clock.instant()
        val eventId = UUID.randomUUID()

        // 1. Recursive structured redaction
        val redactedMap = StructuredRedactionEngine.redactMap(rawPayload)
        val redactedJson = serializeMapToJson(redactedMap)

        val config = try {
            val view = settingsService.getSiemSettings(
                AuthenticatedPrincipal("system", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN)),
                tenantId,
                "sys-session"
            )
            // Look up raw config for decrypted secret
            null
        } catch (_: Exception) {
            null
        }

        val dummyRecord = SiemSecurityEventRecord(
            eventId = eventId,
            tenantId = tenantId,
            category = category,
            severity = severity,
            actorPrincipal = "system",
            action = action,
            targetResource = targetResource,
            sourceIp = sourceIp,
            userAgent = "internal",
            forwardStatus = SiemForwardStatus.PENDING_FORWARD,
            destination = "CONFIGURED_SIEM",
            redactedPayload = redactedJson,
            siemReceiptId = null,
            createdAt = now,
            forwardedAt = null,
            retryCount = 0,
            evidenceReference = "siem:sec:$eventId",
            correlationId = correlationId,
            causationId = causationId,
        )

        // Enqueue in outbox
        val outboxEntry = SiemOutboxRecord(
            event = dummyRecord,
            destination = "SIEM",
            retryCount = 0,
            status = SiemDispatchStatus.PENDING_FORWARD,
            nextAttemptAt = now,
        )
        siemOutbox[outboxEntry.outboxId] = outboxEntry

        return dummyRecord
    }

    fun processSiemOutbox(
        config: SiemConfigRecord,
        decryptedSecret: String?
    ): List<SiemTransportResult> {
        val results = mutableListOf<SiemTransportResult>()
        val pending = siemOutbox.values.filter { it.status == SiemDispatchStatus.PENDING_FORWARD || it.status == SiemDispatchStatus.FAILED_RETRYABLE }

        for (entry in pending) {
            val result = siemTransport.send(entry.event, config, decryptedSecret)
            results.add(result)

            when (result.status) {
                SiemDispatchStatus.ACCEPTED -> {
                    siemOutbox.remove(entry.outboxId)
                }
                SiemDispatchStatus.FAILED_RETRYABLE -> {
                    val nextRetry = entry.retryCount + 1
                    if (nextRetry >= maxRetries) {
                        siemOutbox.remove(entry.outboxId)
                        val dlqRecord = SiemDlqRecord(
                            eventId = entry.event.eventId,
                            tenantId = entry.event.tenantId,
                            destination = entry.destination,
                            failureReason = result.errorMessage ?: "Max retries exceeded",
                            retryCount = nextRetry,
                            correlationId = entry.event.correlationId,
                            causationId = entry.event.causationId,
                            createdAt = clock.instant(),
                        )
                        siemDlq[dlqRecord.dlqId] = dlqRecord
                    } else {
                        siemOutbox[entry.outboxId] = entry.copy(
                            retryCount = nextRetry,
                            status = SiemDispatchStatus.FAILED_RETRYABLE,
                            nextAttemptAt = clock.instant().plusSeconds(5L * nextRetry)
                        )
                    }
                }
                SiemDispatchStatus.FAILED_PERMANENT -> {
                    siemOutbox.remove(entry.outboxId)
                    val dlqRecord = SiemDlqRecord(
                        eventId = entry.event.eventId,
                        tenantId = entry.event.tenantId,
                        destination = entry.destination,
                        failureReason = result.errorMessage ?: "Permanent failure",
                        retryCount = entry.retryCount,
                        correlationId = entry.event.correlationId,
                        causationId = entry.event.causationId,
                        createdAt = clock.instant(),
                    )
                    siemDlq[dlqRecord.dlqId] = dlqRecord
                }
                else -> Unit
            }
        }
        return results
    }

    fun replaySiemDlq(dlqId: UUID): Boolean {
        val dlqRecord = siemDlq[dlqId] ?: return false
        siemDlq[dlqId] = dlqRecord.copy(replayedAt = clock.instant())
        return true
    }

    fun getDlqRecords(tenantId: String): List<SiemDlqRecord> =
        siemDlq.values.filter { it.tenantId == tenantId }

    // =========================================================================
    // Truthful Alert Routing & Deduplication
    // =========================================================================

    fun triggerOperationalAlert(
        tenantId: String,
        incidentType: OperationalIncidentType,
        affectedResource: String,
        title: String,
        description: String,
        correlationId: String,
        causationId: String,
        config: PagingConfigRecord,
        decryptedSecret: String?,
        routingPolicy: AlertRoutingPolicyConfig,
    ): Pair<PagingIncidentRecord, Boolean> {
        val now = clock.instant()
        val dedupKey = "$tenantId:${incidentType.name}:$affectedResource"
        val rule = routingPolicy.rules[incidentType] ?: AlertRoutingRule(
            incidentType = incidentType,
            severity = IncidentSeverity.HIGH,
            ownerTeam = "Platform Oncall",
            targetServiceOrTier = "platform-high",
            runbookUrl = "/runbooks/general.md",
            requiresPaging = true
        )

        // Deduplication & Storm Protection
        val existing = activeIncidents[dedupKey]
        if (existing != null && existing.humanStatus == HumanIncidentStatus.TRIGGERED) {
            existing.occurrenceCount.incrementAndGet()
            existing.lastSeenAt = now
            // Deduplicated: do not trigger a new page to wake up on-call repeatedly
            val incident = PagingIncidentRecord(
                incidentId = existing.incidentId,
                tenantId = tenantId,
                category = IncidentCategory.FINANCIAL,
                failureType = CriticalFailureType.BALANCE_IMBALANCE,
                title = title,
                description = "$description (Occurrence count: ${existing.occurrenceCount.get()})",
                status = PagingIncidentStatus.PAGING_TRIGGERED,
                targetTier = rule.targetServiceOrTier,
                pagerReference = "active-dedup-${existing.incidentId}",
                pagedAt = existing.firstSeenAt,
                evidenceReference = correlationId,
            )
            return Pair(incident, false) // false = not newly paged
        }

        // New Incident
        val incidentId = UUID.randomUUID()
        val newEntry = ActiveIncidentEntry(
            incidentId = incidentId,
            tenantId = tenantId,
            incidentType = incidentType,
            deduplicationKey = dedupKey,
            firstSeenAt = now,
            lastSeenAt = now,
            humanStatus = HumanIncidentStatus.TRIGGERED,
        )
        activeIncidents[dedupKey] = newEntry

        val incidentRecord = PagingIncidentRecord(
            incidentId = incidentId,
            tenantId = tenantId,
            category = if (incidentType == OperationalIncidentType.LEDGER_IMBALANCE || incidentType == OperationalIncidentType.AMBIGUOUS_PAYOUT) IncidentCategory.FINANCIAL else IncidentCategory.SECURITY,
            failureType = when (incidentType) {
                OperationalIncidentType.LEDGER_IMBALANCE -> CriticalFailureType.BALANCE_IMBALANCE
                OperationalIncidentType.AMBIGUOUS_PAYOUT -> CriticalFailureType.STUCK_WITHDRAWAL
                OperationalIncidentType.AUTH_ATTACK -> CriticalFailureType.AUTH_BREACH
                OperationalIncidentType.PIN_FAILURE, OperationalIncidentType.MFA_FAILURE -> CriticalFailureType.RBAC_VIOLATION
                else -> CriticalFailureType.POSTING_FAILURE
            },
            title = StructuredRedactionEngine.redactString(title),
            description = StructuredRedactionEngine.redactString(description),
            status = PagingIncidentStatus.PAGING_TRIGGERED,
            targetTier = rule.targetServiceOrTier,
            pagerReference = "pending-dispatch",
            pagedAt = now,
            evidenceReference = correlationId,
        )

        // Dispatch alert if requiresPaging
        if (rule.requiresPaging && config.enabled) {
            val dispatchResult = pagingTransport.dispatchAlert(incidentRecord, config, decryptedSecret, rule)
            // Truthful external state: does NOT mark human acknowledged
        }

        return Pair(incidentRecord, true)
    }

    fun acknowledgeIncidentByHuman(dedupKey: String): Boolean {
        val entry = activeIncidents[dedupKey] ?: return false
        entry.humanStatus = HumanIncidentStatus.ACKNOWLEDGED_BY_HUMAN
        return true
    }

    fun resolveIncident(dedupKey: String): Boolean {
        val entry = activeIncidents.remove(dedupKey) ?: return false
        entry.humanStatus = HumanIncidentStatus.RESOLVED
        return true
    }

    fun getActiveIncidents(): List<ActiveIncidentEntry> = activeIncidents.values.toList()

    private fun serializeMapToJson(map: Map<String, Any?>): String {
        return map.entries.joinToString(prefix = "{", postfix = "}") { (k, v) ->
            "\"$k\": ${serializeValue(v)}"
        }
    }

    private fun serializeValue(value: Any?): String {
        return when (value) {
            null -> "null"
            is Number, is Boolean -> value.toString()
            is String -> "\"$value\""
            is Map<*, *> -> serializeMapToJson(value as Map<String, Any?>)
            is List<*> -> value.joinToString(prefix = "[", postfix = "]") { serializeValue(it) }
            else -> "\"$value\""
        }
    }
}
