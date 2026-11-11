package com.slotting.admin.ops

import java.time.Clock
import java.time.Instant
import java.time.LocalDate

enum class OpsSeverity {
    CRITICAL,
    WARNING,
    INFO,
}

enum class OpsDecisionStatus {
    UNSCHEDULED,
    SCHEDULED,
    OVERDUE,
}

data class OpsDecision(
    val itemName: String,
    val owner: String?,
    val dueDate: LocalDate?,
    val status: OpsDecisionStatus,
    val reopenTrigger: String,
)

data class OpsNotice(
    val cause: String,
    val classTag: String,
    val severity: OpsSeverity,
    val text: String,
    val createdAt: Instant,
)

interface OpsNoticeRepository {
    fun open(notice: OpsNotice): Boolean

    fun list(): List<OpsNotice>

    fun ack(cause: String): Boolean
}

class InMemoryOpsNoticeRepository : OpsNoticeRepository {
    private val notices = LinkedHashMap<String, OpsNotice>()
    private val acknowledged = mutableSetOf<String>()

    override fun open(notice: OpsNotice): Boolean {
        if (notices.containsKey(notice.cause)) {
            return false
        }
        notices[notice.cause] = notice
        return true
    }

    override fun list(): List<OpsNotice> = notices.values.toList()

    override fun ack(cause: String): Boolean {
        if (!notices.containsKey(cause)) {
            return false
        }
        acknowledged.add(cause)
        return true
    }
}

class OpsWatchService(
    private val repository: OpsNoticeRepository,
    private val clock: Clock = Clock.systemUTC(),
) {
    fun notices(): List<OpsNotice> = repository.list()

    fun ack(cause: String): Boolean = repository.ack(cause)

    fun jwtEdge(probeStatus: Int, jwksHash: String? = null, previousJwksHash: String? = null): OpsNotice? {
        if (probeStatus !in 200..299) {
            return open(
                cause = "JWT_EDGE",
                classTag = "JWT_EDGE",
                severity = OpsSeverity.CRITICAL,
                text = "platform edge rejected the bridge token with status $probeStatus",
            )
        }
        if (jwksHash != null && previousJwksHash != null && jwksHash != previousJwksHash) {
            return open(
                cause = "JWT_EDGE_JWKS_CHANGE",
                classTag = "JWT_EDGE",
                severity = OpsSeverity.INFO,
                text = "platform JWKS key set changed",
            )
        }
        return null
    }

    fun exposure(probeStatus: Int, expected: Int = 200): OpsNotice? {
        if (probeStatus == expected) {
            return null
        }
        return open(
            cause = "EXPOSURE_DRIFT",
            classTag = "EXPOSURE_DRIFT",
            severity = OpsSeverity.WARNING,
            text = "api exposure probe returned $probeStatus, expected $expected",
        )
    }

    fun budgetFlip(current: Boolean, expected: Boolean): OpsNotice? {
        if (current == expected) {
            return null
        }
        return open(
            cause = "KILLSWITCH_FLIP",
            classTag = "KILLSWITCH_FLIP",
            severity = OpsSeverity.WARNING,
            text = "hint flag or kill switch changed without an admin act",
        )
    }

    fun registryEscalations(decisions: List<OpsDecision>, today: LocalDate): List<OpsNotice> {
        val raised = mutableListOf<OpsNotice>()
        decisions.forEach { decision ->
            when {
                decision.status == OpsDecisionStatus.UNSCHEDULED -> {
                    raised += reminder(decision, "DECISION_UNSCHEDULED", OpsSeverity.INFO, "has no owner or date")
                }
                decision.dueDate != null && today.isAfter(decision.dueDate) -> {
                    raised += reminder(decision, "DECISION_OVERDUE", OpsSeverity.CRITICAL, "is overdue")
                }
                decision.dueDate != null && decision.dueDate.minusDays(1) == today -> {
                    raised += reminder(decision, "DECISION_T_MINUS_ONE", OpsSeverity.WARNING, "is due tomorrow")
                }
            }
        }
        return raised
    }

    private fun reminder(decision: OpsDecision, cause: String, severity: OpsSeverity, state: String): OpsNotice =
        open(
            cause = "$cause:${decision.itemName}",
            classTag = "DECISION",
            severity = severity,
            text = "decision ${decision.itemName} $state",
        ) ?: OpsNotice(
            cause = "$cause:${decision.itemName}",
            classTag = "DECISION",
            severity = severity,
            text = "decision ${decision.itemName} $state",
            createdAt = clock.instant(),
        )

    fun raise(cause: String, classTag: String, severity: OpsSeverity, text: String): OpsNotice? =
        open(cause, classTag, severity, text)

    private fun open(cause: String, classTag: String, severity: OpsSeverity, text: String): OpsNotice? {
        val notice = OpsNotice(cause, classTag, severity, text, clock.instant())
        return if (repository.open(notice)) notice else null
    }
}
