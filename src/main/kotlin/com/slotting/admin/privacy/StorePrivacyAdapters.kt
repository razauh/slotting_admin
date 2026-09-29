package com.slotting.admin.privacy

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

class AuthenticationStoreAdapter : StorePrivacyAdapter {
    override val storeId: String = "authentication-store"
    override val supportedCategories: Set<DataCategory> = setOf(
        DataCategory.AUTHENTICATION_DATA,
        DataCategory.SESSION_DATA,
        DataCategory.DEVICE_SESSION,
    )
    override val supportedOperations: Set<PrivacyOperation> = setOf(
        PrivacyOperation.EXPORT,
        PrivacyOperation.DELETE,
        PrivacyOperation.PSEUDONYMIZE,
    )

    // In-memory representation of user sessions & credentials
    val activeSessions = ConcurrentHashMap<String, MutableSet<String>>() // subjectId -> sessionIds
    val credentials = ConcurrentHashMap<String, String>() // subjectId -> credentialHash

    override fun executeAction(command: StoreActionCommand): StoreActionReceipt {
        val sessions = activeSessions[command.subjectId] ?: mutableSetOf()
        val sessionCount = sessions.size
        val hasCreds = credentials.containsKey(command.subjectId)
        val totalRecords = sessionCount + (if (hasCreds) 1 else 0)

        val executedAction = when (command.requestedAction) {
            PostRetentionAction.DELETE -> {
                activeSessions.remove(command.subjectId)
                credentials.remove(command.subjectId)
                PostRetentionAction.DELETE
            }
            PostRetentionAction.PSEUDONYMIZE -> {
                activeSessions.remove(command.subjectId)
                credentials[command.subjectId] = "PSEUDONYMIZED"
                PostRetentionAction.PSEUDONYMIZE
            }
            else -> command.requestedAction
        }

        return StoreActionReceipt(
            storeId = storeId,
            dataCategory = command.dataCategory,
            requestedAction = command.requestedAction,
            executedAction = executedAction,
            status = StoreActionStatus.COMPLETED,
            recordCount = totalRecords,
            details = "Authentication sessions purged and credentials invalidated/pseudonymized.",
            occurredAt = Instant.now(),
        )
    }

    override fun queryData(tenantId: String, subjectId: String, category: DataCategory): StoreDataExportReceipt {
        val sessions = activeSessions[subjectId] ?: emptySet()
        val cred = credentials[subjectId]
        val count = sessions.size + (if (cred != null && cred != "PSEUDONYMIZED") 1 else 0)
        val digest = if (count > 0) sha256("$subjectId:$sessions:$cred") else "EMPTY"
        return StoreDataExportReceipt(
            storeId = storeId,
            dataCategory = category,
            recordCount = count,
            dataDigestSha256 = digest,
            recordsJson = if (count > 0) "{\"sessions\":${sessions.size}}" else null,
        )
    }

    private fun sha256(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}

class LedgerStoreAdapter : StorePrivacyAdapter {
    override val storeId: String = "financial-ledger-store"
    override val supportedCategories: Set<DataCategory> = setOf(
        DataCategory.FINANCIAL_LEDGER,
        DataCategory.FINANCIAL_TRANSACTION_TIMELINE,
        DataCategory.LEDGER,
        DataCategory.PAYMENT,
    )
    override val supportedOperations: Set<PrivacyOperation> = setOf(
        PrivacyOperation.EXPORT,
        PrivacyOperation.PSEUDONYMIZE,
        PrivacyOperation.RETAIN,
    )

    data class LedgerEntry(
        val entryId: UUID = UUID.randomUUID(),
        var subjectId: String,
        val debitAmountCents: Long,
        val creditAmountCents: Long,
        val createdAt: Instant = Instant.now(),
    )

    val ledgerEntries = ConcurrentHashMap<String, MutableList<LedgerEntry>>() // subjectId -> entries
    var statutoryRetentionOverrideEnabled: Boolean = true

    override fun executeAction(command: StoreActionCommand): StoreActionReceipt {
        val entries = ledgerEntries[command.subjectId] ?: mutableListOf()
        val count = entries.size

        // Invariant: Double-entry ledger balance integrity must NEVER be destroyed.
        // If statutory retention applies, records are retained under statutory override.
        // If pseudonymization is requested or permitted, subject references are masked while debit/credit entries remain intact.
        return if (statutoryRetentionOverrideEnabled && command.requestedAction == PostRetentionAction.DELETE) {
            StoreActionReceipt(
                storeId = storeId,
                dataCategory = command.dataCategory,
                requestedAction = command.requestedAction,
                executedAction = PostRetentionAction.RETAIN,
                status = StoreActionStatus.STATUTORY_OVERRIDE,
                recordCount = count,
                details = "Statutory financial record retention obligation overrides destructive deletion; double-entry balances preserved.",
                occurredAt = Instant.now(),
            )
        } else if (command.requestedAction == PostRetentionAction.PSEUDONYMIZE || command.requestedAction == PostRetentionAction.DELETE) {
            val pseudoId = "PSEUDO_" + sha256(command.subjectId).take(12)
            entries.forEach { it.subjectId = pseudoId }
            ledgerEntries.remove(command.subjectId)
            ledgerEntries[pseudoId] = entries
            StoreActionReceipt(
                storeId = storeId,
                dataCategory = command.dataCategory,
                requestedAction = command.requestedAction,
                executedAction = PostRetentionAction.PSEUDONYMIZE,
                status = StoreActionStatus.COMPLETED,
                recordCount = count,
                details = "Subject references pseudonymized on ledger entries; double-entry balance integrity fully preserved.",
                occurredAt = Instant.now(),
            )
        } else {
            StoreActionReceipt(
                storeId = storeId,
                dataCategory = command.dataCategory,
                requestedAction = command.requestedAction,
                executedAction = PostRetentionAction.RETAIN,
                status = StoreActionStatus.STATUTORY_OVERRIDE,
                recordCount = count,
                details = "Ledger records retained per policy.",
                occurredAt = Instant.now(),
            )
        }
    }

    override fun queryData(tenantId: String, subjectId: String, category: DataCategory): StoreDataExportReceipt {
        val entries = ledgerEntries[subjectId] ?: emptyList()
        val digest = if (entries.isNotEmpty()) sha256("$subjectId:${entries.size}") else "EMPTY"
        return StoreDataExportReceipt(
            storeId = storeId,
            dataCategory = category,
            recordCount = entries.size,
            dataDigestSha256 = digest,
            recordsJson = if (entries.isNotEmpty()) "{\"entries\":${entries.size}}" else null,
        )
    }

    private fun sha256(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}

class KycStoreAdapter : StorePrivacyAdapter {
    override val storeId: String = "kyc-document-store"
    override val supportedCategories: Set<DataCategory> = setOf(
        DataCategory.KYC_DOCUMENTS,
        DataCategory.KYC_METADATA,
        DataCategory.KYC_DOCUMENT,
    )
    override val supportedOperations: Set<PrivacyOperation> = setOf(
        PrivacyOperation.EXPORT,
        PrivacyOperation.DELETE,
        PrivacyOperation.REDACT,
    )

    data class KycDoc(val docId: String, val fileName: String, val uploadedAt: Instant = Instant.now())
    val documents = ConcurrentHashMap<String, MutableList<KycDoc>>() // subjectId -> docs

    override fun executeAction(command: StoreActionCommand): StoreActionReceipt {
        val docs = documents[command.subjectId] ?: mutableListOf()
        val count = docs.size

        return when (command.requestedAction) {
            PostRetentionAction.DELETE -> {
                documents.remove(command.subjectId)
                StoreActionReceipt(
                    storeId = storeId,
                    dataCategory = command.dataCategory,
                    requestedAction = command.requestedAction,
                    executedAction = PostRetentionAction.DELETE,
                    status = StoreActionStatus.COMPLETED,
                    recordCount = count,
                    details = "KYC documents and metadata securely deleted.",
                    occurredAt = Instant.now(),
                )
            }
            PostRetentionAction.REDACT -> {
                documents[command.subjectId] = docs.map { it.copy(fileName = "REDACTED") }.toMutableList()
                StoreActionReceipt(
                    storeId = storeId,
                    dataCategory = command.dataCategory,
                    requestedAction = command.requestedAction,
                    executedAction = PostRetentionAction.REDACT,
                    status = StoreActionStatus.COMPLETED,
                    recordCount = count,
                    details = "KYC documents redacted.",
                    occurredAt = Instant.now(),
                )
            }
            else -> {
                StoreActionReceipt(
                    storeId = storeId,
                    dataCategory = command.dataCategory,
                    requestedAction = command.requestedAction,
                    executedAction = PostRetentionAction.RETAIN,
                    status = StoreActionStatus.STATUTORY_OVERRIDE,
                    recordCount = count,
                    details = "KYC documents retained per statutory AML retention.",
                    occurredAt = Instant.now(),
                )
            }
        }
    }

    override fun queryData(tenantId: String, subjectId: String, category: DataCategory): StoreDataExportReceipt {
        val docs = documents[subjectId] ?: emptyList()
        val digest = if (docs.isNotEmpty()) MessageDigest.getInstance("SHA-256")
            .digest(docs.joinToString { it.docId }.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) } else "EMPTY"
        return StoreDataExportReceipt(
            storeId = storeId,
            dataCategory = category,
            recordCount = docs.size,
            dataDigestSha256 = digest,
            recordsJson = if (docs.isNotEmpty()) "{\"docs\":${docs.size}}" else null,
        )
    }
}

class FraudStoreAdapter : StorePrivacyAdapter {
    override val storeId: String = "fraud-risk-store"
    override val supportedCategories: Set<DataCategory> = setOf(
        DataCategory.FRAUD_EVENTS,
        DataCategory.ADMINISTRATIVE_BANS,
    )
    override val supportedOperations: Set<PrivacyOperation> = setOf(
        PrivacyOperation.EXPORT,
        PrivacyOperation.DELETE,
        PrivacyOperation.RETAIN,
    )

    val openInvestigations = ConcurrentHashMap<String, Boolean>() // subjectId -> hasOpenInvestigation
    val fraudRecords = ConcurrentHashMap<String, MutableList<String>>() // subjectId -> fraudEvents

    override fun executeAction(command: StoreActionCommand): StoreActionReceipt {
        val records = fraudRecords[command.subjectId] ?: mutableListOf()
        val count = records.size
        val hasOpenCase = openInvestigations[command.subjectId] ?: false

        return if (hasOpenCase) {
            StoreActionReceipt(
                storeId = storeId,
                dataCategory = command.dataCategory,
                requestedAction = command.requestedAction,
                executedAction = PostRetentionAction.HOLD,
                status = StoreActionStatus.STATUTORY_OVERRIDE,
                recordCount = count,
                details = "Active fraud risk investigation or regulatory report blocks deletion.",
                occurredAt = Instant.now(),
            )
        } else {
            if (command.requestedAction == PostRetentionAction.DELETE) {
                fraudRecords.remove(command.subjectId)
                StoreActionReceipt(
                    storeId = storeId,
                    dataCategory = command.dataCategory,
                    requestedAction = command.requestedAction,
                    executedAction = PostRetentionAction.DELETE,
                    status = StoreActionStatus.COMPLETED,
                    recordCount = count,
                    details = "Closed fraud risk events deleted per retention policy.",
                    occurredAt = Instant.now(),
                )
            } else {
                StoreActionReceipt(
                    storeId = storeId,
                    dataCategory = command.dataCategory,
                    requestedAction = command.requestedAction,
                    executedAction = command.requestedAction,
                    status = StoreActionStatus.COMPLETED,
                    recordCount = count,
                    details = "Fraud records processed.",
                    occurredAt = Instant.now(),
                )
            }
        }
    }

    override fun queryData(tenantId: String, subjectId: String, category: DataCategory): StoreDataExportReceipt {
        val records = fraudRecords[subjectId] ?: emptyList()
        val digest = if (records.isNotEmpty()) MessageDigest.getInstance("SHA-256")
            .digest(records.joinToString().toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) } else "EMPTY"
        return StoreDataExportReceipt(
            storeId = storeId,
            dataCategory = category,
            recordCount = records.size,
            dataDigestSha256 = digest,
            recordsJson = if (records.isNotEmpty()) "{\"fraudEvents\":${records.size}}" else null,
        )
    }
}

class ResponsibleGamingStoreAdapter : StorePrivacyAdapter {
    override val storeId: String = "responsible-gaming-store"
    override val supportedCategories: Set<DataCategory> = setOf(
        DataCategory.RESPONSIBLE_GAMING_RECORDS,
    )
    override val supportedOperations: Set<PrivacyOperation> = setOf(
        PrivacyOperation.EXPORT,
        PrivacyOperation.RETAIN,
        PrivacyOperation.DELETE,
    )

    val activeExclusions = ConcurrentHashMap<String, Boolean>() // subjectId -> isExclusionActive
    val limits = ConcurrentHashMap<String, String>() // subjectId -> limitConfig

    override fun executeAction(command: StoreActionCommand): StoreActionReceipt {
        val isExcluded = activeExclusions[command.subjectId] ?: false
        val hasLimits = limits.containsKey(command.subjectId)
        val count = (if (isExcluded) 1 else 0) + (if (hasLimits) 1 else 0)

        // Invariant: Self-exclusion cannot be deleted to evade exclusion!
        return if (isExcluded && command.requestedAction == PostRetentionAction.DELETE) {
            StoreActionReceipt(
                storeId = storeId,
                dataCategory = command.dataCategory,
                requestedAction = command.requestedAction,
                executedAction = PostRetentionAction.RETAIN,
                status = StoreActionStatus.STATUTORY_OVERRIDE,
                recordCount = count,
                details = "Active self-exclusion record cannot be erased; retention mandated by responsible gaming regulation.",
                occurredAt = Instant.now(),
            )
        } else {
            limits.remove(command.subjectId)
            StoreActionReceipt(
                storeId = storeId,
                dataCategory = command.dataCategory,
                requestedAction = command.requestedAction,
                executedAction = PostRetentionAction.DELETE,
                status = StoreActionStatus.COMPLETED,
                recordCount = count,
                details = "Non-exclusion responsible gaming limit history deleted.",
                occurredAt = Instant.now(),
            )
        }
    }

    override fun queryData(tenantId: String, subjectId: String, category: DataCategory): StoreDataExportReceipt {
        val isExcluded = activeExclusions[subjectId] ?: false
        val limit = limits[subjectId]
        val count = (if (isExcluded) 1 else 0) + (if (limit != null) 1 else 0)
        return StoreDataExportReceipt(
            storeId = storeId,
            dataCategory = category,
            recordCount = count,
            dataDigestSha256 = if (count > 0) "RG_ACTIVE_$subjectId" else "EMPTY",
        )
    }
}

class SupportStoreAdapter : StorePrivacyAdapter {
    override val storeId: String = "customer-support-store"
    override val supportedCategories: Set<DataCategory> = setOf(
        DataCategory.SUPPORT_CASES,
        DataCategory.SUPPORT_ATTACHMENTS,
        DataCategory.COMMUNICATION,
    )
    override val supportedOperations: Set<PrivacyOperation> = setOf(
        PrivacyOperation.EXPORT,
        PrivacyOperation.DELETE,
        PrivacyOperation.REDACT,
    )

    data class SupportCase(val caseId: String, var subject: String, var message: String, val attachments: MutableList<String>)
    val supportCases = ConcurrentHashMap<String, MutableList<SupportCase>>() // subjectId -> cases

    override fun executeAction(command: StoreActionCommand): StoreActionReceipt {
        val cases = supportCases[command.subjectId] ?: mutableListOf()
        val count = cases.size

        return when (command.requestedAction) {
            PostRetentionAction.DELETE -> {
                supportCases.remove(command.subjectId)
                StoreActionReceipt(
                    storeId = storeId,
                    dataCategory = command.dataCategory,
                    requestedAction = command.requestedAction,
                    executedAction = PostRetentionAction.DELETE,
                    status = StoreActionStatus.COMPLETED,
                    recordCount = count,
                    details = "Support cases and attachments permanently deleted.",
                    occurredAt = Instant.now(),
                )
            }
            PostRetentionAction.REDACT -> {
                cases.forEach {
                    it.subject = "REDACTED"
                    it.message = "REDACTED"
                    it.attachments.clear()
                }
                StoreActionReceipt(
                    storeId = storeId,
                    dataCategory = command.dataCategory,
                    requestedAction = command.requestedAction,
                    executedAction = PostRetentionAction.REDACT,
                    status = StoreActionStatus.COMPLETED,
                    recordCount = count,
                    details = "Support cases text and attachments redacted.",
                    occurredAt = Instant.now(),
                )
            }
            else -> {
                StoreActionReceipt(
                    storeId = storeId,
                    dataCategory = command.dataCategory,
                    requestedAction = command.requestedAction,
                    executedAction = command.requestedAction,
                    status = StoreActionStatus.COMPLETED,
                    recordCount = count,
                    details = "Support cases retained per policy.",
                    occurredAt = Instant.now(),
                )
            }
        }
    }

    override fun queryData(tenantId: String, subjectId: String, category: DataCategory): StoreDataExportReceipt {
        val cases = supportCases[subjectId] ?: emptyList()
        val digest = if (cases.isNotEmpty()) MessageDigest.getInstance("SHA-256")
            .digest(cases.joinToString { "${it.caseId}:${it.subject}" }.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) } else "EMPTY"
        return StoreDataExportReceipt(
            storeId = storeId,
            dataCategory = category,
            recordCount = cases.size,
            dataDigestSha256 = digest,
            recordsJson = if (cases.isNotEmpty()) "{\"cases\":${cases.size}}" else null,
        )
    }
}

class NotificationSuppressionAdapter : StorePrivacyAdapter {
    override val storeId: String = "notification-suppression-store"
    override val supportedCategories: Set<DataCategory> = setOf(
        DataCategory.NOTIFICATION_SUPPRESSION,
    )
    override val supportedOperations: Set<PrivacyOperation> = setOf(
        PrivacyOperation.EXPORT,
        PrivacyOperation.RETAIN,
    )

    // Tombstone list: subjectId -> true (player opted out or erased, MUST NEVER receive marketing)
    val suppressedSubjects = ConcurrentHashMap<String, Boolean>()

    override fun executeAction(command: StoreActionCommand): StoreActionReceipt {
        // Invariant: Suppression tombstone must be PRESERVED or CREATED upon erasure so the user is never contacted again!
        suppressedSubjects[command.subjectId] = true
        return StoreActionReceipt(
            storeId = storeId,
            dataCategory = command.dataCategory,
            requestedAction = command.requestedAction,
            executedAction = PostRetentionAction.RETAIN,
            status = StoreActionStatus.STATUTORY_OVERRIDE,
            recordCount = 1,
            details = "Marketing suppression tombstone retained to prevent future unsolicited communication after account erasure.",
            occurredAt = Instant.now(),
        )
    }

    override fun queryData(tenantId: String, subjectId: String, category: DataCategory): StoreDataExportReceipt {
        val isSuppressed = suppressedSubjects[subjectId] ?: false
        return StoreDataExportReceipt(
            storeId = storeId,
            dataCategory = category,
            recordCount = if (isSuppressed) 1 else 0,
            dataDigestSha256 = if (isSuppressed) "SUPPRESSED_$subjectId" else "EMPTY",
        )
    }
}

class ExternalPrivacyProviderAdapter(
    val config: ExternalPrivacyProviderConfig,
    var failSimulated: Boolean = false,
    var transientFailureSimulated: Boolean = false,
) : StorePrivacyAdapter {
    override val storeId: String = "external-provider-${config.providerId}"
    override val supportedCategories: Set<DataCategory> = setOf(
        DataCategory.OPERATIONAL_TELEMETRY,
        DataCategory.MOBILE_TELEMETRY,
        DataCategory.CRASH_REPORTS,
    )
    override val supportedOperations: Set<PrivacyOperation> = setOf(
        PrivacyOperation.DELETE,
    )

    val externalRecords = ConcurrentHashMap<String, Int>() // subjectId -> recordCount

    override fun executeAction(command: StoreActionCommand): StoreActionReceipt {
        val count = externalRecords[command.subjectId] ?: 5

        if (transientFailureSimulated) {
            return StoreActionReceipt(
                storeId = storeId,
                dataCategory = command.dataCategory,
                requestedAction = command.requestedAction,
                executedAction = command.requestedAction,
                status = StoreActionStatus.RETRYABLE_FAILURE,
                recordCount = count,
                details = "External provider endpoint ${config.endpointUrl} returned 503 Service Unavailable; queued for retry.",
                occurredAt = Instant.now(),
            )
        }

        if (failSimulated) {
            return StoreActionReceipt(
                storeId = storeId,
                dataCategory = command.dataCategory,
                requestedAction = command.requestedAction,
                executedAction = command.requestedAction,
                status = StoreActionStatus.PERMANENT_FAILURE,
                recordCount = count,
                details = "External provider rejected erasure request with 400 Bad Request.",
                occurredAt = Instant.now(),
            )
        }

        if (!config.supportsAutomatedErasure) {
            return StoreActionReceipt(
                storeId = storeId,
                dataCategory = command.dataCategory,
                requestedAction = command.requestedAction,
                executedAction = command.requestedAction,
                status = StoreActionStatus.MANUAL_ACTION_REQUIRED,
                recordCount = count,
                details = "Provider '${config.providerId}' does not support automated API erasure; manual action required in partner portal.",
                occurredAt = Instant.now(),
            )
        }

        // Automated success
        externalRecords.remove(command.subjectId)
        return StoreActionReceipt(
            storeId = storeId,
            dataCategory = command.dataCategory,
            requestedAction = command.requestedAction,
            executedAction = PostRetentionAction.DELETE,
            status = StoreActionStatus.COMPLETED,
            recordCount = count,
            details = "External provider deletion successfully acknowledged with provider receipt.",
            occurredAt = Instant.now(),
        )
    }

    override fun queryData(tenantId: String, subjectId: String, category: DataCategory): StoreDataExportReceipt {
        val count = externalRecords[subjectId] ?: 0
        return StoreDataExportReceipt(
            storeId = storeId,
            dataCategory = category,
            recordCount = count,
            dataDigestSha256 = if (count > 0) "EXTERNAL_${config.providerId}_$subjectId" else "EMPTY",
        )
    }
}
