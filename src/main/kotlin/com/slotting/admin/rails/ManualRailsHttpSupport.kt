package com.slotting.admin.rails

import com.slotting.admin.storage.SignedUrl
import com.slotting.admin.storage.StorageSignTransport
import com.slotting.admin.storage.StorageSignedUrlService
import org.springframework.http.HttpStatus
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.util.UUID

data class ManualRailsSettings(
    val depositRate: BigDecimal,
    val payoutRate: BigDecimal,
    val feePercent: BigDecimal,
    val slaWorkingDays: Int,
)

interface ManualRailsSettingsStore {
    fun get(): ManualRailsSettings
    fun update(settings: ManualRailsSettings, by: String)
}

data class DepositQueueRow(
    val id: String,
    val tenantId: String,
    val playerId: String,
    val amountPkr: BigDecimal,
    val transferReference: String,
    val transferredUtc: Instant,
    val fundingAccountTitle: String,
    val fundingAccountNumber: String,
    val receiptObject: String,
    val status: SubmissionStatus,
    val amountUsd: BigDecimal?,
    val rateApplied: BigDecimal?,
    val rejectReason: String?,
)

interface DepositQueueStore {
    fun listSubmitted(tenantId: String): List<DepositQueueRow>
    fun find(id: String): DepositQueueRow?
}

data class PayoutQueueRow(
    val id: String,
    val tenantId: String,
    val playerId: String,
    val amountUsd: BigDecimal,
    val feeUsd: BigDecimal,
    val netUsd: BigDecimal,
    val payoutRate: BigDecimal,
    val payoutPkr: BigDecimal,
    val destType: String,
    val destTitle: String,
    val destNumber: String,
    val status: PayoutStatus,
    val receiptObject: String?,
    val rejectReason: String?,
    val requestedUtc: Instant,
    val paidUtc: Instant?,
)

interface PayoutQueueStore {
    fun listByStatus(tenantId: String, status: PayoutStatus): List<PayoutQueueRow>
    fun listMine(tenantId: String, playerId: String): List<PayoutQueueRow>
    fun find(id: String): PayoutQueueRow?
}

interface PayoutReceiptStore {
    fun updateReceiptObject(id: String, path: String): Boolean
}

interface RailsFundingAccountStore {
    fun listVisible(tenantId: String): List<FundingAccount>
    fun listAll(tenantId: String): List<FundingAccount>
    fun find(id: String): FundingAccount?
    fun insert(account: FundingAccount)
    fun updateVisibility(id: String, visible: Boolean): Boolean
    fun deleteIfUnreferenced(id: String): Boolean
}

data class RailsAuditEntry(
    val tenantId: String,
    val adminId: String,
    val action: String,
    val subjectId: String,
    val oldValue: String?,
    val newValue: String?,
    val occurredAt: Instant,
)

fun interface RailsAuditRecorder {
    fun record(entry: RailsAuditEntry)
}

class RailsHttpException(
    val code: String,
    val status: HttpStatus,
    message: String,
) : RuntimeException(message)

class ManualRailsReceiptService(
    private val signedUrls: StorageSignedUrlService = StorageSignedUrlService(UrlOnlyStorageTransport()),
    private val clock: Clock = Clock.systemUTC(),
) {
    fun depositObjectPath(tenantId: String, playerId: String, fileName: String): String =
        "$tenantId/$playerId/deposit-receipts/${UUID.randomUUID()}-${safeName(fileName)}"

    fun payoutObjectPath(tenantId: String, playerId: String, requestId: String, fileName: String): String =
        "$tenantId/$playerId/payout-receipts/$requestId-${safeName(fileName)}"

    fun uploadUrl(tenantId: String, playerId: String, objectPath: String): SignedUrl {
        requireImagePath(objectPath)
        return signedUrls.issue(tenantId, playerId, "player-documents", objectPath, 300)
    }

    fun readUrl(tenantId: String, playerId: String, objectPath: String): SignedUrl {
        requireImagePath(objectPath)
        return signedUrls.issue(tenantId, playerId, "player-documents", objectPath, 300)
    }

    fun requireImage(fileName: String, contentType: String) {
        val name = fileName.lowercase()
        val type = contentType.lowercase()
        val allowedType = type in setOf("image/png", "image/jpeg", "image/jpg", "image/webp")
        val allowedName = name.endsWith(".png") || name.endsWith(".jpg") || name.endsWith(".jpeg") || name.endsWith(".webp")
        if (!allowedType || !allowedName) {
            throw RailsHttpException("INVALID_RECEIPT_TYPE", HttpStatus.BAD_REQUEST, "receipt must be a PNG, JPEG or WebP image")
        }
    }

    private fun requireImagePath(objectPath: String) {
        val name = objectPath.lowercase()
        if (!name.endsWith(".png") && !name.endsWith(".jpg") && !name.endsWith(".jpeg") && !name.endsWith(".webp")) {
            throw RailsHttpException("INVALID_RECEIPT_TYPE", HttpStatus.BAD_REQUEST, "receipt path must be an image")
        }
    }

    private fun safeName(fileName: String): String {
        val cleaned = fileName.substringAfterLast('/').substringAfterLast('\\')
        if (cleaned.isBlank() || !cleaned.matches(Regex("^[A-Za-z0-9._-]{1,120}$"))) {
            throw RailsHttpException("INVALID_RECEIPT_NAME", HttpStatus.BAD_REQUEST, "receipt file name is invalid")
        }
        return cleaned
    }
}

private class UrlOnlyStorageTransport : StorageSignTransport {
    override fun sign(bucket: String, objectPath: String, expiresInSeconds: Long): String =
        "https://storage.local/$bucket/${objectPath.trimStart('/')}?expires=$expiresInSeconds"
}
