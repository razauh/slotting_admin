package com.slotting.admin.game

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class SignedCallbackRequest(
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val signatureHeader: String,
    val timestampHeader: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class SignedCallbackVerificationResult(
    val resultId: UUID,
    val roundReference: String,
    val tenantId: String,
    val providerId: String,
    val verified: Boolean,
    val directSettlementPermitted: Boolean,
    val extractedMultiplier: Double?,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface ProviderSecretResolver {
    fun resolveSecret(tenantId: String, providerId: String): String?
}

interface SignedGameCallbackBoundaryStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, SignedCallbackVerificationResult>?
    fun isSignatureReplayed(tenantId: String, signature: String): Boolean
    fun save(
        result: SignedCallbackVerificationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        signature: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class SignedGameCallbackBoundaryService(
    private val policy: AdminRbacPolicy,
    private val secretResolver: ProviderSecretResolver,
    private val store: SignedGameCallbackBoundaryStore,
    private val clock: Clock = Clock.systemUTC(),
    private val timestampSkewToleranceSeconds: Long = 300L,
) {
    @Synchronized
    fun verifyAndProcessCallback(request: SignedCallbackRequest): SignedCallbackVerificationResult {
        if (request.tenantId.isBlank() ||
            request.providerId.isBlank() ||
            request.roundReference.isBlank() ||
            request.signatureHeader.isBlank() ||
            request.timestampHeader.isBlank() ||
            request.rawPayload.isBlank() ||
            request.idempotencyKey.isBlank() ||
            request.correlationId.isBlank() ||
            request.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (request.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val timestamp = request.timestampHeader.toLongOrNull()
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        val now = clock.instant()
        if (Math.abs(now.epochSecond - timestamp) > timestampSkewToleranceSeconds) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintRequest(request)
        store.findByIdempotency(request.tenantId, request.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val secret = try {
            secretResolver.resolveSecret(request.tenantId, request.providerId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val computedSignature = computeHmac(secret, "${request.timestampHeader}.${request.rawPayload}")
        if (!MessageDigest.isEqual(computedSignature.toByteArray(Charsets.UTF_8), request.signatureHeader.toByteArray(Charsets.UTF_8))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val cashOutMatch = Regex(""""cashOut"\s*:\s*([0-9]+(?:\.[0-9]+)?)""").find(request.rawPayload)
        val crashPointMatch = Regex(""""crashPoint"\s*:\s*([0-9]+(?:\.[0-9]+)?)""").find(request.rawPayload)
        val extractedMultiplier = cashOutMatch?.groupValues?.get(1)?.toDoubleOrNull()
            ?: crashPointMatch?.groupValues?.get(1)?.toDoubleOrNull()

        val resultId = UUID.randomUUID()
        val evidenceRef = "GAME-CB-EVID-$resultId"

        val result = SignedCallbackVerificationResult(
            resultId = resultId,
            roundReference = request.roundReference,
            tenantId = request.tenantId,
            providerId = request.providerId,
            verified = true,
            directSettlementPermitted = false,
            extractedMultiplier = extractedMultiplier,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = request.tenantId,
            type = "GAME_CALLBACK_SIGNATURE_VERIFIED",
            occurredAt = now,
            correlationId = request.correlationId,
            causationId = request.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = request.tenantId,
            type = "GAME_CALLBACK_SIGNATURE_VERIFIED",
            createdAt = now,
        )

        store.save(
            result = result,
            tenantId = request.tenantId,
            queryFingerprint = fp,
            idempotencyKey = request.idempotencyKey,
            signature = request.signatureHeader,
            audit = audit,
            outbox = outbox,
        )

        return result
    }

    private fun computeHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRequest(req: SignedCallbackRequest): String {
        val md = MessageDigest.getInstance("SHA-256")
        val input = "${req.tenantId}:${req.providerId}:${req.roundReference}:${req.rawPayload}"
        return md.digest(input.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
