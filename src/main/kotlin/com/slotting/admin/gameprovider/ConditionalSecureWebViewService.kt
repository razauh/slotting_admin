package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for GAME-011:
 * "unsafe bridge/navigation/file access"
 */
object ConditionalSecureWebViewBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unsafe bridge/navigation/file access")
        }
    }
}

/**
 * Authoritative classification of WebView posture.
 * Semantic contract: "Otherwise classified intentionally deferred; no WebView added speculatively."
 */
enum class WebViewLaunchPosture {
    INTENTIONALLY_DEFERRED,
    PERMITTED_SECURE,
    DENIED_UNSAFE
}

/**
 * Security constraints strictly enforced if a WebView is ever permitted.
 * Any violation (file access, cleartext, unsafe bridge) is rejected fail-closed.
 */
data class WebViewSecurityConstraints(
    val allowCleartextTraffic: Boolean = false,
    val allowFileAccess: Boolean = false,
    val allowContentAccess: Boolean = false,
    val allowUniversalAccessFromFileURLs: Boolean = false,
    val allowFileAccessFromFileURLs: Boolean = false,
    val allowJavaScriptInterface: Boolean = false,
    val domainAllowlist: Set<String> = emptySet(),
    val tlsEnforced: Boolean = true,
    val sandboxEnabled: Boolean = true
) {
    fun isSecure(): Boolean {
        return !allowCleartextTraffic &&
            !allowFileAccess &&
            !allowContentAccess &&
            !allowUniversalAccessFromFileURLs &&
            !allowFileAccessFromFileURLs &&
            !allowJavaScriptInterface &&
            tlsEnforced &&
            sandboxEnabled
    }
}

data class ProviderCertificationEvidence(
    val providerId: String,
    val requiresWebView: Boolean,
    val certifiedDomains: Set<String>,
    val certificationId: String,
    val certifiedAt: Instant,
    val expiresAt: Instant
)

data class EvaluateConditionalWebViewCommand(
    val tenantId: String,
    val principal: AuthenticatedPrincipal?,
    val providerId: String,
    val gameId: String,
    val requestedLaunchUrl: String? = null,
    val requestedSecurityConstraints: WebViewSecurityConstraints? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class ConditionalWebViewResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val posture: WebViewLaunchPosture,
    val permitted: Boolean,
    val reasonCode: String,
    val safeMessage: String,
    val enforcedSecurityConstraints: WebViewSecurityConstraints?,
    val launchUrl: String?,
    val evidenceReference: String,
    val serverTime: Instant,
    val version: Long = 1L
)

data class ConditionalWebViewRecord(
    val evaluationId: UUID,
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val posture: WebViewLaunchPosture,
    val permitted: Boolean,
    val reasonCode: String,
    val safeMessage: String,
    val launchUrl: String?,
    val evidenceReference: String,
    val evaluatedAt: Instant,
    val version: Long = 1L
)

interface ConditionalWebViewStore {
    fun findEvaluation(tenantId: String, evaluationId: UUID): ConditionalWebViewRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ConditionalWebViewResult>?
    fun saveEvaluation(
        record: ConditionalWebViewRecord,
        idempotencyKey: String,
        fingerprint: String,
        result: ConditionalWebViewResult,
        audit: AuditEvent,
        outbox: OutboxEvent
    )
    fun getProviderCertification(tenantId: String, providerId: String): ProviderCertificationEvidence?
    fun setProviderCertification(tenantId: String, evidence: ProviderCertificationEvidence)
}

class InMemoryConditionalWebViewStore : ConditionalWebViewStore {
    private val evaluations = ConcurrentHashMap<String, ConditionalWebViewRecord>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, ConditionalWebViewResult>>()
    private val certifications = ConcurrentHashMap<String, ProviderCertificationEvidence>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findEvaluation(tenantId: String, evaluationId: UUID): ConditionalWebViewRecord? {
        return evaluations["$tenantId:$evaluationId"]
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ConditionalWebViewResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun saveEvaluation(
        record: ConditionalWebViewRecord,
        idempotencyKey: String,
        fingerprint: String,
        result: ConditionalWebViewResult,
        audit: AuditEvent,
        outbox: OutboxEvent
    ) {
        evaluations["${record.tenantId}:${record.evaluationId}"] = record
        idempotency["${record.tenantId}:$idempotencyKey"] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun getProviderCertification(tenantId: String, providerId: String): ProviderCertificationEvidence? {
        return certifications["$tenantId:$providerId"]
    }

    @Synchronized
    override fun setProviderCertification(tenantId: String, evidence: ProviderCertificationEvidence) {
        certifications["$tenantId:${evidence.providerId}"] = evidence
    }
}

class ConditionalSecureWebViewService(
    private val store: ConditionalWebViewStore,
    private val rbacPolicy: AdminRbacPolicy = AdminRbacPolicy(true),
    private val clock: Clock = Clock.systemUTC()
) {

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(cmd: EvaluateConditionalWebViewCommand): String {
        return sha256(
            "${cmd.tenantId}:${cmd.providerId}:${cmd.gameId}:${cmd.requestedLaunchUrl}:${cmd.requestedSecurityConstraints}:${cmd.expectedVersion}"
        )
    }

    @Synchronized
    fun evaluateWebViewPosture(command: EvaluateConditionalWebViewCommand): ConditionalWebViewResult {
        ConditionalSecureWebViewBinding.checkBound()

        // 1. Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Authorization
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Security Inspection: Check for unsafe bridge, navigation, or file access requests
        command.requestedSecurityConstraints?.let { constraints ->
            if (!constraints.isSecure()) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // Insecure URL scheme check (e.g. cleartext http or file://)
        command.requestedLaunchUrl?.let { urlString ->
            val uri = try {
                URI.create(urlString)
            } catch (e: Exception) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            if (uri.scheme == null || !uri.scheme.equals("https", ignoreCase = true)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // 4. Idempotency Check
        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()

        // 5. Provider Certification & Policy Check
        // Check if verified provider requires WebView and has active certification
        val cert = store.getProviderCertification(command.tenantId, command.providerId)
        val providerRequiresWebView = cert != null && cert.requiresWebView && cert.expiresAt.isAfter(now)

        val resultId = UUID.randomUUID()

        // Target State & Semantic Contract:
        // "Otherwise classified intentionally deferred; no WebView added speculatively."
        val (posture, permitted, reasonCode, safeMessage, launchUrl, constraints) = if (providerRequiresWebView) {
            val certEvidence = cert!!
            val url = command.requestedLaunchUrl ?: "https://${certEvidence.certifiedDomains.first()}/launch"
            val host = URI.create(url).host ?: ""
            if (!certEvidence.certifiedDomains.contains(host)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            val secureConstraints = WebViewSecurityConstraints(
                allowCleartextTraffic = false,
                allowFileAccess = false,
                allowContentAccess = false,
                allowUniversalAccessFromFileURLs = false,
                allowFileAccessFromFileURLs = false,
                allowJavaScriptInterface = false,
                domainAllowlist = certEvidence.certifiedDomains,
                tlsEnforced = true,
                sandboxEnabled = true
            )
            Tuple6(
                WebViewLaunchPosture.PERMITTED_SECURE,
                true,
                "CERTIFIED_PROVIDER_WEBVIEW_PERMITTED",
                "Certified provider WebView permitted under strict sandbox and domain constraints",
                url,
                secureConstraints
            )
        } else {
            Tuple6(
                WebViewLaunchPosture.INTENTIONALLY_DEFERRED,
                false,
                "INTENTIONALLY_DEFERRED_NO_SPECULATIVE_WEBVIEW",
                "Otherwise classified intentionally deferred; no WebView added speculatively",
                null,
                null
            )
        }

        val evidenceReference = sha256(
            "${command.tenantId}:${command.providerId}:${command.gameId}:$posture:$permitted:${now.toEpochMilli()}"
        )

        val result = ConditionalWebViewResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            gameId = command.gameId,
            posture = posture,
            permitted = permitted,
            reasonCode = reasonCode,
            safeMessage = safeMessage,
            enforcedSecurityConstraints = constraints,
            launchUrl = launchUrl,
            evidenceReference = evidenceReference,
            serverTime = now,
            version = 1L
        )

        val record = ConditionalWebViewRecord(
            evaluationId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            gameId = command.gameId,
            posture = posture,
            permitted = permitted,
            reasonCode = reasonCode,
            safeMessage = safeMessage,
            launchUrl = launchUrl,
            evidenceReference = evidenceReference,
            evaluatedAt = now,
            version = 1L
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CONDITIONAL_WEBVIEW_EVALUATED_$posture",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CONDITIONAL_WEBVIEW_EVALUATED",
            createdAt = now
        )

        store.saveEvaluation(record, command.idempotencyKey, fp, result, audit, outbox)

        return result
    }

    private data class Tuple6<A, B, C, D, E, F>(
        val a: A,
        val b: B,
        val c: C,
        val d: D,
        val e: E,
        val f: F
    )
}
